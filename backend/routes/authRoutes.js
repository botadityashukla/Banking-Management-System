const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db');
const { 
    getActivePolicy, 
    validatePasswordComplexity, 
    checkPasswordHistory, 
    recordPasswordHistory, 
    isPasswordExpired, 
    isAccountLocked, 
    getRemainingLockoutMinutes 
} = require('../security/passwordPolicy');
const { logSecurityEvent, getClientIp, getUserAgent } = require('../security/auditLogger');
const { authenticateToken, rateLimiter, JWT_SECRET } = require('../middleware/auth');

/**
 * Helper to generate JWT token
 */
function generateToken(user) {
    const expiresIn = process.env.SESSION_EXPIRY_SECONDS ? `${process.env.SESSION_EXPIRY_SECONDS}s` : '1h';
    return jwt.sign(
        {
            userId: user.UserID,
            username: user.Username,
            email: user.Email,
            role: user.Role,
            customerId: user.CustomerID,
            employeeId: user.EmployeeID,
            tokenVersion: user.TokenVersion
        },
        JWT_SECRET,
        { expiresIn }
    );
}

/**
 * POST /api/auth/login
 * Secure authentication with password verification, lockout enforcement, and rate limiting
 */
router.post('/login', rateLimiter({ windowMs: 60000, maxRequests: 10, keyPrefix: 'login' }), async (req, res) => {
    const { email, password } = req.body;
    const ip = getClientIp(req);
    const ua = getUserAgent(req);

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const policy = await getActivePolicy();

        // 1. Look up user by Email or Username
        const [users] = await db.query(
            'SELECT * FROM UserSecurity WHERE Email = ? OR Username = ?',
            [email, email]
        );

        if (users.length === 0) {
            // Mitigate timing attacks with dummy hash comparison
            await bcrypt.compare(password, '$2a$10$wT0lQfA1xJz7b.92O1E9U.uG5K6E5bO9F2I2b5a5c5d5e5f5g5h5i');
            await logSecurityEvent({
                actorId: email,
                actorRole: 'GUEST',
                actionType: 'AUTH_LOGIN_FAILED',
                targetResource: 'AUTH_ENDPOINT',
                outcome: 'FAILURE',
                ipAddress: ip,
                userAgent: ua,
                details: 'Login attempt for non-existent account.'
            });
            return res.status(401).json({ error: 'Invalid credentials. Please check your email and password.' });
        }

        const user = users[0];

        // 2. Check if account is disabled
        if (!user.IsActive) {
            await logSecurityEvent({
                actorId: user.Email,
                actorRole: user.Role,
                actionType: 'AUTH_DISABLED_LOGIN_ATTEMPT',
                targetResource: 'AUTH_ENDPOINT',
                outcome: 'FAILURE',
                ipAddress: ip,
                userAgent: ua,
                details: 'Login attempt on deactivated account.'
            });
            return res.status(403).json({ error: 'Your account has been deactivated. Please contact bank administration.' });
        }

        // 3. Check Account Lockout Policy
        if (isAccountLocked(user.LockoutUntil)) {
            const remainingMins = getRemainingLockoutMinutes(user.LockoutUntil);
            await logSecurityEvent({
                actorId: user.Email,
                actorRole: user.Role,
                actionType: 'AUTH_LOCKOUT_REJECTION',
                targetResource: 'AUTH_ENDPOINT',
                outcome: 'FAILURE',
                ipAddress: ip,
                userAgent: ua,
                details: `Login attempted while locked out. Remaining: ${remainingMins} minute(s).`
            });
            return res.status(423).json({ 
                error: `Account is temporarily locked due to multiple consecutive failed login attempts. Please try again in ${remainingMins} minute(s).` 
            });
        }

        // 4. Verify Password Hash
        const passwordMatch = await bcrypt.compare(password, user.PasswordHash);

        if (!passwordMatch) {
            const newFailedAttempts = (user.FailedLoginAttempts || 0) + 1;
            let lockoutUntil = null;
            let lockedOutNow = false;

            if (newFailedAttempts >= policy.MaxFailedAttempts) {
                // Lock account for configured lockout duration
                lockoutUntil = new Date(Date.now() + policy.LockoutDurationMinutes * 60 * 1000);
                lockedOutNow = true;

                await db.query(
                    'UPDATE UserSecurity SET FailedLoginAttempts = ?, LockoutUntil = ? WHERE UserID = ?',
                    [newFailedAttempts, lockoutUntil, user.UserID]
                );

                await logSecurityEvent({
                    actorId: user.Email,
                    actorRole: user.Role,
                    actionType: 'AUTH_ACCOUNT_LOCKED',
                    targetResource: 'AUTH_ENDPOINT',
                    outcome: 'WARNING',
                    ipAddress: ip,
                    userAgent: ua,
                    details: `Account locked for ${policy.LockoutDurationMinutes} minutes after ${newFailedAttempts} consecutive failed login attempts.`
                });

                return res.status(423).json({
                    error: `Account has been locked for ${policy.LockoutDurationMinutes} minutes due to ${newFailedAttempts} consecutive failed login attempts.`
                });
            } else {
                await db.query(
                    'UPDATE UserSecurity SET FailedLoginAttempts = ? WHERE UserID = ?',
                    [newFailedAttempts, user.UserID]
                );

                await logSecurityEvent({
                    actorId: user.Email,
                    actorRole: user.Role,
                    actionType: 'AUTH_LOGIN_FAILED',
                    targetResource: 'AUTH_ENDPOINT',
                    outcome: 'FAILURE',
                    ipAddress: ip,
                    userAgent: ua,
                    details: `Password mismatch. Failed attempt ${newFailedAttempts} of ${policy.MaxFailedAttempts}.`
                });

                const remainingAttempts = policy.MaxFailedAttempts - newFailedAttempts;
                return res.status(401).json({
                    error: `Invalid credentials. ${remainingAttempts} attempt(s) remaining before temporary lockout.`
                });
            }
        }

        // 5. Successful Authentication: Reset failed attempts & lockout
        await db.query(
            'UPDATE UserSecurity SET FailedLoginAttempts = 0, LockoutUntil = NULL WHERE UserID = ?',
            [user.UserID]
        );

        // 6. Check Password Expiration & Force Change Flag
        const expired = isPasswordExpired(user.PasswordLastChanged, policy.ExpirationDays);
        const mustChange = Boolean(user.MustChangePassword) || expired;

        // 7. Generate Session Token
        const token = generateToken(user);

        await logSecurityEvent({
            actorId: user.Email,
            actorRole: user.Role,
            actionType: 'AUTH_LOGIN_SUCCESS',
            targetResource: 'AUTH_ENDPOINT',
            outcome: 'SUCCESS',
            ipAddress: ip,
            userAgent: ua,
            details: `User logged in successfully with role ${user.Role}.`
        });

        // 8. Fetch associated Customer or Employee profile details
        let profileDetails = null;
        if (user.CustomerID) {
            const [cust] = await db.query('SELECT CustomerID, FirstName, LastName, Email, Phone, City FROM Customer WHERE CustomerID = ?', [user.CustomerID]);
            if (cust.length > 0) profileDetails = cust[0];
        } else if (user.EmployeeID) {
            const [emp] = await db.query('SELECT EmployeeID, FirstName, LastName, Email, JobTitle, BranchID FROM Employee WHERE EmployeeID = ?', [user.EmployeeID]);
            if (emp.length > 0) profileDetails = emp[0];
        }

        res.json({
            message: 'Authentication successful.',
            token,
            mustChangePassword: mustChange,
            passwordExpired: expired,
            user: {
                userId: user.UserID,
                username: user.Username,
                email: user.Email,
                role: user.Role,
                customerId: user.CustomerID,
                employeeId: user.EmployeeID,
                profile: profileDetails
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error during authentication.' });
    }
});

/**
 * POST /api/auth/change-password
 * Enforces policy complexity, password history (no reuse of last N), and session invalidation
 */
router.post('/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const ip = getClientIp(req);
    const ua = getUserAgent(req);

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current password and new password are required.' });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'New password and confirmation password do not match.' });
    }

    try {
        const policy = await getActivePolicy();

        // 1. Fetch current user hash
        const [users] = await db.query('SELECT * FROM UserSecurity WHERE UserID = ?', [req.user.userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        const user = users[0];

        // 2. Verify current password
        const currentMatch = await bcrypt.compare(currentPassword, user.PasswordHash);
        if (!currentMatch) {
            await logSecurityEvent({
                actorId: user.Email,
                actorRole: user.Role,
                actionType: 'PASSWORD_CHANGE_FAILED',
                targetResource: 'USER_SECURITY',
                outcome: 'FAILURE',
                ipAddress: ip,
                userAgent: ua,
                details: 'Current password verification failed during password change.'
            });
            return res.status(400).json({ error: 'Current password is incorrect.' });
        }

        // 3. Validate new password against complexity policy
        const complexityCheck = await validatePasswordComplexity(newPassword, policy);
        if (!complexityCheck.valid) {
            return res.status(400).json({
                error: 'Password does not meet security policy requirements.',
                details: complexityCheck.errors
            });
        }

        // 4. Check Password History (no reuse of last N)
        const historyCheck = await checkPasswordHistory(user.UserID, newPassword, policy.HistoryLimit);
        if (historyCheck.reused) {
            await logSecurityEvent({
                actorId: user.Email,
                actorRole: user.Role,
                actionType: 'PASSWORD_REUSE_REJECTED',
                targetResource: 'PASSWORD_HISTORY',
                outcome: 'WARNING',
                ipAddress: ip,
                userAgent: ua,
                details: `User attempted to reuse one of the last ${policy.HistoryLimit} passwords.`
            });
            return res.status(400).json({ error: historyCheck.message });
        }

        // 5. Hash new password
        const newHash = await bcrypt.hash(newPassword, 10);

        // 6. Invalidate previous sessions by bumping TokenVersion, update password and timestamp
        const newTokenVersion = (user.TokenVersion || 1) + 1;
        await db.query(
            `UPDATE UserSecurity 
             SET PasswordHash = ?, 
                 PasswordLastChanged = NOW(), 
                 MustChangePassword = FALSE, 
                 TokenVersion = ? 
             WHERE UserID = ?`,
            [newHash, newTokenVersion, user.UserID]
        );

        // 7. Record in Password History
        await recordPasswordHistory(user.UserID, newHash, policy.HistoryLimit);

        // 8. Generate fresh token with new tokenVersion
        user.TokenVersion = newTokenVersion;
        const freshToken = generateToken(user);

        await logSecurityEvent({
            actorId: user.Email,
            actorRole: user.Role,
            actionType: 'PASSWORD_CHANGE_SUCCESS',
            targetResource: 'USER_SECURITY',
            outcome: 'SUCCESS',
            ipAddress: ip,
            userAgent: ua,
            details: 'Password successfully changed and previous sessions invalidated.'
        });

        res.json({
            message: 'Password successfully changed! Previous active sessions have been invalidated for security.',
            token: freshToken
        });

    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).json({ error: 'Internal server error processing password change.' });
    }
});

/**
 * POST /api/auth/logout
 * Session invalidation endpoint
 */
router.post('/logout', authenticateToken, async (req, res) => {
    try {
        // Bump token version to instantly revoke token
        await db.query('UPDATE UserSecurity SET TokenVersion = TokenVersion + 1 WHERE UserID = ?', [req.user.userId]);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'AUTH_LOGOUT',
            targetResource: 'AUTH_SESSION',
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: 'User logged out and session revoked.'
        });

        res.json({ message: 'Logged out successfully.' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'Error logging out.' });
    }
});

/**
 * GET /api/auth/me
 * Return current authenticated session details
 */
router.get('/me', authenticateToken, async (req, res) => {
    try {
        let profile = null;
        if (req.user.customerId) {
            const [rows] = await db.query('SELECT CustomerID, FirstName, LastName, Email, Phone, City FROM Customer WHERE CustomerID = ?', [req.user.customerId]);
            if (rows.length > 0) profile = rows[0];
        } else if (req.user.employeeId) {
            const [rows] = await db.query('SELECT EmployeeID, FirstName, LastName, Email, JobTitle, BranchID FROM Employee WHERE EmployeeID = ?', [req.user.employeeId]);
            if (rows.length > 0) profile = rows[0];
        }

        res.json({
            user: {
                userId: req.user.userId,
                username: req.user.username,
                email: req.user.email,
                role: req.user.role,
                customerId: req.user.customerId,
                employeeId: req.user.employeeId,
                mustChangePassword: req.user.mustChangePassword,
                profile
            }
        });
    } catch (err) {
        console.error('Error in /me:', err);
        res.status(500).json({ error: 'Database error.' });
    }
});

module.exports = router;
