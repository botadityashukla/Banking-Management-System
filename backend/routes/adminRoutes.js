const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../db');
const { getActivePolicy, validatePasswordComplexity, recordPasswordHistory } = require('../security/passwordPolicy');
const { logSecurityEvent, getClientIp, getUserAgent } = require('../security/auditLogger');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { maskAccount, maskPhone, maskEmail } = require('../security/cryptoUtil');

// Restrict all routes in this module to Admin role only
router.use(authenticateToken);
router.use(requireRole('Admin'));

// -----------------------------------------------------------------------------
// 1. PASSWORD POLICY ENGINE MANAGEMENT
// -----------------------------------------------------------------------------

/**
 * GET /api/admin/password-policy
 * Retrieve current policy configuration and policy audit history
 */
router.get('/password-policy', async (req, res) => {
    try {
        const policy = await getActivePolicy();

        // Retrieve recent policy modification audit events
        const [auditEvents] = await db.query(
            `SELECT EventID, Timestamp, ActorID, ActionType, Outcome, Details 
             FROM SecurityAuditLog 
             WHERE ActionType IN ('POLICY_UPDATE', 'PASSWORD_POLICY_UPDATE') 
             ORDER BY Timestamp DESC LIMIT 10`
        );

        res.json({
            policy,
            auditEvents
        });
    } catch (err) {
        console.error('Error fetching password policy:', err);
        res.status(500).json({ error: 'Failed to retrieve password policy.' });
    }
});

/**
 * PUT /api/admin/password-policy
 * Update password policy settings (Audited)
 */
router.put('/password-policy', async (req, res) => {
    const {
        minLength,
        requireUppercase,
        requireLowercase,
        requireNumbers,
        requireSpecialChars,
        expirationDays,
        historyLimit,
        maxFailedAttempts,
        lockoutDurationMinutes
    } = req.body;

    // Validate inputs
    const parsedMinLength = parseInt(minLength, 10);
    const parsedExpiration = parseInt(expirationDays, 10);
    const parsedHistory = parseInt(historyLimit, 10);
    const parsedMaxFailed = parseInt(maxFailedAttempts, 10);
    const parsedLockoutDuration = parseInt(lockoutDurationMinutes, 10);

    if (isNaN(parsedMinLength) || parsedMinLength < 8 || parsedMinLength > 64) {
        return res.status(400).json({ error: 'Minimum length must be an integer between 8 and 64.' });
    }
    if (isNaN(parsedExpiration) || parsedExpiration < 0 || parsedExpiration > 365) {
        return res.status(400).json({ error: 'Expiration days must be between 0 and 365.' });
    }
    if (isNaN(parsedHistory) || parsedHistory < 0 || parsedHistory > 24) {
        return res.status(400).json({ error: 'History limit must be between 0 and 24.' });
    }
    if (isNaN(parsedMaxFailed) || parsedMaxFailed < 1 || parsedMaxFailed > 20) {
        return res.status(400).json({ error: 'Max failed attempts must be between 1 and 20.' });
    }
    if (isNaN(parsedLockoutDuration) || parsedLockoutDuration < 1 || parsedLockoutDuration > 1440) {
        return res.status(400).json({ error: 'Lockout duration must be between 1 and 1440 minutes.' });
    }

    try {
        const query = `
            UPDATE PasswordPolicyConfig SET 
                MinLength = ?,
                RequireUppercase = ?,
                RequireLowercase = ?,
                RequireNumbers = ?,
                RequireSpecialChars = ?,
                ExpirationDays = ?,
                HistoryLimit = ?,
                MaxFailedAttempts = ?,
                LockoutDurationMinutes = ?,
                UpdatedBy = ?,
                UpdatedAt = NOW()
            WHERE PolicyID = 1
        `;

        await db.query(query, [
            parsedMinLength,
            Boolean(requireUppercase),
            Boolean(requireLowercase),
            Boolean(requireNumbers),
            Boolean(requireSpecialChars),
            parsedExpiration,
            parsedHistory,
            parsedMaxFailed,
            parsedLockoutDuration,
            req.user.email
        ]);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'POLICY_UPDATE',
            targetResource: 'PASSWORD_POLICY_CONFIG',
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Admin updated password policy: MinLength=${parsedMinLength}, Expiration=${parsedExpiration}d, History=${parsedHistory}, MaxFailed=${parsedMaxFailed}, Lockout=${parsedLockoutDuration}m`
        });

        const updatedPolicy = await getActivePolicy();
        res.json({
            message: 'Password policy successfully updated and audited.',
            policy: updatedPolicy
        });
    } catch (err) {
        console.error('Error updating password policy:', err);
        res.status(500).json({ error: 'Database error updating password policy.' });
    }
});

// -----------------------------------------------------------------------------
// 2. DATABASE USER ADMINISTRATION (APPLICATION LEVEL)
// -----------------------------------------------------------------------------

/**
 * GET /api/admin/users
 * Lists application users with safe attributes (No hashes exposed)
 */
router.get('/users', async (req, res) => {
    try {
        const [users] = await db.query(`
            SELECT 
                u.UserID,
                u.Username,
                u.Email,
                u.Role,
                u.CustomerID,
                u.EmployeeID,
                u.IsActive,
                u.FailedLoginAttempts,
                u.LockoutUntil,
                u.PasswordLastChanged,
                u.MustChangePassword,
                u.CreatedAt,
                CONCAT(COALESCE(c.FirstName, e.FirstName, ''), ' ', COALESCE(c.LastName, e.LastName, '')) AS FullName
            FROM UserSecurity u
            LEFT JOIN Customer c ON u.CustomerID = c.CustomerID
            LEFT JOIN Employee e ON u.EmployeeID = e.EmployeeID
            ORDER BY u.CreatedAt DESC
        `);

        res.json({ users });
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Database error fetching application users.' });
    }
});

/**
 * POST /api/admin/users/create
 * Create a new application banking user
 */
router.post('/users/create', async (req, res) => {
    const { username, email, password, role, firstName, lastName, branchId, jobTitle } = req.body;

    if (!username || !email || !password || !role) {
        return res.status(400).json({ error: 'Username, email, password, and role are required.' });
    }

    if (!['Admin', 'Employee', 'Customer'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role. Allowed roles: Admin, Employee, Customer.' });
    }

    try {
        // Validate password against active policy
        const policy = await getActivePolicy();
        const complexity = await validatePasswordComplexity(password, policy);
        if (!complexity.valid) {
            return res.status(400).json({
                error: 'Password does not meet active security policy.',
                details: complexity.errors
            });
        }

        // Check if email or username already taken
        const [existing] = await db.query('SELECT UserID FROM UserSecurity WHERE Email = ? OR Username = ?', [email, username]);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'A user with this email or username already exists.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        let customerId = null;
        let employeeId = null;

        // If creating Customer or Employee, insert corresponding entity record
        if (role === 'Customer') {
            const [custRes] = await db.query(
                `INSERT INTO Customer (FirstName, LastName, DOB, Email, Phone, Address, City)
                 VALUES (?, ?, '1995-01-01', ?, CONCAT('9', FLOOR(RAND()*900000000 + 100000000)), 'Online Registration', 'Main City')`,
                [firstName || 'New', lastName || 'Customer', email]
            );
            customerId = custRes.insertId;

            // Automatically open a default savings account for new customers
            const accountNo = 'ACC' + Math.floor(100000 + Math.random() * 900000);
            await db.query(
                `INSERT INTO Account (AccountNo, CustomerID, BranchID, AccountType, Balance, Status, OpenedDate)
                 VALUES (?, ?, ?, 'Savings', 5000.00, 'Active', CURDATE())`,
                [accountNo, customerId, branchId || 1]
            );
        } else if (role === 'Employee') {
            const [empRes] = await db.query(
                `INSERT INTO Employee (FirstName, LastName, Email, JobTitle, Salary, BranchID, HireDate)
                 VALUES (?, ?, ?, ?, 55000.00, ?, CURDATE())`,
                [firstName || 'Staff', lastName || 'Member', email, jobTitle || 'Banking Associate', branchId || 1]
            );
            employeeId = empRes.insertId;
        }

        // Create UserSecurity account
        const [userRes] = await db.query(
            `INSERT INTO UserSecurity (Username, Email, PasswordHash, Role, CustomerID, EmployeeID, IsActive, PasswordLastChanged)
             VALUES (?, ?, ?, ?, ?, ?, TRUE, NOW())`,
            [username, email, passwordHash, role, customerId, employeeId]
        );

        const newUserId = userRes.insertId;
        await recordPasswordHistory(newUserId, passwordHash, policy.HistoryLimit);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'ADMIN_USER_CREATE',
            targetResource: `UserSecurity:${newUserId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Created new application user ${username} (${email}) with role ${role}.`
        });

        res.status(201).json({
            message: `User ${username} successfully created with role ${role}.`,
            userId: newUserId
        });

    } catch (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ error: 'Database error creating user.' });
    }
});

/**
 * PUT /api/admin/users/:id/status
 * Enable or Disable application user account (Revokes sessions)
 */
router.put('/users/:id/status', async (req, res) => {
    const userId = req.params.id;
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
        return res.status(400).json({ error: 'isActive must be a boolean.' });
    }

    try {
        const [users] = await db.query('SELECT UserID, Email, Role, IsActive FROM UserSecurity WHERE UserID = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const targetUser = users[0];

        // Prevent disabling oneself
        if (Number(userId) === Number(req.user.userId)) {
            return res.status(400).json({ error: 'Administrators cannot disable their own active account.' });
        }

        // Update status and bump TokenVersion to immediately revoke active sessions
        await db.query(
            'UPDATE UserSecurity SET IsActive = ?, TokenVersion = TokenVersion + 1 WHERE UserID = ?',
            [isActive, userId]
        );

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'ADMIN_USER_STATUS_CHANGE',
            targetResource: `UserSecurity:${userId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Admin ${req.user.email} changed user ${targetUser.Email} status to ${isActive ? 'ACTIVE' : 'DISABLED'}. Sessions revoked.`
        });

        res.json({
            message: `User account has been ${isActive ? 'enabled' : 'disabled'}. Active sessions have been revoked.`
        });
    } catch (err) {
        console.error('Error toggling status:', err);
        res.status(500).json({ error: 'Database error changing account status.' });
    }
});

/**
 * PUT /api/admin/users/:id/role
 * Assign or Revoke Application Roles (Least Privilege)
 */
router.put('/users/:id/role', async (req, res) => {
    const userId = req.params.id;
    const { role } = req.body;

    if (!['Admin', 'Employee', 'Customer'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role. Must be Admin, Employee, or Customer.' });
    }

    try {
        const [users] = await db.query('SELECT UserID, Email, Role FROM UserSecurity WHERE UserID = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const targetUser = users[0];

        // Update role and bump TokenVersion to force re-authentication with new privileges
        await db.query(
            'UPDATE UserSecurity SET Role = ?, TokenVersion = TokenVersion + 1 WHERE UserID = ?',
            [role, userId]
        );

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'ROLE_ASSIGNMENT',
            targetResource: `UserSecurity:${userId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Admin changed role of ${targetUser.Email} from ${targetUser.Role} to ${role}.`
        });

        res.json({
            message: `Role for ${targetUser.Email} changed to ${role}. User sessions invalidated.`
        });
    } catch (err) {
        console.error('Error changing role:', err);
        res.status(500).json({ error: 'Database error changing role.' });
    }
});

/**
 * POST /api/admin/users/:id/reset-password
 * Administrator-initiated password reset (Requires change on next login)
 */
router.post('/users/:id/reset-password', async (req, res) => {
    const userId = req.params.id;
    const { temporaryPassword } = req.body;

    try {
        const [users] = await db.query('SELECT UserID, Email, Role FROM UserSecurity WHERE UserID = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        const targetUser = users[0];

        const policy = await getActivePolicy();
        const tempPassword = temporaryPassword || 'Reset@Temp2026!';

        // Validate temporary password meets policy
        const complexity = await validatePasswordComplexity(tempPassword, policy);
        if (!complexity.valid) {
            return res.status(400).json({
                error: 'Temporary password violates active policy.',
                details: complexity.errors
            });
        }

        const newHash = await bcrypt.hash(tempPassword, 10);

        // Update password, require change on next login, reset lockout & failed attempts, bump TokenVersion
        await db.query(
            `UPDATE UserSecurity 
             SET PasswordHash = ?, 
                 MustChangePassword = TRUE, 
                 FailedLoginAttempts = 0, 
                 LockoutUntil = NULL, 
                 TokenVersion = TokenVersion + 1, 
                 PasswordLastChanged = NOW() 
             WHERE UserID = ?`,
            [newHash, userId]
        );

        await recordPasswordHistory(userId, newHash, policy.HistoryLimit);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'ADMIN_PASSWORD_RESET',
            targetResource: `UserSecurity:${userId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Admin initiated password reset for ${targetUser.Email}. Flag MustChangePassword set to TRUE.`
        });

        res.json({
            message: `Password reset successfully. The user must change their password upon their next login.`,
            temporaryPassword: tempPassword
        });

    } catch (err) {
        console.error('Error resetting password:', err);
        res.status(500).json({ error: 'Database error resetting password.' });
    }
});

/**
 * DELETE /api/admin/users/:id/safe-deactivate
 * Safely deactivates user account without deleting financial records or audit logs
 */
router.delete('/users/:id/safe-deactivate', async (req, res) => {
    const userId = req.params.id;

    try {
        const [users] = await db.query('SELECT UserID, Email FROM UserSecurity WHERE UserID = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Soft-deactivation to preserve foreign keys and financial history
        await db.query(
            'UPDATE UserSecurity SET IsActive = FALSE, TokenVersion = TokenVersion + 1 WHERE UserID = ?',
            [userId]
        );

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'ADMIN_SAFE_DEACTIVATE',
            targetResource: `UserSecurity:${userId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Account for ${users[0].Email} deactivated safely. Financial transactions and audit logs preserved.`
        });

        res.json({
            message: `User ${users[0].Email} has been safely deactivated. Financial records and audit logs are preserved.`
        });
    } catch (err) {
        console.error('Error deactivating user:', err);
        res.status(500).json({ error: 'Database error deactivating user.' });
    }
});

// -----------------------------------------------------------------------------
// 3. SECURITY AUDIT LOG VIEWER
// -----------------------------------------------------------------------------

/**
 * GET /api/admin/audit-logs
 * Filterable query of security audit events
 */
router.get('/audit-logs', async (req, res) => {
    const { actionType, outcome, actorId, limit = 50, offset = 0 } = req.query;

    try {
        let query = 'SELECT * FROM SecurityAuditLog WHERE 1=1';
        const params = [];

        if (actionType) {
            query += ' AND ActionType = ?';
            params.push(actionType);
        }
        if (outcome) {
            query += ' AND Outcome = ?';
            params.push(outcome);
        }
        if (actorId) {
            query += ' AND ActorID LIKE ?';
            params.push(`%${actorId}%`);
        }

        query += ' ORDER BY Timestamp DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit, 10), parseInt(offset, 10));

        const [logs] = await db.query(query, params);
        const [countRow] = await db.query('SELECT COUNT(*) AS total FROM SecurityAuditLog');

        res.json({
            total: countRow[0].total,
            logs
        });
    } catch (err) {
        console.error('Error fetching audit logs:', err);
        res.status(500).json({ error: 'Database error fetching audit logs.' });
    }
});

// -----------------------------------------------------------------------------
// 4. SECURITY & PRIVACY METRICS
// -----------------------------------------------------------------------------

/**
 * GET /api/admin/security-metrics
 * Aggregated metrics for the Security & Privacy Dashboard
 */
router.get('/security-metrics', async (req, res) => {
    try {
        const [totalUsers] = await db.query('SELECT COUNT(*) AS count FROM UserSecurity');
        const [activeUsers] = await db.query('SELECT COUNT(*) AS count FROM UserSecurity WHERE IsActive = TRUE');
        const [lockedAccounts] = await db.query('SELECT COUNT(*) AS count FROM UserSecurity WHERE LockoutUntil > NOW()');
        
        const [failedLogins24h] = await db.query(
            "SELECT COUNT(*) AS count FROM SecurityAuditLog WHERE ActionType IN ('AUTH_LOGIN_FAILED', 'AUTH_ACCOUNT_LOCKED') AND Timestamp >= NOW() - INTERVAL 1 DAY"
        );

        const [successfulLogins24h] = await db.query(
            "SELECT COUNT(*) AS count FROM SecurityAuditLog WHERE ActionType = 'AUTH_LOGIN_SUCCESS' AND Timestamp >= NOW() - INTERVAL 1 DAY"
        );

        const [recentViolations] = await db.query(
            "SELECT * FROM SecurityAuditLog WHERE Outcome IN ('FAILURE', 'WARNING') ORDER BY Timestamp DESC LIMIT 10"
        );

        const [roleCounts] = await db.query('SELECT Role, COUNT(*) as count FROM UserSecurity GROUP BY Role');

        res.json({
            metrics: {
                totalUsers: totalUsers[0].count,
                activeUsers: activeUsers[0].count,
                lockedAccounts: lockedAccounts[0].count,
                failedLogins24h: failedLogins24h[0].count,
                successfulLogins24h: successfulLogins24h[0].count
            },
            roleCounts,
            recentViolations
        });
    } catch (err) {
        console.error('Error fetching security metrics:', err);
        res.status(500).json({ error: 'Database error fetching metrics.' });
    }
});

// -----------------------------------------------------------------------------
// 5. DATABASE PRIVILEGES & VENDOR PROFILES INSPECTION
// -----------------------------------------------------------------------------

/**
 * GET /api/admin/db-privileges
 * Inspect MySQL user privileges, restricted credentials, and profile comparisons
 */
router.get('/db-privileges', async (req, res) => {
    try {
        // Query grants for restricted app user
        let appGrants = [];
        try {
            const [grants] = await db.query("SHOW GRANTS FOR 'bank_app_user'@'localhost'");
            appGrants = grants.map(g => Object.values(g)[0]);
        } catch (e) {
            appGrants = ['Grant query restricted or user not present: ' + e.message];
        }

        // Query native MySQL password variables
        const [mysqlVars] = await db.query(
            "SHOW VARIABLES WHERE Variable_name IN ('default_password_lifetime', 'password_history', 'password_require_current', 'password_reuse_interval')"
        );

        res.json({
            appUser: 'bank_app_user@localhost',
            adminUser: 'bank_sec_admin@localhost',
            grants: appGrants,
            mysqlNativeVariables: mysqlVars,
            comparisonSummary: {
                architecture: 'Multi-tiered defense: Application controls protect web users; MySQL controls protect service accounts.',
                vendorSupport: {
                    mysql: 'MySQL 8.0 implements per-user attributes (FAILED_LOGIN_ATTEMPTS, PASSWORD EXPIRE INTERVAL, PASSWORD HISTORY).',
                    oracle: 'Oracle Database implements reusable CREATE PROFILE objects with kernel-level resource limits and PL/SQL verify functions.',
                    sqlServer: 'SQL Server relies on Windows CHECK_POLICY and CHECK_EXPIRATION integrated with Active Directory domain policies.'
                }
            }
        });
    } catch (err) {
        console.error('Error in db-privileges:', err);
        res.status(500).json({ error: 'Failed to retrieve database privilege information.' });
    }
});

const { runSecurityTestSuite } = require('../tests/security_tests');

/**
 * POST /api/admin/run-security-tests
 * Executes the full automated security test suite and returns live report
 */
router.post('/run-security-tests', async (req, res) => {
    try {
        const testReport = await runSecurityTestSuite();

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'SECURITY_TEST_SUITE_RUN',
            targetResource: 'TEST_ENGINE',
            outcome: testReport.failed === 0 ? 'SUCCESS' : 'WARNING',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Automated test suite executed: ${testReport.passed}/${testReport.total} passed.`
        });

        res.json(testReport);
    } catch (err) {
        console.error('Error running security tests:', err);
        res.status(500).json({ error: 'Failed to execute security tests: ' + err.message });
    }
});

module.exports = router;
