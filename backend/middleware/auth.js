const jwt = require('jsonwebtoken');
const db = require('../db');
const { logSecurityEvent, getClientIp, getUserAgent } = require('../security/auditLogger');

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_jwt_key_banking_dsp_security_2026_aditya';

/**
 * Authenticates JWT token and verifies user status and token version
 */
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({ error: 'Authentication required. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // Verify active account and token version in database
        const [users] = await db.query(
            'SELECT UserID, Username, Email, Role, CustomerID, EmployeeID, IsActive, TokenVersion, MustChangePassword FROM UserSecurity WHERE UserID = ?',
            [decoded.userId]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'User account no longer exists.' });
        }

        const user = users[0];

        if (!user.IsActive) {
            await logSecurityEvent({
                actorId: user.Email,
                actorRole: user.Role,
                actionType: 'AUTH_DISABLED_LOGIN_ATTEMPT',
                targetResource: 'AUTH_SESSION',
                outcome: 'FAILURE',
                ipAddress: getClientIp(req),
                userAgent: getUserAgent(req),
                details: 'Disabled account attempted API access.'
            });
            return res.status(403).json({ error: 'Account has been disabled by bank administration.' });
        }

        // Token Version check for instant session revocation
        if (decoded.tokenVersion !== user.TokenVersion) {
            return res.status(401).json({ error: 'Session has been invalidated. Please log in again.' });
        }

        req.user = {
            userId: user.UserID,
            username: user.Username,
            email: user.Email,
            role: user.Role,
            customerId: user.CustomerID,
            employeeId: user.EmployeeID,
            mustChangePassword: Boolean(user.MustChangePassword)
        };

        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Session has expired. Please log in again.' });
        }
        return res.status(403).json({ error: 'Invalid authentication token.' });
    }
}

/**
 * Role-Based Access Control Middleware
 */
function requireRole(...allowedRoles) {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required.' });
        }

        if (!allowedRoles.includes(req.user.role)) {
            await logSecurityEvent({
                actorId: req.user.email,
                actorRole: req.user.role,
                actionType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
                targetResource: req.originalUrl,
                outcome: 'WARNING',
                ipAddress: getClientIp(req),
                userAgent: getUserAgent(req),
                details: `Role ${req.user.role} attempted accessing ${req.method} ${req.originalUrl}. Required: [${allowedRoles.join(', ')}]`
            });

            return res.status(403).json({
                error: 'Access denied: You lack sufficient privileges to perform this operation.'
            });
        }

        next();
    };
}

/**
 * Enforces customer data ownership (prevents IDOR)
 * Verifies that a Customer can ONLY access accounts or records that belong to them.
 */
async function requireAccountOwnership(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required.' });
    }

    // Admins and Employees have operational oversight permissions
    if (req.user.role === 'Admin' || req.user.role === 'Employee') {
        return next();
    }

    // For Customers:
    const requestedAccountNo = req.params.accountNo || req.body.accountNo || req.body.fromAccount;
    const requestedCustomerId = req.params.id || req.body.customerId;

    if (requestedCustomerId && Number(requestedCustomerId) !== Number(req.user.customerId)) {
        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'UNAUTHORIZED_CUSTOMER_RECORD_ACCESS',
            targetResource: `Customer:${requestedCustomerId}`,
            outcome: 'WARNING',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Customer ${req.user.customerId} attempted accessing data for Customer ${requestedCustomerId}`
        });
        return res.status(403).json({ error: 'Access denied: You can only access your own customer profile.' });
    }

    if (requestedAccountNo) {
        const [rows] = await db.query(
            'SELECT CustomerID FROM Account WHERE AccountNo = ?',
            [requestedAccountNo]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Account not found.' });
        }

        if (Number(rows[0].CustomerID) !== Number(req.user.customerId)) {
            await logSecurityEvent({
                actorId: req.user.email,
                actorRole: req.user.role,
                actionType: 'UNAUTHORIZED_ACCOUNT_ACCESS_ATTEMPT',
                targetResource: `Account:${requestedAccountNo}`,
                outcome: 'WARNING',
                ipAddress: getClientIp(req),
                userAgent: getUserAgent(req),
                details: `Customer ${req.user.customerId} attempted accessing Account ${requestedAccountNo} owned by Customer ${rows[0].CustomerID}`
            });
            return res.status(403).json({ error: 'Access denied: You do not have ownership of this account.' });
        }
    }

    next();
}

/**
 * In-memory rate limiting middleware for sensitive endpoints
 */
const rateLimitStores = new Map();
function rateLimiter({ windowMs = 60000, maxRequests = 10, keyPrefix = 'rl' }) {
    return (req, res, next) => {
        const ip = getClientIp(req);
        const key = `${keyPrefix}:${ip}`;
        const now = Date.now();

        let record = rateLimitStores.get(key);
        if (!record || now - record.startTime > windowMs) {
            record = { startTime: now, count: 1 };
            rateLimitStores.set(key, record);
            return next();
        }

        record.count++;
        if (record.count > maxRequests) {
            const retryAfterSec = Math.ceil((record.startTime + windowMs - now) / 1000);
            res.setHeader('Retry-After', retryAfterSec);
            return res.status(429).json({
                error: `Too many requests. Please try again after ${retryAfterSec} seconds.`
            });
        }

        next();
    };
}

/**
 * Standard Security Headers Middleware
 */
function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
}

module.exports = {
    authenticateToken,
    requireRole,
    requireAccountOwnership,
    rateLimiter,
    securityHeaders,
    JWT_SECRET
};
