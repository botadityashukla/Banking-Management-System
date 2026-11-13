const db = require('../db');

/**
 * Log a security event to the SecurityAuditLog table
 */
async function logSecurityEvent({
    actorId = 'ANONYMOUS',
    actorRole = 'GUEST',
    actionType,
    targetResource = null,
    outcome = 'SUCCESS',
    ipAddress = null,
    userAgent = null,
    details = null
}) {
    try {
        // Sanitize details to guarantee no secrets or passwords leaked
        let sanitizedDetails = details;
        if (typeof sanitizedDetails === 'object' && sanitizedDetails !== null) {
            const clone = { ...sanitizedDetails };
            delete clone.password;
            delete clone.newPassword;
            delete clone.oldPassword;
            delete clone.token;
            delete clone.encryptionKey;
            sanitizedDetails = JSON.stringify(clone);
        } else if (typeof sanitizedDetails === 'string') {
            // scrub potential secrets
            sanitizedDetails = sanitizedDetails
                .replace(/password[:=]\s*["']?[^,"'\s]+/gi, 'password=[REDACTED]')
                .replace(/token[:=]\s*["']?[^,"'\s]+/gi, 'token=[REDACTED]');
        }

        const query = `
            INSERT INTO SecurityAuditLog 
            (ActorID, ActorRole, ActionType, TargetResource, Outcome, IPAddress, UserAgent, Details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await db.query(query, [
            String(actorId).slice(0, 100),
            String(actorRole).slice(0, 50),
            String(actionType).slice(0, 100),
            targetResource ? String(targetResource).slice(0, 150) : null,
            outcome,
            ipAddress ? String(ipAddress).slice(0, 45) : null,
            userAgent ? String(userAgent).slice(0, 255) : null,
            sanitizedDetails ? String(sanitizedDetails).slice(0, 2000) : null
        ]);
    } catch (err) {
        // Silently capture to prevent logging failures from aborting primary operations
        console.error('CRITICAL: Audit logging error:', err.message);
    }
}

/**
 * Express middleware helper to log request context
 */
function getClientIp(req) {
    return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
}

function getUserAgent(req) {
    return req.headers['user-agent'] || 'Unknown';
}

module.exports = {
    logSecurityEvent,
    getClientIp,
    getUserAgent
};
