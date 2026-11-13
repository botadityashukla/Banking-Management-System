const bcrypt = require('bcryptjs');
const db = require('../db');

// In-memory blacklist of commonly compromised / dictionary passwords
const COMMON_PASSWORDS_BLACKLIST = new Set([
    'password', 'password123', 'password123!', '123456789012', 'admin123456!',
    'welcome12345', 'banking2024!', 'banking2025!', 'banking2026!', 'qwertyuiop12',
    'letmein12345', 'changeme123!', 'iloveyou1234', 'monkey123456', 'trustbank123!',
    'globaltrust!', 'globaltrust2026', 'passphrase123!', 'securepass123'
]);

/**
 * Fetch active password policy from MySQL
 */
async function getActivePolicy() {
    try {
        const [rows] = await db.query('SELECT * FROM PasswordPolicyConfig WHERE PolicyID = 1');
        if (rows.length > 0) {
            return rows[0];
        }
    } catch (err) {
        console.error('Error fetching password policy from DB, using fallback defaults:', err.message);
    }
    return {
        MinLength: 12,
        RequireUppercase: 1,
        RequireLowercase: 1,
        RequireNumbers: 1,
        RequireSpecialChars: 1,
        ExpirationDays: 90,
        HistoryLimit: 5,
        MaxFailedAttempts: 5,
        LockoutDurationMinutes: 15
    };
}

/**
 * Validate candidate password against active password policy
 * Returns { valid: boolean, errors: string[] }
 */
async function validatePasswordComplexity(password, policy = null) {
    if (!policy) {
        policy = await getActivePolicy();
    }
    const errors = [];

    if (!password || typeof password !== 'string') {
        return { valid: false, errors: ['Password is required.'] };
    }

    // 1. Minimum Length
    if (password.length < policy.MinLength) {
        errors.push(`Password must be at least ${policy.MinLength} characters long.`);
    }

    // 2. Uppercase check
    if (policy.RequireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter (A-Z).');
    }

    // 3. Lowercase check
    if (policy.RequireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter (a-z).');
    }

    // 4. Numeric check
    if (policy.RequireNumbers && !/[0-9]/.test(password)) {
        errors.push('Password must contain at least one numeric digit (0-9).');
    }

    // 5. Special Character check
    if (policy.RequireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) {
        errors.push('Password must contain at least one special character (!@#$%^&* etc.).');
    }

    // 6. Common Compromised Passwords Blacklist Check
    const normalized = password.toLowerCase().trim();
    if (COMMON_PASSWORDS_BLACKLIST.has(normalized)) {
        errors.push('This password is commonly used and easily guessed. Please choose a more secure passphrase.');
    }

    return {
        valid: errors.length === 0,
        errors
    };
}

/**
 * Check if the candidate password has been used in the last N passwords for this user
 */
async function checkPasswordHistory(userId, candidatePassword, historyLimit = null) {
    if (!historyLimit) {
        const policy = await getActivePolicy();
        historyLimit = policy.HistoryLimit || 5;
    }

    const [historyRows] = await db.query(
        'SELECT PasswordHash FROM PasswordHistory WHERE UserID = ? ORDER BY CreatedAt DESC LIMIT ?',
        [userId, historyLimit]
    );

    for (const record of historyRows) {
        const isMatch = await bcrypt.compare(candidatePassword, record.PasswordHash);
        if (isMatch) {
            return {
                reused: true,
                message: `You cannot reuse any of your last ${historyLimit} passwords.`
            };
        }
    }

    return { reused: false };
}

/**
 * Record a new password in password history, maintaining the history limit
 */
async function recordPasswordHistory(userId, passwordHash, historyLimit = 5) {
    await db.query(
        'INSERT INTO PasswordHistory (UserID, PasswordHash) VALUES (?, ?)',
        [userId, passwordHash]
    );

    // Prune entries older than the history limit
    const [allHistory] = await db.query(
        'SELECT HistoryID FROM PasswordHistory WHERE UserID = ? ORDER BY CreatedAt DESC',
        [userId]
    );
    if (allHistory.length > historyLimit) {
        const toDelete = allHistory.slice(historyLimit).map(r => r.HistoryID);
        if (toDelete.length > 0) {
            await db.query('DELETE FROM PasswordHistory WHERE HistoryID IN (?)', [toDelete]);
        }
    }
}

/**
 * Check if user's password has expired (e.g. 90 days)
 */
function isPasswordExpired(passwordLastChanged, expirationDays) {
    if (!passwordLastChanged || !expirationDays || expirationDays <= 0) return false;
    const lastChangedDate = new Date(passwordLastChanged);
    const now = new Date();
    const diffTime = Math.abs(now - lastChangedDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays > expirationDays;
}

/**
 * Check if user account is currently locked out
 */
function isAccountLocked(lockoutUntil) {
    if (!lockoutUntil) return false;
    const lockDate = new Date(lockoutUntil);
    const now = new Date();
    return lockDate > now;
}

/**
 * Calculate remaining lockout minutes
 */
function getRemainingLockoutMinutes(lockoutUntil) {
    if (!lockoutUntil) return 0;
    const lockDate = new Date(lockoutUntil);
    const now = new Date();
    const diffMs = lockDate - now;
    if (diffMs <= 0) return 0;
    return Math.ceil(diffMs / (1000 * 60));
}

module.exports = {
    getActivePolicy,
    validatePasswordComplexity,
    checkPasswordHistory,
    recordPasswordHistory,
    isPasswordExpired,
    isAccountLocked,
    getRemainingLockoutMinutes,
    COMMON_PASSWORDS_BLACKLIST
};
