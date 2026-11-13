const crypto = require('crypto');

// AES-256-GCM application-layer encryption configuration
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits auth tag

function getEncryptionKey() {
    const keyHex = process.env.ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    return Buffer.from(keyHex, 'hex');
}

/**
 * Encrypt plaintext using AES-256-GCM with authenticated tag
 * Returns format: iv:authTag:ciphertext (hex encoded)
 */
function encryptData(plaintext) {
    if (!plaintext) return null;
    try {
        const key = getEncryptionKey();
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag().toString('hex');
        return `${iv.toString('hex')}:${authTag}:${encrypted}`;
    } catch (err) {
        console.error('Encryption error:', err);
        throw new Error('Encryption operation failed');
    }
}

/**
 * Decrypt ciphertext using AES-256-GCM
 */
function decryptData(cipherPayload) {
    if (!cipherPayload) return null;
    try {
        const parts = cipherPayload.split(':');
        if (parts.length !== 3) {
            throw new Error('Invalid cipher payload format');
        }
        
        const [ivHex, authTagHex, encryptedHex] = parts;
        const key = getEncryptionKey();
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error('Decryption error:', err);
        throw new Error('Decryption failed or data tampered');
    }
}

/**
 * Mask account number: e.g. ACC1001 -> '•••• •••• 1001'
 */
function maskAccount(accountNo) {
    if (!accountNo) return '';
    const clean = String(accountNo).trim();
    if (clean.length <= 4) return clean;
    const last4 = clean.slice(-4);
    return `•••• •••• ${last4}`;
}

/**
 * Mask phone number: e.g. 8888888888 -> '••••••8888'
 */
function maskPhone(phone) {
    if (!phone) return '';
    const clean = String(phone).trim();
    if (clean.length <= 4) return clean;
    const last4 = clean.slice(-4);
    return `••••••${last4}`;
}

/**
 * Mask email address: e.g. aditya003shukla@gmail.com -> 'ad***@gmail.com'
 */
function maskEmail(email) {
    if (!email || !email.includes('@')) return email;
    const [local, domain] = email.split('@');
    if (local.length <= 2) {
        return `${local.charAt(0)}*@${domain}`;
    }
    const visible = local.slice(0, 2);
    return `${visible}***@${domain}`;
}

/**
 * Mask Govt/National ID: e.g. 1234-5678-9012 -> '•••• •••• 9012'
 */
function maskGovtId(govtId) {
    if (!govtId) return '';
    const clean = String(govtId).replace(/\s|-/g, '');
    const last4 = clean.slice(-4);
    return `•••• •••• ${last4}`;
}

module.exports = {
    encryptData,
    decryptData,
    maskAccount,
    maskPhone,
    maskEmail,
    maskGovtId
};
