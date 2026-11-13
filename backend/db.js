const mysql = require('mysql2/promise');
require('dotenv').config();

// Primary Application Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'Daya_003',
    database: process.env.DB_NAME || 'banking_management_system',
    waitForConnections: true,
    connectionLimit: 15,
    queueLimit: 0,
    multipleStatements: true
});

// Restricted Application User Pool (Demonstrating Least Privilege)
let restrictedPool = null;
function getRestrictedPool() {
    if (!restrictedPool) {
        restrictedPool = mysql.createPool({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_APP_USER || 'bank_app_user',
            password: process.env.DB_APP_PASSWORD || 'BankApp@Secure2026!',
            database: process.env.DB_NAME || 'banking_management_system',
            waitForConnections: true,
            connectionLimit: 5,
            queueLimit: 0
        });
    }
    return restrictedPool;
}

module.exports = pool;
module.exports.getRestrictedPool = getRestrictedPool;
