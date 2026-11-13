-- ==============================================================================
-- DATABASE SECURITY AND PRIVACY (DSP): NATIVE MYSQL 8.0 PASSWORD CONTROLS
-- Script: 02_native_mysql_profiles.sql
-- Topic: Vendor-Specific Password Management Features in MySQL 8.0 Community Server
-- ==============================================================================

-- In MySQL 8.0, password policies can be enforced natively on database accounts
-- via global system variables and per-user ALTER USER clauses.

-- 1. Global Default Password Expiration (90 Days)
-- Setting password lifetime globally for all database users:
-- SET GLOBAL default_password_lifetime = 90;

-- 2. Global Password History (Prevent reuse of last 5 passwords)
-- SET GLOBAL password_history = 5;
-- SET GLOBAL password_reuse_interval = 365;

-- 3. Per-User Native Password Aging & History in MySQL 8.0:
-- Example applying policy to a database employee user:
CREATE USER IF NOT EXISTS 'db_analyst'@'localhost' 
    IDENTIFIED BY 'Analyst@Pass2026!'
    PASSWORD EXPIRE INTERVAL 90 DAY      -- Password expires in 90 days
    PASSWORD HISTORY 5                   -- Disallow reusing last 5 passwords
    PASSWORD REUSE INTERVAL 365 DAY      -- Cannot reuse passwords used in last 365 days
    FAILED_LOGIN_ATTEMPTS 5              -- Lock account after 5 consecutive failed attempts
    PASSWORD_LOCK_TIME 1;                -- Lock for 1 day (or UNBOUNDED until DBA unlocks)

-- 4. Native Account Locking & Unlocking:
-- To manually lock an account:
ALTER USER 'db_analyst'@'localhost' ACCOUNT LOCK;

-- To unlock an account:
ALTER USER 'db_analyst'@'localhost' ACCOUNT UNLOCK;

-- 5. Force Password Change on Next Login (Dual-Password / Expire Now):
ALTER USER 'db_analyst'@'localhost' PASSWORD EXPIRE;

-- 6. Query Native Password Metadata from mysql.user catalog:
SELECT 
    user, 
    host, 
    plugin, 
    account_locked, 
    password_expired, 
    password_lifetime, 
    password_last_changed
FROM mysql.user 
WHERE user = 'db_analyst';

-- Cleanup test user (leave script idempotent)
DROP USER IF EXISTS 'db_analyst'@'localhost';
