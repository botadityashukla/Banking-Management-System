-- ==============================================================================
-- DATABASE SECURITY AND PRIVACY (DSP): DATABASE USER ADMINISTRATION
-- Script: 01_db_users_and_privileges.sql
-- Topic: Principle of Least Privilege, User Administration & MySQL GRANT / REVOKE
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- CONCEPTUAL DISTINCTION:
-- 1. Application-Level Banking Users:
--    Stored in the application database (UserSecurity table). Managed via web UI.
--    Examples: Customers checking balances, Bank Employees approving loans.
--    These users do NOT have credentials to log into the MySQL database engine directly.
--
-- 2. Database Server Accounts:
--    Managed at the DBMS level (mysql.user table). Authenticated by MySQL Server.
--    Used by backend services (Node.js connection pool) or database administrators.
-- ------------------------------------------------------------------------------

-- Step 1: Create a Restricted Application Database User
-- Never connect production backend applications using the MySQL 'root' superuser.
DROP USER IF EXISTS 'bank_app_user'@'localhost';
CREATE USER 'bank_app_user'@'localhost' 
    IDENTIFIED BY 'BankApp@Secure2026!'
    PASSWORD EXPIRE NEVER
    ACCOUNT UNLOCK;

-- Step 2: Apply Least Privilege to Application User
-- The web application only needs Data Manipulation (SELECT, INSERT, UPDATE) and EXECUTE on Stored Procedures.
-- It MUST NOT have DROP, ALTER, CREATE, DELETE, GRANT OPTION, or SHUTDOWN privileges.
GRANT SELECT, INSERT, UPDATE, EXECUTE ON banking_management_system.* TO 'bank_app_user'@'localhost';

-- Revoke dangerous DDL privileges if inadvertently inherited on the schema
REVOKE DROP, ALTER, CREATE, GRANT OPTION ON banking_management_system.* FROM 'bank_app_user'@'localhost';

-- Step 3: Create a Dedicated Database Security Administrator Account
-- Used strictly for schema migrations, backups, and user privilege auditing.
DROP USER IF EXISTS 'bank_sec_admin'@'localhost';
CREATE USER 'bank_sec_admin'@'localhost' 
    IDENTIFIED BY 'DbaSecAdmin@GlobalTrust2026!'
    PASSWORD EXPIRE INTERVAL 90 DAY
    FAILED_LOGIN_ATTEMPTS 5 
    PASSWORD_LOCK_TIME 1;

-- Grant schema-level administrative privileges for maintenance
GRANT ALL PRIVILEGES ON banking_management_system.* TO 'bank_sec_admin'@'localhost';
-- Still withhold global superuser privileges like SHUTDOWN, RELOAD, or FILE unless needed
REVOKE SHUTDOWN ON *.* FROM 'bank_sec_admin'@'localhost';

-- Step 4: Audit and Verify Database Privileges
FLUSH PRIVILEGES;

SHOW GRANTS FOR 'bank_app_user'@'localhost';
SHOW GRANTS FOR 'bank_sec_admin'@'localhost';
