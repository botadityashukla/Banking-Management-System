-- ==============================================================================
-- DATABASE SECURITY AND PRIVACY (DSP): ORACLE DATABASE PROFILES DEMONSTRATION
-- Script: 03_oracle_profile_demonstration.sql
-- Topic: Academic Comparative Study: Oracle Database Profiles vs MySQL 8.0 Controls
-- ==============================================================================
-- NOTE: THIS SCRIPT CONTAINS ORACLE SQL*PLUS / PL-SQL SYNTAX FOR ACADEMIC STUDY.
-- DO NOT EXECUTE THIS SCRIPT DIRECTLY IN MYSQL WORKBENCH OR MYSQL CLI!
-- Oracle Database implements centralized "PROFILES" (CREATE PROFILE), a feature
-- not present as a standalone object in MySQL, where settings are per-user attributes.
-- ==============================================================================

/*
--------------------------------------------------------------------------------
1. CONCEPT: ORACLE DATABASE PROFILES
--------------------------------------------------------------------------------
In Oracle RDBMS (12c, 19c, 21c, 23c), a PROFILE is a named set of database resource
limits and password management rules assigned to one or more database users.
When a profile is assigned, Oracle's kernel enforces the rules at connection and
authentication time.

Profiles address two primary security concerns:
  1. Password Management Parameters (Aging, complexity, history, lockouts)
  2. Resource Limit Parameters (CPU time, idle session time, concurrent sessions)

--------------------------------------------------------------------------------
2. ORACLE PROFILE DEFINITION SYNTAX
--------------------------------------------------------------------------------
*/

-- Step A: Create Custom Password Verification Function (Oracle PL/SQL)
-- Oracle ships with default verification functions (e.g. ora12c_strong_verify_function)
-- in $ORACLE_HOME/rdbms/admin/utlpwdmg.sql

/*
CREATE PROFILE bank_security_profile LIMIT
    -- [A] PASSWORD LIFETIME & AGING
    PASSWORD_LIFE_TIME          90          -- Password expires after 90 days
    PASSWORD_GRACE_TIME         7           -- 7 days grace period with warnings before lock
    
    -- [B] FAILED LOGIN & ACCOUNT LOCKOUT
    FAILED_LOGIN_ATTEMPTS       5           -- Lock account after 5 consecutive bad passwords
    PASSWORD_LOCK_TIME          1/96        -- Lock duration: 15 minutes (1/96th of 24 hours)
    
    -- [C] PASSWORD REUSE & HISTORY RESTRICTION
    PASSWORD_REUSE_TIME         365         -- Cannot reuse password within 365 days
    PASSWORD_REUSE_MAX          5           -- Must change password 5 times before reuse
    
    -- [D] COMPLEXITY VERIFICATION FUNCTION
    PASSWORD_VERIFY_FUNCTION    ora12c_strong_verify_function -- Validates length >= 12, mixed case, symbols
    
    -- [E] RESOURCE RESTRICTION (DENIAL-OF-SERVICE & LEAST PRIVILEGE)
    SESSIONS_PER_USER           2           -- Max 2 concurrent sessions per user
    CPU_PER_SESSION             UNLIMITED
    CONNECT_TIME                480         -- Max connection time: 8 hours (480 minutes)
    IDLE_TIME                   15          -- Terminate session after 15 minutes of inactivity
    LOGICAL_READS_PER_SESSION   DEFAULT;
*/

/*
--------------------------------------------------------------------------------
3. ASSIGNING PROFILES TO ORACLE USERS
--------------------------------------------------------------------------------
CREATE USER bank_teller IDENTIFIED BY "Teller#Secure2026"
    DEFAULT TABLESPACE users
    TEMPORARY TABLESPACE temp
    PROFILE bank_security_profile
    ACCOUNT UNLOCK;

-- Modifying an existing user:
ALTER USER bank_teller PROFILE bank_security_profile;

-- Enabling Resource Limits in Oracle:
ALTER SYSTEM SET RESOURCE_LIMIT = TRUE;
*/

/*
--------------------------------------------------------------------------------
4. COMPARATIVE MATRIX: ORACLE PROFILES vs MYSQL 8.0 vs APPLICATION-LAYER
--------------------------------------------------------------------------------
| Security Feature          | Oracle Database Profiles      | MySQL 8.0 Community Server     | GlobalTrust App-Layer (Node.js) |
|---------------------------|-------------------------------|--------------------------------|---------------------------------|
| Architectural Object      | Named Profile (Reusable)      | Per-User Account Attributes    | Centralized Policy Config Table |
| Password Expiration       | PASSWORD_LIFE_TIME (days)     | PASSWORD EXPIRE INTERVAL N DAY | ExpirationDays (Configurable)   |
| Grace Period              | PASSWORD_GRACE_TIME (days)    | None (Instant expiry/warning)  | Soft-warning & forced redirect  |
| Account Lockout           | FAILED_LOGIN_ATTEMPTS         | FAILED_LOGIN_ATTEMPTS (8.0.19+)| MaxFailedAttempts (Default: 5)  |
| Lockout Duration          | PASSWORD_LOCK_TIME (days/frac)| PASSWORD_LOCK_TIME (days)      | LockoutDurationMinutes (15 min) |
| Password History Count    | PASSWORD_REUSE_MAX            | PASSWORD HISTORY N             | HistoryLimit (Last 5 hashes)    |
| Password History Interval | PASSWORD_REUSE_TIME (days)    | PASSWORD REUSE INTERVAL N DAY  | PasswordHistory table timestamp |
| Complexity Verification   | PL/SQL Verify Function        | validate_password component    | Comprehensive Regex + Blacklist |
| Idle Session Timeout      | IDLE_TIME (Kernel enforced)   | wait_timeout / interactive_tm  | JWT / Session Token Expiry      |
| Concurrent Sessions       | SESSIONS_PER_USER             | max_user_connections           | Session Versioning / Token Rev. |
| Scope of Protection       | DB Connections (SQL*Net)      | DB Connections (Port 3306)     | End-User Banking Customers & UI |

--------------------------------------------------------------------------------
5. KEY ARCHITECTURAL TAKEAWAY FOR DSP SYLLABUS:
--------------------------------------------------------------------------------
Database profiles protect direct database connections made by human database users
and DBAs. However, in a 3-tier web application (Client -> Node.js -> MySQL), end-user
banking customers authenticate against the APPLICATION server, not the database server.
Therefore:
1. Native DB policies protect internal service accounts (e.g. bank_app_user, bank_sec_admin).
2. Application-layer policies protect the hundreds of thousands of retail banking users.
3. A defense-in-depth architecture applies security controls at BOTH tiers.
*/
