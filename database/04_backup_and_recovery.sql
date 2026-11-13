-- ==============================================================================
-- DATABASE SECURITY AND PRIVACY (DSP): BACKUP & RECOVERY PROCEDURES
-- Script: 04_backup_and_recovery.sql
-- Topic: Secure Database Backup, Integrity Verification, and Disaster Recovery
-- ==============================================================================

/*
--------------------------------------------------------------------------------
1. SAFE BACKUP PROCEDURE (POWERSHELL / CLI COMMANDS)
--------------------------------------------------------------------------------

Perform a consistent, single-transaction logical backup using mysqldump:
Run this command from PowerShell:

mysqldump -h localhost -u bank_sec_admin -p `
  --single-transaction `
  --quick `
  --routines `
  --triggers `
  --views `
  --default-character-set=utf8mb4 `
  --result-file="backup_banking_management_system_$(Get-Date -Format 'yyyyMMdd_HHmmss').sql" `
  banking_management_system

Explanation of flags:
- --single-transaction: Uses repeatable-read isolation so live transactions are not blocked.
- --quick: Streams rows directly without buffering large tables into RAM.
- --routines & --triggers & --views: Guarantees stored procedures, triggers, and views are backed up.
- --default-character-set=utf8mb4: Prevents character corruption for names and descriptions.

--------------------------------------------------------------------------------
2. RESTORATION & RECOVERY VERIFICATION ON A SEPARATE TEST DATABASE
--------------------------------------------------------------------------------
NEVER restore directly over a production database without verifying integrity first.
Test recovery into a dedicated verification database:
*/

-- Step A: Create isolated test sandbox database
CREATE DATABASE IF NOT EXISTS banking_recovery_test_sandbox;

-- Step B: Restore from backup file into test database (CLI command):
-- mysql -h localhost -u bank_sec_admin -p banking_recovery_test_sandbox < "backup_banking_management_system_YYYYMMDD_HHMMSS.sql"

-- Step C: Post-Restoration Integrity Verification Query
USE banking_recovery_test_sandbox;

-- Verify table counts match original
SELECT 
    'Customer' AS TableName, COUNT(*) AS RowCount FROM Customer
UNION ALL
SELECT 'Account', COUNT(*) FROM Account
UNION ALL
SELECT 'Transaction', COUNT(*) FROM Transaction
UNION ALL
SELECT 'SecurityAuditLog', COUNT(*) FROM SecurityAuditLog;

-- Verify stored procedures restored
SHOW PROCEDURE STATUS WHERE Db = 'banking_recovery_test_sandbox';

-- Verify triggers restored
SHOW TRIGGERS FROM banking_recovery_test_sandbox;

-- Step D: Clean up sandbox after successful test verification
DROP DATABASE IF EXISTS banking_recovery_test_sandbox;

/*
--------------------------------------------------------------------------------
3. BACKUP FILE PROTECTION AND PRIVACY CONTROLS
--------------------------------------------------------------------------------
Backup files contain unencrypted customer records, account balances, and security tables!
Mandatory security controls:
1. Encrypt backups at rest using AES-256 (e.g. GPG or OpenSSL) before offsite transfer.
2. Restrict file permissions using Windows ACLs (ICACLS) so only the DBA service account can read.
3. Maintain immutable audit logs whenever a backup or restore is performed.
4. Enforce Retention Policy: Automatically purge backups older than the compliance window.
*/
