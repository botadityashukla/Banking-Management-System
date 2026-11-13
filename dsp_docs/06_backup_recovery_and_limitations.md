# Backup, Disaster Recovery, Limitations & Conclusion

## 1. Safe Database Backup Procedure (Phase 9)

In a financial system, backups must be transactionally consistent and executed without blocking live customer deposits or withdrawals.

### Consistent Online Logical Backup (mysqldump)
Run the following PowerShell command as the security administrator:

```powershell
mysqldump -h localhost -u bank_sec_admin -p `
  --single-transaction `
  --quick `
  --routines `
  --triggers `
  --views `
  --default-character-set=utf8mb4 `
  --result-file="backup_banking_management_system_$(Get-Date -Format 'yyyyMMdd_HHmmss').sql" `
  banking_management_system
```

### Explanation of Critical Backup Flags:
* `--single-transaction`: Sets transaction isolation mode to `REPEATABLE READ`, taking a point-in-time snapshot without acquiring table read locks (`FLUSH TABLES WITH READ LOCK`). Retail customers can continue performing banking transactions during the backup window.
* `--quick`: Instructs mysqldump to retrieve rows one by one rather than buffering entire tables in RAM, preventing memory exhaustion.
* `--routines & --triggers & --views`: Ensures stored procedures (`TransferFunds`), integrity triggers (`VerifyTransactionBeforeInsert`), and secure views (`View_Masked_CustomerAccountSummary`) are fully preserved.
* `--default-character-set=utf8mb4`: Prevents character corruption in customer names, addresses, and descriptions.

---

## 2. Restoration & Verification on an Isolated Sandbox Database

**Rule:** Never restore a backup directly over the active database without verifying its structural and transactional integrity in an isolated sandbox.

### Step-by-Step Restoration Process:

1. **Create an Isolated Verification Sandbox:**
   ```sql
   CREATE DATABASE IF NOT EXISTS banking_recovery_test_sandbox;
   ```

2. **Restore Logical Backup into the Sandbox:**
   ```powershell
   mysql -h localhost -u bank_sec_admin -p banking_recovery_test_sandbox < "backup_banking_management_system_YYYYMMDD_HHMMSS.sql"
   ```

3. **Verify Table Row Counts & Structural Integrity:**
   ```sql
   USE banking_recovery_test_sandbox;

   SELECT 'Customer' AS TableName, COUNT(*) AS RowCount FROM Customer
   UNION ALL
   SELECT 'Account', COUNT(*) FROM Account
   UNION ALL
   SELECT 'Transaction', COUNT(*) FROM Transaction
   UNION ALL
   SELECT 'SecurityAuditLog', COUNT(*) FROM SecurityAuditLog;

   -- Verify Stored Procedures
   SHOW PROCEDURE STATUS WHERE Db = 'banking_recovery_test_sandbox';

   -- Verify Triggers
   SHOW TRIGGERS FROM banking_recovery_test_sandbox;
   ```

4. **Decommission Sandbox After Verification:**
   ```sql
   DROP DATABASE IF EXISTS banking_recovery_test_sandbox;
   ```

---

## 3. Backup Security & Protection Controls

Logical and physical backups contain unencrypted customer records and balances:
1. **Encryption at Rest:** Backups must be encrypted immediately after creation using AES-256 (e.g. OpenSSL or GPG) before offsite replication.
2. **Access Control (Least Privilege):** Restrict filesystem permissions using Windows Access Control Lists (`icacls`) so only the database service account can access backup directories.
3. **Audit Logging:** Record an entry in `SecurityAuditLog` whenever a backup or restore job is initiated.
4. **Air-Gapped Offsite Storage:** Protect against ransomware by replicating encrypted backups to write-once-read-many (WORM) storage.

---

## 4. Academic Deployment Limitations & Production Improvements

While this project satisfies all requirements of the DSP syllabus, an enterprise cloud-scale banking deployment would incorporate additional controls:

| Security Domain | Current Academic Deployment | Enterprise Production Enhancement |
| :--- | :--- | :--- |
| **Key Management** | Symmetric key stored in environment variables (`.env`) | Hardware Security Module (HSM) or cloud KMS (AWS KMS, Azure Key Vault) with automated key rotation. |
| **Transport Layer** | Local HTTP / HTTPS self-signed | Enforce TLS 1.3 with Certificate Authority pinning and mTLS (Mutual TLS) between microservices. |
| **Audit Log Storage** | MySQL table (`SecurityAuditLog`) | Streaming audit logs to append-only WORM storage (e.g. Splunk, AWS CloudTrail, Elasticsearch) to guarantee forensic immutability against compromised DBAs. |
| **Database Encryption** | Application-layer encryption for KYC fields (AES-256-GCM) | Transparent Data Encryption (TDE) for tablespace-level encryption at rest. |
| **Multi-Factor Auth** | Password policy engine with lockout | Time-based One-Time Passwords (TOTP / RFC 6238) or FIDO2 WebAuthn hardware keys. |

---

## 5. Conclusion

This project demonstrates the practical application of **Database Security and Privacy (DSP)** concepts within an active financial software architecture. By preserving 100% of the original DBMS project's normalized schema, stored procedures, triggers, and accounts, the upgrade illustrates how legacy systems can be hardened against real-world vulnerabilities.

Through **Bcrypt credential storage**, **dynamic password policy governance**, **server-side RBAC**, **MySQL least privilege service accounts**, **ACID row-level locking concurrency control**, **authenticated AES-256-GCM encryption**, **dynamic data masking**, and **tamper-resistant audit logging**, the system establishes a comprehensive defense-in-depth model that satisfies academic rigor and financial industry standards.
