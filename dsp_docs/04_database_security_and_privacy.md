# Database Security, Data Privacy & Audit Logging

## 1. Database-Level Least Privilege & Account Separation

To prevent global superuser exposure, the application runs on a dedicated restricted MySQL user, completely distinct from the database administrator.

```mermaid
graph TD
    subgraph "MySQL Database Engine (Port 3306)"
        AppPool[Node.js Connection Pool] -->|Authenticates as| AppUser[bank_app_user@localhost]
        DBA[Database Administrator] -->|Authenticates as| SecAdmin[bank_sec_admin@localhost]
        
        AppUser -->|Permitted| DML[SELECT, INSERT, UPDATE, EXECUTE]
        AppUser -.->|Explicitly Denied| DDL[DROP, ALTER, CREATE, GRANT, SUPER]
        
        SecAdmin -->|Permitted| AdminOps[Schema Migrations, Backups, User Grants]
    end
```

### SQL User Definitions & Grants:
* **Restricted Application User (`bank_app_user`):**
  ```sql
  CREATE USER 'bank_app_user'@'localhost' IDENTIFIED BY 'BankApp@Secure2026!';
  GRANT SELECT, INSERT, UPDATE, EXECUTE ON banking_management_system.* TO 'bank_app_user'@'localhost';
  REVOKE DROP, ALTER, CREATE, GRANT OPTION ON banking_management_system.* FROM 'bank_app_user'@'localhost';
  ```
* **Database Security Administrator (`bank_sec_admin`):**
  ```sql
  CREATE USER 'bank_sec_admin'@'localhost' IDENTIFIED BY 'DbaSecAdmin@GlobalTrust2026!'
      PASSWORD EXPIRE INTERVAL 90 DAY
      FAILED_LOGIN_ATTEMPTS 5
      PASSWORD_LOCK_TIME 1;
  GRANT ALL PRIVILEGES ON banking_management_system.* TO 'bank_sec_admin'@'localhost';
  ```

---

## 2. SQL Scripts & Execution Order

To set up or restore the banking database, scripts must be executed in this exact sequence:

1. **`database/schema.sql`**: Creates core relational entities (`Branch`, `Employee`, `Customer`, `Account`, `Transaction`, `Loan`, `TransactionLog`).
2. **`database/dsp_upgrade_migration.sql`**: Adds DSP security tables (`PasswordPolicyConfig`, `UserSecurity`, `PasswordHistory`, `PasswordResetToken`, `SecurityAuditLog`, `CustomerPrivacyProfile`), secure views, and employee seed records without data loss.
3. **`database/procedures.sql`**: Installs stored procedures (`DepositMoney`, `WithdrawMoney`, `TransferFunds`, `ProcessLoanApplication`).
4. **`database/triggers.sql`**: Installs integrity triggers (`VerifyTransactionBeforeInsert`, `UpdateBalanceAfterTransaction`, `LogTransaction`).
5. **`database/views.sql`**: Installs reporting views.
6. **`database/indexes.sql`**: Adds B-Tree indexes for fast indexing on `Account(CustomerID)`, `Transaction(AccountNo, TransactionDate)`, etc.
7. **`database/01_db_users_and_privileges.sql`**: Creates `bank_app_user` and `bank_sec_admin` and applies least privilege `GRANT` and `REVOKE`.
8. **`database/02_native_mysql_profiles.sql`**: Demonstrates native MySQL 8.0 password attributes.
9. **`backend/scripts/run_migrations.js`**: Automatically seeds administrator, employee, and synchronized credentials for all 102 existing customers.

---

## 3. Transaction Isolation & Overdraft Prevention

### ACID Fund Transfers with Row-Level Locking (`TransferFunds`)
To eliminate race conditions and double-spending, transfers execute inside an atomic transaction:
```sql
START TRANSACTION;
SELECT Balance INTO v_Balance FROM Account WHERE AccountNo = p_FromAccountNo FOR UPDATE;
IF v_Balance < p_Amount THEN
    ROLLBACK;
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient funds for transfer.';
ELSE
    INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description, ReferenceAccountNo)
    VALUES (p_FromAccountNo, 'Transfer_Out', p_Amount, ..., p_ToAccountNo);
    INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description, ReferenceAccountNo)
    VALUES (p_ToAccountNo, 'Transfer_In', p_Amount, ..., p_FromAccountNo);
    COMMIT;
END IF;
```
* **Atomicity:** Both debit and credit succeed together, or `ROLLBACK` restores the initial state.
* **Consistency:** Account balances cannot drop below zero.
* **Isolation:** `FOR UPDATE` exclusively locks the sender's account row until `COMMIT`.

### Database Integrity Constraints & Triggers
* **Account Check Constraint:** `CHECK (Balance >= 0)` rejects negative balances at the storage engine level.
* **BEFORE INSERT Trigger (`VerifyTransactionBeforeInsert`):** Validates that withdrawals or outgoing transfers do not exceed the available balance before any row insertion occurs.

---

## 4. Data Privacy, Masking & Encryption

### Conceptual Distinctions for Academic Demonstration:
* **Password Hashing:** One-way irreversible mathematical transformation (Bcrypt with salt). Used for credential verification. Cannot be decrypted.
* **Application-Layer Encryption:** Two-way reversible mathematical transformation using a secret key (AES-256-GCM). Used for confidential data storage (e.g., National ID / Tax ID).
* **Data Masking:** Dynamic presentation-layer obfuscation (e.g. `•••• •••• 1001`). Original data is stored in the database, but masked when presented to unauthorized or customer-facing views.
* **Access Control:** Server-side authorization determining which roles have access to raw, masked, or decrypted data.

### Implementation:
1. **Dynamic Server-Side Masking:**
   - Account Numbers: `•••• •••• 1001` (preserves last 4 characters for customer identification).
   - Phone Numbers: `••••••8888`.
   - Email Addresses: `ad***@gmail.com`.
2. **Authenticated Encryption (AES-256-GCM):**
   - 256-bit symmetric key configured via environment variable `ENCRYPTION_KEY`.
   - Generates 96-bit random IV and 128-bit authentication tag per encryption operation:
     `ivHex:authTagHex:ciphertextHex`.
   - Protects against ciphertext tampering and bit-flipping attacks.

---

## 5. Security Audit Logging Design

The `SecurityAuditLog` table maintains an immutable record of high-value actions:

| Column | Data Type | Description |
| :--- | :--- | :--- |
| **EventID** | BIGINT AUTO_INCREMENT | Unique sequential event identifier (Primary Key) |
| **Timestamp** | TIMESTAMP | Exact UTC timestamp of the event |
| **ActorID** | VARCHAR(100) | Email or user identity responsible for the action |
| **ActorRole** | VARCHAR(50) | Role at execution time (`Admin`, `Employee`, `Customer`) |
| **ActionType** | VARCHAR(100) | Event type (`AUTH_LOGIN_SUCCESS`, `TRANSFER_FUNDS`, `POLICY_UPDATE`, etc.) |
| **TargetResource** | VARCHAR(150) | Target entity (`Account:ACC1001`, `UserSecurity:2`) |
| **Outcome** | ENUM | Status: `SUCCESS`, `FAILURE`, or `WARNING` |
| **IPAddress** | VARCHAR(45) | Client IP address |
| **UserAgent** | VARCHAR(255) | Client browser / device user agent |
| **Details** | TEXT | Sanitized metadata (Secrets and passwords strictly scrubbed) |

* **Non-Recursive Auditing:** Audit logging helper functions operate outside audit interceptors to prevent infinite recursive writes.
* **Protection:** Ordinary users and employees possess zero DDL or DML write access to audit logs.
