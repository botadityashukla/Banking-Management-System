# GlobalTrust Banking Management System (DSP Upgraded)

A full-stack, secure banking web application developed for **Database Management Systems (DBMS)** and upgraded for **Database Security and Privacy (DSP)**.

This project demonstrates database security, data confidentiality, privacy, authentication, authorization, tamper-resistant audit logging, and least privilege operations while retaining all 102 existing banking customers, accounts, branches, transactions, and loans.

---

## 1. Key DSP Security & Privacy Features

* **Configurable Password Policy Engine:**
  - Minimum 12 characters length policy.
  - Mandatory uppercase, lowercase, numeric, and special characters.
  - Automatic rejection of commonly used and compromised passphrases.
  - 90-day password expiration policy.
  - Password history prevention restricting reuse of the last 5 passwords.
  - Automatic account lockout for 15 minutes after 5 consecutive failed login attempts.
  - Forced password change flow upon administrative resets.
  - Secure credential storage using Bcrypt (10 salt rounds).
  - Instant session invalidation (JWT `TokenVersion` increment) on password updates or account deactivations.
* **Role-Based Access Control (RBAC):**
  - **Admin:** Password policy governance, user administration, security audit trail, and least privilege inspection.
  - **Bank Employee:** Branch operations, deposit/withdraw execution, and loan application review/approvals.
  - **Customer:** Least privilege access to personal accounts, balances, statements, transfers, and loans.
* **Insecure Direct Object Reference (IDOR) Protection:** Server-side ownership verification (`requireAccountOwnership`) ensures clients can only access their own financial records.
* **Database-Level Security (MySQL 8.0):**
  - Dedicated restricted application user (`bank_app_user`) granted ONLY `SELECT, INSERT, UPDATE, EXECUTE` on `banking_management_system`.
  - Dangerous DDL (`DROP, ALTER, CREATE, GRANT, SUPER`) denied at the MySQL server layer.
  - Separate security administrator account (`bank_sec_admin`) for DBA tasks.
  - Atomic transactions with row-level locking (`SELECT ... FOR UPDATE`) in `TransferFunds`.
  - Overdraft prevention via `BEFORE INSERT` triggers and table `CHECK (Balance >= 0)` constraints.
* **Data Privacy & Encryption:**
  - Dynamic server-side account masking (`•••• •••• 1001`), phone masking, and email obfuscation.
  - Application-layer authenticated symmetric encryption (AES-256-GCM) with 256-bit environment key for sensitive identification data.
* **Security Audit Logging:** Structured `SecurityAuditLog` records actor, role, action type, outcome, IP address, and sanitized metadata.
* **Academic Comparative Study:** Contrasts native MySQL 8.0 user attributes against Oracle Database Profiles (`CREATE PROFILE`) and SQL Server domain policies.

---

## 2. Academic Demonstration Credentials

| Role | Email / Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@globaltrust.com` | `Admin@Secure2026!` | Access Security & Privacy Governance Dashboard |
| **Bank Employee** | `employee@globaltrust.com` | `Employee@Bank2026!` | Access Branch Operations & Loan Processing |
| **Customer** | `aditya003shukla@gmail.com` | `Customer@Pass2026!` | Access Customer Dashboard (Account ACC1001) |
| *All Other 101 Customers* | *(Their registered email)* | `Customer@Pass2026!` | Access individual customer accounts |

---

## 3. Quick Start & Setup Instructions

### Prerequisites
* **Node.js** (v16+ recommended, tested on v24)
* **MySQL Server** (v8.0+ recommended, tested on v8.0.45)

### Step 1: Database Setup & Migrations
1. Open your MySQL client (e.g. MySQL Workbench or CLI).
2. Execute the base schema and migrations in order:
   - `database/schema.sql` (Creates base tables)
   - `database/dsp_upgrade_migration.sql` (Adds DSP security & audit tables)
   - `database/procedures.sql` (Creates stored procedures)
   - `database/triggers.sql` (Creates triggers)
   - `database/views.sql` (Creates views)
   - `database/indexes.sql` (Creates indexes)
   - `database/01_db_users_and_privileges.sql` (Creates restricted `bank_app_user` and `bank_sec_admin`)

3. Run the automated credential synchronization script:
   ```bash
   cd backend
   node scripts/run_migrations.js
   ```

### Step 2: Backend Configuration
Verify or update `backend/.env`:
```env
PORT=3000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=YourPassword
DB_NAME=banking_management_system
DB_APP_USER=bank_app_user
DB_APP_PASSWORD=BankApp@Secure2026!
JWT_SECRET=supersecret_jwt_key_banking_dsp_security_2026_aditya
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### Step 3: Start the Backend Server
```bash
cd backend
npm start
```
The server will start on `http://localhost:3000`.

### Step 4: Open the Frontend
Open `http://localhost:3000/index.html` in your browser. (The Express backend serves all static frontend assets directly).

---

## 4. Running the Automated Security Test Suite

The project includes an automated test suite verifying all 10 Password Security Tests and 13 System Security Tests (23 total assertions):

### Option A: From Command Line
```bash
cd backend
node tests/security_tests.js
```

### Option B: From the Admin Web Dashboard
1. Log into `http://localhost:3000/index.html` using the Admin credentials (`admin@globaltrust.com` / `Admin@Secure2026!`).
2. Navigate to the **Automated DSP Tests** tab.
3. Click **Execute All 23 Security Tests**. All 23 assertions will execute live and display green verified statuses.

---

## 5. DSP Documentation Index

Detailed academic documentation is organized inside the [`dsp_docs/`](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs) directory:

1. [Project Overview & Architecture](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs/01_project_overview_and_architecture.md)
2. [Security Gap Analysis & STRIDE Threat Model](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs/02_security_gap_analysis_and_threat_model.md)
3. [Password Policy Engine & Database User Administration](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs/03_password_policy_engine_and_user_admin.md)
4. [Database Security, Data Privacy & Audit Logging](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs/04_database_security_and_privacy.md)
5. [Security Testing & Verification Report](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs/05_security_testing_and_verification.md)
6. [Backup, Recovery Procedures & Academic Conclusion](file:///c:/Users/ADITYA%20SHUKLA/OneDrive/Desktop/Banking%20Management%20project/dsp_docs/06_backup_recovery_and_limitations.md)
