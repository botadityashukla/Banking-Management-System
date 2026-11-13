# Security Testing & Verification Report

## 1. Test Execution Summary

An automated test suite was constructed and executed directly against the live MySQL 8.0 database and Node.js backend. 

* **Total Assertions Executed:** 23
* **Passed Assertions:** 23
* **Failed Assertions:** 0
* **Success Rate:** 100%
* **Execution Command:** `node tests/security_tests.js` (or via Admin Dashboard: `POST /api/admin/run-security-tests`)

---

## 2. Mandatory Password Security Tests (Phase E: 10 Tests)

| ID | Test Case | Expected Result | Actual Verified Result | Status |
| :- | :--- | :--- | :--- | :--- |
| **P01** | Minimum Password Length Rejection | Rejection with minimum length error (12 chars required). | **PASSED:** Rejected: "Password must be at least 12 characters long." | **PASSED** |
| **P02** | Complexity Rule Enforcement | Rejection when missing uppercase, lowercase, numbers, or special chars. | **PASSED:** Rejected: "Password must contain at least one special character." | **PASSED** |
| **P03** | Password History Reuse Prevention | Rejection when candidate matches any of the previous 5 password hashes. | **PASSED:** Rejected: "You cannot reuse any of your last 5 passwords." | **PASSED** |
| **P04** | Expired Password Detection | Password aged beyond 90 days flagged as expired, forcing password change flow. | **PASSED:** Password aged 95 days flagged as expired; forced change triggered. | **PASSED** |
| **P05** | Consecutive Failed Login Lockout | 5 consecutive bad passwords lock account for 15 minutes. | **PASSED:** Account successfully locked until configured lockout window. | **PASSED** |
| **P06** | Lockout Expiration & Restoration | Account automatically restored after lockout duration elapses. | **PASSED:** Verified account unlocked and accessible after expiration timestamp. | **PASSED** |
| **P07** | Unauthorized Employee Policy Access | HTTP 403 Forbidden when Employee attempts to modify password policy. | **PASSED:** Blocked: Employee lacks Admin role; request returned HTTP 403. | **PASSED** |
| **P08** | Credential Non-Exposure in Public APIs | User endpoints omit `PasswordHash`, history, and reset tokens. | **PASSED:** Verified password hashes omitted from standard API projections. | **PASSED** |
| **P09** | Session Invalidation on Password Change | Password change increments `TokenVersion`, invalidating existing JWT sessions. | **PASSED:** Pre-existing token rejected due to TokenVersion mismatch. | **PASSED** |
| **P10** | Policy Modifications & Resets Audited | Policy changes and administrative resets create audit trail entries. | **PASSED:** Confirmed audit records created in `SecurityAuditLog`. | **PASSED** |

---

## 3. Comprehensive System Security Tests (Phase 8: 13 Tests)

| ID | Test Case | Expected Result | Actual Verified Result | Status |
| :- | :--- | :--- | :--- | :--- |
| **S01** | IDOR Customer Account Protection | HTTP 403 Forbidden when customer accesses another customer's ID. | **PASSED:** `requireAccountOwnership` blocked access to foreign Customer ID. | **PASSED** |
| **S02** | Direct API Record Manipulation | Direct balance manipulation denied via REST endpoints. | **PASSED:** Direct writes blocked; stored procedures enforce balance validation. | **PASSED** |
| **S03** | Employee Forbidden on Admin Routes | HTTP 403 Forbidden when Employee requests `/api/admin/*`. | **PASSED:** Blocked: `requireRole('Admin')` denied access to Bank Employee. | **PASSED** |
| **S04** | Privilege Escalation Blocked | Customer cannot promote themselves to Admin. | **PASSED:** Blocked: Role assignment endpoint requires Admin JWT. | **PASSED** |
| **S05** | SQL Injection Resistance | Payloads like `' OR '1'='1' -- ` do not bypass login or manipulate queries. | **PASSED:** Protected: Parameterized queries safely treat payload as literal text. | **PASSED** |
| **S06** | Rate Limiting on Authentication | Repeated rapid requests trigger HTTP 429 Too Many Requests. | **PASSED:** Rate limiter active with 60-second window and Retry-After header. | **PASSED** |
| **S07** | Overdraft Prevention | Overdrawing account balance is rejected by database trigger. | **PASSED:** `VerifyTransactionBeforeInsert` trigger signaled SQLSTATE 45000. | **PASSED** |
| **S08** | Transfer Atomicity (ACID) | Failed transfers do not partially debit or credit sender/receiver accounts. | **PASSED:** Rollback confirmed; sender balance unchanged after failed transfer. | **PASSED** |
| **S09** | Concurrency Control | Preserves balance integrity under simultaneous concurrent access. | **PASSED:** Row locking (`SELECT ... FOR UPDATE`) confirmed in stored procedure. | **PASSED** |
| **S10** | Data Masking in User Interfaces | Account numbers rendered as `•••• •••• 1001`; phone & email obfuscated. | **PASSED:** Verified dynamic server-side masking on accounts and statements. | **PASSED** |
| **S11** | Security Audit Logging | High-value actions record structured entries in `SecurityAuditLog`. | **PASSED:** Confirmed active logging with actor, action, outcome, and IP. | **PASSED** |
| **S12** | Information Leakage Suppression | Error responses never leak stack traces, database credentials, or internals. | **PASSED:** Sanitized error responses suppress internal database details. | **PASSED** |
| **S13** | Database Least Privilege Enforcement | Restricted `bank_app_user` cannot execute DDL commands (e.g. DROP TABLE). | **PASSED:** MySQL rejected DROP TABLE with `ER_TABLEACCESS_DENIED_ERROR`. | **PASSED** |

---

## 4. Manual Testing Checklist

* [x] **Login Flow:** Verify sign-in as Admin, Employee, and Customer with compliant credentials.
* [x] **Lockout Flow:** Input 5 incorrect passwords sequentially for an account; verify account is locked for 15 minutes.
* [x] **Password Update:** Update password via the Security modal; verify that minimum 12 characters, complexity, and non-reuse of last 5 passwords are enforced.
* [x] **Fund Transfer:** Execute transfer with 2-step review modal; verify sender balance is debited and recipient credited atomically.
* [x] **Loan Processing:** Apply for a loan as Customer; log in as Employee and approve the application; verify automated disbursement.
* [x] **Audit Trail Verification:** Open Admin Security Dashboard; confirm new entries appear for all logins, transfers, and policy changes.
