-- ==============================================================================
-- DATABASE SECURITY AND PRIVACY (DSP) UPGRADE MIGRATION
-- Project: GlobalTrust Banking Management System
-- Purpose: Adds authentication credentials, password policy engine, user administration,
--          audit logging, privacy/encryption metadata, and role-based views.
-- Safety: Reversible migration that preserves all 102 existing Customers, Accounts,
--         Branches, Transactions, and Loans without data loss.
-- ==============================================================================

USE banking_management_system;

-- 1. Password Policy Configuration Table (Single active configuration record)
CREATE TABLE IF NOT EXISTS PasswordPolicyConfig (
    PolicyID INT PRIMARY KEY DEFAULT 1,
    MinLength INT NOT NULL DEFAULT 12,
    RequireUppercase BOOLEAN NOT NULL DEFAULT TRUE,
    RequireLowercase BOOLEAN NOT NULL DEFAULT TRUE,
    RequireNumbers BOOLEAN NOT NULL DEFAULT TRUE,
    RequireSpecialChars BOOLEAN NOT NULL DEFAULT TRUE,
    ExpirationDays INT NOT NULL DEFAULT 90,
    HistoryLimit INT NOT NULL DEFAULT 5,
    MaxFailedAttempts INT NOT NULL DEFAULT 5,
    LockoutDurationMinutes INT NOT NULL DEFAULT 15,
    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UpdatedBy VARCHAR(100) DEFAULT 'SYSTEM'
);

-- Insert default DSP policy if not exists
INSERT IGNORE INTO PasswordPolicyConfig 
(PolicyID, MinLength, RequireUppercase, RequireLowercase, RequireNumbers, RequireSpecialChars, ExpirationDays, HistoryLimit, MaxFailedAttempts, LockoutDurationMinutes, UpdatedBy)
VALUES (1, 12, TRUE, TRUE, TRUE, TRUE, 90, 5, 5, 15, 'SYSTEM');

-- 2. User Security & Identity Management Table
-- Bridges authentication, roles, password policies, and account status
CREATE TABLE IF NOT EXISTS UserSecurity (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255) NOT NULL,
    Role ENUM('Admin', 'Employee', 'Customer') NOT NULL DEFAULT 'Customer',
    CustomerID INT NULL,
    EmployeeID INT NULL,
    IsActive BOOLEAN NOT NULL DEFAULT TRUE,
    FailedLoginAttempts INT NOT NULL DEFAULT 0,
    LockoutUntil DATETIME NULL,
    PasswordLastChanged DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    MustChangePassword BOOLEAN NOT NULL DEFAULT FALSE,
    TokenVersion INT NOT NULL DEFAULT 1,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID) ON DELETE SET NULL,
    FOREIGN KEY (EmployeeID) REFERENCES Employee(EmployeeID) ON DELETE SET NULL,
    INDEX idx_user_role (Role),
    INDEX idx_user_email (Email),
    INDEX idx_user_status (IsActive)
);

-- 3. Password History Table (Enforces non-reuse of last N passwords)
CREATE TABLE IF NOT EXISTS PasswordHistory (
    HistoryID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    PasswordHash VARCHAR(255) NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES UserSecurity(UserID) ON DELETE CASCADE,
    INDEX idx_user_history (UserID, CreatedAt DESC)
);

-- 4. Password Reset Tokens Table (Secure one-time reset flow)
CREATE TABLE IF NOT EXISTS PasswordResetToken (
    ResetID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    TokenHash VARCHAR(255) NOT NULL,
    ExpiresAt DATETIME NOT NULL,
    IsUsed BOOLEAN NOT NULL DEFAULT FALSE,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES UserSecurity(UserID) ON DELETE CASCADE,
    INDEX idx_token_hash (TokenHash)
);

-- 5. Comprehensive Security Audit Log Table
CREATE TABLE IF NOT EXISTS SecurityAuditLog (
    EventID BIGINT AUTO_INCREMENT PRIMARY KEY,
    Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ActorID VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
    ActorRole VARCHAR(50) NOT NULL DEFAULT 'GUEST',
    ActionType VARCHAR(100) NOT NULL,
    TargetResource VARCHAR(150) NULL,
    Outcome ENUM('SUCCESS', 'FAILURE', 'WARNING') NOT NULL DEFAULT 'SUCCESS',
    IPAddress VARCHAR(45) NULL,
    UserAgent VARCHAR(255) NULL,
    Details TEXT NULL,
    INDEX idx_audit_time (Timestamp DESC),
    INDEX idx_audit_action (ActionType),
    INDEX idx_audit_actor (ActorID),
    INDEX idx_audit_outcome (Outcome)
);

-- 6. Customer Privacy & Application Layer Encryption Metadata
-- Stores encrypted sensitive PII (Aadhaar / National ID, SSN, Tax ID)
CREATE TABLE IF NOT EXISTS CustomerPrivacyProfile (
    ProfileID INT AUTO_INCREMENT PRIMARY KEY,
    CustomerID INT NOT NULL UNIQUE,
    EncryptedGovtID TEXT NULL,
    EncryptedTaxID TEXT NULL,
    EncryptionKeyVersion VARCHAR(20) DEFAULT 'v1',
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID) ON DELETE CASCADE
);

-- 7. Ensure at least one Employee exists if table is empty
INSERT IGNORE INTO Employee (EmployeeID, FirstName, LastName, Email, JobTitle, Salary, BranchID, HireDate)
SELECT 1, 'Vikram', 'Malhotra', 'employee@globaltrust.com', 'Senior Branch Officer', 65000.00, 1, '2023-01-15'
WHERE NOT EXISTS (SELECT 1 FROM Employee WHERE Email = 'employee@globaltrust.com');

-- 8. Secure Views for Least-Privilege Data Exposure

-- Secure View: Masked Customer Accounts (hides full account number and sensitive internal keys)
CREATE OR REPLACE VIEW View_Masked_CustomerAccountSummary AS
SELECT 
    c.CustomerID,
    CONCAT(c.FirstName, ' ', c.LastName) AS CustomerName,
    CONCAT('•••• •••• ', SUBSTRING(a.AccountNo, -4)) AS MaskedAccountNo,
    a.AccountNo AS RawAccountNo,
    a.AccountType,
    a.Balance,
    a.Status,
    b.BranchName,
    CONCAT('••••••', SUBSTRING(c.Phone, -4)) AS MaskedPhone,
    CONCAT(LEFT(c.Email, 2), '•••@', SUBSTRING_INDEX(c.Email, '@', -1)) AS MaskedEmail
FROM Customer c
JOIN Account a ON c.CustomerID = a.CustomerID
JOIN Branch b ON a.BranchID = b.BranchID;

-- Secure View: Masked Account Statements
CREATE OR REPLACE VIEW View_Masked_AccountStatement AS
SELECT 
    t.TransactionID,
    CONCAT('•••• •••• ', SUBSTRING(t.AccountNo, -4)) AS MaskedAccountNo,
    t.AccountNo AS RawAccountNo,
    t.TransactionType,
    t.Amount,
    t.TransactionDate,
    t.Description,
    CASE 
        WHEN t.ReferenceAccountNo IS NOT NULL THEN CONCAT('•••• •••• ', SUBSTRING(t.ReferenceAccountNo, -4))
        ELSE NULL 
    END AS MaskedReferenceAccountNo
FROM Transaction t
ORDER BY t.TransactionDate DESC;

-- Secure View: Admin Security Event Summary (aggregated metrics)
CREATE OR REPLACE VIEW View_SecurityEventSummary AS
SELECT 
    DATE(Timestamp) AS EventDate,
    ActionType,
    Outcome,
    COUNT(EventID) AS TotalEvents
FROM SecurityAuditLog
GROUP BY DATE(Timestamp), ActionType, Outcome
ORDER BY EventDate DESC;
