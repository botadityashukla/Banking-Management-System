USE banking_management_system;

-- 1. Account Statement View
CREATE OR REPLACE VIEW View_AccountStatement AS
SELECT 
    t.TransactionID,
    t.AccountNo,
    t.TransactionType,
    t.Amount,
    t.TransactionDate,
    t.Description,
    t.ReferenceAccountNo
FROM 
    Transaction t
ORDER BY 
    t.TransactionDate DESC;

-- 2. Customer Account Summary View
CREATE OR REPLACE VIEW View_CustomerAccountSummary AS
SELECT 
    c.CustomerID,
    CONCAT(c.FirstName, ' ', c.LastName) AS CustomerName,
    a.AccountNo,
    a.AccountType,
    a.Balance,
    a.Status,
    b.BranchName
FROM 
    Customer c
JOIN 
    Account a ON c.CustomerID = a.CustomerID
JOIN 
    Branch b ON a.BranchID = b.BranchID;

-- 3. Loan Reports View
CREATE OR REPLACE VIEW View_LoanReports AS
SELECT 
    l.LoanID,
    CONCAT(c.FirstName, ' ', c.LastName) AS CustomerName,
    l.LoanType,
    l.Amount,
    l.InterestRate,
    l.DurationMonths,
    l.Status,
    b.BranchName
FROM 
    Loan l
JOIN 
    Customer c ON l.CustomerID = c.CustomerID
JOIN 
    Branch b ON l.BranchID = b.BranchID;

-- 4. Branch Transaction Reports View
CREATE OR REPLACE VIEW View_BranchTransactionReports AS
SELECT 
    b.BranchID,
    b.BranchName,
    t.TransactionType,
    COUNT(t.TransactionID) AS TotalTransactions,
    SUM(t.Amount) AS TotalAmount
FROM 
    Branch b
JOIN 
    Account a ON b.BranchID = a.BranchID
JOIN 
    Transaction t ON a.AccountNo = t.AccountNo
GROUP BY 
    b.BranchID, b.BranchName, t.TransactionType;
