USE banking_management_system;

-- 1. Customers with highest balances
SELECT 
    c.CustomerID,
    CONCAT(c.FirstName, ' ', c.LastName) AS CustomerName,
    SUM(a.Balance) AS TotalBalance
FROM 
    Customer c
JOIN 
    Account a ON c.CustomerID = a.CustomerID
GROUP BY 
    c.CustomerID, CustomerName
ORDER BY 
    TotalBalance DESC
LIMIT 10;

-- 2. Loan summary reports (Total loan amount by type)
SELECT 
    LoanType,
    COUNT(LoanID) AS NumberOfLoans,
    SUM(Amount) AS TotalLoanAmount,
    AVG(InterestRate) AS AverageInterestRate
FROM 
    Loan
WHERE 
    Status IN ('Approved', 'Active')
GROUP BY 
    LoanType;

-- 3. Branch-wise transaction reports
SELECT 
    b.BranchName,
    t.TransactionType,
    COUNT(t.TransactionID) AS TransactionCount,
    SUM(t.Amount) AS TotalAmount
FROM 
    Branch b
JOIN 
    Account a ON b.BranchID = a.BranchID
JOIN 
    Transaction t ON a.AccountNo = t.AccountNo
GROUP BY 
    b.BranchName, t.TransactionType
ORDER BY 
    b.BranchName, t.TransactionType;

-- 4. Monthly transaction statistics
SELECT 
    YEAR(TransactionDate) AS TxYear,
    MONTH(TransactionDate) AS TxMonth,
    TransactionType,
    COUNT(TransactionID) AS TotalTransactions,
    SUM(Amount) AS TotalAmountVolume
FROM 
    Transaction
GROUP BY 
    YEAR(TransactionDate), MONTH(TransactionDate), TransactionType
ORDER BY 
    TxYear DESC, TxMonth DESC, TransactionType;
