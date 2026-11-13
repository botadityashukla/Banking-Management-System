USE banking_management_system;

-- Index for Account lookup
CREATE INDEX idx_account_customer ON Account(CustomerID);

-- Index for Transaction lookup
CREATE INDEX idx_transaction_account ON Transaction(AccountNo);
CREATE INDEX idx_transaction_date ON Transaction(TransactionDate);

-- Index for Customer lookup
CREATE INDEX idx_customer_email ON Customer(Email);

-- Index for Loan lookup
CREATE INDEX idx_loan_customer ON Loan(CustomerID);
CREATE INDEX idx_loan_status ON Loan(Status);
