USE banking_management_system;

DELIMITER //

-- 1. Deposit Money Procedure
CREATE PROCEDURE DepositMoney(
    IN p_AccountNo VARCHAR(20),
    IN p_Amount DECIMAL(15, 2),
    IN p_Description VARCHAR(255)
)
BEGIN
    INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description)
    VALUES (p_AccountNo, 'Deposit', p_Amount, p_Description);
END //

-- 2. Withdraw Money Procedure
CREATE PROCEDURE WithdrawMoney(
    IN p_AccountNo VARCHAR(20),
    IN p_Amount DECIMAL(15, 2),
    IN p_Description VARCHAR(255)
)
BEGIN
    -- Validation is handled by BEFORE INSERT trigger
    INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description)
    VALUES (p_AccountNo, 'Withdrawal', p_Amount, p_Description);
END //

-- 3. Transfer Funds Procedure (Uses START TRANSACTION, COMMIT, ROLLBACK)
CREATE PROCEDURE TransferFunds(
    IN p_FromAccountNo VARCHAR(20),
    IN p_ToAccountNo VARCHAR(20),
    IN p_Amount DECIMAL(15, 2),
    IN p_Description VARCHAR(255)
)
BEGIN
    DECLARE v_Balance DECIMAL(15, 2);
    
    -- Transaction to ensure ACID properties
    START TRANSACTION;
    
    SELECT Balance INTO v_Balance FROM Account WHERE AccountNo = p_FromAccountNo FOR UPDATE;
    
    IF v_Balance < p_Amount THEN
        ROLLBACK;
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient funds for transfer.';
    ELSE
        -- Insert withdrawal for sender
        INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description, ReferenceAccountNo)
        VALUES (p_FromAccountNo, 'Transfer_Out', p_Amount, CONCAT('Transfer to ', p_ToAccountNo, ': ', p_Description), p_ToAccountNo);
        
        -- Insert deposit for receiver
        INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description, ReferenceAccountNo)
        VALUES (p_ToAccountNo, 'Transfer_In', p_Amount, CONCAT('Transfer from ', p_FromAccountNo, ': ', p_Description), p_FromAccountNo);
        
        COMMIT;
    END IF;
END //

-- 4. Loan Application Processing Procedure
CREATE PROCEDURE ProcessLoanApplication(
    IN p_LoanID INT,
    IN p_Status ENUM('Approved', 'Rejected'),
    IN p_AccountNo VARCHAR(20) -- Account to deposit the loan amount if approved
)
BEGIN
    DECLARE v_CurrentStatus VARCHAR(20);
    DECLARE v_Amount DECIMAL(15, 2);
    
    SELECT Status, Amount INTO v_CurrentStatus, v_Amount FROM Loan WHERE LoanID = p_LoanID;
    
    IF v_CurrentStatus != 'Pending' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Loan is not in Pending status.';
    ELSE
        UPDATE Loan SET Status = p_Status WHERE LoanID = p_LoanID;
        
        IF p_Status = 'Approved' THEN
            -- Deposit loan amount into account
            INSERT INTO Transaction (AccountNo, TransactionType, Amount, Description)
            VALUES (p_AccountNo, 'Deposit', v_Amount, CONCAT('Loan Disbursement (LoanID: ', p_LoanID, ')'));
            
            UPDATE Loan SET Status = 'Active' WHERE LoanID = p_LoanID;
        END IF;
    END IF;
END //

DELIMITER ;
