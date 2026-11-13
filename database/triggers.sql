USE banking_management_system;

DELIMITER //

-- 1. Trigger to validate transactions before insert
CREATE TRIGGER VerifyTransactionBeforeInsert
BEFORE INSERT ON Transaction
FOR EACH ROW
BEGIN
    DECLARE v_Balance DECIMAL(15, 2);
    
    IF NEW.TransactionType IN ('Withdrawal', 'Transfer_Out') THEN
        SELECT Balance INTO v_Balance FROM Account WHERE AccountNo = NEW.AccountNo;
        
        IF v_Balance < NEW.Amount THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance for this transaction.';
        END IF;
    END IF;
END //

-- 2. Trigger to automatically update account balance after transactions
CREATE TRIGGER UpdateBalanceAfterTransaction
AFTER INSERT ON Transaction
FOR EACH ROW
BEGIN
    IF NEW.TransactionType IN ('Deposit', 'Transfer_In') THEN
        UPDATE Account 
        SET Balance = Balance + NEW.Amount 
        WHERE AccountNo = NEW.AccountNo;
    ELSEIF NEW.TransactionType IN ('Withdrawal', 'Transfer_Out') THEN
        UPDATE Account 
        SET Balance = Balance - NEW.Amount 
        WHERE AccountNo = NEW.AccountNo;
    END IF;
END //

-- 3. Trigger to maintain transaction logs
CREATE TRIGGER LogTransaction
AFTER INSERT ON Transaction
FOR EACH ROW
BEGIN
    INSERT INTO TransactionLog (TransactionID, AccountNo, Action, Details)
    VALUES (NEW.TransactionID, NEW.AccountNo, NEW.TransactionType, CONCAT('Amount: ', NEW.Amount, ' processed.'));
END //

DELIMITER ;
