CREATE DATABASE IF NOT EXISTS banking_management_system;
USE banking_management_system;

-- 1. Branch Table
CREATE TABLE Branch (
    BranchID INT AUTO_INCREMENT PRIMARY KEY,
    BranchName VARCHAR(100) NOT NULL UNIQUE,
    City VARCHAR(100) NOT NULL,
    BranchAddress VARCHAR(255) NOT NULL,
    ContactNumber VARCHAR(20) NOT NULL
);

-- 2. Employee Table
CREATE TABLE Employee (
    EmployeeID INT AUTO_INCREMENT PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    LastName VARCHAR(50) NOT NULL,
    Email VARCHAR(100) NOT NULL UNIQUE,
    JobTitle VARCHAR(50) NOT NULL,
    Salary DECIMAL(10, 2) NOT NULL CHECK (Salary > 0),
    BranchID INT,
    HireDate DATE NOT NULL,
    FOREIGN KEY (BranchID) REFERENCES Branch(BranchID) ON DELETE SET NULL
);

-- 3. Customer Table
CREATE TABLE Customer (
    CustomerID INT AUTO_INCREMENT PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    LastName VARCHAR(50) NOT NULL,
    DOB DATE NOT NULL,
    Email VARCHAR(100) NOT NULL UNIQUE,
    Phone VARCHAR(20) NOT NULL UNIQUE,
    Address VARCHAR(255) NOT NULL,
    City VARCHAR(100) NOT NULL,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Account Table
CREATE TABLE Account (
    AccountNo VARCHAR(20) PRIMARY KEY,
    CustomerID INT NOT NULL,
    BranchID INT NOT NULL,
    AccountType ENUM('Savings', 'Current', 'Salary') NOT NULL,
    Balance DECIMAL(15, 2) NOT NULL DEFAULT 0.00 CHECK (Balance >= 0),
    Status ENUM('Active', 'Closed', 'Suspended') DEFAULT 'Active',
    OpenedDate DATE NOT NULL,
    FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID) ON DELETE CASCADE,
    FOREIGN KEY (BranchID) REFERENCES Branch(BranchID) ON DELETE RESTRICT
);

-- 5. Transaction Table
CREATE TABLE Transaction (
    TransactionID INT AUTO_INCREMENT PRIMARY KEY,
    AccountNo VARCHAR(20) NOT NULL,
    TransactionType ENUM('Deposit', 'Withdrawal', 'Transfer_In', 'Transfer_Out') NOT NULL,
    Amount DECIMAL(15, 2) NOT NULL CHECK (Amount > 0),
    TransactionDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    Description VARCHAR(255),
    ReferenceAccountNo VARCHAR(20) DEFAULT NULL, -- For transfers
    FOREIGN KEY (AccountNo) REFERENCES Account(AccountNo) ON DELETE CASCADE,
    FOREIGN KEY (ReferenceAccountNo) REFERENCES Account(AccountNo) ON DELETE SET NULL
);

-- 6. Loan Table
CREATE TABLE Loan (
    LoanID INT AUTO_INCREMENT PRIMARY KEY,
    CustomerID INT NOT NULL,
    BranchID INT NOT NULL,
    LoanType ENUM('Home', 'Personal', 'Auto', 'Education') NOT NULL,
    Amount DECIMAL(15, 2) NOT NULL CHECK (Amount > 0),
    InterestRate DECIMAL(5, 2) NOT NULL CHECK (InterestRate >= 0),
    DurationMonths INT NOT NULL CHECK (DurationMonths > 0),
    StartDate DATE NOT NULL,
    Status ENUM('Pending', 'Approved', 'Rejected', 'Active', 'Closed') DEFAULT 'Pending',
    FOREIGN KEY (CustomerID) REFERENCES Customer(CustomerID) ON DELETE CASCADE,
    FOREIGN KEY (BranchID) REFERENCES Branch(BranchID) ON DELETE RESTRICT
);

-- 7. Transaction Log Table for triggers
CREATE TABLE TransactionLog (
    LogID INT AUTO_INCREMENT PRIMARY KEY,
    TransactionID INT,
    AccountNo VARCHAR(20),
    Action VARCHAR(50),
    LogTimestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    Details VARCHAR(255)
);
