const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateToken, requireRole, requireAccountOwnership } = require('../middleware/auth');
const { logSecurityEvent, getClientIp, getUserAgent } = require('../security/auditLogger');
const { maskAccount, maskPhone, maskEmail, encryptData, decryptData } = require('../security/cryptoUtil');

// -----------------------------------------------------------------------------
// 1. BACKWARD COMPATIBLE LOGIN ROUTE
// -----------------------------------------------------------------------------

/**
 * POST /api/login
 * Backward-compatible login handler that forwards to the secure auth mechanism
 */
router.post('/login', async (req, res, next) => {
    // If password is included, route directly to modern auth logic
    if (req.body.password) {
        return req.app._router.handle({ ...req, url: '/api/auth/login' }, res, next);
    }

    // If legacy client sent only email, look up customer but encourage secure password login
    const { email } = req.body;
    try {
        const [rows] = await db.execute('SELECT * FROM Customer WHERE Email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Customer not found. Please check your email.' });
        }
        res.json({ 
            message: 'Login successful. Note: Password authentication is required for full security.', 
            customer: rows[0],
            legacyNotice: 'Please use /api/auth/login with password for authenticated sessions.'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// -----------------------------------------------------------------------------
// 2. ACCOUNTS & BALANCES (PROTECTED WITH RBAC & OWNERSHIP CHECK)
// -----------------------------------------------------------------------------

/**
 * GET /api/customers/:id/accounts
 * Protected: Customers can only access their own accounts; Employees & Admins have operational access
 */
router.get('/customers/:id/accounts', authenticateToken, requireAccountOwnership, async (req, res) => {
    const customerId = req.params.id;
    try {
        const [rows] = await db.execute('SELECT * FROM View_CustomerAccountSummary WHERE CustomerID = ?', [customerId]);
        
        // Add masked account numbers for safe frontend rendering
        const safeRows = rows.map(acc => ({
            ...acc,
            MaskedAccountNo: maskAccount(acc.AccountNo)
        }));

        res.json({ accounts: safeRows });
    } catch (err) {
        console.error('Error fetching accounts:', err);
        res.status(500).json({ error: 'Database error fetching accounts.' });
    }
});

/**
 * GET /api/accounts/:accountNo/balance
 * Protected with IDOR ownership validation
 */
router.get('/accounts/:accountNo/balance', authenticateToken, requireAccountOwnership, async (req, res) => {
    const accountNo = req.params.accountNo;
    try {
        const [rows] = await db.execute('SELECT AccountNo, Balance, Status FROM Account WHERE AccountNo = ?', [accountNo]);
        if (rows.length === 0) return res.status(404).json({ error: 'Account not found' });
        
        res.json({
            ...rows[0],
            MaskedAccountNo: maskAccount(rows[0].AccountNo)
        });
    } catch (err) {
        console.error('Error fetching balance:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// -----------------------------------------------------------------------------
// 3. TRANSACTIONS (ROW LOCKING, AUDITING, ATOMIC EXECUTION)
// -----------------------------------------------------------------------------

/**
 * POST /api/transactions/deposit
 * Protected: Customers can deposit into their accounts; Staff can deposit into any valid account
 */
router.post('/transactions/deposit', authenticateToken, async (req, res) => {
    const { accountNo, amount, description } = req.body;
    const ip = getClientIp(req);
    const ua = getUserAgent(req);

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Deposit amount must be a positive number.' });
    }

    try {
        // Verify account exists
        const [acc] = await db.execute('SELECT CustomerID, Status FROM Account WHERE AccountNo = ?', [accountNo]);
        if (acc.length === 0) return res.status(404).json({ error: 'Account not found.' });
        if (acc[0].Status !== 'Active') return res.status(400).json({ error: 'Account is not in active status.' });

        // If caller is Customer, verify ownership
        if (req.user.role === 'Customer' && Number(acc[0].CustomerID) !== Number(req.user.customerId)) {
            return res.status(403).json({ error: 'Access denied: You cannot deposit into an unlinked account directly.' });
        }

        // Execute stored procedure
        await db.execute('CALL DepositMoney(?, ?, ?)', [accountNo, parsedAmount, description || 'Funds Deposit']);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'DEPOSIT_FUNDS',
            targetResource: `Account:${accountNo}`,
            outcome: 'SUCCESS',
            ipAddress: ip,
            userAgent: ua,
            details: `Deposited $${parsedAmount} into account ${maskAccount(accountNo)}.`
        });

        res.json({ message: 'Deposit successful.' });
    } catch (err) {
        console.error('Deposit error:', err);
        res.status(500).json({ error: err.message || 'Database error during deposit.' });
    }
});

/**
 * POST /api/transactions/withdraw
 * Protected: Requires account ownership, checks balance, uses row locking
 */
router.post('/transactions/withdraw', authenticateToken, requireAccountOwnership, async (req, res) => {
    const { accountNo, amount, description } = req.body;
    const ip = getClientIp(req);
    const ua = getUserAgent(req);

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Withdrawal amount must be a positive number.' });
    }

    try {
        const [acc] = await db.execute('SELECT Balance, Status FROM Account WHERE AccountNo = ?', [accountNo]);
        if (acc.length === 0) return res.status(404).json({ error: 'Account not found.' });
        if (acc[0].Status !== 'Active') return res.status(400).json({ error: 'Account is not in active status.' });

        if (Number(acc[0].Balance) < parsedAmount) {
            await logSecurityEvent({
                actorId: req.user.email,
                actorRole: req.user.role,
                actionType: 'WITHDRAW_FUNDS_REJECTED',
                targetResource: `Account:${accountNo}`,
                outcome: 'FAILURE',
                ipAddress: ip,
                userAgent: ua,
                details: `Insufficient funds: Requested $${parsedAmount}, Available: $${acc[0].Balance}`
            });
            return res.status(400).json({ error: 'Insufficient account balance for withdrawal.' });
        }

        // Execute stored procedure (Triggers balance update)
        await db.execute('CALL WithdrawMoney(?, ?, ?)', [accountNo, parsedAmount, description || 'Funds Withdrawal']);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'WITHDRAW_FUNDS',
            targetResource: `Account:${accountNo}`,
            outcome: 'SUCCESS',
            ipAddress: ip,
            userAgent: ua,
            details: `Withdrew $${parsedAmount} from account ${maskAccount(accountNo)}.`
        });

        res.json({ message: 'Withdrawal successful.' });
    } catch (err) {
        console.error('Withdrawal error:', err);
        res.status(400).json({ error: err.message || 'Error processing withdrawal. Check balance.' });
    }
});

/**
 * POST /api/transactions/transfer
 * ACID compliant transfer procedure with row locking (SELECT ... FOR UPDATE) and balance validation
 */
router.post('/transactions/transfer', authenticateToken, requireAccountOwnership, async (req, res) => {
    const { fromAccount, toAccount, amount, description } = req.body;
    const ip = getClientIp(req);
    const ua = getUserAgent(req);

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ error: 'Transfer amount must be greater than zero.' });
    }

    if (fromAccount === toAccount) {
        return res.status(400).json({ error: 'Source and destination accounts cannot be identical.' });
    }

    try {
        // Verify destination exists and is active
        const [dest] = await db.execute('SELECT AccountNo, Status FROM Account WHERE AccountNo = ?', [toAccount]);
        if (dest.length === 0) {
            return res.status(404).json({ error: 'Recipient account number does not exist.' });
        }
        if (dest[0].Status !== 'Active') {
            return res.status(400).json({ error: 'Recipient account is not active.' });
        }

        // Execute TransferFunds stored procedure (encapsulates START TRANSACTION, FOR UPDATE row locking, COMMIT/ROLLBACK)
        await db.execute('CALL TransferFunds(?, ?, ?, ?)', [
            fromAccount, 
            toAccount, 
            parsedAmount, 
            description || 'Fund Transfer'
        ]);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'TRANSFER_FUNDS',
            targetResource: `From:${fromAccount}->To:${toAccount}`,
            outcome: 'SUCCESS',
            ipAddress: ip,
            userAgent: ua,
            details: `Transferred $${parsedAmount} from ${maskAccount(fromAccount)} to ${maskAccount(toAccount)}.`
        });

        res.json({ message: 'Transfer completed successfully.' });
    } catch (err) {
        console.error('Transfer error:', err);
        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'TRANSFER_FUNDS_FAILED',
            targetResource: `From:${fromAccount}->To:${toAccount}`,
            outcome: 'FAILURE',
            ipAddress: ip,
            userAgent: ua,
            details: `Transfer failed: ${err.message}`
        });
        res.status(400).json({ error: err.message || 'Error processing transfer. Please verify balance.' });
    }
});

/**
 * GET /api/accounts/:accountNo/transactions
 * Protected: Transaction history with masking
 */
router.get('/accounts/:accountNo/transactions', authenticateToken, requireAccountOwnership, async (req, res) => {
    const accountNo = req.params.accountNo;
    try {
        const [rows] = await db.execute('SELECT * FROM View_AccountStatement WHERE AccountNo = ?', [accountNo]);
        
        const maskedTransactions = rows.map(tx => ({
            ...tx,
            MaskedAccountNo: maskAccount(tx.AccountNo),
            MaskedReferenceAccountNo: tx.ReferenceAccountNo ? maskAccount(tx.ReferenceAccountNo) : null
        }));

        res.json({ transactions: maskedTransactions });
    } catch (err) {
        console.error('Error fetching transactions:', err);
        res.status(500).json({ error: 'Database error fetching transaction history.' });
    }
});

// -----------------------------------------------------------------------------
// 4. LOANS (APPLICATIONS & APPROVALS)
// -----------------------------------------------------------------------------

/**
 * POST /api/loans/apply
 * Protected loan application
 */
router.post('/loans/apply', authenticateToken, async (req, res) => {
    const { customerId, branchId, loanType, amount, durationMonths } = req.body;

    // Enforce ownership: customer can only apply for themselves
    if (req.user.role === 'Customer' && Number(customerId) !== Number(req.user.customerId)) {
        return res.status(403).json({ error: 'You can only apply for loans on your own behalf.' });
    }

    try {
        let interestRate = 5.0; 
        if (loanType === 'Personal') interestRate = 12.5;
        if (loanType === 'Home') interestRate = 8.5;
        if (loanType === 'Auto') interestRate = 10.0;
        if (loanType === 'Education') interestRate = 9.0;

        const query = `
            INSERT INTO Loan (CustomerID, BranchID, LoanType, Amount, InterestRate, DurationMonths, StartDate, Status) 
            VALUES (?, ?, ?, ?, ?, ?, CURDATE(), 'Pending')`;
        
        await db.execute(query, [customerId, branchId, loanType, amount, interestRate, durationMonths]);
        
        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'LOAN_APPLICATION',
            targetResource: `Customer:${customerId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Applied for ${loanType} loan of $${amount} for ${durationMonths} months.`
        });

        res.json({ message: 'Loan application submitted successfully and is pending approval.' });
    } catch (err) {
        console.error('Loan apply error:', err);
        res.status(500).json({ error: err.message || 'Database error during loan application' });
    }
});

/**
 * GET /api/customers/:id/loans
 * Protected: View customer's loan list
 */
router.get('/customers/:id/loans', authenticateToken, requireAccountOwnership, async (req, res) => {
    const customerId = req.params.id;
    try {
        const [rows] = await db.execute('SELECT * FROM Loan WHERE CustomerID = ? ORDER BY StartDate DESC', [customerId]);
        res.json({ loans: rows });
    } catch (err) {
        console.error('Error fetching loans:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

/**
 * PUT /api/loans/:id/process
 * Protected: Employees and Admins approve or reject loans
 */
router.put('/loans/:id/process', authenticateToken, requireRole('Employee', 'Admin'), async (req, res) => {
    const loanId = req.params.id;
    const { status, disbursementAccountNo } = req.body;

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ error: 'Status must be Approved or Rejected.' });
    }

    try {
        if (status === 'Approved' && !disbursementAccountNo) {
            return res.status(400).json({ error: 'Disbursement account number is required when approving a loan.' });
        }

        // Call stored procedure ProcessLoanApplication
        await db.execute('CALL ProcessLoanApplication(?, ?, ?)', [
            loanId,
            status,
            disbursementAccountNo || 'ACC1001'
        ]);

        await logSecurityEvent({
            actorId: req.user.email,
            actorRole: req.user.role,
            actionType: 'LOAN_DECISION',
            targetResource: `Loan:${loanId}`,
            outcome: 'SUCCESS',
            ipAddress: getClientIp(req),
            userAgent: getUserAgent(req),
            details: `Loan ${loanId} processed as ${status}. Disbursed to: ${disbursementAccountNo || 'N/A'}`
        });

        res.json({ message: `Loan application successfully ${status.toLowerCase()}.` });
    } catch (err) {
        console.error('Error processing loan:', err);
        res.status(400).json({ error: err.message || 'Error processing loan application.' });
    }
});

// -----------------------------------------------------------------------------
// 5. BRANCHES & ANALYTICS
// -----------------------------------------------------------------------------

/**
 * GET /api/branches
 * Public list of branches
 */
router.get('/branches', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT BranchID, BranchName, City, ContactNumber FROM Branch');
        res.json({ branches: rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

/**
 * GET /api/admin/stats
 * Operational analytics: Protected for Admins and Employees
 */
router.get('/admin/stats', authenticateToken, requireRole('Admin', 'Employee'), async (req, res) => {
    try {
        const [highestBalances] = await db.query(`
            SELECT c.CustomerID, CONCAT(c.FirstName, ' ', c.LastName) AS CustomerName, SUM(a.Balance) AS TotalBalance
            FROM Customer c JOIN Account a ON c.CustomerID = a.CustomerID
            GROUP BY c.CustomerID, CustomerName ORDER BY TotalBalance DESC LIMIT 5`);
            
        const [branchTxds] = await db.query(`
            SELECT b.BranchName, t.TransactionType, sum(t.Amount) as TotalVolume, count(t.TransactionID) as TotalCount
            FROM Branch b JOIN Account a ON b.BranchID = a.BranchID JOIN Transaction t ON a.AccountNo = t.AccountNo
            GROUP BY b.BranchName, t.TransactionType`);

        res.json({ highestBalances, branchTxds });
    } catch (err) {
        console.error('Error fetching stats:', err);
        res.status(500).json({ error: 'Database error fetching stats' });
    }
});

// -----------------------------------------------------------------------------
// 6. PRIVACY & ENCRYPTION DEMONSTRATION ENDPOINT
// -----------------------------------------------------------------------------

/**
 * GET /api/privacy/demo
 * Demonstrates Masking vs Encryption vs Plaintext for academic presentation
 */
router.get('/privacy/demo', authenticateToken, async (req, res) => {
    try {
        const sampleAccount = 'ACC10014892';
        const samplePhone = '9876543210';
        const sampleEmail = 'customer.vip@globaltrust.com';
        const sampleNationalId = '1234-5678-9012';

        const encryptedNationalId = encryptData(sampleNationalId);
        const decryptedNationalId = decryptData(encryptedNationalId);

        res.json({
            title: 'Data Privacy & Encryption Demonstration',
            demonstrations: {
                accountMasking: {
                    original: sampleAccount,
                    masked: maskAccount(sampleAccount),
                    technique: 'Dynamic Server-Side Masking (Right-preserve 4 digits)'
                },
                phoneMasking: {
                    original: samplePhone,
                    masked: maskPhone(samplePhone),
                    technique: 'Dynamic Server-Side Masking'
                },
                emailMasking: {
                    original: sampleEmail,
                    masked: maskEmail(sampleEmail),
                    technique: 'Pseudonymized Email Masking'
                },
                applicationEncryption: {
                    originalPlaintext: sampleNationalId,
                    cipherPayload: encryptedNationalId,
                    decryptedVerification: decryptedNationalId,
                    algorithm: 'AES-256-GCM (Authenticated Symmetric Encryption with IV & Auth Tag)',
                    keyManagement: 'Environment-isolated 256-bit symmetric key'
                }
            }
        });
    } catch (err) {
        console.error('Privacy demo error:', err);
        res.status(500).json({ error: 'Error generating privacy demonstration.' });
    }
});

module.exports = router;
