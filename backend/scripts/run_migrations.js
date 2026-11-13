const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

async function runMigrations() {
    console.log('--- STARTING DSP SECURITY MIGRATION ---');
    const dbConfig = {
        host: process.env.DB_HOST || 'localhost',
        user: 'root', // DBA connection to perform initial schema & privilege creation
        password: process.env.DB_ROOT_PASSWORD || 'Daya_003',
        multipleStatements: true
    };

    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        console.log('✓ Connected to MySQL instance as root.');

        // 1. Run dsp_upgrade_migration.sql
        const dspSqlPath = path.join(__dirname, '../../database/dsp_upgrade_migration.sql');
        const dspSql = fs.readFileSync(dspSqlPath, 'utf8');
        console.log('Executing dsp_upgrade_migration.sql...');
        await connection.query(dspSql);
        console.log('✓ dsp_upgrade_migration.sql executed successfully.');

        // Connect specifically to banking_management_system
        await connection.changeUser({ database: 'banking_management_system' });

        // 2. Hash default secure passwords
        const adminPassHash = await bcrypt.hash('Admin@Secure2026!', 10);
        const employeePassHash = await bcrypt.hash('Employee@Bank2026!', 10);
        const defaultCustPassHash = await bcrypt.hash('Customer@Pass2026!', 10);

        // 3. Seed Administrator
        const [adminExists] = await connection.query('SELECT UserID FROM UserSecurity WHERE Email = ?', ['admin@globaltrust.com']);
        let adminUserId;
        if (adminExists.length === 0) {
            const [res] = await connection.query(
                `INSERT INTO UserSecurity (Username, Email, PasswordHash, Role, IsActive, PasswordLastChanged) 
                 VALUES (?, ?, ?, 'Admin', TRUE, NOW())`,
                ['admin', 'admin@globaltrust.com', adminPassHash]
            );
            adminUserId = res.insertId;
            await connection.query('INSERT INTO PasswordHistory (UserID, PasswordHash) VALUES (?, ?)', [adminUserId, adminPassHash]);
            console.log('✓ Created Admin account: admin@globaltrust.com');
        } else {
            adminUserId = adminExists[0].UserID;
            console.log('• Admin account already exists (UserID: ' + adminUserId + ')');
        }

        // 4. Seed Employee
        const [empRow] = await connection.query('SELECT EmployeeID FROM Employee WHERE Email = ?', ['employee@globaltrust.com']);
        const employeeId = empRow.length > 0 ? empRow[0].EmployeeID : null;
        const [employeeExists] = await connection.query('SELECT UserID FROM UserSecurity WHERE Email = ?', ['employee@globaltrust.com']);
        let employeeUserId;
        if (employeeExists.length === 0) {
            const [res] = await connection.query(
                `INSERT INTO UserSecurity (Username, Email, PasswordHash, Role, EmployeeID, IsActive, PasswordLastChanged) 
                 VALUES (?, ?, ?, 'Employee', ?, TRUE, NOW())`,
                ['emp_vikram', 'employee@globaltrust.com', employeePassHash, employeeId]
            );
            employeeUserId = res.insertId;
            await connection.query('INSERT INTO PasswordHistory (UserID, PasswordHash) VALUES (?, ?)', [employeeUserId, employeePassHash]);
            console.log('✓ Created Employee account: employee@globaltrust.com');
        } else {
            employeeUserId = employeeExists[0].UserID;
            console.log('• Employee account already exists (UserID: ' + employeeUserId + ')');
        }

        // 5. Seed Customer security credentials for all existing 102 customers
        const [customers] = await connection.query('SELECT CustomerID, FirstName, LastName, Email FROM Customer');
        console.log(`Processing security credentials for ${customers.length} existing customers...`);
        let newCustCount = 0;
        for (const c of customers) {
            const [exists] = await connection.query('SELECT UserID FROM UserSecurity WHERE Email = ?', [c.Email]);
            if (exists.length === 0) {
                const username = (c.Email.split('@')[0] + '_' + c.CustomerID).toLowerCase().replace(/[^a-z0-9_]/g, '');
                const [ins] = await connection.query(
                    `INSERT INTO UserSecurity (Username, Email, PasswordHash, Role, CustomerID, IsActive, PasswordLastChanged)
                     VALUES (?, ?, ?, 'Customer', ?, TRUE, NOW())`,
                    [username, c.Email, defaultCustPassHash, c.CustomerID]
                );
                await connection.query('INSERT INTO PasswordHistory (UserID, PasswordHash) VALUES (?, ?)', [ins.insertId, defaultCustPassHash]);
                newCustCount++;
            }
        }
        console.log(`✓ Synchronized security accounts for ${newCustCount} new customer accounts.`);

        // 6. Log Migration in SecurityAuditLog
        await connection.query(
            `INSERT INTO SecurityAuditLog (ActorID, ActorRole, ActionType, TargetResource, Outcome, Details)
             VALUES ('SYSTEM_MIGRATION', 'ADMIN', 'SYSTEM_MIGRATION_EXECUTE', 'DATABASE_SCHEMA', 'SUCCESS', 'DSP Security upgrade migration executed successfully with credentials seeded.')`
        );

        // 7. Execute Database Users & Privileges Script
        try {
            const privSqlPath = path.join(__dirname, '../../database/01_db_users_and_privileges.sql');
            const privSql = fs.readFileSync(privSqlPath, 'utf8');
            console.log('Executing 01_db_users_and_privileges.sql...');
            await connection.query(privSql);
            console.log('✓ MySQL users bank_app_user and bank_sec_admin created with least privilege.');
        } catch (privErr) {
            console.warn('Note on MySQL user privileges creation:', privErr.message);
        }

        console.log('\n--- VERIFICATION STATUS ---');
        const [userCount] = await connection.query('SELECT COUNT(*) as count FROM UserSecurity');
        const [policyRows] = await connection.query('SELECT * FROM PasswordPolicyConfig WHERE PolicyID = 1');
        const [auditCount] = await connection.query('SELECT COUNT(*) as count FROM SecurityAuditLog');
        console.log(`Total UserSecurity Records: ${userCount[0].count}`);
        console.log(`Total SecurityAuditLog Entries: ${auditCount[0].count}`);
        console.log('Current Active Password Policy:');
        console.table(policyRows);

        console.log('\n--- DEMO USER CREDENTIALS ---');
        console.log('1. Admin:    admin@globaltrust.com    | Password: Admin@Secure2026!');
        console.log('2. Employee: employee@globaltrust.com | Password: Employee@Bank2026!');
        console.log('3. Customer: aditya003shukla@gmail.com| Password: Customer@Pass2026!');
        console.log('All other 101 customers default password: Customer@Pass2026!');
        console.log('--- DSP SECURITY MIGRATION COMPLETE ---');

    } catch (err) {
        console.error('Migration failed:', err);
        process.exitCode = 1;
    } finally {
        if (connection) await connection.end();
    }
}

runMigrations();
