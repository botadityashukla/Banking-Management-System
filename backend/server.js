const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const { securityHeaders } = require('./middleware/auth');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const apiRoutes = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

// Apply standard security headers on all HTTP responses
app.use(securityHeaders);

// CORS configuration (allow local frontend access)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));

// Mount API routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', apiRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        system: 'GlobalTrust Banking Management System (DSP Upgraded)',
        security: 'Active',
        timestamp: new Date().toISOString()
    });
});

// Centralized error handling middleware: NEVER leak internal errors or stack traces!
app.use((err, req, res, next) => {
    console.error('Unhandled Server Error:', err);
    res.status(err.status || 500).json({
        error: process.env.NODE_ENV === 'development' && err.message 
            ? err.message 
            : 'An unexpected security or processing error occurred. Please try again.'
    });
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`GlobalTrust Banking Server running on http://localhost:${PORT}`);
        console.log(`Frontend accessible at http://localhost:${PORT}/index.html`);
    });
}

module.exports = app;
