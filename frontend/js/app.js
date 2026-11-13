/**
 * GlobalTrust Bank - Frontend Application Core Module
 * Role-Based Navigation, Session Management, and Security Helpers
 */

const API_BASE = 'http://localhost:3000';

/**
 * Common fetch wrapper for authenticated API calls
 */
async function apiCall(endpoint, method = 'GET', body = null) {
    const token = localStorage.getItem('token');
    const headers = {
        'Content-Type': 'application/json'
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const options = {
        method,
        headers
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        let data = {};
        
        try {
            data = await response.json();
        } catch (jsonErr) {
            data = { error: 'Invalid response format from server.' };
        }

        if (!response.ok) {
            // Handle session revocation or expiry
            if (response.status === 401 && !endpoint.includes('/login')) {
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                localStorage.removeItem('customer');
                window.location.href = 'index.html?session=expired';
                return;
            }
            throw new Error(data.error || (data.details ? data.details.join(', ') : 'An unexpected error occurred.'));
        }

        return data;
    } catch (err) {
        throw err;
    }
}

/**
 * Get current session user
 */
function getCurrentUser() {
    const raw = localStorage.getItem('user');
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (e) {
        return null;
    }
}

/**
 * Enforces authentication and role authorization on protected pages
 */
function requireAuth(allowedRoles = null) {
    const token = localStorage.getItem('token');
    const user = getCurrentUser();

    if (!token || !user) {
        window.location.href = 'index.html';
        return;
    }

    if (allowedRoles && allowedRoles.length > 0) {
        if (!allowedRoles.includes(user.role)) {
            alert('Access Denied: Your account role does not have permission to view this section.');
            if (user.role === 'Admin') {
                window.location.href = 'admin-security.html';
            } else if (user.role === 'Employee') {
                window.location.href = 'employee-portal.html';
            } else {
                window.location.href = 'dashboard.html';
            }
        }
    }
}

/**
 * Logs out user, invalidates session token on server, and redirects
 */
async function logout() {
    try {
        await apiCall('/api/auth/logout', 'POST');
    } catch (e) {
        // proceed even if network error
    } finally {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('customer');
        window.location.href = 'index.html';
    }
}

/**
 * Format account numbers with masking (e.g. •••• •••• 1001)
 */
function maskAccount(accountNo) {
    if (!accountNo) return '';
    const clean = String(accountNo).trim();
    if (clean.length <= 4) return clean;
    return '•••• •••• ' + clean.slice(-4);
}

/**
 * Format currency amount with commas and 2 decimals
 */
function formatCurrency(amount) {
    const num = Number(amount) || 0;
    return '$' + num.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

/**
 * Format timestamp to clean local date/time
 */
function formatDateTime(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) + ' ' + 
           d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

/**
 * Displays a non-intrusive floating toast notification
 */
function showToast(message, type = 'info') {
    let toast = document.getElementById('globalToast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'globalToast';
        toast.className = 'bank-toast';
        document.body.appendChild(toast);
    }

    const typeClasses = {
        success: 'border-success text-success',
        danger: 'border-danger text-danger',
        warning: 'border-warning text-warning',
        info: 'border-primary text-primary'
    };

    const icons = {
        success: 'bi-check-circle-fill',
        danger: 'bi-exclamation-octagon-fill',
        warning: 'bi-exclamation-triangle-fill',
        info: 'bi-info-circle-fill'
    };

    toast.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi ${icons[type] || 'bi-info-circle'} fs-5 me-2 ${typeClasses[type] || ''}"></i>
            <div class="flex-grow-1 text-dark small fw-medium">${message}</div>
            <button type="button" class="btn-close btn-close-sm ms-2" onclick="this.parentElement.parentElement.style.display='none'"></button>
        </div>
    `;

    toast.style.display = 'block';
    setTimeout(() => {
        if (toast) toast.style.display = 'none';
    }, 4500);
}

/**
 * Injects responsive, role-aware navbar into container
 */
function injectNavbar() {
    const container = document.getElementById('navbar-container');
    if (!container) return;

    const user = getCurrentUser();
    const role = user ? user.role : 'Customer';
    const email = user ? user.email : '';
    const currentPath = window.location.pathname.split('/').pop() || 'dashboard.html';

    let roleBadgeClass = 'bg-secondary';
    if (role === 'Admin') roleBadgeClass = 'bg-danger';
    if (role === 'Employee') roleBadgeClass = 'bg-warning text-dark';
    if (role === 'Customer') roleBadgeClass = 'bg-primary';

    // Build role-specific navigation links
    let navLinksHtml = '';

    if (role === 'Admin') {
        navLinksHtml = `
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'admin-security.html' ? 'active' : ''}" href="admin-security.html">
                    <i class="bi bi-shield-lock me-1"></i> Security & Privacy
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'employee-portal.html' ? 'active' : ''}" href="employee-portal.html">
                    <i class="bi bi-person-badge me-1"></i> Staff Portal
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'dashboard.html' ? 'active' : ''}" href="dashboard.html">
                    <i class="bi bi-speedometer2 me-1"></i> Accounts
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'history.html' ? 'active' : ''}" href="history.html">
                    <i class="bi bi-clock-history me-1"></i> History
                </a>
            </li>
        `;
    } else if (role === 'Employee') {
        navLinksHtml = `
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'employee-portal.html' ? 'active' : ''}" href="employee-portal.html">
                    <i class="bi bi-person-badge me-1"></i> Branch Operations
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'deposit.html' ? 'active' : ''}" href="deposit.html">
                    <i class="bi bi-box-arrow-in-down me-1"></i> Deposit
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'withdraw.html' ? 'active' : ''}" href="withdraw.html">
                    <i class="bi bi-box-arrow-up me-1"></i> Withdraw
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'transfer.html' ? 'active' : ''}" href="transfer.html">
                    <i class="bi bi-arrow-left-right me-1"></i> Transfer
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'history.html' ? 'active' : ''}" href="history.html">
                    <i class="bi bi-clock-history me-1"></i> History
                </a>
            </li>
        `;
    } else {
        // Customer Links
        navLinksHtml = `
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'dashboard.html' ? 'active' : ''}" href="dashboard.html">
                    <i class="bi bi-wallet2 me-1"></i> Dashboard
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'deposit.html' ? 'active' : ''}" href="deposit.html">
                    <i class="bi bi-box-arrow-in-down me-1"></i> Deposit
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'withdraw.html' ? 'active' : ''}" href="withdraw.html">
                    <i class="bi bi-box-arrow-up me-1"></i> Withdraw
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'transfer.html' ? 'active' : ''}" href="transfer.html">
                    <i class="bi bi-arrow-left-right me-1"></i> Transfer
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'loan.html' ? 'active' : ''}" href="loan.html">
                    <i class="bi bi-file-earmark-text me-1"></i> Loans
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link ${currentPath === 'history.html' ? 'active' : ''}" href="history.html">
                    <i class="bi bi-clock-history me-1"></i> History
                </a>
            </li>
        `;
    }

    const navHTML = `
    <nav class="navbar navbar-expand-lg navbar-dark navbar-bank sticky-top">
        <div class="container">
            <a class="navbar-brand" href="${role === 'Admin' ? 'admin-security.html' : (role === 'Employee' ? 'employee-portal.html' : 'dashboard.html')}">
                <i class="bi bi-bank fs-4 text-primary-subtle"></i>
                <span>GlobalTrust Bank</span>
            </a>
            <button class="navbar-toggler border-0" type="button" data-bs-toggle="collapse" data-bs-target="#navbarMain">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarMain">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    ${navLinksHtml}
                </ul>
                <div class="d-flex align-items-center gap-3 mt-3 mt-lg-0">
                    <div class="d-flex flex-column text-end d-none d-sm-flex">
                        <span class="text-white small fw-medium">${email}</span>
                        <div class="d-flex justify-content-end align-items-center gap-1 mt-1">
                            <span class="badge ${roleBadgeClass} role-badge">${role}</span>
                        </div>
                    </div>
                    <button class="btn btn-outline-light btn-sm px-3" onclick="openPasswordModal()">
                        <i class="bi bi-key me-1"></i> Security
                    </button>
                    <button class="btn btn-danger btn-sm px-3" onclick="logout()">
                        <i class="bi bi-box-arrow-right me-1"></i> Logout
                    </button>
                </div>
            </div>
        </div>
    </nav>

    <!-- Global Password Change Modal -->
    <div class="modal fade" id="changePasswordModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title fw-bold">
                        <i class="bi bi-shield-lock text-primary me-2"></i>Change Password
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body p-4">
                    <div id="pwdModalAlert" class="alert d-none small mb-3"></div>
                    <form id="globalChangePasswordForm">
                        <div class="mb-3">
                            <label class="form-label">Current Password</label>
                            <input type="password" class="form-control" id="modalCurrentPwd" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">New Password</label>
                            <input type="password" class="form-control" id="modalNewPwd" required>
                            <div class="form-text small">Must be at least 12 characters with uppercase, lowercase, number, and special character. Cannot reuse last 5 passwords.</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="modalConfirmPwd" required>
                        </div>
                        <div class="d-grid mt-4">
                            <button type="submit" class="btn btn-bank-primary">Update Password</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    `;

    container.innerHTML = navHTML;
}

/**
 * Open password change modal
 */
function openPasswordModal() {
    const modalEl = document.getElementById('changePasswordModal');
    if (!modalEl) return;
    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    const form = document.getElementById('globalChangePasswordForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const currentPassword = document.getElementById('modalCurrentPwd').value;
        const newPassword = document.getElementById('modalNewPwd').value;
        const confirmPassword = document.getElementById('modalConfirmPwd').value;
        const alertBox = document.getElementById('pwdModalAlert');

        try {
            const res = await apiCall('/api/auth/change-password', 'POST', {
                currentPassword,
                newPassword,
                confirmPassword
            });
            if (res.token) {
                localStorage.setItem('token', res.token);
            }
            alertBox.className = 'alert alert-success small mb-3';
            alertBox.textContent = res.message;
            alertBox.classList.remove('d-none');
            form.reset();
            setTimeout(() => {
                modal.hide();
                showToast('Password changed successfully!', 'success');
            }, 1800);
        } catch (err) {
            alertBox.className = 'alert alert-danger small mb-3';
            alertBox.textContent = err.message;
            alertBox.classList.remove('d-none');
        }
    };
}

// Auto-inject navigation bar once DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    injectNavbar();
});
