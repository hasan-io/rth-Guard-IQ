<?php
// auth/settings.php
// Session-based auth — no $auth class needed

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Auth check — simple session based
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

require_once '../includes/db.php';
require_once '../includes/header.php'; 

$userId      = $_SESSION['user_id'];
$success_msg = '';
$error_msg   = '';

// =============================================
// Handle POST requests
// =============================================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? '';

    if (!validateCSRFToken('settings_form', $csrf_token)) {
        $error_msg = "Invalid security token. Please try again.";
    } else {

        // -- Update Profile --
        if (isset($_POST['update_profile'])) {
            $email     = trim($_POST['email'] ?? '');
            $full_name = trim($_POST['full_name'] ?? '');

            if (empty($email)) {
                $error_msg = "Email is required.";
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error_msg = "Invalid email format.";
            } else {
                try {
                    // Check email not used by someone else
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                    $stmt->execute([$email, $userId]);
                    if ($stmt->fetch()) {
                        $error_msg = "Email already in use by another account.";
                    } else {
                        $stmt = $pdo->prepare("UPDATE users SET email = ?, full_name = ?, updated_at = NOW() WHERE id = ?");
                        $stmt->execute([$email, $full_name, $userId]);

                        // Update session immediately
                        $_SESSION['email']     = $email;
                        $_SESSION['full_name'] = $full_name;

                        $success_msg = "Profile updated successfully.";
                    }
                } catch (PDOException $e) {
                    $error_msg = "Error updating profile.";
                }
            }
        }

        // -- Change Password --
        elseif (isset($_POST['change_password'])) {
            $current_password = $_POST['current_password'] ?? '';
            $new_password     = $_POST['new_password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';

            if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
                $error_msg = "All password fields are required.";
            } elseif ($new_password !== $confirm_password) {
                $error_msg = "New passwords do not match.";
            } elseif (strlen($new_password) < 8) {
                $error_msg = "Password must be at least 8 characters.";
            } else {
                try {
                    $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
                    $stmt->execute([$userId]);
                    $user = $stmt->fetch();

                    if ($user && password_verify($current_password, $user['password_hash'])) {
                        $hashed = password_hash($new_password, PASSWORD_DEFAULT);
                        $stmt   = $pdo->prepare("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?");
                        $stmt->execute([$hashed, $userId]);
                        $success_msg = "Password changed successfully.";
                    } else {
                        $error_msg = "Current password is incorrect.";
                    }
                } catch (PDOException $e) {
                    $error_msg = "Error changing password.";
                }
            }
        }

        // -- Update Notifications --
        elseif (isset($_POST['update_notifications'])) {
            $success_msg = "Notification preferences updated.";
        }

        // -- Update Security Settings --
        elseif (isset($_POST['update_security'])) {
            $success_msg = "Security settings updated.";
        }

        // -- Update Preferences --
        elseif (isset($_POST['update_preferences'])) {
            $success_msg = "Preferences updated.";
        }
    }
}

// =============================================
// Load fresh user data from DB
// =============================================
try {
    $stmt = $pdo->prepare("SELECT username, email, full_name, role, created_at, last_login FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $userData = $stmt->fetch();
} catch (PDOException $e) {
    $userData = [];
}

// Fallback defaults for settings
$userSettings = [
    'email_notifications' => 1,
    'push_notifications'  => 1,
    'security_alerts'     => 1,
    'two_factor_auth'     => 0,
    'session_timeout'     => 30
];

// Generate CSRF token
$csrf_token = generateCSRFToken('settings_form');

// Include header (sidebar + nav)
require_once '../includes/header.php';
?>

<div class="row g-4">
    <!-- Page Header -->
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2 class="mb-1"><i class="fas fa-cog me-2"></i>Settings</h2>
                <p class="text-muted mb-0">Manage your account and preferences</p>
            </div>
            <div>
                <span class="badge bg-secondary">
                    <i class="fas fa-user me-1"></i>
                    <?= htmlspecialchars($userData['username'] ?? $_SESSION['username'] ?? 'User') ?>
                </span>
            </div>
        </div>

        <?php if ($success_msg): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="fas fa-check-circle me-2"></i> <?= htmlspecialchars($success_msg) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if ($error_msg): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-circle me-2"></i> <?= htmlspecialchars($error_msg) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
    </div>

    <!-- Settings Tabs -->
    <div class="col-12">
        <ul class="nav nav-tabs mb-4" id="settingsTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="profile-tab" data-bs-toggle="tab" data-bs-target="#profile" type="button">
                    <i class="fas fa-user me-2"></i> Profile
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button">
                    <i class="fas fa-shield-alt me-2"></i> Security
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="notifications-tab" data-bs-toggle="tab" data-bs-target="#notifications" type="button">
                    <i class="fas fa-bell me-2"></i> Notifications
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="preferences-tab" data-bs-toggle="tab" data-bs-target="#preferences" type="button">
                    <i class="fas fa-sliders-h me-2"></i> Preferences
                </button>
            </li>
        </ul>

        <div class="tab-content" id="settingsTabsContent">

            <!-- ==================== PROFILE TAB ==================== -->
            <div class="tab-pane fade show active" id="profile" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-user-edit me-2"></i>Profile Information</h5>

                    <form method="POST" class="row g-3">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

                        <div class="col-md-6">
                            <label class="form-label">Username</label>
                            <input type="text" class="form-control" value="<?= htmlspecialchars($userData['username'] ?? '') ?>" readonly>
                            <div class="form-text">Username cannot be changed</div>
                        </div>

                        <div class="col-md-6">
                            <label for="email" class="form-label">Email Address *</label>
                            <input type="email" class="form-control" id="email" name="email"
                                value="<?= htmlspecialchars($userData['email'] ?? '') ?>" required>
                        </div>

                        <div class="col-md-6">
                            <label for="full_name" class="form-label">Full Name</label>
                            <input type="text" class="form-control" id="full_name" name="full_name"
                                value="<?= htmlspecialchars($userData['full_name'] ?? '') ?>"
                                placeholder="Enter your full name">
                        </div>

                        <div class="col-md-6">
                            <label class="form-label">Account Type</label>
                            <input type="text" class="form-control"
                                value="<?= htmlspecialchars(ucfirst($userData['role'] ?? 'user')) ?>" readonly>
                        </div>

                        <div class="col-md-6">
                            <label class="form-label">Member Since</label>
                            <input type="text" class="form-control"
                                value="<?= !empty($userData['created_at']) ? date('F j, Y', strtotime($userData['created_at'])) : 'N/A' ?>" readonly>
                        </div>

                        <div class="col-md-6">
                            <label class="form-label">Last Login</label>
                            <input type="text" class="form-control"
                                value="<?= !empty($userData['last_login']) ? date('F j, Y H:i', strtotime($userData['last_login'])) : 'N/A' ?>" readonly>
                        </div>

                        <div class="col-12 mt-2">
                            <button type="submit" name="update_profile" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i> Update Profile
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- ==================== SECURITY TAB ==================== -->
            <div class="tab-pane fade" id="security" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-shield-alt me-2"></i>Security Settings</h5>

                    <div class="mb-5">
                        <h6 class="border-bottom pb-2 mb-3">Change Password</h6>
                        <form method="POST" class="row g-3">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

                            <div class="col-md-6">
                                <label class="form-label">Current Password *</label>
                                <div class="input-group">
                                    <input type="password" class="form-control" id="current_password" name="current_password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePwd('current_password')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="col-md-6"></div>

                            <div class="col-md-6">
                                <label class="form-label">New Password *</label>
                                <div class="input-group">
                                    <input type="password" class="form-control" id="new_password" name="new_password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePwd('new_password')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                                <div class="form-text">Minimum 8 characters</div>
                            </div>

                            <div class="col-md-6">
                                <label class="form-label">Confirm New Password *</label>
                                <div class="input-group">
                                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePwd('confirm_password')">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                </div>
                            </div>

                            <div class="col-12 mt-2">
                                <button type="submit" name="change_password" class="btn btn-primary">
                                    <i class="fas fa-key me-2"></i> Change Password
                                </button>
                            </div>
                        </form>
                    </div>

                    <div>
                        <h6 class="border-bottom pb-2 mb-3">Security Features</h6>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="two_factor_auth" name="two_factor_auth" value="1">
                                <label class="form-check-label" for="two_factor_auth">
                                    <strong>Two-Factor Authentication</strong>
                                    <p class="text-muted mb-0 small">Add an extra layer of security</p>
                                </label>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Session Timeout</label>
                                <select class="form-select" name="session_timeout">
                                    <option value="15">15 minutes</option>
                                    <option value="30" selected>30 minutes</option>
                                    <option value="60">1 hour</option>
                                    <option value="120">2 hours</option>
                                </select>
                            </div>
                            <button type="submit" name="update_security" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i> Save Security Settings
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- ==================== NOTIFICATIONS TAB ==================== -->
            <div class="tab-pane fade" id="notifications" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-bell me-2"></i>Notification Preferences</h5>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

                        <?php foreach ([
                            ['email_notifications', 'Email Notifications', 'Receive security alerts via email'],
                            ['push_notifications', 'Push Notifications', 'Real-time alerts in your browser'],
                            ['security_alerts', 'Critical Security Alerts', 'Immediate notifications for critical events'],
                        ] as [$name, $label, $desc]): ?>
                        <div class="form-check form-switch mb-4">
                            <input class="form-check-input" type="checkbox" id="<?= $name ?>"
                                name="<?= $name ?>" value="1" checked>
                            <label class="form-check-label" for="<?= $name ?>">
                                <strong><?= $label ?></strong>
                                <p class="text-muted mb-0 small"><?= $desc ?></p>
                            </label>
                        </div>
                        <?php endforeach; ?>

                        <button type="submit" name="update_notifications" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i> Save Notification Settings
                        </button>
                    </form>
                </div>
            </div>

            <!-- ==================== PREFERENCES TAB ==================== -->
            <div class="tab-pane fade" id="preferences" role="tabpanel">
                <div class="dashboard-card">
                    <h5 class="mb-4"><i class="fas fa-sliders-h me-2"></i>User Preferences</h5>
                    <form method="POST" id="preferencesForm">
                        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label class="form-label">Timezone</label>
                                <select class="form-select" name="timezone">
                                    <option value="UTC" selected>UTC</option>
                                    <option value="Asia/Kolkata">India (IST)</option>
                                    <option value="America/New_York">Eastern (ET)</option>
                                    <option value="America/Los_Angeles">Pacific (PT)</option>
                                    <option value="Europe/London">London (GMT)</option>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Items Per Page</label>
                                <select class="form-select" name="items_per_page">
                                    <option value="10">10</option>
                                    <option value="20" selected>20</option>
                                    <option value="50">50</option>
                                    <option value="100">100</option>
                                </select>
                            </div>
                            <div class="col-12">
                                <div class="form-check form-switch mb-3">
                                    <input class="form-check-input" type="checkbox" id="auto_refresh" name="auto_refresh" value="1" checked>
                                    <label class="form-check-label" for="auto_refresh">
                                        <strong>Auto-Refresh Dashboard</strong>
                                        <p class="text-muted mb-0 small">Refresh dashboard data every 30 seconds</p>
                                    </label>
                                </div>
                            </div>
                        </div>
                        <div class="mt-3">
                            <button type="submit" name="update_preferences" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i> Save Preferences
                            </button>
                        </div>
                    </form>
                </div>
            </div>

        </div><!-- /tab-content -->
    </div>

    <!-- Account Management -->
    <div class="col-12">
        <div class="dashboard-card">
            <h5 class="mb-4 text-danger"><i class="fas fa-exclamation-triangle me-2"></i>Account Management</h5>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle me-2"></i>
                <strong>Warning:</strong> The following actions are permanent and cannot be undone.
            </div>
            <div class="row g-3">
                <div class="col-md-6">
                    <div class="card bg-dark border-danger">
                        <div class="card-body">
                            <h6 class="card-title text-danger"><i class="fas fa-file-export me-2"></i>Export Data</h6>
                            <p class="card-text small text-muted">Download all your personal data.</p>
                            <a href="../pages/export.php" class="btn btn-outline-danger btn-sm">
                                <i class="fas fa-download me-1"></i> Go to Export
                            </a>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card bg-dark border-danger">
                        <div class="card-body">
                            <h6 class="card-title text-danger"><i class="fas fa-sign-out-alt me-2"></i>Logout</h6>
                            <p class="card-text small text-muted">Sign out from all sessions.</p>
                            <a href="logout.php" class="btn btn-danger btn-sm">
                                <i class="fas fa-sign-out-alt me-1"></i> Logout Now
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function togglePwd(id) {
    const el = document.getElementById(id);
    const btn = el.nextElementSibling.querySelector('i');
    if (el.type === 'password') {
        el.type = 'text';
        btn.classList.replace('fa-eye', 'fa-eye-slash');
    } else {
        el.type = 'password';
        btn.classList.replace('fa-eye-slash', 'fa-eye');
    }
}

// Restore active tab
$(document).ready(function() {
    $('#settingsTabs button').click(function() {
        localStorage.setItem('activeSettingsTab', $(this).attr('id'));
    });
    var activeTab = localStorage.getItem('activeSettingsTab');
    if (activeTab && document.getElementById(activeTab)) {
        new bootstrap.Tab(document.getElementById(activeTab)).show();
    }
});
</script>

<?php require_once '../includes/footer.php'; ?>