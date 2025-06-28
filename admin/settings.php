<?php
require_once '../config.php';

// Check if admin is logged in
if (!isset($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit();
}

// Check session timeout
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
    session_destroy();
    header('Location: login.php?msg=timeout');
    exit();
}
$_SESSION['last_activity'] = time();

$pdo = getDBConnection();
$message = '';
$error = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    if (!validateCSRFToken($csrf_token)) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'update_settings') {
            try {
                $settings = [
                    'max_login_attempts' => (int)($_POST['max_login_attempts'] ?? 5),
                    'lockout_duration' => (int)($_POST['lockout_duration'] ?? 900),
                    'session_timeout' => (int)($_POST['session_timeout'] ?? 3600),
                    'require_fingerprint' => (int)($_POST['require_fingerprint'] ?? 1),
                    'max_concurrent_sessions' => (int)($_POST['max_concurrent_sessions'] ?? 1),
                    'auto_cleanup_days' => (int)($_POST['auto_cleanup_days'] ?? 30)
                ];
                
                // Update settings
                foreach ($settings as $key => $value) {
                    $stmt = $pdo->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?");
                    $stmt->execute([$key, $value, $value]);
                }
                
                $message = 'Settings updated successfully.';
                logActivity('Updated system settings', 'Settings modified by admin', null);
            } catch (Exception $e) {
                $error = 'Failed to update settings: ' . $e->getMessage();
            }
        }
    }
}

// Get current settings
$settings = [];
$stmt = $pdo->query("SELECT setting_key, setting_value FROM system_settings");
while ($row = $stmt->fetch()) {
    $settings[$row['setting_key']] = $row['setting_value'];
}

// Set defaults
$defaults = [
    'max_login_attempts' => 5,
    'lockout_duration' => 900,
    'session_timeout' => 3600,
    'require_fingerprint' => 1,
    'max_concurrent_sessions' => 1,
    'auto_cleanup_days' => 30
];

foreach ($defaults as $key => $default_value) {
    if (!isset($settings[$key])) {
        $settings[$key] = $default_value;
    }
}

// Get system statistics
$stats = $pdo->query("
    SELECT 
        (SELECT COUNT(*) FROM license_keys) as total_licenses,
        (SELECT COUNT(*) FROM license_keys WHERE status = 'active') as active_licenses,
        (SELECT COUNT(*) FROM license_usage_log) as total_logs,
        (SELECT COUNT(*) FROM admins) as total_admins
")->fetch();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Settings - Admin Panel</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="admin-style.css">
</head>
<body>
    <div class="admin-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">
                <h2><i class="fas fa-shield-alt"></i> Admin Panel</h2>
            </div>
            <nav class="sidebar-nav">
                <a href="index.php" class="nav-item">
                    <i class="fas fa-tachometer-alt"></i> Dashboard
                </a>
                <a href="licenses.php" class="nav-item">
                    <i class="fas fa-key"></i> License Keys
                </a>
                <a href="generate.php" class="nav-item">
                    <i class="fas fa-plus-circle"></i> Generate Keys
                </a>
                <a href="users.php" class="nav-item">
                    <i class="fas fa-users"></i> User Management
                </a>
                <a href="logs.php" class="nav-item">
                    <i class="fas fa-list-alt"></i> Activity Logs
                </a>
                <a href="settings.php" class="nav-item active">
                    <i class="fas fa-cog"></i> Settings
                </a>
                <a href="logout.php" class="nav-item logout">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </nav>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <div class="header">
                <h1>System Settings</h1>
                <div class="user-info">
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['admin_username']); ?></span>
                    <small>Last login: <?php echo date('Y-m-d H:i:s', $_SESSION['last_activity']); ?></small>
                </div>
            </div>

            <?php if ($message): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <!-- System Statistics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['total_licenses']); ?></h3>
                        <p>Total Licenses</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon active">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['active_licenses']); ?></h3>
                        <p>Active Licenses</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon info">
                        <i class="fas fa-list"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['total_logs']); ?></h3>
                        <p>Total Logs</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon secondary">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['total_admins']); ?></h3>
                        <p>Total Admins</p>
                    </div>
                </div>
            </div>

            <!-- Settings Form -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-cog"></i> System Settings</h3>
                </div>
                <div class="card-content">
                    <form method="POST" class="settings-form">
                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                        <input type="hidden" name="action" value="update_settings">
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="max_login_attempts">
                                    <i class="fas fa-lock"></i>
                                    Max Login Attempts
                                </label>
                                <input type="number" id="max_login_attempts" name="max_login_attempts" 
                                       value="<?php echo htmlspecialchars($settings['max_login_attempts']); ?>" 
                                       min="1" max="20" required>
                                <small>Maximum failed login attempts before lockout</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="lockout_duration">
                                    <i class="fas fa-clock"></i>
                                    Lockout Duration (seconds)
                                </label>
                                <input type="number" id="lockout_duration" name="lockout_duration" 
                                       value="<?php echo htmlspecialchars($settings['lockout_duration']); ?>" 
                                       min="60" max="86400" required>
                                <small>Duration of lockout after max attempts</small>
                            </div>
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="session_timeout">
                                    <i class="fas fa-hourglass"></i>
                                    Session Timeout (seconds)
                                </label>
                                <input type="number" id="session_timeout" name="session_timeout" 
                                       value="<?php echo htmlspecialchars($settings['session_timeout']); ?>" 
                                       min="300" max="86400" required>
                                <small>Session timeout duration</small>
                            </div>
                            
                            <div class="form-group">
                                <label for="max_concurrent_sessions">
                                    <i class="fas fa-users"></i>
                                    Max Concurrent Sessions
                                </label>
                                <input type="number" id="max_concurrent_sessions" name="max_concurrent_sessions" 
                                       value="<?php echo htmlspecialchars($settings['max_concurrent_sessions']); ?>" 
                                       min="1" max="10" required>
                                <small>Maximum concurrent sessions per license</small>
                            </div>
                        </div>
                        
                        <div class="form-row">
                            <div class="form-group">
                                <label for="auto_cleanup_days">
                                    <i class="fas fa-broom"></i>
                                    Auto Cleanup Days
                                </label>
                                <input type="number" id="auto_cleanup_days" name="auto_cleanup_days" 
                                       value="<?php echo htmlspecialchars($settings['auto_cleanup_days']); ?>" 
                                       min="1" max="365" required>
                                <small>Days to keep old logs before auto-cleanup</small>
                            </div>
                            
                            <div class="form-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" name="require_fingerprint" value="1" 
                                           <?php echo $settings['require_fingerprint'] ? 'checked' : ''; ?>>
                                    <span class="checkmark"></span>
                                    <i class="fas fa-fingerprint"></i>
                                    Require Device Fingerprint
                                </label>
                                <small>Require device fingerprint for license activation</small>
                            </div>
                        </div>
                        
                        <div class="form-actions">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- System Information -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-info-circle"></i> System Information</h3>
                </div>
                <div class="card-content">
                    <div class="system-info">
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>PHP Version:</strong> <?php echo PHP_VERSION; ?>
                            </div>
                            <div class="info-item">
                                <strong>Database:</strong> MySQL
                            </div>
                            <div class="info-item">
                                <strong>Server Time:</strong> <?php echo date('Y-m-d H:i:s'); ?>
                            </div>
                            <div class="info-item">
                                <strong>Timezone:</strong> <?php echo date_default_timezone_get(); ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <style>
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: rgba(99, 102, 241, 0.1);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: var(--primary-color);
        }
        
        .stat-icon.active {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-color);
        }
        
        .stat-icon.info {
            background: rgba(59, 130, 246, 0.1);
            color: var(--info-color);
        }
        
        .stat-icon.secondary {
            background: rgba(107, 114, 128, 0.1);
            color: var(--text-secondary);
        }
        
        .stat-content h3 {
            font-size: 2rem;
            font-weight: 700;
            margin: 0;
            color: var(--text-primary);
        }
        
        .stat-content p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .settings-form {
            max-width: 100%;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }
        
        .form-group small {
            display: block;
            margin-top: 0.25rem;
            color: var(--text-muted);
            font-size: 0.8rem;
        }
        
        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        .checkbox-label input[type="checkbox"] {
            display: none;
        }
        
        .checkmark {
            width: 20px;
            height: 20px;
            border: 2px solid var(--border-color);
            border-radius: 0.25rem;
            position: relative;
            transition: all 0.3s ease;
        }
        
        .checkbox-label input[type="checkbox"]:checked + .checkmark {
            background: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .checkbox-label input[type="checkbox"]:checked + .checkmark::after {
            content: '✓';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .form-actions {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
        }
        
        .system-info {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1.5rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        
        .info-item {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .info-item strong {
            color: var(--text-primary);
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</body>
</html> 