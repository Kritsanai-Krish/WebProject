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

// Get statistics
$stats = [
    'total_licenses' => $pdo->query("SELECT COUNT(*) FROM license_keys")->fetchColumn(),
    'active_licenses' => $pdo->query("SELECT COUNT(*) FROM license_keys WHERE status = 'active'")->fetchColumn(),
    'expired_licenses' => $pdo->query("SELECT COUNT(*) FROM license_keys WHERE status = 'expired'")->fetchColumn(),
    'banned_licenses' => $pdo->query("SELECT COUNT(*) FROM license_keys WHERE status = 'banned'")->fetchColumn(),
    'paused_licenses' => $pdo->query("SELECT COUNT(*) FROM license_keys WHERE status = 'paused'")->fetchColumn(),
];

// Get recent activities
$recentActivities = $pdo->query("
    SELECT l.*, a.username as created_by_name 
    FROM license_keys l 
    LEFT JOIN admins a ON l.created_by = a.id 
    ORDER BY l.updated_at DESC 
    LIMIT 10
")->fetchAll();

// Get recent login attempts
$recentLogins = $pdo->query("
    SELECT * FROM login_attempts 
    ORDER BY attempt_time DESC 
    LIMIT 10
")->fetchAll();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - License Management</title>
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
                <a href="index.php" class="nav-item active">
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
                <a href="settings.php" class="nav-item">
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
                <h1>Dashboard</h1>
                <div class="user-info">
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['admin_username']); ?></span>
                    <small>Last login: <?php echo date('Y-m-d H:i:s', $_SESSION['last_activity']); ?></small>
                </div>
            </div>

            <!-- Statistics Cards -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['total_licenses']; ?></h3>
                        <p>Total Licenses</p>
                    </div>
                </div>
                <div class="stat-card active">
                    <div class="stat-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['active_licenses']; ?></h3>
                        <p>Active Licenses</p>
                    </div>
                </div>
                <div class="stat-card expired">
                    <div class="stat-icon">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['expired_licenses']; ?></h3>
                        <p>Expired Licenses</p>
                    </div>
                </div>
                <div class="stat-card banned">
                    <div class="stat-icon">
                        <i class="fas fa-ban"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['banned_licenses']; ?></h3>
                        <p>Banned Licenses</p>
                    </div>
                </div>
            </div>

            <!-- Recent Activities -->
            <div class="content-grid">
                <div class="content-card">
                    <div class="card-header">
                        <h3><i class="fas fa-history"></i> Recent License Activities</h3>
                    </div>
                    <div class="card-content">
                        <div class="table-responsive">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>License Key</th>
                                        <th>Status</th>
                                        <th>Expires</th>
                                        <th>Last Used</th>
                                        <th>Created By</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($recentActivities as $activity): ?>
                                    <tr>
                                        <td>
                                            <code><?php echo htmlspecialchars(substr($activity['license_key'], 0, 12) . '...'); ?></code>
                                        </td>
                                        <td>
                                            <span class="status-badge status-<?php echo $activity['status']; ?>">
                                                <?php echo ucfirst($activity['status']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php echo $activity['expires_at'] ? date('Y-m-d H:i', strtotime($activity['expires_at'])) : 'Never'; ?>
                                        </td>
                                        <td>
                                            <?php echo $activity['last_used_at'] ? date('Y-m-d H:i', strtotime($activity['last_used_at'])) : 'Never'; ?>
                                        </td>
                                        <td>
                                            <?php echo htmlspecialchars($activity['created_by_name'] ?? 'System'); ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="content-card">
                    <div class="card-header">
                        <h3><i class="fas fa-shield-alt"></i> Security Logs</h3>
                    </div>
                    <div class="card-content">
                        <div class="table-responsive">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Status</th>
                                        <th>Time</th>
                                        <th>User Agent</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($recentLogins as $login): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($login['ip_address']); ?></td>
                                        <td>
                                            <span class="status-badge status-<?php echo $login['success'] ? 'success' : 'failed'; ?>">
                                                <?php echo $login['success'] ? 'Success' : 'Failed'; ?>
                                            </span>
                                        </td>
                                        <td><?php echo date('Y-m-d H:i:s', strtotime($login['attempt_time'])); ?></td>
                                        <td>
                                            <span class="truncate" title="<?php echo htmlspecialchars($login['user_agent']); ?>">
                                                <?php echo htmlspecialchars(substr($login['user_agent'], 0, 50) . '...'); ?>
                                            </span>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="admin-script.js"></script>
</body>
</html> 