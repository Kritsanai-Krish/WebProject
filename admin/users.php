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

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    if (!validateCSRFToken($csrf_token)) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        $license_id = (int)($_POST['license_id'] ?? 0);
        
        if ($license_id > 0) {
            try {
                switch ($action) {
                    case 'reset_device':
                        $stmt = $pdo->prepare("UPDATE license_keys SET locked_fingerprint = NULL, locked_ip = NULL, locked_user_agent = NULL, locked_cookies = NULL, locked_screen_resolution = NULL, locked_timezone = NULL, locked_language = NULL, locked_platform = NULL, locked_browser = NULL WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'Device lock reset successfully.';
                        logActivity('Reset device lock', "License ID: {$license_id}", null);
                        break;
                        
                    case 'ban_user':
                        $stmt = $pdo->prepare("UPDATE license_keys SET status = 'banned' WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'User banned successfully.';
                        logActivity('Banned user', "License ID: {$license_id}", null);
                        break;
                        
                    case 'unban_user':
                        $stmt = $pdo->prepare("UPDATE license_keys SET status = 'active' WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'User unbanned successfully.';
                        logActivity('Unbanned user', "License ID: {$license_id}", null);
                        break;
                        
                    case 'extend_access':
                        $days = (int)($_POST['extend_days'] ?? 30);
                        $stmt = $pdo->prepare("UPDATE license_keys SET expires_at = DATE_ADD(COALESCE(expires_at, NOW()), INTERVAL ? DAY) WHERE id = ?");
                        $stmt->execute([$days, $license_id]);
                        $message = "Access extended by {$days} days successfully.";
                        logActivity('Extended user access', "License ID: {$license_id}, Days: {$days}", null);
                        break;
                }
            } catch (Exception $e) {
                $error = 'Failed to perform action: ' . $e->getMessage();
            }
        }
    }
}

// Get filters
$status_filter = $_GET['status'] ?? '';
$search = $_GET['search'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$per_page = 20;
$offset = ($page - 1) * $per_page;

// Build query for active users (license keys with device locks)
$where_conditions = ["l.locked_fingerprint IS NOT NULL"];
$params = [];

if ($status_filter) {
    $where_conditions[] = "l.status = ?";
    $params[] = $status_filter;
}

if ($search) {
    $where_conditions[] = "(l.license_key LIKE ? OR l.locked_ip LIKE ? OR l.locked_user_agent LIKE ?)";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
}

$where_clause = 'WHERE ' . implode(' AND ', $where_conditions);

// Get total count
$count_query = "SELECT COUNT(*) FROM license_keys l {$where_clause}";
$stmt = $pdo->prepare($count_query);
$stmt->execute($params);
$total_records = $stmt->fetchColumn();
$total_pages = ceil($total_records / $per_page);

// Get active users
$query = "
    SELECT l.*, a.username as created_by_name,
           (SELECT COUNT(*) FROM license_usage_log WHERE license_key_id = l.id) as usage_logs,
           (SELECT MAX(access_time) FROM license_usage_log WHERE license_key_id = l.id) as last_activity
    FROM license_keys l 
    LEFT JOIN admins a ON l.created_by = a.id 
    {$where_clause}
    ORDER BY l.last_used_at DESC 
    LIMIT {$per_page} OFFSET {$offset}
";

$stmt = $pdo->prepare($query);
$stmt->execute($params);
$users = $stmt->fetchAll();

// Get statistics
$stats = $pdo->query("
    SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_users,
        COUNT(CASE WHEN status = 'banned' THEN 1 END) as banned_users,
        COUNT(CASE WHEN expires_at < NOW() THEN 1 END) as expired_users
    FROM license_keys 
    WHERE locked_fingerprint IS NOT NULL
")->fetch();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - Admin Panel</title>
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
                <a href="users.php" class="nav-item active">
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
                <button id="sidebarToggle" class="sidebar-toggle"><i class="fas fa-bars"></i></button>
                <h1>User Management</h1>
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

            <!-- Statistics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['total_users']; ?></h3>
                        <p>Total Users</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon active">
                        <i class="fas fa-user-check"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['active_users']; ?></h3>
                        <p>Active Users</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon warning">
                        <i class="fas fa-user-clock"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['expired_users']; ?></h3>
                        <p>Expired Users</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon danger">
                        <i class="fas fa-user-slash"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo $stats['banned_users']; ?></h3>
                        <p>Banned Users</p>
                    </div>
                </div>
            </div>

            <!-- Filters -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-filter"></i> Filters</h3>
                </div>
                <div class="card-content">
                    <form method="GET" class="filter-form">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="status">Status</label>
                                <select id="status" name="status">
                                    <option value="">All Status</option>
                                    <option value="active" <?php echo $status_filter === 'active' ? 'selected' : ''; ?>>Active</option>
                                    <option value="paused" <?php echo $status_filter === 'paused' ? 'selected' : ''; ?>>Paused</option>
                                    <option value="expired" <?php echo $status_filter === 'expired' ? 'selected' : ''; ?>>Expired</option>
                                    <option value="banned" <?php echo $status_filter === 'banned' ? 'selected' : ''; ?>>Banned</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="search">Search</label>
                                <input type="text" id="search" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search license key, IP, or user agent...">
                            </div>
                            <div class="form-group">
                                <label>&nbsp;</label>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search"></i> Search
                                </button>
                                <a href="users.php" class="btn btn-secondary">
                                    <i class="fas fa-times"></i> Clear
                                </a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Users Table -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-users"></i> Active Users (<?php echo $total_records; ?> total)</h3>
                </div>
                <div class="card-content">
                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Status</th>
                                    <th>IP Address</th>
                                    <th>Device Info</th>
                                    <th>Last Activity</th>
                                    <th>Expires</th>
                                    <th>Usage</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($users as $user): ?>
                                <tr>
                                    <td>
                                        <code class="license-key" onclick="copyToClipboard('<?php echo $user['license_key']; ?>')" title="Click to copy">
                                            <?php echo htmlspecialchars($user['license_key']); ?>
                                        </code>
                                    </td>
                                    <td>
                                        <span class="status-badge status-<?php echo $user['status']; ?>">
                                            <?php echo ucfirst($user['status']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($user['locked_ip'] ?? 'N/A'); ?></code>
                                    </td>
                                    <td>
                                        <div class="device-info">
                                            <div><strong>Browser:</strong> <?php echo htmlspecialchars($user['locked_browser'] ?? 'Unknown'); ?></div>
                                            <div><strong>Platform:</strong> <?php echo htmlspecialchars($user['locked_platform'] ?? 'Unknown'); ?></div>
                                            <div><strong>Resolution:</strong> <?php echo htmlspecialchars($user['locked_screen_resolution'] ?? 'Unknown'); ?></div>
                                        </div>
                                    </td>
                                    <td>
                                        <?php 
                                        if ($user['last_activity']) {
                                            $last_activity = strtotime($user['last_activity']);
                                            $now = time();
                                            $diff = $now - $last_activity;
                                            
                                            if ($diff < 3600) {
                                                echo '<span style="color: #10b981;">' . floor($diff / 60) . ' min ago</span>';
                                            } elseif ($diff < 86400) {
                                                echo '<span style="color: #f59e0b;">' . floor($diff / 3600) . ' hours ago</span>';
                                            } else {
                                                echo '<span style="color: #ef4444;">' . floor($diff / 86400) . ' days ago</span>';
                                            }
                                        } else {
                                            echo '<span style="color: var(--text-muted);">Never</span>';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <?php 
                                        if ($user['expires_at']) {
                                            $expires = strtotime($user['expires_at']);
                                            $now = time();
                                            $days_left = ceil(($expires - $now) / 86400);
                                            
                                            if ($days_left < 0) {
                                                echo '<span style="color: #ef4444;">Expired</span>';
                                            } elseif ($days_left <= 7) {
                                                echo '<span style="color: #f59e0b;">' . $days_left . ' days left</span>';
                                            } else {
                                                echo '<span style="color: #10b981;">' . $days_left . ' days left</span>';
                                            }
                                        } else {
                                            echo '<span style="color: #10b981;">Never</span>';
                                        }
                                        ?>
                                    </td>
                                    <td>
                                        <?php echo $user['usage_count']; ?> / <?php echo $user['max_usage']; ?>
                                        <?php if ($user['usage_logs'] > 0): ?>
                                            <br><small style="color: var(--text-muted);"><?php echo $user['usage_logs']; ?> log entries</small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <button onclick="performAction('reset_device', <?php echo $user['id']; ?>)" class="btn btn-info btn-sm" title="Reset Device Lock">
                                                <i class="fas fa-unlock"></i>
                                            </button>
                                            
                                            <?php if ($user['status'] === 'banned'): ?>
                                                <button onclick="performAction('unban_user', <?php echo $user['id']; ?>)" class="btn btn-success btn-sm" title="Unban User">
                                                    <i class="fas fa-user-check"></i>
                                                </button>
                                            <?php else: ?>
                                                <button onclick="performAction('ban_user', <?php echo $user['id']; ?>)" class="btn btn-danger btn-sm" title="Ban User">
                                                    <i class="fas fa-user-slash"></i>
                                                </button>
                                            <?php endif; ?>
                                            
                                            <button onclick="showExtendModal(<?php echo $user['id']; ?>)" class="btn btn-secondary btn-sm" title="Extend Access">
                                                <i class="fas fa-clock"></i>
                                            </button>
                                            
                                            <button onclick="showDeviceDetails(<?php echo $user['id']; ?>)" class="btn btn-primary btn-sm" title="View Details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                    <div class="pagination">
                        <?php if ($page > 1): ?>
                            <a href="?page=<?php echo $page - 1; ?>&status=<?php echo urlencode($status_filter); ?>&search=<?php echo urlencode($search); ?>" class="btn btn-secondary">
                                <i class="fas fa-chevron-left"></i> Previous
                            </a>
                        <?php endif; ?>
                        
                        <span class="page-info">
                            Page <?php echo $page; ?> of <?php echo $total_pages; ?>
                        </span>
                        
                        <?php if ($page < $total_pages): ?>
                            <a href="?page=<?php echo $page + 1; ?>&status=<?php echo urlencode($status_filter); ?>&search=<?php echo urlencode($search); ?>" class="btn btn-secondary">
                                Next <i class="fas fa-chevron-right"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Extend Modal -->
    <div id="extendModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Extend User Access</h3>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <form method="POST" id="extendForm">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="action" value="extend_access">
                <input type="hidden" name="license_id" id="extendLicenseId">
                
                <div class="form-group">
                    <label for="extend_days">Extend by (days)</label>
                    <input type="number" id="extend_days" name="extend_days" min="1" max="3650" value="30" required>
                </div>
                
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Extend Access</button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Device Details Modal -->
    <div id="deviceModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Device Details</h3>
                <span class="close" onclick="closeDeviceModal()">&times;</span>
            </div>
            <div id="deviceDetails" class="modal-body">
                <!-- Device details will be loaded here -->
            </div>
        </div>
    </div>

    <script>
        function performAction(action, licenseId) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="action" value="${action}">
                <input type="hidden" name="license_id" value="${licenseId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }
        
        function showExtendModal(licenseId) {
            document.getElementById('extendLicenseId').value = licenseId;
            document.getElementById('extendModal').style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('extendModal').style.display = 'none';
        }
        
        function showDeviceDetails(licenseId) {
            // This would typically load device details via AJAX
            // For now, we'll show a placeholder
            document.getElementById('deviceDetails').innerHTML = `
                <div style="padding: 1.5rem;">
                    <p>Device details for license ID: ${licenseId}</p>
                    <p>This would show detailed device information including:</p>
                    <ul>
                        <li>Browser details</li>
                        <li>Operating system</li>
                        <li>Screen resolution</li>
                        <li>Timezone</li>
                        <li>Language settings</li>
                        <li>Canvas fingerprint</li>
                        <li>WebGL fingerprint</li>
                    </ul>
                </div>
            `;
            document.getElementById('deviceModal').style.display = 'block';
        }
        
        function closeDeviceModal() {
            document.getElementById('deviceModal').style.display = 'none';
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                const notification = document.createElement('div');
                notification.className = 'copy-notification';
                notification.textContent = 'License key copied to clipboard!';
                notification.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: var(--success-color);
                    color: white;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    z-index: 1000;
                    animation: slideIn 0.3s ease;
                `;
                document.body.appendChild(notification);
                
                setTimeout(() => {
                    notification.remove();
                }, 3000);
            }).catch(function(err) {
                console.error('Failed to copy: ', err);
            });
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            const extendModal = document.getElementById('extendModal');
            const deviceModal = document.getElementById('deviceModal');
            
            if (event.target === extendModal) {
                closeModal();
            }
            if (event.target === deviceModal) {
                closeDeviceModal();
            }
        }
    </script>

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
        
        .stat-icon.warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning-color);
        }
        
        .stat-icon.danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger-color);
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
        
        .filter-form {
            margin-bottom: 1rem;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            align-items: end;
        }
        
        .action-buttons {
            display: flex;
            gap: 0.25rem;
            flex-wrap: wrap;
        }
        
        .btn-sm {
            padding: 0.5rem 0.75rem;
            font-size: 0.875rem;
        }
        
        .device-info {
            font-size: 0.8rem;
            line-height: 1.4;
        }
        
        .device-info div {
            margin-bottom: 0.25rem;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
        }
        
        .page-info {
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .modal {
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
        }
        
        .modal-content {
            background-color: var(--card-bg);
            margin: 15% auto;
            padding: 0;
            border-radius: 0.5rem;
            width: 90%;
            max-width: 500px;
            border: 1px solid var(--border-color);
        }
        
        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-header h3 {
            margin: 0;
        }
        
        .close {
            color: var(--text-muted);
            font-size: 1.5rem;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: var(--text-secondary);
        }
        
        .modal-content form,
        .modal-body {
            padding: 1.5rem;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .action-buttons {
                flex-direction: column;
            }
            
            .btn-sm {
                width: 100%;
                justify-content: center;
            }
        }
    </style>
</body>
</html> 