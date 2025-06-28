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
        
        if ($action === 'clear_logs') {
            try {
                $days = (int)($_POST['days'] ?? 30);
                $stmt = $pdo->prepare("DELETE FROM license_usage_log WHERE access_time < DATE_SUB(NOW(), INTERVAL ? DAY)");
                $stmt->execute([$days]);
                $deleted_count = $stmt->rowCount();
                $message = "Cleared {$deleted_count} log entries older than {$days} days.";
                logActivity('Cleared logs', "Cleared {$deleted_count} entries older than {$days} days", null);
            } catch (Exception $e) {
                $error = 'Failed to clear logs: ' . $e->getMessage();
            }
        }
    }
}

// Get filters
$status_filter = $_GET['status'] ?? '';
$search = $_GET['search'] ?? '';
$date_from = $_GET['date_from'] ?? '';
$date_to = $_GET['date_to'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$per_page = 50;
$offset = ($page - 1) * $per_page;

// Build query
$where_conditions = [];
$params = [];

if ($status_filter) {
    $where_conditions[] = "l.status = ?";
    $params[] = $status_filter;
}

if ($search) {
    $where_conditions[] = "(l.ip_address LIKE ? OR l.user_agent LIKE ? OR l.reason LIKE ? OR lk.license_key LIKE ?)";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
}

if ($date_from) {
    $where_conditions[] = "l.access_time >= ?";
    $params[] = $date_from . ' 00:00:00';
}

if ($date_to) {
    $where_conditions[] = "l.access_time <= ?";
    $params[] = $date_to . ' 23:59:59';
}

$where_clause = $where_conditions ? 'WHERE ' . implode(' AND ', $where_conditions) : '';

// Get total count
$count_query = "
    SELECT COUNT(*) 
    FROM license_usage_log l 
    LEFT JOIN license_keys lk ON l.license_key_id = lk.id 
    {$where_clause}
";
$stmt = $pdo->prepare($count_query);
$stmt->execute($params);
$total_records = $stmt->fetchColumn();
$total_pages = ceil($total_records / $per_page);

// Get logs
$query = "
    SELECT l.*, lk.license_key, lk.status as license_status
    FROM license_usage_log l 
    LEFT JOIN license_keys lk ON l.license_key_id = lk.id 
    {$where_clause}
    ORDER BY l.access_time DESC 
    LIMIT {$per_page} OFFSET {$offset}
";

$stmt = $pdo->prepare($query);
$stmt->execute($params);
$logs = $stmt->fetchAll();

// Get statistics
$stats = $pdo->query("
    SELECT 
        COUNT(*) as total_logs,
        COUNT(CASE WHEN status = 'success' THEN 1 END) as success_logs,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_logs,
        COUNT(CASE WHEN status = 'blocked' THEN 1 END) as blocked_logs,
        COUNT(DISTINCT ip_address) as unique_ips,
        COUNT(DISTINCT license_key_id) as unique_licenses
    FROM license_usage_log
")->fetch();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activity Logs - Admin Panel</title>
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
                <a href="logs.php" class="nav-item active">
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
                <h1>Activity Logs</h1>
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
                        <i class="fas fa-list"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['total_logs']); ?></h3>
                        <p>Total Logs</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon active">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['success_logs']); ?></h3>
                        <p>Success</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon warning">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['failed_logs']); ?></h3>
                        <p>Failed</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon danger">
                        <i class="fas fa-ban"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['blocked_logs']); ?></h3>
                        <p>Blocked</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon info">
                        <i class="fas fa-globe"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['unique_ips']); ?></h3>
                        <p>Unique IPs</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon secondary">
                        <i class="fas fa-key"></i>
                    </div>
                    <div class="stat-content">
                        <h3><?php echo number_format($stats['unique_licenses']); ?></h3>
                        <p>Active Licenses</p>
                    </div>
                </div>
            </div>

            <!-- Filters -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-filter"></i> Filters</h3>
                    <button onclick="showClearModal()" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Clear Old Logs
                    </button>
                </div>
                <div class="card-content">
                    <form method="GET" class="filter-form">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="status">Status</label>
                                <select id="status" name="status">
                                    <option value="">All Status</option>
                                    <option value="success" <?php echo $status_filter === 'success' ? 'selected' : ''; ?>>Success</option>
                                    <option value="failed" <?php echo $status_filter === 'failed' ? 'selected' : ''; ?>>Failed</option>
                                    <option value="blocked" <?php echo $status_filter === 'blocked' ? 'selected' : ''; ?>>Blocked</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="date_from">From Date</label>
                                <input type="date" id="date_from" name="date_from" value="<?php echo htmlspecialchars($date_from); ?>">
                            </div>
                            <div class="form-group">
                                <label for="date_to">To Date</label>
                                <input type="date" id="date_to" name="date_to" value="<?php echo htmlspecialchars($date_to); ?>">
                            </div>
                            <div class="form-group">
                                <label for="search">Search</label>
                                <input type="text" id="search" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search IP, user agent, reason, or license key...">
                            </div>
                            <div class="form-group">
                                <label>&nbsp;</label>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search"></i> Search
                                </button>
                                <a href="logs.php" class="btn btn-secondary">
                                    <i class="fas fa-times"></i> Clear
                                </a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Logs Table -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-list-alt"></i> Activity Logs (<?php echo $total_records; ?> total)</h3>
                    <div class="export-buttons">
                        <button onclick="exportLogs('csv')" class="btn btn-secondary">
                            <i class="fas fa-download"></i> Export CSV
                        </button>
                        <button onclick="exportLogs('json')" class="btn btn-secondary">
                            <i class="fas fa-download"></i> Export JSON
                        </button>
                    </div>
                </div>
                <div class="card-content">
                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>License Key</th>
                                    <th>IP Address</th>
                                    <th>Status</th>
                                    <th>User Agent</th>
                                    <th>Reason</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td>
                                        <?php echo date('Y-m-d H:i:s', strtotime($log['access_time'])); ?>
                                        <br><small style="color: var(--text-muted);">
                                            <?php 
                                            $time_diff = time() - strtotime($log['access_time']);
                                            if ($time_diff < 3600) {
                                                echo floor($time_diff / 60) . ' min ago';
                                            } elseif ($time_diff < 86400) {
                                                echo floor($time_diff / 3600) . ' hours ago';
                                            } else {
                                                echo floor($time_diff / 86400) . ' days ago';
                                            }
                                            ?>
                                        </small>
                                    </td>
                                    <td>
                                        <?php if ($log['license_key']): ?>
                                            <code class="license-key" onclick="copyToClipboard('<?php echo $log['license_key']; ?>')" title="Click to copy">
                                                <?php echo htmlspecialchars($log['license_key']); ?>
                                            </code>
                                            <br><small style="color: var(--text-muted);">
                                                Status: <?php echo ucfirst($log['license_status'] ?? 'Unknown'); ?>
                                            </small>
                                        <?php else: ?>
                                            <span style="color: var(--text-muted);">System</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <code><?php echo htmlspecialchars($log['ip_address']); ?></code>
                                        <?php if (filter_var($log['ip_address'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)): ?>
                                            <br><small style="color: var(--text-muted);">Public IP</small>
                                        <?php else: ?>
                                            <br><small style="color: var(--text-muted);">Private IP</small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <span class="status-badge status-<?php echo $log['status']; ?>">
                                            <?php echo ucfirst($log['status']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="user-agent">
                                            <?php 
                                            $user_agent = $log['user_agent'];
                                            if (strlen($user_agent) > 50) {
                                                echo htmlspecialchars(substr($user_agent, 0, 50)) . '...';
                                            } else {
                                                echo htmlspecialchars($user_agent);
                                            }
                                            ?>
                                            <button onclick="showUserAgent('<?php echo htmlspecialchars($user_agent); ?>')" class="btn btn-sm btn-secondary" title="View Full">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="reason">
                                            <?php 
                                            $reason = $log['reason'];
                                            if (strlen($reason) > 50) {
                                                echo htmlspecialchars(substr($reason, 0, 50)) . '...';
                                            } else {
                                                echo htmlspecialchars($reason);
                                            }
                                            ?>
                                            <?php if (strlen($reason) > 50): ?>
                                                <button onclick="showReason('<?php echo htmlspecialchars($reason); ?>')" class="btn btn-sm btn-secondary" title="View Full">
                                                    <i class="fas fa-eye"></i>
                                                </button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <button onclick="showLogDetails(<?php echo $log['id']; ?>)" class="btn btn-primary btn-sm" title="View Details">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <?php if ($log['license_key_id']): ?>
                                                <a href="licenses.php?search=<?php echo urlencode($log['license_key']); ?>" class="btn btn-secondary btn-sm" title="View License">
                                                    <i class="fas fa-key"></i>
                                                </a>
                                            <?php endif; ?>
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
                            <a href="?page=<?php echo $page - 1; ?>&status=<?php echo urlencode($status_filter); ?>&search=<?php echo urlencode($search); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>" class="btn btn-secondary">
                                <i class="fas fa-chevron-left"></i> Previous
                            </a>
                        <?php endif; ?>
                        
                        <span class="page-info">
                            Page <?php echo $page; ?> of <?php echo $total_pages; ?>
                        </span>
                        
                        <?php if ($page < $total_pages): ?>
                            <a href="?page=<?php echo $page + 1; ?>&status=<?php echo urlencode($status_filter); ?>&search=<?php echo urlencode($search); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>" class="btn btn-secondary">
                                Next <i class="fas fa-chevron-right"></i>
                            </a>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Clear Logs Modal -->
    <div id="clearModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Clear Old Logs</h3>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <form method="POST" id="clearForm">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="action" value="clear_logs">
                
                <div class="form-group">
                    <label for="days">Clear logs older than (days)</label>
                    <input type="number" id="days" name="days" min="1" max="365" value="30" required>
                    <small>This will permanently delete log entries older than the specified number of days.</small>
                </div>
                
                <div class="form-actions">
                    <button type="submit" class="btn btn-danger">Clear Logs</button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Details Modal -->
    <div id="detailsModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Log Details</h3>
                <span class="close" onclick="closeDetailsModal()">&times;</span>
            </div>
            <div id="logDetails" class="modal-body">
                <!-- Log details will be loaded here -->
            </div>
        </div>
    </div>

    <script>
        function showClearModal() {
            document.getElementById('clearModal').style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('clearModal').style.display = 'none';
        }
        
        function showLogDetails(logId) {
            // This would typically load log details via AJAX
            document.getElementById('logDetails').innerHTML = `
                <div style="padding: 1.5rem;">
                    <p>Detailed information for log ID: ${logId}</p>
                    <p>This would show:</p>
                    <ul>
                        <li>Full user agent string</li>
                        <li>Device fingerprint</li>
                        <li>Complete reason/error message</li>
                        <li>Geolocation data (if available)</li>
                        <li>Related license information</li>
                    </ul>
                </div>
            `;
            document.getElementById('detailsModal').style.display = 'block';
        }
        
        function closeDetailsModal() {
            document.getElementById('detailsModal').style.display = 'none';
        }
        
        function showUserAgent(userAgent) {
            alert('User Agent:\n\n' + userAgent);
        }
        
        function showReason(reason) {
            alert('Reason:\n\n' + reason);
        }
        
        function exportLogs(format) {
            const currentUrl = new URL(window.location);
            currentUrl.searchParams.set('export', format);
            window.location.href = currentUrl.toString();
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
            const clearModal = document.getElementById('clearModal');
            const detailsModal = document.getElementById('detailsModal');
            
            if (event.target === clearModal) {
                closeModal();
            }
            if (event.target === detailsModal) {
                closeDetailsModal();
            }
        }
    </script>

    <style>
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: rgba(99, 102, 241, 0.1);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
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
        
        .stat-icon.info {
            background: rgba(59, 130, 246, 0.1);
            color: var(--info-color);
        }
        
        .stat-icon.secondary {
            background: rgba(107, 114, 128, 0.1);
            color: var(--text-secondary);
        }
        
        .stat-content h3 {
            font-size: 1.5rem;
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
        
        .export-buttons {
            display: flex;
            gap: 0.5rem;
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
        
        .user-agent, .reason {
            display: flex;
            align-items: center;
            gap: 0.5rem;
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
            
            .export-buttons {
                flex-direction: column;
                margin-top: 1rem;
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