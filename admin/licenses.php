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
                    case 'ban':
                        $stmt = $pdo->prepare("UPDATE license_keys SET status = 'banned' WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'License key banned successfully.';
                        logActivity('Banned license key', "License ID: {$license_id}", null);
                        break;
                        
                    case 'activate':
                        $stmt = $pdo->prepare("UPDATE license_keys SET status = 'active' WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'License key activated successfully.';
                        logActivity('Activated license key', "License ID: {$license_id}", null);
                        break;
                        
                    case 'pause':
                        $stmt = $pdo->prepare("UPDATE license_keys SET status = 'paused' WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'License key paused successfully.';
                        logActivity('Paused license key', "License ID: {$license_id}", null);
                        break;
                        
                    case 'reset_device':
                        $stmt = $pdo->prepare("UPDATE license_keys SET locked_fingerprint = NULL, locked_ip = NULL, locked_user_agent = NULL, locked_cookies = NULL, locked_screen_resolution = NULL, locked_timezone = NULL, locked_language = NULL, locked_platform = NULL, locked_browser = NULL WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'Device lock reset successfully.';
                        logActivity('Reset device lock', "License ID: {$license_id}", null);
                        break;
                        
                    case 'extend':
                        $days = (int)($_POST['extend_days'] ?? 30);
                        $stmt = $pdo->prepare("UPDATE license_keys SET expires_at = DATE_ADD(COALESCE(expires_at, NOW()), INTERVAL ? DAY) WHERE id = ?");
                        $stmt->execute([$days, $license_id]);
                        $message = "License extended by {$days} days successfully.";
                        logActivity('Extended license', "License ID: {$license_id}, Days: {$days}", null);
                        break;
                        
                    case 'delete':
                        $stmt = $pdo->prepare("DELETE FROM license_keys WHERE id = ?");
                        $stmt->execute([$license_id]);
                        $message = 'License key deleted successfully.';
                        logActivity('Deleted license key', "License ID: {$license_id}", null);
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

// Build query
$where_conditions = [];
$params = [];

if ($status_filter) {
    $where_conditions[] = "l.status = ?";
    $params[] = $status_filter;
}

if ($search) {
    $where_conditions[] = "(l.license_key LIKE ? OR l.notes LIKE ?)";
    $params[] = "%{$search}%";
    $params[] = "%{$search}%";
}

$where_clause = $where_conditions ? 'WHERE ' . implode(' AND ', $where_conditions) : '';

// Get total count
$count_query = "SELECT COUNT(*) FROM license_keys l {$where_clause}";
$stmt = $pdo->prepare($count_query);
$stmt->execute($params);
$total_records = $stmt->fetchColumn();
$total_pages = ceil($total_records / $per_page);

// Get license keys
$query = "
    SELECT l.*, a.username as created_by_name,
           (SELECT COUNT(*) FROM license_usage_log WHERE license_key_id = l.id) as usage_logs
    FROM license_keys l 
    LEFT JOIN admins a ON l.created_by = a.id 
    {$where_clause}
    ORDER BY l.created_at DESC 
    LIMIT {$per_page} OFFSET {$offset}
";

$stmt = $pdo->prepare($query);
$stmt->execute($params);
$licenses = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Management - Admin Panel</title>
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
                <a href="licenses.php" class="nav-item active">
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
                <h1>License Management</h1>
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
                                <input type="text" id="search" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search license key or notes...">
                            </div>
                            <div class="form-group">
                                <label>&nbsp;</label>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search"></i> Search
                                </button>
                                <a href="licenses.php" class="btn btn-secondary">
                                    <i class="fas fa-times"></i> Clear
                                </a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <!-- License Keys Table -->
            <div class="content-card">
                <div class="card-header">
                    <h3><i class="fas fa-key"></i> License Keys (<?php echo $total_records; ?> total)</h3>
                    <a href="generate.php" class="btn btn-primary">
                        <i class="fas fa-plus"></i> Generate New
                    </a>
                </div>
                <div class="card-content">
                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Status</th>
                                    <th>Expires</th>
                                    <th>Usage</th>
                                    <th>Device Lock</th>
                                    <th>Created</th>
                                    <th>Created By</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($licenses)): ?>
                                <tr>
                                    <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                        No license keys found.
                                    </td>
                                </tr>
                                <?php else: ?>
                                    <?php foreach ($licenses as $license): ?>
                                    <tr>
                                        <td>
                                            <code class="license-key" onclick="copyToClipboard('<?php echo $license['license_key']; ?>')" title="Click to copy">
                                                <?php echo htmlspecialchars($license['license_key']); ?>
                                            </code>
                                        </td>
                                        <td>
                                            <span class="status-badge status-<?php echo $license['status']; ?>">
                                                <?php echo ucfirst($license['status']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php 
                                            if ($license['expires_at']) {
                                                $expires = strtotime($license['expires_at']);
                                                $now = time();
                                                $days_left = ceil(($expires - $now) / 86400);
                                                
                                                if ($days_left < 0) {
                                                    echo '<span style="color: #ef4444;">Expired</span>';
                                                } elseif ($days_left <= 7) {
                                                    echo '<span style="color: #f59e0b;">' . date('Y-m-d H:i', $expires) . ' (' . $days_left . ' days left)</span>';
                                                } else {
                                                    echo date('Y-m-d H:i', $expires);
                                                }
                                            } else {
                                                echo '<span style="color: #10b981;">Never</span>';
                                            }
                                            ?>
                                        </td>
                                        <td>
                                            <?php echo $license['usage_count']; ?> / <?php echo $license['max_usage']; ?>
                                            <?php if ($license['usage_logs'] > 0): ?>
                                                <br><small style="color: var(--text-muted);"><?php echo $license['usage_logs']; ?> log entries</small>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($license['locked_fingerprint']): ?>
                                                <span class="status-badge status-active">Locked</span>
                                            <?php else: ?>
                                                <span class="status-badge status-expired">Unlocked</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php echo date('Y-m-d H:i', strtotime($license['created_at'])); ?>
                                        </td>
                                        <td>
                                            <?php echo htmlspecialchars($license['created_by_name'] ?? 'System'); ?>
                                        </td>
                                        <td>
                                            <div class="action-buttons">
                                                <?php if ($license['status'] === 'active'): ?>
                                                    <button onclick="performAction('pause', <?php echo $license['id']; ?>)" class="btn btn-warning btn-sm" title="Pause">
                                                        <i class="fas fa-pause"></i>
                                                    </button>
                                                    <button onclick="performAction('ban', <?php echo $license['id']; ?>)" class="btn btn-danger btn-sm" title="Ban">
                                                        <i class="fas fa-ban"></i>
                                                    </button>
                                                <?php elseif ($license['status'] === 'paused'): ?>
                                                    <button onclick="performAction('activate', <?php echo $license['id']; ?>)" class="btn btn-success btn-sm" title="Activate">
                                                        <i class="fas fa-play"></i>
                                                    </button>
                                                    <button onclick="performAction('ban', <?php echo $license['id']; ?>)" class="btn btn-danger btn-sm" title="Ban">
                                                        <i class="fas fa-ban"></i>
                                                    </button>
                                                <?php elseif ($license['status'] === 'banned'): ?>
                                                    <button onclick="performAction('activate', <?php echo $license['id']; ?>)" class="btn btn-success btn-sm" title="Activate">
                                                        <i class="fas fa-play"></i>
                                                    </button>
                                                <?php endif; ?>
                                                
                                                <?php if ($license['locked_fingerprint']): ?>
                                                    <button onclick="performAction('reset_device', <?php echo $license['id']; ?>)" class="btn btn-info btn-sm" title="Reset Device Lock">
                                                        <i class="fas fa-unlock"></i>
                                                    </button>
                                                <?php endif; ?>
                                                
                                                <button onclick="showExtendModal(<?php echo $license['id']; ?>)" class="btn btn-secondary btn-sm" title="Extend">
                                                    <i class="fas fa-clock"></i>
                                                </button>
                                                
                                                <button onclick="performAction('delete', <?php echo $license['id']; ?>)" class="btn btn-danger btn-sm" title="Delete">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
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
                <h3>Extend License</h3>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <form method="POST" id="extendForm">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                <input type="hidden" name="action" value="extend">
                <input type="hidden" name="license_id" id="extendLicenseId">
                
                <div class="form-group">
                    <label for="extend_days">Extend by (days)</label>
                    <input type="number" id="extend_days" name="extend_days" min="1" max="3650" value="30" required>
                </div>
                
                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Extend License</button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function performAction(action, licenseId) {
            if (action === 'delete' && !confirm('Are you sure you want to delete this license key?')) {
                return;
            }
            
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
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('extendModal');
            if (event.target === modal) {
                closeModal();
            }
        }
    </script>

    <style>
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
        
        .modal-content form {
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
