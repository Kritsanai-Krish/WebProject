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
        $quantity = (int)($_POST['quantity'] ?? 1);
        $duration = $_POST['duration'] ?? '';
        $max_usage = (int)($_POST['max_usage'] ?? 1);
        $notes = sanitizeInput($_POST['notes'] ?? '');
        
        // Validate inputs
        if ($quantity < 1 || $quantity > 100) {
            $error = 'Quantity must be between 1 and 100.';
        } elseif ($max_usage < 1 || $max_usage > 1000) {
            $error = 'Max usage must be between 1 and 1000.';
        } else {
            try {
                $pdo->beginTransaction();
                
                $generated_keys = [];
                
                for ($i = 0; $i < $quantity; $i++) {
                    // Generate unique license key
                    do {
                        $license_key = LICENSE_KEY_PREFIX . '-' . strtoupper(bin2hex(random_bytes(16)));
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM license_keys WHERE license_key = ?");
                        $stmt->execute([$license_key]);
                    } while ($stmt->fetchColumn() > 0);
                    
                    // Calculate expiration date
                    $expires_at = null;
                    if ($duration !== 'never') {
                        $expires_at = date('Y-m-d H:i:s', strtotime("+{$duration}"));
                    }
                    
                    // Insert license key
                    $stmt = $pdo->prepare("
                        INSERT INTO license_keys (license_key, expires_at, max_usage, notes, created_by) 
                        VALUES (?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([$license_key, $expires_at, $max_usage, $notes, $_SESSION['admin_id']]);
                    
                    $generated_keys[] = $license_key;
                }
                
                $pdo->commit();
                
                $message = "Successfully generated {$quantity} license key(s).";
                
                // Log activity
                logActivity('Generated license keys', "Generated {$quantity} keys with duration: {$duration}", null);
                
            } catch (Exception $e) {
                $pdo->rollBack();
                $error = 'Failed to generate license keys: ' . $e->getMessage();
            }
        }
    }
}

// Get recent generated keys
$recentKeys = $pdo->query("
    SELECT l.*, a.username as created_by_name 
    FROM license_keys l 
    LEFT JOIN admins a ON l.created_by = a.id 
    ORDER BY l.created_at DESC 
    LIMIT 10
")->fetchAll();
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generate License Keys - Admin Panel</title>
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
                <a href="generate.php" class="nav-item active">
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
                <h1>Generate License Keys</h1>
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

            <div class="content-grid">
                <!-- Generate Form -->
                <div class="content-card">
                    <div class="card-header">
                        <h3><i class="fas fa-plus-circle"></i> Generate New License Keys</h3>
                    </div>
                    <div class="card-content">
                        <form method="POST" class="generate-form">
                            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="quantity">
                                        <i class="fas fa-hashtag"></i>
                                        Quantity
                                    </label>
                                    <input type="number" id="quantity" name="quantity" min="1" max="100" value="1" required>
                                    <small>Number of keys to generate (1-100)</small>
                                </div>
                                
                                <div class="form-group">
                                    <label for="duration">
                                        <i class="fas fa-clock"></i>
                                        Duration
                                    </label>
                                    <select id="duration" name="duration" required>
                                        <option value="1 day">1 Day</option>
                                        <option value="7 days">7 Days</option>
                                        <option value="30 days">30 Days</option>
                                        <option value="90 days">90 Days</option>
                                        <option value="1 year">1 Year</option>
                                        <option value="never" selected>Never Expire</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label for="max_usage">
                                        <i class="fas fa-users"></i>
                                        Max Usage
                                    </label>
                                    <input type="number" id="max_usage" name="max_usage" min="1" max="1000" value="1" required>
                                    <small>Maximum number of devices (1-1000)</small>
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <label for="notes">
                                    <i class="fas fa-sticky-note"></i>
                                    Notes (Optional)
                                </label>
                                <textarea id="notes" name="notes" rows="3" placeholder="Add any notes about these license keys..."></textarea>
                            </div>
                            
                            <div class="form-actions">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-magic"></i>
                                    Generate License Keys
                                </button>
                                <button type="button" class="btn btn-secondary" onclick="resetForm()">
                                    <i class="fas fa-undo"></i>
                                    Reset
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Recent Generated Keys -->
                <div class="content-card">
                    <div class="card-header">
                        <h3><i class="fas fa-history"></i> Recently Generated Keys</h3>
                    </div>
                    <div class="card-content">
                        <div class="table-responsive">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>License Key</th>
                                        <th>Status</th>
                                        <th>Expires</th>
                                        <th>Max Usage</th>
                                        <th>Created</th>
                                        <th>Created By</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($recentKeys)): ?>
                                    <tr>
                                        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                            No license keys found.
                                        </td>
                                    </tr>
                                    <?php else: ?>
                                        <?php foreach ($recentKeys as $key): ?>
                                        <tr>
                                            <td>
                                                <code class="license-key" onclick="copyToClipboard('<?php echo $key['license_key']; ?>')" title="Click to copy">
                                                    <?php echo htmlspecialchars($key['license_key']); ?>
                                                </code>
                                            </td>
                                            <td>
                                                <span class="status-badge status-<?php echo $key['status']; ?>">
                                                    <?php echo ucfirst($key['status']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <?php echo $key['expires_at'] ? date('Y-m-d H:i', strtotime($key['expires_at'])) : 'Never'; ?>
                                            </td>
                                            <td>
                                                <?php echo $key['usage_count']; ?> / <?php echo $key['max_usage']; ?>
                                            </td>
                                            <td>
                                                <?php echo date('Y-m-d H:i', strtotime($key['created_at'])); ?>
                                            </td>
                                            <td>
                                                <?php echo htmlspecialchars($key['created_by_name'] ?? 'System'); ?>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function resetForm() {
            document.getElementById('quantity').value = '1';
            document.getElementById('duration').value = 'never';
            document.getElementById('max_usage').value = '1';
            document.getElementById('notes').value = '';
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                // Show success message
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
        
        // Add click animation to license keys
        document.querySelectorAll('.license-key').forEach(key => {
            key.style.cursor = 'pointer';
            key.addEventListener('click', function() {
                this.style.transform = 'scale(0.95)';
                setTimeout(() => {
                    this.style.transform = 'scale(1)';
                }, 150);
            });
        });
    </script>
    
    <style>
        .generate-form {
            max-width: 800px;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
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
        
        .form-actions {
            display: flex;
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .btn {
            padding: 0.875rem 1.5rem;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }
        
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.15);
            color: var(--text-primary);
        }
        
        .license-key {
            cursor: pointer;
            transition: all 0.3s ease;
            user-select: all;
        }
        
        .license-key:hover {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary-color);
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
            
            .form-actions {
                flex-direction: column;
            }
        }
    </style>
</body>
</html>
