<?php
require_once '../config.php';

// Redirect if already logged in
if (isset($_SESSION['admin_id'])) {
    header('Location: index.php');
    exit();
}

$error = '';
$success = '';

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // Validate CSRF token
    if (!validateCSRFToken($csrf_token)) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $pdo = getDBConnection();
        
        // Check for brute force protection
        $clientIP = getClientIP();
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        $stmt->execute([$clientIP]);
        $failedAttempts = $stmt->fetchColumn();
        
        if ($failedAttempts >= MAX_LOGIN_ATTEMPTS) {
            $error = 'Too many failed login attempts. Please try again later.';
        } else {
            // Check admin credentials
            $stmt = $pdo->prepare("SELECT * FROM admins WHERE username = ?");
            $stmt->execute([$username]);
            $admin = $stmt->fetch();
            
            if ($admin && password_verify($password, $admin['password_hash'])) {
                // Check if account is locked
                if ($admin['locked_until'] && strtotime($admin['locked_until']) > time()) {
                    $error = 'Account is temporarily locked. Please try again later.';
                } else {
                    // Successful login
                    $_SESSION['admin_id'] = $admin['id'];
                    $_SESSION['admin_username'] = $admin['username'];
                    $_SESSION['last_activity'] = time();
                    
                    // Update admin login info
                    $stmt = $pdo->prepare("UPDATE admins SET last_login = NOW(), last_login_ip = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?");
                    $stmt->execute([$clientIP, $admin['id']]);
                    
                    // Log successful login
                    $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address, attempt_time, success, user_agent) VALUES (?, NOW(), 1, ?)");
                    $stmt->execute([$clientIP, $_SERVER['HTTP_USER_AGENT'] ?? '']);
                    
                    header('Location: index.php');
                    exit();
                }
            } else {
                // Failed login
                $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address, attempt_time, success, user_agent) VALUES (?, NOW(), 0, ?)");
                $stmt->execute([$clientIP, $_SERVER['HTTP_USER_AGENT'] ?? '']);
                
                // Update failed attempts for admin if exists
                if ($admin) {
                    $newFailedAttempts = $admin['failed_attempts'] + 1;
                    $lockedUntil = null;
                    
                    if ($newFailedAttempts >= MAX_LOGIN_ATTEMPTS) {
                        $lockedUntil = date('Y-m-d H:i:s', time() + LOCKOUT_DURATION);
                    }
                    
                    $stmt = $pdo->prepare("UPDATE admins SET failed_attempts = ?, locked_until = ? WHERE id = ?");
                    $stmt->execute([$newFailedAttempts, $lockedUntil, $admin['id']]);
                }
                
                $error = 'Invalid username or password.';
            }
        }
    }
}

// Handle logout message
if (isset($_GET['msg'])) {
    switch ($_GET['msg']) {
        case 'logout':
            $success = 'You have been successfully logged out.';
            break;
        case 'timeout':
            $error = 'Session expired. Please login again.';
            break;
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - License Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="admin-style.css">
</head>
<body class="login-page">
    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h1>Admin Login</h1>
                <p>Enter your credentials to access the admin panel</p>
            </div>
            
            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                
                <div class="form-group">
                    <label for="username">
                        <i class="fas fa-user"></i>
                        Username
                    </label>
                    <input type="text" id="username" name="username" required 
                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                           autocomplete="username">
                </div>
                
                <div class="form-group">
                    <label for="password">
                        <i class="fas fa-lock"></i>
                        Password
                    </label>
                    <div class="password-input">
                        <input type="password" id="password" name="password" required 
                               autocomplete="current-password">
                        <button type="button" class="toggle-password" onclick="togglePassword()">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                
                <button type="submit" class="login-btn">
                    <i class="fas fa-sign-in-alt"></i>
                    Login
                </button>
            </form>
            
            <div class="login-footer">
                <p><i class="fas fa-shield-alt"></i> Secure Admin Access</p>
                <small>All login attempts are logged for security purposes</small>
            </div>
        </div>
    </div>

    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const toggleBtn = document.querySelector('.toggle-password i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleBtn.className = 'fas fa-eye-slash';
            } else {
                passwordInput.type = 'password';
                toggleBtn.className = 'fas fa-eye';
            }
        }
        
        // Auto-focus username field
        document.getElementById('username').focus();
        
        // Prevent form resubmission
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
</body>
</html> 