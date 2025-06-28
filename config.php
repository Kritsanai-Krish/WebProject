<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'license');
define('DB_USER', 'root');
define('DB_PASS', '');

// Security Configuration
define('SECRET_KEY', 'your-secret-key-change-this-in-production');
define('SESSION_NAME', 'license_session');
define('CSRF_TOKEN_NAME', 'csrf_token');

// System Configuration
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_DURATION', 900); // 15 minutes
define('SESSION_TIMEOUT', 3600); // 1 hour
define('REQUIRE_FINGERPRINT', true);
define('MAX_CONCURRENT_SESSIONS', 1);

// License Key Configuration
define('LICENSE_KEY_LENGTH', 32);
define('LICENSE_KEY_PREFIX', 'LIC');

// File paths
define('ROOT_PATH', __DIR__);
define('ADMIN_PATH', ROOT_PATH . '/admin');
define('INCLUDES_PATH', ROOT_PATH . '/includes');

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start session with secure settings
function initSecureSession() {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
        ini_set('session.use_strict_mode', 1);
        ini_set('session.cookie_samesite', 'Strict');
        session_name(SESSION_NAME);
        session_start();
    }
}

// Database connection
function getDBConnection() {
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        die("Database connection failed: " . $e->getMessage());
    }
}

// Security functions
function generateCSRFToken() {
    if (!isset($_SESSION[CSRF_TOKEN_NAME])) {
        $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
    }
    return $_SESSION[CSRF_TOKEN_NAME];
}

function validateCSRFToken($token) {
    return isset($_SESSION[CSRF_TOKEN_NAME]) && hash_equals($_SESSION[CSRF_TOKEN_NAME], $token);
}

function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function getClientIP() {
    $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function generateDeviceFingerprint() {
    $fingerprint = [
        'ip' => getClientIP(),
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'screen_resolution' => $_POST['screen_resolution'] ?? '',
        'timezone' => $_POST['timezone'] ?? '',
        'language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        'platform' => $_POST['platform'] ?? '',
        'browser' => $_POST['browser'] ?? '',
        'cookies_enabled' => $_POST['cookies_enabled'] ?? '',
        'canvas_fingerprint' => $_POST['canvas_fingerprint'] ?? '',
        'webgl_fingerprint' => $_POST['webgl_fingerprint'] ?? '',
    ];
    
    return hash('sha256', json_encode($fingerprint));
}

function logActivity($action, $details = '', $licenseKeyId = null) {
    try {
        $pdo = getDBConnection();
        
        // ถ้าไม่มี license_key_id ให้ใช้ NULL
        if ($licenseKeyId === null) {
            $stmt = $pdo->prepare("INSERT INTO license_usage_log (license_key_id, ip_address, user_agent, fingerprint, status, reason) VALUES (NULL, ?, ?, ?, ?, ?)");
            $stmt->execute([
                getClientIP(),
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                generateDeviceFingerprint(),
                'success',
                $action . ': ' . $details
            ]);
        } else {
            $stmt = $pdo->prepare("INSERT INTO license_usage_log (license_key_id, ip_address, user_agent, fingerprint, status, reason) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $licenseKeyId,
                getClientIP(),
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                generateDeviceFingerprint(),
                'success',
                $action . ': ' . $details
            ]);
        }
    } catch (Exception $e) {
        // ถ้าเกิด error ให้ log ไปที่ error log แทน
        error_log("Failed to log activity: " . $e->getMessage());
    }
}

// Initialize secure session
initSecureSession();
?> 