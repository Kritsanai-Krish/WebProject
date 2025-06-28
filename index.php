<?php
require_once 'config.php';

// ถ้า login แล้ว ให้ไป profile
if (isset($_SESSION['license_key']) && isset($_SESSION['license_data'])) {
    header('Location: profile.php');
    exit();
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $license_key = sanitizeInput($_POST['license_key'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';
    $screen_resolution = $_POST['screen_resolution'] ?? '';
    $timezone = $_POST['timezone'] ?? '';
    $platform = $_POST['platform'] ?? '';
    $browser = $_POST['browser'] ?? '';
    $cookies_enabled = $_POST['cookies_enabled'] ?? '';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $accept_language = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    $client_ip = getClientIP();

    // CSRF
    if (!validateCSRFToken($csrf_token)) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare('SELECT * FROM license_keys WHERE license_key = ?');
        $stmt->execute([$license_key]);
        $license = $stmt->fetch();

        if (!$license) {
            $error = 'License key not found.';
            logActivity('Login failed', 'License not found', null);
        } elseif ($license['status'] !== 'active') {
            $error = 'License is not active.';
            logActivity('Login failed', 'License not active', $license['id']);
        } elseif ($license['expires_at'] && strtotime($license['expires_at']) < time()) {
            $error = 'License expired.';
            logActivity('Login failed', 'License expired', $license['id']);
        } elseif ($license['usage_count'] >= $license['max_usage']) {
            $error = 'License usage limit reached.';
            logActivity('Login failed', 'Usage limit reached', $license['id']);
        } else {
            // ตรวจสอบ device lock
            $device_match = true;
            if ($license['locked_fingerprint']) {
                $fingerprint = hash('sha256', json_encode([
                    'ip' => $license['locked_ip'],
                    'user_agent' => $license['locked_user_agent'],
                    'screen_resolution' => $license['locked_screen_resolution'],
                    'timezone' => $license['locked_timezone'],
                    'language' => $license['locked_language'],
                    'platform' => $license['locked_platform'],
                    'browser' => $license['locked_browser'],
                    'cookies_enabled' => $license['locked_cookies'],
                ]));
                $current_fingerprint = hash('sha256', json_encode([
                    'ip' => $client_ip,
                    'user_agent' => $user_agent,
                    'screen_resolution' => $screen_resolution,
                    'timezone' => $timezone,
                    'language' => $accept_language,
                    'platform' => $platform,
                    'browser' => $browser,
                    'cookies_enabled' => $cookies_enabled,
                ]));
                if ($fingerprint !== $current_fingerprint) {
                    $device_match = false;
                }
            }
            if (!$device_match) {
                $error = 'This license is locked to another device.';
                logActivity('Login failed', 'Device mismatch', $license['id']);
            } else {
                // ถ้ายังไม่ lock ให้ lock device นี้
                if (!$license['locked_fingerprint']) {
                    $stmt = $pdo->prepare('UPDATE license_keys SET locked_fingerprint = ?, locked_ip = ?, locked_user_agent = ?, locked_screen_resolution = ?, locked_timezone = ?, locked_language = ?, locked_platform = ?, locked_browser = ?, locked_cookies = ?, usage_count = usage_count + 1, last_used_at = NOW() WHERE id = ?');
                    $stmt->execute([
                        hash('sha256', json_encode([
                            'ip' => $client_ip,
                            'user_agent' => $user_agent,
                            'screen_resolution' => $screen_resolution,
                            'timezone' => $timezone,
                            'language' => $accept_language,
                            'platform' => $platform,
                            'browser' => $browser,
                            'cookies_enabled' => $cookies_enabled,
                        ])),
                        $client_ip,
                        $user_agent,
                        $screen_resolution,
                        $timezone,
                        $accept_language,
                        $platform,
                        $browser,
                        $cookies_enabled,
                        $license['id']
                    ]);
                } else {
                    // update last_used_at
                    $stmt = $pdo->prepare('UPDATE license_keys SET last_used_at = NOW() WHERE id = ?');
                    $stmt->execute([$license['id']]);
                }
                // login success
                $_SESSION['license_key'] = $license_key;
                $_SESSION['license_data'] = $license;
                logActivity('Login success', 'User logged in', $license['id']);
                header('Location: profile.php');
                exit();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login with License Key</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background: #191a1a; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: #23272f; border-radius: 1rem; box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37); padding: 2.5rem 2rem; width: 100%; max-width: 400px; }
        .login-header { text-align: center; margin-bottom: 2rem; }
        .login-header h1 { font-size: 2rem; font-weight: 700; background: linear-gradient(135deg, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #cbd5e1; font-weight: 500; }
        .form-group input { width: 100%; padding: 0.75rem 1rem; border: 1px solid #334155; border-radius: 0.5rem; background: rgba(255,255,255,0.05); color: #fff; font-size: 1rem; }
        .form-group input:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.1); }
        .login-btn { width: 100%; padding: 0.875rem 1.5rem; background: linear-gradient(135deg, #6366f1, #8b5cf6); border: none; border-radius: 0.5rem; color: white; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.3s ease; margin-top: 1rem; }
        .login-btn:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(99,102,241,0.2); }
        .alert { padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #fca5a5; display: flex; align-items: center; gap: 0.5rem; }
        .login-footer { text-align: center; margin-top: 2rem; color: #64748b; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1><i class="fas fa-key"></i> License Login</h1>
            <p>Enter your license key to access your profile</p>
        </div>
        <?php if ($error): ?>
            <div class="alert"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form method="POST" autocomplete="off" id="licenseForm">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="hidden" name="screen_resolution" id="screen_resolution">
            <input type="hidden" name="timezone" id="timezone">
            <input type="hidden" name="platform" id="platform">
            <input type="hidden" name="browser" id="browser">
            <input type="hidden" name="cookies_enabled" id="cookies_enabled">
            <div class="form-group">
                <label for="license_key"><i class="fas fa-key"></i> License Key</label>
                <input type="text" id="license_key" name="license_key" required maxlength="100" autofocus placeholder="Enter your license key">
            </div>
            <button type="submit" class="login-btn"><i class="fas fa-sign-in-alt"></i> Login</button>
        </form>
        <div class="login-footer">
            <p>Powered by Secure License System</p>
        </div>
    </div>
    <script>
        // Collect device info
        function collectDeviceInfo() {
            document.getElementById('screen_resolution').value = screen.width + 'x' + screen.height;
            document.getElementById('timezone').value = Intl.DateTimeFormat().resolvedOptions().timeZone;
            document.getElementById('platform').value = navigator.platform;
            let browser = 'Unknown';
            if (navigator.userAgent.includes('Chrome')) browser = 'Chrome';
            else if (navigator.userAgent.includes('Firefox')) browser = 'Firefox';
            else if (navigator.userAgent.includes('Safari')) browser = 'Safari';
            else if (navigator.userAgent.includes('Edge')) browser = 'Edge';
            document.getElementById('browser').value = browser;
            document.getElementById('cookies_enabled').value = navigator.cookieEnabled ? '1' : '0';
        }
        collectDeviceInfo();
        document.getElementById('licenseForm').addEventListener('submit', collectDeviceInfo);
    </script>
</body>
</html>
