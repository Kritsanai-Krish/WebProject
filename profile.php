<?php
require_once 'config.php';

if (!isset($_SESSION['license_key']) || !isset($_SESSION['license_data'])) {
    header('Location: index.php');
    exit();
}

$pdo = getDBConnection();
$stmt = $pdo->prepare('SELECT * FROM license_keys WHERE license_key = ?');
$stmt->execute([$_SESSION['license_key']]);
$license = $stmt->fetch();

if (!$license) {
    session_destroy();
    header('Location: index.php?msg=invalid');
    exit();
}
$_SESSION['license_data'] = $license;
?>
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Profile</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background:#191a1a;color:#fff;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem; }
        .profile-container { background:#23272f;border-radius:1rem;box-shadow:0 8px 32px 0 rgba(31,38,135,0.37);padding:2rem;width:100%;max-width:500px; }
        h1 { text-align:center;font-size:2rem;font-weight:700;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:1.5rem; }
        .info { margin-bottom:1rem; }
        .info strong { display:inline-block;width:120px;color:#cbd5e1; }
        .logout-btn { width:100%;padding:0.875rem 1.5rem;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:0.5rem;color:white;font-size:1rem;font-weight:600;cursor:pointer;transition:all 0.3s ease;margin-top:1rem; }
        .logout-btn:hover { transform:translateY(-2px);box-shadow:0 10px 15px -3px rgba(99,102,241,0.2); }
    </style>
</head>
<body>
    <div class="profile-container">
        <h1><i class="fas fa-id-badge"></i> License Profile</h1>
        <div class="info"><strong>License Key:</strong> <code id="licenseKey"><?php echo htmlspecialchars($license['license_key']); ?></code></div>
        <div class="info"><strong>Status:</strong> <?php echo htmlspecialchars(ucfirst($license['status'])); ?></div>
        <div class="info"><strong>Expires:</strong> <?php echo $license['expires_at'] ? date('Y-m-d H:i', strtotime($license['expires_at'])) : 'Never'; ?></div>
        <div class="info"><strong>Last Used:</strong> <?php echo $license['last_used_at'] ? date('Y-m-d H:i', strtotime($license['last_used_at'])) : 'Never'; ?></div>
        <div class="info"><strong>Usage:</strong> <?php echo $license['usage_count']; ?> / <?php echo $license['max_usage']; ?></div>
        <button class="logout-btn" onclick="window.location.href='logout.php'">
            <i class="fas fa-sign-out-alt"></i> Logout
        </button>
    </div>
    <script>
        document.getElementById('licenseKey').addEventListener('click', function(){
            navigator.clipboard.writeText(this.textContent).then(()=>{
                alert('License key copied to clipboard');
            });
        });
    </script>
</body>
</html>
 