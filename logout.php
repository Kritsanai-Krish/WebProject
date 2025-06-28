<?php
require_once 'config.php';

// Log the logout activity
if (isset($_SESSION['license_key'])) {
    logActivity('User logout', 'User logged out successfully', $_SESSION['license_data']['id'] ?? null);
}

// Destroy session
session_destroy();

// Redirect to main page
header('Location: index.php?msg=logout');
exit();
?> 