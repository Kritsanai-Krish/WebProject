<?php
require_once '../config.php';

// Log the logout activity
if (isset($_SESSION['admin_id'])) {
    logActivity('Admin logout', 'Admin logged out successfully', $_SESSION['admin_id']);
}

// Destroy session
session_destroy();

// Redirect to login page
header('Location: login.php?msg=logout');
exit();
?> 