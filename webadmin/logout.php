<?php
/**
 * pyIRCX Web Admin Logout
 * Destroys the admin session
 *
 * Copyright (C) 2026 pyIRCX Project
 * Licensed under GNU GPL v3
 */

// Prevent caching
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

session_start();

// Destroy all session data
$_SESSION = array();

// Destroy the session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Destroy the session
session_destroy();

// Redirect to login page with logout message
header('Location: login.php?logout=1');
exit();
?>
