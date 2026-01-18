<?php
/**
 * pyIRCX Web Admin API Router
 * Routes API requests to the Python backend (api.py)
 *
 * Copyright (C) 2026 John D. Lewis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 1 : 0);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

// Start session for authentication
session_start();

// Prevent direct access without proper headers
header('Content-Type: application/json');

// Enable CORS if needed (remove in production if not needed)
// header('Access-Control-Allow-Origin: *');

// Authentication check - require valid admin session
if (!isset($_SESSION['admin_user']) || !isset($_SESSION['admin_level']) || $_SESSION['admin_level'] !== 'ADMIN') {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized', 'redirect' => 'login.php']);
    exit(1);
}

// CSRF protection for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        http_response_code(403);
        echo json_encode(['error' => 'CSRF token validation failed']);
        exit(1);
    }
}

// Security: Only allow POST requests for most operations
$method = $_SERVER['REQUEST_METHOD'];
$allowed_get_commands = ['stats', 'realtime-status', 'staff', 'channels', 'recent-registrations',
                          'config', 'full-config', 'full-config', 'logs', 'server-access-list', 'newsflash-list', 'mailbox-list',
                          'newsflash-settings', 'list-nicks-paginated', 'list-channels-paginated',
                          'get-channel-access', 'search-nicks', 'search-channels', 'service-status', 'get-motd', 'services', 'list-services'];

// Get command and arguments
$command = $_REQUEST['cmd'] ?? '';
$args = $_REQUEST['args'] ?? [];

// Validate command
if (empty($command)) {
    echo json_encode(['error' => 'No command specified']);
    exit(1);
}

// Security check for GET requests
if ($method === 'GET' && !in_array($command, $allowed_get_commands)) {
    echo json_encode(['error' => 'This command requires POST']);
    exit(1);
}

// Path to api.py
$API_PATH = '/opt/pyircx/api.py';
// Development fallback
if (!file_exists($API_PATH)) {
    $API_PATH = dirname(__FILE__) . '/api.py';
}

// Special handling for service control commands
if ($command === 'service-control') {
    $action = $_POST['action'] ?? '';
    if (!in_array($action, ['start', 'stop', 'restart', 'status'])) {
        echo json_encode(['error' => 'Invalid service action']);
        exit(1);
    }

    if ($action === 'status') {
        // Get service status
        exec('systemctl is-active pyircx.service 2>&1', $output, $return_code);
        $status = trim(implode('', $output));
        echo json_encode(['status' => $status]);
    } else {
        // Control service (uses polkit for authorization)
        $sudo_cmd = "systemctl $action pyircx.service 2>&1";
        exec($sudo_cmd, $output, $return_code);

        if ($return_code === 0) {
            echo json_encode(['success' => true, 'message' => "Service $action successful"]);
        } else {
            echo json_encode(['error' => 'Failed to control service: ' . implode("\n", $output)]);
        }
    }
    exit(0);
}

// Special handling for service status check
if ($command === 'service-status') {
    exec('systemctl is-active pyircx.service 2>&1', $output, $return_code);
    $status = trim(implode('', $output));
    echo json_encode(['status' => $status]);
    exit(0);
}

// Special handling for logs command - call journalctl directly from PHP
if ($command === 'logs') {
    $lines = isset($args[0]) ? intval($args[0]) : 100;
    $level = isset($args[1]) ? $args[1] : null;
    $search = isset($args[2]) ? $args[2] : null;

    $cmd = ['journalctl', '-u', 'pyircx.service', '-n', strval($lines), '--no-pager', '--output=short-iso'];

    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );

    $process = proc_open($cmd, $descriptorspec, $pipes);

    if (is_resource($process)) {
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $ret = proc_close($process);

        if ($ret === 0 && !empty($stdout)) {
            $log_lines = explode("\n", trim($stdout));

            // Apply filters
            if ($level) {
                $log_lines = array_filter($log_lines, function($line) use ($level) {
                    return strpos($line, "[$level]") !== false;
                });
            }

            if ($search) {
                $log_lines = array_filter($log_lines, function($line) use ($search) {
                    return stripos($line, $search) !== false;
                });
            }

            echo json_encode([
                'logs' => implode("\n", $log_lines),
                'line_count' => count($log_lines),
                'source' => 'journalctl'
            ]);
            exit(0);
        }
    }

    // Fallback to file if journalctl fails
}

// Build command to execute api.py
$cmd_parts = ['python3', escapeshellarg($API_PATH), escapeshellarg($command)];

// Add arguments if provided
if (!empty($args)) {
    if (!is_array($args)) {
        $args = [$args];
    }
    foreach ($args as $arg) {
        $cmd_parts[] = escapeshellarg($arg);
    }
}

$full_cmd = implode(' ', $cmd_parts) . ' 2>&1';

// Execute command
exec($full_cmd, $output, $return_code);
// Debug logging
$result = implode("\n", $output);

// Try to parse as JSON, if it fails return raw output
$json = json_decode($result, true);
if ($json === null && json_last_error() !== JSON_ERROR_NONE) {
    echo json_encode(['error' => 'Invalid JSON response from API', 'raw_output' => $result]);
} else {
    echo $result;
}
?>
