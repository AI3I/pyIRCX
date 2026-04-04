<?php
/**
 * pyIRCX Web Admin API Router
 * Routes API requests to the Python backend (api.py)
 */

// Secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 1 : 0);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

// Start session for authentication
session_start();
require_once __DIR__ . '/session_auth.php';

// Prevent direct access without proper headers
header('Content-Type: application/json');

// Enable CORS if needed (remove in production if not needed)
// header('Access-Control-Allow-Origin: *');

// Authentication check - require valid admin session
pyircx_require_admin_session(true);

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
                          'newsflash-settings', 'list-nicknames-paginated', 'list-channels-paginated',
                          'get-channel-access', 'search-nicknames', 'search-channels', 'service-status', 'get-motd', 'services', 'list-services'];

// Get command and arguments
$command = $_REQUEST['cmd'] ?? '';
$args = $_REQUEST['args'] ?? [];
$stdin_payload = $_POST['stdin_payload'] ?? null;

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
    $API_PATH = dirname(__DIR__) . '/api.py';
}

// Normalize service control requests to Python API arguments
if ($command === 'service-control') {
    $action = $_POST['action'] ?? '';
    if (!in_array($action, ['start', 'stop', 'restart', 'reload', 'status'])) {
        echo json_encode(['error' => 'Invalid service action']);
        exit(1);
    }
    $args = [$action];
}

// Build command to execute api.py
$stdin_commands = [
    'add-staff' => 'add-staff-stdin',
    'change-staff-password' => 'change-staff-password-stdin',
    'register-nick' => 'register-nick-stdin',
    'edit-nick' => 'edit-nick-stdin',
];

$api_command = $command;
if ($stdin_payload !== null && array_key_exists($command, $stdin_commands)) {
    $api_command = $stdin_commands[$command];
}

$cmd_parts = ['python3', $API_PATH, $api_command];

// Add arguments if provided
if (!empty($args)) {
    if (!is_array($args)) {
        $args = [$args];
    }
    foreach ($args as $arg) {
        $cmd_parts[] = (string)$arg;
    }
}

$result = '';
$stderr = '';

$descriptor_spec = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];
$process = proc_open($cmd_parts, $descriptor_spec, $pipes);
if (!is_resource($process)) {
    echo json_encode(['error' => 'Failed to launch API process']);
    exit(1);
}

if ($stdin_payload !== null && $api_command !== $command) {
    fwrite($pipes[0], $stdin_payload);
}
fclose($pipes[0]);

$stdout = stream_get_contents($pipes[1]);
fclose($pipes[1]);

$stderr = stream_get_contents($pipes[2]);
fclose($pipes[2]);

$return_code = proc_close($process);
$result = $stdout;

// Try to parse as JSON, if it fails return raw output
$json = json_decode($result, true);
if ($json === null && json_last_error() !== JSON_ERROR_NONE) {
    $raw_output = trim($result);
    if ($raw_output === '' && $stderr !== '') {
        $raw_output = trim($stderr);
    }
    if ($return_code !== 0 && $raw_output === '') {
        $raw_output = 'API process exited with code ' . $return_code;
    }
    echo json_encode(['error' => 'Invalid JSON response from API', 'raw_output' => $raw_output]);
} else {
    echo $result;
}
?>
