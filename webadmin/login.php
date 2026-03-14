<?php
/**
 * pyIRCX Web Admin Login
 * Authentication for administration panel
 */


// Prevent caching
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 1 : 0);  // Require HTTPS only if available
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);

session_start();

// If already logged in, redirect to admin panel
if (isset($_SESSION['admin_user']) && isset($_SESSION['admin_level'])) {
    header('Location: index.php');
    exit();
}

$RATE_FILE = sys_get_temp_dir() . '/pyircx_webadmin_rate.json';
$RATE_MAX_ATTEMPTS = 5;
$RATE_WINDOW = 60;   // seconds
$RATE_LOCKOUT = 300; // seconds

function rate_with_state($path, $callback) {
    $fp = fopen($path, 'c+');
    if (!$fp) {
        $state = [];
        return $callback($state);
    }
    flock($fp, LOCK_EX);
    $raw = stream_get_contents($fp);
    $state = json_decode($raw, true);
    if (!is_array($state)) {
        $state = [];
    }
    // Garbage collect stale entries to prevent unbounded growth.
    $now = time();
    $pruned = [];
    foreach ($state as $k => $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $attempts = $entry['attempts'] ?? [];
        if (!is_array($attempts)) {
            $attempts = [];
        }
        $attempts = array_values(array_filter($attempts, function ($ts) use ($now) {
            return is_numeric($ts) && $ts > ($now - 86400); // keep only recent 24h attempts
        }));
        $locked_until = isset($entry['locked_until']) && is_numeric($entry['locked_until'])
            ? intval($entry['locked_until'])
            : 0;
        if ($locked_until > $now || count($attempts) > 0) {
            $pruned[$k] = ['attempts' => $attempts, 'locked_until' => $locked_until];
        }
    }
    $state = $pruned;
    $result = $callback($state);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($state));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $result;
}

function rate_check($path, $keys, $max_attempts, $window, $lockout) {
    $now = time();
    return rate_with_state($path, function (&$state) use ($keys, $max_attempts, $window, $lockout, $now) {
        $blocked = false;
        $retry_after = 0;
        foreach ($keys as $key) {
            $entry = $state[$key] ?? ['attempts' => [], 'locked_until' => 0];
            $attempts = $entry['attempts'] ?? [];
            $attempts = array_values(array_filter($attempts, function ($ts) use ($now, $window) {
                return $ts > ($now - $window);
            }));
            $entry['attempts'] = $attempts;
            if (!empty($entry['locked_until']) && $entry['locked_until'] > $now) {
                $blocked = true;
                $retry_after = max($retry_after, $entry['locked_until'] - $now);
            } elseif (count($attempts) >= $max_attempts) {
                $entry['locked_until'] = $now + $lockout;
                $entry['attempts'] = [];
                $blocked = true;
                $retry_after = max($retry_after, $lockout);
            }
            $state[$key] = $entry;
        }
        return ['blocked' => $blocked, 'retry_after' => $retry_after];
    });
}

function rate_record_failure($path, $keys, $window) {
    $now = time();
    rate_with_state($path, function (&$state) use ($keys, $window, $now) {
        foreach ($keys as $key) {
            $entry = $state[$key] ?? ['attempts' => [], 'locked_until' => 0];
            $attempts = $entry['attempts'] ?? [];
            $attempts = array_values(array_filter($attempts, function ($ts) use ($now, $window) {
                return $ts > ($now - $window);
            }));
            $attempts[] = $now;
            $entry['attempts'] = $attempts;
            $state[$key] = $entry;
        }
        return null;
    });
}

function rate_clear($path, $keys) {
    rate_with_state($path, function (&$state) use ($keys) {
        foreach ($keys as $key) {
            unset($state[$key]);
        }
        return null;
    });
}

$error = '';
$success = '';

// Check if logged out
if (isset($_GET['logout']) && $_GET['logout'] == '1') {
    $success = 'You have been successfully logged out';
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (empty($username) || empty($password)) {
        $error = 'Please enter both username and password';
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_key = strtolower($username);
        $rate_keys = ["ip:$ip", "ipuser:$ip:$user_key"];
        $rate = rate_check($RATE_FILE, $rate_keys, $RATE_MAX_ATTEMPTS, $RATE_WINDOW, $RATE_LOCKOUT);
        if ($rate['blocked']) {
            $error = 'Too many login attempts. Please try again in ' . intval($rate['retry_after']) . ' seconds.';
        } else {
        // Path to api.py
        $API_PATH = '/opt/pyircx/api.py';
        if (!file_exists($API_PATH)) {
            $API_PATH = dirname(__FILE__) . '/api.py';
        }

        // Call test-staff-login via Python API using stdin for password (security)
        $descriptorspec = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout
            2 => ["pipe", "w"]   // stderr
        ];

        $cmd = sprintf(
            'python3 %s test-staff-login-stdin %s',
            escapeshellarg($API_PATH),
            escapeshellarg($username)
        );

        $process = proc_open($cmd, $descriptorspec, $pipes);

        if (is_resource($process)) {
            // Write password to stdin
            fwrite($pipes[0], $password);
            fclose($pipes[0]);

            // Read output
            $result = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);

            $return_code = proc_close($process);
        } else {
            $result = '{"error": "Failed to execute command"}';
        }

        $json = json_decode($result, true);

        if ($json && isset($json['success']) && $json['success'] === true) {
            // Check if user is ADMIN level
            if ($json['level'] === 'ADMIN') {
                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                // Set session variables
                $_SESSION['admin_user'] = $username;
                $_SESSION['admin_level'] = $json['level'];
                $_SESSION['login_time'] = time();

                // Generate CSRF token
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                // Clear rate limits on success
                rate_clear($RATE_FILE, $rate_keys);

                // Redirect to admin panel
                header('Location: index.php');
                exit();
            } else {
                rate_record_failure($RATE_FILE, $rate_keys, $RATE_WINDOW);
                $error = 'Access denied. Only administrators can access this panel.';
            }
        } else {
            rate_record_failure($RATE_FILE, $rate_keys, $RATE_WINDOW);
            $error = 'Invalid username or password';
        }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - pyIRCX Administration</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            color: #ecf0f1;
        }

        .login-container {
            background: rgba(44, 62, 80, 0.95);
            border-radius: 12px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .login-header h1 {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .login-header p {
            font-size: 16px;
            opacity: 0.8;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            font-size: 14px;
        }

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 6px;
            color: #ecf0f1;
            font-size: 15px;
            transition: all 0.2s;
        }

        .form-group input:focus {
            outline: none;
            background: rgba(255, 255, 255, 0.15);
            border-color: #3498db;
        }

        .form-group input::placeholder {
            color: rgba(236, 240, 241, 0.5);
        }

        .success-message {
            background: rgba(46, 204, 113, 0.2);
            border: 1px solid rgba(46, 204, 113, 0.5);
            color: #2ecc71;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .error-message {
            background: rgba(231, 76, 60, 0.2);
            border: 1px solid rgba(231, 76, 60, 0.5);
            color: #e74c3c;
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .btn-login {
            width: 100%;
            padding: 14px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-login:hover {
            background: #2980b9;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(52, 152, 219, 0.3);
        }

        .btn-login:active {
            transform: translateY(0);
        }

        .login-footer {
            margin-top: 25px;
            text-align: center;
            font-size: 13px;
            opacity: 0.7;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>💬 pyIRCX</h1>
            <p>Administration Panel</p>
        </div>

        <?php if ($success): ?>
            <div class="success-message">
                <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error-message">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    placeholder="Enter your username"
                    required
                    autofocus
                    autocomplete="username"
                    value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                >
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter your password"
                    required
                    autocomplete="current-password"
                >
            </div>

            <button type="submit" class="btn-login">Sign In</button>
        </form>

        <div class="login-footer">
            Only administrators can access this panel
        </div>
    </div>
</body>
</html>
