<?php
/**
 * pyIRCX Web Admin Login
 * Authentication for administration panel
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

                // Redirect to admin panel
                header('Location: index.php');
                exit();
            } else {
                $error = 'Access denied. Only administrators can access this panel.';
            }
        } else {
            $error = 'Invalid username or password';
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
