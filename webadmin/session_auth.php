<?php
/**
 * Shared WebAdmin session authentication helpers.
 */

if (!defined('PYIRCX_WEBADMIN_ABSOLUTE_TIMEOUT')) {
    define('PYIRCX_WEBADMIN_ABSOLUTE_TIMEOUT', 8 * 60 * 60);
}

if (!defined('PYIRCX_WEBADMIN_IDLE_TIMEOUT')) {
    define('PYIRCX_WEBADMIN_IDLE_TIMEOUT', 30 * 60);
}

function pyircx_webadmin_clear_session() {
    $_SESSION = [];

    if (session_status() === PHP_SESSION_ACTIVE) {
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'] ?? '/',
                $params['domain'] ?? '',
                !empty($params['secure']),
                !empty($params['httponly'])
            );
        }
        session_destroy();
    }
}

function pyircx_webadmin_session_status() {
    if (!isset($_SESSION['admin_user']) || !isset($_SESSION['admin_level']) || $_SESSION['admin_level'] !== 'ADMIN') {
        return ['authenticated' => false, 'reason' => 'missing'];
    }

    $now = time();
    $login_time = isset($_SESSION['login_time']) ? intval($_SESSION['login_time']) : 0;
    $last_activity = isset($_SESSION['last_activity']) ? intval($_SESSION['last_activity']) : $login_time;

    if ($login_time <= 0) {
        pyircx_webadmin_clear_session();
        return ['authenticated' => false, 'reason' => 'expired'];
    }

    if (($now - $login_time) > PYIRCX_WEBADMIN_ABSOLUTE_TIMEOUT) {
        pyircx_webadmin_clear_session();
        return ['authenticated' => false, 'reason' => 'expired'];
    }

    if ($last_activity <= 0 || ($now - $last_activity) > PYIRCX_WEBADMIN_IDLE_TIMEOUT) {
        pyircx_webadmin_clear_session();
        return ['authenticated' => false, 'reason' => 'expired'];
    }

    $_SESSION['last_activity'] = $now;
    return ['authenticated' => true, 'reason' => 'active'];
}

function pyircx_require_admin_session($api_mode = false) {
    $status = pyircx_webadmin_session_status();
    if ($status['authenticated']) {
        return $status;
    }

    if ($api_mode) {
        http_response_code(401);
        echo json_encode([
            'error' => $status['reason'] === 'expired' ? 'Session expired' : 'Unauthorized',
            'redirect' => 'login.php'
        ]);
        exit(1);
    }

    $target = 'login.php';
    if ($status['reason'] === 'expired') {
        $target .= '?expired=1';
    }
    header('Location: ' . $target);
    exit();
}
