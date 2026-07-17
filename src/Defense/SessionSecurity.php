<?php
defined('ABSPATH') || exit;
class SessionSecurity {
    public static function enforce() {
        if (session_status() !== PHP_SESSION_ACTIVE) return;
        $params = session_get_cookie_params();
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $modified = false;
        if (!$params['httponly']) { $params['httponly'] = true; $modified = true; }
        if ($secure && !$params['secure']) { $params['secure'] = true; $modified = true; }
        if (empty($params['samesite']) || $params['samesite'] === '') { $params['samesite'] = 'Lax'; $modified = true; }
        if ($modified) session_set_cookie_params($params);
    }
}