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
        // PHP 7.4+: session_set_cookie_params 在 session 激活时会触发 E_WARNING
        // 用 @ 抑制；同步通过 ini_set 让下个 session_start 生效
        if ($modified) {
            @ini_set('session.cookie_httponly', $params['httponly'] ? '1' : '0');
            if ($params['secure'])  @ini_set('session.cookie_secure', '1');
            if ($params['samesite']) @ini_set('session.cookie_samesite', $params['samesite']);
            @session_set_cookie_params($params);
        }
    }
}