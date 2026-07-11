<?php
defined('ABSPATH') || exit;

class SecurityHeaders {
    public static function apply() {
        // 基础安全头
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

        // Content-Security-Policy（允许仪表盘所需的 CDN）
        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; " .
               "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.staticfile.org; " .
               "img-src 'self' data:; " .
               "font-src 'self' data: https://cdn.staticfile.org; " .
               "connect-src 'self' https://cdn.jsdelivr.net;";   // 新增：允许连接 CDN
        header("Content-Security-Policy: {$csp}");
    }
}