<?php
defined('ABSPATH') || exit;

class CorsPolicy {
    private static $allowed_origins = [];

    public static function init() {
        // 自动从当前请求中获取本站域名（无需 WordPress 函数）
        $host = $_SERVER['HTTP_HOST'] ?? '';
        if ($host) {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
            self::$allowed_origins[] = $scheme . $host;
        }
    }

    public static function check() {
        if (empty($_SERVER['HTTP_ORIGIN'])) return;

        $origin = $_SERVER['HTTP_ORIGIN'];
        $allowed = false;
        foreach (self::$allowed_origins as $ao) {
            if (strcasecmp($origin, $ao) === 0) {
                $allowed = true;
                break;
            }
        }

        if ($allowed) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Access-Control-Allow-Credentials: true');
            header('Vary: Origin');
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
                header('Access-Control-Allow-Headers: Content-Type, Authorization');
                http_response_code(204);
                exit;
            }
        } else {
            waf_block('CORS policy violation: ' . $origin);
        }
    }
}