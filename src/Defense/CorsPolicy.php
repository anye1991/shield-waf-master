<?php
defined('ABSPATH') || exit;

class CorsPolicy {
    private static $allowed_origins = [];

    public static function init() {
        // 优先从配置读取可信域名
        if (defined('WAF_CORS_ALLOWED_ORIGINS') && WAF_CORS_ALLOWED_ORIGINS) {
            $configured = explode(',', WAF_CORS_ALLOWED_ORIGINS);
            foreach ($configured as $origin) {
                $origin = trim($origin);
                if ($origin) self::$allowed_origins[] = $origin;
            }
        }
        // 用 SERVER_NAME（服务端配置，不可被客户端伪造）兜底，而非 HTTP_HOST
        $host = $_SERVER['SERVER_NAME'] ?? '';
        if (!$host) {
            // 仅在 SERVER_NAME 不可用时退回 HTTP_HOST（此时需用户确认部署在可信反代后）
            $host = $_SERVER['HTTP_HOST'] ?? '';
        }
        if ($host) {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
            $origin = $scheme . $host;
            if (!in_array($origin, self::$allowed_origins)) {
                self::$allowed_origins[] = $origin;
            }
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
            // 校验 Origin 格式，防止 malformed origin 写入响应头
            if (!preg_match('#^https?://[a-zA-Z0-9.\-]+(?::\d+)?$#', $origin)) {
                waf_block('CORS policy violation: malformed origin');
            }
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