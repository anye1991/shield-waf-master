<?php
defined('ABSPATH') || exit;
class ApiRateLimit {
    private static $paths = [
        '/wp-login.php' => ['limit' => 5, 'window' => 300],
        '/wp-json/'     => ['limit' => 30, 'window' => 60],
    ];
    public static function check() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        foreach (self::$paths as $path => $cfg) {
            if (strpos($uri, $path) === 0) {
                self::checkLimit($path, $cfg['limit'], $cfg['window']);
                break;
            }
        }
    }
    private static function checkLimit($key, $limit, $window) {
        $ip = waf_get_real_ip();
        $file = WAF_LOG_PATH . 'api_rate_' . md5($key) . '.txt';
        $now = time();
        $lines = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
        $new = [];
        $count = 0;
        foreach ($lines as $line) {
            $parts = explode('|', $line);
            $ts = (int)$parts[0];
            $lip = $parts[1] ?? '';
            if ($ts > $now - $window) {
                if ($lip === $ip) $count++;
                $new[] = $line;
            }
        }
        if ($count >= $limit) {
            waf_smart_ban($ip);
            waf_block("API rate limit exceeded for $key");
}
        $new[] = "$now|$ip";
        @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    }
}