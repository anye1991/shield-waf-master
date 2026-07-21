<?php
defined('ABSPATH') || exit;

class HoneypotLinks {
    private static $trigger_dir = null;
    private static $initialized = false;

    private static $path_patterns = [
        '/admin-login',
        '/wp-admin-backup',
        '/phpmyadmin-old',
        '/config-backup',
        '/secret-panel',
        '/dev-tools',
        '/test-admin',
        '/hidden-login',
        '/backup-config',
        '/database-dump',
    ];

    private static $param_names = [
        'debug',
        'test',
        'admin',
        'dev',
        'preview',
        'mode',
    ];

    private static function init() {
        if (self::$initialized) return;
        $base = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (sys_get_temp_dir() . '/shield_waf_');
        self::$trigger_dir = $base . '/honeypot_triggers/';
        if (!is_dir(self::$trigger_dir)) @mkdir(self::$trigger_dir, 0700, true);
        self::$initialized = true;
    }

    public static function checkRequest(): bool {
        self::init();

        if (self::isSearchEngine()) {
            return false;
        }

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $ip  = self::getClientIp();

        foreach (self::$path_patterns as $pattern) {
            if (preg_match('#^' . preg_quote($pattern, '#') . '($|\?|/)#i', $uri)) {
                self::recordTrigger($ip, $uri, 'path_match');
                return true;
            }
        }

        foreach (self::$param_names as $param) {
            if (isset($_GET[$param]) && is_string($_GET[$param]) && !empty($_GET[$param])) {
                $val = (string)$_GET[$param];
                if (strlen($val) < 8) continue;
                $matches = preg_match_all('/(admin|root|secret|password|login|config|shell|cmd)/i', $val);
                if ($matches >= 2) {
                    self::recordTrigger($ip, $uri, 'param_match:' . $param);
                    return true;
                }
            }
        }

        return false;
    }

    public static function injectToHtml(string $html): string {
        if (stripos($html, '<!DOCTYPE') === false && stripos($html, '<html') === false) {
            return $html;
        }
        if (self::isAdminPage()) {
            return $html;
        }

        $links = self::generateLinks(3);
        $injection = implode("\n", $links);

        if (stripos($html, '</body>') !== false) {
            $html = str_ireplace('</body>', $injection . '</body>', $html);
        } else {
            $html .= $injection;
        }

        return $html;
    }

    private static function generateLinks(int $count = 3): array {
        $links = [];
        $styles = [
            'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;',
            'display:none;',
            'position:fixed;bottom:0;right:0;opacity:0.001;font-size:1px;color:#fff;width:1px;height:1px;',
            'position:absolute;clip:rect(0 0 0 0);width:1px;height:1px;overflow:hidden;',
        ];

        $path_keys = array_rand(self::$path_patterns, min($count, count(self::$path_patterns)));
        if (!is_array($path_keys)) $path_keys = [$path_keys];

        foreach ($path_keys as $idx) {
            $path = self::$path_patterns[$idx];
            $style = $styles[array_rand($styles)];
            $text = self::generateLinkText();
            $token = self::generateToken();

            $params = '';
            if (mt_rand(0, 1) === 1) {
                $param = self::$param_names[array_rand(self::$param_names)];
                $params = '?' . $param . '=' . $token;
            }

            $links[] = '<a href="' . htmlspecialchars($path . $params, ENT_QUOTES)
                     . '" style="' . $style . '" aria-hidden="true" tabindex="-1" '
                     . 'rel="nofollow noopener">' . htmlspecialchars($text, ENT_QUOTES) . '</a>';
        }

        return $links;
    }

    private static function generateLinkText(): string {
        $texts = [
            'admin', 'login', 'panel', 'dashboard', 'control',
            'secret', 'private', 'internal', 'dev', 'test',
        ];
        return $texts[array_rand($texts)];
    }

    private static function generateToken(): string {
        return substr(md5(uniqid(mt_rand(), true)), 0, 16);
    }

    private static function recordTrigger(string $ip, string $uri, string $reason) {
        self::init();
        $file = self::$trigger_dir . md5($ip) . '.json';
        $records = [];
        if (is_file($file)) {
            $raw = @file_get_contents($file);
            if ($raw) {
                $data = json_decode($raw, true);
                if (is_array($data)) {
                    $records = $data;
                }
            }
        }
        $records[] = [
            'ip' => $ip,
            'uri' => $uri,
            'reason' => $reason,
            'time' => time(),
        ];
        if (count($records) > 100) {
            $records = array_slice($records, -100);
        }
        @file_put_contents($file, json_encode($records), LOCK_EX);
    }

    public static function getTriggerCount(string $ip): int {
        self::init();
        $file = self::$trigger_dir . md5($ip) . '.json';
        if (!is_file($file)) return 0;
        $raw = @file_get_contents($file);
        if (!$raw) return 0;
        $records = json_decode($raw, true);
        if (!is_array($records)) return 0;
        $count = 0;
        $threshold = time() - 86400;
        foreach ($records as $r) {
            if (($r['time'] ?? 0) > $threshold) {
                $count++;
            }
        }
        return $count;
    }

    private static function isAdminPage(): bool {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return stripos($uri, 'wp-admin') !== false
            || stripos($uri, '/admin/') !== false
            || stripos($uri, '/login/') !== false;
    }

    private static function getClientIp(): string {
        if (function_exists('waf_get_real_ip')) return waf_get_real_ip();
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private static function isSearchEngine(): bool {
        static $search_engine_patterns = [
            '/Googlebot/i', '/Bingbot/i', '/Baiduspider/i', '/YandexBot/i',
            '/DuckDuckBot/i', '/Sogou web spider/i', '/360Spider/i',
            '/Bytespider/i', '/ShenmaBot/i', '/Applebot/i', '/facebookexternalhit/i',
            '/Twitterbot/i', '/LinkedInBot/i', '/Pinterest/i', '/AhrefsBot/i',
            '/SemrushBot/i', '/MJ12bot/i', '/DotBot/i', '/rogerbot/i',
            '/NaverBot/i', '/SeznamBot/i',
        ];
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        foreach ($search_engine_patterns as $pattern) {
            if (preg_match($pattern, $ua)) {
                return true;
            }
        }
        return false;
    }

    public static function cleanOldTriggers(int $maxAge = 86400): void {
        self::init();
        if (!is_dir(self::$trigger_dir)) return;
        foreach (glob(self::$trigger_dir . '*.json') as $file) {
            if (time() - filemtime($file) > $maxAge) {
                @unlink($file);
            }
        }
    }
}