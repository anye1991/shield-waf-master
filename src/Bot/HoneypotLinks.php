<?php
/**
 * 盾甲 WAF 蜜罐链接系统 (src/Bot/HoneypotLinks.php)
 *
 * 功能：
 *  1. 在HTML页面中注入对人类不可见的蜜罐链接
 *  2. 爬虫/扫描器点击后立即标记为恶意
 *  3. 支持多种隐藏方式（CSS off-screen、零宽字符、颜色融合）
 *  4. 动态生成随机路径，防止被识别绕过
 */
defined('ABSPATH') || exit;

class HoneypotLinks {
    private static $trigger_dir = null;
    private static $initialized = false;

    // 蜜罐路径前缀（看起来像真实路径）
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

    // 蜜罐参数名（看起来像正常参数）
    private static $param_names = [
        'debug',
        'test',
        'admin',
        'dev',
        'preview',
        'mode',
    ];

    /**
     * 初始化蜜罐系统
     */
    private static function init() {
        if (self::$initialized) return;
        $base = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (sys_get_temp_dir() . '/shield_waf_');
        self::$trigger_dir = $base . '/honeypot_triggers/';
        if (!is_dir(self::$trigger_dir)) @mkdir(self::$trigger_dir, 0700, true);
        self::$initialized = true;
    }

    /**
     * 检查当前请求是否命中了蜜罐
     * @return bool
     */
    public static function checkRequest(): bool {
        self::init();
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $ip  = self::getClientIp();

        // 检查路径是否匹配蜜罐模式
        foreach (self::$path_patterns as $pattern) {
            if (stripos($uri, $pattern) !== false) {
                self::recordTrigger($ip, $uri, 'path_match');
                return true;
            }
        }

        // 检查参数是否匹配蜜罐参数名 + 非空值
        // 注：避免误判 ?mode=admin / ?preview=true 等正常请求，
        // 要求值长度≥8 且同时含 2+ 敏感词才触发
        foreach (self::$param_names as $param) {
            if (isset($_GET[$param]) && !empty($_GET[$param])) {
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

    /**
     * 注入蜜罐链接到HTML内容（在</body>前插入）
     * @param string $html 原始HTML内容
     * @return string 注入后的HTML
     */
    public static function injectToHtml(string $html): string {
        // 只在HTML页面注入，不注入JSON/XML等
        if (stripos($html, '<!DOCTYPE') === false && stripos($html, '<html') === false) {
            return $html;
        }
        // 已登录/后台页面不注入（管理员可能会误点）
        if (self::isAdminPage()) {
            return $html;
        }

        $links = self::generateLinks(3);
        $injection = implode("\n", $links);

        // 在 </body> 前插入
        if (stripos($html, '</body>') !== false) {
            $html = str_ireplace('</body>', $injection . '</body>', $html);
        } else {
            $html .= $injection;
        }

        return $html;
    }

    /**
     * 生成蜜罐链接HTML
     * @param int $count 生成数量
     * @return array
     */
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

            // 随机添加一些参数让它看起来更真实
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

    /**
     * 生成看起来像真实链接文字的随机文本
     */
    private static function generateLinkText(): string {
        $texts = [
            'admin', 'login', 'panel', 'dashboard', 'control',
            '管理', '登录', '后台', '控制面板', '管理员',
            'secret', 'private', 'internal', 'dev', 'test',
        ];
        return $texts[array_rand($texts)];
    }

    /**
     * 生成随机token
     */
    private static function generateToken(): string {
        return substr(md5(uniqid(mt_rand(), true)), 0, 16);
    }

    /**
     * 记录蜜罐触发
     */
    private static function recordTrigger(string $ip, string $uri, string $reason) {
        self::init();
        $file = self::$trigger_dir . md5($ip) . '.json';
        $record = [
            'ip' => $ip,
            'uri' => $uri,
            'reason' => $reason,
            'time' => time(),
        ];
        @file_put_contents($file, json_encode($record), LOCK_EX);
    }

    /**
     * 获取某IP的蜜罐触发次数（最近24小时）
     */
    public static function getTriggerCount(string $ip): int {
        self::init();
        $file = self::$trigger_dir . md5($ip) . '.json';
        if (!is_file($file)) return 0;
        $raw = @file_get_contents($file);
        if (!$raw) return 0;
        $data = json_decode($raw, true);
        if (!is_array($data)) return 0;
        // 24小时内有效
        if (time() - ($data['time'] ?? 0) > 86400) return 0;
        return 1;
    }

    /**
     * 判断是否是后台/已登录页面（简单判断）
     */
    private static function isAdminPage(): bool {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return stripos($uri, 'wp-admin') !== false
            || stripos($uri, 'admin') !== false
            || stripos($uri, 'login') !== false;
    }

    private static function getClientIp(): string {
        if (function_exists('waf_get_real_ip')) return waf_get_real_ip();
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}
