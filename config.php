<?php
/**
 * 盾甲 WAF 配置文件
 * 
 * 密钥优先读取服务器环境变量（如 fastcgi_param），
 * 其次从同目录下的 .env 文件加载。
 * .env 文件已被 Nginx 禁止外部访问，确保安全。
 */
defined('ABSPATH') || exit;

// ======================== 简易 .env 加载 ========================
function waf_load_env($dir) {
    $file = $dir . '/.env';
    if (!is_file($file)) return;
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        // 跳过注释
        if (strpos($line, '#') === 0) continue;
        if (strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $key   = trim($key);
        $value = trim($value, " \t\n\r\0\x0B\"'");
        // 仅当服务器环境变量未设置时才从 .env 加载
        if (!getenv($key)) {
			$_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }
    }
}
waf_load_env(__DIR__);

// ======================== 密钥（优先级：服务器环境 > .env > 默认值） ========================
define('WAF_MAGIC_KEY',    getenv('WAF_MAGIC_KEY')    ?: 'change-me-magic-key-32-chars-min');
define('WAF_2FA_PASS',     getenv('WAF_2FA_PASS')     ?: 'change-me-2fa-password');

// ======================== 暗门有效期与重试次数 ========================
define('WAF_MAGIC_EXPIRE',    3600);
define('WAF_MAGIC_MAX_RETRY', 3);

// ======================== 日志与存储路径 ========================
define('WAF_LOG_PATH',        __DIR__ . '/waf_logs/');
define('WAF_ADMIN_IP_FILE',   WAF_LOG_PATH . 'admin_ips.txt');
define('WAF_ADMIN_IP_TTL',    86400);

// ======================== 安全功能开关 ========================
define('WAF_NORMALIZE_SQL_COMMENTS', true);
define('WAF_403_TEMPLATE',    __DIR__ . '/waf_403_template.php');

// ======================== CC 攻击防护 ========================
define('WAF_CC_LIMIT',  60);
define('WAF_CC_WINDOW', 60);
define('WAF_CC_LOG',    WAF_LOG_PATH . 'cc_counter.txt');

// ======================== 告警 Webhook ========================
define('WAF_WEBHOOK_URL', '');

// ======================== 仪表盘 ========================
define('WAF_DASHBOARD_PATH', '/waf-dashboard');
define('WAF_STATS_CACHE_SEC', 10);

// ======================== CDN 配置 ========================
define('WAF_TRUST_CF_IP', false);