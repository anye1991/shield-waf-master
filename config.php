<?php
/**
 * 盾甲 WAF 配置文件
 * 
 * 密钥优先读取服务器环境变量（如 fastcgi_param），
 * 其次从同目录下的 .env 文件加载。
 * .env 文件已被 Nginx 禁止外部访问，确保安全。
 */
// 兼容非 WordPress 环境：未定义 ABSPATH 时自动定义为本文件所在目录
// 注：与 shield-waf.php 顶部定义保持一致（dirname(__FILE__) === dirname(__DIR__) when called from /workspace/shield-waf-master/）
if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__FILE__) . '/');
}

// ======================== 版本号 ========================
define('SHIELD_WAF_VERSION', '5.2.0');

// ======================== 环境变量读取封装（兼容禁用 getenv/putenv 的环境） ========================
function waf_getenv($key) {
    if (isset($_ENV[$key])) {
        return $_ENV[$key];
    }
    if (isset($_SERVER[$key]) && strpos($key, 'HTTP_') !== 0) {
        return $_SERVER[$key];
    }
    if (function_exists('getenv')) {
        $val = getenv($key);
        if ($val !== false) {
            return $val;
        }
    }
    return false;
}

// ======================== 简易 .env 加载（带白名单） ========================
function waf_load_env($dir) {
    $file = $dir . '/.env';
    if (!is_file($file)) return;

    $allowedPrefixes = ['WAF_', 'SHIELD_'];
    $deniedPatterns = ['PHP_', 'HTTP_', 'REMOTE_', 'SERVER_', 'PATH', 'LD_', 'TEMP', 'TMP'];

    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if (strpos($line, '#') === 0) continue;
        if (strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $key   = trim($key);
        $value = trim($value, " \t\n\r\0\x0B\"'");

        if (!preg_match('/^[A-Z][A-Z0-9_]*$/', $key)) continue;

        $isAllowed = false;
        foreach ($allowedPrefixes as $prefix) {
            if (strpos($key, $prefix) === 0) {
                $isAllowed = true;
                break;
            }
        }
        if (!$isAllowed) continue;

        $isDenied = false;
        foreach ($deniedPatterns as $pattern) {
            if (strpos($key, $pattern) === 0) {
                $isDenied = true;
                break;
            }
        }
        if ($isDenied) continue;

        if (waf_getenv($key) === false) {
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
            if (function_exists('putenv')) {
                @putenv($key . '=' . $value);
            }
        }
    }
}
waf_load_env(__DIR__);

// ======================== 日志与存储路径（提前定义，供密钥自动生成使用） ========================
// 注意：末尾不带斜杠，拼接时统一加 /xxx
// 允许外部（shield-waf.php）在加载 config.php 之前预定义，实现 /tmp 自动降级
if (!defined('WAF_LOG_PATH')) {
    define('WAF_LOG_PATH', __DIR__ . '/logs');
}

// ======================== 密钥自动生成 ========================
function waf_generate_random_key($length = 32) {
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes($length));
    }
    if (function_exists('openssl_random_pseudo_bytes')) {
        return bin2hex(openssl_random_pseudo_bytes($length));
    }
    return '';
}

function waf_get_auto_key($keyName, $defaultValue, $minLength = 32) {
    static $cache = [];
    if (isset($cache[$keyName])) {
        return $cache[$keyName];
    }

    $envValue = waf_getenv($keyName);
    if ($envValue !== false && $envValue !== '' && $envValue !== $defaultValue) {
        $cache[$keyName] = $envValue;
        return $envValue;
    }

    $autoKeyFile = WAF_LOG_PATH . '/auto_key.php';
    if (!is_dir(WAF_LOG_PATH)) {
        @mkdir(WAF_LOG_PATH, 0700, true);
    }
    $htaccess = WAF_LOG_PATH . '/.htaccess';
    if (!is_file($htaccess)) {
        @file_put_contents($htaccess, "Order Deny,Allow\nDeny from all\n");
        @chmod($htaccess, 0600);
    }

    if (is_file($autoKeyFile)) {
        $autoKeys = @include $autoKeyFile;
        if (is_array($autoKeys) && isset($autoKeys[$keyName]) && is_string($autoKeys[$keyName]) && $autoKeys[$keyName] !== '') {
            $cache[$keyName] = $autoKeys[$keyName];
            return $autoKeys[$keyName];
        }
    }

    $needGenerate = ($envValue === false || $envValue === '' || $envValue === $defaultValue);
    if ($needGenerate) {
        $newKey = waf_generate_random_key($minLength);
        if ($newKey && strlen($newKey) >= $minLength) {
            $autoKeys = [];
            if (is_file($autoKeyFile)) {
                $existing = @include $autoKeyFile;
                if (is_array($existing)) {
                    $autoKeys = $existing;
                }
            }
            $autoKeys[$keyName] = $newKey;
            $content = '<?php return ' . var_export($autoKeys, true) . ';';
            @file_put_contents($autoKeyFile, $content, LOCK_EX);
            @chmod($autoKeyFile, 0600);

            @file_put_contents(WAF_LOG_PATH . '/security.log',
                '[' . date('Y-m-d H:i:s') . "] 警告：" . $keyName . " 未设置，已自动生成随机密钥并保存到 auto_key.php\n",
                FILE_APPEND);

            $cache[$keyName] = $newKey;
            return $newKey;
        }
    }

    $cache[$keyName] = $defaultValue;
    return $defaultValue;
}

// ======================== 密钥（全部统一存储在 auto_key.php） ========================
// 优先级：服务器环境变量 > .env > auto_key.php（自动生成） > 启动失败
// 安全设计：所有密钥统一存放 auto_key.php，config.php 可纳入版本管理
// 安全策略：默认值留空，自动生成失败时直接 die()，绝不回退到可被猜测的弱密钥
// WAF_MAGIC_KEY：暗门密钥（URL 参数 ?magic=xxx）
// WAF_PASSWORD：  暗门密码（页面输入框）
$_resolvedMagicKey = waf_get_auto_key('WAF_MAGIC_KEY', '', 32);
if ($_resolvedMagicKey === '' || strlen($_resolvedMagicKey) < 32) {
    @file_put_contents(WAF_LOG_PATH . '/security.log',
        '[' . date('Y-m-d H:i:s') . "] 致命：WAF_MAGIC_KEY 未配置且自动生成失败，拒绝启动\n",
        FILE_APPEND);
    http_response_code(500);
    die('Shield WAF: magic key configuration failure');
}
define('WAF_MAGIC_KEY', $_resolvedMagicKey);
unset($_resolvedMagicKey);

$_resolvedPassword = waf_get_auto_key('WAF_PASSWORD', '', 24);
if ($_resolvedPassword === '' || strlen($_resolvedPassword) < 24) {
    @file_put_contents(WAF_LOG_PATH . '/security.log',
        '[' . date('Y-m-d H:i:s') . "] 致命：WAF_PASSWORD 未配置且自动生成失败，拒绝启动\n",
        FILE_APPEND);
    http_response_code(500);
    die('Shield WAF: password configuration failure');
}
define('WAF_PASSWORD', $_resolvedPassword);
unset($_resolvedPassword);

// ======================== 暗门有效期与重试次数 ========================
define('WAF_MAGIC_EXPIRE',    waf_getenv('WAF_MAGIC_EXPIRE')    !== false ? (int)waf_getenv('WAF_MAGIC_EXPIRE')    : 3600);
define('WAF_MAGIC_MAX_RETRY', waf_getenv('WAF_MAGIC_MAX_RETRY') !== false ? (int)waf_getenv('WAF_MAGIC_MAX_RETRY') : 3);

// ======================== 日志与存储路径 ========================
define('WAF_ADMIN_IP_FILE',     WAF_LOG_PATH . '/admin_ips.txt');
define('WAF_ADMIN_IP_TTL',      86400);
define('WAF_LOG_MAX_SIZE',  waf_getenv('WAF_LOG_MAX_SIZE') !== false ? (int)waf_getenv('WAF_LOG_MAX_SIZE') : 10485760);
// 向后兼容：旧版常量名 WAF_LOG_MAX_FILESIZE 已弃用，统一为 WAF_LOG_MAX_SIZE
if (!defined('WAF_LOG_MAX_FILESIZE')) {
    define('WAF_LOG_MAX_FILESIZE', WAF_LOG_MAX_SIZE);
}

// ======================== 管理员 IP 白名单（直配置，方便测试） ========================
// 在 config.php 直接配置管理员 IP（或 CIDR 网段），无需登录控制台手动添加。
// 白名单效果：
//   1. 跳过速率限制（waf_cc_check）
//   2. 跳过封禁检查（waf_is_banned 不拦截白名单 IP）
//   3. waf_smart_ban 不对白名单 IP 累进封禁（但仍会 waf_block 触发 403 页面）
//   4. 沙箱、暗门等敏感操作只允许白名单 IP
//
// 配置示例：
//   define('WAF_ADMIN_IPS', ['127.0.0.1', '192.168.1.100', '10.0.0.0/8']);
//
// 也可通过 .env 配置：WAF_ADMIN_IPS=127.0.0.1,192.168.1.100,10.0.0.0/8
if (!defined('WAF_ADMIN_IPS')) {
    $env_admin_ips = waf_getenv('WAF_ADMIN_IPS');
    if ($env_admin_ips !== false && $env_admin_ips !== '') {
        $admin_ip_list = array_filter(array_map('trim', explode(',', $env_admin_ips)));
        define('WAF_ADMIN_IPS', $admin_ip_list);
    } else {
        define('WAF_ADMIN_IPS', []); // 默认空数组，通过控制台或 .env 配置
    }
    unset($env_admin_ips, $admin_ip_list);
}

// ======================== 测试模式（只拦截不封IP） ========================
// 测试模式效果：
//   1. waf_smart_ban / waf_ban 不执行实际封禁（但记录到 logs/test_mode_ban.log）
//   2. waf_block 仍触发 403 拦截页面（但不会把 IP 加入 ban.txt）
//   3. 方便测试 WAF 拦截规则是否生效，又不影响后续访问
//
// 配置示例：
//   define('WAF_TEST_MODE', true);  // 启用测试模式
//   .env 写入：WAF_TEST_MODE=true
//
// 生产环境务必保持 false！
if (!defined('WAF_TEST_MODE')) {
    $env_test_mode = waf_getenv('WAF_TEST_MODE');
    define('WAF_TEST_MODE', $env_test_mode !== false ? ($env_test_mode === 'true') : false);
    unset($env_test_mode);
}

// ======================== 安全功能开关 ========================
define('WAF_NORMALIZE_SQL_COMMENTS', true);
define('WAF_ERROR_MASKING', waf_getenv('WAF_ERROR_MASKING') !== false ? (waf_getenv('WAF_ERROR_MASKING') === 'true') : true);
define('WAF_403_TEMPLATE',    __DIR__ . '/src/Admin/Waf403Template.php');
define('WAF_MAX_BODY_SIZE',       waf_getenv('WAF_MAX_BODY_SIZE')       !== false ? (int)waf_getenv('WAF_MAX_BODY_SIZE')       : 1048576);
define('WAF_MAX_ENCODING_DEPTH',  waf_getenv('WAF_MAX_ENCODING_DEPTH')  !== false ? (int)waf_getenv('WAF_MAX_ENCODING_DEPTH')  : 8);
define('WAF_MAX_PAYLOAD_SIZE',    waf_getenv('WAF_MAX_PAYLOAD_SIZE')    !== false ? (int)waf_getenv('WAF_MAX_PAYLOAD_SIZE')    : 100000);
define('WAF_SESSION_REGENERATE',  waf_getenv('WAF_SESSION_REGENERATE')  !== false ? (waf_getenv('WAF_SESSION_REGENERATE') === 'true')  : true);
define('WAF_DB_DEBUG',            waf_getenv('WAF_DB_DEBUG')            !== false ? (waf_getenv('WAF_DB_DEBUG') === 'true')            : false);
// WAF 调试模式：开启后输出详细检测日志（生产环境务必关闭）
define('WAF_DEBUG',               waf_getenv('WAF_DEBUG')               !== false ? (waf_getenv('WAF_DEBUG') === 'true')               : false);
// 存储目录：用于 RaceCondition 等模块的临时文件存储，默认使用系统临时目录
define('WAF_STORAGE_DIR',         waf_getenv('WAF_STORAGE_DIR')         !== false ? waf_getenv('WAF_STORAGE_DIR')                     : (sys_get_temp_dir() . '/shield-waf'));
// 上传路径白名单：识别为上传目录的路径前缀，用于相关防护逻辑
define('WAF_UPLOAD_PATH',         waf_getenv('WAF_UPLOAD_PATH')         !== false ? waf_getenv('WAF_UPLOAD_PATH')                     : '/wp-content/uploads/');
// WordPress 密码策略集成：设为 true 自动接管 wp_hash_password/wp_check_password
define('WAF_PASSWORD_WP_INTEGRATION', waf_getenv('WAF_PASSWORD_WP_INTEGRATION') !== false ? (waf_getenv('WAF_PASSWORD_WP_INTEGRATION') === 'true') : false);
define('SHIELD_WAF_CSP',                waf_getenv('SHIELD_WAF_CSP')                !== false ? waf_getenv('SHIELD_WAF_CSP')                : '');
define('SHIELD_WAF_PERMISSIONS_POLICY', waf_getenv('SHIELD_WAF_PERMISSIONS_POLICY') !== false ? waf_getenv('SHIELD_WAF_PERMISSIONS_POLICY') : '');

// ======================== 场景白名单（通用性配置） ========================
// WAF 通过路径关键字自动识别请求场景，对登录/支付回调/搜索/评论等业务核心路径
// 跳过特征检测（CSRF/Bot/注入正则等），仅保留速率限制、IP封禁、Session防护等基础安全。
// 这样既能防护攻击，又不会误伤任何 PHP 应用的正常业务流程。
//
// 1) 高可信路径（HARD_SKIP）：POST 表单本身是业务核心，任何特征拦截都会误伤
//    默认已覆盖：login/signin/register/auth/my-account/payment/callback/checkout
//                alipay/wechat/paypal/stripe/oauth/webhook 等
//    如需追加，在此数组中添加路径关键字（不区分大小写，支持前缀匹配）
if (!defined('WAF_TRUSTED_PATHS')) {
    define('WAF_TRUSTED_PATHS', []);
}
// 2) 敏感输入路径（SOFT_SKIP）：含富文本/搜索词，跳过黑名单关键字检测但保留结构化检测
//    默认已覆盖：comment/search/forum/post/reply/edit 等
//    如需追加，在此数组中添加路径关键字
if (!defined('WAF_SOFTSKIP_PATHS')) {
    define('WAF_SOFTSKIP_PATHS', []);
}

// ======================== 机器人检测 ========================
// 是否通过 DNS 反向解析验证搜索引擎蜘蛛真实性（最可靠，但每次请求增加一次DNS查询）
// false = 仅通过 UA + 头特征验证（默认，零延迟）
// true  = 启用 DNS 反查（forward+reverse 双向验证，推荐高安全需求站点开启）
define('WAF_BOT_VERIFY_DNS', waf_getenv('WAF_BOT_VERIFY_DNS') !== false ? (waf_getenv('WAF_BOT_VERIFY_DNS') === 'true') : false);

// ======================== CC 攻击防护 ========================
// 默认 120 次/分钟（静态资源已在 shield-waf.php 顶部放行，此处仅计动态请求）
// AJAX 请求（WordPress heartbeat/wp-json/admin-ajax）阈值更高（240 次/分钟）
// 可通过环境变量 WAF_CC_LIMIT 自定义
define('WAF_CC_LIMIT',  waf_getenv('WAF_CC_LIMIT')  !== false ? (int)waf_getenv('WAF_CC_LIMIT')  : 120);
define('WAF_CC_WINDOW', waf_getenv('WAF_CC_WINDOW') !== false ? (int)waf_getenv('WAF_CC_WINDOW') : 60);
define('WAF_CC_LOG',    WAF_LOG_PATH . '/cc_counter.txt');
// AJAX 请求（wp-json/admin-ajax/heartbeat）速率上限
define('WAF_CC_LIMIT_AJAX', waf_getenv('WAF_CC_LIMIT_AJAX') !== false ? (int)waf_getenv('WAF_CC_LIMIT_AJAX') : 240);
// 单 IP 在 CC 日志文件中的最大行数（超过丢弃最旧），防止日志无限增长
define('WAF_CC_FILE_MAX_PER_IP', waf_getenv('WAF_CC_FILE_MAX_PER_IP') !== false ? (int)waf_getenv('WAF_CC_FILE_MAX_PER_IP') : 1000);
// 异步清理触发间隔（每 N 次请求触发一次全窗口清理）
define('WAF_CC_CLEANUP_INTERVAL', waf_getenv('WAF_CC_CLEANUP_INTERVAL') !== false ? (int)waf_getenv('WAF_CC_CLEANUP_INTERVAL') : 100);
// 是否跳过速率限制（用于调试或内网白名单场景）
define('WAF_SKIP_RATELIMIT', waf_getenv('WAF_SKIP_RATELIMIT') !== false ? (waf_getenv('WAF_SKIP_RATELIMIT') === 'true') : false);

// ======================== 告警 Webhook ========================
define('WAF_WEBHOOK_URL', '');

// ======================== 仪表盘 ========================
define('WAF_DASHBOARD_PATH', '/waf-dashboard');
define('WAF_STATS_CACHE_SEC', 10);

// ======================== CDN 配置 ========================
define('WAF_TRUST_CF_IP', false);
// CORS 跨域白名单（逗号分隔）
define('WAF_CORS_ALLOWED_ORIGINS', waf_getenv('WAF_CORS_ALLOWED_ORIGINS') !== false ? waf_getenv('WAF_CORS_ALLOWED_ORIGINS') : (waf_getenv('WAF_ALLOWED_ORIGINS') !== false ? waf_getenv('WAF_ALLOWED_ORIGINS') : ''));
// 向后兼容：旧版常量名 WAF_ALLOWED_ORIGINS 已弃用
if (!defined('WAF_ALLOWED_ORIGINS')) {
    define('WAF_ALLOWED_ORIGINS', WAF_CORS_ALLOWED_ORIGINS);
}

// ======================== 沙箱配置 ========================
// 沙箱工作模式：
//   learning  - 学习模式（首次安装默认）：只扫描告警，不删除任何文件，让用户排查后门
//   baseline  - 基线模式：建立干净文件哈希基线
//   protecting- 保护模式：秒删除新落地文件，精准切割被篡改的原始文件
define('WAF_SANDBOX_MODE', waf_getenv('WAF_SANDBOX_MODE') !== false ? waf_getenv('WAF_SANDBOX_MODE') : 'learning');
// 自动扫描间隔（秒），默认 300 = 5 分钟
define('WAF_SANDBOX_SCAN_INTERVAL', waf_getenv('WAF_SANDBOX_SCAN_INTERVAL') !== false ? (int)waf_getenv('WAF_SANDBOX_SCAN_INTERVAL') : 300);
// 监控目录（数组），默认为 ABSPATH（站点根目录）
// PHP 7.0+ 支持数组常量，无需 json_encode
if (!defined('WAF_SANDBOX_MONITOR_DIRS')) {
    define('WAF_SANDBOX_MONITOR_DIRS', [ABSPATH]);
}
// 隔离区目录
define('WAF_SANDBOX_QUARANTINE_DIR', WAF_LOG_PATH . '/quarantine');
// 新落地的恶意文件是否秒删除（true=直接删除，false=移入隔离区）
define('WAF_SANDBOX_INSTANT_DELETE_NEW', waf_getenv('WAF_SANDBOX_INSTANT_DELETE_NEW') !== false ? (waf_getenv('WAF_SANDBOX_INSTANT_DELETE_NEW') === 'true') : true);
// 修改的现有文件含恶意代码时是否自动隔离（true=自动隔离待审核，false=仅告警）
define('WAF_SANDBOX_AUTO_QUARANTINE', waf_getenv('WAF_SANDBOX_AUTO_QUARANTINE') !== false ? (waf_getenv('WAF_SANDBOX_AUTO_QUARANTINE') === 'true') : true);
// 沙箱扫描排除目录（PHP 数组，PHP 7.0+ 支持）
if (!defined('WAF_SANDBOX_EXCLUDE_DIRS')) {
    define('WAF_SANDBOX_EXCLUDE_DIRS', [
        WAF_LOG_PATH,               // 日志目录
        '/wp-content/cache/',      // 缓存目录
        '/wp-content/uploads/',    // 上传目录（由 upload.php 单独防护）
    ]);
}
// 恶意代码判定阈值（评分 >= 此值即判定为恶意）
define('WAF_SANDBOX_MALWARE_THRESHOLD', waf_getenv('WAF_SANDBOX_MALWARE_THRESHOLD') !== false ? (int)waf_getenv('WAF_SANDBOX_MALWARE_THRESHOLD') : 50);
// 沙箱白名单路径（这些路径下的文件永不删除/隔离）
if (!defined('WAF_SANDBOX_WHITELIST_PATHS')) {
    define('WAF_SANDBOX_WHITELIST_PATHS', []);
}
// 沙箱↔AutoLearn 联动开关（事件回流 + 特征反哺 + 基线冻结联动）
// true = 启用三个集成点（推荐）
// false = 沙箱与 AutoLearn 完全解耦，互不影响
define('WAF_SANDBOX_LEARN_COUPLING', waf_getenv('WAF_SANDBOX_LEARN_COUPLING') !== false ? (waf_getenv('WAF_SANDBOX_LEARN_COUPLING') === 'true') : true);

// ======================== 上传检测配置 ========================
// 是否启用文件上传检测
define('WAF_UPLOAD_DETECTION', waf_getenv('WAF_UPLOAD_DETECTION') !== false ? (waf_getenv('WAF_UPLOAD_DETECTION') === 'true') : true);
// 允许上传的文件扩展名白名单（PHP 数组）
// 默认包含常见图片 + 文档 + 压缩包，覆盖大多数网站需求
// 注意：这只是一个宽松的默认值，高危扩展名（php/asp/jsp/exe）无论如何都不会放行
define('WAF_UPLOAD_ALLOWED_EXT', [
    // 图片
    'jpg','jpeg','png','gif','webp','bmp','ico','svg',
    // 文档
    'pdf','doc','docx','xls','xlsx','ppt','pptx','txt','rtf','odt','ods','odp',
    // 压缩包
    'zip','rar','7z','tar','gz','bz2',
    // 音视频（如果网站允许）
    'mp3','mp4','wav','webm','ogg','avi','mov',
]);
// 允许的 MIME 类型（PHP 数组）
define('WAF_UPLOAD_ALLOWED_MIME', [
    // 图片
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'image/bmp', 'image/x-icon', 'image/svg+xml',
    // 文档
    'application/pdf',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'text/plain', 'application/rtf',
    // 压缩包
    'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
    'application/x-tar', 'application/gzip', 'application/x-bzip2',
    // 音视频
    'audio/mpeg', 'audio/wav', 'audio/ogg',
    'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
]);
// 是否使用 GD 库验证图像真实性（比 finfo 更严格，能识别图像马）
define('WAF_UPLOAD_GD_VERIFY', waf_getenv('WAF_UPLOAD_GD_VERIFY') !== false ? (waf_getenv('WAF_UPLOAD_GD_VERIFY') === 'true') : true);
// 是否允许 SVG 上传（SVG 可携带脚本和 XXE，风险较高）
define('WAF_UPLOAD_ALLOW_SVG', waf_getenv('WAF_UPLOAD_ALLOW_SVG') !== false ? (waf_getenv('WAF_UPLOAD_ALLOW_SVG') === 'true') : false);
// 上传文件内容恶意评分阈值（>= 此值直接拦截）
define('WAF_UPLOAD_BLOCK_THRESHOLD', waf_getenv('WAF_UPLOAD_BLOCK_THRESHOLD') !== false ? (int)waf_getenv('WAF_UPLOAD_BLOCK_THRESHOLD') : 60);
// 上传文件内容可疑阈值（>= 此值记录日志，< 此值放行）
define('WAF_UPLOAD_LOG_THRESHOLD', waf_getenv('WAF_UPLOAD_LOG_THRESHOLD') !== false ? (int)waf_getenv('WAF_UPLOAD_LOG_THRESHOLD') : 30);
// 上传文件扫描最大大小（字节），超过此大小只扫描头部和尾部
define('WAF_UPLOAD_SCAN_MAX_SIZE', waf_getenv('WAF_UPLOAD_SCAN_MAX_SIZE') !== false ? (int)waf_getenv('WAF_UPLOAD_SCAN_MAX_SIZE') : 5 * 1024 * 1024);
// 上传检测是否启用累进封禁
define('WAF_UPLOAD_BAN_ON_BLOCK', waf_getenv('WAF_UPLOAD_BAN_ON_BLOCK') !== false ? (waf_getenv('WAF_UPLOAD_BAN_ON_BLOCK') === 'true') : true);

// ======================== 语义引擎配置 ========================
// 语义分析是否启用（关闭后仅使用归一化+评分，防御能力降低）
define('WAF_SEMANTIC_ENGINE', waf_getenv('WAF_SEMANTIC_ENGINE') !== false ? (waf_getenv('WAF_SEMANTIC_ENGINE') === 'true') : true);
define('WAF_SEMANTIC_ENABLED', waf_getenv('WAF_SEMANTIC_ENABLED') !== false ? (waf_getenv('WAF_SEMANTIC_ENABLED') === 'true') : true);
// 语义记忆池是否启用（记录每个IP的语义指纹，跨请求对比分析）
define('WAF_SEMANTIC_MEMORY', waf_getenv('WAF_SEMANTIC_MEMORY') !== false ? (waf_getenv('WAF_SEMANTIC_MEMORY') === 'true') : true);
// 语义记忆池保留时间（小时）
define('WAF_SEMANTIC_MEMORY_TTL', 48);
// 攻击链分析是否启用（关联同一IP多步攻击行为）
define('WAF_ATTACK_CHAIN', waf_getenv('WAF_ATTACK_CHAIN') !== false ? (waf_getenv('WAF_ATTACK_CHAIN') === 'true') : true);
// 攻击链保留时间（小时）
define('WAF_ATTACK_CHAIN_TTL', 24);
// 参数位置上下文分析（L11）：同 payload 在不同位置（query/post/cookie/header/json）威胁不同
define('WAF_PARAM_POSITION_ANALYZER', waf_getenv('WAF_PARAM_POSITION_ANALYZER') !== false ? (waf_getenv('WAF_PARAM_POSITION_ANALYZER') === 'true') : true);
// 跨请求上下文分析（L12）：CSRF/重放攻击/会话异常/时序异常/API滥用检测
define('WAF_REQUEST_CONTEXT_ANALYZER', waf_getenv('WAF_REQUEST_CONTEXT_ANALYZER') !== false ? (waf_getenv('WAF_REQUEST_CONTEXT_ANALYZER') === 'true') : true);

// ======================== 主动防御配置 ========================
// 主动防御是否启用（蜜罐+预判拦截+攻击链封堵）
define('WAF_ACTIVE_DEFENSE', waf_getenv('WAF_ACTIVE_DEFENSE') !== false ? (waf_getenv('WAF_ACTIVE_DEFENSE') === 'true') : true);
// 蜜罐是否启用（部署虚假管理后台/phpMyAdmin/Git仓库等）
define('WAF_HONEYTRAP', waf_getenv('WAF_HONEYTRAP') !== false ? (waf_getenv('WAF_HONEYTRAP') === 'true') : true);
// 攻击路径预判是否启用
define('WAF_PATH_PREDICTION', waf_getenv('WAF_PATH_PREDICTION') !== false ? (waf_getenv('WAF_PATH_PREDICTION') === 'true') : true);
// 误报控制是否启用（7层确认机制，确保不误杀正常请求）
define('WAF_FALSE_POSITIVE_GUARD', waf_getenv('WAF_FALSE_POSITIVE_GUARD') !== false ? (waf_getenv('WAF_FALSE_POSITIVE_GUARD') === 'true') : true);

// ======================== 评分系统配置 ========================
// 评分系统是否启用
define('WAF_SCORER_ENABLED', waf_getenv('WAF_SCORER_ENABLED') !== false ? (waf_getenv('WAF_SCORER_ENABLED') === 'true') : true);
// 自动学习是否启用
define('WAF_AUTOLEARN_ENABLED', waf_getenv('WAF_AUTOLEARN_ENABLED') !== false ? (waf_getenv('WAF_AUTOLEARN_ENABLED') === 'true') : true);
// 拦截阈值（总分>=此值拦截），与 shield-waf.php 中 $blockThreshold 保持一致
// 四级响应：<30 放行 / 30-50 记录 / 50-75 观察 / >=75 拦截
// 注：当前架构为规则引擎+语义解析器双路评分，取较高值作为最终判定
define('WAF_SCORE_BLOCK', waf_getenv('WAF_SCORE_BLOCK') !== false ? (int)waf_getenv('WAF_SCORE_BLOCK') : 70);
// 监控阈值（总分>=此值记录日志但不拦截）
define('WAF_SCORE_MONITOR', waf_getenv('WAF_SCORE_MONITOR') !== false ? (int)waf_getenv('WAF_SCORE_MONITOR') : 40);
// 语义分析权重（暂未使用，保留供未来四维评分架构使用）
// 当前语义证据通过 SemanticEngine 直接与规则引擎融合计算，不使用此配置
define('WAF_SEMANTIC_WEIGHT', 30);

// ======================== 性能优化配置 ========================
// APCu 缓存是否启用（优先使用 APCu 共享内存，文件降级兜底）
define('WAF_APCU_ENABLED', waf_getenv('WAF_APCU_ENABLED') !== false ? (waf_getenv('WAF_APCU_ENABLED') === 'true') : function_exists('apcu_enabled') && apcu_enabled());
// 单次检测输入最大长度（字节），超过此值截断扫描，防止 OOM
define('WAF_INPUT_MAX_LENGTH', waf_getenv('WAF_INPUT_MAX_LENGTH') !== false ? (int)waf_getenv('WAF_INPUT_MAX_LENGTH') : 8192);
// CC 防护 APCu TTL（秒）
define('WAF_CC_APCU_TTL', waf_getenv('WAF_CC_APCU_TTL') !== false ? (int)waf_getenv('WAF_CC_APCU_TTL') : 60);
// 恶意文件扫描缓存 TTL（秒）
define('WAF_MALWARE_SCAN_CACHE_TTL', waf_getenv('WAF_MALWARE_SCAN_CACHE_TTL') !== false ? (int)waf_getenv('WAF_MALWARE_SCAN_CACHE_TTL') : 300);
// 大文件流式扫描分块大小（字节）
define('WAF_LARGE_FILE_CHUNK_SIZE', waf_getenv('WAF_LARGE_FILE_CHUNK_SIZE') !== false ? (int)waf_getenv('WAF_LARGE_FILE_CHUNK_SIZE') : 1048576);
// 正则预筛是否启用（正常请求快速跳过）
define('WAF_REGEX_PREFILTER', waf_getenv('WAF_REGEX_PREFILTER') !== false ? (waf_getenv('WAF_REGEX_PREFILTER') === 'true') : true);
// 合并大正则是否启用（减少 preg_match 调用次数）
define('WAF_COMBINED_PATTERN', waf_getenv('WAF_COMBINED_PATTERN') !== false ? (waf_getenv('WAF_COMBINED_PATTERN') === 'true') : true);
// 机器人检测配置
