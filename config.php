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
define('SHIELD_WAF_VERSION', '4.1.1');

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

        if (!getenv($key)) {
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }
    }
}
waf_load_env(__DIR__);

// ======================== 日志与存储路径（提前定义，供密钥自动生成使用） ========================
// 注意：末尾不带斜杠，拼接时统一加 /xxx
define('WAF_LOG_PATH',          __DIR__ . '/logs');

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
    $envValue = getenv($keyName);
    if ($envValue !== false && $envValue !== '') {
        return $envValue;
    }

    $autoKeyFile = WAF_LOG_PATH . '/auto_key.php';
    if (is_file($autoKeyFile)) {
        $autoKeys = @include $autoKeyFile;
        if (is_array($autoKeys) && isset($autoKeys[$keyName]) && !empty($autoKeys[$keyName])) {
            return $autoKeys[$keyName];
        }
    }

    if ($envValue === $defaultValue || $envValue === false || $envValue === '') {
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
            @file_put_contents($autoKeyFile, $content);
            @chmod($autoKeyFile, 0600);

            @file_put_contents(WAF_LOG_PATH . '/security.log',
                '[' . date('Y-m-d H:i:s') . "] 警告：检测到 " . $keyName . " 使用默认值，已自动生成随机密钥并保存到 auto_key.php\n",
                FILE_APPEND);

            return $newKey;
        }
    }

    return $defaultValue;
}

// ======================== 密钥（优先级：服务器环境 > .env > 自动生成 > 默认值） ========================
define('WAF_MAGIC_KEY', waf_get_auto_key('WAF_MAGIC_KEY', 'change-me-magic-key-32-chars-min', 32));
define('WAF_2FA_PASS',  waf_get_auto_key('WAF_2FA_PASS',  'change-me-2fa-password', 32));

// ======================== 密码认证（WordPress 简化模式：直接使用密码，禁用双重加密） ========================
// WordPress 用户直接设置密码即可，无需复杂的双重加密
// 首次安装建议设置强密码：WAF_PASSWORD=你的强密码
// 后续可通过控制台修改密码
if (!defined('WAF_PASSWORD')) {
    $envPassword = getenv('WAF_PASSWORD');
    if ($envPassword !== false && $envPassword !== '') {
        define('WAF_PASSWORD', $envPassword);
    } else {
        define('WAF_PASSWORD', 'shield-waf-2026');
    }
    unset($envPassword);
}

// ======================== 暗门有效期与重试次数 ========================
define('WAF_MAGIC_EXPIRE',    getenv('WAF_MAGIC_EXPIRE')    !== false ? (int)getenv('WAF_MAGIC_EXPIRE')    : 3600);
define('WAF_MAGIC_MAX_RETRY', getenv('WAF_MAGIC_MAX_RETRY') !== false ? (int)getenv('WAF_MAGIC_MAX_RETRY') : 3);

// ======================== 日志与存储路径 ========================
define('WAF_ADMIN_IP_FILE',     WAF_LOG_PATH . '/admin_ips.txt');
define('WAF_ADMIN_IP_TTL',      86400);
define('WAF_LOG_MAX_FILESIZE',  getenv('WAF_LOG_MAX_FILESIZE') !== false ? (int)getenv('WAF_LOG_MAX_FILESIZE') : 10485760);

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
    $env_admin_ips = getenv('WAF_ADMIN_IPS');
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
    $env_test_mode = getenv('WAF_TEST_MODE');
    define('WAF_TEST_MODE', $env_test_mode !== false ? ($env_test_mode === 'true') : false);
    unset($env_test_mode);
}

// ======================== 安全功能开关 ========================
define('WAF_NORMALIZE_SQL_COMMENTS', true);
define('WAF_ERROR_MASKING', getenv('WAF_ERROR_MASKING') !== false ? (getenv('WAF_ERROR_MASKING') === 'true') : true);
define('WAF_403_TEMPLATE',    __DIR__ . '/src/Admin/Waf403Template.php');
define('WAF_MAX_BODY_SIZE',       getenv('WAF_MAX_BODY_SIZE')       !== false ? (int)getenv('WAF_MAX_BODY_SIZE')       : 1048576);
define('WAF_MAX_ENCODING_DEPTH',  getenv('WAF_MAX_ENCODING_DEPTH')  !== false ? (int)getenv('WAF_MAX_ENCODING_DEPTH')  : 8);
define('WAF_MAX_PAYLOAD_SIZE',    getenv('WAF_MAX_PAYLOAD_SIZE')    !== false ? (int)getenv('WAF_MAX_PAYLOAD_SIZE')    : 100000);
define('WAF_SESSION_REGENERATE',  getenv('WAF_SESSION_REGENERATE')  !== false ? (getenv('WAF_SESSION_REGENERATE') === 'true')  : true);
define('WAF_DB_DEBUG',            getenv('WAF_DB_DEBUG')            !== false ? (getenv('WAF_DB_DEBUG') === 'true')            : false);
define('SHIELD_WAF_CSP',                getenv('SHIELD_WAF_CSP')                !== false ? getenv('SHIELD_WAF_CSP')                : '');
define('SHIELD_WAF_PERMISSIONS_POLICY', getenv('SHIELD_WAF_PERMISSIONS_POLICY') !== false ? getenv('SHIELD_WAF_PERMISSIONS_POLICY') : '');

// ======================== 机器人检测 ========================
// 是否通过 DNS 反向解析验证搜索引擎蜘蛛真实性（最可靠，但每次请求增加一次DNS查询）
// false = 仅通过 UA + 头特征验证（默认，零延迟）
// true  = 启用 DNS 反查（forward+reverse 双向验证，推荐高安全需求站点开启）
define('WAF_BOT_VERIFY_DNS', getenv('WAF_BOT_VERIFY_DNS') !== false ? (getenv('WAF_BOT_VERIFY_DNS') === 'true') : false);

// ======================== CC 攻击防护 ========================
define('WAF_CC_LIMIT',  getenv('WAF_CC_LIMIT')  !== false ? (int)getenv('WAF_CC_LIMIT')  : 60);
define('WAF_CC_WINDOW', getenv('WAF_CC_WINDOW') !== false ? (int)getenv('WAF_CC_WINDOW') : 60);
define('WAF_CC_LOG',    WAF_LOG_PATH . '/cc_counter.txt');

// ======================== 告警 Webhook ========================
define('WAF_WEBHOOK_URL', '');

// ======================== 仪表盘 ========================
define('WAF_DASHBOARD_PATH', '/waf-dashboard');
define('WAF_STATS_CACHE_SEC', 10);

// ======================== CDN 配置 ========================
define('WAF_TRUST_CF_IP', false);
define('WAF_ALLOWED_ORIGINS', getenv('WAF_ALLOWED_ORIGINS') !== false ? getenv('WAF_ALLOWED_ORIGINS') : '');

// ======================== 沙箱配置 ========================
// 沙箱工作模式：
//   learning  - 学习模式（首次安装默认）：只扫描告警，不删除任何文件，让用户排查后门
//   baseline  - 基线模式：建立干净文件哈希基线
//   protecting- 保护模式：秒删除新落地文件，精准切割被篡改的原始文件
define('WAF_SANDBOX_MODE', getenv('WAF_SANDBOX_MODE') !== false ? getenv('WAF_SANDBOX_MODE') : 'learning');
// 自动扫描间隔（秒），默认 300 = 5 分钟
define('WAF_SANDBOX_SCAN_INTERVAL', getenv('WAF_SANDBOX_SCAN_INTERVAL') !== false ? (int)getenv('WAF_SANDBOX_SCAN_INTERVAL') : 300);
// 监控目录（数组），默认为 ABSPATH（站点根目录）
// PHP 7.0+ 支持数组常量，无需 json_encode
if (!defined('WAF_SANDBOX_MONITOR_DIRS')) {
    define('WAF_SANDBOX_MONITOR_DIRS', [ABSPATH]);
}
// 隔离区目录
define('WAF_SANDBOX_QUARANTINE_DIR', WAF_LOG_PATH . '/quarantine');
// 新落地的恶意文件是否秒删除（true=直接删除，false=移入隔离区）
define('WAF_SANDBOX_INSTANT_DELETE_NEW', getenv('WAF_SANDBOX_INSTANT_DELETE_NEW') !== false ? (getenv('WAF_SANDBOX_INSTANT_DELETE_NEW') === 'true') : true);
// 修改的现有文件含恶意代码时是否自动隔离（true=自动隔离待审核，false=仅告警）
define('WAF_SANDBOX_AUTO_QUARANTINE', getenv('WAF_SANDBOX_AUTO_QUARANTINE') !== false ? (getenv('WAF_SANDBOX_AUTO_QUARANTINE') === 'true') : true);
// 沙箱扫描排除目录（PHP 数组，PHP 7.0+ 支持）
if (!defined('WAF_SANDBOX_EXCLUDE_DIRS')) {
    define('WAF_SANDBOX_EXCLUDE_DIRS', [
        WAF_LOG_PATH,               // 日志目录
        '/wp-content/cache/',      // 缓存目录
        '/wp-content/uploads/',    // 上传目录（由 upload.php 单独防护）
    ]);
}
// 恶意代码判定阈值（评分 >= 此值即判定为恶意）
define('WAF_SANDBOX_MALWARE_THRESHOLD', getenv('WAF_SANDBOX_MALWARE_THRESHOLD') !== false ? (int)getenv('WAF_SANDBOX_MALWARE_THRESHOLD') : 50);
// 沙箱白名单路径（这些路径下的文件永不删除/隔离）
if (!defined('WAF_SANDBOX_WHITELIST_PATHS')) {
    define('WAF_SANDBOX_WHITELIST_PATHS', []);
}
// 沙箱↔AutoLearn 联动开关（事件回流 + 特征反哺 + 基线冻结联动）
// true = 启用三个集成点（推荐）
// false = 沙箱与 AutoLearn 完全解耦，互不影响
define('WAF_SANDBOX_LEARN_COUPLING', getenv('WAF_SANDBOX_LEARN_COUPLING') !== false ? (getenv('WAF_SANDBOX_LEARN_COUPLING') === 'true') : true);

// ======================== 上传检测配置 ========================
// 是否启用文件上传检测
define('WAF_UPLOAD_DETECTION', getenv('WAF_UPLOAD_DETECTION') !== false ? (getenv('WAF_UPLOAD_DETECTION') === 'true') : true);
// 允许上传的文件扩展名白名单（PHP 数组）
define('WAF_UPLOAD_ALLOWED_EXT', ['jpg','jpeg','png','gif','webp','bmp','ico','svg']);
// 允许的 MIME 类型（PHP 数组）
define('WAF_UPLOAD_ALLOWED_MIME', [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'image/bmp', 'image/x-icon', 'image/svg+xml',
]);
// 是否使用 GD 库验证图像真实性（比 finfo 更严格，能识别图像马）
define('WAF_UPLOAD_GD_VERIFY', getenv('WAF_UPLOAD_GD_VERIFY') !== false ? (getenv('WAF_UPLOAD_GD_VERIFY') === 'true') : true);
// 是否允许 SVG 上传（SVG 可携带脚本和 XXE，风险较高）
define('WAF_UPLOAD_ALLOW_SVG', getenv('WAF_UPLOAD_ALLOW_SVG') !== false ? (getenv('WAF_UPLOAD_ALLOW_SVG') === 'true') : false);
// 上传文件内容恶意评分阈值（>= 此值直接拦截）
define('WAF_UPLOAD_BLOCK_THRESHOLD', getenv('WAF_UPLOAD_BLOCK_THRESHOLD') !== false ? (int)getenv('WAF_UPLOAD_BLOCK_THRESHOLD') : 60);
// 上传文件内容可疑阈值（>= 此值记录日志，< 此值放行）
define('WAF_UPLOAD_LOG_THRESHOLD', getenv('WAF_UPLOAD_LOG_THRESHOLD') !== false ? (int)getenv('WAF_UPLOAD_LOG_THRESHOLD') : 30);
// 上传文件扫描最大大小（字节），超过此大小只扫描头部和尾部
define('WAF_UPLOAD_SCAN_MAX_SIZE', getenv('WAF_UPLOAD_SCAN_MAX_SIZE') !== false ? (int)getenv('WAF_UPLOAD_SCAN_MAX_SIZE') : 5 * 1024 * 1024);
// 上传检测是否启用累进封禁
define('WAF_UPLOAD_BAN_ON_BLOCK', getenv('WAF_UPLOAD_BAN_ON_BLOCK') !== false ? (getenv('WAF_UPLOAD_BAN_ON_BLOCK') === 'true') : true);

// ======================== 语义引擎配置 ========================
// 语义分析是否启用（关闭后仅使用归一化+评分，防御能力降低）
define('WAF_SEMANTIC_ENGINE', getenv('WAF_SEMANTIC_ENGINE') !== false ? (getenv('WAF_SEMANTIC_ENGINE') === 'true') : true);
define('WAF_SEMANTIC_ENABLED', getenv('WAF_SEMANTIC_ENABLED') !== false ? (getenv('WAF_SEMANTIC_ENABLED') === 'true') : true);
// 语义记忆池是否启用（记录每个IP的语义指纹，跨请求对比分析）
define('WAF_SEMANTIC_MEMORY', getenv('WAF_SEMANTIC_MEMORY') !== false ? (getenv('WAF_SEMANTIC_MEMORY') === 'true') : true);
// 语义记忆池保留时间（小时）
define('WAF_SEMANTIC_MEMORY_TTL', 48);
// 攻击链分析是否启用（关联同一IP多步攻击行为）
define('WAF_ATTACK_CHAIN', getenv('WAF_ATTACK_CHAIN') !== false ? (getenv('WAF_ATTACK_CHAIN') === 'true') : true);
// 攻击链保留时间（小时）
define('WAF_ATTACK_CHAIN_TTL', 24);

// ======================== 主动防御配置 ========================
// 主动防御是否启用（蜜罐+预判拦截+攻击链封堵）
define('WAF_ACTIVE_DEFENSE', getenv('WAF_ACTIVE_DEFENSE') !== false ? (getenv('WAF_ACTIVE_DEFENSE') === 'true') : true);
// 蜜罐是否启用（部署虚假管理后台/phpMyAdmin/Git仓库等）
define('WAF_HONEYTRAP', getenv('WAF_HONEYTRAP') !== false ? (getenv('WAF_HONEYTRAP') === 'true') : true);
// 攻击路径预判是否启用
define('WAF_PATH_PREDICTION', getenv('WAF_PATH_PREDICTION') !== false ? (getenv('WAF_PATH_PREDICTION') === 'true') : true);
// 误报控制是否启用（7层确认机制，确保不误杀正常请求）
define('WAF_FALSE_POSITIVE_GUARD', getenv('WAF_FALSE_POSITIVE_GUARD') !== false ? (getenv('WAF_FALSE_POSITIVE_GUARD') === 'true') : true);

// ======================== 评分系统配置 ========================
// 评分系统是否启用
define('WAF_SCORER_ENABLED', getenv('WAF_SCORER_ENABLED') !== false ? (getenv('WAF_SCORER_ENABLED') === 'true') : true);
// 自动学习是否启用
define('WAF_AUTOLEARN_ENABLED', getenv('WAF_AUTOLEARN_ENABLED') !== false ? (getenv('WAF_AUTOLEARN_ENABLED') === 'true') : true);
// 拦截阈值（总分>=此值拦截）- 与 shield-waf.php 中 $blockThreshold 保持一致
// 注：原默认值 60 与 shield-waf.php 硬编码的 70 不一致，导致 Scorer 拦截后 Detector 未拦截
define('WAF_SCORE_BLOCK', getenv('WAF_SCORE_BLOCK') !== false ? (int)getenv('WAF_SCORE_BLOCK') : 70);
// 监控阈值（总分>=此值记录日志但不拦截）
define('WAF_SCORE_MONITOR', getenv('WAF_SCORE_MONITOR') !== false ? (int)getenv('WAF_SCORE_MONITOR') : 40);
// 语义分析权重（四维评分中语义占比，范围0-100，其余三维度均分剩余）
define('WAF_SEMANTIC_WEIGHT', 30);

// ======================== 性能优化配置 ========================
// APCu 缓存是否启用（优先使用 APCu 共享内存，文件降级兜底）
define('WAF_APCU_ENABLED', getenv('WAF_APCU_ENABLED') !== false ? (getenv('WAF_APCU_ENABLED') === 'true') : function_exists('apcu_enabled') && apcu_enabled());
// 单次检测输入最大长度（字节），超过此值截断扫描，防止 OOM
define('WAF_INPUT_MAX_LENGTH', getenv('WAF_INPUT_MAX_LENGTH') !== false ? (int)getenv('WAF_INPUT_MAX_LENGTH') : 8192);
// CC 防护 APCu TTL（秒）
define('WAF_CC_APCU_TTL', getenv('WAF_CC_APCU_TTL') !== false ? (int)getenv('WAF_CC_APCU_TTL') : 60);
// 恶意文件扫描缓存 TTL（秒）
define('WAF_MALWARE_SCAN_CACHE_TTL', getenv('WAF_MALWARE_SCAN_CACHE_TTL') !== false ? (int)getenv('WAF_MALWARE_SCAN_CACHE_TTL') : 300);
// 大文件流式扫描分块大小（字节）
define('WAF_LARGE_FILE_CHUNK_SIZE', getenv('WAF_LARGE_FILE_CHUNK_SIZE') !== false ? (int)getenv('WAF_LARGE_FILE_CHUNK_SIZE') : 1048576);
// 正则预筛是否启用（正常请求快速跳过）
define('WAF_REGEX_PREFILTER', getenv('WAF_REGEX_PREFILTER') !== false ? (getenv('WAF_REGEX_PREFILTER') === 'true') : true);
// 合并大正则是否启用（减少 preg_match 调用次数）
define('WAF_COMBINED_PATTERN', getenv('WAF_COMBINED_PATTERN') !== false ? (getenv('WAF_COMBINED_PATTERN') === 'true') : true);
// 机器人检测配置
