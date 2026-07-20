<?php
/**
 * 盾甲 WAF 主入口（最终安全版）
 * 改动：
 *  - 白名单 IP 仅跳过速率限制，不跳过暗门
 *  - 暗门仅保护 wp-admin，允许登录页正常访问
 *  - 已登录 WordPress 的用户直接放行 wp-admin
 *  - 重定向改为绝对路径
 *  - 新增 wp-login.php POST 频率限制（防暴力破解，固定文件）
 *  - 常量重命名为 WAF_SKIP_RATELIMIT
 *  - v3.0.0 架构重组：所有模块归入 src/{Core,Semantic,Bot,Learn,Defense,Admin,Support}
 */
// 兼容非 WordPress 环境：未定义 ABSPATH 时自动定义为本文件所在目录
if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__FILE__) . '/');
}

// ====================== PHP 版本检查（v4.1.1 定格 PHP 7.4+） ======================
if (PHP_VERSION_ID < 70400) {
    http_response_code(500);
    header('Content-Type: text/html; charset=utf-8');
    die('<!DOCTYPE html><html><head><meta charset="utf-8"><title>PHP 版本不兼容</title></head>'
        . '<body style="font-family:sans-serif;padding:40px;max-width:720px;margin:auto;color:#333">'
        . '<h2 style="color:#c00">🛡️ 盾甲 WAF：PHP 版本不兼容</h2>'
        . '<p>当前 PHP 版本：<b>' . PHP_VERSION . '</b></p>'
        . '<p>盾甲 WAF v4.1.1 最低要求 <b>PHP 7.4</b>。</p>'
        . '<p>请升级 PHP 到 7.4 或更高版本（推荐 8.x）。</p>'
        . '<hr><p style="color:#999;font-size:12px">暗夜铭少 · Shield WAF v4.1.1</p>'
        . '</body></html>');
}

// ====================== 日志目录自动权限 + /tmp 降级（无需手动 chown） ======================
$wafLogDir = __DIR__ . '/logs';
if (!is_dir($wafLogDir)) {
    @mkdir($wafLogDir, 0777, true);
}
if (is_dir($wafLogDir) && !is_writable($wafLogDir)) {
    @chmod($wafLogDir, 0777);
}
// 仍不可写时预定义 WAF_LOG_PATH 为 /tmp（config.php 中会跳过重复定义）
if (!is_writable($wafLogDir)) {
    $fallback = '/tmp/shield_waf_logs';
    if (!is_dir($fallback)) {
        @mkdir($fallback, 0777, true);
    }
    if (is_dir($fallback) && is_writable($fallback)) {
        define('WAF_LOG_PATH', $fallback);
        error_log(sprintf('[ShieldWAF] 日志目录 %s 不可写，已自动降级到 %s', $wafLogDir, $fallback));
    }
}

// ====================== 配置与函数 ======================
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Support/Functions.php';

// ====================== 静态资源请求快速放行（避免图片/CSS/JS 被 WAF 误拦截） ======================
function waf_is_static_request() {
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($uri, PHP_URL_PATH) ?: '/';
    $staticExts = ['.jpg','.jpeg','.png','.gif','.webp','.svg','.ico','.avif','.apng',
                   '.css','.js','.woff','.woff2','.ttf','.eot','.otf',
                   '.mp3','.mp4','.webm','.pdf','.zip','.map'];
    $lower = strtolower($path);
    foreach ($staticExts as $ext) {
        if (substr($lower, -strlen($ext)) === $ext) return true;
    }
    // WordPress 图片 resize 路径（如 /wp-content/uploads/2024/01/image-300x200.jpg）
    if (strpos($lower, '/wp-content/uploads/') !== false) return true;
    return false;
}

// ====================== 登录页面白名单（多用户网站前台登录不拦截） ======================
function waf_is_login_page() {
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    $lower = strtolower($path);

    // WordPress 默认登录页
    if (strpos($lower, 'wp-login.php') !== false) return true;
    if (strpos($lower, 'wp-login') !== false) return true;

    // 常见前台登录路径（多用户网站）
    $loginPaths = ['/login', '/sign-in', '/signin', '/my-account', '/account',
                   '/member/login', '/user/login', '/auth/login', '/customer/login',
                   '/members/login', '/users/login', '/user/signin'];
    foreach ($loginPaths as $loginPath) {
        if ($lower === $loginPath || strpos($lower, $loginPath . '/') === 0) return true;
    }

    // WooCommerce My Account
    if (strpos($lower, '/my-account') !== false) return true;

    // BuddyPress / BuddyBoss
    if (strpos($lower, '/members/') !== false && strpos($lower, 'login') !== false) return true;

    // Ultimate Member
    if (strpos($lower, '/account') !== false) return true;

    return false;
}

// ====================== 一次性读取原始请求体（限制大小防OOM） ======================
if (!defined('WAF_RAW_BODY')) {
    $maxBody = defined('WAF_MAX_BODY_SIZE') ? WAF_MAX_BODY_SIZE : 1048576;
    define('WAF_RAW_BODY', file_get_contents('php://input', false, null, 0, $maxBody) ?: '');
}

// ====================== 安全响应头 ======================
require_once __DIR__ . '/src/Defense/SecurityHeaders.php';
SecurityHeaders::apply();

// 静态资源：已应用安全响应头，直接放行，不做任何 WAF 检测
if (waf_is_static_request()) {
    return;
}

// ====================== 登录页面检测 ======================
$isLoginPage = waf_is_login_page();

// ====================== WebSocket 阻断 ======================
require_once __DIR__ . '/src/Defense/WebSocketBlock.php';
WebSocketBlock::deny();

// ====================== 启动会话 ======================
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// ====================== 会话安全（必须在 session_start 后） ======================
require_once __DIR__ . '/src/Defense/SessionSecurity.php';
SessionSecurity::enforce();

// ====================== CORS 策略 ======================
require_once __DIR__ . '/src/Defense/CorsPolicy.php';
CorsPolicy::init();
CorsPolicy::check();

// ====================== IP 白名单处理 ======================
require_once __DIR__ . '/src/Admin/IpManager.php';
if (waf_is_admin_ip()) {
    if (rand(1, 100) === 1) waf_clean_admin_ips();
    define('WAF_SKIP_RATELIMIT', true);
    // 注意：不 return，继续执行后续安全检测（注入、上传等）
}

// 随机清理过期 ban 记录
if (rand(1, 100) === 1) waf_clean_ban_file();

// ====================== 速率限制 ======================
require_once __DIR__ . '/src/Defense/RateLimit.php';
if (!waf_cc_check()) {
    waf_block('请求过于频繁，请稍后再试');
}

require_once __DIR__ . '/src/Defense/ApiRateLimit.php';
ApiRateLimit::check();

// ====================== IP 封禁检查 ======================
if (waf_is_banned()) {
    waf_block('Banned IP');
}

// ====================== 请求方法限制 ======================
$allowed_methods = ['GET', 'POST', 'HEAD'];
if (!in_array($_SERVER['REQUEST_METHOD'], $allowed_methods)) {
    waf_block('不允许的请求方法: ' . $_SERVER['REQUEST_METHOD']);
}

// ====================== CSRF 防护 ======================
require_once __DIR__ . '/src/Defense/CsrfProtect.php';
CsrfProtect::check();

// ====================== 机器人检测 ======================
require_once __DIR__ . '/src/Bot/BotManager.php';
// 注：原代码把整个 $_SERVER 当 headers 传给 BotManager，
// 导致环境变量(如 PATH/HTTP_PROXY等)也被当成 header 参与 Bot 指纹分析，触发误判。
// 修复：只提取 HTTP_ 开头的请求头 + Content-Type/Content-Length。
$_waf_http_headers = [];
foreach ($_SERVER as $_waf_k => $_waf_v) {
    if (strpos($_waf_k, 'HTTP_') === 0) {
        $_waf_name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($_waf_k, 5)))));
        $_waf_http_headers[$_waf_name] = $_waf_v;
    } elseif ($_waf_k === 'CONTENT_TYPE') {
        $_waf_http_headers['Content-Type'] = $_waf_v;
    } elseif ($_waf_k === 'CONTENT_LENGTH') {
        $_waf_http_headers['Content-Length'] = $_waf_v;
    }
}
$botResult = BotManager::check([
    'uri'     => $_SERVER['REQUEST_URI'] ?? '/',
    'ua'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'headers' => $_waf_http_headers,
    'ip'      => waf_get_real_ip(),
]);
unset($_waf_http_headers, $_waf_k, $_waf_v, $_waf_name);

// 已验证的搜索引擎蜘蛛：bot层面直接放行，攻击检测层面提升阈值（防误拦）
$isVerifiedSearchEngine = false;
if (($botResult['category'] ?? '') === 'search_engine' && ($botResult['confidence'] ?? 0) >= 90) {
    $isVerifiedSearchEngine = true;
}

if ($botResult['action'] === 'block') {
    waf_block('Malicious bot detected - ' . ($botResult['reason'] ?? ''));
}

// ====================== 虚拟沙箱初始化 ======================
// 沙箱依赖：归一化引擎（AdversarialDefense 14层解码）、检测器、语义引擎
require_once __DIR__ . '/src/Semantic/AdversarialDefense.php';
require_once __DIR__ . '/src/Core/Detector.php';
require_once __DIR__ . '/src/Semantic/SemanticEngine.php';
require_once __DIR__ . '/src/Admin/Sandbox.php';
WafSandbox::init();

// ====================== 输入采集与分块解码 ======================
require_once __DIR__ . '/src/Defense/Chunked.php';
$uri  = $_SERVER['REQUEST_URI'] ?? '/';
$body = waf_decode_chunked_body();

// ====================== Content-Type 校验 + 上下文归一化 ======================
$contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
if (!empty($body) && !empty($contentType)) {
    $type_clean = strtolower(trim(explode(';', $contentType)[0]));
    $valid_types = [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'application/json',
        'application/xml',
        'text/xml',
        '',
    ];
    if (!in_array($type_clean, $valid_types)) {
        waf_block('不允许的 Content-Type: ' . $type_clean);
    }

    if ($type_clean === 'application/json') {
        $body = AdversarialDefense::normalizeJson($body);
    } elseif ($type_clean === 'application/xml' || $type_clean === 'text/xml') {
        $body = AdversarialDefense::normalizeXml($body);
    }
}

// ====================== HTTP 参数污染检测 ======================
if (!empty($_SERVER['QUERY_STRING'])) {
    parse_str($_SERVER['QUERY_STRING'], $query_params);
    $seen = [];
    foreach (explode('&', $_SERVER['QUERY_STRING']) as $pair) {
        if (strpos($pair, '=') === false) continue;
        list($key, $val) = explode('=', $pair, 2);
        if (isset($seen[$key])) {
            waf_block('检测到参数污染: ' . $key);
        }
        $seen[$key] = 1;
    }
}

// ====================== GraphQL 注入检测 ======================
require_once __DIR__ . '/src/Defense/GraphQLDefender.php';
GraphQLDefender::check();

// ====================== 高级防护模块 ======================
require_once __DIR__ . '/src/Defense/SsrfDefender.php';
SsrfDefender::check();

require_once __DIR__ . '/src/Defense/NoSqlInjection.php';
NoSqlInjection::check();

require_once __DIR__ . '/src/Defense/RequestSmuggling.php';
RequestSmuggling::check();

require_once __DIR__ . '/src/Defense/JwtSecurity.php';
JwtSecurity::check();

require_once __DIR__ . '/src/Defense/TemplateInjection.php';
TemplateInjection::check();

require_once __DIR__ . '/src/Defense/ApiSecurity.php';
ApiSecurity::check();

require_once __DIR__ . '/src/Defense/CrlfInjection.php';
CrlfInjection::check();

require_once __DIR__ . '/src/Defense/CachePoisoning.php';
CachePoisoning::check();

require_once __DIR__ . '/src/Defense/LdapInjection.php';
require_once __DIR__ . '/src/Defense/XPathInjection.php';
require_once __DIR__ . '/src/Defense/XxeInjection.php';
require_once __DIR__ . '/src/Defense/Deserialization.php';
require_once __DIR__ . '/src/Defense/FileInclusion.php';
require_once __DIR__ . '/src/Defense/SessionFixation.php';
require_once __DIR__ . '/src/Defense/SessionHijack.php';
require_once __DIR__ . '/src/Defense/OpenRedirect.php';
require_once __DIR__ . '/src/Defense/IdorDetection.php';
require_once __DIR__ . '/src/Defense/RaceCondition.php';

$waf_inputs = array_merge($_GET, $_POST, $_COOKIE);

$ldapResult = LdapInjection::detect($waf_inputs);
if ($ldapResult['detected']) {
    waf_block('LDAP Injection attack detected - ' . json_encode($ldapResult['details']));
}

$xpathResult = XPathInjection::detect($waf_inputs);
if ($xpathResult['detected']) {
    waf_block('XPath Injection attack detected - ' . json_encode($xpathResult['details']));
}

$xxeResult = XxeInjection::detect(WAF_RAW_BODY, $waf_inputs);
if ($xxeResult['detected']) {
    waf_block('XXE Injection attack detected - ' . json_encode($xxeResult['details']));
}

$deserResult = Deserialization::detect($waf_inputs, WAF_RAW_BODY);
if ($deserResult['detected']) {
    waf_block('Deserialization attack detected - ' . json_encode($deserResult['details']));
}

$fiResult = FileInclusion::detect($waf_inputs);
if ($fiResult['detected']) {
    waf_block('File Inclusion attack detected - ' . json_encode($fiResult['details']));
}

$sfResult = SessionFixation::detect();
if ($sfResult['detected']) {
    waf_block('Session Fixation attack detected - ' . json_encode($sfResult['details']));
}

$shResult = SessionHijack::detect();
if ($shResult['detected']) {
    waf_block('Session Hijacking attack detected - ' . json_encode($shResult['details']));
}

$orResult = OpenRedirect::detect($waf_inputs);
// 登录页面的 redirect_to 参数不拦截（多用户网站正常跳转）
if ($orResult['detected'] && !$isLoginPage) {
    waf_block('Open Redirect attack detected - ' . json_encode($orResult['details']));
}

$idorResult = IdorDetection::detect($waf_inputs);
if ($idorResult['detected']) {
    waf_block('IDOR attack detected - ' . json_encode($idorResult['details']));
}

$rcResult = RaceCondition::detect();
if ($rcResult['detected']) {
    waf_block('Race Condition attack detected - ' . json_encode($rcResult['details']));
}

// ====================== 收集其他输入源并全局归一化 ======================
$post = !empty($_POST) ? http_build_query($_POST) : '';
$headers = '';
foreach (['HTTP_USER_AGENT','HTTP_REFERER','HTTP_X_FORWARDED_FOR','HTTP_ACCEPT_LANGUAGE'] as $h) {
    if (!empty($_SERVER[$h])) {
        $headers .= $_SERVER[$h] . ' ';
    }
}
$cookie = !empty($_COOKIE) ? http_build_query($_COOKIE) : '';

$normResult = AdversarialDefense::normalizeWithContext("$uri $body $post $headers $cookie");
$all = $normResult['output'];

// ====================== 攻击检测（L14语义上下文评分系统 + 自动学习 + 智能评分） ======================
$attackResult = waf_analyze_attack($all, $normResult);

// 智能评分系统（四维：熵值+语义+结构偏差+偏离分析）
require_once __DIR__ . '/src/Core/Scorer.php';
$scorerResult = WafScorer::score($all, $uri, $_GET, $normResult, waf_get_real_ip());

// 综合判断：规则检测或智能评分任一达到拦截阈值即拦截
// 已验证搜索引擎：提升阈值到95，确保正常爬取不误拦（但真带攻击载荷仍会拦）
// 注：detector 阈值统一为 70，与 Scorer 保持一致，避免 60 分误拦截正常请求
$blockThreshold = 70;
$scorerIsAttack = $scorerResult['is_attack'];
$detectorIsAttack = $attackResult['is_attack'];

if ($isVerifiedSearchEngine) {
    $blockThreshold = 95;
    $scorerIsAttack = ($scorerResult['total_score'] >= $blockThreshold);
    $detectorIsAttack = ($attackResult['total_score'] >= $blockThreshold);
}

if ($detectorIsAttack || $scorerIsAttack) {
    // 登录页面：只记录日志，不拦截（多用户网站前台登录必须正常）
    // 但极端高危攻击（score >= 95）仍然拦截，防止登录页被利用
    $maxScore = max($attackResult['total_score'], $scorerResult['total_score']);
    if ($isLoginPage && $maxScore < 95) {
        // 记录但不拦截
        $logMsg = sprintf('[LOGIN_PAGE_ALLOW] %s | score=%.1f | uri=%s',
            date('Y-m-d H:i:s'), $maxScore, $uri);
        error_log('[ShieldWAF] ' . $logMsg);
    } else {
        // 非登录页面或高危攻击：正常拦截
        AutoLearn::recordAttack($all, $attackResult);
        waf_smart_ban(waf_get_real_ip());
        $riskInfo = sprintf(
            'Risk: %s (%.1f%%, depth=%d, hits=%d, learned=%d%s | Scorer: %.1f [E=%.0f S=%.0f C=%.0f D=%.0f])%s',
            $attackResult['risk_level'],
            $attackResult['total_score'],
            $attackResult['encoding_depth'],
            $attackResult['hit_count'],
            $attackResult['learned_hits'],
            !empty($attackResult['double_encoding']) ? ', dbl_enc=1' : '',
            $scorerResult['total_score'],
            $scorerResult['entropy_score'],
            $scorerResult['semantic_score'],
            $scorerResult['compiler_score'],
            $scorerResult['deviation_score'],
            $isVerifiedSearchEngine ? ' | SE_THRESHOLD=' . $blockThreshold : ''
        );
        waf_block('Attack detected - ' . $riskInfo);
    }
}

// 记录正常请求模式到自适应学习系统
AutoLearn::recordNormal($uri, array_keys($_GET + $_POST));

// ====================== 文件上传检测 ======================
require_once __DIR__ . '/src/Defense/Upload.php';
waf_check_upload();

// ====================== 路由处理（仪表盘、扫描 API） ======================
$requestPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($requestPath === '/waf-dashboard-api') {
    require_once __DIR__ . '/src/Admin/DashboardApi.php';
    exit;
}
if ($requestPath === '/waf-dashboard') {
    require_once __DIR__ . '/src/Admin/Dashboard.php';
    exit;
}
if ($requestPath === '/waf-scanner-api') {
    require_once __DIR__ . '/src/Admin/ScannerApi.php';
    exit;
}
if ($requestPath === '/waf-dashboard-bot') {
    require_once __DIR__ . '/src/Admin/DashboardBot.php';
    exit;
}
if ($requestPath === '/waf-sandbox-api') {
    require_once __DIR__ . '/src/Admin/SandboxApi.php';
    exit;
}
if ($requestPath === '/waf-password-api') {
    require_once __DIR__ . '/src/Admin/PasswordApi.php';
    exit;
}

// ====================== 登录页暴力破解防护（固定文件，无跨小时边界问题） ======================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($requestPath, 'wp-login.php') !== false) {
    $login_ip = waf_get_real_ip();
    $login_file = WAF_LOG_PATH . '/login_attempt.txt';
    $now = time();
    $window = 300; // 5 分钟窗口
    $limit = 10;   // 最多 10 次 POST 尝试
    $lines = is_file($login_file) ? file($login_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $valid = [];
    $count = 0;
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        if (count($parts) !== 2) continue;
        $ts = (int)$parts[0];
        $ip = $parts[1];
        if ($ts > $now - $window) {
            if ($ip === $login_ip) $count++;
            $valid[] = $line;
        }
    }
    if ($count >= $limit) {
        waf_smart_ban($login_ip);
        waf_block('登录尝试过于频繁');
    }
    $valid[] = "$now|$login_ip";
    @file_put_contents($login_file, implode("\n", $valid) . "\n", LOCK_EX);
}

// ====================== 输出过滤 ======================
require_once __DIR__ . '/src/Defense/OutputFilter.php';
waf_output_filter_start();

// ====================== 后台暗门 ======================
require_once __DIR__ . '/src/Admin/DarkGate.php';

$is_admin = (strpos($requestPath, 'wp-admin') !== false);

if ($is_admin) {
    // 如果用户已经通过 WordPress 登录，直接放行
    $logged_in = false;

    // 优先使用 WordPress 原生函数判断（最可靠）
    if (function_exists('is_user_logged_in')) {
        $logged_in = is_user_logged_in();
    } elseif (!empty($_COOKIE)) {
        // 回退方案：手动验证 WordPress 登录 Cookie 的格式和有效性
        foreach ($_COOKIE as $name => $val) {
            if (strpos($name, 'wordpress_logged_in_') === 0) {
                // Cookie 值格式：username|expiration|hmac_hash
                $parts = explode('|', $val);
                if (count($parts) === 3) {
                    list($username, $expiration, $hash) = $parts;
                    // 基本格式校验：用户名非空、过期时间是有效数字、哈希是 32+ 位十六进制
                    if (!empty($username) && !empty($hash) &&
                        is_numeric($expiration) && $expiration > time() &&
                        preg_match('/^[a-f0-9]{32,}$/i', $hash)) {
                        $logged_in = true;
                        break;
                    }
                }
            }
        }
    }

    if ($logged_in) {
        return;
    }

    // 未登录 → 暗门验证
    $magic = $_GET['magic'] ?? '';
    if (!empty($magic)) {
        if (hash_equals(WAF_MAGIC_KEY, $magic)) {
            $_SESSION['waf_ok1'] = time() + WAF_MAGIC_EXPIRE;
            $_SESSION['waf_ip']  = waf_get_real_ip();
            // 安全重定向：用 SERVER_NAME 而非 HTTP_HOST 防止开放重定向
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https://' : 'http://';
            $host = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'];
            if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $host)) {
                $host = 'localhost';
            }
            header('Location: ' . $scheme . $host . '/wp-admin/?w=1');
            exit;
        } else {
            waf_attempt_inc('magic');
            if (waf_attempt_get('magic') >= WAF_MAGIC_MAX_RETRY) {
                waf_smart_ban(waf_get_real_ip());
            }
            waf_block('Invalid magic key');
        }
    }

    if (isset($_GET['w'])) {
        $ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time()
               && $_SESSION['waf_ip'] === waf_get_real_ip();
        if (!$ok1) {
            waf_block('1st factor expired or IP mismatch');
        }
        $ok2_valid = isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
        if (!$ok2_valid) {
            waf_2fa();
        }
    }

    $final = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time()
             && $_SESSION['waf_ip'] === waf_get_real_ip()
             && isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
    if (!$final) {
        waf_block('Access denied');
    }
}
