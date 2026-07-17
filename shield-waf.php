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
defined('ABSPATH') || exit;

// ====================== 配置与函数 ======================
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Support/Functions.php';

// ====================== 安全响应头 ======================
require_once __DIR__ . '/src/Defense/SecurityHeaders.php';
SecurityHeaders::apply();

// ====================== 会话安全（必须在 session_start 前） ======================
require_once __DIR__ . '/src/Defense/SessionSecurity.php';
SessionSecurity::enforce();

// ====================== WebSocket 阻断 ======================
require_once __DIR__ . '/src/Defense/WebSocketBlock.php';
WebSocketBlock::deny();

// ====================== 启动会话 ======================
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

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
$botResult = BotManager::check([
    'uri'     => $_SERVER['REQUEST_URI'] ?? '/',
    'ua'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'headers' => $_SERVER,
    'ip'      => waf_get_real_ip(),
]);

// 已验证的搜索引擎蜘蛛：bot层面直接放行，攻击检测层面提升阈值（防误拦）
$isVerifiedSearchEngine = false;
if (($botResult['category'] ?? '') === 'search_engine' && ($botResult['confidence'] ?? 0) >= 90) {
    $isVerifiedSearchEngine = true;
}

if ($botResult['action'] === 'block') {
    waf_block('Malicious bot detected - ' . ($botResult['reason'] ?? ''));
}

// ====================== 虚拟沙箱初始化 ======================
// 沙箱依赖：归一化引擎、检测器、语义引擎
require_once __DIR__ . '/src/Core/Normalizer.php';
WafNormalizer::init();
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
        $body = WafNormalizer::normalizeJson($body);
    } elseif ($type_clean === 'application/xml' || $type_clean === 'text/xml') {
        $body = WafNormalizer::normalizeXml($body);
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

// ====================== 收集其他输入源并全局归一化 ======================
$post = !empty($_POST) ? http_build_query($_POST) : '';
$headers = '';
foreach (['HTTP_USER_AGENT','HTTP_REFERER','HTTP_X_FORWARDED_FOR','HTTP_ACCEPT_LANGUAGE'] as $h) {
    if (!empty($_SERVER[$h])) {
        $headers .= $_SERVER[$h] . ' ';
    }
}
$cookie = !empty($_COOKIE) ? http_build_query($_COOKIE) : '';

$normResult = WafNormalizer::normalizeWithContext("$uri $body $post $headers $cookie");
$all = $normResult['output'];

// ====================== 攻击检测（L14语义上下文评分系统 + 自动学习 + 智能评分） ======================
$attackResult = waf_analyze_attack($all, $normResult);

// 智能评分系统（四维：熵值+语义+结构偏差+偏离分析）
require_once __DIR__ . '/src/Core/Scorer.php';
$scorerResult = WafScorer::score($all, $uri, $_GET, $normResult);

// 综合判断：规则检测或智能评分任一达到拦截阈值即拦截
// 已验证搜索引擎：提升阈值到95，确保正常爬取不误拦（但真带攻击载荷仍会拦）
$blockThreshold = 60;
$scorerIsAttack = $scorerResult['is_attack'];
$detectorIsAttack = $attackResult['is_attack'];

if ($isVerifiedSearchEngine) {
    $blockThreshold = 95;
    $scorerIsAttack = ($scorerResult['total_score'] >= $blockThreshold);
    $detectorIsAttack = ($attackResult['total_score'] >= $blockThreshold);
}

if ($detectorIsAttack || $scorerIsAttack) {
    // 记录攻击到自动学习系统
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

// ====================== 登录页暴力破解防护（固定文件，无跨小时边界问题） ======================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($requestPath, 'wp-login.php') !== false) {
    $login_ip = waf_get_real_ip();
    $login_file = WAF_LOG_PATH . 'login_attempt.txt';
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
    if (!empty($_COOKIE)) {
        foreach ($_COOKIE as $name => $val) {
            if (strpos($name, 'wordpress_logged_in_') === 0) {
                $logged_in = true;
                break;
            }
        }
    }
    if ($logged_in) {
        return;
    }

    // 未登录 → 暗门验证
    $magic = $_GET['magic'] ?? '';
    if (!empty($magic)) {
        if ($magic === WAF_MAGIC_KEY) {
            $_SESSION['waf_ok1'] = time() + WAF_MAGIC_EXPIRE;
            $_SESSION['waf_ip']  = waf_get_real_ip();
            $redirect = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://');
            $redirect .= $_SERVER['HTTP_HOST'] . '/wp-admin/?w=1';
            header('Location: ' . $redirect);
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
        if (empty($_SESSION['waf_ok2'])) {
            waf_2fa();
        }
    }

    $final = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time()
             && $_SESSION['waf_ip'] === waf_get_real_ip()
             && isset($_SESSION['waf_ok2']);
    if (!$final) {
        waf_block('Access denied');
    }
}
