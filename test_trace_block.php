<?php
// 首页403拦截点追踪 - 通过 monkey patch waf_block
error_reporting(E_ERROR | E_PARSE);

$_SERVER["REQUEST_URI"] = "/";
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["REMOTE_ADDR"] = "127.0.0.1";
$_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0";
$_SERVER["HTTP_HOST"] = "localhost";
$_SERVER["HTTP_ACCEPT"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
$_SERVER["HTTP_ACCEPT_LANGUAGE"] = "zh-CN,zh;q=0.9,en;q=0.8";
$_SERVER["HTTP_ACCEPT_ENCODING"] = "gzip, deflate";
$_SERVER["SERVER_PROTOCOL"] = "HTTP/1.1";
$_SERVER["SERVER_NAME"] = "localhost";
$_SERVER["SERVER_PORT"] = "80";
$_SERVER["HTTP_CONNECTION"] = "keep-alive";
$_SERVER["HTTP_UPGRADE_INSECURE_REQUESTS"] = "1";
$_GET = []; $_POST = []; $_COOKIE = []; $_REQUEST = [];

define('WAF_TRACE_MODE', true);

require_once __DIR__ . "/config.php";
require_once __DIR__ . "/src/Support/Functions.php";

// monkey patch waf_block - 拦截原始 waf_block
$origBlockFunc = 'waf_block';
$blockLog = [];

// 通过 namespace 技巧重定义 waf_block 不可行，改用 runkit
// 实际做法：手工 trace 每个检查点
$steps = [];

function trace_step($name) {
    global $steps;
    $steps[] = $name;
    echo "[STEP] " . $name . "\n";
}

try {
    trace_step("SecurityHeaders");
    require_once __DIR__ . "/src/Defense/SecurityHeaders.php";
    SecurityHeaders::apply();

    trace_step("WebSocketBlock");
    require_once __DIR__ . "/src/Defense/WebSocketBlock.php";
    WebSocketBlock::deny();

    trace_step("session_start");
    if (session_status() !== PHP_SESSION_ACTIVE) @session_start();

    trace_step("SessionSecurity");
    require_once __DIR__ . "/src/Defense/SessionSecurity.php";
    SessionSecurity::enforce();

    trace_step("CorsPolicy");
    require_once __DIR__ . "/src/Defense/CorsPolicy.php";
    CorsPolicy::init();
    CorsPolicy::check();

    trace_step("IpManager + admin check");
    require_once __DIR__ . "/src/Admin/IpManager.php";
    $is_admin = waf_is_admin_ip();

    trace_step("RateLimit waf_cc_check");
    require_once __DIR__ . "/src/Defense/RateLimit.php";
    $cc_ok = waf_cc_check();

    trace_step("ApiRateLimit");
    require_once __DIR__ . "/src/Defense/ApiRateLimit.php";
    ApiRateLimit::check();

    trace_step("waf_is_banned");
    $banned = waf_is_banned();

    trace_step("CSRF check");
    require_once __DIR__ . "/src/Defense/CsrfProtect.php";
    CsrfProtect::check();

    trace_step("BotManager");
    require_once __DIR__ . "/src/Bot/BotManager.php";
    $botResult = BotManager::check([
        "uri" => "/",
        "ua" => $_SERVER["HTTP_USER_AGENT"],
        "headers" => $_SERVER,
        "ip" => "127.0.0.1",
    ]);
    echo "  BotManager action=" . $botResult["action"] . " reason=" . ($botResult["reason"] ?? "") . "\n";
    if ($botResult["action"] === "block") {
        echo "  >>> BotManager 阻止了请求！\n";
    }

    trace_step("Sandbox init");
    require_once __DIR__ . "/src/Semantic/AdversarialDefense.php";
    require_once __DIR__ . "/src/Core/Detector.php";
    require_once __DIR__ . "/src/Semantic/SemanticEngine.php";
    require_once __DIR__ . "/src/Admin/Sandbox.php";
    WafSandbox::init();

    trace_step("Content-Type校验");
    $contentType = $_SERVER["CONTENT_TYPE"] ?? $_SERVER["HTTP_CONTENT_TYPE"] ?? "";

    trace_step("HPP参数污染");
    // 没有query string

    trace_step("GraphQLDefender");
    require_once __DIR__ . "/src/Defense/GraphQLDefender.php";
    GraphQLDefender::check();

    trace_step("SsrfDefender");
    require_once __DIR__ . "/src/Defense/SsrfDefender.php";
    SsrfDefender::check();

    trace_step("NoSqlInjection");
    require_once __DIR__ . "/src/Defense/NoSqlInjection.php";
    NoSqlInjection::check();

    trace_step("RequestSmuggling");
    require_once __DIR__ . "/src/Defense/RequestSmuggling.php";
    RequestSmuggling::check();

    trace_step("JwtSecurity");
    require_once __DIR__ . "/src/Defense/JwtSecurity.php";
    JwtSecurity::check();

    trace_step("TemplateInjection");
    require_once __DIR__ . "/src/Defense/TemplateInjection.php";
    TemplateInjection::check();

    trace_step("ApiSecurity");
    require_once __DIR__ . "/src/Defense/ApiSecurity.php";
    ApiSecurity::check();

    trace_step("CrlfInjection");
    require_once __DIR__ . "/src/Defense/CrlfInjection.php";
    CrlfInjection::check();

    trace_step("CachePoisoning");
    require_once __DIR__ . "/src/Defense/CachePoisoning.php";
    CachePoisoning::check();

    trace_step("LdapInjection");
    require_once __DIR__ . "/src/Defense/LdapInjection.php";
    require_once __DIR__ . "/src/Defense/XPathInjection.php";
    require_once __DIR__ . "/src/Defense/XxeInjection.php";
    require_once __DIR__ . "/src/Defense/Deserialization.php";
    require_once __DIR__ . "/src/Defense/FileInclusion.php";
    require_once __DIR__ . "/src/Defense/SessionFixation.php";
    require_once __DIR__ . "/src/Defense/SessionHijack.php";
    require_once __DIR__ . "/src/Defense/OpenRedirect.php";
    require_once __DIR__ . "/src/Defense/IdorDetection.php";
    require_once __DIR__ . "/src/Defense/RaceCondition.php";

    $waf_inputs = array_merge($_GET, $_POST, $_COOKIE);

    $ldapResult = LdapInjection::detect($waf_inputs);
    echo "  LDAP detected: " . ($ldapResult["detected"] ? "YES" : "no") . "\n";
    if ($ldapResult["detected"]) throw new Exception("LDAP block");

    $xpathResult = XPathInjection::detect($waf_inputs);
    echo "  XPath detected: " . ($xpathResult["detected"] ? "YES" : "no") . "\n";

    $xxeResult = XxeInjection::detect(WAF_RAW_BODY, $waf_inputs);
    echo "  XXE detected: " . ($xxeResult["detected"] ? "YES" : "no") . "\n";

    $deserResult = Deserialization::detect($waf_inputs, WAF_RAW_BODY);
    echo "  Deserialization detected: " . ($deserResult["detected"] ? "YES" : "no") . "\n";

    $fiResult = FileInclusion::detect($waf_inputs);
    echo "  FileInclusion detected: " . ($fiResult["detected"] ? "YES" : "no") . "\n";

    echo "\n✅ 所有检查点通过 - 无任何拦截\n";

} catch (Exception $e) {
    echo "\n❌ 异常: " . $e->getMessage() . "\n";
    echo "Trace: " . implode(" -> ", $steps) . "\n";
} catch (Error $e) {
    echo "\n❌ 致命错误: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . ":" . $e->getLine() . "\n";
    echo "Trace: " . implode(" -> ", $steps) . "\n";
}
