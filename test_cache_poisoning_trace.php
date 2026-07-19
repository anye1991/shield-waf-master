<?php
error_reporting(E_ERROR | E_PARSE);

$_SERVER["REQUEST_URI"] = "/";
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["REMOTE_ADDR"] = "127.0.0.1";
$_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0";
$_SERVER["HTTP_HOST"] = "localhost";
$_SERVER["HTTP_ACCEPT"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
$_SERVER["HTTP_ACCEPT_LANGUAGE"] = "zh-CN,zh;q=0.9,en;q=0.8";
$_SERVER["HTTP_ACCEPT_ENCODING"] = "gzip, deflate";
$_SERVER["HTTP_CONNECTION"] = "keep-alive";
$_SERVER["HTTP_UPGRADE_INSECURE_REQUESTS"] = "1";
$_SERVER["HTTP_COOKIE"] = "wordpress_logged_in_test=admin%7C123; theme=light; location_pref=US";
$_GET = []; $_POST = []; $_COOKIE = [
    "wordpress_logged_in_test" => "admin|123",
    "theme" => "light",
    "location_pref" => "US",
    "session_token" => "abc123",
];

require_once __DIR__ . "/config.php";
require_once __DIR__ . "/src/Support/Functions.php";

// 替换 waf_block 抓取
function waf_block_override($msg = '') {
    echo "  >>>> waf_block触发: " . $msg . "\n";
    debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
    exit;
}

// 重新定义 waf_block 通过命名空间技巧不可行
// 改用反射或继承方式 - 这里用最直接的：把 CachePoisoning 类复制并修改

// 直接读取 CachePoisoning 文件内容并替换 waf_block 调用
$code = file_get_contents(__DIR__ . "/src/Defense/CachePoisoning.php");
// 替换 waf_block('xxx') 为 echo 'xxx'; return;
$code = preg_replace_callback(
    "/waf_block\('([^']+)'\);/",
    function($m) {
        $msg = $m[1];
        // 替换字符串拼接
        $msg = preg_replace("/' \. \\\$([^ ]+) \. '/", "'{\$$1}'", $msg);
        $msg = preg_replace("/\\\$(\w+) \. '/", "{\$$1}'", $msg);
        $msg = preg_replace("/' \. \\\$(\w+)/", "'{\$$1}", $msg);
        return "throw new Exception(\"CACHE_POISON_BLOCK: $msg\");";
    },
    $code
);
// 移除 defined('ABSPATH') || exit;
$code = str_replace("defined('ABSPATH') || exit;", "", $code);
// 写入临时文件
$tmpFile = __DIR__ . "/test_cache_poisoning_isolated.php";
file_put_contents($tmpFile, $code);
require_once $tmpFile;

try {
    echo "=== 模拟首页/正常请求 ===\n";
    echo "Cookie: " . json_encode($_COOKIE) . "\n\n";

    echo "[step 1] checkCacheBypassHeaders\n";
    // 通过反射调用私有方法
    $class = new ReflectionClass('CachePoisoning');
    $method = $class->getMethod('checkCacheBypassHeaders');
    $method->setAccessible(true);
    $method->invoke(null);
    echo "  passed\n";

    echo "[step 2] checkDangerousHeaderInjection\n";
    $method = $class->getMethod('checkDangerousHeaderInjection');
    $method->setAccessible(true);
    $method->invoke(null);
    echo "  passed\n";

    echo "[step 3] checkPoisoningPatterns\n";
    $method = $class->getMethod('checkPoisoningPatterns');
    $method->setAccessible(true);
    $method->invoke(null);
    echo "  passed\n";

    echo "[step 4] checkVaryHeaderManipulation\n";
    $method = $class->getMethod('checkVaryHeaderManipulation');
    $method->setAccessible(true);
    $method->invoke(null);
    echo "  passed\n";

    echo "[step 5] checkQueryStringPoisoning\n";
    $method = $class->getMethod('checkQueryStringPoisoning');
    $method->setAccessible(true);
    $method->invoke(null);
    echo "  passed\n";

    echo "[step 6] checkHostHeaderPoisoning\n";
    $method = $class->getMethod('checkHostHeaderPoisoning');
    $method->setAccessible(true);
    $method->invoke(null);
    echo "  passed\n";

    echo "\n✅ 全部通过\n";
} catch (Exception $e) {
    echo "\n❌ " . $e->getMessage() . "\n";
}

@unlink($tmpFile);
