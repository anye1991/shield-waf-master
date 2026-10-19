<?php
/**
 * CLI 测试脚本：单独跑 RobinsonFisher 和 FingerprintMatcher
 * 用法：php test_engines.php
 */
define('ABSPATH', '/tmp/');
if (!defined('WAF_LOG_PATH')) {
    define('WAF_LOG_PATH', dirname(__DIR__, 2) . '/logs');
}

require_once __DIR__ . '/NaiveBayesClassifier.php';
require_once __DIR__ . '/Storage.php';
require_once __DIR__ . '/RobinsonFisher.php';
require_once __DIR__ . '/FingerprintMatcher.php';

// ====================== 测试样本 ======================
$attackSamples = [
    // SQL 注入
    "1' OR '1'='1",
    "1 UNION SELECT NULL,NULL--",
    "admin'--",
    "1' AND SLEEP(5)--",
    "' OR 1=1#",
    "1; DROP TABLE users--",
    "1' UNION SELECT username,password FROM users--",
    "1 AND 1=1",
    "1' OR 'x'='x",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    // XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    // 路径遍历
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "/etc/shadow",
    "....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    // 命令注入
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(uname -a)",
    "& ping -c 10 127.0.0.1",
    "; rm -rf /",
    // 代码执行
    "eval($_POST['cmd'])",
    "assert($_GET['x'])",
    "system('id')",
    "passthru('ls')",
    "shell_exec('whoami')",
    "preg_replace('/.*/e', 'phpinfo()', '')",
    // SSTI
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config.items()}}",
    // SSRF
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/admin",
    "http://127.0.0.1:6379/",
    "gopher://127.0.0.1:6379/_test",
    // XXE
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    // 反序列化
    "O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}",
    // 混淆
    "base64_decode('cGhwaW5mbygp')",
    "gzinflate(base64_decode('...'))",
    "str_rot13('nopny')",
    // 混合
    "1' UNION SELECT '<script>alert(1)</script>'--",
    "../../etc/passwd%00.jpg",
    "'; system('id'); //",
    // 更多变体
    "1%27%20OR%201%3D1--",
    "<SCRIPT>alert(1)</SCRIPT>",
    "1 UnIoN sElEcT NULL--",
];

$normalSamples = [
    "index.php?id=123",
    "search?q=hello+world",
    "user/profile?name=john",
    "api/v1/users?page=2&limit=10",
    "product?category=electronics&sort=price",
    "login?redirect=/dashboard",
    "article?slug=how-to-code",
    "cart?add=1001&qty=2",
    "blog?tag=php&page=1",
    "contact?subject=hello&message=world",
];

// ====================== 跑测试 ======================
echo "===== Robinson-Fisher 测试 =====\n\n";
$rfAttackHit = 0;
$rfNormalHit = 0;
$rfThreshold = 50; // RF score >= 50 视为攻击

echo "-- 攻击样本（RF score >= {$rfThreshold} 视为检出）--\n";
foreach ($attackSamples as $i => $s) {
    $r = Learning_RobinsonFisher::classify($s);
    $hit = ($r['score'] >= $rfThreshold);
    if ($hit) $rfAttackHit++;
    printf("[%02d] %-50s score=%.1f extreme=%d %s\n",
        $i + 1,
        mb_substr($s, 0, 50, 'UTF-8'),
        $r['score'],
        $r['extreme_count'],
        $hit ? 'HIT' : 'MISS'
    );
}

echo "\n-- 正常样本（RF score >= {$rfThreshold} 视为误报）--\n";
foreach ($normalSamples as $i => $s) {
    $r = Learning_RobinsonFisher::classify($s);
    $hit = ($r['score'] >= $rfThreshold);
    if (!$hit) $rfNormalHit++;
    printf("[%02d] %-50s score=%.1f extreme=%d %s\n",
        $i + 1,
        mb_substr($s, 0, 50, 'UTF-8'),
        $r['score'],
        $r['extreme_count'],
        $hit ? 'FP' : 'OK'
    );
}

printf("\nRF 攻击检出：%d/%d\n", $rfAttackHit, count($attackSamples));
printf("RF 正常不误报：%d/%d\n", $rfNormalHit, count($normalSamples));

// ====================== 指纹测试 ======================
echo "\n===== FingerprintMatcher 测试 =====\n\n";

// 先把所有攻击样本入库（模拟"已确认攻击"）
foreach ($attackSamples as $s) {
    Learning_FingerprintMatcher::addFingerprint($s, ['attack_type' => 'test']);
}

$fpAttackHit = 0;
$fpNormalHit = 0;

echo "-- 攻击样本（matched=true 视为检出）--\n";
foreach ($attackSamples as $i => $s) {
    $r = Learning_FingerprintMatcher::match($s);
    if ($r['matched']) $fpAttackHit++;
    printf("[%02d] %-50s sim=%.4f %s\n",
        $i + 1,
        mb_substr($s, 0, 50, 'UTF-8'),
        $r['similarity'],
        $r['matched'] ? 'HIT' : 'MISS'
    );
}

echo "\n-- 正常样本（matched=true 视为误报）--\n";
foreach ($normalSamples as $i => $s) {
    $r = Learning_FingerprintMatcher::match($s);
    if (!$r['matched']) $fpNormalHit++;
    printf("[%02d] %-50s sim=%.4f %s\n",
        $i + 1,
        mb_substr($s, 0, 50, 'UTF-8'),
        $r['similarity'],
        $r['matched'] ? 'FP' : 'OK'
    );
}

printf("\n指纹攻击检出：%d/%d\n", $fpAttackHit, count($attackSamples));
printf("指纹正常不误报：%d/%d\n", $fpNormalHit, count($normalSamples));

echo "\n===== 完成 =====\n";