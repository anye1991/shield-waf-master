<?php
define('ABSPATH', '/tmp/');
define('WAF_LOG_PATH', dirname(__DIR__, 2) . '/logs');

require_once __DIR__ . '/NaiveBayesClassifier.php';
require_once __DIR__ . '/Storage.php';
require_once __DIR__ . '/RobinsonFisher.php';
require_once __DIR__ . '/FingerprintMatcher.php';

$attackSamples = [
    "1 OR 1=1", "1 UNION SELECT NULL", "admin--", "sleep(5)",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../etc/passwd", "cat /etc/passwd", "eval($_POST)",
    "{{7*7}}", "169.254.169.254", "base64_decode('cGhwaW5mbygp')"
];

echo "===== 开始测试 RF 分类器 =====\n";
foreach ($attackSamples as $i => $s) {
    $r = Learning_RobinsonFisher::classify($s);
    printf("[%02d] %-30s score=%.1f reason=%s\n", $i + 1, mb_substr($s, 0, 30), $r['score'], $r['reason']);
}
echo "===== 测试完成 =====\n";
