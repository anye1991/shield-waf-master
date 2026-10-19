<?php
define('ABSPATH', __DIR__ . '/');
define('WAF_LOG_PATH', __DIR__ . '/logs');
if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0775, true);

// 模拟 WAF 底层需要的依赖函数
if (!function_exists('waf_ensure_dir')) {
    function waf_ensure_dir($dir) { if (!is_dir($dir)) @mkdir($dir, 0775, true); }
}
if (!function_exists('waf_safe_read_json')) {
    function waf_safe_read_json($f, $d = []) {
        if (!is_file($f)) return $d;
        $j = json_decode(@file_get_contents($f), true);
        return is_array($j) ? $j : $d;
    }
}
if (!function_exists('waf_safe_write_json')) {
    function waf_safe_write_json($f, $d) {
        waf_ensure_dir(dirname($f));
        return @file_put_contents($f, json_encode($d, JSON_UNESCAPED_SLASHES), LOCK_EX);
    }
}

require_once 'src/Learn/NaiveBayesClassifier.php';
require_once 'src/Learn/RobinsonFisher.php';

echo "=========================================\n";
echo "  盾甲 WAF 五路融合引擎 (RF + 贝叶斯) 实战\n";
echo "=========================================\n\n";

// 准备测试样本
$samples = [
    // 强力攻击样本（应该得高分，被拦截）
    "1 UNION SELECT username, password FROM users--", 
    "<script>alert('XSS')</script>",
    "../../../../etc/passwd",
    "eval(base64_decode('cGhwaW5mbygp'));",
    "cat /etc/shadow | grep root",
    
    // 正常业务样本（应该得低分，被放行）
    "index.php?category=shoes&page=2",
    "user/profile?uid=1024&tab=settings",
    "search?q=how+to+make+money",
    "api/v1/articles?sort=newest"
];

foreach ($samples as $i => $payload) {
    echo "测试 Payload [" . ($i + 1) . "]: {$payload}\n";
    
    // 1. 调用朴素贝叶斯
    $bayes = NaiveBayesClassifier::getAttackScore($payload);
    
    // 2. 调用 Robinson-Fisher
    $rfResult = Learning_RobinsonFisher::classify($payload);
    $rf = $rfResult['score'];
    
    // 3. 模拟评分融合（取两者最大值作为 AI 引擎得分）
    $finalScore = max($bayes, $rf);
    
    // 判定
    $action = $finalScore >= 70 ? "❌ [拦截]" : "✅ [放行]";
    
    printf("  - 贝叶斯评分: %5.1f\n", $bayes);
    printf("  - RF 评分:    %5.1f (%s)\n", $rf, $rfResult['reason']);
    printf("  - AI 最终分:  %5.1f  => %s\n", $finalScore, $action);
    echo "-----------------------------------------\n";
}
