<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
 * 许可  : MIT -- SPDX-License-Identifier: MIT
 */

/**
 * AI 接线自检（CLI，不需要 Web 服务器）
 *   php tests/ai_check.php
 *
 * 验证：旧版完整 AI 代码是否真的挂进了语枢内核的插拔口，
 *       而不是「类存在但每次请求都冷启动降级」。
 */
declare(strict_types=1);

$root = dirname(__DIR__);
if (!defined('ABSPATH'))      define('ABSPATH', $root . '/');
if (!defined('WAF_HOME'))     define('WAF_HOME', $root);
if (!defined('WAF_LOG_PATH')) define('WAF_LOG_PATH', $root . '/var/logs');
if (!defined('WAF_DATA_PATH'))define('WAF_DATA_PATH', $root . '/var/data');
if (!is_dir(WAF_LOG_PATH))    mkdir(WAF_LOG_PATH, 0750, true);

require $root . '/ai/bootstrap.php';
require_once $root . '/core/YslEngine.php';

$fail = 0;
$check = function (string $label, bool $ok, string $detail = '') use (&$fail): void {
    printf("[%s] %-46s %s\n", $ok ? ' OK ' : 'FAIL', $label, $detail);
    if (!$ok) $fail++;
};

echo "=== 1. 类是否真的加载（AI 自学习层，必检） ===\n";
$aiClasses = [
    'YslAiBridge', 'NaiveBayesClassifier', 'Learning_RobinsonFisher',
    'Learning_FingerprintMatcher', 'Learning_SampleCollector',
    'Learning_SampleFilter', 'Learning_ReviewQueue',
    'Learning_TrainingScheduler', 'Learning_SemanticWeightBridge',
    'Learning_ModelEvaluator', 'Learning_Storage', 'AutoLearn',
];
foreach ($aiClasses as $c) {
    $check('class ' . $c, class_exists($c));
}

// 语义解析层（AST 式深度解析）自 v6.1.0 起默认不加载；仅 WAF_SEMANTIC_LAYER=1 时存在
$semanticClasses = ['WafNormalizer', 'SemanticEngine', 'MultiVectorFusion', 'FalsePositiveGuard', 'SqlSemanticParser', 'XxeSemanticParser'];
if (class_exists('SemanticEngine')) {
    echo "=== 1b. 语义解析层类（已加载） ===\n";
    foreach ($semanticClasses as $c) {
        $check('class ' . $c, class_exists($c));
    }
} else {
    echo "=== 1b. 语义解析层（未加载，核心+AI 精简模式，跳过） ===\n";
    foreach ($semanticClasses as $c) {
        printf("[SKIP] %-46s 语义层未加载\n", 'class ' . $c);
    }
}

echo "\n=== 2. 冷启动基线训练（15 攻击 / 15 正常） ===\n";
$attacks = [
    "' OR 1=1--", "UNION SELECT password FROM users", "<script>alert(1)</script>",
    "../../etc/passwd", "; cat /etc/shadow", "1' AND SLEEP(5)--",
    "<img src=x onerror=alert(1)>", "eval(base64_decode(...))",
    "admin'--", "SELECT * FROM information_schema.tables",
    '${jndi:ldap://evil/x}', '{{7*7}}', '<?php system($_GET["c"]); ?>',
    "filename=\"shell.php\"", "union all select null,version()",
];
$normals = [
    "The union of two sets A and B contains all elements",
    "Please select a shipping address for your order",
    "Hello, how are you today?", "产品详情页与购物车结算流程",
    "SELECT a category from the dropdown menu", "index.php?page=about",
    "The quick brown fox jumps over the lazy dog", "请联系客服获取发票",
    "We use cookies to improve your experience", "Meeting notes for Monday",
    "Please enter your email address", "Spring boot application properties",
    "Thank you for your order", "用户中心与订单列表", "Welcome to our website",
];
NaiveBayesClassifier::reset();
foreach ($attacks as $s)  NaiveBayesClassifier::train($s, 'attack');
foreach ($normals as $s)  NaiveBayesClassifier::train($s, 'normal');
NaiveBayesClassifier::save();
$stats = NaiveBayesClassifier::getModelStats();
$check('模型样本数 >= 30', ($stats['total_samples'] ?? 0) >= 30, 'total_samples=' . ($stats['total_samples'] ?? '缺失'));
$check('契约别名 total_samples 存在', isset($stats['total_samples']));
$modelFile = WAF_LOG_PATH . '/bayes_model.json';
$modelRaw  = is_file($modelFile) ? (string)file_get_contents($modelFile) : '';
$check('模型文件非 0 字节且可解析', $modelRaw !== '' && is_array(json_decode($modelRaw, true)),
       strlen($modelRaw) . ' bytes');

echo "\n=== 3. AI 各引擎真实出信号 ===\n";
$attackText = "' OR 1=1 UNION SELECT password FROM users--";
$normalText = "Please select a shipping address for your order";
$predA = NaiveBayesClassifier::predict($attackText);
$predN = NaiveBayesClassifier::predict($normalText);
$check('贝叶斯 attack_prob 有值', isset($predA['attack_prob']), 'attack=' . $predA['attack_prob'] . ' normal=' . $predN['attack_prob']);
$check('贝叶斯能区分攻击/正常', $predA['attack_prob'] > $predN['attack_prob'],
       sprintf('%.3f > %.3f', $predA['attack_prob'], $predN['attack_prob']));
$check('predict 返回 score_dimensions', isset($predA['score_dimensions']) && is_array($predA['score_dimensions']));
$fisher = Learning_RobinsonFisher::classify($attackText);
$check('Fisher classify 返回 score', isset($fisher['score']), 'score=' . ($fisher['score'] ?? 'NULL') . ' reason=' . ($fisher['reason'] ?? ''));
$fp = Learning_FingerprintMatcher::match($attackText);
$check('指纹 match 返回 similarity', isset($fp['similarity']), 'similarity=' . ($fp['similarity'] ?? 'NULL'));

echo "\n=== 4. YslAiBridge::process() 是否走出冷启动 ===\n";
$scorer = [
    'dimensions'    => [10, 20, 15, 5, 10, 0],
    'total_score'   => 14,
    'risk_level'    => 'low',
    'feature_vector'=> [],
];
$context = [
    'text' => $attackText, 'uri' => '/search?q=' . urlencode($attackText),
    'params' => ['q' => $attackText], 'ip' => '203.0.113.9',
    'headers' => [], 'method' => 'GET', 'body' => '', 'contentType' => '',
];
$ai = YslAiBridge::process($scorer, $context, null);
$check('不再是 cold_start', ($ai['sample_action'] ?? '') !== 'cold_start', 'sample_action=' . ($ai['sample_action'] ?? 'NULL'));
$check('ai_signals.bayes 有值', !empty($ai['ai_signals']['bayes']));
$check('ai_signals.fisher 有值', !empty($ai['ai_signals']['fisher']));
$check('融合分数已算出', isset($ai['total_score']), 'base=' . $ai['base_total'] . ' fused=' . $ai['total_score']);
$check('elapsed_ms 被记录', isset($ai['elapsed_ms']), $ai['elapsed_ms'] . ' ms');

echo "\n=== 4b. 样本分流三条分支（验证适配过的 collectAttack/add/enqueue） ===\n";
$high = $scorer;
$high['dimensions']  = [80, 90, 85, 60, 50, 20];
$high['total_score'] = 85;
$aiHigh = YslAiBridge::process($high, $context, null);
$check('高置信 → trained', ($aiHigh['sample_action'] ?? '') === 'trained',
       'action=' . ($aiHigh['sample_action'] ?? 'NULL') . ' fused=' . ($aiHigh['total_score'] ?? 'NULL'));
$mid = $scorer;
$mid['dimensions']  = [40, 50, 40, 30, 30, 10];
$mid['total_score'] = 38;
$aiMid = YslAiBridge::process($mid, $context, null);
$check('中风险 → review', ($aiMid['sample_action'] ?? '') === 'review',
       'action=' . ($aiMid['sample_action'] ?? 'NULL') . ' fused=' . ($aiMid['total_score'] ?? 'NULL'));
$queueFiles = glob(WAF_LOG_PATH . '/learning/*.json') ?: [];
$check('训练/审核队列真的落盘', count($queueFiles) > 0, implode(', ', array_map('basename', $queueFiles)));

if (class_exists('SemanticEngine')) {
    echo "\n=== 5. 语义层是否被内核启用 ===\n";
    $health = YslEngine::healthCheck();
    $check('semantic = true', ($health['semantic'] ?? false) === true);
    $check('ai_bridge 健康项存在', isset($health['ai_bridge']['modules']));
    $sem = SemanticEngine::analyze($attackText, '/search', ['q' => $attackText], [], '203.0.113.9');
    $check('SemanticEngine 返回 total_score', isset($sem['total_score']), 'total_score=' . ($sem['total_score'] ?? 'NULL'));
    $check('语义层返回误报判定字段', array_key_exists('fp_is_false_positive', $sem));
    $semN = SemanticEngine::analyze($normalText, '/checkout', ['address' => $normalText], [], '203.0.113.9');
    $check('正常文本语义分低于攻击文本', ($semN['total_score'] ?? 999) < ($sem['total_score'] ?? 0),
           'normal=' . ($semN['total_score'] ?? 'NULL') . ' attack=' . ($sem['total_score'] ?? 'NULL'));

    echo "\n=== 6. 16 个语义解析器是否可实例化 ===\n";
    $parsers = glob($root . '/semantic/*SemanticParser.php') ?: [];
    $check('解析器数量 = 16', count($parsers) === 16, '实际 ' . count($parsers));
    $loaded = 0;
    foreach ($parsers as $p) {
        $cls = basename($p, '.php');
        if (class_exists($cls)) $loaded++;
    }
    $check('全部解析器可被 autoload', $loaded === count($parsers), $loaded . '/' . count($parsers));
} else {
    echo "\n=== 5/6. 语义层未加载（核心+AI 精简模式，跳过语义相关断言） ===\n";
    printf("[SKIP] %-46s 语义层未加载\n", 'semantic = true');
    printf("[SKIP] %-46s 语义层未加载\n", 'SemanticEngine 解析');
    printf("[SKIP] %-46s 语义层未加载\n", '16 语义解析器 autoload');
}

echo "\n=== 结果 ===\n";
printf("%s（%d 项失败）\n", $fail === 0 ? '全部通过' : '存在失败', $fail);
exit($fail === 0 ? 0 : 1);
