<?php
define("ABSPATH", "/workspace/shield-waf-master/");
define("WAF_LOG_PATH", "/workspace/shield-waf-master/logs/");
if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0777, true);
require_once '/workspace/shield-waf-master/src/Core/Scorer.php';

// 清理记忆池，确保全新测试
@unlink('/tmp/shield_memory/memory_pool.json');

$ip = '192.168.1.100';
$uri = '/test.php';

echo "╔══════════════════════════════════════════════════════════════════════╗\n";
echo "║           自动学习系统配合测试 - 行为基线建立与偏离检测                ║\n";
echo "╚══════════════════════════════════════════════════════════════════════╝\n\n";

echo "【第一阶段】建立正常行为基线 (5次正常请求)\n";
echo str_repeat("-", 60) . "\n";

$normalPayloads = [
    'hello world',
    'php tutorial',
    'mysql数据库',
    'javascript入门',
    'linux命令',
];

foreach ($normalPayloads as $i => $payload) {
    $params = ['q' => $payload];
    $result = WafScorer::score($payload, $uri, $params, [], $ip);
    $baselineExists = $result['learned']['behavior_baseline_exists'] ? '✓已建立' : '✗未建立';
    $evoScore = $result['learned']['evolution_score'];
    printf("  请求%d: %-20s  总分=%5.1f  基线=%s  演化分=%d\n",
        $i+1, $payload, $result['total_score'], $baselineExists, $evoScore);
}

echo "\n【第二阶段】同一IP发起攻击 - 行为偏离加成是否生效？\n";
echo str_repeat("-", 60) . "\n";

$attackPayloads = [
    ['name' => 'SQL注入', 'payload' => "' OR 1=1--"],
    ['name' => 'XSS', 'payload' => '<script>alert(1)</script>'],
    ['name' => '零宽XSS', 'payload' => "<s\u{200b}cript>ale\u{200c}rt(1)</scr\u{200d}ipt>"],
    ['name' => '数学斜体SQL', 'payload' => "\u{1D460}\u{1D452}\u{1D459}\u{1D452}\u{1D450}\u{1D461} * FROM users --"],
];

foreach ($attackPayloads as $atk) {
    $params = ['q' => $atk['payload']];
    $result = WafScorer::score($atk['payload'], $uri, $params, [], $ip);
    $baselineExists = $result['learned']['behavior_baseline_exists'] ? '✓' : '✗';
    $evoScore = $result['learned']['evolution_score'];
    $anomalies = isset($result['memory_pool']['anomalies']) 
        ? implode(",", $result['memory_pool']['anomalies']) 
        : '';
    printf("  %-12s  总分=%5.1f  基线=%s  演化分=%d  异常=[%s]  动作=%s\n",
        $atk['name'], $result['total_score'], $baselineExists, $evoScore, $anomalies, $result['action']);
}

echo "\n【第三阶段】检查学习系统存储状态\n";
echo str_repeat("-", 60) . "\n";

$report = AutoLearn::getReport();
echo "  AutoLearn 统计:\n";
echo "    总攻击数: {$report['total_attacks']}\n";
echo "    已学习规则: {$report['total_learned_rules']}\n";
echo "    正常模式数: {$report['normal_patterns']}\n";
echo "    正常请求总数: {$report['total_normal']}\n";
echo "    反馈数: {$report['feedback_count']}\n";

$profile = SemanticMemoryPool::getProfile($ip);
echo "\n  SemanticMemoryPool 画像 ($ip):\n";
echo "    存在: " . ($profile['exists'] ? '是' : '否') . "\n";
if ($profile['exists']) {
    echo "    总请求数: {$profile['total_requests']}\n";
    echo "    攻击者画像: {$profile['actor_profile']}\n";
    echo "    最近记录数: {$profile['recent_count']}\n";
    echo "    基线样本数: " . ($profile['baseline']['sample_count'] ?? 0) . "\n";
}
