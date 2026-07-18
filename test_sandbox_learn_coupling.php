<?php
/**
 * 沙箱↔AutoLearn 三集成点联动测试
 *
 * 验证：
 *   集成点 1：沙箱事件回流 → AutoLearn 标记 IP 高危 → 偏差分加成
 *   集成点 2：AutoLearn 高频特征 → 沙箱扫描合并查询（单向只读）
 *   集成点 3：lockBaseline → AutoLearn 行为基线冻结 → recordNormal 跳过
 *
 * 运行：php test_sandbox_learn_coupling.php
 */
define('ABSPATH', '/workspace/shield-waf-master/');
define('WAF_LOG_PATH', '/tmp/waf_coupling_test/');
if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0777, true);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Semantic/AdversarialDefense.php';
require_once __DIR__ . '/src/Learn/AutoLearn.php';
require_once __DIR__ . '/src/Admin/Sandbox.php';

WafSandbox::init();

echo "╔══════════════════════════════════════════════════════════════════════╗\n";
echo "║   沙箱↔AutoLearn 三集成点联动测试                                       ║\n";
echo "╚══════════════════════════════════════════════════════════════════════╝\n\n";

$pass = 0;
$fail = 0;
function assert_true($cond, $msg, &$pass, &$fail) {
    if ($cond) {
        $pass++;
        echo "  ✓ $msg\n";
    } else {
        $fail++;
        echo "  ✗ $msg\n";
    }
}

// 清理环境
@unlink(WAF_LOG_PATH . 'sandbox_blacklist.json');
@unlink(WAF_LOG_PATH . 'baseline_freeze.json');
@unlink(WAF_LOG_PATH . 'learned_patterns.json');

// 通过反射清空 AutoLearn 静态缓存
$alRef = new ReflectionClass('AutoLearn');
$invMethod = $alRef->getMethod('invalidateCache');
$invMethod->setAccessible(true);
$invMethod->invoke(null);

$invalidateAl = function() use ($invMethod) {
    $invMethod->invoke(null);
};

// 反射访问 private loadNormal 用于测试断言
$loadNormalMethod = $alRef->getMethod('loadNormal');
$loadNormalMethod->setAccessible(true);
$getNormalCount = function() use ($loadNormalMethod) {
    $n = $loadNormalMethod->invoke(null);
    return count($n['patterns'] ?? []);
};

echo "【集成点 1】沙箱事件回流 → IP 高危标记\n";
echo str_repeat("-", 70) . "\n";

// 模拟沙箱事件触发
$attackerIp = '203.0.113.42';
$_SERVER['REMOTE_ADDR'] = $attackerIp;

AutoLearn::markIpFromSandbox($attackerIp, 'surgical_cut', ['path' => '/tmp/test.php', 'score' => 80]);
AutoLearn::markIpFromSandbox($attackerIp, 'instant_delete', ['path' => '/tmp/shell.php', 'score' => 95]);

$risk = AutoLearn::getSandboxIpRisk($attackerIp);
echo "  攻击 IP {$attackerIp} 触发 2 次沙箱事件，偏差风险 = {$risk}\n";
assert_true($risk > 0, '沙箱事件后 IP 应有偏差风险加成 (>0)', $pass, $fail);
assert_true($risk >= 0.3, '2 次事件风险至少 0.3', $pass, $fail);
assert_true($risk < 0.6, '2 次事件风险应 < 0.6（未达 frozen 阈值 3）', $pass, $fail);

// 第 3 次事件触发 frozen
AutoLearn::markIpFromSandbox($attackerIp, 'quarantine', ['path' => '/tmp/x.php', 'score' => 70]);
$risk = AutoLearn::getSandboxIpRisk($attackerIp);
echo "  攻击 IP 触发第 3 次事件（达 frozen 阈值），偏差风险 = {$risk}\n";
assert_true($risk >= 0.6, '3 次事件风险升级到 0.6', $pass, $fail);

// 干净 IP 应无风险
$cleanIp = '198.51.100.1';
$cleanRisk = AutoLearn::getSandboxIpRisk($cleanIp);
assert_true($cleanRisk === 0.0, "干净 IP 风险应为 0 (实际={$cleanRisk})", $pass, $fail);

// 非法 IP 应跳过
AutoLearn::markIpFromSandbox('not-an-ip', 'test', []);
AutoLearn::markIpFromSandbox('', 'test', []);
AutoLearn::markIpFromSandbox('cli', 'test', []);
$badRisk = AutoLearn::getSandboxIpRisk('not-an-ip');
assert_true($badRisk === 0.0, '非法 IP 应被过滤', $pass, $fail);

echo "\n【集成点 1b】getDeviationScore 整合沙箱风险\n";
echo str_repeat("-", 70) . "\n";

// 给 AutoLearn 喂一些正常请求，建立行为基线（用干净 IP）
$cleanIp2 = '198.51.100.7';
$_SERVER['REMOTE_ADDR'] = $cleanIp2;
$normalUri = '/api/search';
for ($i = 0; $i < 8; $i++) {
    AutoLearn::recordNormal($normalUri, ['q', 'page']);
}
// 正常 IP 查询：不应有沙箱风险加成
$baseDeviation = AutoLearn::getDeviationScore($normalUri, ['q']);
echo "  正常 IP {$cleanIp2} 偏差分 = {$baseDeviation}\n";
assert_true($baseDeviation < 0.18, '正常 IP 偏差分应低（无沙箱风险加成）', $pass, $fail);

// 切换到攻击 IP，应当叠加沙箱风险
$_SERVER['REMOTE_ADDR'] = $attackerIp;
$attackerDeviation = AutoLearn::getDeviationScore($normalUri, ['q']);
echo "  攻击 IP {$attackerIp} 同一 URI 偏差分 = {$attackerDeviation}（应叠加沙箱风险）\n";
assert_true($attackerDeviation > $baseDeviation, '攻击 IP 偏差分应 > 正常 IP', $pass, $fail);
assert_true($attackerDeviation > 0.1, '攻击 IP 应有沙箱风险加成（>0.1）', $pass, $fail);

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

echo "\n【集成点 2】AutoLearn 特征反哺 → 沙箱扫描合并查询\n";
echo str_repeat("-", 70) . "\n";

// 先造一些"高频"特征到 learned_patterns.json
$patternsFile = WAF_LOG_PATH . 'learned_patterns.json';
$fakePatterns = [
    'rules' => [
        'r1' => ['pattern' => 'evil_func(', 'type' => 'rce', 'severity' => 80, 'hit_count' => 15, 'name' => 'test1', 'last_seen' => time()],
        'r2' => ['pattern' => 'if(', 'type' => 'xss', 'severity' => 80, 'hit_count' => 100, 'name' => 'should_be_filtered', 'last_seen' => time()],
        'r3' => ['pattern' => 'backdoor_call(', 'type' => 'rce', 'severity' => 60, 'hit_count' => 5, 'name' => 'too_few_hits', 'last_seen' => time()],
    ],
    'total_learned' => 3,
    'last_learn_time' => time(),
];
waf_safe_write_json($patternsFile, $fakePatterns);
$invalidateAl();

$hotSigs = AutoLearn::getHotSignatures(10, 50);
echo "  AutoLearn 返回热门特征数 = " . count($hotSigs) . "\n";
assert_true(isset($hotSigs['evil_func(']), '高频真实特征应返回', $pass, $fail);
assert_true(!isset($hotSigs['if(']), '常见合法函数名 if( 应被过滤（防反向污染）', $pass, $fail);
assert_true(!isset($hotSigs['backdoor_call(']), 'hit_count<10 的应被过滤', $pass, $fail);
assert_true($hotSigs['evil_func('] <= 15, '反哺特征权重应 <= 15', $pass, $fail);

// 测试沙箱侧合并查询：用 analyzeLineForMalware 验证
$ref = new ReflectionClass('WafSandbox');
$m = $ref->getMethod('analyzeLineForMalware');
$m->setAccessible(true);

// evil_func( + 已有特征码（让 score > 0），应触发反哺加分
$line = 'eval(base64_decode($_POST[\'x\'])); evil_func(arg);';
$r = $m->invoke(null, $line, '');
$hasAutoLearnIndicator = strpos($r['reason'], 'AutoLearn热点') !== false;
echo "  analyzeLineForMalware 评分 = {$r['score']}, 原因包含反哺标记: " . ($hasAutoLearnIndicator ? '是' : '否') . "\n";
assert_true($hasAutoLearnIndicator, 'eval 行应触发 AutoLearn 反哺加分', $pass, $fail);

// 单纯特征不命中（防反向污染）：清白代码不应被反哺误杀
$cleanLine = 'function add($a, $b) { return $a + $b; }';
$r2 = $m->invoke(null, $cleanLine, '');
echo "  干净代码评分 = {$r2['score']}\n";
assert_true(!$r2['is_malicious'], '干净代码不应被反哺误杀', $pass, $fail);

echo "\n【集成点 3】基线联动 → AutoLearn 行为基线冻结\n";
echo str_repeat("-", 70) . "\n";

@unlink(WAF_LOG_PATH . 'baseline_freeze.json');
$invalidateAl();

// 冻结前：recordNormal 应正常工作
$frozen1 = AutoLearn::isBaselineFrozen();
assert_true(!$frozen1, '初始状态：基线未冻结', $pass, $fail);

AutoLearn::recordNormal('/test/before_freeze', ['a']);
$beforeCount = $getNormalCount();
echo "  冻结前 recordNormal，patterns 数 = {$beforeCount}\n";
assert_true($beforeCount >= 1, '冻结前应能学习新正常模式', $pass, $fail);

// 冻结
AutoLearn::freezeBaseline('sandbox_lock');
$frozen2 = AutoLearn::isBaselineFrozen();
assert_true($frozen2, 'freezeBaseline 后基线应冻结', $pass, $fail);

// 冻结期间：recordNormal 应跳过
$beforeCount2 = $getNormalCount();
AutoLearn::recordNormal('/test/after_freeze', ['b']);
$afterCount = $getNormalCount();
echo "  冻结后 recordNormal，patterns 数 = {$afterCount}（之前 {$beforeCount2}）\n";
assert_true($afterCount === $beforeCount2, '冻结期间 recordNormal 应跳过（防"教坏"）', $pass, $fail);

// 解冻
AutoLearn::unfreezeBaseline();
$frozen3 = AutoLearn::isBaselineFrozen();
assert_true(!$frozen3, 'unfreezeBaseline 后基线应解冻', $pass, $fail);

// 解冻后：recordNormal 应恢复
$beforeCount3 = $getNormalCount();
AutoLearn::recordNormal('/test/after_unfreeze', ['c']);
$afterCount2 = $getNormalCount();
echo "  解冻后 recordNormal，patterns 数 = {$afterCount2}（之前 {$beforeCount3}）\n";
assert_true($afterCount2 > $beforeCount3, '解冻后 recordNormal 应恢复学习', $pass, $fail);

echo "\n【集成点 3b】lockBaseline/unlockBaseline 联动调用\n";
echo str_repeat("-", 70) . "\n";

@unlink(WAF_LOG_PATH . 'baseline_freeze.json');
@unlink(WAF_LOG_PATH . 'baseline_meta.json');
@unlink(WAF_LOG_PATH . 'baseline.json');
$invalidateAl();

WafSandbox::lockBaseline();
$frozenAfterLock = AutoLearn::isBaselineFrozen();
assert_true($frozenAfterLock, 'WafSandbox::lockBaseline() 应联动冻结 AutoLearn', $pass, $fail);

WafSandbox::unlockBaseline();
$frozenAfterUnlock = AutoLearn::isBaselineFrozen();
assert_true(!$frozenAfterUnlock, 'WafSandbox::unlockBaseline() 应联动解冻 AutoLearn', $pass, $fail);

echo "\n" . str_repeat("=", 70) . "\n";
echo "【汇总】\n";
printf("  通过: %d / 失败: %d （共 %d）\n", $pass, $fail, $pass + $fail);
echo str_repeat("=", 70) . "\n";

// 清理测试数据
@unlink(WAF_LOG_PATH . 'sandbox_blacklist.json');
@unlink(WAF_LOG_PATH . 'baseline_freeze.json');
@unlink(WAF_LOG_PATH . 'learned_patterns.json');
@unlink(WAF_LOG_PATH . 'normal_patterns.json');
@unlink(WAF_LOG_PATH . 'baseline.json');
@unlink(WAF_LOG_PATH . 'baseline_meta.json');

exit($fail === 0 ? 0 : 1);
