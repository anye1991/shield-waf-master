<?php
/**
 * 盾甲 WAF v4.0 - 极限测试套件
 * 覆盖：边界值、压力测试、兼容性、异常场景、性能基准
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '512M');
ini_set('max_execution_time', 300);

if (ob_get_level() > 0) ob_end_flush();
echo "start\n"; flush();

require_once __DIR__ . '/src/Password/DualPassword.php';
echo "loaded DualPassword\n"; flush();

$total = 0;
$passed = 0;
$failed = 0;
$results = [];
$benchmarks = [];

function test($name, $fn) {
    global $total, $passed, $failed, $results;
    $total++;
    try {
        $fn();
        $passed++;
        $results[] = ['name' => $name, 'status' => 'pass'];
        echo "  [PASS] $name\n";
    } catch (\Throwable $e) {
        $failed++;
        $results[] = ['name' => $name, 'status' => 'fail', 'error' => $e->getMessage()];
        echo "  [FAIL] $name\n    → " . $e->getMessage() . "\n";
    }
    flush();
}

function assert_true($cond, $msg = '') {
    if (!$cond) throw new \Exception($msg ?: 'Assertion failed');
}

function assert_equals($a, $b, $msg = '') {
    if ($a !== $b) throw new \Exception($msg ?: "Expected " . var_export($b, true) . ", got " . var_export($a, true));
}

function bench($name, $fn, $iterations = 1000) {
    global $benchmarks;
    $start = microtime(true);
    for ($i = 0; $i < $iterations; $i++) $fn();
    $end = microtime(true);
    $elapsed = ($end - $start) * 1000;
    $perOp = ($elapsed / $iterations) * 1000;
    $benchmarks[] = [
        'name' => $name,
        'iterations' => $iterations,
        'total_ms' => round($elapsed, 2),
        'per_op_us' => round($perOp, 2)
    ];
    return $elapsed;
}

echo "\n";
echo "========================================\n";
echo "  盾甲 WAF v4.0 - 极限测试套件\n";
echo "========================================\n\n";

// ============================================================
echo "[1] 双重密码加密 - 边界值测试\n";
echo "----------------------------------------\n";

test('空字符串密码抛出异常（预期行为）', function() {
    $thrown = false;
    try {
        DualPassword::hash('');
    } catch (\Throwable $e) {
        $thrown = true;
    }
    assert_true($thrown, '空密码应被拒绝');
});

test('单字符密码', function() {
    $hash = DualPassword::hash('a');
    assert_true(DualPassword::verify('a', $hash));
    assert_true(!DualPassword::verify('b', $hash));
});

test('72字节密码（bcrypt边界）', function() {
    $pwd = str_repeat('A', 72);
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

test('73字节密码（超过bcrypt边界）', function() {
    $pwd72 = str_repeat('A', 72);
    $pwd73 = str_repeat('A', 73);
    $hash = DualPassword::hash($pwd73);
    assert_true(DualPassword::verify($pwd73, $hash));
    assert_true(!DualPassword::verify($pwd72, $hash));
});

test('1024字节长密码', function() {
    $pwd = str_repeat('X', 1024);
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

test('4096字节超长密码', function() {
    $pwd = str_repeat('Z', 4096);
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

test('Unicode表情密码', function() {
    $pwd = '🛡️盾甲WAF🔒安全🔥测试🎉';
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

test('全部特殊字符', function() {
    $pwd = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/`~\\';
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

echo "  → 8项边界测试完成\n\n";

// ============================================================
echo "[2] 旧格式兼容测试\n";
echo "----------------------------------------\n";

test('bcrypt格式验证 + needsRehash', function() {
    $bcrypt = password_hash('test123', PASSWORD_BCRYPT);
    assert_true(DualPassword::verify('test123', $bcrypt));
    assert_true(DualPassword::needsRehash($bcrypt));
});

test('MD5格式验证', function() {
    $md5 = md5('hello_world');
    assert_true(DualPassword::verify('hello_world', $md5));
    assert_true(DualPassword::needsRehash($md5));
});

test('SHA1格式验证', function() {
    $sha1 = sha1('sha1pass');
    assert_true(DualPassword::verify('sha1pass', $sha1));
});

test('SHA256格式验证', function() {
    $sha256 = hash('sha256', 'sha256test');
    assert_true(DualPassword::verify('sha256test', $sha256));
});

test('SHA512格式验证', function() {
    $sha512 = hash('sha512', 'sha512test');
    assert_true(DualPassword::verify('sha512test', $sha512));
});

test('错误密码不通过', function() {
    $hash = DualPassword::hash('correct');
    assert_true(!DualPassword::verify('wrong', $hash));
    assert_true(!DualPassword::verify('', $hash));
    assert_true(!DualPassword::verify('CORRECT', $hash));
});

test('双重哈希不需要rehash', function() {
    $hash = DualPassword::hash('testpass');
    assert_true(!DualPassword::needsRehash($hash));
});

echo "  → 7项兼容测试完成\n\n";

// ============================================================
echo "[3] 密码信息识别测试\n";
echo "----------------------------------------\n";

test('info识别dual-v1', function() {
    $hash = DualPassword::hash('test123');
    $info = DualPassword::info($hash);
    assert_equals($info['format'], 'dual-v1');
    assert_true(isset($info['primary']));
    assert_true(isset($info['secondary']));
});

test('info识别bcrypt', function() {
    $info = DualPassword::info(password_hash('x', PASSWORD_BCRYPT));
    assert_equals($info['format'], 'bcrypt');
});

test('info识别md5/sha1/sha256/sha512', function() {
    assert_equals(DualPassword::info(md5('x'))['format'], 'md5');
    assert_equals(DualPassword::info(sha1('x'))['format'], 'sha1');
    assert_equals(DualPassword::info(hash('sha256', 'x'))['format'], 'sha256');
    assert_equals(DualPassword::info(hash('sha512', 'x'))['format'], 'sha512');
});

test('空字符串返回empty', function() {
    assert_equals(DualPassword::info('')['format'], 'empty');
});

test('未知格式返回unknown', function() {
    assert_equals(DualPassword::info('not_a_valid_hash_12345')['format'], 'unknown');
});

echo "  → 5项识别测试完成\n\n";

// ============================================================
echo "[4] 异常输入与鲁棒性测试\n";
echo "----------------------------------------\n";

test('超长hash字符串(10000字符)', function() {
    $longHash = str_repeat('a', 10000);
    $result = DualPassword::verify('test', $longHash);
    assert_true($result === false);
});

test('二进制垃圾hash', function() {
    $garbage = random_bytes(256);
    $result = @DualPassword::verify('test', $garbage);
    assert_true($result === false || $result === null);
});

test('SQL注入式密码', function() {
    $pwd = "' OR '1'='1";
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

test('XSS式密码', function() {
    $pwd = '<script>alert(1)</script>';
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

test('路径遍历式密码', function() {
    $pwd = '../../etc/passwd';
    $hash = DualPassword::hash($pwd);
    assert_true(DualPassword::verify($pwd, $hash));
});

echo "  → 5项鲁棒性测试完成\n\n";

// ============================================================
echo "[5] 性能基准测试\n";
echo "----------------------------------------\n";

$samplePwd = 'Benchmark_P@ssw0rd!';
$sampleHash = DualPassword::hash($samplePwd);

$t = bench('hash生成 (10次)', function() use ($samplePwd) {
    DualPassword::hash($samplePwd);
}, 10);
echo "  hash生成: 10次 / " . round($t, 2) . "ms / 单次≈" . round($t/10, 2) . "ms\n";

$t = bench('verify验证 (100次)', function() use ($samplePwd, $sampleHash) {
    DualPassword::verify($samplePwd, $sampleHash);
}, 100);
echo "  verify验证: 100次 / " . round($t, 2) . "ms / 单次≈" . round($t/100, 2) . "ms\n";

$t = bench('info识别 (1000次)', function() use ($sampleHash) {
    DualPassword::info($sampleHash);
}, 1000);
echo "  info识别: 1000次 / " . round($t, 2) . "ms / 单次≈" . round($t/1000*1000, 2) . "μs\n";

$t = bench('needsRehash (1000次)', function() use ($sampleHash) {
    DualPassword::needsRehash($sampleHash);
}, 1000);
echo "  needsRehash: 1000次 / " . round($t, 2) . "ms / 单次≈" . round($t/1000*1000, 2) . "μs\n";

echo "\n";

// ============================================================
echo "[6] 一致性测试（100次随机）\n";
echo "----------------------------------------\n";

$consistencyPass = 0;
$consistencyTotal = 100;
for ($i = 0; $i < $consistencyTotal; $i++) {
    $pwd = 'test_pwd_' . bin2hex(random_bytes(8));
    $hash = DualPassword::hash($pwd);
    if (DualPassword::verify($pwd, $hash) && !DualPassword::verify($pwd . '_wrong', $hash)) {
        $consistencyPass++;
    }
}
echo "  100次随机验证: $consistencyPass / $consistencyTotal ";
if ($consistencyPass === $consistencyTotal) {
    echo "✓ 全部通过\n";
    $passed++;
} else {
    echo "✗ 有失败\n";
    $failed++;
}
$total++;
$results[] = ['name' => '100次随机一致性', 'status' => $consistencyPass === $consistencyTotal ? 'pass' : 'fail'];

echo "\n";

// ============================================================
echo "[7] 算法降级链测试\n";
echo "----------------------------------------\n";

$bestAlgo = 'unknown';
test('detectBestPrimaryAlgo返回有效值', function() use (&$bestAlgo) {
    $algo = DualPassword::detectBestPrimaryAlgo();
    $bestAlgo = $algo;
    assert_true(in_array($algo, ['argon2id-sodium', 'argon2id', 'argon2i', 'bcrypt-12', 'bcrypt-10', 'phpass']));
});
echo "  当前最佳算法: $bestAlgo\n";

test('支持算法列表≥1', function() {
    $algos = DualPassword::getAvailableAlgos();
    assert_true(count($algos) >= 1);
    $names = array_column($algos, 'algo');
    echo "  支持算法数: " . count($algos) . " (" . implode(', ', $names) . ")\n";
});

echo "\n";

// ============================================================
echo "[8] 内存占用测试\n";
echo "----------------------------------------\n";

$memBefore = memory_get_usage();
$hashes = [];
for ($i = 0; $i < 100; $i++) {
    $hashes[] = DualPassword::hash('mem_test_' . $i);
}
$memAfter = memory_get_usage();
$memPerHash = ($memAfter - $memBefore) / 100;
echo "  100个hash内存占用: " . round(($memAfter - $memBefore)/1024, 2) . " KB\n";
echo "  平均每个hash: " . round($memPerHash, 2) . " bytes\n";
unset($hashes);
$passed++;
$total++;
$results[] = ['name' => '内存占用测试', 'status' => 'pass'];

echo "\n";

// ============================================================
echo "[9] 并发与重入测试\n";
echo "----------------------------------------\n";

test('同一密码多次hash结果不同（加盐）', function() {
    $pwd = 'same_password';
    $hash1 = DualPassword::hash($pwd);
    $hash2 = DualPassword::hash($pwd);
    assert_true($hash1 !== $hash2);
    assert_true(DualPassword::verify($pwd, $hash1));
    assert_true(DualPassword::verify($pwd, $hash2));
});

test('100次循环验证不崩溃', function() {
    $pwd = 'stress_test_pwd';
    $hash = DualPassword::hash($pwd);
    for ($i = 0; $i < 100; $i++) {
        if (!DualPassword::verify($pwd, $hash)) {
            throw new \Exception("第 $i 次验证失败");
        }
    }
    assert_true(true);
});

echo "\n";

// ============================================================
// 汇总
echo "\n";
echo "========================================\n";
echo "           测试汇总\n";
echo "========================================\n";
echo "  总测试数:  $total\n";
echo "  通过:      $passed\n";
echo "  失败:      $failed\n";
echo "  通过率:    " . ($total > 0 ? round($passed/$total*100, 2) : 0) . "%\n";
echo "----------------------------------------\n";
echo "  性能基准:\n";
foreach ($benchmarks as $b) {
    echo "    " . $b['name'] . ": " . $b['total_ms'] . "ms / 单操作 " . $b['per_op_us'] . "μs\n";
}
echo "========================================\n";

// 失败详情
if ($failed > 0) {
    echo "\n【失败详情】\n";
    foreach ($results as $r) {
        if ($r['status'] === 'fail') {
            echo "  ✗ " . $r['name'] . "\n";
            echo "    → " . ($r['error'] ?? 'unknown') . "\n";
        }
    }
}

// 保存结果
@file_put_contents(__DIR__ . '/test_results_extreme.json', json_encode([
    'summary' => [
        'total' => $total,
        'passed' => $passed,
        'failed' => $failed,
        'pass_rate' => $total > 0 ? round($passed/$total*100, 2) : 0,
    ],
    'benchmarks' => $benchmarks,
    'details' => $results,
    'date' => date('Y-m-d H:i:s'),
    'php_version' => PHP_VERSION,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

echo "\n结果已保存到 test_results_extreme.json\n";

exit($failed > 0 ? 1 : 0);
