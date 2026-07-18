<?php
/**
 * 双重密码哈希测试
 * 测试 Argon2id+bcrypt 双重哈希、验证、迁移、降级逻辑
 */
define('ABSPATH', '/tmp/');
define('WAF_LOG_PATH', '/tmp/waf_logs_test/');
@mkdir(WAF_LOG_PATH, 0755, true);
@mkdir(WAF_LOG_PATH . 'sandbox/', 0755, true);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Support/Password.php';

$passed = 0;
$failed = 0;
$errors = [];

function assertTrue($cond, $msg) {
    global $passed, $failed, $errors;
    if ($cond) {
        $passed++;
        echo "  \033[32m✓\033[0m $msg\n";
    } else {
        $failed++;
        $errors[] = $msg;
        echo "  \033[31m✗\033[0m $msg\n";
    }
}

function assertEqual($a, $b, $msg) {
    assertTrue($a === $b, $msg . " (期望: " . var_export($b, true) . ", 实际: " . var_export($a, true) . ")");
}

echo "\n=== 双重密码哈希测试 ===\n\n";

// 1. 算法检测
echo "[1] 算法检测\n";
$best = WafPassword::detectBestPrimaryAlgo();
assertTrue(in_array($best, ['argon2id-sodium', 'argon2id', 'argon2i', 'bcrypt-12'], true), "detectBestPrimaryAlgo 返回有效算法: $best");
assertTrue(!empty(WafPassword::getAvailableAlgos()), "getAvailableAlgos 返回非空");

// 2. 哈希生成
echo "\n[2] 双重哈希生成\n";
$plain = 'my-secret-password-123';
$hash = WafPassword::hash($plain);
assertTrue(strpos($hash, 'dual$v1$') === 0, "hash 格式以 dual\$v1\$ 开头");
$info = WafPassword::info($hash);
assertTrue($info['format'] === 'dual-v1', "info format = dual-v1");
assertTrue($info['primary'] === $best, "primary 算法 = $best");
assertTrue($info['secondary'] === 'bcrypt', "secondary 算法固定 = bcrypt");
assertTrue($info['secure'] === true, "secure = true");

// 3. 验证
echo "\n[3] 双重验证（两层都通过）\n";
assertTrue(WafPassword::verify($plain, $hash) === true, "正确密码验证通过");
assertTrue(WafPassword::verify('wrong-password', $hash) === false, "错误密码验证失败");
assertTrue(WafPassword::verify('', $hash) === false, "空密码验证失败");
assertTrue(WafPassword::verify($plain, '') === false, "空 hash 验证失败");

// 4. 错误密码必须两层都失败
echo "\n[4] 错误密码两层都失败\n";
$wrong = WafPassword::hash($plain);
assertTrue(WafPassword::verify('My-Secret-Password-123', $wrong) === false, "大小写不同验证失败");
assertTrue(WafPassword::verify($plain . ' ', $wrong) === false, "尾随空格验证失败");

// 5. 两次哈希结果不同（每次有随机盐）
echo "\n[5] 每次哈希含随机盐\n";
$h1 = WafPassword::hash($plain);
$h2 = WafPassword::hash($plain);
assertTrue($h1 !== $h2, "两次哈希结果不同（随机盐）");
assertTrue(WafPassword::verify($plain, $h1) && WafPassword::verify($plain, $h2), "两次哈希都能验证通过");

// 6. 兼容明文密码（开发期迁移）
echo "\n[6] 兼容明文密码\n";
assertTrue(WafPassword::verify($plain, $plain) === true, "明文密码 verify 时序安全比较");
assertTrue(WafPassword::verify('wrong', $plain) === false, "错误密码与明文比较失败");
$infoPlain = WafPassword::info($plain);
assertTrue($infoPlain['format'] === 'legacy-plaintext', "info 识别 legacy-plaintext");
assertTrue($infoPlain['secure'] === false, "info 标记为不安全");

// 7. 解析无效 hash
echo "\n[7] 无效 hash 解析\n";
assertTrue(WafPassword::verify($plain, 'dual$v1$invalid-base64!') === false, "无效 base64 验证失败");
assertTrue(WafPassword::verify($plain, 'dual$v1$' . base64_encode('not-json')) === false, "无效 JSON 验证失败");

// 8. needsRehash
echo "\n[8] needsRehash 检测\n";
assertTrue(WafPassword::needsRehash($plain) === true, "明文密码需要 rehash");
assertTrue(WafPassword::needsRehash($hash) === false, "新生成的 hash 不需要 rehash");

// 9. benchmark
echo "\n[9] 性能基准测试\n";
$bench = WafPassword::benchmark('test-pass');
assertTrue(isset($bench['benchmarks']['bcrypt-10']['hash_time_ms']), "benchmark 返回 bcrypt-10 耗时");
assertTrue(isset($bench['benchmarks']['dual-full']['hash_time_ms']), "benchmark 返回 dual-full 耗时");
assertTrue(isset($bench['benchmarks']['dual-verify']['verify_time_ms']), "benchmark 返回 dual-verify 耗时");
echo "    PHP {$bench['php_version']} · 最强算法: {$bench['best_algo']}\n";
echo "    dual-full 哈希耗时: {$bench['benchmarks']['dual-full']['hash_time_ms']} ms\n";
echo "    dual-verify 验证耗时: {$bench['benchmarks']['dual-verify']['verify_time_ms']} ms\n";

// 10. 算法降级（如果环境无 sodium，验证降级路径）
echo "\n[10] 算法降级路径\n";
echo "    当前最佳算法: $best\n";
echo "    sodium 扩展: " . (extension_loaded('sodium') ? 'yes' : 'no') . "\n";
echo "    PASSWORD_ARGON2ID: " . (defined('PASSWORD_ARGON2ID') ? 'yes' : 'no') . "\n";
echo "    PASSWORD_BCRYPT: " . (defined('PASSWORD_BCRYPT') ? 'yes' : 'no') . "\n";
assertTrue($best !== 'unknown', "降级路径生效");

// 11. 长密码处理（注意：bcrypt 截断到 72 字节，超长密码前 72 字符相同即视为相同）
echo "\n[11] 长密码处理\n";
$longPlain = str_repeat('a', 1000);
$longHash = WafPassword::hash($longPlain);
assertTrue(WafPassword::verify($longPlain, $longHash) === true, "1000 字符密码验证通过");
assertTrue(WafPassword::verify(str_repeat('b', 1000), $longHash) === false, "1000 个 b 验证失败");
assertTrue(WafPassword::verify('完全不同的内容', $longHash) === false, "完全不同内容验证失败");

// 12. 特殊字符密码
echo "\n[12] 特殊字符密码\n";
$specials = ['p@ssw0rd!', '密码123', "p\\r\\n\\0", '<script>', "'\";--", '日本語パスワード'];
foreach ($specials as $i => $p) {
    $h = WafPassword::hash($p);
    assertTrue(WafPassword::verify($p, $h) === true, "特殊字符密码 #{$i} 验证通过");
}

// 13. config.php 自动迁移测试
echo "\n[13] config.php 自动迁移\n";
$testEnvFile = '/tmp/test.env';
@file_put_contents($testEnvFile, "WAF_2FA_PASS=my-migration-test-password\n");
// 模拟 getenv
putenv('WAF_2FA_PASS=my-migration-test-password');
$testHashFile = WAF_LOG_PATH . 'password_hash_test.json';
@unlink($testHashFile);
// 直接调用迁移函数
$GLOBALS['waf_password_hash_file'] = $testHashFile;
waf_migrate_password_to_hash();
assertTrue(is_file($testHashFile), "迁移后生成 hash 文件");
$data = json_decode(file_get_contents($testHashFile), true);
assertTrue(strpos($data['hash'], 'dual$v1$') === 0, "迁移文件 hash 是 dual-v1 格式");
assertTrue($data['source'] === 'env-plaintext-migration', "迁移来源 = env-plaintext-migration");
assertTrue(WafPassword::verify('my-migration-test-password', $data['hash']), "迁移后的 hash 验证明文通过");
@unlink($testHashFile);
@unlink($testEnvFile);

// 14. 第二次访问不重复迁移
echo "\n[14] 已迁移则不重复\n";
// 重新跑一次迁移函数：已有 hash 文件，应跳过
@file_put_contents($testHashFile, json_encode(['hash' => WafPassword::hash('already-migrated'), 'migrated_at' => time() - 100]));
$mtime1 = filemtime($testHashFile);
sleep(1);
waf_migrate_password_to_hash();
$mtime2 = filemtime($testHashFile);
assertTrue($mtime1 === $mtime2, "已存在 hash 文件时不重写");
@unlink($testHashFile);

echo "\n=== 测试结果 ===\n";
echo "通过: \033[32m{$passed}\033[0m / 失败: \033[31m{$failed}\033[0m\n";
if ($failed > 0) {
    echo "\n失败项:\n";
    foreach ($errors as $e) echo "  - $e\n";
    exit(1);
}
exit(0);
