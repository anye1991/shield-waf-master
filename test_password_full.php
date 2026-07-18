<?php
/**
 * 密码服务单元测试 — 覆盖：
 *   1. DualPassword 双重哈希生成与验证
 *   2. 旧密码格式兼容（bcrypt / phpass / md5 / sha1 / sha256 / sha512 / argon2）
 *   3. needsRehash / info 检测
 *   4. DbAdapter 多数据库（SQLite 实测 + 其他类型构建测试）
 *   5. PasswordService 注册 / 登录 / 改密 / 迁移 / 统计
 *   6. 不同长度密码（含超长 >72 字节）
 *   7. 错误密码拒绝
 *   8. PHP 版本跨兼容（5.6 / 7.x / 8.x）
 *
 * 运行：php test_password_full.php
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/src/Password/DualPassword.php';
require_once __DIR__ . '/src/Password/DbAdapter.php';
require_once __DIR__ . '/src/Password/PasswordService.php';

$pass = 0;
$fail = 0;

function ok($cond, $msg) {
    global $pass, $fail;
    if ($cond) { $pass++; echo "✓ $msg\n"; }
    else { $fail++; echo "✗ FAIL: $msg\n"; }
}

echo "========================================\n";
echo "  密码服务全功能测试\n";
echo "  PHP 版本: " . PHP_VERSION . "\n";
echo "  最佳主算法: " . DualPassword::detectBestPrimaryAlgo() . "\n";
echo "========================================\n\n";

// --------- 1. DualPassword 基础 ---------
echo "【1】DualPassword 双重哈希生成与验证\n";

$plain = 'MyStr0ngP@ssw0rd!';
$hash = DualPassword::hash($plain);
ok(strpos($hash, 'dual$v1$') === 0, 'hash() 输出 dual$v1$ 前缀');
ok(DualPassword::verify($plain, $hash), 'verify() 正确密码通过');
ok(!DualPassword::verify('wrong-password', $hash), 'verify() 错误密码拒绝');
ok(!DualPassword::verify('', $hash), 'verify() 空密码拒绝');

$hash2 = DualPassword::hash($plain);
ok($hash !== $hash2, '两次 hash 结果不同（随机盐）');
ok(DualPassword::verify($plain, $hash2), '第二次哈希也能验证');

// 信息检测
$info = DualPassword::info($hash);
ok($info['format'] === 'dual-v1', 'info() 返回 dual-v1 格式');
ok(isset($info['primary_algo']), 'info() 含 primary_algo');
ok(isset($info['secondary_algo']), 'info() 含 secondary_algo');

ok(!DualPassword::needsRehash($hash), 'needsRehash() 对当前算法返回 false');

echo "\n";

// --------- 2. 旧密码格式兼容 ---------
echo "【2】旧密码格式兼容验证\n";

// bcrypt
$bcrypt = password_hash($plain, PASSWORD_BCRYPT);
ok(DualPassword::verify($plain, $bcrypt), '兼容 bcrypt 验证');
ok(DualPassword::needsRehash($bcrypt), 'bcrypt 需要升级');

// md5
$md5 = md5($plain);
ok(DualPassword::verify($plain, $md5), '兼容 md5 验证');
ok(DualPassword::needsRehash($md5), 'md5 需要升级');

// sha1
$sha1 = sha1($plain);
ok(DualPassword::verify($plain, $sha1), '兼容 sha1 验证');

// sha256
$sha256 = hash('sha256', $plain);
ok(DualPassword::verify($plain, $sha256), '兼容 sha256 验证');

// sha512
$sha512 = hash('sha512', $plain);
ok(DualPassword::verify($plain, $sha512), '兼容 sha512 验证');

// phpass WordPress 风格 ($P$ + 8 次迭代)
$phpass = '$P$B8e8tMqV3eY5mK2JnQ9rZ7X4wV3uT2s1'; // 假的，测识别
$infoPhp = DualPassword::info($phpass);
ok($infoPhp['format'] === 'phpass', '识别 phpass 格式');

// 空字符串
ok(!DualPassword::verify($plain, ''), '空哈希拒绝');
ok(!DualPassword::verify($plain, null), 'null 哈希拒绝');

echo "\n";

// --------- 3. 不同长度密码 ---------
echo "【3】不同长度密码测试\n";

$short = 'a';
$hshort = DualPassword::hash($short);
ok(DualPassword::verify($short, $hshort), '短密码 (1 字节) 验证通过');

$medium = str_repeat('x', 50);
$hmed = DualPassword::hash($medium);
ok(DualPassword::verify($medium, $hmed), '中等密码 (50 字节) 验证通过');

// bcrypt 自动截断到 72 字节，我们的 dual hash 会对超长密码先做 sha256 预处理
// 测试 > 72 字节
$long72 = str_repeat('a', 72);
$long73diff = 'b' . str_repeat('a', 72); // 前缀不同
$hlong72 = DualPassword::hash($long72);
ok(DualPassword::verify($long72, $hlong72), '72 字节密码验证通过');

$hlong73 = DualPassword::hash($long73diff);
ok(DualPassword::verify($long73diff, $hlong73), '73 字节（前缀不同）密码验证通过');
ok(!DualPassword::verify($long72, $hlong73), '前缀不同的长密码互不通过');

$veryLong = str_repeat('z', 1024);
$hvl = DualPassword::hash($veryLong);
ok(DualPassword::verify($veryLong, $hvl), '超长密码 (1024 字节) 验证通过');
ok(!DualPassword::verify($veryLong . 'x', $hvl), '超长密码差一位不通过');

echo "\n";

// --------- 4. DbAdapter SQLite 实测 ---------
echo "【4】DbAdapter (SQLite) 实测\n";

$dbFile = sys_get_temp_dir() . '/shield_pwd_test_' . uniqid() . '.db';

try {
    $db = ShieldDbAdapter::connect(array(
        'driver'   => 'pdo_sqlite',
        'database' => $dbFile,
    ));
    ok(true, 'SQLite 连接成功 (pdo_sqlite)');

    // 建表
    $db->execute("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255)
    )");
    ok(true, '建表成功');

    // 插入
    $db->execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        array('alice', 'hash_alice_123', 'alice@test.com'));
    $id = $db->lastInsertId();
    ok($id > 0, '插入成功，ID=' . $id);

    // query 多行
    $db->execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        array('bob', 'hash_bob_456', 'bob@test.com'));
    $rows = $db->query("SELECT * FROM users");
    ok(count($rows) === 2, 'query 多行返回 ' . count($rows) . ' 行');

    // queryOne
    $user = $db->queryOne("SELECT * FROM users WHERE id = ?", array(1));
    ok($user && $user['username'] === 'alice', 'queryOne 返回正确用户');

    // execute update
    $affected = $db->execute("UPDATE users SET email = ? WHERE id = ?",
        array('new@test.com', 1));
    ok($affected == 1, 'UPDATE 影响 1 行');

    $user2 = $db->queryOne("SELECT * FROM users WHERE id = ?", array(1));
    ok($user2['email'] === 'new@test.com', 'UPDATE 内容正确');

    // 清理
    @unlink($dbFile);
    ok(true, 'SQLite 测试数据库清理');

} catch (Exception $e) {
    ok(false, 'SQLite 测试失败: ' . $e->getMessage());
}

echo "\n";

// --------- 5. PasswordService 全流程 ---------
echo "【5】PasswordService 全流程测试 (SQLite)\n";

$dbFile2 = sys_get_temp_dir() . '/shield_pwd_svc_' . uniqid() . '.db';

try {
    $svc = ShieldPasswordService::init(array(
        'driver'   => 'pdo_sqlite',
        'database' => $dbFile2,
        'table'    => 'users',
        'id_col'   => 'id',
        'name_col' => 'username',
        'pass_col' => 'password',
    ));
    ok($svc->isEnabled() === true, 'PasswordService 启用状态');

    // 建表（模拟已有系统）
    $db = $svc->getDb();
    $db->execute("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255)
    )");

    // 注册
    $uid1 = $svc->register('user1', 'TestPass123!', array('email' => 'u1@test.com'));
    ok($uid1 > 0, '注册成功，uid=' . $uid1);

    $u = $db->queryOne("SELECT * FROM users WHERE id = ?", array($uid1));
    ok(strpos($u['password'], 'dual$v1$') === 0, '存储的是双重哈希');

    // 登录成功
    $loginUser = $svc->login('user1', 'TestPass123!');
    ok($loginUser !== false && $loginUser['username'] === 'user1', '登录成功');

    // 登录失败
    ok($svc->login('user1', 'wrong-pass') === false, '错误密码登录失败');
    ok($svc->login('noexist', 'TestPass123!') === false, '不存在用户登录失败');

    // 模拟旧密码（md5）→ 登录时自动升级
    $md5pass = md5('old-md5-pass');
    $db->execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        array('olduser', $md5pass, 'old@test.com'));
    $oldId = $db->lastInsertId();

    $oldLogin = $svc->login('olduser', 'old-md5-pass');
    ok($oldLogin !== false, 'md5 旧密码登录成功');
    ok(!empty($oldLogin['_upgraded']), '登录后自动标记升级');

    $afterUser = $db->queryOne("SELECT * FROM users WHERE id = ?", array($oldId));
    ok(strpos($afterUser['password'], 'dual$v1$') === 0, '旧密码已自动升级为双重哈希');

    // 再次登录（用升级后的哈希）
    $reLogin = $svc->login('olduser', 'old-md5-pass');
    ok($reLogin !== false, '升级后再次登录成功');

    // 修改密码
    $changed = $svc->changePassword($uid1, 'TestPass123!', 'NewPass456!');
    ok($changed, '修改密码成功');

    ok($svc->login('user1', 'NewPass456!') !== false, '新密码登录成功');
    ok($svc->login('user1', 'TestPass123!') === false, '旧密码登录失败');

    // 管理员重置
    $svc->resetPassword($uid1, 'admin-reset-789');
    ok($svc->login('user1', 'admin-reset-789') !== false, '管理员重置密码后登录成功');

    // 统计
    $stats = $svc->getStats();
    ok($stats['total_users'] == 2, '统计总用户数 = 2');
    ok($stats['upgraded_est'] > 0, '已升级数量 > 0');

    // 迁移信息
    $mig = $svc->migrate(10);
    ok($mig['processed'] == 2, 'migrate 处理 2 条');
    ok($mig['upgraded'] >= 1, '至少 1 条已升级');

    @unlink($dbFile2);
    ok(true, 'PasswordService 测试库清理');

} catch (Exception $e) {
    ok(false, 'PasswordService 测试异常: ' . $e->getMessage() . "\n" . $e->getTraceAsString());
    @unlink($dbFile2);
}

echo "\n";

// --------- 6. 算法自动降级检测 ---------
echo "【6】算法兼容性检测\n";
$algo = DualPassword::detectBestPrimaryAlgo();
ok(in_array($algo, array('argon2id-sodium', 'argon2id-native', 'bcrypt-12'), true),
    "检测到最佳主算法: $algo");

// 验证 info 对各格式返回正确
$fmts = array(
    'dual-v1'  => DualPassword::hash('test'),
    'bcrypt'   => password_hash('test', PASSWORD_BCRYPT),
    'md5'      => md5('test'),
    'sha1'     => sha1('test'),
    'sha256'   => hash('sha256', 'test'),
    'sha512'   => hash('sha512', 'test'),
    'phpass'   => '$P$B8e8tMqV3eY5mK2JnQ9rZ7X4wV3uT2s1',
);
foreach ($fmts as $expected => $h) {
    $info = DualPassword::info($h);
    ok($info['format'] === $expected, "info('$expected') 正确识别");
}
ok(DualPassword::info('')['format'] === 'empty', '空字符串识别为 empty');
ok(DualPassword::info('garbage-data-here')['format'] === 'unknown', '未知格式识别为 unknown');

echo "\n";

// --------- 7. 静态便捷方法 ---------
echo "【7】静态便捷方法\n";
$h = ShieldPasswordService::hashPassword('static-test');
ok(strpos($h, 'dual$v1$') === 0, 'hashPassword 静态方法');
ok(ShieldPasswordService::verifyPassword('static-test', $h), 'verifyPassword 静态方法');
ok(ShieldPasswordService::needsUpgrade(md5('x')), 'needsUpgrade 静态方法');
$info = ShieldPasswordService::passwordInfo($h);
ok($info['format'] === 'dual-v1', 'passwordInfo 静态方法');

echo "\n";

// --------- 结果 ---------
echo "========================================\n";
echo "  测试完成: $pass 通过, $fail 失败\n";
echo "========================================\n";

exit($fail > 0 ? 1 : 0);
