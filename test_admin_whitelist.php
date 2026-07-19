<?php
/**
 * 测试：管理员 IP 白名单 + 测试模式（只拦截不封IP）
 * 用子进程隔离每个测试用例，避免 require_once 缓存配置常量
 */

error_reporting(E_ERROR | E_PARSE);

$waf_dir = __DIR__;
$stub = <<<PHP
<?php
\$_SERVER['REQUEST_METHOD'] = 'GET';
\$_SERVER['REMOTE_ADDR']    = getenv('WAF_TEST_IP') ?: '127.0.0.1';
\$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 TestClient';
\$_SERVER['HTTP_HOST']      = 'localhost';
\$_SERVER['SERVER_NAME']    = 'localhost';
\$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
\$_SERVER['REQUEST_URI']    = '/?id=1';
\$_SERVER['QUERY_STRING']   = 'id=1';
\$_GET = ['id' => '1']; \$_POST = []; \$_COOKIE = []; \$_REQUEST = \$_GET;

define('ABSPATH', '$waf_dir/');
require_once '$waf_dir/config.php';
require_once '$waf_dir/src/Support/Functions.php';
require_once '$waf_dir/src/Admin/IpManager.php';

\$op = getenv('WAF_TEST_OP') ?: 'smart_ban';
\$ip = getenv('WAF_TEST_IP') ?: '8.8.8.8';
// extra_code 在 switch 之前执行（用于设置 ban.txt 等）
switch (\$op) {
    case 'smart_ban':
        waf_smart_ban(\$ip);
        break;
    case 'ban':
        waf_ban(\$ip, 3600);
        break;
    case 'is_banned':
        // extra_code 会先执行（写 ban.txt），然后再调用 waf_is_banned
        echo waf_is_banned() ? 'BANNED' : 'NOT_BANNED';
        exit;
    case 'is_admin':
        echo waf_is_admin_ip(\$ip) ? 'ADMIN' : 'NOT_ADMIN';
        exit;
}
PHP;

function run_case($ip, $admin_ips, $test_mode, $op, $extra_code = '') {
    @unlink(__DIR__ . '/logs/ban.txt');
    @unlink(__DIR__ . '/logs/test_mode_ban.log');
    @unlink(__DIR__ . '/logs/admin_ips.txt');

    $env = [
        'WAF_TEST_IP'   => $ip,
        'WAF_TEST_OP'   => $op,
        'WAF_ADMIN_IPS' => is_array($admin_ips) ? implode(',', $admin_ips) : '',
        'WAF_TEST_MODE' => $test_mode ? 'true' : 'false',
    ];

    $tmpFile = tempnam(sys_get_temp_dir(), 'waf_stub_');
    // extra_code 放在 require_once 之后、switch 之前执行
    $inject_pos = strpos($GLOBALS['stub'], '// extra_code 在 switch 之前执行');
    $stub_with_extra = substr($GLOBALS['stub'], 0, $inject_pos) .
                       $extra_code . "\n" .
                       substr($GLOBALS['stub'], $inject_pos);
    file_put_contents($tmpFile, $stub_with_extra);

    // 用 env 命令传环境变量，兼容 dash/bash
    $envStr = 'env';
    foreach ($env as $k => $v) $envStr .= ' ' . escapeshellarg($k . '=' . $v);
    $cmd = $envStr . ' php -d error_reporting="E_ERROR|E_PARSE" ' . escapeshellarg($tmpFile);
    $out = shell_exec($cmd . ' 2>&1');
    @unlink($tmpFile);

    return [
        'out' => trim($out),
        'ban' => @file_get_contents(__DIR__ . '/logs/ban.txt'),
        'test_log' => @file_get_contents(__DIR__ . '/logs/test_mode_ban.log'),
    ];
}

echo "===== 管理员IP白名单 + 测试模式 测试 =====\n\n";

// 测试1：默认模式 smart_ban 应写入 ban.txt
$r = run_case('8.8.8.8', [], false, 'smart_ban');
$ok = !empty($r['ban']) && strpos($r['ban'], '8.8.8.8') !== false;
echo "[1] 默认模式 smart_ban → ban.txt 应有 IP: " . ($ok ? '✅' : '❌') . "\n";
echo "    ban.txt: " . trim((string)$r['ban']) . "\n";
echo "    out: " . $r['out'] . "\n\n";

// 测试2：白名单 IP smart_ban 应跳过
$r = run_case('8.8.8.8', ['8.8.8.8'], false, 'smart_ban');
$ok = empty($r['ban']) || strpos($r['ban'], '8.8.8.8') === false;
echo "[2] 白名单IP smart_ban → 不应封禁: " . ($ok ? '✅' : '❌') . "\n";
echo "    ban.txt: " . (empty($r['ban']) ? '(空)' : trim($r['ban'])) . "\n\n";

// 测试3：测试模式 smart_ban 应记录到 test_mode_ban.log
$r = run_case('8.8.8.8', [], true, 'smart_ban');
$ok = empty($r['ban']) && !empty($r['test_log']);
echo "[3] 测试模式 smart_ban → 不封禁但记录 test_mode_ban.log: " . ($ok ? '✅' : '❌') . "\n";
echo "    ban.txt: " . (empty($r['ban']) ? '(空)' : trim($r['ban'])) . "\n";
echo "    test_mode_ban.log: " . trim((string)$r['test_log']) . "\n\n";

// 测试4：CIDR 网段
$r = run_case('10.1.2.3', ['10.0.0.0/8'], false, 'smart_ban');
$ok = empty($r['ban']) || strpos($r['ban'], '10.1.2.3') === false;
echo "[4] CIDR 10.0.0.0/8 命中 10.1.2.3: " . ($ok ? '✅' : '❌') . "\n";
echo "    ban.txt: " . (empty($r['ban']) ? '(空)' : trim($r['ban'])) . "\n\n";

// 测试5：测试模式 is_banned，历史 ban 不应拦截
// extra_code 只做 setup（写 ban.txt），不输出，由 stub 的 case 'is_banned' 统一输出
$waf_logs = $waf_dir . '/logs';
$extra = "@mkdir('$waf_logs',0775,true); @file_put_contents('$waf_logs/ban.txt','8.8.8.8|'.(time()+3600).\"\\n\");";
$r = run_case('8.8.8.8', [], true, 'is_banned', $extra);
$ok = $r['out'] === 'NOT_BANNED';
echo "[5] 测试模式 is_banned 历史ban不拦截: " . ($ok ? '✅' : '❌') . " (" . $r['out'] . ")\n\n";

// 测试6：默认模式 is_banned 应拦截
$r = run_case('8.8.8.8', [], false, 'is_banned', $extra);
$ok = $r['out'] === 'BANNED';
echo "[6] 默认模式 is_banned 历史ban拦截: " . ($ok ? '✅' : '❌') . " (" . $r['out'] . ")\n\n";

// 测试7：白名单 IP is_banned 不拦截
$r = run_case('8.8.8.8', ['8.8.8.8'], false, 'is_banned', $extra);
$ok = $r['out'] === 'NOT_BANNED';
echo "[7] 白名单IP is_banned 不拦截: " . ($ok ? '✅' : '❌') . " (" . $r['out'] . ")\n\n";

// 测试8：waf_ban 测试模式
$r = run_case('8.8.8.8', [], true, 'ban');
$ok = empty($r['ban']) && !empty($r['test_log']);
echo "[8] 测试模式 waf_ban → 不封禁但记录日志: " . ($ok ? '✅' : '❌') . "\n";
echo "    ban.txt: " . (empty($r['ban']) ? '(空)' : trim($r['ban'])) . "\n";
echo "    test_mode_ban.log: " . trim((string)$r['test_log']) . "\n\n";

// 测试9：waf_is_admin_ip 常量
$r = run_case('8.8.8.8', ['8.8.8.8'], false, 'is_admin');
$ok = $r['out'] === 'ADMIN';
echo "[9] WAF_ADMIN_IPS=['8.8.8.8'] is_admin_ip('8.8.8.8'): " . ($ok ? '✅' : '❌') . " (" . $r['out'] . ")\n\n";

// 测试10：CIDR is_admin
$r = run_case('10.1.2.3', ['10.0.0.0/8'], false, 'is_admin');
$ok = $r['out'] === 'ADMIN';
echo "[10] WAF_ADMIN_IPS=['10.0.0.0/8'] is_admin_ip('10.1.2.3'): " . ($ok ? '✅' : '❌') . " (" . $r['out'] . ")\n\n";

// 测试11：非白名单 is_admin
$r = run_case('1.2.3.4', ['8.8.8.8'], false, 'is_admin');
$ok = $r['out'] === 'NOT_ADMIN';
echo "[11] WAF_ADMIN_IPS=['8.8.8.8'] is_admin_ip('1.2.3.4') 应为 NOT_ADMIN: " . ($ok ? '✅' : '❌') . " (" . $r['out'] . ")\n\n";

echo "===== 测试完成 =====\n";
