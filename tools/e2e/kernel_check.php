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
 * 加密内核进程内验收：直接调用 YslWaf::inspectCurrentRequest()，
 * 验证「decrypt → 解析 → 证据 → 仲裁」整条链路真的能给出正确决策，
 * 而不是「文件能被 require 就算过」。
 *
 * 用法：php tools/e2e/kernel_check.php <waf_root> <log_dir>
 */
declare(strict_types=1);

$root = rtrim((string)($argv[1] ?? dirname(__DIR__, 2)), '/');
$log  = rtrim((string)($argv[2] ?? $root . '/var/logs'), '/');
@mkdir($log, 0775, true);

// 与 shield-waf.php 一致的引导常量：AI 层与 Support/Functions.php 都以此作为「已加载」判据，
// 缺了会直接 exit（静默退出，退出码 0），这里必须提前定义。
if (!defined('ABSPATH')) {
    define('ABSPATH', $root . '/');
}
if (!defined('WAF_HOME')) {
    define('WAF_HOME', $root);
}

require_once $root . '/core/YslWaf.php';

// ---------------------------------------------------------------- AI 层
$aiOk = false;
if (is_file($root . '/ai/bootstrap.php')) {
    try {
        require_once $root . '/ai/bootstrap.php';
        $aiOk = class_exists('Learning_TrainingScheduler')
             && class_exists('Learning_SampleCollector')
             && class_exists('AutoLearn');
    } catch (Throwable $e) {
        fwrite(STDERR, "  AI 层加载异常：" . $e->getMessage() . PHP_EOL);
    }
}

// ---------------------------------------------------------------- 判定用例
$cases = [
    // [名称, method, uri, params, ua, 期望 action]
    ['正常请求',        'GET',  '/?page=2&kw=防火墙',                    ['page' => '2', 'kw' => '防火墙'], '', 'allow'],
    ['SQL 注入 UNION',  'GET',  '/?id=1%20UNION%20SELECT%20pass%20FROM%20admin', ['id' => '1 UNION SELECT pass FROM admin'], '', 'block'],
    ['SQL 注入 闭合',   'GET',  '/?id=1%27%20OR%20%271%27%3D%271',       ['id' => "1' OR '1'='1"], '', 'block'],
    ['XSS script',      'GET',  '/?q=<script>alert(1)</script>',         ['q' => '<script>alert(1)</script>'], '', 'block'],
    ['XSS onerror',     'GET',  '/?q=<img src=x onerror=alert(1)>',      ['q' => '<img src=x onerror=alert(1)>'], '', 'block'],
    ['路径穿越',        'GET',  '/?file=../../../../etc/passwd',          ['file' => '../../../../etc/passwd'], '', 'block'],
    ['命令注入',        'GET',  '/?cmd=;cat%20/etc/passwd',              ['cmd' => ';cat /etc/passwd'], '', 'block'],
    ['正常中文路径',    'GET',  '/article/' . rawurlencode('安全周报'),   [], '', 'allow'],
];

$pass = 0;
$fail = 0;
printf("  %-16s %-8s %-8s %-6s %s\n", '用例', '决策', '期望', '分值', '命中原因');
printf("  %s\n", str_repeat('-', 66));

foreach ($cases as $c) {
    [$name, $method, $uri, $params, $ua, $want] = $c;

    $_SERVER['REQUEST_METHOD'] = $method;
    $_SERVER['REQUEST_URI']    = $uri;
    $_SERVER['REMOTE_ADDR']    = '203.0.113.' . random_int(2, 250);
    $_SERVER['HTTP_USER_AGENT'] = $ua;
    $_GET  = $params;
    $_POST = [];

    $r = YslWaf::inspectCurrentRequest([
        'log_path' => $log,
        'mode'     => 'enforce',
    ]);

    $action = (string)($r['action'] ?? '?');
    // 放行面：allow 与 monitor 都是「不拦截」，两者都算通过；拦截面必须是 block
    $ok = in_array($want, ['allow', 'monitor'], true)
        ? in_array($action, ['allow', 'monitor'], true)
        : $action === 'block';
    $ok ? $pass++ : $fail++;

    printf(
        "  %-16s %-8s %-8s %-6s %s\n",
        $name,
        ($ok ? '' : '✗ ') . $action,
        is_array($want) ? '任一' : $want,
        (string)($r['score'] ?? '-'),
        (string)($r['reason'] ?? '-')
    );
}

printf("  %s\n", str_repeat('-', 66));
printf("  内核决策：%d/%d 正确，AI 层：%s\n", $pass, $pass + $fail, $aiOk ? '已加载' : '未加载');

exit(($fail === 0 && $aiOk) ? 0 : 1);
