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
 * YSL语枢-盾甲WAF · 控制台按钮端到端验收（Docker / 真实 HTTP / 真实落盘）
 *
 *   php tests/control_check.php [base_url]
 *
 * 不是「按钮存在就算过」：每个动作都验证
 *   ① 响应 ok 与回读状态 ② 运行时行为真的变了（observe / 白名单 / 误报复核）
 *   ③ 危险动作必须二次确认 ④ 测试结束把环境恢复原状。
 */
declare(strict_types=1);

// 可配置（v6.5.1）：CI / 任意环境可用 argv[1] 或 WAF_TEST_BASE / WAF_TEST_HOME 覆盖；
// 未指定时沿用官方容器 e2e 的 /app:8080，行为与旧版完全一致。
$base = rtrim((string)($argv[1] ?? (getenv('WAF_TEST_BASE') ?: 'http://127.0.0.1:8080')), '/');
$home = rtrim((string)(getenv('WAF_TEST_HOME') ?: (is_dir('/app/core') ? '/app' : dirname(__DIR__))), '/');
require_once $home . '/runtime.php';
$keyFile = wafCtlKeyFile($home, '/dev/shm/waf-data');
$KEY = trim((string)@file_get_contents($keyFile));
$CSRF = wafCtlToken($KEY);

$pass = 0; $fail = 0;
function ck(string $n, bool $c): void {
    global $pass, $fail;
    if ($c) { $pass++; echo "  PASS  $n\n"; } else { $fail++; echo "  FAIL  $n\n"; }
}
function http(string $url, ?array $post = null): array {
    $h = ['Content-Type: application/x-www-form-urlencoded'];
    $opt = ['http' => ['timeout' => 20, 'ignore_errors' => true, 'header' => implode("\r\n", $h)]];
    if ($post !== null) {
        $opt['http']['method'] = 'POST';
        $opt['http']['content'] = http_build_query($post);
    }
    $ctx = stream_context_create($opt);
    $body = (string)@file_get_contents($url, false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $line, $m)) { $code = (int)$m[1]; }
    }
    if ($code === 0) {
        $body = '[NO_RESPONSE] ' . json_encode(error_get_last(), JSON_UNESCAPED_UNICODE) . ' | ' . $body;
    }
    return [$code, $body];
}
function act(string $action, array $params = [], bool $confirm = false, ?string $key = null, ?string $csrf = null): array {
    global $base, $KEY, $CSRF;
    [$code, $body] = http($base . '/waf-control', [
        'key'     => $key ?? $KEY,
        'csrf'    => $csrf ?? $CSRF,
        'action'  => $action,
        'params'  => json_encode($params, JSON_UNESCAPED_UNICODE),
        'confirm' => $confirm ? '1' : '0',
    ]);
    $j = json_decode($body, true);
    return [$code, is_array($j) ? $j : ['ok' => false, 'raw' => substr($body, 0, 200)]];
}
function page(string $path): array {
    global $base;
    return http($base . $path);
}
function attack(string $qs = "?id=1%27%20OR%201%3D1--"): int {
    [$code] = page('/' . $qs);
    return $code;
}

echo "== 0) 前置：页面、控制台与鉴权矩阵 ==\n";
[$sc, $html] = page('/waf-screen?key=' . rawurlencode($KEY));
ck('大屏 200 且含控制台抽屉', $sc === 200 && str_contains($html, 'id="ctlDrawer"'));
preg_match_all('/data-act="([a-z.]+)"/', $html, $am);
ck('大屏控制按钮 >= 35 个（实际 ' . count($am[1]) . '）', count($am[1]) >= 35);
ck('页面内嵌 CSRF token', str_contains($html, 'var CTL_CSRF = "' . $CSRF . '"'));
[$cc, $console] = page('/waf-console?key=' . rawurlencode($KEY));
ck('控制台 200 且含零 JS 表单', $cc === 200 && str_contains($console, 'action="/waf-control"'));
[$sc2, $static] = page('/waf-screen?key=' . rawurlencode($KEY) . '&static=1');
ck('静态快照不含密钥', $sc2 === 200 && !str_contains($static, $KEY));
ck('静态快照 CSRF 为空', str_contains($static, 'var CTL_CSRF = ""'));

[$c, $j] = act('state.get');
ck('state.get 返回真实运行状态', $c === 200 && !empty($j['ok']) && isset($j['state']['runtime']));
[$c] = http($base . '/waf-control');
ck('GET 控制端点 -> 405', $c === 405);
[$c] = act('state.get', [], false, '', $CSRF);
ck('空密钥 -> 403', $c === 403);
[$c] = act('state.get', [], false, 'wrong-key', $CSRF);
ck('错误密钥 -> 403', $c === 403);
[$c] = act('state.get', [], false, $KEY, 'bad-csrf');
ck('错误 CSRF -> 403', $c === 403);
[$c] = act('no.such.action');
ck('未知动作 -> 400', $c === 400);
[$c] = act('logs.purge');
ck('危险动作未确认 -> 400', $c === 400);

echo "== 1) 运行配置：回读 + 真实防护行为 ==\n";
[$c, $j] = act('mode.set', ['value' => 'observe']);
ck('切换到 observe 并回读', $c === 200 && ($j['state']['runtime']['mode'] ?? '') === 'observe');
$a1 = attack();
ck('observe 下注入请求放行 200', $a1 === 200);
[$c, $j] = act('mode.set', ['value' => 'enforce']);
ck('切回 enforce 并回读', $c === 200 && ($j['state']['runtime']['mode'] ?? '') === 'enforce');
$a2 = attack();
ck('enforce 下同一注入被拦 403', $a2 === 403);

[$c, $j] = act('guard.set', ['name' => 'fp', 'on' => '0']);
ck('关闭叙述性误报复核并回读', $c === 200 && ($j['state']['runtime']['guards']['fp'] ?? true) === false);
[$bc] = page('/?q=The%20union%20of%20two%20sets%20A%20and%20B');
ck('关闭后叙述性 benign 文本被拦 403', $bc === 403);
[$c, $j] = act('guard.set', ['name' => 'fp', 'on' => '1']);
ck('重新开启误报复核', $c === 200 && ($j['state']['runtime']['guards']['fp'] ?? false) === true);
[$bc2] = page('/?q=The%20union%20of%20two%20sets%20A%20and%20B');
ck('恢复后 benign 文本 200', $bc2 === 200);

foreach (['ai', 'tautology', 'bypass', 'errors'] as $g) {
    [$c, $j] = act('guard.set', ['name' => $g, 'on' => '0']);
    $off = ($j['state']['runtime']['guards'][$g] ?? null) === false;
    [$c2, $j2] = act('guard.set', ['name' => $g, 'on' => '1']);
    $on = ($j2['state']['runtime']['guards'][$g] ?? null) === true;
    ck('开关 ' . $g . ' 关 / 开双向回读', $c === 200 && $off && $c2 === 200 && $on);
}
[$c, $j] = act('config.body_max', ['value' => 1048576]);
ck('body 上限写入并回读', $c === 200 && ($j['state']['runtime']['body_max'] ?? 0) === 1048576);
[$c, $j] = act('config.body_max', ['value' => 8388608]);
ck('body 上限恢复默认', $c === 200 && ($j['state']['runtime']['body_max'] ?? 0) === 8388608);
[$c] = act('config.body_max', ['value' => 999999999]);
ck('非法 body 上限被拒', $c === 400);

[$c, $j] = act('whitelist.add', ['cidr' => '127.0.0.1']);
ck('白名单加入并回读', $c === 200 && in_array('127.0.0.1', $j['state']['runtime']['whitelist'] ?? [], true));
[$wcode, $wbody] = page('/?id=1%27%20OR%201%3D1--');
ck('白名单内 IP 硬旁路生效 200', $wcode === 200);
if ($wcode !== 200) {
    echo '    DEBUG 白名单攻击码=', var_export($wcode, true), ' body=', substr($wbody, 0, 400),
         ' runtime=', (string)@file_get_contents($home . '/var/data/runtime.json'), "\n";
}
[$c, $j] = act('whitelist.del', ['cidr' => '127.0.0.1']);
ck('白名单移除并回读', $c === 200 && !in_array('127.0.0.1', $j['state']['runtime']['whitelist'] ?? [], true));
ck('移出白名单后恢复拦截 403', attack() === 403);
[$c] = act('whitelist.add', ['cidr' => 'not-an-ip']);
ck('非法 CIDR 被拒', $c === 400);

echo "== 2) 熔断 / 状态文件 / AI / 日志 ==\n";
[$c, $j] = act('circuit.open', [], true);
ck('熔断演练后回读为熔断态', $c === 200 && ($j['state']['circuit']['state'] ?? '') === 'open');
[$sc3, $html3] = page('/waf-screen?key=' . rawurlencode($KEY) . '&format=json');
$jc = json_decode($html3, true);
ck('大屏熔断状态同步且已中文化', $sc3 === 200 && str_contains((string)($jc['circuit_note'] ?? ''), '熔断中')
    && !str_contains((string)($jc['circuit_note'] ?? ''), 'open'));
[$c, $j] = act('circuit.reset');
ck('熔断复位后回读为正常态', $c === 200 && ($j['state']['circuit']['state'] ?? '') === 'closed');
[$c, $j] = act('circuit.close');
ck('强制关闭熔断', $c === 200 && ($j['state']['circuit']['state'] ?? '') === 'closed');

foreach (['windows.clear', 'chains.clear', 'honeypot.clear', 'locks.clear',
          'ai.queues.clear', 'ai.fingerprints.clear'] as $a) {
    [$c, $j] = act($a);
    ck('动作 ' . $a . ' 执行成功', $c === 200 && !empty($j['ok']));
    if ($c !== 200 || empty($j['ok'])) { echo '    DEBUG ', $a, ' code=', $c, ' resp=', substr(json_encode($j, JSON_UNESCAPED_UNICODE), 0, 400), "\n"; }
}
[$c, $j] = act('ai.model.reset', [], true);
ck('重置贝叶斯模型（需确认）', $c === 200 && !empty($j['ok']));

// 日志类动作会改动 attack.log：整体备份后恢复，不破坏大屏真实数据
$logFiles = array_values(array_unique([
    '/dev/shm/waf-logs/ysl/attack.log', $home . '/logs/ysl/attack.log',
]));
$bak = [];
foreach ($logFiles as $f) { $bak[$f] = is_file($f) ? (string)@file_get_contents($f) : null; }
[$c, $j] = act('logs.export');
ck('导出 jsonl 成功', $c === 200 && !empty($j['ok']) && str_contains((string)($j['detail'] ?? ''), 'export_'));
[$c, $j] = act('logs.rotate');
ck('归档 attack.log 成功', $c === 200 && !empty($j['ok']));
[$c, $j] = act('logs.purge', [], true);
ck('清空 attack.log（需确认）成功', $c === 200 && !empty($j['ok']));
foreach ($logFiles as $f) {
    if ($bak[$f] !== null) { @file_put_contents($f, $bak[$f], LOCK_EX); }
}
ck('日志已按备份原样恢复', (int)@filesize($logFiles[0]) === strlen((string)$bak[$logFiles[0]]));

echo "== 3) 文件 DNA：独立 CLI 真实执行 ==\n";
foreach (['dna.plan', 'dna.status', 'dna.selftest', 'dna.scan', 'dna.audit'] as $a) {
    [$c, $j] = act($a);
    ck('DNA ' . $a . ' 执行成功', $c === 200 && !empty($j['ok']));
}
[$c, $j] = act('dna.selftest');
ck('DNA 自检输出 19/19', str_contains((string)($j['detail'] ?? ''), 'SELFTEST PASS (19/19)'));
[$c, $j] = act('dna.restore', ['file' => '../etc/passwd'], true);
ck('非法还原路径被拒', $c === 400);
[$c, $j] = act('dna.restore', ['file' => 'demo/index.php'], true);
ck('合法还原路径执行成功', $c === 200 && !empty($j['ok']));
foreach (['dna.baseline', 'dna.rebaseline', 'dna.apply'] as $a) {
    [$c, $j] = act($a, [], true);
    ck('DNA ' . $a . '（需确认）执行成功', $c === 200 && !empty($j['ok']));
}
[$c, $j] = act('dna.watch.stop', [], true);
ck('停止 DNA 守护', $c === 200 && !empty($j['ok']) && empty($j['state']['dna']['watch_pid']));
[$c, $j] = act('dna.watch.start');
$pid = (int)($j['state']['dna']['watch_pid'] ?? 0);
ck('启动 DNA 守护并回读 PID', $c === 200 && $pid > 0);
ck('守护进程真实存活', $pid > 0 && wafCtlWatchAlive($pid));

echo "== 4) 访问控制 / 恢复出厂 / 审计 ==\n";
[$c, $j] = act('key.rotate', [], true);
$newKey = (string)($j['new_key'] ?? '');
ck('轮换密钥返回新 key + 新 CSRF', $c === 200 && strlen($newKey) === 32 && !empty($j['new_csrf']));
[$oldCode] = page('/waf-screen?key=' . rawurlencode($KEY));
[$newCode] = page('/waf-screen?key=' . rawurlencode($newKey));
ck('旧 key 立即 403 / 新 key 200', $oldCode === 403 && $newCode === 200);
// 测试收尾：把原密钥写回两处，保证交付链接不变
foreach (array_values(array_unique([$keyFile, $home . '/var/data/console.key'])) as $f) {
    @file_put_contents($f, $KEY . "\n", LOCK_EX);
    @chmod($f, 0600);
}
[$r1] = page('/waf-screen?key=' . rawurlencode($KEY));
[$r2] = page('/waf-screen?key=' . rawurlencode($newKey));
ck('原密钥已恢复，轮换出的 key 失效', $r1 === 200 && $r2 === 403);

[$c, $j] = act('runtime.reset', [], true);
$rt = $j['state']['runtime'] ?? [];
ck('恢复出厂配置并回读（含 errors 关）', $c === 200 && ($rt['mode'] ?? '') === 'enforce'
    && ($rt['body_max'] ?? 0) === 8388608 && ($rt['whitelist'] ?? [1]) === []
    && ($rt['guards']['ai'] ?? false) === true && ($rt['guards']['fp'] ?? false) === true
    && ($rt['guards']['errors'] ?? true) === false);
[$c, $j] = act('control.audit');
ck('控制审计可读且含本次动作', $c === 200 && count($j['audit'] ?? []) >= 5);
ck('最终注入请求仍被拦截', attack() === 403);
[$c, $j] = act('state.get');
ck('最终 DNA 守护在运行', !empty($j['state']['dna']['watch_pid']));
// 测试收尾：移除运行时覆盖文件，环境回到「未配置」的初始状态
@unlink(wafRtPath($home));
ck('运行时覆盖已清理，环境复位', !is_file(wafRtPath($home)));

echo "\n结果：PASS $pass / FAIL $fail\n";
exit($fail === 0 ? 0 : 1);
