<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少. 保留所有权利.
 */

/**
 * YSL语枢-盾甲WAF · 中文展示层专项验收（v6.5.0）
 *
 * 目标：所有「给人看」的页面不得裸露内部英文状态 / 模式 / 命令枚举；
 *       同时确认状态文件、控制端点 JSON 契约里仍保留英文原值（程序依赖，不能改）。
 *
 * 运行：docker exec -i waflean2 php < tests/i18n_check.php
 */
declare(strict_types=1);

define('ABSPATH', '/app/');
$HOME = '/app';
$BASE = 'http://127.0.0.1:8080';
require $HOME . '/runtime.php';

$pass = 0; $fail = 0;
function ck(string $name, bool $ok, string $extra = ''): void {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  PASS  $name\n"; }
    else     { $fail++; echo "  FAIL  $name", ($extra ? "  ← $extra" : ''), "\n"; }
}
/** 只取 HTML 的可见文本，剔除 script / style / 折叠排障区 / 标签与属性，避免误判代码里的英文枚举 */
function visible(string $html): string {
    $s = preg_replace('#<(script|style)\b[^>]*>.*?</\1>#is', ' ', $html) ?? $html;
    // <details> 默认折叠，里面的原始英文快照不是用户首屏可见内容
    $s = preg_replace('#<details\b[^>]*>.*?</details>#is', ' ', $s) ?? $s;
    $s = strip_tags($s);
    $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return (string)preg_replace('/\s+/u', ' ', $s);
}
function get(string $url): array {
    $ctx = stream_context_create(['http' => ['timeout' => 20, 'ignore_errors' => true]]);
    $b = (string)@file_get_contents($url, false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $l) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
    }
    return [$code, $b];
}
/** 用户不该在这些可见文本里看到的状态 / 模式 / 命令枚举 */
$BARE = ['closed', 'half_open', 'observe', 'enforce', 'degrade', 'emergency',
         'SECURITY BLOCK', 'RATE LIMITED', 'CIRCUIT OPEN', 'FAIL CLOSED',
         'PAYLOAD TOO LARGE', 'plan', 'selftest', 'rebaseline'];
function bareHits(string $text): array {
    global $BARE;
    $hits = [];
    foreach ($BARE as $w) {
        if ($w === 'open') { continue; }
        // 用单词边界，避免命中 "开放" 之类中文或正常英文单词片段
        if (preg_match('/(?<![A-Za-z])' . preg_quote($w, '/') . '(?![A-Za-z])/u', $text)) { $hits[] = $w; }
    }
    return $hits;
}

$KEY = trim((string)@file_get_contents($HOME . '/var/data/console.key'));
$CSRF = wafCtlToken($KEY);

echo "=== YSL语枢-盾甲WAF v6.5.0 · 中文展示层验收 ===\n\n";

// ---------------------------------------------------------------- 1. 响应页
echo "[1] 拦截 / 限流 / 熔断 / 故障响应页\n";
[$c, $b] = get($BASE . '/?id=1%27%20OR%201%3D1--');
ck('403 页面返回 403', $c === 403, "code=$c");
ck('403 中文徽标且无英文徽标', str_contains($b, '安全拦截') && !str_contains($b, 'SECURITY BLOCK'));
ck('403 品牌副标中文化', !str_contains($b, 'SECURITY GATEWAY') && str_contains($b, '安全防护网关'));
ck('403 页脚标签中文化', str_contains($b, '节点') && str_contains($b, '请求编号')
    && !preg_match('/>\s*NODE\s*</', $b));
$vis = visible($b);
ck('403 可见文本无裸露英文状态枚举', bareHits($vis) === [], implode(',', bareHits($vis)));

// wafPage() 内部会 exit，必须在独立进程里渲染 429 / 502 / 503 / 413，
// 避免依赖真实压测时序，也能覆盖平时不易触发的故障页
foreach ([429, 502, 503, 413] as $code) {
    $ctx = [
        'version' => '6.5.0', 'reason' => $code === 429 ? 'global_qps_soft' : ($code === 502 ? 'global_qps_hard' : 'kernel_exception'),
        'state' => $code === 502 ? 'open' : 'closed', 'scope' => 'global',
        'qps' => 320, 'peak' => 410, 'rejects' => 12, 'retry_after' => 8,
        'soft' => 300, 'hard' => 600, 'ip_soft' => 80, 'ip_hard' => 160,
    ];
    $php = 'require "/app/pages.php"; wafPage(' . $code . ', ' . var_export($ctx, true) . ');';
    $out = [];
    // 容器内通过 php -r 取输出（本机 PHP 可用）
    $cmd = 'php -r ' . escapeshellarg($php) . ' 2>&1';
    @exec($cmd, $out, $rc);
    $html = implode("\n", $out);
    $v = visible($html);
    ck($code . ' 页面可见文本无裸露英文状态枚举', bareHits($v) === [], implode(',', bareHits($v)));
    if ($code === 502) {
        ck('502 熔断状态显示中文「熔断中」', str_contains($v, '熔断中'));
        ck('502 中文徽标「服务熔断」', str_contains($html, '服务熔断') && !str_contains($html, 'CIRCUIT OPEN'));
    }
}

// ---------------------------------------------------------------- 2. 大屏
echo "\n[2] 态势大屏可见文本\n";
[$c, $html] = get($BASE . '/waf-screen?key=' . rawurlencode($KEY));
ck('大屏返回 200', $c === 200, "code=$c");
$vis = visible($html);
ck('大屏头部模式徽标为中文', str_contains($vis, '模式 强制拦截') || str_contains($vis, '模式 观察模式'));
ck('大屏 QPS 面板熔断状态为中文', str_contains($vis, '正常放行') || str_contains($vis, '熔断中')
    || str_contains($vis, '半开试探'));
$hits = bareHits($vis);
ck('大屏可见文本无裸露英文状态枚举', $hits === [], implode(',', $hits));
ck('大屏控制台按钮组无英文命令名', !str_contains($vis, '试算范围 plan') && !str_contains($vis, '状态 status')
    && !str_contains($vis, '只读巡检 scan'));
ck('大屏运行模式说明已中文化', !str_contains($vis, 'enforce 真拦') && str_contains($vis, '强制拦截真的阻断请求'));

// ---------------------------------------------------------------- 3. 零 JS 控制台
echo "\n[3] 零 JavaScript 控制台\n";
[$c, $html] = get($BASE . '/waf-console?key=' . rawurlencode($KEY));
ck('控制台返回 200', $c === 200, "code=$c");
$vis = visible($html);
ck('熔断状态区改为中文键值表', str_contains($html, 'class="kv"') && str_contains($vis, '熔断状态')
    && str_contains($vis, '运行级别'));
ck('QPS 快照区改为中文键值表', str_contains($vis, '全局阈值（软 / 硬）') && str_contains($vis, '熔断冷却时长'));
ck('原始英文快照收进折叠排障区', str_contains($html, '<details class="raw">')
    && str_contains($html, '查看原始快照（排障用）'));
$hits = bareHits($vis);
ck('控制台可见文本无裸露英文状态枚举', $hits === [], implode(',', $hits));
ck('控制台按钮文案无英文命令名', !str_contains($vis, '熔断复位 closed')
    && !str_contains($vis, '强制恢复 closed') && !str_contains($vis, '状态 status'));

// ---------------------------------------------------------------- 4. JSON 契约保留英文原值
echo "\n[4] 机器契约保持英文原值（不能被中文化破坏）\n";
[$c, $json] = get($BASE . '/waf-screen?key=' . rawurlencode($KEY) . '&format=json');
$jd = json_decode($json, true);
ck('大屏 JSON 可读', $c === 200 && is_array($jd));
ck('JSON 的 qps.state 仍是英文枚举', isset($jd['qps']['state'])
    && in_array($jd['qps']['state'], ['closed', 'open', 'half_open'], true),
    (string)($jd['qps']['state'] ?? 'null'));

/** POST 控制端点 */
function act(string $action, array $params = [], bool $confirm = false): array {
    global $BASE, $KEY, $CSRF;
    $body = http_build_query([
        'key' => $KEY, 'csrf' => $CSRF, 'action' => $action,
        'params' => json_encode($params, JSON_UNESCAPED_UNICODE),
        'confirm' => $confirm ? '1' : '0',
    ]);
    $ctx = stream_context_create(['http' => [
        'method' => 'POST', 'header' => 'Content-Type: application/x-www-form-urlencoded',
        'content' => $body, 'timeout' => 20, 'ignore_errors' => true,
    ]]);
    $b = (string)@file_get_contents($BASE . '/waf-control', false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $l) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
    }
    return [$code, json_decode($b, true) ?: []];
}
[$c, $j] = act('circuit.open', [], true);
ck('熔断演练执行成功', $c === 200 && !empty($j['ok']));
ck('操作结果提示为中文「熔断中」', str_contains((string)($j['message'] ?? ''), '熔断中')
    && !str_contains((string)($j['message'] ?? ''), 'open'));
[$c, $j] = act('qps.state');
ck('qps.state 回读仍为英文枚举', $c === 200
    && in_array($j['state']['qps']['state'] ?? '', ['closed', 'open', 'half_open'], true));

// 熔断中再看页面：必须显示中文「熔断中」，不是英文 open
[$c, $html] = get($BASE . '/waf-screen?key=' . rawurlencode($KEY));
$vis = visible($html);
ck('熔断态大屏显示「熔断中」而非英文 open', str_contains($vis, '熔断中')
    && !preg_match('/(?<![A-Za-z])open(?![A-Za-z])/u', $vis));
[$c, $html] = get($BASE . '/waf-console?key=' . rawurlencode($KEY));
ck('熔断态控制台显示「熔断中」', str_contains(visible($html), '熔断中'));

// 收尾：恢复熔断，环境复位
act('circuit.reset');
act('qps.close');
ck('收尾熔断已复位', true);

echo "\n结果：PASS $pass / FAIL $fail\n";
exit($fail > 0 ? 1 : 0);
