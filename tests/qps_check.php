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
 * YSL语枢-盾甲WAF · QPS 限流 / 熔断 + 美化响应页 端到端验收（v6.4.0）
 *
 * 用法（容器内）：php tests/qps_check.php
 * 全部通过真实 HTTP 请求与真实落盘状态验证，不 mock、不改 core/。
 */
declare(strict_types=1);

// 可配置（v6.5.1）：CI / 任意环境可用 argv[1] 或 WAF_TEST_BASE / WAF_TEST_HOME 覆盖；
// 未指定时沿用官方容器 e2e 的 /app:8080，行为与旧版完全一致。
// 用 define() 而非 const：保持下方函数内对 BASE 的全局常量引用不变。
$wafTestBase = rtrim((string)($argv[1] ?? (getenv('WAF_TEST_BASE') ?: 'http://127.0.0.1:8080')), '/');
$home = rtrim((string)(getenv('WAF_TEST_HOME') ?: (is_dir('/app/core') ? '/app' : dirname(__DIR__))), '/');
define('BASE', $wafTestBase);
require_once $home . '/runtime.php';
$logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (getenv('WAF_LOG_DIR') ?: $home . '/var/logs');
$key    = trim((string)@file_get_contents($home . '/var/data/console.key'));
$csrf   = wafCtlToken($key);
$pass = 0; $fail = 0;

function ck(string $name, bool $ok, string $extra = ''): void {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  PASS  ", $name, "\n"; }
    else     { $fail++; echo "  FAIL  ", $name, ($extra ? '  ← ' . $extra : ''), "\n"; }
}
function act(string $action, array $params = [], bool $confirm = false): array {
    global $key, $csrf;
    $ctx = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query([
            'key' => $key, 'csrf' => $csrf, 'action' => $action,
            'params' => json_encode($params), 'confirm' => $confirm ? '1' : '0',
        ]),
        'ignore_errors' => true, 'timeout' => 20,
    ]]);
    $body = (string)@file_get_contents(BASE . '/waf-control', false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $l) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
    }
    $j = json_decode($body, true);
    return [$code, is_array($j) ? $j : ['raw' => substr($body, 0, 300)]];
}
/** 返回 [状态码, 响应头数组(小写键), 响应体] */
function page(string $path): array {
    $ctx = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 20]]);
    $body = (string)@file_get_contents(BASE . $path, false, $ctx);
    $code = 0; $heads = [];
    foreach ($http_response_header ?? [] as $l) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
        elseif (str_contains($l, ':')) {
            [$k, $v] = explode(':', $l, 2);
            $heads[strtolower(trim($k))] = trim($v);
        }
    }
    return [$code, $heads, $body];
}
function resetAll(): void {
    global $home;
    @unlink(wafRtPath($home));
    act('qps.reset');
}

echo "=== YSL语枢-盾甲WAF v6.5.0 · QPS 与响应页验收 ===\n\n";
resetAll();

// ---------------------------------------------------------------- 1. 403 美化页
echo "[1] 403 安全拦截页\n";
[$c, $h, $b] = page('/?id=1%27%20OR%201%3D1--');
ck('攻击返回 403', $c === 403, "code=$c");
ck('Content-Type 为 text/html（不再是纯文本）', str_contains($h['content-type'] ?? '', 'text/html'));
ck('含中文标题「访问已被拦截」', str_contains($b, '访问已被拦截'));
ck('含真实拦截原因中文映射', str_contains($b, '拦截原因') && preg_match('/拦截原因<\/div><div class="v">[^\x00-\x7F]/u', $b) === 1,
   '实际值见规则标识');
ck('同时保留原始规则标识便于取证', str_contains($b, '规则标识') && str_contains($b, 'core_evidence_taint'));
ck('风险等级已中文化（不裸露 critical）', str_contains($b, '危急')
    && !preg_match('/风险等级<\/div><div class="v">critical/', $b));
ck('含请求编号 / 时间 / 客户端地址 / 路径', str_contains($b, '请求编号') && str_contains($b, '客户端地址') && str_contains($b, '请求路径'));
ck('含品牌与版本号', str_contains($b, 'YSL语枢-盾甲WAF') && str_contains($b, '6.5.0'));
ck('严格 CSP（script-src none）', str_contains($h['content-security-policy'] ?? '', "script-src 'none'"));
ck('no-store / nosniff / DENY', str_contains($h['cache-control'] ?? '', 'no-store')
    && ($h['x-content-type-options'] ?? '') === 'nosniff' && ($h['x-frame-options'] ?? '') === 'DENY');
ck('带 X-WAF-Request-Id', ($h['x-waf-request-id'] ?? '') !== '');
ck('零外部资源（无 http 链接、无 <script）', !str_contains($b, '<script') && !preg_match('#(src|href)="https?://#i', $b));
[$c2] = page('/?id=12');
ck('正常请求仍为 200', $c2 === 200, "code=$c2");

// ---------------------------------------------------------------- 2. 大屏 / 控制台
echo "\n[2] 大屏 QPS 面板与 JSON\n";
$k = $key;
[$c, $h, $b] = page('/waf-screen?key=' . rawurlencode($k));
ck('大屏返回 200', $c === 200, "code=$c");
ck('大屏含 QPS 限流与熔断面板', str_contains($b, 'QPS 限流与熔断'));
ck('大屏含 QPS 指示灯组与底栏汇总灯', str_contains($b, 'QPS 指示灯') && str_contains($b, 'qps-lamps')
    && str_contains($b, 'QPS 熔断'));
ck('大屏含 QPS 控制台分组', str_contains($b, 'data-act="qps.config"') && str_contains($b, 'data-multi='));
[$c, $h, $j] = page('/waf-screen?key=' . rawurlencode($k) . '&format=json');
$jd = json_decode($j, true);
ck('JSON 含 qps 与 qps_lamps', is_array($jd) && isset($jd['qps']['state'], $jd['qps_lamps'][0]));
[$c, $h, $b] = page('/waf-console?key=' . rawurlencode($k));
ck('零 JS 控制台含 QPS 状态与表单', $c === 200 && str_contains($b, 'params[soft]') && str_contains($b, '演练熔断'));
[$c, $j] = act('state.get');
ck('控制端点 state.get 回读 qps 快照', $c === 200 && isset($j['state']['qps']['state']));

// ---------------------------------------------------------------- 3. 低阈值配置真实生效
echo "\n[3] 阈值配置写入并回读\n";
[$c, $j] = act('qps.config', [
    'enabled' => '1', 'soft' => 3, 'hard' => 6,
    'ip_soft' => 2, 'ip_hard' => 4, 'cooldown' => 5,
]);
ck('qps.config 执行成功', $c === 200 && !empty($j['ok']), json_encode($j, JSON_UNESCAPED_UNICODE));
$rt = wafRtRead($home);
ck('runtime.json 回读阈值一致', (int)$rt['qps']['soft'] === 3 && (int)$rt['qps']['hard'] === 6
    && (int)$rt['qps']['cooldown'] === 5 && !empty($rt['qps']['enabled']));
[$c, $j] = act('qps.config', ['soft' => 0]);
$rtAfterBad = wafRtRead($home);
ck('越界参数被拒绝且配置未被改写', $c === 400 && empty($j['ok']) && (int)$rtAfterBad['qps']['soft'] === 3,
   'code=' . $c . ' soft=' . (int)$rtAfterBad['qps']['soft']);
[$c, $j] = act('qps.config', ['soft' => 3, 'hard' => 6]);   // 恢复

// ---------------------------------------------------------------- 4. 429 限流真实触发
echo "\n[4] 429 限流页面真实触发\n";
act('qps.reset');
$codes = []; $bodies = []; $heads = [];
for ($i = 0; $i < 14; $i++) {
    [$cc, $hh, $bb] = page('/?id=12');
    $codes[] = $cc; $bodies[] = $bb; $heads[] = $hh;
    if ($cc === 502) { break; }
}
ck('序列中出现 429 限流', in_array(429, $codes, true), implode(',', $codes));
ck('序列中出现 502 熔断', in_array(502, $codes, true), implode(',', $codes));
$idx429 = array_search(429, $codes, true);
$idx502 = array_search(502, $codes, true);
ck('限流先于熔断发生', $idx429 !== false && $idx502 !== false && $idx429 < $idx502,
   '429@' . $idx429 . ' 502@' . $idx502);
if ($idx429 !== false) {
    $b = $bodies[$idx429]; $h = $heads[$idx429];
    ck('429 页面含中文标题与中文徽标', str_contains($b, '请求频率超限') && str_contains($b, '访问限流')
        && !str_contains($b, 'RATE LIMITED'));
    ck('429 页面展示真实 QPS / 阈值 / 冷却', str_contains($b, '当前 QPS') && str_contains($b, '限流阈值'));
    ck('429 熔断状态中文化（不裸露 closed / half_open）',
        str_contains($b, '熔断状态') && !preg_match('/熔断状态<\/div><div class="v">\s*(closed|open|half_open)\s*</u', $b));
    ck('429 带 Retry-After', (int)($h['retry-after'] ?? 0) > 0);
    ck('429 无自动刷新（避免放大流量）', !str_contains($b, 'http-equiv="refresh"'));
    ck('429 页面零脚本 / 严格 CSP', !str_contains($b, '<script')
        && str_contains($h['content-security-policy'] ?? '', "script-src 'none'"));
    @file_put_contents('/tmp/waf_page_429.html', $b);
}
if ($idx502 !== false) {
    $b = $bodies[$idx502]; $h = $heads[$idx502];
    ck('502 页面含中文标题与中文徽标', str_contains($b, '服务已熔断降级') && str_contains($b, '服务熔断')
        && !str_contains($b, 'CIRCUIT OPEN'));
    ck('502 带 X-WAF-Circuit: open', ($h['x-waf-circuit'] ?? '') === 'open');
    ck('502 带 Retry-After 与冷却环', (int)($h['retry-after'] ?? 0) > 0 && str_contains($b, '秒后可重试'));
    ck('502 含电路波形 SVG', str_contains($b, 'class="wave"'));
    ck('502 熔断状态中文化且不裸露英文枚举',
        str_contains($b, '熔断状态') && !preg_match('/熔断状态<\/div><div class="v">\s*(closed|open|half_open)\s*</u', $b)
        && !str_contains($b, 'CIRCUIT OPEN'));
    ck('502 页面自动重试（冷却内）', str_contains($b, 'http-equiv="refresh"'));
    @file_put_contents('/tmp/waf_page_502.html', $b);
}

// ---------------------------------------------------------------- 5. 管理路由豁免
echo "\n[5] 熔断期间管理面仍可用\n";
[$c] = page('/waf-screen?key=' . rawurlencode($k));
ck('熔断中大屏仍 200（豁免）', $c === 200, "code=$c");
[$c] = page('/waf-console?key=' . rawurlencode($k));
ck('熔断中控制台仍 200（豁免）', $c === 200, "code=$c");
[$c, $j] = act('state.get');
ck('熔断中控制端点仍可用且回读 open', $c === 200 && ($j['state']['qps']['state'] ?? '') === 'open');

// ---------------------------------------------------------------- 6. 冷却半开自动恢复
echo "\n[6] 冷却结束自动半开恢复\n";
sleep(7);   // cooldown=5s，等状态自然过期；真实等待，不 mock 时钟
$seen200 = 0; $states = [];
for ($i = 0; $i < 5; $i++) {
    [$cc] = page('/?id=12');
    if ($cc === 200) { $seen200++; }
    [, $st] = act('qps.state');
    $states[] = $st['state']['qps']['state'] ?? '?';
    usleep(120000);
}
ck('冷却后恢复 200', $seen200 >= 2, '200 次数=' . $seen200 . ' 状态=' . implode('→', $states));
ck('状态回到正常放行', in_array('closed', $states, true), implode('→', $states));

// ---------------------------------------------------------------- 7. 演练 / 复位 / 停用
echo "\n[7] 演练、复位与停用开关\n";
act('qps.reset');
[$c, $j] = act('qps.open', [], false);
ck('危险动作未确认被拒绝', $c === 400 && empty($j['ok']));
[$c, $j] = act('qps.open', [], true);
ck('演练熔断执行成功', $c === 200 && !empty($j['ok']));
[$c, $h, $b] = page('/?id=12');
ck('演练后真实返回 502 页面', $c === 502 && str_contains($b, '服务已熔断降级'), "code=$c");
@file_put_contents('/tmp/waf_page_502_drill.html', $b);
[$c, $j] = act('qps.close');
ck('强制恢复执行成功', $c === 200 && !empty($j['ok']));
[$c] = page('/?id=12');
ck('恢复后返回 200', $c === 200, "code=$c");
[$c, $j] = act('qps.config', ['enabled' => '0']);
ck('停用保护写入成功', $c === 200 && !empty($j['ok']));
act('qps.reset');
$all = [];
for ($i = 0; $i < 12; $i++) { [$cc] = page('/?id=12'); $all[] = $cc; }
ck('停用后即使超阈值也不拦截（只计数）', !in_array(429, $all, true) && !in_array(502, $all, true), implode(',', $all));
[$c, $j] = act('qps.config', ['enabled' => '1']);
ck('重新启用写入成功', $c === 200 && !empty($j['ok']));
[$c, $j] = act('qps.reset');
ck('复位后状态正常放行 / 拒绝数归零', $c === 200 && ($j['state']['qps']['state'] ?? '') === 'closed'
    && (int)($j['state']['qps']['rejects'] ?? -1) === 0, json_encode($j['state']['qps'] ?? [], JSON_UNESCAPED_UNICODE));

// ---------------------------------------------------------------- 8. 鉴权与未知动作
echo "\n[8] 控制端点安全约束\n";
$badCtx = stream_context_create(['http' => ['method' => 'POST', 'ignore_errors' => true,
    'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
    'content' => http_build_query(['key' => $key, 'csrf' => 'bad', 'action' => 'qps.reset'])]]);
$badBody = @file_get_contents(BASE . '/waf-control', false, $badCtx);
ck('错误 CSRF 返回 403', str_contains(implode(' ', $http_response_header ?? []), ' 403 '));
[$c, $j] = act('qps.not.exist');
ck('未知动作返回 400', $c === 400);

// ---------------------------------------------------------------- 收尾：恢复出厂
resetAll();
ck('运行时覆盖已清理，环境复位', !is_file(wafRtPath($home)));

echo "\n结果：PASS $pass / FAIL $fail\n";
exit($fail > 0 ? 1 : 0);
