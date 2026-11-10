<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少. 保留所有权利.
 */

/**
 * YSL语枢-盾甲WAF · 全功能控制矩阵专项验收（v6.5.0）
 *
 *   docker exec -i waflean2 php /app/tests/feature_matrix_check.php
 *
 * 用户反馈「在监控没有看到所有功能都能控制」。本测试核对：
 *   ① 大屏主区域确实有全功能控制矩阵，且覆盖数 = 功能总数（无遗漏）
 *   ② 每个功能项都绑定真实动作或真实控制台分区；页面里每一个 data-act
 *      都能在 control.php 的动作白名单里找到（杜绝假按钮）
 *   ③ 底栏状态灯由「只读不可点」变成可点击直达控制
 *   ④ 蜜罐卡片与高危专区可见，默认停用
 *   ⑤ JSON 契约输出同一份功能矩阵；静态快照不泄露密钥 / CSRF 且禁用操作
 *   ⑥ 全中文展示，不裸露内部英文状态枚举
 */
declare(strict_types=1);

$BASE = 'http://127.0.0.1:8080';
$HOME = '/app';
require_once $HOME . '/runtime.php';

$KEY  = trim((string)@file_get_contents(wafCtlKeyFile($HOME, '/dev/shm/waf-data')));
$CSRF = wafCtlToken($KEY);

$pass = 0; $fail = 0;
function ck(string $n, bool $c, string $extra = ''): void {
    global $pass, $fail;
    if ($c) { $pass++; echo "  PASS  $n\n"; }
    else    { $fail++; echo "  FAIL  $n", ($extra ? "  ← $extra" : ''), "\n"; }
}
function get(string $url): array {
    $ctx = stream_context_create(['http' => ['timeout' => 30, 'ignore_errors' => true]]);
    $b = (string)@file_get_contents($url, false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $l) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
    }
    return [$code, $b];
}
/** 从 control.php 源码里解析真实动作白名单，测试不另写一份可能过期的清单 */
function knownActions(): array {
    $src = (string)@file_get_contents('/app/control.php');
    if (!preg_match('/\$KNOWN\s*=\s*\[(.*?)\];/s', $src, $m)) { return []; }
    preg_match_all("/'([a-z][a-z0-9_.]*)'/", $m[1], $a);
    return array_values(array_unique($a[1] ?? []));
}
function visible(string $html): string {
    $s = preg_replace('#<(script|style)\b[^>]*>.*?</\1>#is', ' ', $html) ?? $html;
    $s = preg_replace('#<details\b[^>]*>.*?</details>#is', ' ', $s) ?? $s;
    $s = strip_tags($s);
    $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return (string)preg_replace('/\s+/u', ' ', $s);
}

echo "=== YSL语枢-盾甲WAF v6.5.0 · 全功能控制矩阵验收 ===\n\n";

echo "[1] 动作白名单与页面按钮一致性\n";
$known = knownActions();
ck('成功解析 control.php 动作白名单', count($known) >= 40, '实际 ' . count($known));
[$sc, $html] = get($BASE . '/waf-screen?key=' . rawurlencode($KEY));
ck('大屏返回 200', $sc === 200);
preg_match_all('/data-act="([a-z][a-z0-9_.]*)"/', $html, $am);
$acts = array_values(array_unique($am[1] ?? []));
$unknown = array_values(array_diff($acts, $known));
ck('页面所有 data-act 都是后端真实动作（无假按钮）', $unknown === [], implode(',', $unknown));
ck('页面控制按钮覆盖 >= 35 个不同动作', count($acts) >= 35, '实际 ' . count($acts));

echo "\n[2] 全功能矩阵：覆盖数 = 总数，逐项都有入口\n";
[$jc, $json] = get($BASE . '/waf-screen?key=' . rawurlencode($KEY) . '&format=json');
$jd = json_decode($json, true);
ck('JSON 接口返回 features 矩阵', $jc === 200 && is_array($jd) && isset($jd['features']));
$f = $jd['features'] ?? [];
$total = (int)($f['total'] ?? 0);
$ctrl  = (int)($f['controllable'] ?? 0);
ck('功能总数 >= 35 项', $total >= 35, "total=$total");
ck('可控项 = 功能总数（无遗漏）', $ctrl === $total, "$ctrl / $total");
$groups = $f['groups'] ?? [];
ck('功能分组齐全（检测内核 / 接入防护 / 文件完整性 / 日志与学习 / 访问与视图）',
   count($groups) === 5, implode(',', array_column($groups, 'id')));
$bad = [];
foreach ($f['items'] ?? [] as $it) {
    if (($it['act'] ?? '') === '' && ($it['focus'] ?? '') === '') { $bad[] = $it['id'] . ':无入口'; continue; }
    if (($it['act'] ?? '') !== '' && !in_array($it['act'], $known, true)) { $bad[] = $it['id'] . ':未知动作'; }
    if (!in_array((string)($it['lamp'] ?? ''), ['on', 'warn', 'off', 'info', 'danger'], true)) { $bad[] = $it['id'] . ':灯态非法'; }
    if ((string)($it['status'] ?? '') === '' || (string)($it['name'] ?? '') === '') { $bad[] = $it['id'] . ':缺中文名称或状态'; }
}
ck('每项功能都有真实入口、合法灯态与中文状态', $bad === [], implode(' / ', $bad));
ck('矩阵含蜜罐高危项且默认停用', (function () use ($f) {
    foreach ($f['items'] ?? [] as $it) {
        if ($it['id'] === 'honeypot') { return $it['kind'] === '高危' && $it['lamp'] === 'off'; }
    }
    return false;
})());
ck('矩阵含「立即停用蜜罐」安全侧入口', (function () use ($f) {
    foreach ($f['items'] ?? [] as $it) { if ($it['id'] === 'hp_disable') { return $it['act'] === 'honeypot.disable'; } }
    return false;
})());

echo "\n[3] 大屏主区域与底栏：看得见、点得动\n";
ck('主区域存在全功能控制矩阵面板', str_contains($html, 'id="featurePanel"')
   && str_contains($html, '全功能控制矩阵'));
ck('面板显示 N/N 项可控', str_contains($html, $ctrl . ' / ' . $total . ' 项可控')
   || str_contains($html, (string)$ctrl . '/' . (string)$total));
preg_match_all('/class="feat [a-z]+/i', $html, $fm);
ck('渲染出的功能卡片数 = 功能总数', count($fm[0] ?? []) === $total,
   '卡片 ' . count($fm[0] ?? []) . ' / 功能 ' . $total);
ck('蜜罐卡片带高危样式与停用灯', str_contains($html, 'id="feat-honeypot"')
   && str_contains($html, 'feat-lamp off') && str_contains($html, '已停用（默认）'));
ck('底栏状态灯改为可点击（不再是只读非按钮）', str_contains($html, '点击任一指示灯直达对应控制')
   && !str_contains($html, '只读指示 · 非按钮'));
preg_match_all('/data-focus="(sec-[a-z]+)"/', $html, $fm2);
ck('页面存在大量「直达控制分区」入口', count($fm2[1] ?? []) >= 20, '实际 ' . count($fm2[1] ?? []));
$focusTargets = array_values(array_unique($fm2[1] ?? []));
$missingSec = array_values(array_filter($focusTargets, static fn($id) => !str_contains($html, 'id="' . $id . '"')));
ck('所有 focus 目标都对应真实存在的控制台分区', $missingSec === [], implode(',', $missingSec));
foreach (['sec-mode', 'sec-guards', 'sec-request', 'sec-honeypot', 'sec-state',
          'sec-qps', 'sec-logs', 'sec-dna', 'sec-access'] as $sec) {
    ck('抽屉分区 ' . $sec . ' 存在', str_contains($html, 'id="' . $sec . '"'));
}
ck('蜜罐专区含风险说明与确认短语输入', str_contains($html, '为什么不能随便开启')
   && str_contains($html, 'id="ctlHpPhrase"') && str_contains($html, 'id="ctlHpMinutes"'));
ck('蜜罐专区含启用 / 停用 / 读取 / 清理四个真实按钮',
   substr_count($html, 'data-act="honeypot.') >= 4);

echo "\n[4] 静态快照安全约束\n";
[$ssc, $snap] = get($BASE . '/waf-screen?key=' . rawurlencode($KEY) . '&static=1');
ck('静态快照 200', $ssc === 200);
ck('静态快照不输出密钥与 CSRF', !str_contains($snap, 'var KEY = "' . $KEY . '"')
   && !str_contains($snap, 'var CTL_CSRF = "' . $CSRF . '"'));
ck('静态快照所有控制按钮 / 直达入口均禁用', str_contains($snap, '静态快照不可执行操作')
   && str_contains($snap, "querySelectorAll('[data-focus]')"));
ck('静态快照仍渲染真实功能矩阵（不是空白）', str_contains($snap, 'id="featurePanel"')
   && str_contains($snap, 'feat-grid'));

echo "\n[5] 零 JS 控制台与全中文展示\n";
[$cc, $con] = get($BASE . '/waf-console?key=' . rawurlencode($KEY));
ck('零 JS 控制台 200', $cc === 200);
ck('零 JS 控制台含蜜罐中文状态表与启用表单', str_contains($con, '蜜罐状态（高危 · 默认停用）')
   && str_contains($con, 'name="params[phrase]"') && str_contains($con, '确认开启'));
$vis = visible($html);
$BARE = ['closed', 'half_open', 'observe', 'enforce', 'degrade', 'emergency',
         'SECURITY BLOCK', 'RATE LIMITED', 'CIRCUIT OPEN', 'plan', 'selftest', 'rebaseline'];
$hits = [];
foreach ($BARE as $w) {
    if (preg_match('/(?<![A-Za-z])' . preg_quote($w, '/') . '(?![A-Za-z])/u', $vis)) { $hits[] = $w; }
}
ck('大屏可见文本无裸露英文状态 / 命令枚举', $hits === [], implode(',', $hits));
$vis2 = visible($con);
$hits2 = [];
foreach ($BARE as $w) {
    if (preg_match('/(?<![A-Za-z])' . preg_quote($w, '/') . '(?![A-Za-z])/u', $vis2)) { $hits2[] = $w; }
}
ck('零 JS 控制台可见文本无裸露英文枚举', $hits2 === [], implode(',', $hits2));

echo "\n结果：PASS $pass / FAIL $fail\n";
exit($fail === 0 ? 0 : 1);
