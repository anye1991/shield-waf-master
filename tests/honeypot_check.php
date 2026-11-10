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
 * YSL语枢-盾甲WAF · 蜜罐受控启用专项验收（v6.5.0，Docker / 真实 HTTP / 真实内核）
 *
 *   docker exec -i waflean2 php /app/tests/honeypot_check.php
 *
 * 用户要求「蜜罐不能随便开启」。本测试逐条验证：
 *   ① 默认停用，且内核侧真的不实例化 YslHoneypot、不进入任何诱捕分支
 *   ② 启用必须同时满足：二次确认 + 手动输入确认短语 + 合法有效期；少一项都不写盘
 *   ③ 启用后 runtime.json 真实回读、用途与审批指纹留痕、控制审计有中文记录
 *   ④ 有效期届满由入口自动写回停用（安全侧自动回退）
 *   ⑤ 停用是安全侧一键动作，无需二次确认
 *   ⑥ 大屏 / 零 JS 控制台均能看到蜜罐状态与启用闸门
 *   ⑦ 收尾把环境复位，不留运行时覆盖文件
 */
declare(strict_types=1);

$BASE = 'http://127.0.0.1:8080';
$HOME = '/app';
require_once $HOME . '/runtime.php';

$keyFile = wafCtlKeyFile($HOME, '/dev/shm/waf-data');
$KEY  = trim((string)@file_get_contents($keyFile));
$CSRF = wafCtlToken($KEY);

$pass = 0; $fail = 0;
function ck(string $n, bool $c, string $extra = ''): void {
    global $pass, $fail;
    if ($c) { $pass++; echo "  PASS  $n\n"; }
    else    { $fail++; echo "  FAIL  $n", ($extra ? "  ← $extra" : ''), "\n"; }
}
function http(string $url, ?array $post = null): array {
    $opt = ['http' => ['timeout' => 30, 'ignore_errors' => true,
                       'header' => 'Content-Type: application/x-www-form-urlencoded']];
    if ($post !== null) {
        $opt['http']['method'] = 'POST';
        $opt['http']['content'] = http_build_query($post);
    }
    $ctx = stream_context_create($opt);
    $body = (string)@file_get_contents($url, false, $ctx);
    $code = 0;
    foreach ($http_response_header ?? [] as $l) {
        if (preg_match('#HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
    }
    return [$code, $body];
}
function act(string $action, array $params = [], bool $confirm = false): array {
    global $BASE, $KEY, $CSRF;
    [$c, $b] = http($BASE . '/waf-control', [
        'key' => $KEY, 'csrf' => $CSRF, 'action' => $action,
        'params' => json_encode($params, JSON_UNESCAPED_UNICODE),
        'confirm' => $confirm ? '1' : '0',
    ]);
    $j = json_decode($b, true);
    return [$c, is_array($j) ? $j : ['ok' => false, 'raw' => substr($b, 0, 200)]];
}
function page(string $p): array { global $BASE; return http($BASE . $p); }
/** 反射进内核，验证开关真的作用到 initSubsystems / checkHoneyPot，而不是只改了页面文字 */
function kernelProbe(string $envVal): array {
    $v = $envVal === '1' ? '1' : '0';
    $php = "define('ABSPATH','/app/');"
         . "putenv('WAF_HONEYPOT_ENABLED=" . $v . "');"
         . "require '/app/core/YslEngine.php';"
         . "\$r = new ReflectionClass('YslEngine');"
         . "\$m = \$r->getMethod('initSubsystems'); \$m->setAccessible(true); \$m->invoke(null);"
         . "\$p = \$r->getProperty('honeypot'); \$p->setAccessible(true);"
         . "\$o = \$p->getValue();"
         . "echo (\$o instanceof YslHoneypot) ? 'OBJECT' : 'NULL';"
         . "if ('" . $v . "' === '0') {"
         . "\$c = \$r->getMethod('checkHoneyPot'); \$c->setAccessible(true);"
         . "echo '|' . (\$c->invoke(null) ? 'TRUE' : 'FALSE'); }";
    $out = [];
    @exec('php -r ' . escapeshellarg($php) . ' 2>&1', $out, $rc);
    return [implode('', $out), $rc];
}

echo "=== YSL语枢-盾甲WAF v6.5.0 · 蜜罐受控启用验收 ===\n\n";
@unlink(wafRtPath($HOME));

echo "[1] 默认停用（内核侧真验证）\n";
[$c, $j] = act('state.get');
ck('状态接口回读蜜罐默认停用', $c === 200 && empty($j['state']['honeypot']['enabled']),
   json_encode($j['state']['honeypot'] ?? [], JSON_UNESCAPED_UNICODE));
ck('默认不带有效期 / 用途 / 审批指纹', empty($j['state']['honeypot']['timed'])
   && (string)($j['state']['honeypot']['reason'] ?? '') === '');
[$probe, $rc] = kernelProbe('0');
ck('内核关闭时不实例化蜜罐模块', str_contains($probe, 'NULL'), $probe);
ck('内核关闭时 checkHoneyPot 直接短路（不进诱捕分支）', str_contains($probe, 'FALSE'), $probe);
[$probeOn, $rcOn] = kernelProbe('1');
ck('内核开启时才实例化蜜罐模块（开关真实生效）', str_contains($probeOn, 'OBJECT'), $probeOn);

echo "\n[2] 启用闸门：少一项都不写盘\n";
[$c, $j] = act('honeypot.enable', ['phrase' => '启用蜜罐', 'minutes' => 30], false);
ck('未二次确认被拒绝', $c === 400 && empty($j['ok']));
[$c, $j] = act('honeypot.enable', ['phrase' => '随便点一下', 'minutes' => 30], true);
ck('确认短语错误被拒绝且不写盘', $c === 400 && empty($j['ok']) && str_contains((string)($j['message'] ?? ''), '确认短语'));
[$c, $j] = act('honeypot.enable', ['phrase' => '启用蜜罐', 'minutes' => 0], true);
ck('有效期为 0 被拒绝', $c === 400 && empty($j['ok']) && str_contains((string)($j['message'] ?? ''), '有效期'));
[$c, $j] = act('honeypot.enable', ['phrase' => '启用蜜罐', 'minutes' => 9999], true);
ck('有效期超上限被拒绝', $c === 400 && empty($j['ok']));
[$c, $j] = act('honeypot.state');
ck('上述失败动作均未改变真实状态', $c === 200 && empty($j['state']['honeypot']['enabled']));

echo "\n[3] 合规启用：真实写盘 / 回读 / 留痕 / 审计\n";
[$c, $j] = act('honeypot.enable',
    ['phrase' => '启用蜜罐', 'minutes' => 30, 'reason' => '红队演练验收'], true);
$hp = $j['state']['honeypot'] ?? [];
ck('启用返回 200 且回读已启用', $c === 200 && !empty($j['ok']) && !empty($hp['enabled']), (string)($j['message'] ?? ''));
ck('有效期约 30 分钟且倒计时为正', !empty($hp['timed']) && (int)($hp['left'] ?? 0) > 1700 && (int)($hp['left'] ?? 0) <= 1800,
   json_encode($hp, JSON_UNESCAPED_UNICODE));
ck('用途与审批指纹写入运行配置', (string)($hp['reason'] ?? '') === '红队演练验收' && (string)($hp['by'] ?? '') !== '');
$rtRaw = json_decode((string)@file_get_contents(wafRtPath($HOME)), true);
ck('runtime.json 落盘内容与控制端点回读一致', is_array($rtRaw) && !empty($rtRaw['honeypot']['enabled'])
   && (int)($rtRaw['honeypot']['until'] ?? 0) === (int)($hp['until'] ?? 0));
[$c, $j] = act('honeypot.enable', ['phrase' => '启用蜜罐', 'minutes' => 30], true);
ck('已启用时拒绝重复开启', $c === 400 && empty($j['ok']) && str_contains((string)($j['message'] ?? ''), '已处于启用状态'));
[$c, $j] = act('control.audit');
$auditTxt = (string)($j['detail'] ?? '');
ck('控制审计含「启用蜜罐（高危）」中文动作', $c === 200 && str_contains($auditTxt, '启用蜜罐（高危）'));
ck('控制审计含有效期与用途留痕', str_contains($auditTxt, '30 分钟') || str_contains($auditTxt, '红队演练验收'));

echo "\n[4] 大屏与零 JS 控制台可见可控\n";
[$sc, $html] = page('/waf-screen?key=' . rawurlencode($KEY));
ck('大屏 200 且含蜜罐高危专区', $sc === 200 && str_contains($html, '蜜罐诱捕（高危 · 默认停用）'));
ck('大屏含确认短语输入框与有效期输入', str_contains($html, 'data-phrase="ctlHpPhrase"')
   && str_contains($html, 'id="ctlHpMinutes"') && str_contains($html, 'id="ctlHpReason"'));
ck('大屏含一键停用 / 读取状态 / 清理索引', str_contains($html, 'data-act="honeypot.disable"')
   && str_contains($html, 'data-act="honeypot.state"') && str_contains($html, 'data-act="honeypot.clear"'));
ck('大屏显示启用中的真实状态', str_contains($html, '启用中（高危）'));
[$jc, $json] = page('/waf-screen?key=' . rawurlencode($KEY) . '&format=json');
$jd = json_decode($json, true);
ck('JSON 接口输出蜜罐真实状态', $jc === 200 && is_array($jd) && !empty($jd['honeypot']['enabled']));
ck('JSON 接口输出全功能矩阵且全部可控', is_array($jd['features'] ?? null)
   && (int)($jd['features']['total'] ?? 0) > 30
   && (int)($jd['features']['controllable'] ?? 0) === (int)($jd['features']['total'] ?? 0));
[$cc, $con] = page('/waf-console?key=' . rawurlencode($KEY));
ck('零 JS 控制台含蜜罐中文状态表', $cc === 200 && str_contains($con, '蜜罐状态（高危 · 默认停用）')
   && str_contains($con, '启用时间') && str_contains($con, '用途留痕'));
ck('零 JS 控制台含蜜罐启用表单（短语 / 用途 / 时长 / 勾选确认）',
   str_contains($con, 'name="params[phrase]"') && str_contains($con, 'name="params[minutes]"')
   && str_contains($con, 'name="params[reason]"') && str_contains($con, 'name="confirm"'));

echo "\n[5] 有效期届满自动停用（安全侧自动回退）\n";
$expired = wafRtRead($HOME);
$expired['honeypot'] = [
    'enabled' => true, 'until' => time() - 2, 'enabled_at' => time() - 60,
    'by' => 'test', 'reason' => '到期演练',
];
wafRtWrite($HOME, $expired);
[$pc] = page('/?id=12');           // 任意真实请求触发入口的到期检查
ck('到期请求本身正常返回', $pc === 200 || $pc === 403, "code=$pc");
[$c, $j] = act('state.get');
ck('入口自动写回停用并回读一致', $c === 200 && empty($j['state']['honeypot']['enabled']),
   json_encode($j['state']['honeypot'] ?? [], JSON_UNESCAPED_UNICODE));
$rtAfter = json_decode((string)@file_get_contents(wafRtPath($HOME)), true);
ck('runtime.json 里已不再是启用状态', is_array($rtAfter) && empty($rtAfter['honeypot']['enabled'])
   && (int)($rtAfter['honeypot']['until'] ?? -1) === 0);
$log = (string)@file_get_contents(wafCtlLogPath($HOME));
ck('自动停用写入控制审计', str_contains($log, '有效期届满') && str_contains($log, 'honeypot.disable'));

echo "\n[6] 收尾复位\n";
[$c, $j] = act('honeypot.disable');
ck('最终停用成功', $c === 200 && !empty($j['ok']) && empty($j['state']['honeypot']['enabled']));
@unlink(wafRtPath($HOME));
ck('运行时覆盖已清理，环境复位', !is_file(wafRtPath($HOME)));
ck('复位后注入请求仍被拦截', (function () { global $BASE; [$c] = http($BASE . "/?id=1%27%20OR%201%3D1--"); return $c === 403; })());

echo "\n结果：PASS $pass / FAIL $fail\n";
exit($fail === 0 ? 0 : 1);
