<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少. 保留所有权利.
 */

/**
 * YSL语枢-盾甲WAF · 控制端点（/waf-control）
 *
 * 只读大屏/控制台之外唯一的写入口。安全约束：
 *   - 仅 POST；key 与控制台同一把；无状态 CSRF（HMAC(key, 小时时间片)）
 *   - 动作白名单 + 严格参数校验；危险动作必须 confirm=1（前端二次确认）
 *   - 每个动作真实落盘 / 真实执行，并在响应里回读状态，绝不做「点了没生效」的假按钮
 *   - 操作审计写 logs/ysl/control.log，不进 attack.log，避免污染态势指标
 *
 * 响应：JSON（大屏 fetch）或 format=html（零 JS 控制台表单）。
 */
declare(strict_types=1);

require_once __DIR__ . '/runtime.php';

$home    = rtrim(str_replace('\\', '/', defined('WAF_HOME') ? WAF_HOME : dirname(__DIR__)), '/');
$logDir  = rtrim(str_replace('\\', '/', defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (getenv('WAF_LOG_DIR') ?: $home . '/var/logs')), '/');
$dataDir = rtrim(str_replace('\\', '/', defined('WAF_DATA_PATH') ? WAF_DATA_PATH : (getenv('WAF_DATA_DIR') ?: $home . '/var/data')), '/');
$ysl     = $logDir . '/ysl';
$arch    = $home . '/logs/ysl';
$dnaDir  = $home . '/var/dna';

$P = [
    'home'    => $home,
    'ysl'     => $ysl,
    'arch'    => $arch,
    'data'    => $dataDir,
    'dnaDir'  => $dnaDir,
    'key'     => wafCtlKeyFile($home, $dataDir),
    'pid'     => $home . '/var/data/dna-watch.pid',
    'audit'   => wafCtlLogPath($home),
];

// ---------------------------------------------------------------- 输入与鉴权
$method = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');
$in     = $_POST;
if (!$in) {
    $raw = (string)@file_get_contents('php://input');
    $j   = $raw !== '' ? json_decode($raw, true) : null;
    $in  = is_array($j) ? $j : [];
}
$format  = (string)($in['format'] ?? 'json') === 'html' ? 'html' : 'json';
$given   = (string)($in['key'] ?? '');
$csrf    = (string)($in['csrf'] ?? '');
$action  = (string)($in['action'] ?? '');
$confirm = (string)($in['confirm'] ?? '') === '1';
$params  = $in['params'] ?? [];
if (is_string($params)) {
    $p = json_decode($params, true);
    $params = is_array($p) ? $p : [];
}
if (!is_array($params)) { $params = []; }

function ctlSend(array $r, int $code, string $format): void {
    if ($format === 'html') {
        header('Content-Type: text/html; charset=utf-8');
        http_response_code($code);
        $ok   = !empty($r['ok']);
        $col  = $ok ? '#34d399' : '#fb7185';
        $back = '/waf-console?key=' . rawurlencode((string)($GLOBALS['given'] ?? ''));
        echo '<!doctype html><meta charset="utf-8"><title>YSL语枢-盾甲WAF · 控制结果</title>',
             '<body style="margin:0;background:#050a16;color:#e8f2ff;font:14px/1.8 system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh">',
             '<div style="max-width:620px;padding:28px 32px;border:1px solid rgba(120,170,220,.25);border-radius:14px;background:rgba(120,170,220,.05)">',
             '<div style="font-size:20px;color:', $col, ';font-weight:600">', $ok ? '操作成功' : '操作未执行', '</div>',
             '<div style="margin:10px 0 18px;white-space:pre-wrap">', htmlspecialchars((string)($r['message'] ?? ''), ENT_QUOTES, 'UTF-8'), '</div>',
             '<div style="font-size:12px;color:#7c93b4;white-space:pre-wrap;max-height:240px;overflow:auto">',
             htmlspecialchars((string)($r['detail'] ?? ''), ENT_QUOTES, 'UTF-8'), '</div>',
             '<a style="color:#7ce8ff" href="', htmlspecialchars($back, ENT_QUOTES), '">返回控制台</a></div></body>';
        return;
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    http_response_code($code);
    echo json_encode($r, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

$key = is_file($P['key']) ? trim((string)@file_get_contents($P['key'])) : '';
if ($method !== 'POST') {
    ctlSend(['ok' => false, 'message' => '控制端点仅接受 POST', 'action' => $action], 405, $format);
    return;
}
if ($key === '' || !hash_equals($key, $given)) {
    ctlSend(['ok' => false, 'message' => '未授权：密钥错误或未初始化', 'action' => $action], 403, $format);
    return;
}
if (!wafCtlVerify($key, $csrf)) {
    ctlSend(['ok' => false, 'message' => 'CSRF 校验失败：请刷新控制台页面后重试', 'action' => $action], 403, $format);
    return;
}

// ---------------------------------------------------------------- 通用工具
function ctlPaths(string $rel): array {
    $P = $GLOBALS['P'];
    return array_values(array_unique([$P['ysl'] . '/' . $rel, $P['arch'] . '/' . $rel]));
}
function ctlAttackFiles(): array {
    return ctlPaths('attack.log');
}
function ctlUnlink(string $pattern): int {
    $n = 0;
    foreach ([$GLOBALS['P']['ysl'], $GLOBALS['P']['arch']] as $dir) {
        foreach (glob($dir . '/' . $pattern) ?: [] as $f) {
            if (is_file($f) && @unlink($f)) { $n++; }
        }
    }
    return $n;
}
function ctlWriteJsonBoth(string $rel, array $data): array {
    $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    $done = [];
    foreach (ctlPaths($rel) as $f) {
        $dir = dirname($f);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) { continue; }
        $tmp = $f . '.tmp.' . bin2hex(random_bytes(3));
        if (@file_put_contents($tmp, $json, LOCK_EX) !== false && @rename($tmp, $f)) {
            $done[] = $f;
        } else {
            @unlink($tmp);
        }
    }
    return $done;
}
function ctlCircuitState(): array {
    foreach (ctlPaths('circuit_state.json') as $f) {
        if (is_file($f)) {
            $j = json_decode((string)@file_get_contents($f), true);
            if (is_array($j)) { return $j; }
        }
    }
    return [];
}
function ctlWatchScan(): ?int { return wafCtlWatchScan(); }
function ctlWatchAlive(int $pid): bool { return wafCtlWatchAlive($pid); }
function ctlWatchPid(): ?int { return wafCtlWatchPid($GLOBALS['P']['home']); }
function ctlDnaStatus(): array {
    $f = $GLOBALS['P']['home'] . '/var/data/dna-status.json';
    if (!is_file($f)) { return []; }
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) ? $j : [];
}
function ctlDnaRun(string $cmd, array $args = []): array {
    $bin = PHP_BINARY ?: 'php';
    $parts = [$bin, escapeshellarg($GLOBALS['P']['home'] . '/dna.php'), $cmd,
              '--root=' . escapeshellarg($GLOBALS['P']['home'])];
    foreach ($args as $a) { $parts[] = escapeshellarg($a); }
    $out = []; $code = 0;
    exec(implode(' ', $parts) . ' 2>&1', $out, $code);
    return ['ok' => $code === 0, 'code' => $code, 'output' => implode("\n", array_slice($out, 0, 24))];
}
function ctlLogBytes(): int {
    $n = 0;
    foreach (ctlAttackFiles() as $f) {
        if (is_file($f)) { $n += (int)@filesize($f); }
    }
    return $n;
}
/** 蜜罐触碰次数：与 runtime.php 共用同一份真实统计（honeypot/hits_*.jsonl） */
function ctlHoneypotHits(): int {
    $P = $GLOBALS['P'];
    return wafHpHits($P['ysl'], $P['arch']);
}
/** 控制请求的来源指纹：只留哈希，不把访问者 IP 明文写进运行配置 */
function ctlOperator(): string {
    return substr(hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? '') . '|' . (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 12);
}
/** 响应中回读的真实状态：前端拿到后立刻更新开关与指示灯，不靠猜 */
function ctlState(): array {
    $rt  = wafRtRead($GLOBALS['P']['home']);
    $cb  = ctlCircuitState();
    $dna = ctlDnaStatus();
    return [
        'runtime'     => $rt,
        'circuit'     => ['state' => (string)($cb['state'] ?? 'closed'), 'mode' => (string)($cb['mode'] ?? 'normal')],
        'dna'         => [
            'ver'         => (string)($dna['ver'] ?? '—'),
            'files'       => (int)($dna['files'] ?? 0),
            'healthy'     => !empty($dna['healthy']),
            'last_check'  => (int)($dna['last_check'] ?? 0),
            'watch_pid'   => ctlWatchPid(),
        ],
        'log_bytes'   => ctlLogBytes(),
        // v6.5.0：蜜罐真实状态（含有效期倒计时与触碰次数），大屏 / 控制台据此渲染
        'honeypot'    => wafHpView($rt) + ['hits' => ctlHoneypotHits()],
        'key_hint'    => substr($GLOBALS['key'], 0, 4) . '…',
        'audit_count' => is_file($GLOBALS['P']['audit']) ? count(@file($GLOBALS['P']['audit'], FILE_SKIP_EMPTY_LINES) ?: []) : 0,
        // v6.4.0：接入层 QPS 实时快照，页面/按钮据此显示真实状态
        'qps'         => wafQpsSnapshot(dirname($GLOBALS['P']['ysl']),
                                        wafQpsConfig($rt), $GLOBALS['P']['home']),
    ];
}

// ---------------------------------------------------------------- 动作白名单
$DANGER = [
    'runtime.reset', 'whitelist.clear', 'circuit.open', 'qps.open', 'logs.purge',
    'ai.model.reset', 'dna.baseline', 'dna.rebaseline', 'dna.apply',
    'dna.restore', 'dna.watch.stop', 'key.rotate',
    // v6.5.0：开启蜜罐属于高危操作，除二次点击外还必须手动输入确认短语
    'honeypot.enable',
];
$KNOWN = [
    'state.get', 'control.audit',
    'mode.set', 'guard.set', 'runtime.reset', 'config.body_max',
    'whitelist.add', 'whitelist.del', 'whitelist.clear',
    'circuit.reset', 'circuit.open', 'circuit.close',
    'qps.config', 'qps.reset', 'qps.open', 'qps.close', 'qps.state',
    'windows.clear', 'chains.clear', 'honeypot.clear', 'locks.clear',
    'honeypot.enable', 'honeypot.disable', 'honeypot.state',
    'ai.model.reset', 'ai.queues.clear', 'ai.fingerprints.clear',
    'logs.rotate', 'logs.purge', 'logs.export',
    'dna.plan', 'dna.baseline', 'dna.scan', 'dna.audit', 'dna.apply',
    'dna.rebaseline', 'dna.status', 'dna.selftest', 'dna.restore',
    'dna.watch.start', 'dna.watch.stop',
    'key.rotate',
];

if (!in_array($action, $KNOWN, true)) {
    ctlSend(['ok' => false, 'message' => '未知动作：' . $action, 'action' => $action, 'state' => ctlState()], 400, $format);
    return;
}
if (in_array($action, $DANGER, true) && !$confirm) {
    ctlSend(['ok' => false, 'message' => '该操作需要二次确认（confirm=1）', 'action' => $action, 'state' => ctlState()], 400, $format);
    return;
}

$ok = false; $message = ''; $detail = ''; $extra = [];

switch ($action) {
    // ------------------------------------------------------------ 只读查询
    case 'state.get':
        $ok = true; $message = '已回读当前运行状态';
        break;
    case 'control.audit':
        $recent = wafCtlRecent($P['home'], 15);
        $ok = true; $message = '控制审计最近 ' . count($recent) . ' 条';
        $extra['audit'] = $recent;
        $detail = implode("\n", array_map(static fn($e) =>
            ($e['t'] ?? '') . '  ' . ($e['ok'] ? '成功 ' : '失败 ')
            . ($e['action_cn'] ?? wafCnAction((string)($e['action'] ?? '')))
            . '  ' . ($e['detail_cn'] ?? $e['detail'] ?? ''), $recent));
        break;

    // ------------------------------------------------------------ 运行配置
    case 'mode.set':
        $v = (string)($params['value'] ?? '');
        if (!in_array($v, ['enforce', 'observe'], true)) { $message = '运行模式只能是「强制拦截」或「观察模式」'; break; }
        $rt = wafRtRead($home); $rt['mode'] = $v;
        $ok = wafRtWrite($home, $rt);
        $message = $ok ? ('运行模式已切换为「' . wafCnMode($v) . '」（后续请求立即生效）') : '写入 runtime.json 失败';
        $detail = 'runtime.json = ' . wafRtPath($home);
        break;
    case 'guard.set':
        $name = (string)($params['name'] ?? '');
        $rt   = wafRtRead($home);
        if (!array_key_exists($name, $rt['guards'])) { $message = '未知开关：' . $name; break; }
        $on = (string)($params['on'] ?? '') === '1';
        $rt['guards'][$name] = $on;
        $ok = wafRtWrite($home, $rt);
        $message = $ok ? ('防护开关「' . wafCnGuard($name) . '」已' . ($on ? '开启' : '关闭') . '（后续请求立即生效）') : '写入 runtime.json 失败';
        break;
    case 'runtime.reset':
        $ok = wafRtWrite($home, wafRtDefaults());
        $message = $ok ? '运行配置已恢复出厂默认（模式 / 五个开关 / 请求体上限 / 白名单）' : '恢复失败';
        break;
    case 'config.body_max':
        $n = (int)($params['value'] ?? 0);
        if ($n < 1 || $n > 67108864) { $message = '请求体上限须在 1 ~ 67108864 字节之间'; break; }
        $rt = wafRtRead($home); $rt['body_max'] = $n;
        $ok = wafRtWrite($home, $rt);
        $message = $ok ? ('单请求请求体上限已设为 ' . number_format($n) . ' 字节') : '写入失败';
        break;
    case 'whitelist.add':
        $cidr = trim((string)($params['cidr'] ?? ''));
        if (!wafRtValidCidr($cidr)) { $message = 'IP / CIDR 格式不合法：' . $cidr; break; }
        $rt = wafRtRead($home);
        if (in_array($cidr, $rt['whitelist'], true)) { $ok = true; $message = $cidr . ' 已在白名单中'; break; }
        $rt['whitelist'][] = $cidr;
        $ok = wafRtWrite($home, $rt);
        $message = $ok ? ('已加入硬旁路白名单：' . $cidr) : '写入失败';
        break;
    case 'whitelist.del':
        $cidr = trim((string)($params['cidr'] ?? ''));
        $rt = wafRtRead($home);
        $before = count($rt['whitelist']);
        $rt['whitelist'] = array_values(array_filter($rt['whitelist'], static fn($x) => $x !== $cidr));
        $ok = wafRtWrite($home, $rt);
        $message = $ok ? ('已移除 ' . ($before - count($rt['whitelist'])) . ' 条白名单记录') : '写入失败';
        break;
    case 'whitelist.clear':
        $rt = wafRtRead($home); $rt['whitelist'] = [];
        $ok = wafRtWrite($home, $rt);
        $message = $ok ? '硬旁路白名单已清空' : '写入失败';
        break;

    // ------------------------------------------------------------ 熔断与状态文件
    case 'circuit.reset':
    case 'circuit.open':
    case 'circuit.close':
        $state = $action === 'circuit.open' ? 'open' : 'closed';
        $now   = time();
        $data  = [
            'state' => $state, 'mode' => 'normal', 'opened_at' => $state === 'open' ? $now : null,
            'consecutive_failures' => 0, 'consecutive_successes' => 0,
            'thresholds' => ['normal' => 150, 'degrade' => 300, 'emergency' => 500, 'circuit' => 500],
            'qps' => 0, 'rpm' => 0, 'avg_latency_ms' => 0,
            'total_requests' => 0, 'rejected_requests' => 0, 'updated_at' => $now,
        ];
        $written = ctlWriteJsonBoth('circuit_state.json', $data);
        $read    = ctlCircuitState();
        $ok      = $written !== [] && ($read['state'] ?? '') === $state;
        $message = $ok ? ('熔断状态已置为「' . wafCnState($state) . '」（写入 ' . count($written) . ' 处并回读一致）') : '熔断状态写入失败';
        $detail  = implode("\n", $written);
        break;

    // ------------------------------------------------------------ 接入层 QPS 限流 / 熔断
    case 'qps.config':
        $rt = wafRtRead($home);
        $q  = $rt['qps'];
        $cfgLogDir = dirname($P['ysl']);
        if (array_key_exists('enabled', $params)) {
            $q['enabled'] = !in_array($params['enabled'], [false, 0, '0', 'false', 'off', ''], true);
        }
        $bad = [];
        foreach (['soft' => [1, 1000000], 'hard' => [1, 1000000],
                  'ip_soft' => [1, 1000000], 'ip_hard' => [1, 1000000],
                  'cooldown' => [3, 3600]] as $k => $range) {
            if (!array_key_exists($k, $params)) { continue; }
            $n = (int)$params[$k];
            if ($n < $range[0] || $n > $range[1]) { $bad[] = $k; continue; }
            $q[$k] = $n;
        }
        if ($bad !== []) {
            $message = '参数超出允许范围：' . implode('、', array_map('wafCnQpsParam', $bad));
            break;
        }
        if ($q['hard'] < $q['soft'])       { $q['hard'] = $q['soft']; }
        if ($q['ip_hard'] < $q['ip_soft']) { $q['ip_hard'] = $q['ip_soft']; }
        $rt['qps']  = $q;
        $wrote      = wafRtWrite($home, $rt);
        $read       = wafRtRead($home);
        $ok         = $wrote && $read['qps'] == $q;
        $message    = $ok
            ? ('QPS 配置已写入并回读一致：' . ($q['enabled'] ? '启用' : '停用')
               . ' · 全局 ' . $q['soft'] . '/' . $q['hard']
               . ' · 单 IP ' . $q['ip_soft'] . '/' . $q['ip_hard']
               . ' · 冷却 ' . $q['cooldown'] . 's')
            : 'QPS 配置写入失败';
        $detail     = 'runtime.json = ' . wafRtPath($home);
        break;
    case 'qps.reset':
    case 'qps.open':
    case 'qps.close':
        $op  = substr($action, 4);           // reset / open / close
        $cfg = wafQpsConfig(wafRtRead($home));
        $r   = wafQpsAdmin(dirname($P['ysl']), $home, $op, $cfg);
        $ok  = !empty($r['ok']);
        $message = $ok
            ? ('QPS 熔断状态已置为「' . wafCnState((string)$r['snapshot']['state']) . '」（写入 ' . count($r['written']) . ' 处并回读一致）')
            : 'QPS 状态写入失败';
        $detail  = implode("\n", $r['written']);
        $extra['qps'] = $r['snapshot'];
        break;
    case 'qps.state':
        $cfg = wafQpsConfig(wafRtRead($home));
        $ok  = true;
        $message = 'QPS 状态已读取';
        $extra['qps'] = wafQpsSnapshot(dirname($P['ysl']), $cfg, $home);
        break;

    case 'windows.clear':
        $n = ctlUnlink('window_*.json');
        $ok = true; $message = '已清理时间窗口状态 ' . $n . ' 个文件';
        break;
    case 'chains.clear':
        $n = ctlUnlink('chain_*.json');
        $ok = true; $message = '已清理攻击链会话 ' . $n . ' 个文件';
        break;
    case 'honeypot.clear':
        // 蜜罐模块真实写入的是 hits_*.jsonl / ip_index.json / .ip_index.lock，
        // 只删 *.json 会把命中日志留在盘上，必须一并清理。
        $n = ctlUnlink('honeypot/*.json') + ctlUnlink('honeypot/*.jsonl')
           + ctlUnlink('honeypot/.ip_index.lock') + ctlUnlink('ip_index.json');
        $ok = true; $message = '已清理蜜罐命中日志与 IP 索引 ' . $n . ' 个文件';
        break;

    // ------------------------------------------------------------ 蜜罐（高危 · 默认停用）
    case 'honeypot.enable':
        // 三重闸门：二次点击确认（$DANGER 已拦）+ 手动输入确认短语 + 有限有效期 + 用途留痕。
        // 少任何一项都不写盘，杜绝「误点一下就把主动诱捕挂到生产流量上」。
        $phrase  = trim((string)($params['phrase'] ?? ''));
        $minutes = (int)($params['minutes'] ?? 0);
        $reason  = trim((string)($params['reason'] ?? ''));
        if ($phrase !== '启用蜜罐') {
            $message = '确认短语不正确：请在输入框手动输入「启用蜜罐」四个字';
            break;
        }
        if ($minutes < 1 || $minutes > wafHpMaxMinutes()) {
            $message = '有效期须在 1 ~ ' . wafHpMaxMinutes() . ' 分钟之间（到期自动停用）';
            break;
        }
        $rt = wafRtRead($home);
        if (!empty($rt['honeypot']['enabled'])) {
            $message = '蜜罐已处于启用状态，无需重复开启；如需延长请先停用再重新启用';
            break;
        }
        $rt['honeypot'] = [
            'enabled'    => true,
            'until'      => time() + $minutes * 60,
            'enabled_at' => time(),
            'by'         => ctlOperator(),
            'reason'     => $reason !== '' ? mb_substr($reason, 0, 120) : '控制台演练',
        ];
        $ok = wafRtWrite($home, $rt) && !empty(wafRtRead($home)['honeypot']['enabled']);
        $message = $ok
            ? ('蜜罐已启用 · 有效期 ' . $minutes . ' 分钟（' . gmdate('H:i:s', $rt['honeypot']['until']) . ' UTC 自动停用）· 用途：' . $rt['honeypot']['reason'])
            : '蜜罐启用失败：runtime.json 写入或回读不一致';
        $detail = '审批指纹 ' . $rt['honeypot']['by'] . ' · runtime.json = ' . wafRtPath($home)
                . "\n风险提示：触碰诱饵的请求会被延迟响应、投喂假数据并标记为确认恶意。";
        break;
    case 'honeypot.disable':
        // 关闭是安全侧动作：一键立即生效，不需要二次确认，避免紧急情况下被流程卡住
        $rt = wafRtRead($home);
        $was = !empty($rt['honeypot']['enabled']);
        $rt['honeypot'] = ['enabled' => false, 'until' => 0, 'enabled_at' => 0, 'by' => '', 'reason' => ''];
        $ok = wafRtWrite($home, $rt) && empty(wafRtRead($home)['honeypot']['enabled']);
        $message = $ok ? ($was ? '蜜罐已立即停用，后续请求不再进入任何诱捕分支' : '蜜罐本就处于停用状态，已确认') : '蜜罐停用失败';
        break;
    case 'honeypot.state':
        $ok = true; $message = '蜜罐状态已读取';
        $extra['honeypot'] = wafHpView(wafRtRead($home)) + ['hits' => ctlHoneypotHits()];
        break;
    case 'locks.clear':
        $n = ctlUnlink('*.lock') + ctlUnlink('*.tmp.*');
        $ok = true; $message = '已清理临时锁 / 原子写残留 ' . $n . ' 个文件';
        break;
    case 'ai.model.reset':
        $n = ctlUnlink('bayes_model.json');
        $ok = true; $message = '贝叶斯模型已删除 ' . $n . ' 份，下一请求触发冷启动重训';
        break;
    case 'ai.queues.clear':
        $n = ctlUnlink('learning/train_queue.json') + ctlUnlink('learning/review_queue.json');
        $ok = true; $message = '训练 / 审核队列已清理 ' . $n . ' 个文件';
        break;
    case 'ai.fingerprints.clear':
        $n = ctlUnlink('learning/fingerprints.json');
        $ok = true; $message = '相似指纹库已清理 ' . $n . ' 个文件';
        break;
    case 'logs.rotate':
        $rotated = [];
        foreach (ctlAttackFiles() as $f) {
            if (!is_file($f) || (int)@filesize($f) < 1) { continue; }
            $new = $f . '.' . gmdate('Ymd_His') . '.bak';
            if (@rename($f, $new)) {
                @file_put_contents($f, '', LOCK_EX);
                $rotated[] = basename($new);
            }
        }
        $ok = true; $message = '审计日志已归档 ' . count($rotated) . ' 份（原文件已重建为空）';
        $detail = implode("\n", $rotated);
        break;
    case 'logs.purge':
        $n = 0;
        foreach (ctlAttackFiles() as $f) {
            if (is_file($f) && @file_put_contents($f, '', LOCK_EX) !== false) { $n++; }
        }
        $ok = $n > 0; $message = '已清空 ' . $n . ' 份攻击日志（不可恢复）';
        break;
    case 'logs.export':
        $src = '';
        foreach (ctlAttackFiles() as $f) { if (is_file($f) && (int)@filesize($f) > 0) { $src = $f; break; } }
        if ($src === '') { $message = '没有可导出的审计日志'; break; }
        $dir = $P['arch'];
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) { $message = '导出目录不可写'; break; }
        $dst = $dir . '/export_' . gmdate('Ymd_His') . '.jsonl';
        $ok  = @copy($src, $dst);
        $message = $ok ? ('已导出 ' . basename($dst) . '（' . number_format((int)@filesize($dst)) . ' 字节）') : '导出失败';
        $detail  = $dst;
        break;

    // ------------------------------------------------------------ 文件 DNA（调用独立 CLI，非 Web 管线）
    case 'dna.plan':
    case 'dna.baseline':
    case 'dna.scan':
    case 'dna.audit':
    case 'dna.apply':
    case 'dna.rebaseline':
    case 'dna.status':
    case 'dna.selftest':
        $map = [
            'dna.plan' => 'plan', 'dna.baseline' => 'baseline', 'dna.scan' => 'scan',
            'dna.audit' => 'audit', 'dna.apply' => 'scan', 'dna.rebaseline' => 'rebaseline',
            'dna.status' => 'status', 'dna.selftest' => 'selftest',
        ];
        $args = $action === 'dna.apply' ? ['--apply'] : [];
        $r = ctlDnaRun($map[$action], $args);
        $ok = $r['ok'];
        $message = $ok ? ('文件 DNA「' . wafCnDnaCmd($map[$action]) . '」执行成功（退出码 0）')
                       : ('文件 DNA「' . wafCnDnaCmd($map[$action]) . '」失败（退出码 ' . $r['code'] . '）');
        $detail = $r['output'];
        break;
    case 'dna.restore':
        $file = (string)($params['file'] ?? '');
        if ($file === '' || str_contains($file, '..') || str_starts_with($file, '/')
            || !preg_match('#^[A-Za-z0-9_./-]+$#', $file)) {
            $message = '还原路径不合法：仅接受站点根下的相对路径'; break;
        }
        $r = ctlDnaRun('restore', ['--file=' . $file]);
        $ok = $r['ok'];
        $message = $ok ? ('已从备份还原 ' . $file) : ('还原失败（退出码 ' . $r['code'] . '）');
        $detail = $r['output'];
        break;
    case 'dna.watch.start':
        $pid = ctlWatchPid();
        if ($pid !== null) {
            $ok = true; $message = 'DNA 守护已在运行（进程号 ' . $pid . '，已纳入面板管理）';
            break;
        }
        $log = $P['arch'] . '/dna-watch.out';
        if (!is_dir(dirname($log))) { @mkdir(dirname($log), 0750, true); }
        $cmd = (PHP_BINARY ?: 'php') . ' ' . escapeshellarg($home . '/dna.php')
             . ' watch --root=' . escapeshellarg($home) . ' --interval=30 > '
             . escapeshellarg($log) . ' 2>&1 & echo $!';
        $newPid = (int)trim((string)@exec($cmd));
        usleep(300000);
        if (ctlWatchAlive($newPid)) {
            @file_put_contents($P['pid'], (string)$newPid, LOCK_EX);
            $ok = true; $message = 'DNA 守护已启动（进程号 ' . $newPid . '，间隔 30 秒）';
        } else {
            $message = '守护启动失败，请查看 ' . $log;
            $detail  = (string)@file_get_contents($log);
        }
        break;
    case 'dna.watch.stop':
        $pid = ctlWatchPid();
        if ($pid === null) { $ok = true; $message = 'DNA 守护未运行，无需停止'; break; }
        $sig = function_exists('posix_kill') ? posix_kill($pid, 15) : (bool)@exec('kill ' . (int)$pid . ' 2>/dev/null');
        usleep(300000);
        if (ctlWatchAlive($pid)) {
            if (function_exists('posix_kill')) { posix_kill($pid, 9); }
            usleep(200000);
        }
        @unlink($P['pid']);
        $ok = !ctlWatchAlive($pid);
        $message = $ok ? ('DNA 守护已停止（进程号 ' . $pid . '）') : ('停止失败，进程 ' . $pid . ' 仍存活');
        break;

    // ------------------------------------------------------------ 访问控制
    case 'key.rotate':
        $new = bin2hex(random_bytes(16));
        $targets = array_values(array_unique([$P['key'], $home . '/var/data/console.key']));
        $written = [];
        foreach ($targets as $f) {
            $dir = dirname($f);
            if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) { continue; }
            if (@file_put_contents($f, $new . "\n", LOCK_EX) !== false) {
                @chmod($f, 0600);
                $written[] = $f;
            }
        }
        $ok = count($written) === count($targets);
        $message = $ok ? '控制台密钥已轮换，旧链接立即失效' : '密钥写入失败';
        if ($ok) {
            $extra['new_key']  = $new;
            $extra['new_csrf'] = wafCtlToken($new);
            $GLOBALS['given']  = $new;   // HTML 结果页的返回链接改用新密钥
            $detail = "请保存新密钥（只显示这一次）：\n" . $new;
        }
        break;
}

// ---------------------------------------------------------------- 审计 + 回读响应
// 只读查询不写操作审计，避免刷新状态把 control.log 刷满
if (!in_array($action, ['state.get', 'control.audit', 'qps.state', 'honeypot.state'], true)) {
    wafCtlLog($home, $action, $ok, $message . ($detail !== '' ? ' | ' . mb_substr($detail, 0, 120) : ''));
}
$resp = [
    'ok'      => $ok,
    'action'  => $action,
    'message' => $message,
    'detail'  => $detail,
    'state'   => ctlState(),
] + $extra;
ctlSend($resp, $ok ? 200 : 400, $format);
