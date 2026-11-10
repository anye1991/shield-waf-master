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
 * YSL语枢-盾甲WAF · 控制台（零 JavaScript）
 *
 * 上半部分是只读统计：所有数字都从内核真实日志算出来，没有数据就显示「暂无」。
 * 下半部分是原生表单操作：直接 POST 到 /waf-control，由控制端点真实执行、
 * 真实落盘并在结果页回显，不做「点了保存其实没落盘」的假功能。
 * 完整的分组控制面（含二次确认与状态联动）在 /waf-screen 的控制台抽屉里。
 * 不依赖 CDN / 外部字体 / 图表库，不会被 CSP 或离线环境打断。
 *
 * 访问：/waf-console?key=<var/data/console.key 里的值>
 */
declare(strict_types=1);

$wafHome = defined('WAF_HOME') ? rtrim(str_replace('\\', '/', WAF_HOME), '/')
                               : rtrim(str_replace('\\', '/', __DIR__), '/');
$logDir  = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : ($wafHome . '/var/logs');
$yslDir  = rtrim($logDir, '/') . '/ysl';
$dataDir = defined('WAF_DATA_PATH') ? WAF_DATA_PATH : ($wafHome . '/var/data');
$keyFile = rtrim($dataDir, '/') . '/console.key';
// 运行目录指向 tmpfs 时回退到站点持久目录，避免重启后密钥丢失导致控制台 403
if (!is_file($keyFile) && is_file($wafHome . '/var/data/console.key')) {
    $keyFile = $wafHome . '/var/data/console.key';
}

if (!headers_sent()) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
}

// ---------- 认证：只读，key 不匹配就 403 ----------
$key = is_file($keyFile) ? trim((string)@file_get_contents($keyFile)) : '';
$given = isset($_GET['key']) && is_string($_GET['key']) ? $_GET['key'] : '';
if ($key === '' || $given === '' || !hash_equals($key, $given)) {
    if (!headers_sent()) { http_response_code(403); }
    echo '<!doctype html><meta charset="utf-8"><title>YSL语枢-盾甲WAF · 控制台</title>',
         '<body style="background:#0b1220;color:#e2e8f0;font:14px/1.7 system-ui;padding:40px">',
         '<h2>403 · 未授权或控制台未初始化</h2>',
         '<p>请运行 <code>php install.php --site=/你的站点</code> 生成密钥，并使用安装时打印的完整链接访问。</p>',
         '<p style="color:#94a3b8">本控制台提供零 JavaScript 的表单操作；完整控制面在态势大屏。</p></body>';
    return;
}

// ---------- 控制台表单：与态势大屏共用同一个控制端点 ----------
require_once __DIR__ . '/runtime.php';
$ctlRt   = wafRtRead($wafHome);
$ctlCsrf = wafCtlToken($key);

/** 生成一张原生 POST 表单；危险动作用勾选框做零 JS 的二次确认 */
function ctlForm(string $label, string $action, array $params = [], bool $danger = false): string {
    global $given, $ctlCsrf;
    $p = (string)json_encode($params, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $h = '<form method="post" action="/waf-control" class="cf">'
       . '<input type="hidden" name="key" value="' . e($given) . '">'
       . '<input type="hidden" name="csrf" value="' . e($ctlCsrf) . '">'
       . '<input type="hidden" name="format" value="html">'
       . '<input type="hidden" name="action" value="' . e($action) . '">'
       . '<input type="hidden" name="params" value="' . e($p) . '">';
    if ($danger) {
        $h .= '<label class="cf-danger"><input type="checkbox" name="confirm" value="1"> 确认</label>';
    } else {
        $h .= '<input type="hidden" name="confirm" value="1">';
    }
    return $h . '<button type="submit"' . ($danger ? ' class="danger"' : '') . '>' . e($label) . '</button></form>';
}

// ---------- 读真实日志 ----------
function tailLines(string $file, int $limit): array {
    if (!is_file($file)) { return []; }
    $fp = @fopen($file, 'rb');
    if (!$fp) { return []; }
    $lines = [];
    while (($l = fgets($fp)) !== false) {
        $l = trim($l);
        if ($l === '') { continue; }
        $lines[] = $l;
        if (count($lines) > $limit) { array_shift($lines); }
    }
    fclose($fp);
    return $lines;
}
function e($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

$attackLines = tailLines($yslDir . '/attack.log', 300);
$rows = [];
$reasonCount = [];
$today = date('Y-m-d');
$todayBlocks = 0;
$aiSignals      = 0;  // 有 AI 信号的事件数（审计日志真实字段）
$aiColdStart    = 0;  // 冷启动降级次数
$semanticScored = 0;  // 语义层给出分数的事件数
$fpOverrides    = 0;  // 叙述性误报复核放行次数
$tautologyBlocks = 0; // 布尔恒真式加固拦截次数
$bypassBlocks    = 0; // 确定性绕过结构加固拦截次数
foreach ($attackLines as $line) {
    $d = json_decode($line, true);
    if (!is_array($d)) {
        $rows[] = ['raw' => $line];
        continue;
    }
    $action = (string)($d['action'] ?? $d['decision'] ?? '');
    $reason = (string)($d['reason'] ?? '');
    $ts     = (string)($d['ts'] ?? $d['time'] ?? $d['timestamp'] ?? '');
    if (!empty($d['ai_signals']) && is_array($d['ai_signals'])) {
        $aiSignals++;
        if (!empty($d['ai_signals']['cold_start'])) { $aiColdStart++; }
    }
    if (!empty($d['core_graph']['semantic_score'])) { $semanticScored++; }
    if ($reason === 'fp_narrative_override' || !empty($d['arbiter']['fp_narrative_override'])) { $fpOverrides++; }
    if ($reason === 'sql_boolean_tautology') { $tautologyBlocks++; }
    if ($reason === 'bypass_structure_block') { $bypassBlocks++; }
    if ($reason !== '') { $reasonCount[$reason] = ($reasonCount[$reason] ?? 0) + 1; }
    if (in_array($action, ['block', 'challenge'], true) && strpos($ts, $today) === 0) {
        $todayBlocks++;
    }
    $rows[] = [
        'ts'     => $ts,
        'ip'     => (string)($d['ip'] ?? $d['client_ip'] ?? ''),
        'uri'    => (string)($d['uri'] ?? ''),
        'action' => $action,
        'score'  => $d['score'] ?? $d['final_score'] ?? '',
        'reason' => $reason,
    ];
}
$rows = array_reverse($rows);
arsort($reasonCount);

$chainFiles  = count(glob($yslDir . '/chain_*.json') ?: []);
$windowFiles = count(glob($yslDir . '/window_*.json') ?: []);
$circuitFile = $yslDir . '/circuit_state.json';
$circuitText = is_file($circuitFile) ? trim((string)@file_get_contents($circuitFile)) : '';
$mode       = getenv('WAF_MODE') ?: 'enforce';
$aiEnabled  = getenv('WAF_AI_ENABLED') !== '0';
$semanticEnabled = getenv('WAF_SEMANTIC_LAYER') === '1';
$fpGuard    = getenv('WAF_FP_GUARD') !== '0';
$tautoGuard = getenv('WAF_TAUTOLOGY_GUARD') !== '0';
$bypassGuard = getenv('WAF_BYPASS_GUARD') !== '0';

// 贝叶斯模型：只读统计，文件不存在就显示「暂无」，绝不填占位值
$modelFile = rtrim($logDir, '/') . '/bayes_model.json';
$modelText = is_file($modelFile) ? (string)@file_get_contents($modelFile) : '';
$model = $modelText === '' ? [] : json_decode($modelText, true);
if (!is_array($model)) { $model = []; }
$attackSamples = (int)($model['classes']['attack']['count'] ?? 0);
$normalSamples = (int)($model['classes']['normal']['count'] ?? 0);
$modelReady    = ($attackSamples + $normalSamples) > 0;

// phar 模式下 core/ 在归档内部，外部目录没有 Ysl*.php；不编造数字
$kernelPath   = (defined('ABSPATH') ? rtrim(ABSPATH, '/') : $wafHome) . '/core/Ysl*.php';
$kernelCount  = count(glob($kernelPath) ?: []);
$inPhar       = strpos(__DIR__, 'phar://') === 0;

?><!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YSL语枢-盾甲WAF · 控制台</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e2e8f0;font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px}h1 span{color:#22d3ee}
.sub{color:#94a3b8;font-size:12px;margin-bottom:22px}
.note{background:rgba(148,163,184,.08);border:1px solid rgba(148,163,184,.18);border-radius:10px;padding:10px 14px;font-size:12px;color:#94a3b8;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:22px}
.card{background:#111c30;border:1px solid rgba(148,163,184,.14);border-radius:12px;padding:14px 16px}
.card .v{font-size:22px;font-weight:600;color:#f1f5f9;margin:2px 0}
.card .l{font-size:12px;color:#94a3b8}
h2{font-size:14px;margin:26px 0 10px;color:#cbd5e1;border-left:3px solid #22d3ee;padding-left:9px}
table{width:100%;border-collapse:collapse;font-size:12px;background:#111c30;border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid rgba(148,163,184,.1);white-space:nowrap}
th{color:#94a3b8;font-weight:500;background:#0f1a2c}
td.u{white-space:normal;word-break:break-all;color:#cbd5e1}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px}
.block{background:rgba(239,68,68,.16);color:#fca5a5}.mon{background:rgba(251,191,36,.16);color:#fcd34d}
.empty{color:#64748b;padding:18px;text-align:center;background:#111c30;border-radius:10px}
code{background:rgba(148,163,184,.12);padding:1px 5px;border-radius:4px}
.cf{display:inline-flex;align-items:center;gap:6px;margin:4px 6px 4px 0}
.cf button{padding:6px 11px;border-radius:7px;border:1px solid rgba(34,211,238,.4);background:rgba(34,211,238,.1);color:#a5e9ff;font-size:12px;cursor:pointer;font-family:inherit}
.cf button:hover{background:rgba(34,211,238,.22)}
.cf button.danger{border-color:rgba(244,63,94,.45);background:rgba(244,63,94,.1);color:#fca5a5}
.cf-danger{font-size:11px;color:#fca5a5;display:inline-flex;align-items:center;gap:3px;white-space:nowrap}
.ctl-group{background:#111c30;border:1px solid rgba(148,163,184,.14);border-radius:12px;padding:12px 14px;margin-bottom:12px}
.ctl-group h3{margin:0 0 6px;font-size:13px;color:#cbd5e1;font-weight:600}
.ctl-group .hint{font-size:11px;color:#94a3b8;margin:0 0 9px}
.kv{width:100%;border-collapse:collapse;font-size:12px}
.kv th,.kv td{text-align:left;padding:6px 10px;border-bottom:1px solid rgba(148,163,184,.1)}
.kv th{color:#8fb6dc;font-weight:500;width:38%;white-space:nowrap}
.kv td{color:#dbeaff;word-break:break-all}
.kv tr:last-child th,.kv tr:last-child td{border-bottom:0}
.raw{margin-top:9px;font-size:11px;color:#7f9dc2}
.raw summary{cursor:pointer;color:#8fd3e8;outline:none}
.raw pre{white-space:pre-wrap;word-break:break-all;background:#0b1526;border:1px solid rgba(148,163,184,.14);
  border-radius:8px;padding:10px;color:#93aac9;font-size:10.5px;max-height:260px;overflow:auto}
</style></head><body><div class="wrap">
<h1>YSL语枢-盾甲WAF <span>· 控制台</span></h1>
<div class="sub">内核 v<?= e(defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : '6.5.0') ?> · PHP <?= e(PHP_VERSION) ?> · 模式 <?= e(wafCnMode($mode)) ?></div>

<div class="note">上半部分为<strong>只读统计</strong>（真实审计日志，无数据即显示「暂无」）；下方表单是<strong>真实操作</strong>，直接提交到 <code>/waf-control</code>，经密钥 + CSRF 校验后落盘并在结果页回显。日志目录 <code><?= e($yslDir) ?></code></div>

<div class="grid">
  <div class="card"><div class="l">审计事件总数</div><div class="v"><?= count($attackLines) ?: '暂无' ?></div><div class="l">attack.log 全量行数</div></div>
  <div class="card"><div class="l">今日拦截</div><div class="v"><?= $todayBlocks ?: '0' ?></div><div class="l"><?= e($today) ?></div></div>
  <div class="card"><div class="l">攻击链会话</div><div class="v"><?= $chainFiles ?: '0' ?></div><div class="l">chain_*.json</div></div>
  <div class="card"><div class="l">时间窗口</div><div class="v"><?= $windowFiles ?: '0' ?></div><div class="l">window_*.json</div></div>
  <div class="card"><div class="l">内核文件</div><div class="v"><?= $kernelCount ?: ($inPhar ? '内置' : '—') ?></div><div class="l"><?= $inPhar ? 'phar 单文件' : 'core/Ysl*.php' ?></div></div>
</div>

<div class="note">运行配置：AI 自学习 <strong><?= $aiEnabled ? '已接线' : '关闭（纯内核快路径）' ?></strong> · 语义解析层 <strong><?= $semanticEnabled ? '已加载' : '未加载（核心+AI 精简模式）' ?></strong> · 叙述性误报复核 <strong><?= $fpGuard ? '开启' : '关闭' ?></strong> · 布尔恒真式加固 <strong><?= $tautoGuard ? '开启' : '关闭' ?></strong> · 绕过结构加固 <strong><?= $bypassGuard ? '开启' : '关闭' ?></strong> · 模式 <strong><?= e(wafCnMode($mode)) ?></strong></div>

<h2>AI 运行统计（来自审计日志真实字段）</h2>
<div class="grid">
  <div class="card"><div class="l">AI 信号覆盖</div><div class="v"><?= $aiSignals ?: '0' ?></div><div class="l">最近 <?= count($attackLines) ?> 条中含 AI 信号字段</div></div>
  <div class="card"><div class="l">贝叶斯样本</div><div class="v"><?= $modelReady ? ($attackSamples + $normalSamples) : '暂无' ?></div><div class="l"><?= $modelReady ? ('攻击 ' . $attackSamples . ' / 正常 ' . $normalSamples) : '模型尚未训练' ?></div></div>
  <div class="card"><div class="l">冷启动降级</div><div class="v"><?= $aiColdStart ?></div><div class="l">冷启动标记出现次数</div></div>
  <div class="card"><div class="l">语义解析层</div><div class="v"><?= $semanticEnabled ? $semanticScored : '未加载' ?></div><div class="l"><?= $semanticEnabled ? '语义评分命中次数' : '核心+AI 精简模式' ?></div></div>
  <div class="card"><div class="l">误报复核放行</div><div class="v"><?= $fpOverrides ?></div><div class="l" title="fp_narrative_override">叙述性文本复核放行次数</div></div>
  <div class="card"><div class="l">布尔加固拦截</div><div class="v"><?= $tautologyBlocks ?></div><div class="l" title="sql_boolean_tautology">SQL 布尔恒真拦截次数</div></div>
  <div class="card"><div class="l">绕过结构拦截</div><div class="v"><?= $bypassBlocks ?></div><div class="l" title="bypass_structure_block">编码混淆绕过拦截次数</div></div>
</div>

<h2>拦截原因分布（真实统计）</h2>
<?php if (!$reasonCount): ?>
  <div class="empty">暂无攻击记录。可用 <code>?id=1' OR 1=1--</code> 之类的请求测试。</div>
<?php else: ?>
<table><thead><tr><th>原因</th><th>次数</th></tr></thead><tbody>
<?php foreach ($reasonCount as $r => $c): ?><tr><td class="u" title="<?= e($r) ?>"><?= e(wafCnReason((string)$r)) ?></td><td><?= (int)$c ?></td></tr><?php endforeach; ?>
</tbody></table>
<?php endif; ?>

<h2>最近审计事件（最多 300 条，倒序）</h2>
<?php if (!$rows): ?>
  <div class="empty">暂无审计事件</div>
<?php else: ?>
<table><thead><tr><th>时间</th><th>IP</th><th>路径</th><th>决策</th><th>分数</th><th>原因</th></tr></thead><tbody>
<?php foreach (array_slice($rows, 0, 80) as $r): ?>
  <tr>
    <td><?= e($r['ts'] ?? '') ?></td>
    <td><?= e($r['ip'] ?? '') ?></td>
    <td class="u"><?= e($r['uri'] ?? '') ?></td>
    <td><?php $a = (string)($r['action'] ?? ''); ?><span class="tag <?= in_array($a, ['block','challenge'], true) ? 'block' : 'mon' ?>" title="<?= e($a) ?>"><?= e(wafCnDecision($a)) ?></span></td>
    <td><?= e($r['score'] ?? '') ?></td>
    <td class="u"><?php $rz = (string)($r['raw'] ?? $r['reason'] ?? ''); ?><span title="<?= e($rz) ?>"><?= e(isset($r['raw']) ? (function_exists('mb_substr') ? mb_substr($rz, 0, 160, 'UTF-8') : substr($rz, 0, 160)) : wafCnReason((string)($r['reason'] ?? ''))) ?></span></td>
  </tr>
<?php endforeach; ?>
</tbody></table>
<?php endif; ?>

<h2>熔断状态（内核熔断快照）</h2>
<?php
$cbInfo = $circuitText === '' ? [] : json_decode($circuitText, true);
if (!is_array($cbInfo)) { $cbInfo = []; }
$cbRows = $circuitText === '' ? [] : wafCnCircuitRows($cbInfo);
?>
<?php if ($cbRows === []): ?>
  <div class="empty">暂无（尚未产生熔断状态快照）</div>
<?php else: ?>
  <table class="kv"><tbody>
  <?php foreach ($cbRows as [$ck, $cv]): ?>
    <tr><th><?= e($ck) ?></th><td><?= e($cv) ?></td></tr>
  <?php endforeach; ?>
  </tbody></table>
  <details class="raw"><summary>查看原始快照（排障用）</summary><pre><?= e($circuitText) ?></pre></details>
<?php endif; ?>

<h2>QPS 限流与熔断状态（接入层真实快照）</h2>
<?php
$ctlQps = wafQpsSnapshot($logDir, wafQpsConfig($ctlRt), $wafHome);
$qpsJson = json_encode($ctlQps, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
$qpsRows = wafCnQpsRows($ctlQps);
?>
<table class="kv"><tbody>
<?php foreach ($qpsRows as [$qk, $qv]): ?>
  <tr><th><?= e($qk) ?></th><td><?= e($qv) ?></td></tr>
<?php endforeach; ?>
</tbody></table>
<details class="raw"><summary>查看原始快照（排障用）</summary><pre><?= e((string)$qpsJson) ?></pre></details>

<?php
$hpView = wafHpView($ctlRt) + ['hits' => wafHpHits($yslDir, $wafHome . '/logs/ysl')];
$hpCn   = wafCnHoneypot($hpView);
?>
<h2>蜜罐状态（高危 · 默认停用）</h2>
<div class="note" style="border-color:rgba(251,113,133,.4);color:#fca5a5">
  触碰诱饵的请求会被延迟响应、投喂假数据并标记为「确认恶意」。因此蜜罐默认停用；
  启用必须手动输入确认短语、填写用途、设定有效期并勾选确认，到期自动停用。
  当前：<strong><?= e($hpCn['label'] . ' · ' . $hpCn['note']) ?></strong>
</div>
<table class="kv"><tbody>
<?php foreach (wafCnHoneypotRows($hpView) as [$hk, $hv]): ?>
  <tr><th><?= e($hk) ?></th><td><?= e($hv) ?></td></tr>
<?php endforeach; ?>
</tbody></table>

<h2>控制台操作（零 JavaScript，原生表单直连 /waf-control）</h2>
<?php
$cgNames = [
    'ai'        => 'AI 自学习',
    'fp'        => '叙述性误报复核',
    'tautology' => '布尔恒真加固',
    'bypass'    => '绕过结构加固',
    'errors'    => '错误输出',
];
?>
<div class="ctl-group">
  <h3>运行模式与防护开关</h3>
  <p class="hint">当前模式 <strong><?= e(wafCnMode($ctlRt['mode'])) ?></strong>；点击后下一个请求立即生效，结果页回显真实状态。</p>
  <?= ctlForm($ctlRt['mode'] === 'enforce' ? '切换为观察模式' : '恢复强制拦截', 'mode.set',
              ['value' => $ctlRt['mode'] === 'enforce' ? 'observe' : 'enforce']) ?>
  <?php foreach ($cgNames as $k => $n): ?>
    <?= ctlForm($n . ' → ' . ($ctlRt['guards'][$k] ? '关闭' : '开启'), 'guard.set',
                ['name' => $k, 'on' => $ctlRt['guards'][$k] ? '0' : '1']) ?>
  <?php endforeach; ?>
</div>

<div class="ctl-group">
  <h3>蜜罐诱捕（高危 · 默认停用）</h3>
  <p class="hint">启用需手动输入「启用蜜罐」四个字 + 用途留痕 + 有效期（最长 240 分钟）+ 勾选确认；到期由入口自动停用。停用是安全侧动作，一键立即生效。</p>
  <form method="post" action="/waf-control" class="cf" style="flex-wrap:wrap;gap:8px">
    <input type="hidden" name="key" value="<?= e($given) ?>">
    <input type="hidden" name="csrf" value="<?= e($ctlCsrf) ?>">
    <input type="hidden" name="format" value="html">
    <input type="hidden" name="action" value="honeypot.enable">
    <label style="font-size:11px;color:#94a3b8">确认短语
      <input type="text" name="params[phrase]" placeholder="启用蜜罐" style="display:block;margin-top:3px;padding:5px 7px;border-radius:6px;border:1px solid rgba(148,163,184,.3);background:#0f1b2e;color:#e2e8f0;width:130px">
    </label>
    <label style="font-size:11px;color:#94a3b8">用途
      <input type="text" name="params[reason]" placeholder="红队演练" style="display:block;margin-top:3px;padding:5px 7px;border-radius:6px;border:1px solid rgba(148,163,184,.3);background:#0f1b2e;color:#e2e8f0;width:130px">
    </label>
    <label style="font-size:11px;color:#94a3b8">有效期（分钟）
      <input type="number" name="params[minutes]" value="30" min="1" max="240" style="display:block;margin-top:3px;padding:5px 7px;border-radius:6px;border:1px solid rgba(148,163,184,.3);background:#0f1b2e;color:#e2e8f0;width:96px">
    </label>
    <label class="cf-danger"><input type="checkbox" name="confirm" value="1"> 确认开启</label>
    <button type="submit" class="danger">启用蜜罐（高危）</button>
  </form>
  <?= ctlForm('立即停用蜜罐', 'honeypot.disable') ?>
  <?= ctlForm('读取蜜罐状态', 'honeypot.state') ?>
  <?= ctlForm('清理蜜罐索引', 'honeypot.clear') ?>
</div>

<div class="ctl-group">
  <h3>熔断 / 状态文件 / 审计日志</h3>
  <p class="hint">清理动作返回真实删除文件数；归档保留原文副本。</p>
  <?= ctlForm('熔断复位（恢复正常放行）', 'circuit.reset') ?>
  <?= ctlForm('清理时间窗口', 'windows.clear') ?>
  <?= ctlForm('清理攻击链', 'chains.clear') ?>
  <?= ctlForm('清理蜜罐索引', 'honeypot.clear') ?>
  <?= ctlForm('清理临时锁', 'locks.clear') ?>
  <?= ctlForm('归档攻击日志', 'logs.rotate') ?>
  <?= ctlForm('导出审计日志', 'logs.export') ?>
</div>

<div class="ctl-group">
  <h3>QPS 限流与熔断（接入层）</h3>
  <p class="hint">软阈值触发 429 限流，硬阈值触发 502 保护性熔断，冷却结束自动半开试探恢复；大屏 / 控制台 / 控制端点豁免。全部字段一次写入 <code>var/data/runtime.json</code> 并回读。</p>
  <form method="post" action="/waf-control" class="cf" style="flex-wrap:wrap;gap:8px">
    <input type="hidden" name="key" value="<?= e($given) ?>">
    <input type="hidden" name="csrf" value="<?= e($ctlCsrf) ?>">
    <input type="hidden" name="format" value="html">
    <input type="hidden" name="action" value="qps.config">
    <input type="hidden" name="confirm" value="1">
    <?php foreach ([
        'soft' => '全局软阈值', 'hard' => '全局硬阈值',
        'ip_soft' => '单 IP 软阈值', 'ip_hard' => '单 IP 硬阈值', 'cooldown' => '冷却秒数',
    ] as $qk => $qlb): ?>
      <label style="font-size:11px;color:#94a3b8"><?= e($qlb) ?>
        <input type="number" name="params[<?= e($qk) ?>]" value="<?= (int)$ctlRt['qps'][$qk] ?>"
               min="1" max="1000000" style="display:block;margin-top:3px;padding:5px 7px;border-radius:6px;border:1px solid rgba(148,163,184,.3);background:#0f1b2e;color:#e2e8f0;width:118px">
      </label>
    <?php endforeach; ?>
    <button type="submit">保存 QPS 阈值</button>
  </form>
  <?= ctlForm($ctlRt['qps']['enabled'] ? '停用保护（只计数）' : '启用保护', 'qps.config',
              ['enabled' => $ctlRt['qps']['enabled'] ? '0' : '1']) ?>
  <?= ctlForm('读取实时状态', 'qps.state') ?>
  <?= ctlForm('复位计数与状态', 'qps.reset') ?>
  <?= ctlForm('演练熔断 → 502', 'qps.open', [], true) ?>
  <?= ctlForm('强制恢复（正常放行）', 'qps.close') ?>
</div>

<div class="ctl-group">
  <h3>文件 DNA 防篡改</h3>
  <p class="hint">调用独立 CLI 进程，不占用请求管线；危险项需勾选确认。</p>
  <?= ctlForm('试算巡检范围', 'dna.plan') ?>
  <?= ctlForm('只读巡检', 'dna.scan') ?>
  <?= ctlForm('查看状态', 'dna.status') ?>
  <?= ctlForm('能力自检', 'dna.selftest') ?>
  <?= ctlForm('启动守护', 'dna.watch.start') ?>
  <?= ctlForm('停止守护', 'dna.watch.stop', [], true) ?>
  <?= ctlForm('重建基线', 'dna.rebaseline', [], true) ?>
  <?= ctlForm('处置高置信篡改', 'dna.apply', [], true) ?>
</div>

<div class="ctl-group">
  <h3>危险操作（需勾选「确认」）</h3>
  <p class="hint">清空日志 / 重置模型 / 恢复出厂 / 轮换密钥 / 清空白名单，均不可自动回滚。</p>
  <?= ctlForm('清空攻击日志', 'logs.purge', [], true) ?>
  <?= ctlForm('重置贝叶斯模型', 'ai.model.reset', [], true) ?>
  <?= ctlForm('恢复出厂配置', 'runtime.reset', [], true) ?>
  <?= ctlForm('清空白名单', 'whitelist.clear', [], true) ?>
  <?= ctlForm('轮换控制台密钥', 'key.rotate', [], true) ?>
</div>

<div class="note">完整控制面（全部动作、状态联动、二次确认、操作审计）在
  <a style="color:#22d3ee" href="/waf-screen?key=<?= rawurlencode($given) ?>">态势大屏 · 控制台抽屉</a>；
  所有操作写入 <code>logs/ysl/control.log</code>，不污染 attack.log 指标。</div>

</div></body></html>
