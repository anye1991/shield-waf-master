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
 * YSL语枢-盾甲WAF · 实时威胁态势大屏
 *
 * 设计原则沿用 console.php：指标只读、零占位数字、不引外部资源；控制操作集中在右上角抽屉。
 *   - 所有指标由内核真实审计日志（attack.log / 状态文件）聚合，无数据即显示「暂无」
 *   - 纯服务端渲染 + 内联 CSS/SVG，原生 JS 仅做定时增量刷新，离线 / CSP 环境也能看
 *   - key 鉴权沿用 var/data/console.key，与只读控制台同一把钥匙
 *
 * 访问：/waf-screen?key=<var/data/console.key 里的值>
 * 片段：/waf-screen?key=...&format=fragment   （供大屏自身轮询，只回 #app 内部）
 * 数据：/waf-screen?key=...&format=json       （供外部系统取数，字段与页面一致）
 * 快照：/waf-screen?key=...&static=1          （禁用轮询，便于另存为静态 HTML 演示）
 */
declare(strict_types=1);

// ---------------------------------------------------------------- 路径 / 鉴权
$wafHome = defined('WAF_HOME') ? rtrim(str_replace('\\', '/', WAF_HOME), '/')
                               : rtrim(str_replace('\\', '/', __DIR__), '/');
$logDir  = defined('WAF_LOG_PATH')  ? rtrim(str_replace('\\', '/', WAF_LOG_PATH), '/')
                                    : rtrim(str_replace('\\', '/', getenv('WAF_LOG_DIR') ?: ($wafHome . '/var/logs')), '/');
$dataDir = defined('WAF_DATA_PATH') ? rtrim(str_replace('\\', '/', WAF_DATA_PATH), '/')
                                    : rtrim(str_replace('\\', '/', getenv('WAF_DATA_DIR') ?: ($wafHome . '/var/data')), '/');
$yslDir     = rtrim($logDir, '/') . '/ysl';
$fallback   = $wafHome . '/logs/ysl';           // 持久化快照（tmpfs 重启后仍可见）
$keyFile    = $dataDir . '/console.key';
// 运行目录指向 tmpfs 时，回退到站点持久目录里由 install.php 生成的同一把钥匙，
// 避免容器重启 / tmpfs 清空后大屏与控制台同时变成 403。
if (!is_file($keyFile)) {
    $persistKey = $wafHome . '/var/data/console.key';
    if (is_file($persistKey)) { $keyFile = $persistKey; }
}
$circuitFile = $yslDir . '/circuit_state.json';

if (!headers_sent()) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
}

$key   = is_file($keyFile) ? trim((string)@file_get_contents($keyFile)) : '';
$given = isset($_GET['key']) && is_string($_GET['key']) ? $_GET['key'] : '';
if ($key === '' || $given === '' || !hash_equals($key, $given)) {
    if (!headers_sent()) { http_response_code(403); }
    echo '<!doctype html><meta charset="utf-8"><title>YSL语枢-盾甲WAF · 态势大屏</title>',
         '<body style="margin:0;background:#050a16;color:#e8f2ff;font:14px/1.7 system-ui;display:flex;align-items:center;justify-content:center;height:100vh">',
         '<div style="text-align:center"><div style="font-size:44px;color:#22d3ee;text-shadow:0 0 24px #22d3ee">403</div>',
         '<h2 style="font-weight:500;letter-spacing:2px">未授权或密钥未初始化</h2>',
         '<p style="color:#7c93b4">运行 <code style="color:#a78bfa">php install.php --site=/你的站点</code> 生成密钥，',
         '用安装时打印的完整链接访问。</p>',
         '<p style="color:#7c93b4;font-size:12px">本页指标为只读展示，控制操作在右上角「控制台」抽屉。</p></div></body>';
    return;
}

$fmt    = isset($_GET['format']) && is_string($_GET['format']) ? $_GET['format'] : '';
$static = isset($_GET['static']) && $_GET['static'] === '1';

// 控制台面板：运行时配置、CSRF、DNA 守护与操作审计。
// 静态快照一律不输出密钥与 CSRF token：离线 HTML 天然无法发起控制请求。
require_once __DIR__ . '/runtime.php';
require_once __DIR__ . '/features.php';
$ctlRt    = wafRtRead($wafHome);
$ctlCsrf  = $static ? '' : wafCtlToken($key);
$ctlWatch = wafCtlWatchPid($wafHome);
$ctlAudit = wafCtlRecent($wafHome, 6);

// ---------------------------------------------------------------- 数据聚合
function sE($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function sNum($v): string { return number_format((float)$v, 0, '.', ','); }

/** 控制台按钮：动作、参数、是否危险（需二次点击确认）全部走 data-*，JS 统一分派 */
function sCtlBtn(string $label, string $act, array $params = [], bool $danger = false, string $extra = ''): string {
    $json = json_encode($params, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    return '<button type="button" class="cb ' . ($danger ? 'cb-danger ' : '') . $extra . '"'
         . ' data-act="' . sE($act) . '" data-params="' . sE((string)$json) . '"'
         . ($danger ? ' data-danger="1"' : '') . ' title="' . sE(wafCnAction($act)) . '">'
         . sE($label) . '</button>';
}

/** 读取文件 DNA 独立进程写的只读状态快照；多路径回退，无数据显示「暂无」 */
function sLoadDnaStatus(string $wafHome, string $dataDir): array {
    $candidates = [
        $wafHome . '/var/data/dna-status.json',   // 持久目录（容器 / tmpfs 部署）
        $dataDir . '/dna-status.json',            // 运行数据目录
        $wafHome . '/var/dna/dna-status.json',    // 兼容旧位置
    ];
    foreach (array_unique($candidates) as $f) {
        if (!is_file($f)) { continue; }
        $d = json_decode((string)@file_get_contents($f), true);
        if (!is_array($d) || !isset($d['files'])) { continue; }
        $age = time() - (int)($d['last_check'] ?? 0);
        $d['_source'] = $f;
        $d['_age']    = max(0, $age);
        // 只判断「文件存在」会把死进程显示成绿灯，必须看心跳年龄
        $d['_alive']  = $age <= 180;
        return $d;
    }
    return [];
}

/** DNA 事件类型 → [中文名, 配色类] */
function sDnaKind(string $k): array {
    $map = [
        'baseline'           => ['建立基线', 'info'],
        'baseline_unsigned'  => ['基线补签', 'info'],
        'baseline_bad_sig'   => ['签名异常', 'danger'],
        'malicious'          => ['恶意篡改', 'danger'],
        'new_malicious'      => ['落地后门', 'danger'],
        'dual_tamper'        => ['备份异常', 'danger'],
        'tamper'             => ['内容变更', 'warn'],
        'missing'            => ['文件缺失', 'warn'],
        'surgery_fail'       => ['手术失败', 'warn'],
        'quarantined'        => ['已隔离', 'act'],
        'surgery'            => ['精准手术', 'act'],
        'restored'           => ['整体还原', 'act'],
        'new_file'           => ['新文件', 'info'],
        'adopted'            => ['纳入基线', 'info'],
    ];
    return $map[$k] ?? [$k, 'info'];
}

/**
 * 文件 DNA 指示灯组。每个灯位只取 dna-status.json 的真实字段，绝不编造状态。
 * 语义：on=绿（正常） / warn=琥珀（注意、降级） / danger=红（告警） / info=青（未建档等架构事实）。
 * 第 1 盏是汇总灯，同时供标题与底部「运行状态」栏复用；其余为分项灯。
 */
function sDnaLamps(array $d): array {
    if ($d === []) {
        $idle = static function (string $name): array {
            return ['name' => $name, 'state' => 'info', 'note' => '待建档',
                    'title' => '尚未建立 DNA 基线：运行 php dna.php baseline'];
        };
        return [
            ['name' => '文件 DNA', 'state' => 'info', 'note' => '未建档',
             'title' => '尚未建立 DNA 基线：运行 php dna.php baseline'],
            $idle('巡检心跳'), $idle('基线签名'), $idle('本轮完整性'), $idle('处置模式'),
        ];
    }
    $alive    = !empty($d['_alive']);
    $sigOK    = !empty($d['baseline_ok']);
    $healthy  = !empty($d['healthy']);
    $round    = (int)($d['round_high'] ?? 0);
    $err      = (string)($d['last_error'] ?? '');
    $danger   = !$sigOK || !$healthy || $round > 0 || $err !== '';
    $files    = (int)($d['files'] ?? 0);
    $age      = (int)($d['_age'] ?? 0);
    $readOnly = !empty($d['read_only']);
    $surgTxt  = !empty($d['surgery_on']) ? '手术开' : '手术关';

    $summary = $danger
        ? ['state' => 'danger', 'note' => '检出异常']
        : (!$alive ? ['state' => 'warn', 'note' => '进程未运行']
                   : ['state' => 'on', 'note' => '完好 · ' . $files . ' 文件']);

    return [
        array_merge(['name' => '文件 DNA', 'title' => '文件 DNA 只读状态指示，不可点击'], $summary),
        ['name' => '巡检心跳', 'state' => $alive ? 'on' : 'warn',
         'note'  => $alive ? ($age . 's 前心跳') : '心跳超时',
         'title' => $alive
             ? ('最近一次巡检 ' . $age . ' 秒前 · 间隔 ' . (int)($d['interval'] ?? 0) . ' 秒')
             : '超过 180 秒无心跳，判定守护进程未运行'],
        ['name' => '基线签名', 'state' => $sigOK ? 'on' : 'danger',
         'note'  => $sigOK ? 'HMAC 通过' : '签名异常',
         'title' => $sigOK ? '基线 HMAC-SHA256 校验通过'
                           : '基线签名不可信：已强制只读，禁止自动还原'],
        ['name' => '本轮完整性', 'state' => $danger ? 'danger' : 'on',
         'note'  => $danger ? '本轮异常' : '本轮无异常',
         'title' => $danger
             ? ('本轮高置信 ' . $round . ' 条' . ($err !== '' ? ' · 最近错误：' . $err : ''))
             : ('累计变更 ' . (int)($d['tamper_hits'] ?? 0) . ' 次 · 历史高置信 '
                . (int)($d['high'] ?? 0) . ' 条（均已处置留档）')],
        ['name' => '处置模式', 'state' => $readOnly ? 'warn' : 'on',
         'note'  => ($readOnly ? '只读守护' : '自动处置') . ' · ' . $surgTxt,
         'title' => $readOnly ? '当前只读告警：只记录与留档，不改动站点文件'
                              : '当前允许自动处置高置信篡改'],
    ];
}

/**
 * QPS 接入层指示灯。全部取自 qps_state.json 的真实快照，不编造数值。
 * 语义与 DNA 灯一致：on=绿 / warn=琥珀 / danger=红 / info=青。
 * 第 1 盏是汇总灯，标题与底栏复用；其余为分项灯。
 */
function sQpsLamps(array $q): array {
    if ($q === []) {
        return [['name' => 'QPS 熔断', 'state' => 'info', 'note' => '待初始化',
                 'title' => '尚未产生 QPS 状态快照']];
    }
    $enabled = !empty($q['enabled']);
    $state   = (string)($q['state'] ?? 'closed');
    $qps     = (int)($q['qps'] ?? 0);
    $soft    = (int)($q['soft'] ?? 0);
    $rejects = (int)($q['rejects'] ?? 0);
    $left    = (int)($q['retry_left'] ?? 0);

    if (!$enabled) {
        $head = ['state' => 'info', 'note' => '已停用'];
    } elseif ($state === 'open') {
        $head = ['state' => 'danger', 'note' => '熔断中 · ' . $left . 's'];
    } elseif ($state === 'half_open') {
        $head = ['state' => 'warn', 'note' => '半开试探'];
    } elseif ($soft > 0 && $qps >= $soft) {
        $head = ['state' => 'warn', 'note' => '限流临界'];
    } else {
        $head = ['state' => 'on', 'note' => '正常 · ' . $qps . ' QPS'];
    }
    return [
        array_merge(['name' => 'QPS 熔断', 'title' => '接入层 QPS 只读状态指示，不可点击'], $head),
        ['name' => '保护开关', 'state' => $enabled ? 'on' : 'info',
         'note'  => $enabled ? '已启用' : '已停用',
         'title' => $enabled ? '429 限流与 502 熔断均处于生效状态' : '当前只计数不拦截'],
        ['name' => '全局阈值', 'state' => 'on',
         'note'  => $soft . ' / ' . (int)($q['hard'] ?? 0) . ' QPS',
         'title' => '软阈值触发 429，硬阈值触发 502 熔断'],
        ['name' => '单 IP 阈值', 'state' => 'on',
         'note'  => (int)($q['ip_soft'] ?? 0) . ' / ' . (int)($q['ip_hard'] ?? 0) . ' QPS',
         'title' => '追踪 ' . (int)($q['ip_tracked'] ?? 0) . ' 个近期来源（仅存哈希）'],
        ['name' => '冷却恢复', 'state' => $state === 'open' ? 'warn' : 'on',
         'note'  => (int)($q['cooldown'] ?? 0) . 's 冷却',
         'title' => $state === 'open' ? ('剩余 ' . $left . ' 秒进入半开试探') : '熔断结束后自动半开试探并恢复'],
        ['name' => '拒绝累计', 'state' => $rejects > 0 ? 'warn' : 'on',
         'note'  => '拒绝 ' . $rejects . ' · 峰值 ' . (int)($q['peak'] ?? 0),
         'title' => '最近 429：' . ((int)($q['last_429'] ?? 0) ? date('H:i:s', (int)$q['last_429'] + 8 * 3600) : '无')
                    . ' · 最近 502：' . ((int)($q['last_502'] ?? 0) ? date('H:i:s', (int)$q['last_502'] + 8 * 3600) : '无')],
    ];
}

/**
 * 汇总真实审计事件：运行目录（可能是 tmpfs）+ 持久化归档目录一并读取，去重后按时间排序。
 * tmpfs 重启后高频日志会清空，只读主目录会让大屏突然变空；合并两个真实来源即可持续展示，
 * 去重避免归档重叠导致指标翻倍。绝不编造数据。
 */
function sLoadEvents(string $yslDir, string $fallback, int $limit = 8000): array {
    $sources = [];
    $lines   = [];
    foreach ([$yslDir . '/attack.log', $fallback . '/attack.log'] as $f) {
        if (!is_file($f) || filesize($f) < 1) { continue; }
        $l = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (is_array($l) && $l !== []) {
            $sources[] = $f;
            foreach ($l as $x) { $lines[] = $x; }
        }
    }
    if ($lines === []) { return ['events' => [], 'source' => '', 'lines' => 0, 'raw' => 0]; }
    $raw  = count($lines);
    $seen = [];
    $events = [];
    foreach ($lines as $line) {
        $d = json_decode($line, true);
        if (!is_array($d)) { continue; }
        $sig = md5(json_encode([
            $d['ts'] ?? '', $d['ip'] ?? '', $d['uri'] ?? '',
            $d['action'] ?? '', $d['score'] ?? '',
        ]));
        if (isset($seen[$sig])) { continue; }
        $seen[$sig] = true;
        $ts = isset($d['ts']) && is_numeric($d['ts']) ? (int)$d['ts'] : 0;
        if ($ts <= 0 && !empty($d['time'])) { $ts = (int)strtotime((string)$d['time'] . ' UTC'); }
        $events[] = [
            'ts'     => $ts,
            'time'   => (string)($d['time'] ?? ''),
            'ip'     => (string)($d['ip'] ?? $d['client_ip'] ?? '—'),
            'uri'    => (string)($d['uri'] ?? ''),
            'action' => (string)($d['action'] ?? $d['decision'] ?? ''),
            'reason' => (string)($d['reason'] ?? ''),
            'score'  => (int)($d['score'] ?? $d['final_score'] ?? 0),
            'ms'     => (float)($d['elapsed'] ?? 0),
            'type'   => (string)($d['core_graph']['effect_type'] ?? ''),
            'ai'     => !empty($d['ai_signals']) && is_array($d['ai_signals']),
            'cold'   => !empty($d['ai_signals']['cold_start']),
            'phases' => (array)($d['chain']['phases'] ?? []),
        ];
    }
    usort($events, static function (array $a, array $b): int { return $a['ts'] <=> $b['ts']; });
    if (count($events) > $limit) { $events = array_slice($events, -$limit); }
    return [
        'events' => $events,
        'source' => implode(' + ', $sources),
        'lines'  => count($events),
        'raw'    => $raw,
    ];
}

$TYPE_NAMES = [
    'rce' => '命令执行', 'cmdi' => '命令注入', 'sqli' => 'SQL 注入', 'xss' => '跨站脚本',
    'lfi' => '本地文件包含', 'path_traversal' => '路径穿越', 'nosql' => 'NoSQL 注入',
    'ldap' => 'LDAP 注入', 'ssrf' => '请求伪造', 'xpath' => 'XPath 注入',
    'deserial' => '反序列化', 'ssti' => '模板注入', 'xxe' => 'XML 外部实体',
    'crlf' => 'CRLF 注入', 'file_upload' => '恶意上传', 'scanner' => '扫描探测',
];
$REASON_NAMES = [
    'core_evidence_taint'      => '内核证据链拦截',
    'bypass_structure_block'   => '绕过结构加固',
    'sql_boolean_tautology'    => '布尔恒真加固',
    'taint_tracking_confirmed' => '污点追踪确认',
    'fp_narrative_override'    => '误报复核放行',
    'arbiter_low'              => '低分放行',
    'arbiter_medium'           => '中分观察',
    'arbiter_high'             => '高分拦截',
    'arbiter_critical'         => '危急拦截',
    'arbiter_info'             => '信息级放行',
    'magic_gate_blocked'       => '安全门拦截',
    'malicious_upload'         => '恶意上传',
    'normal'                   => '正常请求',
];
$PALETTE = ['#22d3ee', '#3b82f6', '#a78bfa', '#f472b6', '#fbbf24', '#34d399', '#fb7185', '#60a5fa', '#c084fc', '#2dd4bf'];

/** 把事件聚合成大屏所需的全部指标（同一份数据同时供 HTML 与 JSON 使用） */
function sBuild(array $load, string $yslDir, string $logDir, string $circuitFile, array $TYPE_NAMES, array $REASON_NAMES, string $wafHome, string $fallback): array {
    $ev = $load['events'];
    $n  = count($ev);
    $d  = [
        'meta' => [
            'version'    => defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : '6.5.0',
            'php'        => PHP_VERSION,
            'generated'  => date('Y-m-d H:i:s', time() + 8 * 3600),
            'source'     => $load['source'],
            'lines'      => $load['lines'],
            'raw'        => $load['raw'],
            'first'      => '—', 'last' => '—',
            'mode'       => getenv('WAF_MODE') ?: 'enforce',
            'tz'         => '北京时间 UTC+8',
        ],
        'kpi' => [], 'trend' => [], 'decisions' => [], 'reasons' => [], 'types' => [],
        'score_bins' => [], 'top_ips' => [], 'phases' => [], 'recent' => [],
        'switches' => [], 'circuit' => '', 'circuit_state' => 'normal', 'circuit_note' => '无记录', 'latency' => [],
    ];

    if ($n === 0) {
        return $d;
    }

    $tzOffset = 8 * 3600; // 日志为 UTC，统一以北京时间展示
    $blocks = $mons = $allows = 0;
    $fp = $ai = $cold = 0;
    $sumMs = 0.0; $msList = [];
    $reasonC = $typeC = $ipC = $phaseC = $minuteC = [];
    $bins = ['0-14' => 0, '15-29' => 0, '30-59' => 0, '60-89' => 0, '90-100' => 0];
    $tsList = [];

    foreach ($ev as $e) {
        $act = $e['action'];
        if ($act === 'block' || $act === 'challenge' || $act === 'not_found' || $act === 'unauthorized') { $blocks++; }
        elseif ($act === 'monitor') { $mons++; }
        else { $allows++; }
        if ($e['reason'] === 'fp_narrative_override') { $fp++; }
        if ($e['ai']) { $ai++; }
        if ($e['cold']) { $cold++; }
        if ($e['ms'] > 0) { $sumMs += $e['ms']; $msList[] = $e['ms']; }
        $rc = $e['reason'] !== '' ? $e['reason'] : '未标注';
        $reasonC[$rc] = ($reasonC[$rc] ?? 0) + 1;
        if ($e['type'] !== '') { $typeC[$e['type']] = ($typeC[$e['type']] ?? 0) + 1; }
        $ipC[$e['ip']] = ($ipC[$e['ip']] ?? 0) + 1;
        foreach ($e['phases'] as $p) { $phaseC[(string)$p] = ($phaseC[(string)$p] ?? 0) + 1; }
        $s = $e['score'];
        $bk = $s >= 90 ? '90-100' : ($s >= 60 ? '60-89' : ($s >= 30 ? '30-59' : ($s >= 15 ? '15-29' : '0-14')));
        $bins[$bk]++;
        if ($e['ts'] > 0) {
            $tsList[] = $e['ts'];
            $mk = (int)floor($e['ts'] / 60) * 60;
            if (!isset($minuteC[$mk])) { $minuteC[$mk] = ['b' => 0, 'm' => 0]; }
            if ($act === 'block' || $act === 'challenge') { $minuteC[$mk]['b']++; } else { $minuteC[$mk]['m']++; }
        }
    }
    sort($msList);
    $mn = count($msList);
    $p50 = $mn ? $msList[(int)floor($mn * 0.50)] : 0;
    $p95 = $mn ? $msList[(int)floor($mn * 0.95)] : 0;
    $mx  = $mn ? $msList[$mn - 1] : 0;
    $d['latency'] = ['p50' => round($p50, 1), 'p95' => round($p95, 1), 'max' => round($mx, 1)];

    $tsList = array_values(array_filter($tsList));
    $minTs = $tsList ? min($tsList) : 0;
    $maxTs = $tsList ? max($tsList) : 0;
    $d['meta']['first'] = $minTs ? date('m-d H:i', $minTs + $tzOffset) : '—';
    $d['meta']['last']  = $maxTs ? date('m-d H:i', $maxTs + $tzOffset) : '—';

    // 自适应时间桶：≤2 小时按分钟，≤2 天按小时，其余按天；最多 60 个桶
    $span = $maxTs - $minTs;
    $bucket = $span <= 7200 ? 60 : ($span <= 172800 ? 3600 : 86400);
    while ($span / $bucket > 60) { $bucket *= 2; }
    $trend = [];
    if ($minTs > 0) {
        $start = (int)floor($minTs / $bucket) * $bucket;
        $end   = (int)floor($maxTs / $bucket) * $bucket;
        for ($t = $start; $t <= $end && count($trend) < 60; $t += $bucket) {
            $trend[$t] = ['b' => 0, 'm' => 0];
        }
        foreach ($minuteC as $mk => $c) {
            $key = (int)floor($mk / $bucket) * $bucket;
            if (!isset($trend[$key])) { continue; }
            $trend[$key]['b'] += $c['b'];
            $trend[$key]['m'] += $c['m'];
        }
    }
    foreach ($trend as $t => $c) {
        $d['trend'][] = [
            'label' => $bucket >= 86400 ? date('m-d', $t + $tzOffset) : date('H:i', $t + $tzOffset),
            'block' => $c['b'], 'pass' => $c['m'],
        ];
    }
    $peak = 0;
    foreach ($d['trend'] as $p) { $peak = max($peak, $p['block'] + $p['pass']); }

    $today = date('Y-m-d', $maxTs + $tzOffset);
    $todayBlocks = 0;
    foreach ($ev as $e) {
        if (in_array($e['action'], ['block', 'challenge'], true)
            && $e['ts'] > 0 && date('Y-m-d', $e['ts'] + $tzOffset) === $today) { $todayBlocks++; }
    }

    $d['kpi'] = [
        'total'        => $n,
        'blocked'      => $blocks,
        'monitored'    => $mons,
        'allowed'      => $allows,
        'block_rate'   => $n ? round(100 * $blocks / $n, 1) : 0,
        'today_blocks' => $todayBlocks,
        'avg_ms'       => $mn ? round($sumMs / $mn, 1) : 0,
        'peak'         => $peak,
        'fp'           => $fp,
        'ai'           => $ai,
        'cold'         => $cold,
        'chain'        => count(glob($yslDir . '/chain_*.json') ?: []),
        'window'       => count(glob($yslDir . '/window_*.json') ?: []),
        'source_n'     => count($ipC),
    ];

    $d['decisions'] = [
        ['name' => '拦截', 'value' => $blocks, 'color' => '#22d3ee'],
        ['name' => '观察', 'value' => $mons,   'color' => '#fbbf24'],
        ['name' => '放行', 'value' => $allows, 'color' => '#a78bfa'],
    ];
    arsort($reasonC);
    $i = 0;
    foreach (array_slice($reasonC, 0, 8, true) as $k => $v) {
        $d['reasons'][] = ['name' => $REASON_NAMES[$k] ?? wafCnReason($k), 'raw' => $k, 'value' => $v, 'color' => $GLOBALS['PALETTE'][$i % 10]];
        $i++;
    }
    arsort($typeC);
    $i = 0;
    foreach (array_slice($typeC, 0, 9, true) as $k => $v) {
        $d['types'][] = ['name' => $TYPE_NAMES[$k] ?? (wafCnReason($k) === '其他原因' ? $k : wafCnReason($k)), 'raw' => $k, 'value' => $v, 'color' => $GLOBALS['PALETTE'][$i % 10]];
        $i++;
    }
    foreach ($bins as $k => $v) { $d['score_bins'][] = ['name' => $k, 'value' => $v]; }
    arsort($ipC);
    foreach (array_slice($ipC, 0, 6, true) as $k => $v) {
        $d['top_ips'][] = ['name' => $k, 'value' => $v];
    }
    arsort($phaseC);
    foreach (array_slice($phaseC, 0, 6, true) as $k => $v) {
        $d['phases'][] = ['name' => $k, 'value' => $v];
    }

    $recent = array_slice(array_reverse($ev), 0, 14);
    foreach ($recent as $e) {
        $d['recent'][] = [
            'time'   => $e['ts'] > 0 ? date('H:i:s', $e['ts'] + $tzOffset) : '—',
            'ip'     => $e['ip'], 'uri' => $e['uri'], 'action' => $e['action'],
            'score'  => $e['score'], 'reason' => $REASON_NAMES[$e['reason']] ?? wafCnReason((string)$e['reason']),
        ];
    }

    // AI 模型可能落在运行目录(tmpfs)、包内 var/logs 或日志归档目录；
    // 逐一回退，避免容器重启 / tmpfs 清空后把「已训练」误显示成「未训练」。
    $model = [];
    foreach ([
        $logDir . '/bayes_model.json',
        $yslDir . '/bayes_model.json',
        $wafHome . '/var/logs/bayes_model.json',
        $wafHome . '/logs/bayes_model.json',
        $fallback . '/bayes_model.json',
    ] as $mf) {
        if (!is_file($mf)) { continue; }
        $m = json_decode((string)@file_get_contents($mf), true);
        if (is_array($m)) { $model = $m; break; }
    }
    $attackSamples = (int)($model['classes']['attack']['count'] ?? 0);
    $normalSamples = (int)($model['classes']['normal']['count'] ?? 0);
    $trained = ($attackSamples + $normalSamples) > 0;

    // 状态指示统一为三态 + 明确文案，不再用「灰掉的开关」这种容易被误读成
    // 禁用按钮的表现。info 表示架构事实，不是故障。
    $guard = function (string $env): array {
        $on = getenv($env) !== '0';
        return ['state' => $on ? 'on' : 'warn', 'note' => $on ? '已启用' : '已关闭'];
    };
    $d['switches'] = [
        array_merge(['name' => 'AI 自学习'], $guard('WAF_AI_ENABLED')),
        // v6.1.0 起精简模式已移除 semantic/：这是架构事实，不是「没开的功能」
        ['name' => '语义解析层', 'state' => 'info', 'note' => '精简模式已移除'],
        array_merge(['name' => '叙述性复核'], $guard('WAF_FP_GUARD')),
        array_merge(['name' => '布尔恒真加固'], $guard('WAF_TAUTOLOGY_GUARD')),
        array_merge(['name' => '绕过结构加固'], $guard('WAF_BYPASS_GUARD')),
        ['name' => '贝叶斯样本', 'state' => $trained ? 'on' : 'warn',
         'note' => $trained ? ('攻 ' . $attackSamples . ' / 正 ' . $normalSamples) : '未训练'],
    ];

    // 熔断：解析 JSON 判断真实状态。closed/normal 是健康态，
    // 不能因为「文件非空」就标成有状态；同时只输出精简摘要，不把整段 JSON 糊在页面上。
    $cRaw  = is_file($circuitFile) ? trim((string)@file_get_contents($circuitFile)) : '';
    $cInfo = $cRaw !== '' ? json_decode($cRaw, true) : [];
    if (!is_array($cInfo)) { $cInfo = []; }
    $cState = strtolower((string)($cInfo['state'] ?? ''));
    $cMode  = strtolower((string)($cInfo['mode'] ?? ''));
    $cAlert = ($cState !== '' && $cState !== 'closed')
        || in_array($cMode, ['degrade', 'emergency', 'circuit'], true);
    $d['circuit_state'] = $cAlert ? 'alert' : 'normal';
    // 状态与运行级别全部走中文映射；内部判定仍用英文原值，展示层不裸露枚举
    $d['circuit_note']  = $cRaw === '' ? '无记录'
        : (($cState === '' ? '暂无记录' : wafCnState($cState)) . ' / ' . ($cMode === '' ? '暂无记录' : wafCnState($cMode)));
    $d['circuit'] = $cRaw === '' ? '' : sprintf(
        '%s · %s · QPS %s · 连续失败 %s · 熔断阈值 %s ms',
        $cState === '' ? '暂无记录' : wafCnState($cState),
        $cMode === '' ? '暂无记录' : wafCnState($cMode),
        (string)($cInfo['qps'] ?? 0),
        (string)($cInfo['consecutive_failures'] ?? 0),
        (string)($cInfo['thresholds']['circuit'] ?? '—')
    );
    return $d;
}

$load = sLoadEvents($yslDir, $fallback);
$data = sBuild($load, $yslDir, $logDir, $circuitFile, $TYPE_NAMES, $REASON_NAMES, $wafHome, $fallback);
// 主机层第二道防线：文件 DNA 独立进程的状态快照（只读，不进审计哈希链）
$data['dna'] = sLoadDnaStatus($wafHome, $dataDir);
// 指示灯与页面同源：JSON 接口也带上灯组，避免外部取数时只能靠猜状态
$data['dna_lamps'] = sDnaLamps($data['dna']);
// v6.4.0：接入层 QPS 限流 / 熔断真实快照，页面、指示灯与 JSON 同一个数据源
$ctlQpsCfg = wafQpsConfig($ctlRt);
$data['qps'] = wafQpsSnapshot($logDir, $ctlQpsCfg, $wafHome);
$data['qps_lamps'] = sQpsLamps($data['qps']);

// v6.5.0：全功能控制矩阵。每个功能的灯与状态都取自真实运行数据，
// 每条记录都绑定一个真实后端动作，HTML / JSON / 静态快照共用这一份数据。
$sAttackFiles = array_unique([$yslDir . '/attack.log', $fallback . '/attack.log']);
$sLogBytes = 0;
foreach ($sAttackFiles as $lf) { if (is_file($lf)) { $sLogBytes += (int)@filesize($lf); } }
$sModel = [];
foreach ([$logDir . '/bayes_model.json', $yslDir . '/bayes_model.json',
          $wafHome . '/var/logs/bayes_model.json', $wafHome . '/logs/bayes_model.json',
          $fallback . '/bayes_model.json'] as $mf) {
    if (is_file($mf)) {
        $mj = json_decode((string)@file_get_contents($mf), true);
        if (is_array($mj)) { $sModel = $mj; break; }
    }
}
$sTrained = ((int)($sModel['classes']['attack']['count'] ?? 0)
           + (int)($sModel['classes']['normal']['count'] ?? 0)) > 0;
$sAuditFile = wafCtlLogPath($wafHome);
$sAuditCount = is_file($sAuditFile) ? count(@file($sAuditFile, FILE_SKIP_EMPTY_LINES) ?: []) : 0;
$sHp = wafHpView($ctlRt) + ['hits' => wafHpHits($yslDir, $fallback)];
$data['features'] = wafFeatures([
    'home'          => $wafHome,
    'rt'            => $ctlRt,
    'qps'           => $data['qps'],
    'dna'           => $data['dna'],
    'watch_pid'     => $ctlWatch,
    'log_bytes'     => $sLogBytes,
    'circuit_note'  => $data['circuit_note'],
    'whitelist_n'   => count($ctlRt['whitelist']),
    'hp'            => $sHp,
    'body_max'      => $ctlRt['body_max'],
    'chain_files'   => count(glob($yslDir . '/chain_*.json') ?: []),
    'window_files'  => count(glob($yslDir . '/window_*.json') ?: []),
    'model_trained' => $sTrained,
    'audit_count'   => $sAuditCount,
    'period'        => 5,
]);
$data['honeypot'] = $sHp;

if ($fmt === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    return;
}

// ---------------------------------------------------------------- SVG / HTML 组件
function sAreaChart(array $trend): string {
    if (!$trend) { return '<div class="empty">暂无趋势数据</div>'; }
    $W = 1300; $H = 230; $pl = 46; $pr = 14; $pt = 16; $pb = 30;
    $n = count($trend);
    $max = 1;
    foreach ($trend as $p) { $max = max($max, $p['block'] + $p['pass']); }
    $max = (int)ceil($max / 10) * 10;
    if ($max < 10) { $max = 10; }
    $x = static function (int $i) use ($n, $W, $pl, $pr): float {
        return $n <= 1 ? $pl : $pl + $i * ($W - $pl - $pr) / ($n - 1);
    };
    $y = static function (float $v) use ($H, $pt, $pb, $max): float {
        return $H - $pb - $v / $max * ($H - $pt - $pb);
    };
    $g = '';
    for ($k = 0; $k <= 4; $k++) {
        $gy = $pt + $k * ($H - $pt - $pb) / 4;
        $val = (int)round($max * (4 - $k) / 4);
        $g .= '<line x1="' . $pl . '" y1="' . $gy . '" x2="' . ($W - $pr) . '" y2="' . $gy . '" stroke="rgba(120,170,220,.10)" stroke-width="1"/>';
        $g .= '<text x="' . ($pl - 8) . '" y="' . ($gy + 4) . '" fill="#5f779b" font-size="10" text-anchor="end">' . $val . '</text>';
    }
    // 标签控制在 6 个以内，避免分钟级密集时间桶相互重叠
    $step = max(1, (int)ceil($n / 6));
    foreach ($trend as $i => $p) {
        if ($i % $step !== 0) { continue; }
        $g .= '<text x="' . $x($i) . '" y="' . ($H - 8) . '" fill="#5f779b" font-size="10" text-anchor="middle">' . sE($p['label']) . '</text>';
    }
    $lineB = ''; $lineM = '';
    foreach ($trend as $i => $p) {
        $lineB .= ($i ? ' L' : 'M') . $x($i) . ' ' . $y($p['block']);
        $lineM .= ($i ? ' L' : 'M') . $x($i) . ' ' . $y($p['pass']);
    }
    $areaB = $lineB . ' L' . $x($n - 1) . ' ' . ($H - $pb) . ' L' . $pl . ' ' . ($H - $pb) . ' Z';
    $lastB = $trend[$n - 1]['block'];
    return '<svg viewBox="0 0 ' . $W . ' ' . $H . '" preserveAspectRatio="none" class="chart" role="img" aria-label="攻击流量趋势">'
        . '<defs>'
        . '<linearGradient id="gArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#22d3ee" stop-opacity=".42"/><stop offset="100%" stop-color="#22d3ee" stop-opacity="0"/></linearGradient>'
        . '<linearGradient id="gLine" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#3b82f6"/><stop offset="100%" stop-color="#22d3ee"/></linearGradient>'
        . '<filter id="glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
        . '</defs>'
        . $g
        . '<path d="' . $areaB . '" fill="url(#gArea)"/>'
        . '<path class="draw" d="' . $lineB . '" fill="none" stroke="url(#gLine)" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round" filter="url(#glow)"/>'
        . '<path class="draw" d="' . $lineM . '" fill="none" stroke="#fbbf24" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round" stroke-dasharray="5 4"/>'
        . '<circle cx="' . $x($n - 1) . '" cy="' . $y($lastB) . '" r="4" fill="#22d3ee" filter="url(#glow)"/>'
        . '<circle class="ripple" cx="' . $x($n - 1) . '" cy="' . $y($lastB) . '" r="4" fill="none" stroke="#22d3ee" stroke-width="1.5"/>'
        . '</svg>';
}

function sDonut(array $decisions, int $total): string {
    if ($total <= 0) { return '<div class="empty">暂无决策数据</div>'; }
    $r = 68; $c = 2 * M_PI * $r; $off = 0; $segs = '';
    foreach ($decisions as $d) {
        if ($d['value'] <= 0) { continue; }
        $len = $c * $d['value'] / $total;
        $segs .= '<circle cx="100" cy="100" r="' . $r . '" fill="none" stroke="' . $d['color'] . '" stroke-width="17"'
               . ' stroke-dasharray="' . $len . ' ' . ($c - $len) . '" stroke-dashoffset="' . (-$off) . '"'
               . ' transform="rotate(-90 100 100)" stroke-linecap="butt" class="donut-seg"/>';
        $off += $len;
    }
    return '<svg viewBox="0 0 200 200" class="donut" role="img" aria-label="决策分布">'
        . '<circle cx="100" cy="100" r="' . $r . '" fill="none" stroke="rgba(120,170,220,.09)" stroke-width="17"/>'
        . $segs
        . '<text x="100" y="96" text-anchor="middle" fill="#e8f2ff" font-size="30" font-weight="600">' . sNum($total) . '</text>'
        . '<text x="100" y="118" text-anchor="middle" fill="#7c93b4" font-size="11" letter-spacing="2">审计事件</text>'
        . '</svg>';
}

function sBars(array $items, string $unit = '次'): string {
    if (!$items) { return '<div class="empty">暂无数据</div>'; }
    $max = max(array_column($items, 'value'));
    if ($max <= 0) { $max = 1; }
    $out = '<div class="bars">';
    foreach ($items as $i => $it) {
        $pct = round(100 * $it['value'] / $max, 1);
        $color = $it['color'] ?? '#22d3ee';
        $out .= '<div class="bar-row" style="--d:' . ($i * 60) . 'ms">'
              . '<div class="bar-top"><span class="bar-name" title="'
              . (!empty($it['raw']) ? sE($it['raw']) : sE($it['name'])) . '">' . sE($it['name'])
              . '</span><span class="bar-val">' . sNum($it['value']) . '<em>' . $unit . '</em></span></div>'
              . '<div class="bar-track"><div class="bar-fill" style="width:' . $pct . '%;background:linear-gradient(90deg,' . $color . '33,' . $color . ');box-shadow:0 0 14px ' . $color . '55"></div></div>'
              . '</div>';
    }
    return $out . '</div>';
}

function sHistogram(array $bins): string {
    if (!$bins) { return '<div class="empty">暂无数据</div>'; }
    $max = max(array_column($bins, 'value'));
    if ($max <= 0) { $max = 1; }
    $colors = ['#34d399', '#22d3ee', '#3b82f6', '#a78bfa', '#fb7185'];
    $out = '<div class="hist">';
    foreach ($bins as $i => $b) {
        $h = max(4, round(100 * $b['value'] / $max));
        $out .= '<div class="hist-col"><div class="hist-val">' . sNum($b['value']) . '</div>'
              . '<div class="hist-bar" style="height:' . $h . '%;background:linear-gradient(180deg,' . $colors[$i % 5] . ',' . $colors[$i % 5] . '22);--d:' . ($i * 70) . 'ms"></div>'
              . '<div class="hist-label">' . sE($b['name']) . '</div></div>';
    }
    return $out . '</div>';
}

function sRecent(array $rows): string {
    if (!$rows) { return '<div class="empty">暂无审计事件</div>'; }
    $out = '<div class="feed">';
    foreach ($rows as $i => $r) {
        $a = $r['action'];
        $cls = ($a === 'block' || $a === 'challenge') ? 'b' : (($a === 'monitor') ? 'm' : 'p');
        $lbl = ($a === 'block' || $a === 'challenge') ? '拦截' : (($a === 'monitor') ? '观察' : '放行');
        $out .= '<div class="feed-row" style="--d:' . ($i * 45) . 'ms">'
              . '<span class="feed-time">' . sE($r['time']) . '</span>'
              . '<span class="feed-ip">' . sE($r['ip']) . '</span>'
              . '<span class="feed-uri" title="' . sE($r['uri']) . '">' . sE($r['uri'] === '' ? '—' : $r['uri']) . '</span>'
              . '<span class="feed-score">' . (int)$r['score'] . '</span>'
              . '<span class="feed-reason">' . sE($r['reason'] === '' ? '—' : $r['reason']) . '</span>'
              . '<span class="feed-tag ' . $cls . '">' . $lbl . '</span>'
              . '</div>';
    }
    return $out . '</div>';
}

$full = ($fmt !== 'fragment');
?>
<?php if ($full): ?>
<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YSL语枢-盾甲WAF · 实时威胁态势大屏</title>
<style>
:root{
  --bg:#050a16;--panel:rgba(11,22,44,.74);--line:rgba(96,160,220,.15);
  --cyan:#22d3ee;--blue:#3b82f6;--violet:#a78bfa;--amber:#fbbf24;--red:#fb7185;--green:#34d399;
  --txt:#e8f2ff;--dim:#8199bb;--faint:#5f779b;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--txt);
  font:14px/1.5 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
body{background:
  radial-gradient(1100px 620px at 12% -8%,rgba(34,211,238,.13),transparent 62%),
  radial-gradient(900px 560px at 92% 108%,rgba(167,139,250,.13),transparent 62%),
  radial-gradient(700px 420px at 55% 40%,rgba(59,130,246,.055),transparent 70%),
  #050a16;
  padding:0 0 18px;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(rgba(110,170,230,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(110,170,230,.045) 1px,transparent 1px);
  background-size:44px 44px;mask-image:radial-gradient(ellipse at 50% 30%,#000 25%,transparent 88%)}
body::after{content:"";position:fixed;left:0;right:0;top:0;height:2px;z-index:9;pointer-events:none;
  background:linear-gradient(90deg,transparent,#22d3ee,#3b82f6,#a78bfa,transparent);opacity:.75;
  box-shadow:0 0 18px rgba(34,211,238,.55)}
.scan{position:fixed;left:0;right:0;height:120px;z-index:1;pointer-events:none;
  background:linear-gradient(180deg,transparent,rgba(34,211,238,.035),transparent);animation:scan 12s linear infinite}
@keyframes scan{0%{top:-140px}100%{top:100%}}
.wrap{position:relative;z-index:2;max-width:1920px;margin:0 auto;padding:0 22px}
/* ---------- header ---------- */
.hd{display:flex;align-items:center;gap:18px;padding:18px 4px 16px;border-bottom:1px solid var(--line);margin-bottom:16px}
.logo{width:46px;height:46px;flex:0 0 46px;filter:drop-shadow(0 0 12px rgba(34,211,238,.65));animation:bob 5s ease-in-out infinite}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}
.hd-txt{min-width:0}
.hd h1{margin:0;font-size:23px;font-weight:650;letter-spacing:2.5px;
  background:linear-gradient(90deg,#fff,#9fdcff 55%,#a78bfa);-webkit-background-clip:text;background-clip:text;color:transparent}
.hd .sub{margin-top:3px;font-size:10px;letter-spacing:3.4px;color:var(--faint);text-transform:uppercase}
.hd-right{margin-left:auto;display:flex;align-items:center;gap:18px;white-space:nowrap}
.live{display:flex;align-items:center;gap:8px;font-size:12px;letter-spacing:1.5px;color:var(--cyan)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px var(--cyan);animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.72)}}
.clock{font-size:22px;font-weight:600;letter-spacing:1.5px;color:#dff1ff;text-shadow:0 0 16px rgba(34,211,238,.35)}
.clock small{display:block;font-size:10px;font-weight:400;letter-spacing:1px;color:var(--faint);text-align:right;text-shadow:none}
.pill{padding:5px 12px;border:1px solid rgba(34,211,238,.35);border-radius:20px;font-size:11px;letter-spacing:1px;color:#a5e9ff;background:rgba(34,211,238,.07)}
.tick{font-size:11px;color:var(--faint);min-width:52px;text-align:right}
/* ---------- kpi ---------- */
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:14px}
.kpi{position:relative;overflow:hidden;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 16px 13px;
  animation:fadeUp .6s;transition:transform .25s,border-color .25s,box-shadow .25s}
.kpi:hover{transform:translateY(-3px);border-color:rgba(34,211,238,.45);box-shadow:0 10px 34px rgba(34,211,238,.10)}
.kpi::before{content:"";position:absolute;left:0;top:0;width:100%;height:2px;background:linear-gradient(90deg,var(--kc,#22d3ee),transparent);opacity:.8}
.kpi::after{content:"";position:absolute;right:-30px;top:-30px;width:90px;height:90px;border-radius:50%;
  background:radial-gradient(circle,var(--kc,#22d3ee),transparent 70%);opacity:.10}
.kpi .lab{font-size:11px;letter-spacing:1.2px;color:var(--dim);display:flex;align-items:center;gap:7px}
.kpi .lab i{width:6px;height:6px;border-radius:50%;background:var(--kc,#22d3ee);box-shadow:0 0 8px var(--kc,#22d3ee)}
.kpi .v{font-size:33px;font-weight:650;line-height:1.15;margin:7px 0 2px;color:#fff;text-shadow:0 0 20px var(--kg,rgba(34,211,238,.35))}
.kpi .v small{font-size:13px;font-weight:400;color:var(--dim);margin-left:4px;text-shadow:none}
.kpi .foot{font-size:11px;color:var(--faint);display:flex;justify-content:space-between;align-items:flex-end;gap:6px}
.spark{width:78px;height:22px;opacity:.85;flex:0 0 78px}
/* ---------- panels ---------- */
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.panel{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 17px 16px;
  animation:fadeUp .7s;overflow:hidden}
.panel::before{content:"";position:absolute;top:0;left:18px;right:18px;height:1px;
  background:linear-gradient(90deg,transparent,rgba(34,211,238,.5),transparent)}
.panel h2{margin:0 0 3px;font-size:13px;font-weight:600;letter-spacing:1.4px;color:#dcecff;display:flex;align-items:center;gap:9px}
.panel h2::before{content:"";width:3px;height:13px;border-radius:2px;background:linear-gradient(180deg,var(--cyan),var(--blue));box-shadow:0 0 9px var(--cyan)}
.panel h2 span{margin-left:auto;font-size:10px;font-weight:400;letter-spacing:.5px;color:var(--faint)}
.span8{grid-column:span 8}.span4{grid-column:span 4}.span6{grid-column:span 6}.span5{grid-column:span 5}.span7{grid-column:span 7}.span12{grid-column:span 12}
.chart{width:100%;height:220px;display:block;margin-top:8px}
/* 折线常显：不用 dash 初始隐藏，避免静态打开 / 截图时图表空白 */
.draw{stroke-linecap:round}
.ripple{transform-origin:center;animation:ripple 2s ease-out infinite}
@keyframes ripple{0%{r:4;opacity:.8}100%{r:18;opacity:0}}
.legend{display:flex;gap:20px;justify-content:center;margin-top:2px;font-size:11px;color:var(--dim)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.donut-wrap{display:flex;flex-direction:column;align-items:center;gap:6px;margin-top:4px}
.donut{width:186px;height:186px;display:block;filter:drop-shadow(0 0 14px rgba(34,211,238,.18))}
.donut-seg{animation:donutIn 1.2s ease-out}
@keyframes donutIn{from{opacity:.7}to{opacity:1}}
.dl{display:flex;flex-wrap:wrap;gap:8px 16px;justify-content:center;font-size:11px;color:var(--dim)}
.dl b{color:#e8f2ff;font-weight:600;margin-left:5px}
/* bars */
.bars{margin-top:12px;display:flex;flex-direction:column;gap:11px}
.bar-row{animation:fadeUp .5s;animation-delay:var(--d)}
.bar-top{display:flex;justify-content:space-between;align-items:baseline;gap:8px;margin-bottom:5px}
.bar-name{font-size:12px;color:#cfe2fb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-name i{font-style:normal;font-size:10px;color:var(--faint);margin-left:7px}
.bar-val{font-size:13px;font-weight:600;color:#fff;white-space:nowrap}
.bar-val em{font-style:normal;font-size:10px;color:var(--faint);font-weight:400;margin-left:3px}
.bar-track{height:7px;border-radius:6px;background:rgba(120,170,220,.08);overflow:hidden}
.bar-fill{height:100%;border-radius:6px;transform-origin:left center;animation:grow 1.1s cubic-bezier(.2,.8,.2,1);animation-delay:var(--d)}
@keyframes grow{from{transform:scaleX(.35);opacity:.65}to{transform:none;opacity:1}}
/* histogram */
.hist{display:flex;align-items:flex-end;gap:10px;height:168px;margin-top:12px;padding:0 4px}
.hist-col{flex:1;display:flex;flex-direction:column;align-items:center;height:100%;justify-content:flex-end}
.hist-val{font-size:11px;color:#cfe2fb;margin-bottom:5px}
.hist-bar{width:100%;max-width:52px;border-radius:5px 5px 0 0;transform-origin:bottom center;animation:growH 1s cubic-bezier(.2,.8,.2,1);animation-delay:var(--d);
  box-shadow:inset 0 0 18px rgba(255,255,255,.07)}
@keyframes growH{from{transform:scaleY(.35);opacity:.65}to{transform:none;opacity:1}}
.hist-label{font-size:10px;color:var(--faint);margin-top:7px;white-space:nowrap}
/* feed */
.feed{margin-top:10px;max-height:262px;overflow:hidden}
.feed-row{display:grid;grid-template-columns:74px 116px minmax(120px,1fr) 44px 118px 50px;gap:9px;align-items:center;
  padding:6px 8px;border-bottom:1px solid rgba(120,170,220,.07);font-size:11px;animation:fadeUp .45s;animation-delay:var(--d)}
.feed-row:hover{background:rgba(34,211,238,.05)}
.feed-time{color:var(--cyan);letter-spacing:.4px}
.feed-ip{color:#b9d3f2}
.feed-uri{color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.feed-score{color:#fff;font-weight:600;text-align:right}
.feed-reason{color:#a9c6e8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.feed-tag{text-align:center;padding:2px 0;border-radius:5px;font-size:10px;letter-spacing:.5px}
.feed-tag.b{background:rgba(34,211,238,.14);color:#7ce8ff;border:1px solid rgba(34,211,238,.28)}
.feed-tag.m{background:rgba(251,191,36,.13);color:#fcd34d;border:1px solid rgba(251,191,36,.26)}
.feed-tag.p{background:rgba(167,139,250,.13);color:#c4b5fd;border:1px solid rgba(167,139,250,.26)}
.head-row{display:grid;grid-template-columns:74px 116px minmax(120px,1fr) 44px 118px 50px;gap:9px;padding:2px 8px 7px;
  font-size:10px;letter-spacing:1px;color:var(--faint);border-bottom:1px solid var(--line)}
.mini-list{margin-top:10px;display:flex;flex-direction:column;gap:8px}
.mini-row{display:flex;align-items:center;gap:9px;font-size:11px;animation:fadeUp .5s}
.mini-row .n{width:112px;color:#cfe2fb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mini-row .t{flex:1;height:6px;border-radius:5px;background:rgba(120,170,220,.08);overflow:hidden}
.mini-row .t i{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,#3b82f6,#22d3ee);animation:grow 1s both}
.mini-row .v{width:52px;text-align:right;color:#fff;font-weight:600}
.latency{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:12px}
.lat{background:rgba(120,170,220,.06);border:1px solid var(--line);border-radius:9px;padding:9px 10px;text-align:center}
.lat b{display:block;font-size:19px;color:#dff1ff;font-weight:600}
.lat span{font-size:10px;color:var(--faint);letter-spacing:.6px}
/* footer */
.foot-bar{margin-top:14px;display:flex;flex-wrap:wrap;align-items:center;gap:8px 9px;padding:11px 16px;
  background:var(--panel);border:1px solid var(--line);border-radius:12px;font-size:11px;color:var(--dim);animation:fadeUp .8s}
.foot-label{font-size:11px;color:#93b6dc;letter-spacing:1.2px;white-space:nowrap;padding-right:5px;font-weight:600}
.foot-label em{font-style:normal;color:#547097;font-size:9.5px;letter-spacing:.5px;margin-left:5px;font-weight:400}
.sw{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:16px;font-size:11px;
  border:1px solid rgba(120,170,220,.18);background:rgba(120,170,220,.05);cursor:default;white-space:nowrap}
.sw i{width:6px;height:6px;border-radius:50%;background:#5c708c;flex:none;animation:lampBreath 2.8s ease-in-out infinite}
.sw b{font-weight:500;opacity:.74;font-size:10px;margin-left:2px}
.sw.on{color:#9fe8c8;border-color:rgba(52,211,153,.3);background:rgba(52,211,153,.07)}
.sw.on i{background:var(--green);box-shadow:0 0 8px var(--green)}
.sw.warn{color:#fcd34d;border-color:rgba(251,191,36,.32);background:rgba(251,191,36,.08)}
.sw.warn i{background:#fbbf24;box-shadow:0 0 8px rgba(251,191,36,.75)}
.sw.info{color:#8fd3e8;border-color:rgba(34,211,238,.26);background:rgba(34,211,238,.06)}
.sw.info i{background:#22d3ee;box-shadow:0 0 8px rgba(34,211,238,.6)}
.sw.danger{color:#fca5a5;border-color:rgba(244,63,94,.34);background:rgba(244,63,94,.09)}
.sw.danger i{background:#fb7185;box-shadow:0 0 9px rgba(244,63,94,.85);animation-duration:1.05s}
.sw.warn i{animation-duration:1.9s}
.sw.off{color:#94a3b8;border-color:rgba(100,116,139,.32);background:rgba(100,116,139,.07)}
.sw.off i{background:#64748b;animation:none;box-shadow:none}
@keyframes lampBreath{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.72)}}
.meta{flex-basis:100%;margin-left:auto;color:var(--faint);font-size:10.5px;text-align:right;line-height:1.7}
.meta code{color:#a5c8ea;background:rgba(120,170,220,.08);padding:1px 6px;border-radius:4px}
.circuit{color:#8fb6dc}
.circuit.alert{color:#fcd34d}
.empty{color:var(--faint);text-align:center;padding:34px 10px;font-size:12px}
/* 文件 DNA 完整性（主机层） */
.dna-grid{display:grid;grid-template-columns:210px 1fr 340px;gap:12px;margin-top:12px}
.dna-state{background:rgba(120,170,220,.045);border:1px solid var(--line);border-radius:10px;padding:14px 12px;text-align:center}
.dna-orb{position:relative;width:78px;height:78px;margin:2px auto 11px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:19px;font-weight:600;letter-spacing:2px;border:2px solid}
.dna-orb::after{content:"";position:absolute;inset:-10px;border-radius:50%;border:1px solid currentColor;
  opacity:.4;pointer-events:none;animation:orbRipple 3s ease-out infinite}
.dna-orb.ok{background:radial-gradient(circle,rgba(52,211,153,.2),transparent 70%);border-color:rgba(52,211,153,.6);color:#9fe8c8;box-shadow:0 0 24px rgba(52,211,153,.22)}
.dna-orb.bad{background:radial-gradient(circle,rgba(251,191,36,.2),transparent 70%);border-color:rgba(251,191,36,.65);color:#fcd34d;box-shadow:0 0 24px rgba(251,191,36,.22)}
.dna-orb.danger{background:radial-gradient(circle,rgba(244,63,94,.22),transparent 70%);border-color:rgba(244,63,94,.7);color:#fda4af;
  box-shadow:0 0 28px rgba(244,63,94,.3);animation:orbAlert 1.4s ease-in-out infinite}
.dna-orb.danger::after{animation-duration:1.2s;opacity:.65}
.dna-orb.off{background:rgba(120,170,220,.05);border-color:rgba(120,170,220,.3);color:#8fa6c4}
.dna-orb.off::after{animation:none;opacity:.12}
@keyframes orbRipple{0%{transform:scale(.84);opacity:.55}75%{transform:scale(1.2);opacity:0}100%{opacity:0}}
@keyframes orbAlert{0%,100%{box-shadow:0 0 18px rgba(244,63,94,.22)}50%{box-shadow:0 0 34px rgba(244,63,94,.55)}}
.dna-state .lb{font-size:12px;color:#dff1ff;font-weight:600;letter-spacing:.5px}
.dna-state .sub{font-size:10px;color:var(--faint);line-height:1.85;margin-top:8px}
.dna-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;align-content:start}
.dna-m{background:rgba(120,170,220,.05);border:1px solid var(--line);border-radius:9px;padding:10px 12px}
.dna-m b{display:block;font-size:22px;color:#dff1ff;font-weight:600;line-height:1.3}
.dna-m span{font-size:10px;color:var(--faint);letter-spacing:.6px}
.dna-m.hot b{color:#fcd34d}
.dna-m.cool b{color:#7ce8ff}
.dna-feed{background:rgba(120,170,220,.035);border:1px solid var(--line);border-radius:9px;padding:7px 10px}
.dna-row{display:flex;gap:8px;align-items:center;padding:5px 2px;border-bottom:1px solid rgba(120,170,220,.07);font-size:10.5px}
.dna-row:last-child{border-bottom:0}
.dna-row .t{color:#5f779b;width:54px;flex:none}
.dna-row .k{padding:2px 7px;border-radius:5px;font-size:9.5px;flex:none;white-space:nowrap}
.dna-row .p{color:#a5c8ea;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.k.danger{background:rgba(244,63,94,.14);color:#fda4af;border:1px solid rgba(244,63,94,.26)}
.k.warn{background:rgba(251,191,36,.13);color:#fcd34d;border:1px solid rgba(251,191,36,.26)}
.k.act{background:rgba(34,211,238,.13);color:#7ce8ff;border:1px solid rgba(34,211,238,.26)}
.k.info{background:rgba(120,170,220,.1);color:#9fb8d6;border:1px solid rgba(120,170,220,.2)}
/* DNA 指示灯：标题总灯 + 面板分项灯，与底部状态栏同一套语义色 */
.h2-lamp{display:inline-flex;align-items:center;gap:7px;padding:3px 11px;border-radius:14px;font-style:normal;
  font-size:10.5px;font-weight:500;letter-spacing:.5px;border:1px solid;white-space:nowrap}
.h2-lamp i{width:7px;height:7px;border-radius:50%;flex:none;animation:lampBreath 2.8s ease-in-out infinite}
.h2-lamp.on{color:#9fe8c8;border-color:rgba(52,211,153,.36);background:rgba(52,211,153,.08)}
.h2-lamp.on i{background:#34d399;box-shadow:0 0 10px #34d399,0 0 20px rgba(52,211,153,.45)}
.h2-lamp.warn{color:#fcd34d;border-color:rgba(251,191,36,.36);background:rgba(251,191,36,.08)}
.h2-lamp.warn i{background:#fbbf24;box-shadow:0 0 10px rgba(251,191,36,.8);animation-duration:1.9s}
.h2-lamp.danger{color:#fca5a5;border-color:rgba(244,63,94,.42);background:rgba(244,63,94,.1)}
.h2-lamp.danger i{background:#fb7185;box-shadow:0 0 11px rgba(244,63,94,.9);animation-duration:1.05s}
.h2-lamp.info{color:#8fd3e8;border-color:rgba(34,211,238,.3);background:rgba(34,211,238,.06)}
.h2-lamp.info i{background:#22d3ee;box-shadow:0 0 9px rgba(34,211,238,.6)}
.dna-lamps{display:flex;flex-wrap:wrap;align-items:center;gap:7px;margin:2px 0 12px}
.dna-lamps .cap{font-size:10px;color:#7f9dc2;letter-spacing:1px;margin-right:3px;white-space:nowrap}
.dna-lamps .sw{font-size:10.5px;padding:3px 9px}
.dna-lamps .sw b{font-size:9.5px}
/* v6.4.0 QPS 限流 / 熔断面板 */
.qps-wrap{display:grid;grid-template-columns:230px 1fr;gap:18px;align-items:center}
.qps-gauge{position:relative;text-align:center;padding:6px 0}
.qps-gauge .big{font-size:52px;font-weight:680;line-height:1;color:#fff;text-shadow:0 0 26px rgba(34,211,238,.42)}
.qps-gauge .unit{font-size:11px;letter-spacing:2px;color:#7f9dc2;margin-top:5px}
.qps-gauge .bar{height:7px;border-radius:6px;background:rgba(148,163,184,.14);margin:14px 8px 7px;overflow:hidden;position:relative}
.qps-gauge .bar i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,#34d399,#fbbf24 62%,#fb7185);
  box-shadow:0 0 12px rgba(251,191,36,.4);transition:width .6s ease}
.qps-gauge .bar::after{content:"";position:absolute;top:-2px;bottom:-2px;width:1px;background:rgba(248,113,113,.85);left:100%}
.qps-gauge .bar-lb{display:flex;justify-content:space-between;font-size:9.5px;color:#6b87a9;margin:0 8px}
.qps-cells{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.qps-cell{background:rgba(12,22,40,.85);border:1px solid rgba(148,163,184,.13);border-radius:10px;padding:9px 11px}
.qps-cell .l{font-size:9.5px;letter-spacing:.8px;color:#7f9dc2;white-space:nowrap}
.qps-cell .v{font-size:17px;font-weight:600;color:#dcecff;margin-top:3px;white-space:nowrap}
.qps-cell .v small{font-size:10px;color:#7f9dc2;font-weight:400;margin-left:3px}
.qps-lamps{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px;align-items:center}
.qps-lamps .cap{font-size:10px;color:#7f9dc2;letter-spacing:1px;margin-right:3px}
@media(max-width:1100px){.qps-wrap{grid-template-columns:1fr}.qps-cells{grid-template-columns:repeat(2,1fr)}}
.ctl-mini{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin:2px 0 9px}
.ctl-mini label{font-size:10px;color:#7f9dc2;display:block;margin-bottom:3px}
.ctl-mini input{width:100%}
/* 控制台抽屉：所有 WAF 功能的操作入口，真实调用 /waf-control */
.ctl-open{padding:5px 13px;border:1px solid rgba(34,211,238,.45);border-radius:18px;font-size:11px;letter-spacing:1px;
  color:#a5e9ff;background:rgba(34,211,238,.1);cursor:pointer;font-family:inherit;white-space:nowrap}
.ctl-open:hover{background:rgba(34,211,238,.2);box-shadow:0 0 18px rgba(34,211,238,.35)}
.ctl-drawer{position:fixed;top:0;right:0;width:min(440px,94vw);height:100vh;z-index:60;display:flex;flex-direction:column;
  background:linear-gradient(180deg,rgba(9,17,34,.985),rgba(5,10,22,.99));
  border-left:1px solid rgba(34,211,238,.35);box-shadow:-24px 0 70px rgba(0,0,0,.65),inset 1px 0 0 rgba(34,211,238,.08);
  transform:translateX(105%);transition:transform .35s cubic-bezier(.22,1,.36,1)}
.ctl-drawer.open{transform:none}
.ctl-head{display:flex;align-items:center;gap:10px;padding:16px 18px 13px;border-bottom:1px solid var(--line)}
.ctl-head .ic{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;font-size:14px;color:#7ce8ff;
  background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.3)}
.ctl-head h3{margin:0;font-size:14px;letter-spacing:1.2px;color:#dff1ff;font-weight:600}
.ctl-head p{margin:2px 0 0;font-size:10px;color:var(--faint);letter-spacing:.4px}
.ctl-head .x{margin-left:auto;width:26px;height:26px;border-radius:8px;border:1px solid var(--line);background:rgba(120,170,220,.06);
  color:#a5c8ea;cursor:pointer;font-size:15px;line-height:1}
.ctl-head .x:hover{color:#fff;border-color:rgba(34,211,238,.5)}
.ctl-body{flex:1;overflow-y:auto;padding:14px 16px 24px;scrollbar-width:thin;scrollbar-color:rgba(34,211,238,.35) transparent}
.ctl-state{background:rgba(34,211,238,.055);border:1px solid rgba(34,211,238,.2);border-radius:10px;
  padding:10px 12px;font-size:10.5px;line-height:1.9;color:#a5c8ea;margin-bottom:10px}
.ctl-state b{color:#dff1ff;font-weight:600}
.ctl-result{display:none;border-radius:9px;padding:9px 11px;font-size:11px;line-height:1.7;margin-bottom:10px;white-space:pre-wrap;
  word-break:break-word;max-height:150px;overflow:auto}
.ctl-result.show{display:block}
.ctl-result.ok{background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.35);color:#9fe8c8}
.ctl-result.bad{background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.35);color:#fca5a5}
.ctl-sec{margin-top:14px;border:1px solid var(--line);border-radius:11px;background:rgba(120,170,220,.035);padding:11px 12px 12px}
.ctl-sec h4{margin:0 0 3px;font-size:11.5px;letter-spacing:1px;color:#cfe6ff;font-weight:600;display:flex;align-items:center;gap:7px}
.ctl-sec h4::before{content:"";width:3px;height:11px;border-radius:2px;background:linear-gradient(180deg,#22d3ee,#a78bfa)}
.ctl-sec .hint{font-size:10px;color:var(--faint);line-height:1.7;margin:0 0 9px}
.ctl-btns{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
.ctl-btns.one{grid-template-columns:1fr}
.cb{padding:8px 9px;border-radius:8px;border:1px solid rgba(120,170,220,.24);background:rgba(120,170,220,.06);
  color:#cfe2fb;font-size:10.5px;line-height:1.35;text-align:left;cursor:pointer;font-family:inherit;
  transition:background .18s,border-color .18s,box-shadow .18s;min-height:34px}
.cb:hover{background:rgba(34,211,238,.12);border-color:rgba(34,211,238,.45);box-shadow:0 0 14px rgba(34,211,238,.18)}
.cb.is-on{color:#9fe8c8;border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.09)}
.cb.is-off{color:#fcd34d;border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.08)}
.cb.cb-danger{color:#fca5a5;border-color:rgba(244,63,94,.35);background:rgba(244,63,94,.07)}
.cb.cb-danger:hover{background:rgba(244,63,94,.16)}
.cb.armed{color:#fff;border-color:#fb7185;background:rgba(244,63,94,.32);box-shadow:0 0 20px rgba(244,63,94,.55);
  animation:ctlArm .8s ease-in-out infinite}
.cb:disabled{opacity:.42;cursor:not-allowed;filter:grayscale(.6)}
@keyframes ctlArm{0%,100%{opacity:1}50%{opacity:.62}}
.ctl-row{display:flex;gap:7px;margin-top:8px;align-items:center}
.ctl-row input{flex:1;min-width:0;background:rgba(5,10,22,.7);border:1px solid var(--line);border-radius:7px;
  color:#dff1ff;font-size:10.5px;padding:7px 9px;font-family:inherit;outline:none}
.ctl-row input:focus{border-color:rgba(34,211,238,.55)}
.ctl-row .cb{flex:none;white-space:nowrap}
.ctl-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 6px 3px 9px;border-radius:14px;font-size:10px;
  color:#a5e9ff;background:rgba(34,211,238,.09);border:1px solid rgba(34,211,238,.28)}
.chip button{border:0;background:transparent;color:#7ce8ff;cursor:pointer;font-size:12px;line-height:1;padding:0 2px}
.ctl-audit{margin-top:8px;font-size:10px;color:var(--faint);line-height:1.85;max-height:110px;overflow:auto}
.ctl-audit .ok{color:#9fe8c8}.ctl-audit .no{color:#fca5a5}
.ctl-foot{padding:10px 16px;border-top:1px solid var(--line);font-size:10px;color:var(--faint);line-height:1.7;
  background:rgba(5,10,22,.7)}
.ctl-foot b{color:#7ce8ff;font-weight:500}
/* v6.5.0 全功能控制矩阵：每项都有状态灯 + 真实操作按钮，不再是只读灰灯 */
.feat-sum{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:2px 0 11px;font-size:10px;color:var(--faint)}
.feat-sum .num{font-size:17px;font-weight:600;color:#7ce8ff;letter-spacing:1px}
.feat-sum .ok{color:#9fe8c8}
.feat-sum .legend{display:flex;gap:9px;margin-left:auto;flex-wrap:wrap}
.feat-sum .legend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:3px;vertical-align:1px}
.feat-groups{display:grid;gap:12px;margin-top:10px}
.feat-group{border:1px solid var(--line);border-radius:11px;background:rgba(120,170,220,.03);padding:10px 12px 12px}
.feat-gh{display:flex;align-items:center;gap:8px;font-size:11px;color:#cfe6ff;letter-spacing:1px;margin-bottom:9px}
.feat-gh::before{content:"";width:3px;height:11px;border-radius:2px;background:linear-gradient(180deg,#22d3ee,#a78bfa)}
.feat-gh b{font-weight:600}.feat-gh span{font-size:10px;color:var(--faint);letter-spacing:0}
.feat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(196px,1fr));gap:8px}
.feat{border:1px solid var(--line);border-radius:9px;padding:9px 10px 10px;background:rgba(5,10,22,.44);
  display:flex;flex-direction:column;gap:5px;position:relative;overflow:hidden;transition:border-color .2s,transform .2s}
.feat:hover{border-color:rgba(34,211,238,.42);transform:translateY(-2px)}
.feat.hot{border-color:rgba(251,113,133,.5);background:linear-gradient(180deg,rgba(251,113,133,.09),rgba(5,10,22,.44))}
.feat.flash{border-color:#fb7185;box-shadow:0 0 0 1px rgba(251,113,133,.55),0 0 22px rgba(251,113,133,.35)}
.feat-top{display:flex;align-items:center;gap:7px;min-width:0}
.feat-lamp{width:8px;height:8px;border-radius:50%;flex:none;background:#64748b;box-shadow:0 0 9px currentColor}
.feat-lamp.on{background:#34d399;color:#34d399}
.feat-lamp.warn{background:#fbbf24;color:#fbbf24}
.feat-lamp.off{background:#64748b;color:#64748b}
.feat-lamp.info{background:#38bdf8;color:#38bdf8}
.feat-lamp.danger{background:#fb7185;color:#fb7185;animation:ctlArm 1.1s ease-in-out infinite}
.feat-name{font-size:11.5px;color:#dff1ff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.feat-kind{margin-left:auto;flex:none;font-size:9px;color:#7f9dc2;border:1px solid var(--line);border-radius:8px;padding:1px 5px}
.feat-status{font-size:10.5px;color:#9fe8c8;line-height:1.4;min-height:15px}
.feat.warn .feat-status{color:#fcd34d}.feat.off .feat-status{color:#94a3b8}
.feat.info .feat-status{color:#a5d8ff}.feat.danger .feat-status{color:#fca5a5}
.feat-desc{font-size:9.5px;color:var(--faint);line-height:1.55;height:30px;overflow:hidden}
.feat-btns{display:flex;gap:5px;margin-top:3px}
.feat-btns .cb{flex:1;min-height:28px;padding:5px 6px;font-size:10px;text-align:center}
.feat-btns .cb.more{flex:none;width:52px;color:#7ce8ff}
/* 底栏状态灯：可点击直达对应控制分区 */
.foot-bar .sw{color:#93b6dc;cursor:pointer;font-family:inherit;transition:border-color .18s,box-shadow .18s,transform .18s}
.foot-bar .sw:hover{border-color:rgba(34,211,238,.55);box-shadow:0 0 14px rgba(34,211,238,.25);transform:translateY(-1px)}
.ctl-sec.flash{border-color:#22d3ee;box-shadow:0 0 0 1px rgba(34,211,238,.45),0 0 26px rgba(34,211,238,.22)}
.hp-alert{border:1px solid rgba(251,113,133,.45);background:rgba(251,113,133,.07);border-radius:9px;
  padding:9px 11px;font-size:10px;line-height:1.75;color:#fca5a5;margin-bottom:9px}
.hp-alert b{color:#fff}
.noscript{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:#050a16;z-index:99;color:#e8f2ff}
@keyframes fadeUp{from{opacity:.75;transform:translateY(6px)}to{opacity:1;transform:none}}
@media(max-width:1400px){.kpis{grid-template-columns:repeat(3,1fr)}.span8,.span4,.span5,.span7,.span6{grid-column:span 12}
 .dna-grid{grid-template-columns:200px 1fr}.dna-feed{grid-column:span 2}}
@media(max-width:820px){.hd{flex-wrap:wrap}.hd-right{margin-left:0;width:100%;justify-content:space-between}.kpis{grid-template-columns:repeat(2,1fr)}
 .feed-row,.head-row{grid-template-columns:64px 92px 1fr 38px 50px}.feed-reason{display:none}
 .dna-grid{grid-template-columns:1fr}.dna-feed{grid-column:span 1}.dna-metrics{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<div class="scan"></div>
<div class="wrap">
  <div class="hd">
    <svg class="logo" viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#22d3ee"/><stop offset="1" stop-color="#a78bfa"/></linearGradient></defs>
      <path d="M24 3 42 9v14c0 11-7.6 18.6-18 22C13.6 41.6 6 34 6 23V9L24 3Z" fill="url(#lg)" fill-opacity=".13" stroke="url(#lg)" stroke-width="2"/>
      <path d="M24 11 35 15v9c0 6.8-4.6 11.8-11 14-6.4-2.2-11-7.2-11-14v-9l11-4Z" fill="none" stroke="#7ce8ff" stroke-width="1.1" opacity=".55"/>
      <path d="m26.5 17-8 10h5.2l-2 6 8-10h-5.2l2-6Z" fill="#7ce8ff"/>
    </svg>
    <div class="hd-txt"><h1>YSL语枢-盾甲WAF · 实时威胁态势</h1><div class="sub">安全防护网关 / 威胁态势总览</div></div>
    <div class="hd-right">
      <div class="live"><span class="dot"></span>实时接入</div>
      <div class="clock"><span id="clk">--:--:--</span><small id="clkdate">----/--/--</small></div>
      <div class="pill" id="ctlPill">模式 <?= sE(wafCnMode((string)$data['meta']['mode'])) ?></div>
      <button type="button" class="ctl-open" id="ctlOpen" title="打开控制台：所有 WAF 功能操作">控制台</button>
      <div class="tick" id="tick">--</div>
    </div>
  </div>
  <div id="app">
<?php endif; ?>

<?php
// ---------------------------------------------------------------- app 内容（fragment 与整页共用）
$k = $data['kpi'];
$trendSpark = $data['trend'];
$sparkPts = '';
if ($trendSpark) {
    $nn = count($trendSpark); $mm = 1;
    foreach ($trendSpark as $p) { $mm = max($mm, $p['block'] + $p['pass']); }
    foreach ($trendSpark as $i => $p) {
        $xx = $nn <= 1 ? 0 : $i * 78 / ($nn - 1);
        $yy = 20 - ($p['block'] + $p['pass']) / $mm * 17;
        $sparkPts .= ($i ? ' L' : 'M') . round($xx, 1) . ' ' . round($yy, 1);
    }
}
$sparkSvg = '<svg class="spark" viewBox="0 0 78 22" preserveAspectRatio="none"><path d="' . $sparkPts . '" fill="none" stroke="#22d3ee" stroke-width="1.7" opacity=".9"/></svg>';
$cards = [
    ['审计事件', $k['total'] ?? 0, '', '#22d3ee', 'rgba(34,211,238,.35)', '真实日志条数', $sparkSvg],
    ['拦截总数', $k['blocked'] ?? 0, '', '#3b82f6', 'rgba(59,130,246,.35)', '拦截率 ' . ($k['block_rate'] ?? 0) . '%', $sparkSvg],
    ['观察 / 放行', ($k['monitored'] ?? 0) + ($k['allowed'] ?? 0), '次', '#a78bfa', 'rgba(167,139,250,.35)', '未拦截 · 照常写审计', $sparkSvg],
    ['平均处置耗时', $k['avg_ms'] ?? 0, 'ms', '#34d399', 'rgba(52,211,153,.35)', 'P95 ' . ($data['latency']['p95'] ?? 0) . ' ms', $sparkSvg, number_format((float)($k['avg_ms'] ?? 0), 1, '.', '')],
    ['峰值每分钟', $k['peak'] ?? 0, '次', '#fbbf24', 'rgba(251,191,36,.35)', '单时间桶最高', $sparkSvg],
    ['误报复核放行', $k['fp'] ?? 0, '次', '#f472b6', 'rgba(244,114,182,.35)', '自然语言降级', $sparkSvg],
];
?>
<div class="kpis">
<?php foreach ($cards as $i => $c): ?>
  <div class="kpi" style="--kc:<?= $c[3] ?>;--kg:<?= $c[4] ?>;animation-delay:<?= $i * 70 ?>ms">
    <div class="lab"><i></i><?= sE($c[0]) ?></div>
    <div class="v" data-count="<?= (float)$c[1] ?>"><?= isset($c[7]) ? sE($c[7]) : sNum($c[1]) ?><?php if ($c[2] !== ''): ?><small><?= sE($c[2]) ?></small><?php endif; ?></div>
    <div class="foot"><span><?= sE($c[5]) ?></span><?= $c[6] ?></div>
  </div>
<?php endforeach; ?>
</div>

<div class="grid">
  <section class="panel span8" style="animation-delay:120ms">
    <h2>攻击流量趋势<span><?= sE($data['meta']['first']) ?> — <?= sE($data['meta']['last']) ?> · <?= sE($data['meta']['tz']) ?></span></h2>
    <?= sAreaChart($data['trend']) ?>
    <div class="legend"><span><i style="background:#22d3ee"></i>拦截</span><span><i style="background:#fbbf24"></i>观察 / 放行</span>
      <span style="color:#5f779b">按时间桶聚合 · 取最近 <?= count($data['trend']) ?> 个桶</span></div>
  </section>

  <section class="panel span4" style="animation-delay:180ms">
    <h2>决策分布<span>全部审计事件</span></h2>
    <div class="donut-wrap">
      <?= sDonut($data['decisions'], (int)($k['total'] ?? 0)) ?>
      <div class="dl">
        <?php foreach ($data['decisions'] as $dd): ?>
          <span><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:<?= $dd['color'] ?>;margin-right:5px"></i><?= sE($dd['name']) ?><b><?= sNum($dd['value']) ?></b></span>
        <?php endforeach; ?>
      </div>
    </div>
  </section>

  <section class="panel span4" style="animation-delay:220ms">
    <h2>拦截原因 TOP<span>命中规则分布</span></h2>
    <?= sBars($data['reasons']) ?>
  </section>

  <section class="panel span4" style="animation-delay:260ms">
    <h2>攻击类型 TOP<span>内核语义识别</span></h2>
    <?= sBars($data['types']) ?>
  </section>

  <section class="panel span4" style="animation-delay:300ms">
    <h2>威胁评分分布<span>0 — 100</span></h2>
    <?= sHistogram($data['score_bins']) ?>
    <div class="latency">
      <div class="lat"><b><?= sE($data['latency']['p50'] ?? 0) ?></b><span>P50 毫秒</span></div>
      <div class="lat"><b><?= sE($data['latency']['p95'] ?? 0) ?></b><span>P95 毫秒</span></div>
      <div class="lat"><b><?= sE($data['latency']['max'] ?? 0) ?></b><span>峰值毫秒</span></div>
    </div>
  </section>

  <section class="panel span8" style="animation-delay:340ms">
    <h2>实时审计事件流<span>最新 14 条 · 倒序</span></h2>
    <div class="head-row"><span>时间</span><span>来源 IP</span><span>请求路径</span><span style="text-align:right">分数</span><span>判定原因</span><span>决策</span></div>
    <?= sRecent($data['recent']) ?>
  </section>

  <section class="panel span4" style="animation-delay:380ms">
    <h2>来源与攻击链<span>会话维度</span></h2>
    <div style="font-size:10px;color:#5f779b;letter-spacing:1px;margin-top:11px">来源 IP TOP</div>
    <div class="mini-list">
      <?php $ipmax = $data['top_ips'] ? max(array_column($data['top_ips'], 'value')) : 1; ?>
      <?php foreach ($data['top_ips'] as $i => $ip): ?>
        <div class="mini-row" style="animation-delay:<?= 400 + $i * 60 ?>ms">
          <span class="n"><?= sE($ip['name']) ?></span>
          <span class="t"><i style="width:<?= round(100 * $ip['value'] / max(1, $ipmax)) ?>%"></i></span>
          <span class="v"><?= sNum($ip['value']) ?></span>
        </div>
      <?php endforeach; ?>
      <?php if (!$data['top_ips']): ?><div class="empty">暂无数据</div><?php endif; ?>
    </div>
    <div style="font-size:10px;color:#5f779b;letter-spacing:1px;margin-top:14px">攻击链阶段</div>
    <div class="mini-list">
      <?php $phmax = $data['phases'] ? max(array_column($data['phases'], 'value')) : 1; ?>
      <?php foreach ($data['phases'] as $i => $ph): ?>
        <div class="mini-row" style="animation-delay:<?= 460 + $i * 60 ?>ms">
          <span class="n"><?= sE($ph['name']) ?></span>
          <span class="t"><i style="width:<?= round(100 * $ph['value'] / max(1, $phmax)) ?>%;background:linear-gradient(90deg,#a78bfa,#f472b6)"></i></span>
          <span class="v"><?= sNum($ph['value']) ?></span>
        </div>
      <?php endforeach; ?>
      <?php if (!$data['phases']): ?><div class="empty">暂无数据</div><?php endif; ?>
    </div>
  </section>

  <?php
    $qp      = $data['qps'] ?? [];
    $qpLamps = $data['qps_lamps'] ?? [];
    $qpHead  = $qpLamps[0] ?? ['state' => 'info', 'note' => '待初始化', 'title' => ''];
    $qpPct   = min(100, round(100 * (int)($qp['qps'] ?? 0) / max(1, (int)($qp['hard'] ?? 1))));
  ?>
  <section class="panel span12" style="animation-delay:405ms">
    <h2>QPS 限流与熔断<span>接入层跨请求滑动窗口 · 429 限流 / 502 保护性熔断 · 冷却自动恢复</span>
      <em class="h2-lamp <?= sE($qpHead['state']) ?>" title="<?= sE($qpHead['title']) ?>"><i></i><?= sE($qpHead['note']) ?></em></h2>
    <div class="qps-wrap">
      <div class="qps-gauge">
        <div class="big"><?= sNum($qp['qps'] ?? 0) ?></div>
        <div class="unit">当前全局 QPS · 1 秒窗口</div>
        <div class="bar"><i style="width:<?= (int)$qpPct ?>%"></i></div>
        <div class="bar-lb"><span>0</span><span>软 <?= sNum($qp['soft'] ?? 0) ?></span><span>硬 <?= sNum($qp['hard'] ?? 0) ?></span></div>
      </div>
      <div>
        <div class="qps-cells">
          <div class="qps-cell"><div class="l">窗口峰值</div><div class="v"><?= sNum($qp['peak'] ?? 0) ?><small>QPS</small></div></div>
          <div class="qps-cell"><div class="l">熔断状态</div><div class="v"><?= sE(wafCnState((string)($qp['state'] ?? 'closed'))) ?></div></div>
          <div class="qps-cell"><div class="l">冷却剩余</div><div class="v"><?= (int)($qp['retry_left'] ?? 0) ?><small>秒</small></div></div>
          <div class="qps-cell"><div class="l">累计请求</div><div class="v"><?= sNum($qp['total'] ?? 0) ?><small>次</small></div></div>
          <div class="qps-cell"><div class="l">单 IP 软 / 硬</div><div class="v"><?= sNum($qp['ip_soft'] ?? 0) ?><small>/ <?= sNum($qp['ip_hard'] ?? 0) ?></small></div></div>
          <div class="qps-cell"><div class="l">累计拒绝</div><div class="v"><?= sNum($qp['rejects'] ?? 0) ?><small>次</small></div></div>
          <div class="qps-cell"><div class="l">追踪来源</div><div class="v"><?= sNum($qp['ip_tracked'] ?? 0) ?><small>个</small></div></div>
          <div class="qps-cell"><div class="l">触发原因</div><div class="v" style="font-size:12px;line-height:1.9" title="<?= sE((string)($qp['reason'] ?? '')) ?>"><?= sE(wafCnReason((string)($qp['reason'] ?? ''))) ?></div></div>
        </div>
        <div class="qps-lamps">
          <span class="cap">QPS 指示灯 · 只读</span>
          <?php foreach (array_slice($qpLamps, 1) as $lp): ?>
            <span class="sw <?= sE($lp['state']) ?>" title="<?= sE($lp['title'] ?? '') ?>"><i></i><?= sE($lp['name']) ?><b><?= sE($lp['note']) ?></b></span>
          <?php endforeach; ?>
        </div>
      </div>
    </div>
  </section>

  <section class="panel span12" style="animation-delay:420ms">
    <?php $dna = $data['dna'] ?? []; ?>
    <?php $dnLamps = $data['dna_lamps'] ?? []; ?>
    <?php $dnHead = $dnLamps[0] ?? ['state' => 'info', 'note' => '未建档', 'title' => '']; ?>
    <h2>文件 DNA 完整性<span>主机层第二道防线 · 独立巡检进程 · 只读状态快照</span>
      <em class="h2-lamp <?= sE($dnHead['state']) ?>" title="<?= sE($dnHead['title']) ?>"><i></i><?= sE($dnHead['note']) ?></em></h2>
    <div class="dna-lamps">
      <span class="cap">DNA 指示灯 · 只读</span>
      <?php foreach (array_slice($dnLamps, 1) as $lp): ?>
        <span class="sw <?= sE($lp['state']) ?>" title="<?= sE($lp['title'] ?? '') ?>"><i></i><?= sE($lp['name']) ?><b><?= sE($lp['note']) ?></b></span>
      <?php endforeach; ?>
    </div>
    <?php if ($dna === []): ?>
      <div class="empty">暂无数据 · 运行 <code style="color:#a5c8ea">php dna.php baseline</code> 建立基线后开始巡检</div>
    <?php else: ?>
      <?php
        $dnAlive  = !empty($dna['_alive']);
        $dnOK     = $dnAlive && !empty($dna['baseline_ok']) && !empty($dna['healthy']);
        // 签名不可信 / 本轮高置信 / 最近错误都是红灯级，不能用历史累计 high 判断当前告警
        $dnDanger = empty($dna['baseline_ok']) || empty($dna['healthy'])
                    || (int)($dna['round_high'] ?? 0) > 0 || (string)($dna['last_error'] ?? '') !== '';
        $dnCls    = $dnDanger ? 'danger' : ($dnOK ? 'ok' : ($dnAlive ? 'bad' : 'off'));
        $dnLabel  = $dnDanger ? '告警' : ($dnOK ? '完好' : ($dnAlive ? '异常' : '未运行'));
        $dnMetrics = [
            ['高置信后门', (int)($dna['high'] ?? 0),         'hot'],
            ['内容篡改',   (int)($dna['tamper_hits'] ?? 0),  'hot'],
            ['新增文件',   (int)($dna['new_files'] ?? 0),    ''],
            ['隔离留档',   (int)($dna['quarantine'] ?? 0),   'cool'],
            ['精准手术',   (int)($dna['surgery'] ?? 0),      'cool'],
            ['整体还原',   (int)($dna['restores'] ?? 0),     'cool'],
        ];
      ?>
      <div class="dna-grid">
        <div class="dna-state">
          <div class="dna-orb <?= $dnCls ?>"><?= sE($dnLabel) ?></div>
          <div class="lb">建档 <?= sNum($dna['files'] ?? 0) ?> 个文件</div>
          <div class="sub">
            基线签名 <?= sE($dna['signature'] ?? '—') ?><br>
            最近巡检 <?= sE($dna['_age'] ?? 0) ?> 秒前<?= $dnAlive ? '' : ' · 进程未运行' ?><br>
            模式 <?= !empty($dna['read_only']) ? '只读告警' : '自动处置' ?> · 手术 <?= !empty($dna['surgery_on']) ? '开' : '关' ?>
          </div>
        </div>
        <div class="dna-metrics">
          <?php foreach ($dnMetrics as $m): ?>
            <div class="dna-m <?= $m[2] ?>"><b><?= sNum($m[1]) ?></b><span><?= sE($m[0]) ?></span></div>
          <?php endforeach; ?>
        </div>
        <div class="dna-feed">
          <?php $dnEvents = array_slice(array_reverse((array)($dna['recent'] ?? [])), 0, 7); ?>
          <?php if (!$dnEvents): ?><div class="empty" style="padding:20px">暂无事件</div><?php endif; ?>
          <?php foreach ($dnEvents as $e): ?>
            <?php [$kn, $kc] = sDnaKind((string)($e['kind'] ?? '')); $ts = strtotime((string)($e['t'] ?? '')); ?>
            <div class="dna-row">
              <span class="t"><?= $ts ? sE(date('H:i:s', $ts + 8 * 3600)) : '—' ?></span>
              <span class="k <?= $kc ?>"><?= sE($kn) ?></span>
              <span class="p" title="<?= sE($e['path'] ?? '') ?>"><?= sE($e['path'] ?? '') ?></span>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
      <?php if (!empty($dna['last_error'])): ?>
        <div class="circuit alert" style="margin-top:9px;font-size:10.5px">最近错误：<?= sE($dna['last_error']) ?></div>
      <?php endif; ?>
    <?php endif; ?>
  </section>

  <?php $ft = $data['features']; ?>
  <section class="panel span12" id="featurePanel" style="animation-delay:440ms">
    <h2>全功能控制矩阵<span>每项功能都有状态灯与真实操作入口 · 不做只读摆设</span>
      <em class="h2-lamp on" title="逐项核对：每项都绑定了 control.php 里真实存在的动作"><i></i><?= (int)$ft['controllable'] ?> / <?= (int)$ft['total'] ?> 项可控</em></h2>
    <div class="feat-sum">
      <span class="num"><?= (int)$ft['controllable'] ?>/<?= (int)$ft['total'] ?></span>
      <span class="ok">项功能已接入真实控制，点击卡片按钮立即生效并回读状态；点「详细」直达控制台对应分区</span>
      <span class="legend">
        <span><i style="background:#34d399"></i>正常</span>
        <span><i style="background:#fbbf24"></i>需留意</span>
        <span><i style="background:#64748b"></i>未运行</span>
        <span><i style="background:#38bdf8"></i>可维护</span>
        <span><i style="background:#fb7185"></i>高危</span>
      </span>
    </div>
    <div class="feat-groups">
      <?php foreach ($ft['groups'] as $fg): ?>
        <div class="feat-group">
          <div class="feat-gh"><b><?= sE($fg['name']) ?></b><span><?= count($fg['items']) ?> 项 · 逐项可控</span></div>
          <div class="feat-grid">
            <?php foreach ($fg['items'] as $fi): ?>
              <div class="feat <?= sE($fi['lamp']) ?><?= $fi['kind'] === '高危' ? ' hot' : '' ?>" id="feat-<?= sE($fi['id']) ?>">
                <div class="feat-top">
                  <i class="feat-lamp <?= sE($fi['lamp']) ?>"></i>
                  <span class="feat-name" title="<?= sE($fi['name']) ?>"><?= sE($fi['name']) ?></span>
                  <span class="feat-kind"><?= sE($fi['kind']) ?></span>
                </div>
                <div class="feat-status" id="fs-<?= sE($fi['id']) ?>"><?= sE($fi['status']) ?></div>
                <div class="feat-desc" title="<?= sE($fi['desc']) ?>"><?= sE($fi['desc']) ?></div>
                <div class="feat-btns">
                  <?= sCtlBtn($fi['label'], $fi['act'], $fi['params'], $fi['danger']) ?>
                  <?php if ($fi['focus'] !== ''): ?>
                    <button type="button" class="cb more" data-focus="<?= sE($fi['focus']) ?>" title="打开控制台并定位到该功能">详细</button>
                  <?php endif; ?>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  </section>
</div>

<div class="foot-bar">
  <div class="foot-label">运行状态<em>点击任一指示灯直达对应控制</em></div>
  <?php
    $footFocus = [
        'AI 自学习' => 'sec-guards', '语义解析层' => 'sec-state', '叙述性复核' => 'sec-guards',
        '布尔恒真加固' => 'sec-guards', '绕过结构加固' => 'sec-guards', '贝叶斯样本' => 'sec-state',
    ];
  ?>
  <?php foreach ($data['switches'] as $sw): ?>
    <button type="button" class="sw <?= sE($sw['state']) ?>" data-focus="<?= sE($footFocus[$sw['name']] ?? 'sec-guards') ?>" title="点击打开控制台并定位到「<?= sE($sw['name']) ?>」的控制分区"><i></i><?= sE($sw['name']) ?><b><?= sE($sw['note']) ?></b></button>
  <?php endforeach; ?>
  <button type="button" class="sw <?= $data['circuit_state'] === 'alert' ? 'warn' : 'on' ?>" data-focus="sec-state" title="点击打开控制台并定位到熔断控制"><i></i>熔断<b><?= sE($data['circuit_note']) ?></b></button>
  <?php $qpFoot = $data['qps_lamps'][0] ?? ['name' => 'QPS 熔断', 'state' => 'info', 'note' => '待初始化', 'title' => '']; ?>
  <button type="button" class="sw <?= sE($qpFoot['state']) ?>" data-focus="sec-qps" title="点击打开控制台并定位到 QPS 控制"><i></i><?= sE($qpFoot['name']) ?><b><?= sE($qpFoot['note']) ?></b></button>
  <?php $dnFoot = $data['dna_lamps'][0] ?? ['name' => '文件 DNA', 'state' => 'info', 'note' => '未建档', 'title' => '']; ?>
  <button type="button" class="sw <?= sE($dnFoot['state']) ?>" data-focus="sec-dna" title="点击打开控制台并定位到文件 DNA 控制"><i></i><?= sE($dnFoot['name']) ?><b><?= sE($dnFoot['note']) ?></b></button>
  <?php $hpFoot = wafCnHoneypot($data['honeypot']); ?>
  <button type="button" class="sw <?= $hpFoot['lamp'] === 'danger' ? 'warn' : 'off' ?>" data-focus="sec-honeypot" title="点击打开控制台并定位到蜜罐控制（默认停用）"><i></i>蜜罐<b><?= sE($hpFoot['label']) ?></b></button>
  <div class="meta">
    内核 v<?= sE($data['meta']['version']) ?> · PHP <?= sE($data['meta']['php']) ?> · 生成 <?= sE($data['meta']['generated']) ?>（<?= sE($data['meta']['tz']) ?>）<br>
    数据源 <code><?= sE($data['meta']['source'] === '' ? '暂无' : $data['meta']['source']) ?></code> · <?= sNum($data['meta']['lines']) ?> 条事件<?= $data['meta']['raw'] > $data['meta']['lines'] ? '（窗口取最近 ' . sNum($data['meta']['lines']) . ' 条 / 全量 ' . sNum($data['meta']['raw']) . ' 条）' : '' ?> · 全部功能见上方控制矩阵，状态灯可点击直达
    <?php if ($data['circuit'] !== ''): ?><br><span class="circuit <?= $data['circuit_state'] === 'alert' ? 'alert' : '' ?>">熔断状态：<?= sE($data['circuit']) ?></span><?php endif; ?>
  </div>
</div>

<?php if ($full): ?>
  </div><!-- /#app -->
</div><!-- /.wrap -->

<?php
$hpNow       = wafCnHoneypot($data['honeypot']);
$ctlModeTxt  = $ctlRt['mode'] === 'observe' ? '观察模式' : '强制拦截';
$ctlShort    = ['ai' => 'AI', 'fp' => '误报复核', 'tautology' => '布尔恒真', 'bypass' => '绕过结构', 'errors' => '错误输出'];
$ctlGuardSum = [];
foreach ($ctlShort as $k => $short) {
    $ctlGuardSum[] = $short . ($ctlRt['guards'][$k] ? '开' : '关');
}
$ctlLogBytes = 0;
foreach (array_unique([$yslDir . '/attack.log', $fallback . '/attack.log']) as $lf) {
    if (is_file($lf)) { $ctlLogBytes += (int)@filesize($lf); }
}
$ctlGuardNames = [
    'ai'        => 'AI 自学习',
    'fp'        => '叙述性误报复核',
    'tautology' => '布尔恒真加固',
    'bypass'    => '绕过结构加固',
    'errors'    => '错误输出（排查用）',
];
?>
<aside class="ctl-drawer" id="ctlDrawer" aria-label="YSL语枢-盾甲WAF控制台">
  <div class="ctl-head">
    <div class="ic">⌘</div>
    <div><h3>YSL语枢-盾甲WAF控制台</h3><p>所有操作即时生效 · 每步真实回读 · 全量审计</p></div>
    <button type="button" class="x" id="ctlClose" title="关闭控制台">×</button>
  </div>
  <div class="ctl-body">
    <div class="ctl-state" id="ctlStatus">
      模式 <b id="sMode"><?= sE($ctlModeTxt) ?></b> · 开关 <b id="sGuards"><?= sE(implode(' / ', $ctlGuardSum)) ?></b><br>
      熔断 <b id="sCircuit"><?= sE($data['circuit_note'] ?: '暂无记录') ?></b> · QPS <b id="sQps"><?= sE(wafCnState((string)($data['qps']['state'] ?? 'closed')) . ' · ' . ($data['qps']['qps'] ?? 0)) ?></b> · DNA 守护 <b id="sWatch"><?= $ctlWatch ? '进程 ' . (int)$ctlWatch : '未运行' ?></b> · 审计 <b id="sLog"><?= sE(number_format($ctlLogBytes / 1048576, 2)) ?> MB</b><br>
      白名单 <b id="sWl"><?= count($ctlRt['whitelist']) ?></b> 条 · body 上限 <b id="sBody"><?= sNum($ctlRt['body_max']) ?></b> 字节 · 密钥 <b><?= $static ? '—' : sE(substr($key, 0, 4)) . '…' ?></b><br>
      蜜罐 <b id="sHpTop" style="color:<?= $hpNow['lamp'] === 'danger' ? '#fca5a5' : '#9fe8c8' ?>"><?= sE($hpNow['label']) ?></b> · 有效期 <b id="sHpLeft"><?= sE($hpNow['note']) ?></b>
    </div>
    <div class="ctl-result" id="ctlResult"></div>

    <div class="ctl-sec" id="sec-mode">
      <h4>运行模式</h4>
      <p class="hint">强制拦截真的阻断请求；观察模式只记录审计日志、不拦截。切换后下一个请求立即生效。</p>
      <div class="ctl-btns one">
        <?= sCtlBtn($ctlRt['mode'] === 'enforce' ? '切换为观察模式' : '恢复强制拦截',
                    'mode.set', ['value' => $ctlRt['mode'] === 'enforce' ? 'observe' : 'enforce'], false, 'mode-btn') ?>
      </div>
    </div>

    <div class="ctl-sec" id="sec-guards">
      <h4>防护开关（5 项）</h4>
      <p class="hint">点击切换开 / 关，按钮颜色即当前真实状态；关闭后内核行为立即变化。</p>
      <div class="ctl-btns">
        <?php foreach ($ctlGuardNames as $k => $name): ?>
          <?= sCtlBtn($name . ' · ' . ($ctlRt['guards'][$k] ? '开' : '关'), 'guard.set',
                      ['name' => $k, 'on' => $ctlRt['guards'][$k] ? '0' : '1'], false,
                      'guard-btn ' . ($ctlRt['guards'][$k] ? 'is-on' : 'is-off')) ?>
        <?php endforeach; ?>
      </div>
    </div>

    <div class="ctl-sec" id="sec-request">
      <h4>请求与白名单</h4>
      <p class="hint">硬旁路白名单内的 IP / CIDR 完全跳过检测；body 上限 1 ~ 67108864 字节。</p>
      <div class="ctl-row">
        <input id="ctlBody" type="number" min="1" max="67108864" value="<?= (int)$ctlRt['body_max'] ?>" aria-label="body 上限字节">
        <button type="button" class="cb" data-act="config.body_max" data-input="ctlBody" data-pkey="value">设置上限</button>
      </div>
      <div class="ctl-row">
        <input id="ctlCidr" type="text" placeholder="IP 或 CIDR，如 10.0.0.0/8" aria-label="白名单地址">
        <button type="button" class="cb" data-act="whitelist.add" data-input="ctlCidr" data-pkey="cidr">加入</button>
        <button type="button" class="cb" data-act="whitelist.del" data-input="ctlCidr" data-pkey="cidr">移除</button>
      </div>
      <div class="ctl-chips" id="ctlWl">
        <?php if (!$ctlRt['whitelist']): ?><span class="chip" style="opacity:.55">白名单为空</span><?php endif; ?>
        <?php foreach ($ctlRt['whitelist'] as $w): ?>
          <span class="chip"><?= sE($w) ?><button type="button" title="移除" data-act="whitelist.del" data-params='{"cidr":"<?= sE($w) ?>"}'>×</button></span>
        <?php endforeach; ?>
      </div>
      <div class="ctl-btns" style="margin-top:8px">
        <?= sCtlBtn('清空白名单', 'whitelist.clear', [], true) ?>
        <?= sCtlBtn('恢复出厂配置', 'runtime.reset', [], true) ?>
      </div>
    </div>

    <?php $hpNow = wafCnHoneypot($data['honeypot']); ?>
    <div class="ctl-sec" id="sec-honeypot" style="border-color:rgba(251,113,133,.38)">
      <h4>蜜罐诱捕（高危 · 默认停用）</h4>
      <div class="hp-alert">
        <b>为什么不能随便开启：</b>触碰诱饵的请求会被延迟响应、投喂假数据，并把来源 IP 标记为「确认恶意」（仲裁加 40 分）。
        误开会拖慢正常流量、污染攻击链。因此默认停用；启用必须手动输入确认短语、填写用途、设定有效期并二次点击确认，到期自动停用。
      </div>
      <p class="hint">
        当前状态 <b id="sHp" style="color:<?= $hpNow['lamp'] === 'danger' ? '#fca5a5' : '#9fe8c8' ?>"><?= sE($hpNow['label'] . ' · ' . $hpNow['note']) ?></b>
        · 触碰 <b id="sHpHits"><?= (int)($data['honeypot']['hits'] ?? 0) ?></b> 次
        · 用途 <b id="sHpReason"><?= sE((string)($data['honeypot']['reason'] ?? '') !== '' ? $data['honeypot']['reason'] : '暂无') ?></b>
      </p>
      <div class="ctl-row">
        <input id="ctlHpPhrase" type="text" placeholder="手动输入四个字：启用蜜罐" aria-label="蜜罐启用确认短语">
      </div>
      <div class="ctl-row">
        <input id="ctlHpReason" type="text" placeholder="启用用途（留痕，如：红队演练）" aria-label="蜜罐启用用途">
        <input id="ctlHpMinutes" type="number" min="1" max="240" value="30" style="max-width:88px" aria-label="有效期分钟">
        <span style="font-size:10px;color:var(--faint);white-space:nowrap">分钟后自动停用</span>
      </div>
      <div class="ctl-btns">
        <button type="button" class="cb cb-danger" data-act="honeypot.enable" data-danger="1"
                data-phrase="ctlHpPhrase" data-multi="ctlHpMinutes:minutes,ctlHpReason:reason"
                title="高危：需输入确认短语 + 二次点击确认">启用蜜罐（高危）</button>
        <button type="button" class="cb" data-act="honeypot.disable" title="安全侧：一键立即停用，无需二次确认">立即停用</button>
        <button type="button" class="cb" data-act="honeypot.state" title="读取蜜罐真实状态">读取状态</button>
        <button type="button" class="cb" data-act="honeypot.clear" title="清理被标记的蜜罐 IP 索引">清理蜜罐索引</button>
      </div>
    </div>

    <div class="ctl-sec" id="sec-state">
      <h4>熔断与状态文件</h4>
      <p class="hint">写入后回读校验一致；清理类操作返回真实删除文件数。</p>
      <div class="ctl-btns">
        <?= sCtlBtn('熔断复位（恢复正常放行）', 'circuit.reset') ?>
        <?= sCtlBtn('熔断演练（置为熔断中）', 'circuit.open', [], true) ?>
        <?= sCtlBtn('强制关闭熔断', 'circuit.close') ?>
        <?= sCtlBtn('清理时间窗口', 'windows.clear') ?>
        <?= sCtlBtn('清理攻击链会话', 'chains.clear') ?>
        <?= sCtlBtn('清理蜜罐索引', 'honeypot.clear') ?>
        <?= sCtlBtn('清理临时锁', 'locks.clear') ?>
        <?= sCtlBtn('重置贝叶斯模型', 'ai.model.reset', [], true) ?>
        <?= sCtlBtn('清空训练/审核队列', 'ai.queues.clear') ?>
        <?= sCtlBtn('清空指纹库', 'ai.fingerprints.clear') ?>
      </div>
    </div>

    <div class="ctl-sec" id="sec-qps">
      <h4>QPS 限流与熔断（接入层）</h4>
      <p class="hint">软阈值 → 429 限流；硬阈值 → 502 保护性熔断；冷却结束自动半开试探恢复。大屏 / 控制台 / 控制端点豁免，不会把自己熔断。改完可在新窗口访问站点首页查看 502 页面。</p>
      <div class="ctl-mini">
        <div><label>全局软阈值 (QPS)</label><input id="ctlQSoft" type="number" min="1" max="1000000" value="<?= (int)($data['qps']['soft'] ?? 300) ?>"></div>
        <div><label>全局硬阈值 (QPS)</label><input id="ctlQHard" type="number" min="1" max="1000000" value="<?= (int)($data['qps']['hard'] ?? 600) ?>"></div>
        <div><label>单 IP 软阈值 (QPS)</label><input id="ctlQIpSoft" type="number" min="1" max="1000000" value="<?= (int)($data['qps']['ip_soft'] ?? 80) ?>"></div>
        <div><label>单 IP 硬阈值 (QPS)</label><input id="ctlQIpHard" type="number" min="1" max="1000000" value="<?= (int)($data['qps']['ip_hard'] ?? 160) ?>"></div>
        <div><label>熔断冷却 (秒)</label><input id="ctlQCd" type="number" min="3" max="3600" value="<?= (int)($data['qps']['cooldown'] ?? 30) ?>"></div>
      </div>
      <div class="ctl-btns">
        <button type="button" class="cb" data-act="qps.config" data-params="{}"
                data-multi="ctlQSoft:soft,ctlQHard:hard,ctlQIpSoft:ip_soft,ctlQIpHard:ip_hard,ctlQCd:cooldown">应用阈值</button>
        <?= sCtlBtn(($data['qps']['enabled'] ?? true) ? '停用保护（只计数）' : '启用保护', 'qps.config',
                    ['enabled' => ($data['qps']['enabled'] ?? true) ? '0' : '1'], false, 'qps-enable-btn') ?>
        <?= sCtlBtn('读取实时状态', 'qps.state') ?>
        <?= sCtlBtn('复位计数与状态', 'qps.reset') ?>
        <?= sCtlBtn('演练熔断 → 502', 'qps.open', [], true) ?>
        <?= sCtlBtn('强制恢复（正常放行）', 'qps.close') ?>
      </div>
    </div>

    <div class="ctl-sec" id="sec-logs">
      <h4>审计日志</h4>
      <p class="hint">归档保留原文；导出生成 jsonl 副本；清空不可恢复。</p>
      <div class="ctl-btns">
        <?= sCtlBtn('归档 attack.log', 'logs.rotate') ?>
        <?= sCtlBtn('导出 jsonl', 'logs.export') ?>
        <?= sCtlBtn('清空 attack.log', 'logs.purge', [], true) ?>
        <?= sCtlBtn('查看控制审计', 'control.audit') ?>
      </div>
    </div>

    <div class="ctl-sec" id="sec-dna">
      <h4>文件 DNA 防篡改</h4>
      <p class="hint">调用独立巡检进程（不在请求管线内）；处置篡改、建立 / 重建基线、从备份还原、停止守护均需二次确认。</p>
      <div class="ctl-btns">
        <?= sCtlBtn('试算巡检范围', 'dna.plan') ?>
        <?= sCtlBtn('只读巡检', 'dna.scan') ?>
        <?= sCtlBtn('完整性审计', 'dna.audit') ?>
        <?= sCtlBtn('查看状态', 'dna.status') ?>
        <?= sCtlBtn('能力自检', 'dna.selftest') ?>
        <?= sCtlBtn('处置高置信篡改', 'dna.apply', [], true) ?>
        <?= sCtlBtn('建立基线', 'dna.baseline', [], true) ?>
        <?= sCtlBtn('重建基线', 'dna.rebaseline', [], true) ?>
        <?= sCtlBtn('启动守护', 'dna.watch.start') ?>
        <?= sCtlBtn('停止守护', 'dna.watch.stop', [], true) ?>
      </div>
      <div class="ctl-row">
        <input id="ctlRestore" type="text" placeholder="站点根下相对路径，如 demo/x.php" aria-label="还原文件">
        <button type="button" class="cb cb-danger" data-danger="1" data-act="dna.restore" data-input="ctlRestore" data-pkey="file">从备份还原</button>
      </div>
    </div>

    <div class="ctl-sec" id="sec-access">
      <h4>访问控制与视图</h4>
      <p class="hint">轮换密钥后旧链接立即失效，新密钥只显示一次。静态快照不可执行任何操作。</p>
      <div class="ctl-btns">
        <?= sCtlBtn('轮换控制台密钥', 'key.rotate', [], true) ?>
        <?= sCtlBtn('立即刷新数据', 'state.get') ?>
        <button type="button" class="cb" data-view="pause" id="ctlPause">暂停轮询</button>
        <button type="button" class="cb" data-view="refresh">刷新一次</button>
        <button type="button" class="cb" data-view="fullscreen">全屏显示</button>
        <button type="button" class="cb" data-view="static">静态快照</button>
        <button type="button" class="cb" data-view="console">简洁控制台</button>
        <button type="button" class="cb" data-view="close">关闭面板</button>
      </div>
      <div class="ctl-row" style="margin-top:8px">
        <span style="font-size:10px;color:var(--faint);white-space:nowrap">刷新间隔</span>
        <?php foreach ([3, 5, 10, 30] as $p): ?>
          <button type="button" class="cb" data-view="period:<?= $p ?>" style="flex:1;text-align:center"><?= $p ?>s</button>
        <?php endforeach; ?>
      </div>
    </div>

    <div class="ctl-sec" id="sec-audit">
      <h4>最近控制操作</h4>
      <div class="ctl-audit" id="ctlAudit">
        <?php if (!$ctlAudit): ?><span style="opacity:.6">暂无操作记录</span><?php endif; ?>
        <?php foreach ($ctlAudit as $a): ?>
          <div><span class="<?= !empty($a['ok']) ? 'ok' : 'no' ?>"><?= !empty($a['ok']) ? '成功' : '失败' ?></span>
            <?= sE(substr((string)($a['t'] ?? ''), 11, 8)) ?> <?= sE($a['action_cn'] ?? $a['action'] ?? '') ?> · <?= sE(mb_substr((string)($a['detail_cn'] ?? $a['detail'] ?? ''), 0, 46)) ?></div>
        <?php endforeach; ?>
      </div>
    </div>
  </div>
  <div class="ctl-foot">
    <b>安全约束</b>：仅 POST + 密钥 + CSRF + 动作白名单；危险操作二次确认；全部写入 <b>logs/ysl/control.log</b>，不污染 attack.log 指标。
  </div>
</aside>

<noscript><div class="noscript">本页数据已由服务端完整渲染；启用 JavaScript 可获得实时刷新与动效。</div></noscript>
<script>
(function(){
  var STATIC = <?= $static ? 'true' : 'false' ?>;
  // 静态快照不写入密钥：另存为 HTML 分享时不会泄露访问钥匙
  var KEY = <?= $static ? '""' : json_encode($given, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
  // CSRF token 由服务端用同一把密钥签发；静态快照为空，天然无法发起控制请求
  var CTL_CSRF = <?= json_encode($ctlCsrf, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
  var PERIOD = 5, PAUSED = false;
  function pad(n){return n<10?'0'+n:''+n;}
  function clock(){
    var d=new Date();
    var a=document.getElementById('clk'), b=document.getElementById('clkdate');
    if(a)a.textContent=pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds());
    if(b)b.textContent=d.getFullYear()+'/'+pad(d.getMonth()+1)+'/'+pad(d.getDate());
  }
  clock(); setInterval(clock,1000);

  // 数字始终由服务端渲染真实值，不做从 0 递增（避免首屏/截图出现错误的中间数字）
  // 刷新后用短暂高亮提示数据已更新
  function flash(){
    document.querySelectorAll('#app .kpi .v').forEach(function(el){
      el.style.transition='text-shadow .35s';
      el.style.textShadow='0 0 22px rgba(34,211,238,.85)';
      setTimeout(function(){ el.style.textShadow=''; },420);
    });
  }

  var left=PERIOD;
  var tick=document.getElementById('tick');
  function setTick(){ if(tick)tick.textContent=(STATIC?'静态快照':(PAUSED?'已暂停':(left+'s 后刷新'))); }

  function refresh(){
    if(STATIC)return;
    var u=location.pathname+'?key='+encodeURIComponent(KEY)+'&format=fragment&_='+Date.now();
    fetch(u,{cache:'no-store'}).then(function(r){
      if(!r.ok)throw new Error('HTTP '+r.status);
      return r.text();
    }).then(function(html){
      var app=document.getElementById('app');
      if(app && html.indexOf('class="kpis"')!==-1){ app.innerHTML=html; flash(); }
    }).catch(function(){ /* 网络异常保留上一帧，不清空 */ });
  }

  // ---------------- 控制台：真实调用 /waf-control，执行后回读状态并刷新大屏 ----------------
  var GUARD_NAMES = {ai:'AI 自学习',fp:'叙述性误报复核',tautology:'布尔恒真加固',bypass:'绕过结构加固',errors:'错误输出（排查用）'};
  var GUARD_SHORT = {ai:'AI',fp:'误报复核',tautology:'布尔恒真',bypass:'绕过结构',errors:'错误输出'};
  // 中文映射与服务端 i18n.php 同源；控制端点 JSON 里的英文枚举只在此转换一次
  var CN_STATE = <?= json_encode(wafCnStateMap(), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
  var CN_MODE  = <?= json_encode(wafCnModeMap(),  JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
  function cnState(s){ return CN_STATE[String(s||'').toLowerCase()] || '其他状态'; }
  function cnMode(m){ return CN_MODE[String(m||'').toLowerCase()] || '其他模式'; }
  var drawer=document.getElementById('ctlDrawer'), resultEl=document.getElementById('ctlResult');
  function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  function ctlText(id,v){var e=document.getElementById(id); if(e)e.textContent=v;}
  function ctlToggle(on){ if(drawer)drawer.classList.toggle('open',on); }
  function ctlFmt(n){return (Number(n||0)/1048576).toFixed(2)+' MB';}

  function ctlApplyState(st){
    if(!st)return;
    var rt=st.runtime||{};
    if(rt.mode){
      var mb=document.querySelector('.mode-btn');
      if(mb){
        mb.dataset.params=JSON.stringify({value:rt.mode==='enforce'?'observe':'enforce'});
        mb.textContent=rt.mode==='enforce'?'切换为观察模式':'恢复强制拦截';
        mb.classList.toggle('is-off',rt.mode==='observe');
      }
      ctlText('sMode',rt.mode==='observe'?'观察模式':'强制拦截');
      var pill=document.getElementById('ctlPill'); if(pill)pill.textContent='模式 '+cnMode(rt.mode);
    }
    if(rt.guards){
      var sum=[];
      document.querySelectorAll('.guard-btn').forEach(function(b){
        var p={}; try{p=JSON.parse(b.dataset.params||'{}');}catch(e){}
        var k=p.name; if(!k)return;
        var on=!!rt.guards[k];
        b.dataset.params=JSON.stringify({name:k,on:on?'0':'1'});
        b.classList.toggle('is-on',on); b.classList.toggle('is-off',!on);
        b.textContent=(GUARD_NAMES[k]||k)+' · '+(on?'开':'关');
        sum.push((GUARD_SHORT[k]||k)+(on?'开':'关'));
      });
      ctlText('sGuards',sum.join(' / '));
    }
    if(typeof rt.body_max!=='undefined'){
      ctlText('sBody',Number(rt.body_max).toLocaleString());
      var bi=document.getElementById('ctlBody'); if(bi)bi.value=rt.body_max;
    }
    if(rt.whitelist){
      var wl=document.getElementById('ctlWl');
      if(wl){
        wl.innerHTML=rt.whitelist.length ? rt.whitelist.map(function(c){
          return '<span class="chip">'+esc(c)+'<button type="button" title="移除" data-act="whitelist.del" data-params=\''+JSON.stringify({cidr:c})+'\'>×</button></span>';
        }).join('') : '<span class="chip" style="opacity:.55">白名单为空</span>';
      }
      ctlText('sWl',rt.whitelist.length);
    }
    if(st.circuit)ctlText('sCircuit',cnState(st.circuit.state)+' / '+(st.circuit.mode?cnState(st.circuit.mode):'暂无记录'));
    if(st.qps){
      ctlText('sQps',cnState(st.qps.state)+' · '+(st.qps.qps||0));
      var qs=['soft','hard','ip_soft','ip_hard','cooldown'];
      var qid=['ctlQSoft','ctlQHard','ctlQIpSoft','ctlQIpHard','ctlQCd'];
      qs.forEach(function(k,i){ var el=document.getElementById(qid[i]); if(el&&typeof st.qps[k]!=='undefined')el.value=st.qps[k]; });
      var qp=document.querySelector('.qps-enable-btn');
      if(qp){
        qp.dataset.params=JSON.stringify({enabled:st.qps.enabled?'0':'1'});
        qp.textContent=st.qps.enabled?'停用保护（只计数）':'启用保护';
      }
    }
    if(st.dna)ctlText('sWatch',st.dna.watch_pid?('PID '+st.dna.watch_pid):'未运行');
    if(typeof st.log_bytes!=='undefined')ctlText('sLog',ctlFmt(st.log_bytes));
    // v6.5.0：蜜罐状态实时回写（状态灯、倒计时、用途、触碰次数、矩阵卡片）
    if(st.honeypot){
      var hp=st.honeypot, on=!!hp.enabled;
      var left=on?(hp.timed?('剩余 '+Math.ceil((hp.left||0)/60)+' 分钟'):'长期启用'):'不适用';
      var label=on?'启用中（高危）':'已停用（默认）';
      var col=on?'#fca5a5':'#9fe8c8';
      var e1=document.getElementById('sHp'); if(e1){e1.textContent=label+' · '+left;e1.style.color=col;}
      var e2=document.getElementById('sHpTop'); if(e2){e2.textContent=label;e2.style.color=col;}
      ctlText('sHpLeft',left); ctlText('sHpHits',hp.hits||0); ctlText('sHpReason',hp.reason||'暂无');
      var card=document.getElementById('feat-honeypot'), fs=document.getElementById('fs-honeypot');
      if(fs)fs.textContent=label+' · '+left;
      if(card){
        card.className='feat '+(on?'danger':'off')+' hot';
        var lp=card.querySelector('.feat-lamp'); if(lp)lp.className='feat-lamp '+(on?'danger':'off');
      }
      var dc=document.getElementById('feat-hp_disable'), dfs=document.getElementById('fs-hp_disable');
      if(dfs)dfs.textContent=label;
      if(dc){
        dc.className='feat '+(on?'danger':'off')+' hot';
        var dl=dc.querySelector('.feat-lamp'); if(dl)dl.className='feat-lamp '+(on?'danger':'off');
      }
    }
  }

  function ctlResult(j){
    if(!resultEl)return;
    resultEl.className='ctl-result show '+(j.ok?'ok':'bad');
    resultEl.textContent=(j.ok?'✓ ':'✗ ')+(j.message||'')
      +(j.new_key?('\n新密钥（只显示一次，请保存并重新打开链接）：\n'+j.new_key):'')
      +(j.detail?('\n'+String(j.detail).slice(0,420)):'');
  }
  function ctlAudit(list){
    var box=document.getElementById('ctlAudit'); if(!box)return;
    box.innerHTML=list.length ? list.map(function(a){
      return '<div><span class="'+(a.ok?'ok':'no')+'">'+(a.ok?'成功':'失败')+'</span> '
        +esc(String(a.t||'').slice(11,19))+' '+esc(a.action_cn||a.action||'')+' · '+esc(String(a.detail_cn||a.detail||'').slice(0,46))+'</div>';
    }).join('') : '<span style="opacity:.6">暂无操作记录</span>';
  }
  function ctlArm(btn){
    if(btn.classList.contains('armed'))return true;
    btn.classList.add('armed');
    btn.dataset.oldText=btn.textContent;
    btn.textContent='再点一次确认 · '+btn.dataset.oldText;
    setTimeout(function(){ btn.classList.remove('armed'); if(btn.dataset.oldText){btn.textContent=btn.dataset.oldText;delete btn.dataset.oldText;} },6000);
    return false;
  }
  function ctlRun(btn){
    if(STATIC)return;
    var params={}; try{params=JSON.parse(btn.dataset.params||'{}');}catch(e){}
    if(btn.dataset.input){
      var el=document.getElementById(btn.dataset.input);
      params[btn.dataset.pkey||'value']=el?String(el.value).trim():'';
    }
    // v6.4.0：多输入框一次提交，格式 "id:pkey,id:pkey"，用于 QPS 五个阈值
    if(btn.dataset.multi){
      btn.dataset.multi.split(',').forEach(function(spec){
        var a=spec.split(':'); var el=document.getElementById(a[0]);
        if(el)params[a[1]||a[0]]=String(el.value).trim();
      });
    }
    // v6.5.0：高危蜜罐启用必须手动输入确认短语，服务端二次校验
    if(btn.dataset.phrase){
      var phe=document.getElementById(btn.dataset.phrase);
      params.phrase=phe?String(phe.value).trim():'';
    }
    var body=new URLSearchParams();
    body.set('key',KEY); body.set('csrf',CTL_CSRF); body.set('action',btn.dataset.act);
    body.set('params',JSON.stringify(params)); body.set('confirm',btn.classList.contains('armed')?'1':'0');
    btn.disabled=true;
    fetch('/waf-control',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString(),cache:'no-store'})
      .then(function(r){return r.json().then(function(j){return j;});})
      .then(function(j){
        ctlResult(j);
        if(j.new_key&&j.new_csrf){ KEY=j.new_key; CTL_CSRF=j.new_csrf; }
        if(j.state)ctlApplyState(j.state);
        if(j.audit)ctlAudit(j.audit);
        refresh();
      })
      .catch(function(e){ctlResult({ok:false,message:'控制请求失败：'+e.message});})
      .then(function(){ btn.disabled=false; btn.classList.remove('armed'); if(btn.dataset.oldText){btn.textContent=btn.dataset.oldText;delete btn.dataset.oldText;} });
  }
  function ctlView(v,btn){
    if(v==='pause'){ PAUSED=!PAUSED; btn.textContent=PAUSED?'恢复轮询':'暂停轮询'; setTick(); }
    else if(v.indexOf('period:')===0){ PERIOD=parseInt(v.slice(7),10)||5; left=PERIOD; setTick(); }
    else if(v==='refresh'){ refresh(); }
    else if(v==='fullscreen'){
      if(!document.fullscreenElement){ if(document.documentElement.requestFullscreen)document.documentElement.requestFullscreen(); }
      else if(document.exitFullscreen){ document.exitFullscreen(); }
    }
    else if(v==='static'&&!STATIC){ window.open(location.pathname+'?key='+encodeURIComponent(KEY)+'&static=1','_blank'); }
    else if(v==='console'&&!STATIC){ window.open('/waf-console?key='+encodeURIComponent(KEY),'_blank'); }
    else if(v==='close'){ ctlToggle(false); }
  }
  // v6.5.0：功能矩阵 / 底栏状态灯点击后打开控制台并定位到对应分区，高亮提示
  function ctlFocus(id){
    if(STATIC)return;
    ctlToggle(true);
    var sec=document.getElementById(id);
    if(!sec)return;
    setTimeout(function(){
      if(sec.scrollIntoView)sec.scrollIntoView({behavior:'smooth',block:'center'});
      sec.classList.add('flash');
      setTimeout(function(){sec.classList.remove('flash');},2200);
    },80);
  }
  document.addEventListener('click',function(e){
    var t=e.target; if(!t||!t.closest)return;
    var b=t.closest('[data-act]');
    if(b){
      if(STATIC||b.disabled)return;
      if(b.dataset.danger==='1'&&!b.classList.contains('armed')){ ctlArm(b); return; }
      ctlRun(b); return;
    }
    var v=t.closest('[data-view]');
    if(v&&!v.disabled){ ctlView(v.dataset.view,v); return; }
    var f=t.closest('[data-focus]');
    if(f&&!f.disabled){ ctlFocus(f.dataset.focus); return; }
    if(t.closest('#ctlOpen')){ ctlToggle(true); return; }
    if(t.closest('#ctlClose')){ ctlToggle(false); return; }
  });

  if(STATIC){
    document.querySelectorAll('[data-act]').forEach(function(b){b.disabled=true;b.title='静态快照不可执行操作';});
    document.querySelectorAll('[data-focus]').forEach(function(b){b.disabled=true;b.title='静态快照不可执行操作';});
    document.querySelectorAll('[data-view="pause"],[data-view="refresh"],[data-view^="period:"]').forEach(function(b){b.disabled=true;});
    if(resultEl){resultEl.className='ctl-result show bad';resultEl.textContent='当前为静态快照：不含密钥与 CSRF，所有控制操作已禁用。';}
  }

  if(!STATIC){
    setInterval(function(){ if(PAUSED){ setTick(); return; } left--; if(left<=0){ left=PERIOD; refresh(); } setTick(); },1000);
    setTick();
  }else{ setTick(); }
})();
</script>
</body></html>
<?php endif; ?>
