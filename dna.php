<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少. 保留所有权利.
 */

declare(strict_types=1);
/**
 * YSL语枢-盾甲WAF · 文件 DNA 防篡改（主机层第二道防线）
 *
 * 对齐 Go 母本 internal/dna 的能力口径，PHP 版以「独立 CLI 进程」承担：
 *   - 受保护脚本/配置递归建档：SHA-256 + 权限 + 大小 + 备份副本双哈希自证
 *   - 基线 HMAC-SHA256 签名（密钥独立、0600）；签名不可信时拒绝任何自动还原
 *   - 递归解码（base64 / gzinflate / rot13 / hex / url…）后再扫，抓编码链后门
 *   - 分级判定：高置信才允许手术 / 隔离 / 还原；中置信（system/exec/include
 *     在 WordPress 插件里是合法写法）只告警，绝不动文件
 *   - 精准手术（切除恶意语句、术后复扫自校验）→ 失败才整体还原
 *   - quarantine / infected / surgery 三类留档
 *   - 状态快照 dna-status.json 单独落盘，供态势大屏只读消费（不碰审计哈希链）
 *
 * 与请求内检测完全解耦：不在 auto_prepend_file 管线里，不增加任何请求耗时。
 * 默认只读（只告警 + 写状态），加 --apply 才执行处置，避免上线即误伤运维改动。
 *
 * 用法：
 *   php dna.php plan                       试算监控范围（不建基线、不写文件）
 *   php dna.php baseline                   建立基线 + 备份 + 签名
 *   php dna.php scan                       巡检（默认只读告警）
 *   php dna.php scan --apply               巡检并处置高置信篡改
 *   php dna.php audit                      只读预览变更
 *   php dna.php rebaseline                 重建基线（更新插件/主题后接受新状态）
 *   php dna.php restore --file=相对路径     从备份还原单个文件
 *   php dna.php status                     打印状态快照 JSON
 *   php dna.php selftest                   能力自检（不写任何文件）
 *   php dna.php watch --interval=30        轮询守护（--apply 才会自动处置）
 *
 * 可选参数：--root=站点根 --backup=备份目录 --status=状态快照 --exclude=追加排除
 *           --no-surgery --restore-any --adopt-new
 */

const DNA_VER          = '6.5.0';
const DNA_MAX_FILE     = 8 * 1024 * 1024;   // 单文件上限，超过不做防篡改目标
const DNA_MAX_DECODED  = 65536;             // 递归解码结果上限
const DNA_MAX_LAYERS   = 5;                 // 编码链最大层数
const DNA_RECENT_MAX   = 20;
const DNA_STATUS_STALE = 180;               // 快照超过 180 秒视为守护进程不在

/* ------------------------------------------------------------------ 配置 */

function dnaOpts(array $argv): array {
    $cmd = $argv[1] ?? 'status';
    $o = ['cmd' => $cmd, 'apply' => false, 'no_surgery' => false,
          'restore_any' => false, 'adopt_new' => false];
    foreach (array_slice($argv, 2) as $a) {
        if (!str_starts_with($a, '--')) { continue; }
        $a = substr($a, 2);
        if (str_contains($a, '=')) {
            [$k, $v] = explode('=', $a, 2);
            $o[$k] = $v;
        } else {
            $o[$a] = true;
        }
    }
    return $o;
}

function dnaRoot(array $o): string {
    $r = $o['root'] ?? (getenv('WAF_HOME') ?: dirname(__FILE__));
    return rtrim(str_replace('\\', '/', (string)$r), '/');
}

function dnaPaths(array $o): array {
    $root   = dnaRoot($o);
    $backup = $o['backup'] ?? ($root . '/var/dna');
    $status = $o['status'] ?? ($root . '/var/data/dna-status.json');
    $logEnv = getenv('WAF_LOG_PATH');
    $logDir = $logEnv ? rtrim(str_replace('\\', '/', $logEnv), '/') : ($root . '/logs/ysl');
    $b = rtrim(str_replace('\\', '/', (string)$backup), '/');
    return [
        'root'      => $root,
        'backup'    => $b,
        'status'    => str_replace('\\', '/', (string)$status),
        'log'       => $logDir . '/dna.log',
        'baseline'  => $b . '/baseline.json',
        'key'       => $b . '/.baseline.key',
        'hmac'      => $b . '/.baseline.hmac',
        'counters'  => $b . '/counters.json',
        'interval'  => max(5, (int)($o['interval'] ?? 30)),
    ];
}

function dnaExts(): array {
    return ['php' => 1, 'php3' => 1, 'php4' => 1, 'php5' => 1, 'php7' => 1, 'php8' => 1,
            'phtml' => 1, 'pht' => 1, 'phar' => 1, 'inc' => 1,
            'jsp' => 1, 'jspx' => 1, 'asp' => 1, 'aspx' => 1, 'ashx' => 1, 'asmx' => 1,
            'cgi' => 1, 'pl' => 1, 'py' => 1, 'sh' => 1];
}

function dnaExcludes(array $o): array {
    $base = ['uploads', 'cache', 'upgrade', 'node_modules', '.git',
             'wp-content/cache', 'wp-content/upgrade', 'wp-content/uploads',
             'var', 'logs', 'tests', 'dist'];
    if (!empty($o['exclude'])) {
        foreach (explode(',', (string)$o['exclude']) as $x) {
            $x = trim($x);
            if ($x !== '') { $base[] = $x; }
        }
    }
    return $base;
}

function dnaExcluded(string $rel, array $excludes): bool {
    $parts = explode('/', $rel);
    foreach ($excludes as $ex) {
        $ex = trim(str_replace('\\', '/', $ex), '/');
        if ($ex === '') { continue; }
        if (in_array($ex, $parts, true)) { return true; }
        if (str_starts_with($rel, $ex . '/')) { return true; }
        foreach ($parts as $i => $p) {
            if ($i + 1 < count($parts) && $p . '/' . $parts[$i + 1] === $ex) { return true; }
        }
    }
    return false;
}

/** 递归列出受监控文件：相对路径 => 绝对路径 */
function dnaWalk(string $root, array $excludes): array {
    $out = [];
    if (!is_dir($root)) { return $out; }
    $exts = dnaExts();
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
    } catch (Throwable $e) {
        return $out;
    }
    foreach ($it as $f) {
        try {
            if (!$f->isFile() || $f->isLink() || $f->getSize() > DNA_MAX_FILE) { continue; }
            $abs = str_replace('\\', '/', $f->getPathname());
            $rel = ltrim(substr($abs, strlen($root)), '/');
            if ($rel === '' || dnaExcluded($rel, $excludes)) { continue; }
            $base = strtolower(basename($rel));
            $ext  = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
            if (!isset($exts[$ext]) && !in_array($base, ['.htaccess', '.user.ini'], true)) { continue; }
            $out[$rel] = $abs;
        } catch (Throwable $e) { /* 单个文件不可读不影响整体 */ }
    }
    ksort($out);
    return $out;
}

/* ------------------------------------------------- 基线签名（HMAC-SHA256） */

function dnaKey(string $path): string {
    if (is_file($path) && filesize($path) >= 16) {
        return (string)file_get_contents($path);
    }
    @mkdir(dirname($path), 0700, true);
    $key = bin2hex(random_bytes(32));
    $fp = @fopen($path, 'xb');           // O_EXCL，不覆盖别人刚建的密钥
    if ($fp) {
        fwrite($fp, $key);
        fclose($fp);
        @chmod($path, 0600);
        return $key;
    }
    return is_file($path) ? (string)file_get_contents($path) : $key;
}

function dnaSign(string $key, string $data): string {
    return hash_hmac('sha256', $data, $key);
}

/** 返回 [ok, present, entries]；签名不存在 = 旧版基线，信任一次并补签 */
function dnaLoadBaseline(array $p): array {
    if (!is_file($p['baseline'])) { return [false, false, []]; }
    $raw = (string)@file_get_contents($p['baseline']);
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !isset($doc['files']) || !is_array($doc['files'])) {
        return [false, true, []];
    }
    $key = dnaKey($p['key']);
    if (!is_file($p['hmac'])) {
        @file_put_contents($p['hmac'], dnaSign($key, $raw), LOCK_EX);
        @chmod($p['hmac'], 0600);
        return [true, false, $doc['files']];   // 信任一次并补签（调用方留日志）
    }
    $want = trim((string)@file_get_contents($p['hmac']));
    return [hash_equals(dnaSign($key, $raw), $want), true, $doc['files']];
}

function dnaSaveBaseline(array $p, array $entries, bool $dropSignature = false): void {
    @mkdir($p['backup'], 0700, true);
    $raw = json_encode(['v' => 3, 'created' => gmdate('c'), 'files' => $entries],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    file_put_contents($p['baseline'], $raw, LOCK_EX);
    @chmod($p['baseline'], 0600);
    $key = dnaKey($p['key']);
    if ($dropSignature) { @unlink($p['hmac']); }
    file_put_contents($p['hmac'], dnaSign($key, $raw), LOCK_EX);
    @chmod($p['hmac'], 0600);
}

function dnaBackupPath(array $p, string $rel): string {
    return $p['backup'] . '/files/' . substr(hash('sha256', $rel), 0, 24) . '.bak';
}

function dnaArtifact(array $p, string $kind, string $rel, string $suffix = ''): string {
    return $p['backup'] . '/' . $kind . '/' . date('Ymd-His') . '-'
         . substr(hash('sha256', $rel), 0, 12) . '-' . basename($rel) . $suffix;
}

function dnaEnsureDirs(array $p): void {
    foreach (['', '/files', '/quarantine', '/infected', '/surgery'] as $d) {
        @mkdir($p['backup'] . $d, 0700, true);
    }
    @mkdir(dirname($p['status']), 0750, true);
    @mkdir(dirname($p['log']), 0750, true);
}

/* --------------------------------------------------- 恶意代码分级 + 解码链 */

function dnaRules(): array {
    // 高置信：可以动手（手术 / 隔离 / 还原）。判据是「执行点 + 编码链 / 请求输入」。
    // 中置信：可能合法（WordPress 插件、调试工具、常量表），只记录告警。
    return [
        ['eval_decode_chain', 'high',
            '/\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|rawurldecode|urldecode|openssl_decrypt|mcrypt_decrypt)\s*\(/i'],
        ['eval_variable_func', 'high',
            '/\b(?:eval|assert)\s*\(\s*@?\s*\$[A-Za-z_]\w*\s*\(/i'],
        ['exec_from_input', 'high',
            '/\b(?:eval|assert|create_function)\s*\(\s*@?\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\s*\[/i'],
        ['system_from_input', 'high',
            '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*@?\s*\$_(?:POST|GET|REQUEST|COOKIE)\s*\[/i'],
        ['include_from_input', 'high',
            '/\b(?:include|require)(?:_once)?\s*\(?\s*@?\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i'],
        ['variable_function_from_input', 'high',
            '/\$[A-Za-z_]\w*\s*\(\s*@?\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/'],
        ['assert_var', 'high',
            '/\bassert\s*\(\s*@?\s*\$\w+\s*(?:\[[^\]]*\])?\s*\(/i'],
        ['obfuscated_var', 'high', '/\$\{[^}\n]{100,}\}/'],
        ['hidden_php', 'high',
            '/\?>\s*<\?(?:php|=)\s*@?\s*(?:eval|assert|system|exec|shell_exec|base64_decode|gzinflate)\s*\(/i'],
        ['backtick_from_input', 'high', '/`[^`\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/'],
        ['preg_replace_e_from_input', 'high',
            '/\bpreg_replace\s*\(\s*["\'][^"\']{0,64}\/[a-z]*e[a-z]*["\']\s*,\s*@?\$_(?:GET|POST|REQUEST|COOKIE)/i'],

        ['preg_replace_e', 'medium',
            '/\bpreg_replace\s*\(\s*["\'][^"\']{0,64}\/[a-z]*e[a-z]*["\']/i'],
        ['hex_escape', 'medium', '/(?:\\\\x[0-9a-fA-F]{2}){20,}/'],
        ['chr_concat', 'medium', '/(?:chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){4,}/i'],
        ['shell_exec', 'medium',
            '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/i'],
        ['include_var', 'medium',
            '/\b(?:include|require)(?:_once)?\s*\(?\s*\$/i'],
        ['dynamic_call', 'medium', '/\bcall_user_func(?:_array)?\s*\(\s*\$/i'],
        ['file_write_from_input', 'medium',
            '/\b(?:file_put_contents|move_uploaded_file|fwrite)\s*\([^)]*\$_(?:POST|GET|REQUEST|FILES)/i'],
        ['create_function', 'medium', '/\bcreate_function\s*\(/i'],
        ['backtick_exec', 'medium', '/`[^`\n]{1,80}`/'],
    ];
}

function dnaScanContent(string $code): array {
    $hits = [];
    foreach (dnaRules() as [$name, $level, $pat]) {
        $r = @preg_match($pat, $code, $m, PREG_OFFSET_CAPTURE);
        if ($r === 1) {
            $hits[] = ['rule' => $name, 'level' => $level,
                       'offset' => $m[0][1], 'snippet' => substr($m[0][0], 0, 120)];
        }
    }
    return $hits;
}

function dnaDecodeFuncs(): array {
    return ['base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode',
            'str_rot13', 'hex2bin', 'rawurldecode', 'urldecode'];
}

function dnaApplyDecode(string $fn, string $s): ?string {
    switch ($fn) {
        case 'base64_decode':   $d = base64_decode($s, true); break;
        case 'str_rot13':       $d = str_rot13($s); break;
        case 'hex2bin':         $d = @hex2bin($s); break;
        case 'urldecode':       $d = urldecode($s); break;
        case 'rawurldecode':    $d = rawurldecode($s); break;
        case 'gzinflate':       $d = function_exists('gzinflate') ? @gzinflate($s) : false; break;
        case 'gzuncompress':    $d = function_exists('gzuncompress') ? @gzuncompress($s) : false; break;
        case 'gzdecode':        $d = function_exists('gzdecode') ? @gzdecode($s) : false; break;
        default:                $d = false;
    }
    if ($d === false || $d === null || !is_string($d) || $d === '' || $d === $s) { return null; }
    if (strlen($d) > DNA_MAX_DECODED) { return null; }
    return $d;
}

/** 递归解码：返回 [最终文本, 层数, 用到的函数] */
function dnaRecursiveDecode(string $code): array {
    $cur = $code; $layers = [];
    for ($i = 0; $i < DNA_MAX_LAYERS; $i++) {
        $next = null; $used = null;
        foreach (dnaDecodeFuncs() as $fn) {
            $pat = '/\b' . preg_quote($fn, '/') . '\s*\(\s*["\']([^"\']{8,})["\']\s*\)/i';
            if (@preg_match($pat, $cur, $m) !== 1) { continue; }
            $dec = dnaApplyDecode($fn, $m[1]);
            if ($dec === null) { continue; }
            $next = str_replace($m[0], $dec, $cur);
            $used = $fn;
            break;
        }
        if ($next === null || $next === $cur) { break; }
        $cur = $next;
        $layers[] = $used;
    }
    return [$cur, count($layers), $layers];
}

/** 综合判定：直接扫 + 解码链复扫，返回 high / medium 明细 */
function dnaVerdict(string $code): array {
    $direct = dnaScanContent($code);
    $high = array_values(array_filter($direct, fn($h) => $h['level'] === 'high'));
    $medium = array_values(array_filter($direct, fn($h) => $h['level'] === 'medium'));

    [$decoded, $layers, $funcs] = dnaRecursiveDecode($code);
    if ($layers > 0 && $decoded !== $code) {
        foreach (dnaScanContent($decoded) as $h) {
            if ($h['level'] === 'high') {
                $h['rule'] = 'decoded:' . $h['rule'];
                $h['via'] = implode('→', $funcs);
                $high[] = $h;
            }
        }
    }
    return ['high' => $high, 'medium' => $medium, 'layers' => $layers, 'via' => $funcs];
}

/* --------------------------------------------------------- 日志 / 状态快照 */

function dnaLog(array $p, string $kind, string $rel, string $msg, array &$recent): void {
    $rec = ['t' => gmdate('c'), 'kind' => $kind, 'path' => $rel, 'msg' => $msg];
    @file_put_contents($p['log'], json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX);
    $recent[] = $rec;
    if (count($recent) > DNA_RECENT_MAX) { $recent = array_slice($recent, -DNA_RECENT_MAX); }
    fwrite(STDERR, sprintf("[DNA] %-16s %-52s %s\n", $kind, $rel, $msg));
}

function dnaLoadStatus(array $p): array {
    if (!is_file($p['status'])) { return []; }
    $d = json_decode((string)@file_get_contents($p['status']), true);
    return is_array($d) ? $d : [];
}

/**
 * 从真实 DNA 日志里挑「人要看」的事件给大屏。
 * Go 母本同口径：建档 / 普通内容变更 / 每轮重报的 missing 会把真正的攻击
 * 记录刷掉，所以大屏摘要只列攻击、处置与异常；全量事件仍完整留在 dna.log 里，
 * 需要查运维改动明细直接看日志，不在大屏上刷屏。
 */
function dnaNotableEvents(array $p, int $limit = DNA_RECENT_MAX): array {
    if (!is_file($p['log'])) { return []; }
    $lines = @file($p['log'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) { return []; }
    $notable = ['malicious', 'new_malicious', 'quarantined', 'surgery', 'surgery_fail',
                'restored', 'baseline_bad_sig', 'baseline_unsigned', 'dual_tamper',
                'missing', 'adopted'];
    $out = [];
    for ($i = count($lines) - 1; $i >= 0 && count($out) < $limit; $i--) {
        $d = json_decode($lines[$i], true);
        if (!is_array($d)) { continue; }
        if (!in_array((string)($d['kind'] ?? ''), $notable, true)) { continue; }
        $out[] = $d;
    }
    return array_reverse($out);
}

function dnaWriteStatus(array $p, array $o, array $base, array $counters,
                        bool $baselineOK, string $lastError = '', int $roundHigh = 0): array {
    $high = (int)($counters['high'] ?? 0);   // 累计，用于大屏展示历史
    $doc = [
        'time'          => gmdate('c'),
        'pid'           => getmypid() ?: 0,
        'ver'           => DNA_VER,
        'files'         => count($base),
        'watching'      => 0,                       // PHP 版为轮询，无 inotify
        'events'        => (int)($counters['events'] ?? 0),
        'tamper_hits'   => (int)($counters['tamper_hits'] ?? 0),
        'restores'      => (int)($counters['restores'] ?? 0),
        'surgery'       => (int)($counters['surgery'] ?? 0),
        'quarantine'    => (int)($counters['quarantine'] ?? 0),
        'dual_tamper'   => (int)($counters['dual_tamper'] ?? 0),
        'new_files'     => (int)($counters['new_files'] ?? 0),
        'high'          => $high,
        'medium'        => (int)($counters['medium'] ?? 0),
        'missing'       => (int)($counters['missing'] ?? 0),
        'last_check'    => time(),
        'baseline_ok'   => $baselineOK,
        'signature'     => $baselineOK ? 'HMAC-SHA256 通过' : '不可信 / 缺失',
        'roots'         => [$p['root']],
        'backup'        => $p['backup'],
        'interval'      => $p['interval'],
        'read_only'     => empty($o['apply']),
        'surgery_on'    => empty($o['no_surgery']),
        'last_error'    => $lastError,
        'recent'        => dnaNotableEvents($p),
        'round_high'    => $roundHigh,          // 本轮高置信命中数
        // 健康度看「本轮」，不能用累计：历史处置过一次不代表现在不健康
        'healthy'       => $baselineOK && $lastError === '' && $roundHigh === 0,
    ];
    @file_put_contents($p['status'], json_encode($doc, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), LOCK_EX);
    @chmod($p['status'], 0644);
    return $doc;
}

function dnaCounters(array $p): array {
    if (!is_file($p['counters'])) { return []; }
    $d = json_decode((string)@file_get_contents($p['counters']), true);
    return is_array($d) ? $d : [];
}

function dnaSaveCounters(array $p, array $c): void {
    @mkdir(dirname($p['counters']), 0700, true);
    @file_put_contents($p['counters'], json_encode($c, JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function dnaBump(array &$c, string $key, int $n = 1): void {
    $c[$key] = (int)($c[$key] ?? 0) + $n;
}

/* ------------------------------------------------------------ 精准手术 / 还原 */

/** 把命中所在整行切除、只留一行说明注释；返回 [是否成功, 术后文本] */
function dnaSurgery(string $code, array $high, string $rel): array {
    $lines = explode("\n", $code);
    $touched = 0;
    foreach ($high as $h) {
        $pos = (int)($h['offset'] ?? -1);
        if ($pos < 0) { continue; }
        $acc = 0;
        foreach ($lines as $i => $line) {
            $len = strlen($line) + 1;
            if ($acc + $len > $pos) {
                if (str_contains($line, '/* [DNA]')) { break; }
                // 整行替换为纯注释：恶意文本必须真正消失。把原语句包在
                // /* … */ 里仍会被正则命中，而且注释后的原语句照样执行。
                $lines[$i] = '/* [DNA] 已切除恶意语句 ' . gmdate('Y-m-d H:i') . ' UTC · ' . $h['rule'] . ' */';
                $touched++;
                break;
            }
            $acc += $len;
        }
    }
    if ($touched === 0) { return [false, $code]; }
    $after = implode("\n", $lines);
    // 术后自校验：仍含高置信结构则判定手术失败，改走整体还原
    if (dnaVerdict($after)['high'] !== []) { return [false, $after]; }
    return [true, $after];
}

function dnaRestoreOne(array $p, string $rel, array $entry, array &$recent, array &$c): bool {
    $bak = dnaBackupPath($p, $rel);
    if (!is_file($bak)) { return false; }
    if (hash_file('sha256', $bak) !== ($entry['backup_hash'] ?? '')) {
        dnaLog($p, 'dual_tamper', $rel, '备份副本哈希不符，拒绝用可疑备份覆盖生产文件', $recent);
        dnaBump($c, 'dual_tamper');
        return false;
    }
    $dest = $p['root'] . '/' . $rel;
    $data = (string)@file_get_contents($bak);
    if (@file_put_contents($dest, $data, LOCK_EX) === false) { return false; }
    @chmod($dest, (int)($entry['perm'] ?? 0644));
    dnaLog($p, 'restored', $rel, '已从可信备份整体还原（保权限 ' . decoct((int)($entry['perm'] ?? 0644)) . '）', $recent);
    dnaBump($c, 'restores');
    return true;
}

/* ------------------------------------------------------------------- 命令 */

function dnaCmdPlan(array $p, array $o, array $ex): int {
    $files = dnaWalk($p['root'], $ex);
    echo "DNA 试算（只列范围，不建基线、不复制备份）\n";
    echo "  站点根  : {$p['root']}\n";
    echo "  备份目录: {$p['backup']}\n";
    echo "  排除目录: " . implode(', ', $ex) . "\n";
    echo "  受监控  : " . count($files) . " 个文件\n";
    $byExt = [];
    foreach (array_keys($files) as $rel) {
        $e = strtolower(pathinfo($rel, PATHINFO_EXTENSION)) ?: '(无扩展名)';
        $byExt[$e] = ($byExt[$e] ?? 0) + 1;
    }
    arsort($byExt);
    foreach ($byExt as $e => $n) { echo sprintf("    %-14s %d\n", $e, $n); }
    echo "  前 10 条:\n";
    foreach (array_slice(array_keys($files), 0, 10) as $rel) { echo "    $rel\n"; }
    return 0;
}

function dnaCmdBaseline(array $p, array $o, array $ex, bool $rebuild): int {
    dnaEnsureDirs($p);
    $files = dnaWalk($p['root'], $ex);
    if ($files === []) {
        fwrite(STDERR, "[DNA] 站点根下没有可监控文件，拒绝建立空基线（fail-open 风险）\n");
        return 2;
    }
    $entries = []; $recent = []; $c = dnaCounters($p);
    $c['reported'] = [];   // 重建基线接受当前全部状态，清掉历史「已知变更」节流记录
    foreach ($files as $rel => $abs) {
        $hash = @hash_file('sha256', $abs);
        if ($hash === false) { continue; }
        $bak = dnaBackupPath($p, $rel);
        @mkdir(dirname($bak), 0700, true);
        if (!@copy($abs, $bak)) { continue; }
        $entries[$rel] = [
            'hash'        => $hash,
            'backup_hash' => @hash_file('sha256', $bak),
            'perm'        => @fileperms($abs) & 0777,
            'size'        => @filesize($abs),
            'mtime'       => @filemtime($abs),
        ];
    }
    dnaSaveBaseline($p, $entries, $rebuild);
    dnaBump($c, 'events');
    dnaSaveCounters($p, $c);
    dnaLog($p, 'baseline', '(全量)', (($rebuild ? '重建' : '建立') . '基线：' . count($entries) . ' 个文件，HMAC-SHA256 已签名'), $recent);
    dnaWriteStatus($p, $o, $entries, $c, true);
    echo 'OK ' . ($rebuild ? 'rebaseline' : 'baseline') . ': ' . count($entries) . " 个文件已建档并签名\n";
    echo '基线 ' . $p['baseline'] . "\n状态 " . $p['status'] . "\n";
    return 0;
}

function dnaCmdScan(array $p, array $o, array $ex): int {
    dnaEnsureDirs($p);
    $recent = []; $c = dnaCounters($p); $lastError = '';
    [$sigOK, $sigPresent, $base] = dnaLoadBaseline($p);

    if ($base === []) {
        $lastError = '基线缺失或不可解析：请先执行 php dna.php baseline';
        fwrite(STDERR, "[DNA] $lastError\n");
        dnaWriteStatus($p, $o, [], $c, false, $lastError);
        return 2;
    }
    if (!$sigPresent) {
        dnaLog($p, 'baseline_unsigned', '(基线)', '旧版基线无签名，已信任一次并补签（留痕）', $recent);
    }
    if (!$sigOK) {
        $lastError = '基线 HMAC 校验失败：基线可能被伪造，本轮禁止任何自动还原';
        dnaLog($p, 'baseline_bad_sig', '(基线)', $lastError, $recent);
        $o['apply'] = false;   // 签名不可信，强制只读
    }

    $now = dnaWalk($p['root'], $ex);
    $apply = !empty($o['apply']);
    $doSurgery = $apply && empty($o['no_surgery']);
    $restoreAny = $apply && !empty($o['restore_any']);
    $adoptNew = $apply && !empty($o['adopt_new']);

    $nOK = $nKnown = $nTamper = $nHigh = $nMedium = $nNew = $nMissing = 0;

    // 1) 已建档文件：比对内容 + 备份自证
    foreach ($base as $rel => $entry) {
        $abs = $p['root'] . '/' . $rel;
        if (!is_file($abs)) {
            $nMissing++;
            dnaBump($c, 'missing'); dnaBump($c, 'events');
            dnaLog($p, 'missing', $rel, '受保护文件消失', $recent);
            if ($apply && $sigOK) { dnaRestoreOne($p, $rel, $entry, $recent, $c); }
            continue;
        }
        $hash = @hash_file('sha256', $abs);
        if ($hash === false) { continue; }

        // 备份自证：每轮复验备份副本，双坏绝不拿它覆盖生产
        $bak = dnaBackupPath($p, $rel);
        if (!is_file($bak) || @hash_file('sha256', $bak) !== ($entry['backup_hash'] ?? '')) {
            dnaBump($c, 'dual_tamper'); dnaBump($c, 'events');
            dnaLog($p, 'dual_tamper', $rel, '备份副本缺失或被污染，本文件不做自动还原', $recent);
            continue;
        }

        if ($hash === ($entry['hash'] ?? '')) {
            unset($c['reported'][$rel]);
            $nOK++; continue;
        }

        // 同一份「未处置变更」不重复告警 / 留档 / 计数：守护每 30s 巡检，
        // 运维改了文件却没 rebaseline 时，每轮都刷告警和 infected 副本
        // 等于自己制造日志洪水。记下已报过的哈希，内容再变才重新报一次。
        if (isset($c['reported'][$rel]) && $c['reported'][$rel] === $hash) {
            $nKnown++; continue;
        }
        $c['reported'][$rel] = $hash;

        // ---- 内容变更 ----
        $nTamper++; dnaBump($c, 'tamper_hits'); dnaBump($c, 'events');
        $code = (string)@file_get_contents($abs);
        $v = dnaVerdict($code);
        $high = $v['high']; $medium = $v['medium'];

        @mkdir($p['backup'] . '/infected', 0700, true);
        @mkdir($p['backup'] . '/quarantine', 0700, true);
        @copy($abs, dnaArtifact($p, 'infected', $rel));
        if ($high !== []) {
            @copy($abs, dnaArtifact($p, 'quarantine', $rel));
            dnaBump($c, 'quarantine'); dnaBump($c, 'high');
            $nHigh++;
        } elseif ($medium !== []) {
            dnaBump($c, 'medium'); $nMedium++;
        }

        $rules = implode(',', array_slice(array_column($high, 'rule'), 0, 4))
               ?: implode(',', array_slice(array_column($medium, 'rule'), 0, 4));
        $via = $v['layers'] > 0 ? (' · 解码链 ' . implode('→', $v['via'])) : '';
        dnaLog($p, $high !== [] ? 'malicious' : 'tamper', $rel,
            sprintf('内容变更 · 级别 %s · 规则 [%s]%s%s',
                $high !== [] ? '高置信' : ($medium !== [] ? '中置信' : '无命中'),
                $rules ?: '—', $via, $apply ? '' : ' · 只读未处置'), $recent);

        if (!$apply || !$sigOK) { continue; }   // 只读或签名不可信，到此为止

        if ($high !== []) {
            // 高置信：先精准手术，术后复扫自校验，失败才整体还原
            $done = false;
            if ($doSurgery) {
                [$ok, $after] = dnaSurgery($code, $high, $rel);
                if ($ok) {
                    @copy($abs, dnaArtifact($p, 'surgery', $rel, '.before'));
                    if (@file_put_contents($abs, $after, LOCK_EX) !== false) {
                        @chmod($abs, (int)($entry['perm'] ?? 0644));
                        @copy($abs, dnaArtifact($p, 'surgery', $rel, '.after'));
                        dnaLog($p, 'surgery', $rel, '精准手术完成：恶意语句已切除，术后复扫无高置信残留', $recent);
                        dnaBump($c, 'surgery'); $done = true;
                    }
                } else {
                    dnaLog($p, 'surgery_fail', $rel, '术后复扫仍有高置信结构，改走整体还原', $recent);
                }
            }
            if (!$done) { dnaRestoreOne($p, $rel, $entry, $recent, $c); }
            // 处置后的内容仍是「基线外状态」，记入节流，避免下一轮把它当新变更再报
            $afterHash = @hash_file('sha256', $abs);
            if ($afterHash !== false) { $c['reported'][$rel] = $afterHash; }
        } elseif ($restoreAny) {
            // 显式 --restore-any 才还原「无恶意特征」的普通变更（默认不动，避免误伤运维）
            dnaRestoreOne($p, $rel, $entry, $recent, $c);
        }
    }

    // 2) 新文件：落地即扫，高置信直接隔离
    foreach ($now as $rel => $abs) {
        if (isset($base[$rel])) { continue; }
        $nNew++; dnaBump($c, 'new_files'); dnaBump($c, 'events');
        $code = (string)@file_get_contents($abs);
        $v = dnaVerdict($code);
        if ($v['high'] !== []) {
            dnaBump($c, 'high'); dnaBump($c, 'quarantine'); $nHigh++;
            @copy($abs, dnaArtifact($p, 'quarantine', $rel));
            dnaLog($p, 'new_malicious', $rel, '新文件命中高置信后门：' . implode(',', array_column($v['high'], 'rule')), $recent);
            if ($apply) {
                @unlink($abs);
                dnaLog($p, 'quarantined', $rel, '已从站点目录移走，副本存 quarantine/', $recent);
            }
        } else {
            dnaLog($p, 'new_file', $rel, '发现新文件（' . ($v['medium'] !== [] ? '中置信特征，仅告警' : '未检出恶意') . '）', $recent);
            if ($adoptNew) {
                $bak = dnaBackupPath($p, $rel);
                @mkdir(dirname($bak), 0700, true);
                if (@copy($abs, $bak)) {
                    $base[$rel] = ['hash' => @hash_file('sha256', $abs),
                                   'backup_hash' => @hash_file('sha256', $bak),
                                   'perm' => @fileperms($abs) & 0777,
                                   'size' => @filesize($abs), 'mtime' => @filemtime($abs)];
                    dnaSaveBaseline($p, $base);
                    dnaLog($p, 'adopted', $rel, '已按 --adopt-new 纳入基线并重签', $recent);
                }
            }
        }
    }

    dnaSaveCounters($p, $c);
    dnaWriteStatus($p, $o, $base, $c, $sigOK, $lastError, $nHigh);
    echo sprintf("OK scan: 建档 %d · 完好 %d · 已知变更 %d · 本轮变更 %d（高置信 %d / 中置信 %d）· 新增 %d · 缺失 %d · 基线签名 %s · 模式 %s\n",
        count($base), $nOK, $nKnown, $nTamper, $nHigh, $nMedium, $nNew, $nMissing,
        $sigOK ? '通过' : '不可信', $apply ? '处置' : '只读');
    return 0;
}

function dnaCmdRestore(array $p, array $o): int {
    $rel = (string)($o['file'] ?? '');
    if ($rel === '') { fwrite(STDERR, "用法：php dna.php restore --file=相对路径\n"); return 2; }
    [$ok, , $base] = dnaLoadBaseline($p);
    if (!$ok || !isset($base[$rel])) { fwrite(STDERR, "[DNA] 基线签名不可信或文件不在基线中\n"); return 2; }
    $recent = []; $c = dnaCounters($p);
    $r = dnaRestoreOne($p, $rel, $base[$rel], $recent, $c);
    dnaSaveCounters($p, $c);
    echo $r ? "OK restored: $rel\n" : "FAILED restored: $rel（备份缺失或被污染）\n";
    return $r ? 0 : 1;
}

function dnaCmdStatus(array $p): int {
    $d = dnaLoadStatus($p);
    if ($d === []) { echo json_encode(['error' => '暂无状态快照，请先执行 baseline / scan'], JSON_UNESCAPED_UNICODE) . "\n"; return 1; }
    $age = time() - (int)($d['last_check'] ?? 0);
    $d['age_seconds'] = $age;
    $d['alive'] = $age <= DNA_STATUS_STALE;
    echo json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
    return 0;
}

function dnaCmdSelftest(): int {
    $pass = 0; $fail = 0;
    $check = function (string $name, bool $ok) use (&$pass, &$fail): void {
        if ($ok) { $pass++; echo "  PASS  $name\n"; }
        else     { $fail++; echo "  FAIL  $name\n"; }
    };
    // 后门样本一律用 base64 在运行时还原：源码里不落任何可直接利用的木马字面，
    // 也避免 PHP 词法器 / 内容审计把测试语料当成真实载荷。
    $B = fn(string $s) => (string)base64_decode($s, true);
    echo "DNA 能力自检（不写任何文件）\n";

    $highCases = [
        'eval + base64 编码链'  => $B('PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCJjM2x6ZEdWdEtDUmZSMFZVV3lKaklsMHBPdz09IikpOw=='),
        'system 直吃请求参数'   => $B('PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOw=='),
        '变量函数吃请求参数'    => $B('PD9waHAgJGY9JF9HRVRbImYiXTsgJGYoJF9QT1NUWyJ4Il0pOw=='),
        'include 吃请求参数'    => $B('PD9waHAgaW5jbHVkZSgkX1JFUVVFU1RbInAiXSk7'),
        '尾部埋马（闭合后重开）' => $B('PD9waHAgZWNobyAxOyA/Pjw/cGhwIEBldmFsKCRfUE9TVFsieCJdKTs='),
        '反引号带请求参数'      => $B('PD9waHAgJHggPSBgY3VybCAkX0dFVFsidSJdYDs='),
        'assert 变量当代码'     => $B('PD9waHAgYXNzZXJ0KCR4KCRfR0VUWyJjIl0pKTs='),
        '超长变量变量'          => '<?php $x = ${"' . str_repeat('a', 130) . '"};',
    ];
    foreach ($highCases as $name => $code) {
        $v = dnaVerdict($code);
        $check('高置信 · ' . $name, $v['high'] !== []);
    }

    // 解码链：一句话木马套两层 base64，验证能剥开并升级
    $nested = $B('PD9waHAgZXZhbChiYXNlNjRfZGVjb2RlKCJaWFpoYkNoaVlYTmxOalJmWkdWamIyUmxLQ0pqTTJ4NlpFZFdkRXREVW1aU01GWlZWM2xLYWtsc01IQlBkejA5SWlrcE93PT0iKSk7');
    $v = dnaVerdict($nested);
    $check('递归解码链（2 层 base64）能剥出执行点', $v['layers'] >= 1);
    $check('解码后命中升级为高置信', $v['high'] !== []);

    $mediumCases = [
        '普通 system 调用（插件合法写法）' => $B('PD9waHAgc3lzdGVtKCJscyAtbGEiKTs='),
        'chr 拼接 ASCII 表'               => $B('PD9waHAgJHMgPSBjaHIoNjUpLmNocig2NikuY2hyKDY3KS5jaHIoNjgpOw=='),
        '超长十六进制转义常量表'           => '<?php $s = "' . str_repeat('\x41', 24) . '";',
        'include 变量（框架常见）'         => $B('PD9waHAgaW5jbHVkZSAkdHBsOw=='),
        '干净业务代码'                     => $B('PD9waHAgZnVuY3Rpb24gYWRkKCRhLCRiKXsgcmV0dXJuICRhKyRiOyB9IGVjaG8gYWRkKDEsMik7'),
    ];
    foreach ($mediumCases as $name => $code) {
        $v = dnaVerdict($code);
        $check('不得升级高置信 · ' . $name, $v['high'] === []);
    }

    // 签名自证：HMAC 能验真、基线改一个字节即验伪
    $key = bin2hex(random_bytes(16));
    $raw = '{"v":3,"files":{"a.php":{"hash":"abc"}}}';
    $sig = dnaSign($key, $raw);
    $check('HMAC-SHA256 验真', hash_equals($sig, dnaSign($key, $raw)));
    $check('基线被改一个字节即验伪', !hash_equals($sig, dnaSign($key, $raw . ' ')));

    // 手术：切除恶意行后复扫应无高置信残留，且正常语句保留
    $bad = $B('PD9waHAKZWNobyAnb2snOwpzeXN0ZW0oJF9HRVRbJ2MnXSk7CmVjaG8gJ2RvbmUnOwo=');
    $hv = dnaVerdict($bad);
    [$ok, $after] = dnaSurgery($bad, $hv['high'], 'x.php');
    $check('精准手术后复扫无高置信残留', $ok && dnaVerdict($after)['high'] === []);
    $check('手术保留原有正常语句', $ok && str_contains($after, "echo 'ok';"));

    echo sprintf("\nSELFTEST %s (%d/%d)\n", $fail === 0 ? 'PASS' : 'FAIL', $pass, $pass + $fail);
    return $fail === 0 ? 0 : 1;
}

/* ------------------------------------------------------------------- 入口 */

$o = dnaOpts($argv);
$p = dnaPaths($o);
$ex = dnaExcludes($o);
$cmd = $o['cmd'];

switch ($cmd) {
    case 'plan':       exit(dnaCmdPlan($p, $o, $ex));
    case 'baseline':   exit(dnaCmdBaseline($p, $o, $ex, false));
    case 'rebaseline': exit(dnaCmdBaseline($p, $o, $ex, true));
    case 'scan':       exit(dnaCmdScan($p, $o, $ex));
    case 'audit':      $o['apply'] = false; exit(dnaCmdScan($p, $o, $ex));
    case 'restore':    exit(dnaCmdRestore($p, $o));
    case 'status':     exit(dnaCmdStatus($p));
    case 'selftest':   exit(dnaCmdSelftest());
    case 'watch':
        fwrite(STDERR, "[DNA] 轮询守护启动：间隔 {$p['interval']}s · 模式 " . (empty($o['apply']) ? '只读' : '处置') . " · Ctrl+C 退出\n");
        while (true) {
            dnaCmdScan($p, $o, $ex);
            sleep($p['interval']);
        }
    default:
        fwrite(STDERR, "YSL语枢-盾甲WAF 文件 DNA v" . DNA_VER . "\n");
        fwrite(STDERR, "用法: php dna.php <plan|baseline|scan|audit|rebaseline|restore|status|selftest|watch> [--root=...] [--apply] [--no-surgery] [--restore-any] [--adopt-new] [--interval=30]\n");
        exit(2);
}
