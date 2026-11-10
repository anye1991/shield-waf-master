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
 * YSL语枢-盾甲WAF · 运行时配置与控制面共享层
 *
 * 背景：原版所有开关都是「进程启动时读环境变量」，Web 请求无法改变已启动进程的环境。
 * 为了让大屏控制按钮真能生效，引入一份持久化的运行时覆盖：
 *   var/data/runtime.json —— 每请求由入口读取并应用到 config / putenv / 常量。
 * 文件不存在时完全等价于旧版（默认值取自环境变量），不写任何文件。
 *
 * 安全：只有白名单字段会被接受；IP/CIDR 严格校验；原子写 + 0600。
 * 控制审计单独写 logs/ysl/control.log，不进 attack.log，避免污染大屏指标。
 */
declare(strict_types=1);

// QPS 接入层的默认值与状态工具；require_once 避免 phar / 源码多入口重复定义常量
require_once __DIR__ . '/qps.php';
// 中文展示层：所有面向用户的状态 / 原因 / 命令枚举映射集中在这里
require_once __DIR__ . '/i18n.php';

function wafRtPath(string $home): string {
    return rtrim(str_replace('\\', '/', $home), '/') . '/var/data/runtime.json';
}

function wafRtDefaults(): array {
    // 入口每请求会 putenv 覆盖运行时开关，直接用 getenv() 会让「恢复出厂」
    // 变成「恢复成当前值」。优先使用入口在 putenv 之前冻结的启动环境快照。
    $env = defined('WAF_ENV_DEFAULTS') && is_array(WAF_ENV_DEFAULTS) ? WAF_ENV_DEFAULTS : [
        'mode'      => getenv('WAF_MODE') ?: 'enforce',
        'ai'        => getenv('WAF_AI_ENABLED') !== '0',
        'fp'        => getenv('WAF_FP_GUARD') !== '0',
        'tautology' => getenv('WAF_TAUTOLOGY_GUARD') !== '0',
        'bypass'    => getenv('WAF_BYPASS_GUARD') !== '0',
        'errors'    => getenv('WAF_KEEP_DISPLAY_ERRORS') === '1',
        'honeypot'  => getenv('WAF_HONEYPOT_ENABLED') === '1',
    ];
    $mode = strtolower((string)($env['mode'] ?? 'enforce'));
    return [
        'version'    => 1,
        'mode'       => $mode === 'observe' ? 'observe' : 'enforce',
        'guards'     => [
            'ai'        => (bool)($env['ai'] ?? true),
            'fp'        => (bool)($env['fp'] ?? true),
            'tautology' => (bool)($env['tautology'] ?? true),
            'bypass'    => (bool)($env['bypass'] ?? true),
            'errors'    => (bool)($env['errors'] ?? false),
        ],
        'body_max'   => 8388608,
        'whitelist'  => [],
        // v6.4.0：接入层 QPS 限流 / 熔断配置，控制台可实时改
        'qps'        => wafQpsDefaults(),
        // v6.5.0：蜜罐是高危主动诱捕（延迟响应 / 假数据 / 触碰即标记确认恶意），
        // 默认停用。必须由控制端点显式启用，且带确认短语、有效期与审批留痕。
        'honeypot'   => [
            'enabled'    => (bool)($env['honeypot'] ?? false),
            'until'      => 0,          // 自动停用时刻（Unix 秒，0 = 不限时）
            'enabled_at' => 0,
            'by'         => '',
            'reason'     => '',
        ],
        'updated_at' => '',
        'updated_by' => '',
    ];
}

/**
 * 蜜罐有效期硬上限：最长 4 小时，到期后入口自动写回停用，
 * 避免「演练完忘记关」让诱捕逻辑长期挂在生产请求上。
 */
function wafHpMaxMinutes(): int { return 240; }

/**
 * 蜜罐触碰次数：优先读 YslHoneypot 真实写入的 honeypot/hits_*.jsonl。
 * 内核的 attack.log 里 honeypot 字段恒为 false（审计汇总只认 hit 键，
 * 而 activateHoneyPot 写的是 active/delay/fake_response），所以不能用它计数。
 * 老版本若把命中写进 attack.log，则在 hits 文件为空时回退兼容。
 * 运行目录与持久归档可能挂成同一份文件，用 inode 去重避免双倍计数。
 */
function wafHpHits(string $yslDir, string $fallback): int {
    $n = 0; $seen = [];
    foreach ([$yslDir . '/honeypot', $fallback . '/honeypot'] as $dir) {
        foreach (glob($dir . '/hits_*.jsonl') ?: [] as $f) {
            if (!is_file($f)) { continue; }
            $ino = @fileinode($f);
            if ($ino !== false && isset($seen[$ino])) { continue; }
            if ($ino !== false) { $seen[$ino] = true; }
            $n += count(@file($f, FILE_SKIP_EMPTY_LINES) ?: []);
        }
    }
    if ($n > 0) { return $n; }
    // 兼容旧格式：attack.log 里 honeypot 为对象或 true
    foreach ([$yslDir . '/attack.log', $fallback . '/attack.log'] as $f) {
        if (!is_file($f)) { continue; }
        $ino = @fileinode($f);
        if ($ino !== false && isset($seen[$ino])) { continue; }
        if ($ino !== false) { $seen[$ino] = true; }
        $fh = @fopen($f, 'rb');
        if (!$fh) { continue; }
        $size = (int)@filesize($f);
        if ($size > 524288) { @fseek($fh, -524288, SEEK_END); @fgets($fh); }
        while (($line = fgets($fh)) !== false) {
            if (str_contains($line, '"honeypot":true') || str_contains($line, '"honeypot":{"')) { $n++; }
        }
        @fclose($fh);
    }
    return $n;
}

/** 把蜜罐状态归一化为可展示的结构（中文由 i18n 层负责） */
function wafHpView(array $rt): array {
    $h = $rt['honeypot'] ?? [];
    $enabled = !empty($h['enabled']);
    $until   = (int)($h['until'] ?? 0);
    $left    = ($enabled && $until > 0) ? max(0, $until - time()) : 0;
    return [
        'enabled'    => $enabled,
        'until'      => $until,
        'left'       => $left,
        'enabled_at' => (int)($h['enabled_at'] ?? 0),
        'by'         => (string)($h['by'] ?? ''),
        'reason'     => (string)($h['reason'] ?? ''),
        'timed'      => $until > 0,
    ];
}

/** IP 或 CIDR，IPv4 / IPv6 均可；拒绝任何非地址内容 */
function wafRtValidCidr(string $s): bool {
    $s = trim($s);
    if ($s === '' || strlen($s) > 64 || !preg_match('#^[0-9a-fA-F:.]+(?:/\d{1,3})?$#', $s)) {
        return false;
    }
    if (str_contains($s, '/')) {
        [$ip, $mask] = explode('/', $s, 2);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !ctype_digit($mask)) {
            return false;
        }
        $max = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 32 : 128;
        return (int)$mask >= 0 && (int)$mask <= $max;
    }
    return filter_var($s, FILTER_VALIDATE_IP) !== false;
}

function wafRtRead(string $home): array {
    $d = wafRtDefaults();
    $f = wafRtPath($home);
    if (!is_file($f)) {
        return $d;
    }
    $j = json_decode((string)@file_get_contents($f), true);
    if (!is_array($j)) {
        return $d;
    }
    if (isset($j['mode']) && in_array($j['mode'], ['enforce', 'observe'], true)) {
        $d['mode'] = $j['mode'];
    }
    if (isset($j['guards']) && is_array($j['guards'])) {
        foreach (array_keys($d['guards']) as $g) {
            if (array_key_exists($g, $j['guards'])) {
                $d['guards'][$g] = (bool)$j['guards'][$g];
            }
        }
    }
    if (isset($j['body_max'])) {
        $n = (int)$j['body_max'];
        if ($n >= 1 && $n <= 67108864) {
            $d['body_max'] = $n;
        }
    }
    if (isset($j['whitelist']) && is_array($j['whitelist'])) {
        $w = [];
        foreach ($j['whitelist'] as $cidr) {
            if (is_string($cidr) && wafRtValidCidr($cidr)) {
                $w[] = trim($cidr);
            }
        }
        $d['whitelist'] = array_values(array_unique($w));
    }
    // QPS 段：逐字段范围校验，非法值一律回落默认，避免把限流关死或卡死熔断
    if (isset($j['qps']) && is_array($j['qps'])) {
        $q = $j['qps'];
        $d['qps']['enabled'] = (bool)($q['enabled'] ?? true);
        foreach (['soft' => [1, 1000000], 'hard' => [1, 1000000],
                  'ip_soft' => [1, 1000000], 'ip_hard' => [1, 1000000],
                  'cooldown' => [3, 3600]] as $k => $range) {
            if (isset($q[$k])) {
                $n = (int)$q[$k];
                if ($n >= $range[0] && $n <= $range[1]) { $d['qps'][$k] = $n; }
            }
        }
        if ($d['qps']['hard'] < $d['qps']['soft'])         { $d['qps']['hard'] = $d['qps']['soft']; }
        if ($d['qps']['ip_hard'] < $d['qps']['ip_soft'])   { $d['qps']['ip_hard'] = $d['qps']['ip_soft']; }
    }
    // 蜜罐段：只认控制端点写出的白名单字段；已过有效期一律按停用处理，
    // 入口随后会原子写回落盘，杜绝「页面显示已停用、内核还在诱捕」。
    if (isset($j['honeypot']) && is_array($j['honeypot'])) {
        $h = $j['honeypot'];
        $until = (int)($h['until'] ?? 0);
        $expired = $until > 0 && time() >= $until;
        $d['honeypot'] = [
            'enabled'    => !empty($h['enabled']) && !$expired,
            'until'      => $expired ? 0 : $until,
            'enabled_at' => (int)($h['enabled_at'] ?? 0),
            'by'         => substr((string)($h['by'] ?? ''), 0, 64),
            'reason'     => substr((string)($h['reason'] ?? ''), 0, 120),
        ];
    }
    $d['updated_at'] = (string)($j['updated_at'] ?? '');
    $d['updated_by'] = (string)($j['updated_by'] ?? '');
    return $d;
}

function wafRtWrite(string $home, array $d): bool {
    $f   = wafRtPath($home);
    $dir = dirname($f);
    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
        return false;
    }
    $d['version']    = 1;
    $d['updated_at'] = gmdate('c');
    $d['updated_by'] = 'waf-control';
    $json = json_encode($d, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($json === false) {
        return false;
    }
    $tmp = $f . '.tmp.' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
        return false;
    }
    @chmod($tmp, 0600);
    if (!@rename($tmp, $f)) {
        @unlink($tmp);
        return false;
    }
    @chmod($f, 0600);
    return true;
}

/** 控制台密钥：运行目录（可能是 tmpfs）优先，回退站点持久目录 */
function wafCtlKeyFile(string $home, string $dataDir): string {
    $a = rtrim(str_replace('\\', '/', $dataDir), '/') . '/console.key';
    $b = rtrim(str_replace('\\', '/', $home), '/') . '/var/data/console.key';
    if (is_file($a)) { return $a; }
    if (is_file($b)) { return $b; }
    return $a;
}

/**
 * 无状态 CSRF：token = HMAC(key, 当前小时时间片)。
 * 攻击者拿不到 key 就算不出 token；服务端接受当前与前一时间片，避免整点边界失效。
 * 静态快照不输出 key / token，因此离线 HTML 天然无法发起控制请求。
 */
function wafCtlToken(string $key, ?int $slot = null): string {
    $slot = $slot ?? (int)floor(time() / 3600);
    return hash_hmac('sha256', 'waf-control|' . $slot, $key);
}

function wafCtlVerify(string $key, string $token): bool {
    if ($token === '') {
        return false;
    }
    $now = (int)floor(time() / 3600);
    foreach ([$now, $now - 1] as $slot) {
        if (hash_equals(wafCtlToken($key, $slot), $token)) {
            return true;
        }
    }
    return false;
}

function wafCtlLogPath(string $home): string {
    return rtrim(str_replace('\\', '/', $home), '/') . '/logs/ysl/control.log';
}

function wafCtlLog(string $home, string $action, bool $ok, string $detail): void {
    $f   = wafCtlLogPath($home);
    $dir = dirname($f);
    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
        return;
    }
    $entry = [
        't'      => gmdate('c'),
        'action' => $action,
        'ok'     => $ok,
        'detail' => mb_substr($detail, 0, 300),
        'ip'     => substr(hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? '')), 0, 12),
        'ua'     => substr(hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 12),
    ];
    @file_put_contents($f,
        json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n",
        FILE_APPEND | LOCK_EX);
}

function wafCtlWatchPidFile(string $home): string {
    return rtrim(str_replace('\\', '/', $home), '/') . '/var/data/dna-watch.pid';
}
function wafCtlWatchScan(): ?int {
    foreach (glob('/proc/[0-9]*/cmdline') ?: [] as $f) {
        $c = @file_get_contents($f);
        if ($c === false) { continue; }
        $c = str_replace("\0", ' ', $c);
        // 只认 php 进程本身：docker exec -d 会留下一个 sh -lc 外壳，
        // 它的 cmdline 也含 "dna.php watch"，杀它并不会停掉守护。
        $parts = preg_split('/\s+/', trim($c)) ?: [];
        $bin   = basename((string)($parts[0] ?? ''));
        if ($bin !== 'php' && !str_starts_with($bin, 'php')) { continue; }
        if (str_contains($c, 'dna.php watch') && str_contains($c, '--root=')) {
            return (int)basename(dirname($f));
        }
    }
    return null;
}
function wafCtlWatchAlive(int $pid): bool {
    if ($pid < 2) { return false; }
    $c = @file_get_contents('/proc/' . $pid . '/cmdline');
    if ($c === false) { return false; }
    $c = str_replace("\0", ' ', $c);
    $parts = preg_split('/\s+/', trim($c)) ?: [];
    $bin   = basename((string)($parts[0] ?? ''));
    return ($bin === 'php' || str_starts_with($bin, 'php'))
        && str_contains($c, 'dna.php watch');
}
/** 优先读 PID 文件；文件失效时扫描 /proc 把已存在的守护纳入管理 */
function wafCtlWatchPid(string $home): ?int {
    $f = wafCtlWatchPidFile($home);
    if (is_file($f)) {
        $pid = (int)trim((string)@file_get_contents($f));
        if (wafCtlWatchAlive($pid)) { return $pid; }
        @unlink($f);
    }
    $found = wafCtlWatchScan();
    if ($found !== null) {
        @file_put_contents($f, (string)$found, LOCK_EX);
        return $found;
    }
    return null;
}

function wafCtlRecent(string $home, int $limit = 12): array {
    $f = wafCtlLogPath($home);
    if (!is_file($f)) { return []; }
    $lines = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $out = [];
    foreach (array_slice(array_reverse($lines), 0, $limit) as $line) {
        $j = json_decode($line, true);
        if (!is_array($j)) { continue; }
        // 只做「展示归一化」：control.log 原文保留英文枚举，读取时补中文视图。
        // 历史记录（中文化之前写入）也能显示中文，不篡改审计日志。
        $j['detail_cn'] = wafCnAuditDetail((string)($j['detail'] ?? ''));
        $j['action_cn'] = wafCnAction((string)($j['action'] ?? ''));
        $out[] = $j;
    }
    return $out;
}
