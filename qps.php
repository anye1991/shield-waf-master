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
 * YSL语枢-盾甲WAF · 接入层 QPS 限流与熔断（v6.4.0）
 *
 * 为什么需要这一层：
 *   内核 core/YslCircuitBreaker.php 的滑动窗口 $requestTimestamps 是「对象实例属性」。
 *   PHP 每个 Web 请求都会重新 new YslCircuitBreaker，静态属性与实例属性全部重建，
 *   于是窗口计数恒为 0/1 —— 代码里写了四档降级，跨请求却永远累加不起来。
 *   实测 circuit_state.json 长期是 qps:0 / total_requests:1，自动熔断从未被触发，
 *   只有控制端点手工写 open 才有效。core/ 是封存原版，禁止改动，因此在外壳补一层
 *   真实生效的接入层限流，内核自带的 breaker 仍作为内核内部降级信号保留。
 *
 * 实现：
 *   - flock 独占锁 + 单个小状态文件，10 个 100ms 桶组成 1 秒滑动窗口（O(1)，不存大数组）
 *   - 全局 QPS 与单 IP QPS 双维度；IP 只存 sha256 前 12 位哈希，不落明文
 *   - 软阈值 → 429 限流；硬阈值 → 502 熔断；冷却结束后半开试探，成功自动恢复
 *   - 管理路由（大屏 / 控制台 / 控制端点）在入口分发时已 exit，天然豁免，不会把自己熔断
 *   - 配置来自 var/data/runtime.json 的 qps 段，控制台可实时改，下一个请求立即生效
 *
 * 状态码语义（与美化页 pages.php 一致）：
 *   429 = 频率超限但仍可用（Retry-After 短）
 *   502 = 保护性熔断，节点降级（Retry-After = 剩余冷却）
 */
declare(strict_types=1);

const WAF_QPS_SLOTS = 10;      // 10 个桶
const WAF_QPS_SLOT_MS = 100;   // 每桶 100ms → 窗口 1000ms

function wafQpsDefaults(): array {
    return [
        'enabled'   => true,
        'soft'      => 300,    // 全局 QPS 软阈值 → 429
        'hard'      => 600,    // 全局 QPS 硬阈值 → 502
        'ip_soft'   => 80,     // 单 IP QPS 软阈值 → 429
        'ip_hard'   => 160,    // 单 IP QPS 硬阈值 → 502
        'cooldown'  => 30,     // 熔断冷却秒
        'window_ms' => 1000,
    ];
}

/** 从运行时配置里取 qps 段，逐字段范围校验，杜绝非法值把限流关死或卡死 */
function wafQpsConfig(array $rt): array {
    $d = wafQpsDefaults();
    $q = isset($rt['qps']) && is_array($rt['qps']) ? $rt['qps'] : [];
    $d['enabled'] = (bool)($q['enabled'] ?? true);
    $int = static function (string $k, int $min, int $max) use ($q, $d): int {
        if (!array_key_exists($k, $q)) { return (int)$d[$k]; }
        $n = (int)$q[$k];
        return ($n >= $min && $n <= $max) ? $n : (int)$d[$k];
    };
    $d['soft']      = $int('soft', 1, 1000000);
    $d['hard']      = $int('hard', 1, 1000000);
    $d['ip_soft']   = $int('ip_soft', 1, 1000000);
    $d['ip_hard']   = $int('ip_hard', 1, 1000000);
    $d['cooldown']  = $int('cooldown', 3, 3600);
    $d['window_ms'] = 1000;  // 当前实现固定 1s 窗口，保留字段便于将来扩展
    if ($d['hard'] < $d['soft'])     { $d['hard'] = $d['soft']; }
    if ($d['ip_hard'] < $d['ip_soft']) { $d['ip_hard'] = $d['ip_soft']; }
    return $d;
}

function wafQpsStateFile(string $logDir): string {
    return rtrim(str_replace('\\', '/', $logDir), '/') . '/ysl/qps_state.json';
}

/** 读状态候选路径：运行目录（常为 tmpfs）优先，持久归档目录兜底 */
function wafQpsStateFiles(string $logDir, string $home = ''): array {
    $out = [wafQpsStateFile($logDir)];
    if ($home !== '') {
        $out[] = rtrim(str_replace('\\', '/', $home), '/') . '/logs/ysl/qps_state.json';
    }
    return array_values(array_unique(array_filter($out)));
}

function wafQpsWindowNew(): array {
    return ['slot' => 0, 'b' => array_fill(0, WAF_QPS_SLOTS, 0),
            'qps' => 0, 'peak' => 0, 'total' => 0, 'last' => 0];
}

function wafQpsStateNew(): array {
    return [
        'ver' => 1, 'global' => wafQpsWindowNew(), 'ips' => [],
        'state' => 'closed', 'opened_at' => 0, 'reason' => '', 'scope' => '',
        'probe_ok' => 0, 'rejects' => 0, 'last_429' => 0, 'last_502' => 0,
        'updated_at' => time(),
    ];
}

/** 推进滑动窗口并给指定桶 +1；返回窗口内的真实 QPS */
function wafQpsTick(array &$w, int $slotNo, int $now): int {
    if (!isset($w['b']) || !is_array($w['b']) || count($w['b']) !== WAF_QPS_SLOTS) {
        $w = wafQpsWindowNew();
    }
    $cur = (int)($w['slot'] ?? 0);
    if ($cur === 0) { $cur = $slotNo; }
    $delta = $slotNo - $cur;
    if ($delta > 0) {
        if ($delta >= WAF_QPS_SLOTS) {
            $w['b'] = array_fill(0, WAF_QPS_SLOTS, 0);
        } else {
            for ($i = 1; $i <= $delta; $i++) {
                $w['b'][($cur + $i) % WAF_QPS_SLOTS] = 0;
            }
        }
    } elseif ($delta < 0) {
        // 时钟回拨：丢弃整个窗口，避免旧桶污染计数
        $w['b'] = array_fill(0, WAF_QPS_SLOTS, 0);
    }
    $w['slot'] = $slotNo;
    $idx = $slotNo % WAF_QPS_SLOTS;
    $w['b'][$idx] = (int)($w['b'][$idx] ?? 0) + 1;
    $q = (int)array_sum($w['b']);
    $w['qps']   = $q;
    $w['total'] = (int)($w['total'] ?? 0) + 1;
    $w['peak']  = max((int)($w['peak'] ?? 0), $q);
    $w['last']  = $now;
    return $q;
}

/** 只读快照，供大屏 / 控制台 / JSON 接口展示，不修改任何状态 */
function wafQpsSnapshot(string $logDir, array $cfg, string $home = ''): array {
    $s = wafQpsStateNew();
    foreach (wafQpsStateFiles($logDir, $home) as $f) {
        if (!is_file($f)) { continue; }
        $j = json_decode((string)@file_get_contents($f), true);
        if (is_array($j) && isset($j['global'])) { $s = array_merge($s, $j); break; }
    }
    $now = time();
    $g   = is_array($s['global'] ?? null) ? $s['global'] : wafQpsWindowNew();
    $open = (string)($s['state'] ?? 'closed') === 'open';
    $until = $open ? max(0, (int)$cfg['cooldown'] - ($now - (int)($s['opened_at'] ?? 0))) : 0;
    // 展示用的「当前 QPS」对过期窗口做衰减，避免停流量后仍显示旧峰值
    $stale = $now - (int)($g['last'] ?? 0) > 2;
    return [
        'enabled'   => (bool)$cfg['enabled'],
        'state'     => (string)($s['state'] ?? 'closed'),
        'reason'    => (string)($s['reason'] ?? ''),
        'scope'     => (string)($s['scope'] ?? ''),
        'qps'       => $stale ? 0 : (int)($g['qps'] ?? 0),
        'peak'      => (int)($g['peak'] ?? 0),
        'total'     => (int)($g['total'] ?? 0),
        'ip_qps'    => 0,
        'ip_tracked'=> count(is_array($s['ips'] ?? null) ? $s['ips'] : []),
        'rejects'   => (int)($s['rejects'] ?? 0),
        'last_429'  => (int)($s['last_429'] ?? 0),
        'last_502'  => (int)($s['last_502'] ?? 0),
        'cooldown'  => (int)$cfg['cooldown'],
        'retry_left'=> $until,
        'soft'      => (int)$cfg['soft'],
        'hard'      => (int)$cfg['hard'],
        'ip_soft'   => (int)$cfg['ip_soft'],
        'ip_hard'   => (int)$cfg['ip_hard'],
        'updated_at'=> (int)($s['updated_at'] ?? 0),
    ];
}

/**
 * 管理动作：reset（清计数并复位）/ open（演练熔断）/ close（强制恢复）。
 * 写主状态文件 + 持久回退目录，保证 tmpfs 与持久部署都能读到同一状态。
 */
function wafQpsAdmin(string $logDir, string $home, string $op, array $cfg): array {
    $files = wafQpsStateFiles($logDir, $home);
    $base  = wafQpsStateNew();
    if ($op === 'reset') {
        $s = $base;
    } else {
        $s = $base;
        foreach ($files as $f) {
            if (!is_file($f)) { continue; }
            $j = json_decode((string)@file_get_contents($f), true);
            if (is_array($j) && isset($j['global'])) { $s = array_merge($s, $j); break; }
        }
        if ($op === 'open') {
            $s['state'] = 'open'; $s['opened_at'] = time(); $s['reason'] = 'manual_drill';
            $s['scope'] = 'manual'; $s['probe_ok'] = 0;
        } else {
            $s['state'] = 'closed'; $s['opened_at'] = 0; $s['reason'] = '';
            $s['scope'] = ''; $s['probe_ok'] = 0;
        }
    }
    $s['updated_at'] = time();
    $json = json_encode($s, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    $written = [];
    foreach ($files as $f) {
        $dir = dirname($f);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) { continue; }
        $tmp = $f . '.tmp.' . bin2hex(random_bytes(3));
        if (@file_put_contents($tmp, $json, LOCK_EX) !== false && @rename($tmp, $f)) {
            $written[] = $f;
        } else {
            @unlink($tmp);
        }
    }
    $snap = wafQpsSnapshot($logDir, $cfg, $home);
    return ['ok' => $written !== [] && $snap['state'] === ($op === 'open' ? 'open' : 'closed'),
            'written' => $written, 'snapshot' => $snap];
}

/**
 * 主入口：每请求调用一次。返回 ['block'=>bool, 'code'=>int, ...真实数据]。
 * 不抛异常：状态文件不可写时 fail-open（记 error_log），绝不因为限流模块把站点打挂。
 */
function wafQpsGuard(string $logDir, array $cfg, string $home = ''): array {
    $now   = time();
    $file  = wafQpsStateFile($logDir);
    $dir   = dirname($file);
    $pass  = static function (array $s, int $g, int $ip, string $state = '') use ($cfg): array {
        return [
            'block' => false, 'code' => 200, 'state' => $state ?: (string)($s['state'] ?? 'closed'),
            'qps' => $g, 'ip_qps' => $ip, 'peak' => (int)($s['global']['peak'] ?? 0),
            'total' => (int)($s['global']['total'] ?? 0), 'rejects' => (int)($s['rejects'] ?? 0),
            'soft' => (int)$cfg['soft'], 'hard' => (int)$cfg['hard'],
            'ip_soft' => (int)$cfg['ip_soft'], 'ip_hard' => (int)$cfg['ip_hard'],
            'cooldown' => (int)$cfg['cooldown'], 'retry_after' => 0,
            'reason' => '', 'scope' => '',
        ];
    };

    if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
        error_log('[ShieldWAF][QPS] state dir unavailable, fail-open: ' . $dir);
        return $pass(wafQpsStateNew(), 0, 0, 'closed');
    }
    $fh = @fopen($file, 'c+');
    if ($fh === false) {
        error_log('[ShieldWAF][QPS] state file unwritable, fail-open: ' . $file);
        return $pass(wafQpsStateNew(), 0, 0, 'closed');
    }
    if (!@flock($fh, LOCK_EX)) {
        @fclose($fh);
        return $pass(wafQpsStateNew(), 0, 0, 'closed');
    }

    $raw = '';
    rewind($fh);
    while (!feof($fh)) { $raw .= (string)fread($fh, 8192); }
    $j = json_decode($raw, true);
    $s = (is_array($j) && isset($j['global'])) ? array_merge(wafQpsStateNew(), $j) : wafQpsStateNew();
    if (!is_array($s['ips'])) { $s['ips'] = []; }

    $slotNo = intdiv((int)round(microtime(true) * 1000), WAF_QPS_SLOT_MS);
    $gQps   = wafQpsTick($s['global'], $slotNo, $now);

    $ipRaw = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $ipKey = substr(hash('sha256', $ipRaw), 0, 12);
    if (!isset($s['ips'][$ipKey]) || !is_array($s['ips'][$ipKey])) {
        $s['ips'][$ipKey] = wafQpsWindowNew();
    }
    $ipQps = wafQpsTick($s['ips'][$ipKey], $slotNo, $now);
    // 只保留最近 60 秒活跃的 IP，最多 128 个，避免状态文件无限膨胀
    foreach ($s['ips'] as $k => $w) {
        if (!is_array($w) || $now - (int)($w['last'] ?? 0) > 60) { unset($s['ips'][$k]); }
    }
    if (count($s['ips']) > 128) {
        $s['ips'] = array_slice($s['ips'], -128, 128, true);
    }

    $state = (string)($s['state'] ?? 'closed');
    $out   = $pass($s, $gQps, $ipQps, $state);

    // ---- 熔断状态机 ----
    if ($state === 'open') {
        $left = (int)$cfg['cooldown'] - ($now - (int)($s['opened_at'] ?? 0));
        if ($left > 0 && (bool)$cfg['enabled']) {
            $s['rejects'] = (int)($s['rejects'] ?? 0) + 1;
            $s['last_502'] = $now;
            // 熔断期间到达的请求绝不能继续累加滑动窗口：否则窗口永远满，
            // 冷却结束进入半开时立刻又超硬阈值，熔断将永远无法自动恢复。
            $s['global']['b'] = array_fill(0, WAF_QPS_SLOTS, 0);
            $s['global']['qps'] = 0;
            $s['ips'] = [];
            $out['block'] = true; $out['code'] = 502;
            $out['qps'] = 0; $out['ip_qps'] = 0;
            $out['retry_after'] = $left;
            $out['reason'] = (string)($s['reason'] ?? '') ?: 'circuit_open';
            $out['scope']  = (string)($s['scope'] ?? '') ?: 'global';
            $out['rejects'] = (int)$s['rejects'];
        } else {
            // 冷却结束 → 半开试探：清空窗口重新计数，放行本次
            $s['state'] = 'half_open';
            $s['global'] = wafQpsWindowNew();
            $s['ips'] = [];
            $s['probe_ok'] = 0;
            $out['state'] = 'half_open';
        }
    } elseif ($state === 'half_open') {
        $over = $gQps >= (int)$cfg['hard'] || $ipQps >= (int)$cfg['ip_hard'];
        if ((bool)$cfg['enabled'] && $over) {
            $s['state'] = 'open'; $s['opened_at'] = $now;
            $s['reason'] = 'half_open_failed'; $s['scope'] = $gQps >= (int)$cfg['hard'] ? 'global' : 'ip';
            $s['probe_ok'] = 0;
            $s['rejects'] = (int)($s['rejects'] ?? 0) + 1; $s['last_502'] = $now;
            $out = array_merge($out, ['block' => true, 'code' => 502, 'state' => 'open',
                'retry_after' => (int)$cfg['cooldown'], 'reason' => 'half_open_failed',
                'scope' => $s['scope'], 'rejects' => (int)$s['rejects']]);
        } else {
            $s['probe_ok'] = (int)($s['probe_ok'] ?? 0) + 1;
            if ($s['probe_ok'] >= 3) {
                $s['state'] = 'closed'; $s['opened_at'] = 0;
                $s['reason'] = ''; $s['scope'] = ''; $s['probe_ok'] = 0;
                $out['state'] = 'closed';
            } else {
                $out['state'] = 'half_open';
            }
        }
    } elseif ((bool)$cfg['enabled']) {
        // ---- 正常态：软阈值 429 / 硬阈值 502 ----
        if ($gQps >= (int)$cfg['hard'] || $ipQps >= (int)$cfg['ip_hard']) {
            $global = $gQps >= (int)$cfg['hard'];
            $s['state'] = 'open'; $s['opened_at'] = $now;
            $s['reason'] = $global ? 'global_qps_hard' : 'ip_qps_hard';
            $s['scope']  = $global ? 'global' : 'ip';
            $s['probe_ok'] = 0;
            $s['rejects'] = (int)($s['rejects'] ?? 0) + 1; $s['last_502'] = $now;
            $out = array_merge($out, ['block' => true, 'code' => 502, 'state' => 'open',
                'retry_after' => (int)$cfg['cooldown'], 'reason' => $s['reason'],
                'scope' => $s['scope'], 'rejects' => (int)$s['rejects']]);
        } elseif ($gQps >= (int)$cfg['soft'] || $ipQps >= (int)$cfg['ip_soft']) {
            $global = $gQps >= (int)$cfg['soft'];
            $s['rejects'] = (int)($s['rejects'] ?? 0) + 1; $s['last_429'] = $now;
            $out = array_merge($out, ['block' => true, 'code' => 429,
                'retry_after' => 2, 'reason' => $global ? 'global_qps_soft' : 'ip_qps_soft',
                'scope' => $global ? 'global' : 'ip', 'rejects' => (int)$s['rejects']]);
        }
    }

    $s['updated_at'] = $now;
    $json = json_encode($s, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($json !== false) {
        rewind($fh);
        @ftruncate($fh, 0);
        @fwrite($fh, $json);
        @fflush($fh);
    }
    @flock($fh, LOCK_UN);
    @fclose($fh);
    return $out;
}
