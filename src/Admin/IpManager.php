<?php
/**
 * IP 管理器（封禁 / 白名单 / 暴力计数 / 累进惩罚）
 */
defined('ABSPATH') || exit;

// ====================== 封禁管理 ======================

/**
 * 检查当前 IP 是否处于有效封禁期内
 * 注意：不删除过期记录，以保留历史用于累进惩罚
 */
function waf_is_banned() {
    $file = WAF_LOG_PATH . 'ban.txt';
    if (!is_file($file)) return false;
    $ip   = waf_get_real_ip();
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now  = time();
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        if ($d[0] === $ip && (int)$d[1] > $now) {
            return true;
        }
    }
    return false;
}

/**
 * 封禁一个 IP
 * @param string $ip
 * @param int    $sec 封禁秒数
 */
function waf_ban($ip, $sec = 86400) {
    if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);
    @file_put_contents(WAF_LOG_PATH . 'ban.txt', "$ip|" . (time() + $sec) . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * 清理过期超过 30 天的封禁记录（防止文件无限增长）
 * 随机或定期调用即可
 */
function waf_clean_ban_file() {
    $file = WAF_LOG_PATH . 'ban.txt';
    if (!is_file($file)) return;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now   = time();
    $new   = [];
    $changed = false;
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) { $changed = true; continue; }
        // 过期超过 30 天才删除
        if ((int)$d[1] + 2592000 < $now) {
            $changed = true;
            continue;
        }
        $new[] = $line;
    }
    if ($changed) {
        @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    }
}

function waf_unban($ip) {
    $file = WAF_LOG_PATH . 'ban.txt';
    if (!is_file($file)) return;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $new   = [];
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        if ($d[0] !== $ip) {
            $new[] = $line;
        }
    }
    if (count($new) !== count($lines)) {
        @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    }
}

function waf_get_banned_ips() {
    $file = WAF_LOG_PATH . 'ban.txt';
    if (!is_file($file)) return [];
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now   = time();
    $result = [];
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        $expire = (int)$d[1];
        $status = $expire > $now ? 'active' : 'expired';
        $duration = $expire === PHP_INT_MAX ? '永久' : ($expire > $now ? date('Y-m-d H:i:s', $expire) : '已过期');
        $result[] = [
            'ip'       => $d[0],
            'expire'   => $expire,
            'expire_str' => $duration,
            'status'   => $status,
            'history_count' => waf_get_ban_history_count($d[0])
        ];
    }
    return $result;
}

// ====================== 管理员 IP 白名单 ======================

function waf_is_admin_ip($ip = null) {
    if ($ip === null) $ip = waf_get_real_ip();
    $file = WAF_ADMIN_IP_FILE;
    if (!is_file($file)) return false;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now   = time();
    $valid = [];
    $found = false;
    foreach ($lines as $line) {
        $parts  = explode('|', $line);
        $entry_ip = $parts[0];
        $expire   = isset($parts[1]) ? (int)$parts[1] : 0;
        if ($expire > 0 && $expire <= $now) continue;
        if ($entry_ip === $ip) $found = true;
        $valid[] = $line;
    }
    if (count($valid) !== count($lines)) {
        @file_put_contents($file, implode("\n", $valid) . "\n", LOCK_EX);
    }
    return $found;
}

function waf_add_admin_ip($ip, $ttl = WAF_ADMIN_IP_TTL) {
    if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);
    $expire = $ttl > 0 ? time() + $ttl : 0;
    $file   = WAF_ADMIN_IP_FILE;
    $lines  = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $now    = time();
    $new    = [];
    $exists = false;
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        if ($parts[0] === $ip) {
            $exists = true;
            if ($expire === 0 || $expire > $now) {
                $new[] = "$ip|" . ($expire > 0 ? $expire : '0');
            }
        } else {
            $new[] = $line;
        }
    }
    if (!$exists) {
        $new[] = "$ip|" . ($expire > 0 ? $expire : '0');
    }
    @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
}

function waf_clean_admin_ips() {
    $file = WAF_ADMIN_IP_FILE;
    if (!is_file($file)) return;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now   = time();
    $new   = [];
    foreach ($lines as $line) {
        $parts  = explode('|', $line);
        $expire = isset($parts[1]) ? (int)$parts[1] : 0;
        if ($expire === 0 || $expire > $now) {
            $new[] = $line;
        }
    }
    if (count($new) !== count($lines)) {
        @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    }
}

function waf_remove_admin_ip($ip) {
    $file = WAF_ADMIN_IP_FILE;
    if (!is_file($file)) return;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $new   = [];
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        if ($parts[0] !== $ip) {
            $new[] = $line;
        }
    }
    if (count($new) !== count($lines)) {
        @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    }
}

function waf_get_admin_ips() {
    $file = WAF_ADMIN_IP_FILE;
    if (!is_file($file)) return [];
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now   = time();
    $result = [];
    foreach ($lines as $line) {
        $parts  = explode('|', $line);
        $expire = isset($parts[1]) ? (int)$parts[1] : 0;
        $status = ($expire === 0 || $expire > $now) ? 'active' : 'expired';
        $result[] = [
            'ip'      => $parts[0],
            'expire'  => $expire,
            'expire_str' => $expire === 0 ? '永久' : ($expire > $now ? date('Y-m-d H:i:s', $expire) : '已过期'),
            'status'  => $status
        ];
    }
    return $result;
}

// ====================== 暴力尝试计数器 ======================

function waf_attempt_file($type) {
    return WAF_LOG_PATH . "attempt_{$type}.txt";
}

function waf_attempt_clean($type) {
    $file = waf_attempt_file($type);
    if (!is_file($file)) return;
    $now   = time();
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $new   = [];
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        if ((int)$d[1] <= $now) continue;
        $new[] = $line;
    }
    if (count($new) !== count($lines)) {
        @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    }
}

function waf_attempt_get($type) {
    waf_attempt_clean($type);
    $file = waf_attempt_file($type);
    if (!is_file($file)) return 0;
    $ip   = waf_get_real_ip();
    $now  = time();
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        if (strpos($d[0], $ip . ':') === 0 && (int)$d[1] > $now) {
            return (int)substr($d[0], strlen($ip) + 1);
        }
    }
    return 0;
}

function waf_attempt_inc($type, $window = 900) {
    if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);
    $file = waf_attempt_file($type);
    $ip   = waf_get_real_ip();
    $exp  = time() + $window;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $found = false;
    $new   = [];
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        if (strpos($d[0], $ip . ':') === 0) {
            $cnt = (int)substr($d[0], strlen($ip) + 1) + 1;
            $new[] = "$ip:$cnt|$exp";
            $found = true;
        } else {
            if ((int)$d[1] > time()) $new[] = $line;
        }
    }
    if (!$found) $new[] = "$ip:1|$exp";
    @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
}

/**
 * 重置某个类型的错误尝试计数器
 */
function waf_attempt_reset($type) {
    $file = waf_attempt_file($type);
    if (!is_file($file)) return;
    $ip   = waf_get_real_ip();
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $new   = [];
    foreach ($lines as $line) {
        $d = explode('|', $line);
        if (count($d) !== 2) continue;
        if (strpos($d[0], $ip . ':') === 0) {
            // 跳过当前IP的记录（删除）
            continue;
        }
        $new[] = $line;
    }
    @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
}

// ====================== 累进惩罚（4 阶段） ======================

/**
 * 获取某个 IP 在 ban.txt 中出现的总次数（历史记录，含已过期但未清理的）
 */
function waf_get_ban_history_count($ip) {
    $file = WAF_LOG_PATH . 'ban.txt';
    if (!is_file($file)) return 0;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $count = 0;
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        if (count($parts) >= 2 && trim($parts[0]) === $ip) {
            $count++;
        }
    }
    return $count;
}

/**
 * 根据历史封禁次数（不含本次）返回本次封禁时长
 * 第1次：1天，第2次：7天，第3次：30天，第4次及以上：永久
 */
function waf_get_ban_duration($historyCount) {
    $level = $historyCount + 1;
    switch ($level) {
        case 1:  return 86400;        // 1 天
        case 2:  return 604800;       // 7 天
        case 3:  return 2592000;      // 30 天
        default: return PHP_INT_MAX;   // 永久
    }
}

/**
 * 智能封禁：自动累进，跳过管理员白名单 IP
 */
function waf_smart_ban($ip) {
    if (waf_is_admin_ip($ip)) return;
    $history  = waf_get_ban_history_count($ip);
    $duration = waf_get_ban_duration($history);
    waf_ban($ip, $duration);
}

// ====================== IP 段支持 ======================

function waf_ip_in_range($ip, $range) {
    if (strpos($range, '/') === false) {
        return $ip === $range;
    }
    list($network, $prefix) = explode('/', $range, 2);
    $network = ip2long($network);
    $ip = ip2long($ip);
    $mask = -1 << (32 - (int)$prefix);
    $network &= $mask;
    return ($ip & $mask) === $network;
}

function waf_is_admin_ip_range($ip = null) {
    if ($ip === null) $ip = waf_get_real_ip();
    $file = WAF_ADMIN_IP_FILE;
    if (!is_file($file)) return false;
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $now   = time();
    foreach ($lines as $line) {
        $parts  = explode('|', $line);
        $entry_ip = $parts[0];
        $expire   = isset($parts[1]) ? (int)$parts[1] : 0;
        if ($expire > 0 && $expire <= $now) continue;
        if (waf_ip_in_range($ip, $entry_ip)) return true;
    }
    return false;
}