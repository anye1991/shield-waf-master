<?php
defined('ABSPATH') || exit;

if (!defined('WAF_CC_LOG')) {
    $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
    define('WAF_CC_LOG', $logDir . '/cc_counter.txt');
}
if (!defined('WAF_CC_WINDOW')) define('WAF_CC_WINDOW', 60);
if (!defined('WAF_CC_LIMIT')) define('WAF_CC_LIMIT', 60);
// 单 IP 在文件后端中的最大记录行数，超过则丢弃最旧记录，防止单文件无限增长
if (!defined('WAF_CC_FILE_MAX_PER_IP')) define('WAF_CC_FILE_MAX_PER_IP', 1000);
// 异步清理：每 N 次请求触发一次全窗口清理（写时仍然过滤过期行，但读时跳过过期行不再强制全量重写）
if (!defined('WAF_CC_CLEANUP_INTERVAL')) define('WAF_CC_CLEANUP_INTERVAL', 100);

/**
 * CC 频率限制检测。
 * 优先使用 APCu 共享内存计数（性能比文件高 100 倍），文件作降级兜底。
 * 不改变 fail-closed 安全语义：无法确定时拦截更安全。
 */
function waf_cc_check() {
    if (defined('WAF_SKIP_RATELIMIT') && WAF_SKIP_RATELIMIT) {
        return true;
    }

    $ip = waf_get_real_ip();
    // 净化 IP，防止注入换行符或管道符破坏文件格式
    $ip = filter_var($ip, FILTER_VALIDATE_IP);
    if (!$ip) {
        $ip = '0.0.0.0';
    }
    $ip = str_replace(["\n", "\r", "|"], '', $ip);

    // APCu 优先（共享内存，性能比文件高 100 倍）
    if (function_exists('apcu_enabled') && apcu_enabled()) {
        return waf_cc_check_apcu($ip);
    }

    // 文件降级
    return waf_cc_check_file($ip);
}

/**
 * APCu 后端：单次原子自增，O(1) 复杂度
 */
function waf_cc_check_apcu($ip) {
    $key = 'waf_cc_' . md5($ip);
    $found = false;
    $count = apcu_inc($key, 1, $found);
    if (!$found) {
        // 首次访问：初始化计数并设置窗口 TTL
        if (apcu_store($key, 1, WAF_CC_WINDOW) === false) {
            // APCu 写入失败，降级到文件后端
            return waf_cc_check_file($ip);
        }
        $count = 1;
    }
    // 计数超过阈值即拦截（含本次请求）
    return $count <= WAF_CC_LIMIT;
}

/**
 * 文件后端：在 APCu 不可用时使用。
 * 优化点：
 *   1. 单 IP 行数上限 WAF_CC_FILE_MAX_PER_IP，超过则丢弃该 IP 最旧记录，避免单文件无限增长
 *   2. 异步清理：每 WAF_CC_CLEANUP_INTERVAL 次请求才触发全窗口清理，其余请求仅追加新行
 *   3. 写入时仍用 flock(LOCK_EX) 持有锁贯穿读改写，保持 fail-closed 与原子性
 */
function waf_cc_check_file($ip) {
    $now = time();
    $file = WAF_CC_LOG;

    $fp = fopen($file, 'c+');
    if (!$fp) {
        // fail-closed：无法确定时拦截更安全
        if (defined('WAF_DEBUG') && WAF_DEBUG) {
            error_log('ShieldWAF RateLimit: cannot open cc log file: ' . $file);
        }
        return false;
    }

    flock($fp, LOCK_EX);

    $contents = stream_get_contents($fp);
    $lines = $contents ? explode("\n", trim($contents)) : [];

    // 单 IP 在窗口内已有计数
    $count = 0;
    $ipLineCount = 0;
    foreach ($lines as $line) {
        if ($line === '') continue;
        $parts = explode('|', $line, 2);
        $ts = (int)$parts[0];
        $lip = $parts[1] ?? '';
        // 窗口内且属于本 IP
        if ($ts > $now - WAF_CC_WINDOW && $lip === $ip) {
            $count++;
            $ipLineCount++;
        }
    }

    if ($count >= WAF_CC_LIMIT) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }

    // 异步清理决策：用计数文件触发周期性全量重写
    $cleanupCounter = waf_cc_bump_counter($file . '.cnt');
    $doCleanup = ($cleanupCounter % WAF_CC_CLEANUP_INTERVAL === 0);

    if ($doCleanup || $ipLineCount >= WAF_CC_FILE_MAX_PER_IP) {
        // 全量重写：过滤掉所有过期行 + 本 IP 多余旧行
        $new = [];
        $keptForIp = 0;
        foreach ($lines as $line) {
            if ($line === '') continue;
            $parts = explode('|', $line, 2);
            $ts = (int)$parts[0];
            $lip = $parts[1] ?? '';
            if ($ts <= $now - WAF_CC_WINDOW) continue; // 过期
            if ($lip === $ip) {
                $keptForIp++;
                // 保留最新的 WAF_CC_FILE_MAX_PER_IP-1 行（加上即将写入的 1 行不超过上限）
                if ($keptForIp >= WAF_CC_FILE_MAX_PER_IP) continue;
            }
            $new[] = $line;
        }
        $new[] = "$now|$ip";
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, implode("\n", $new) . "\n");
    } else {
        // 仅追加新行，不做全量重写
        fseek($fp, 0, SEEK_END);
        if ($contents && strlen($contents) > 0 && substr($contents, -1) !== "\n") {
            fwrite($fp, "\n");
        }
        fwrite($fp, "$now|$ip\n");
    }

    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return true;
}

/**
 * 文件后端辅助：维护一个简单计数器用于触发周期性清理。
 * 计数器自身存储在独立文件，依赖主锁同步（fp 已持有 LOCK_EX）。
 */
function waf_cc_bump_counter($counterFile) {
    // 主文件已持有 LOCK_EX，计数器文件无需再加锁
    $cnt = 0;
    if (is_file($counterFile)) {
        $raw = @file_get_contents($counterFile);
        if ($raw !== false && is_numeric($raw)) {
            $cnt = (int)$raw;
        }
    }
    $cnt++;
    @file_put_contents($counterFile, (string)$cnt);
    return $cnt;
}
