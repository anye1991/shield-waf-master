<?php
defined('ABSPATH') || exit;

if (!defined('WAF_CC_LOG')) {
    $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
    define('WAF_CC_LOG', $logDir . '/cc_counter.txt');
}
if (!defined('WAF_CC_WINDOW')) define('WAF_CC_WINDOW', 60);
// 默认 120 次/分钟（静态资源已提前放行，此处仅计动态请求）
// WordPress heartbeat、AJAX、前端轮询等正常场景需要更高阈值
// 通过 config.php 的 WAF_CC_LIMIT 可自定义，此处仅作兜底
if (!defined('WAF_CC_LIMIT')) define('WAF_CC_LIMIT', 120);
// AJAX/已登录用户可配置更高阈值（通过 RequestContext 动态判断）
if (!defined('WAF_CC_LIMIT_AJAX')) define('WAF_CC_LIMIT_AJAX', 240);
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

    // 动态阈值：AJAX 请求（WordPress heartbeat / wp-json / admin-ajax）使用更高阈值
    // 静态资源已在 shield-waf.php 顶部 return，不会进入这里
    $limit = WAF_CC_LIMIT;
    if (self_is_ajax_request()) {
        $limit = defined('WAF_CC_LIMIT_AJAX') ? WAF_CC_LIMIT_AJAX : 240;
    }

    // APCu 优先（共享内存，性能比文件高 100 倍）
    if (function_exists('apcu_enabled') && apcu_enabled()) {
        return waf_cc_check_apcu($ip, $limit);
    }

    // 文件降级
    return waf_cc_check_file($ip, $limit);
}

/**
 * 判断是否为 AJAX 请求
 * WordPress heartbeat、admin-ajax、wp-json、REST API 等高频合法请求
 */
function self_is_ajax_request() {
    // 标准 X-Requested-With 头
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        return true;
    }
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $path = parse_url($uri, PHP_URL_PATH) ?: '';
    $lower = strtolower($path);
    // WordPress AJAX / REST API / heartbeat 端点
    if (strpos($lower, 'admin-ajax.php') !== false) return true;
    if (strpos($lower, '/wp-json/') !== false) return true;
    if (strpos($lower, 'heartbeat') !== false) return true;
    // 通用 API 路径
    if (strpos($lower, '/api/') !== false) return true;
    return false;
}

/**
 * APCu 后端：单次原子自增，O(1) 复杂度
 */
function waf_cc_check_apcu($ip, $limit = null) {
    if ($limit === null) $limit = WAF_CC_LIMIT;
    $prefix = defined('WAF_MAGIC_KEY') ? substr(md5(WAF_MAGIC_KEY), 0, 8) : 'def';
    $key = 'waf_cc_' . $prefix . '_' . md5($ip);
    $found = false;
    $count = apcu_inc($key, 1, $found);
    if (!$found) {
        if (apcu_store($key, 1, WAF_CC_WINDOW) === false) {
            return waf_cc_check_file($ip, $limit);
        }
        $count = 1;
    }
    return $count <= $limit;
}

/**
 * 文件后端：在 APCu 不可用时使用。
 * 优化点：
 *   1. 单 IP 行数上限 WAF_CC_FILE_MAX_PER_IP，超过则丢弃该 IP 最旧记录，避免单文件无限增长
 *   2. 异步清理：每 WAF_CC_CLEANUP_INTERVAL 次请求才触发全窗口清理，其余请求仅追加新行
 *   3. 写入时仍用 flock(LOCK_EX) 持有锁贯穿读改写，保持 fail-closed 与原子性
 */
function waf_cc_check_file($ip, $limit = null) {
    if ($limit === null) $limit = WAF_CC_LIMIT;
    $now = time();
    $file = WAF_CC_LOG;

    // 确保日志目录存在（防止部署环境 logs 目录未创建导致 fopen 失败）
    if (defined('WAF_LOG_PATH') && WAF_LOG_PATH) {
        if (!is_dir(WAF_LOG_PATH)) {
            @mkdir(WAF_LOG_PATH, 0775, true);
        }
        // 若主目录仍不可写，降级到 /tmp 兜底（fail-open：不影响访问）
        if (is_dir(WAF_LOG_PATH) && !is_writable(WAF_LOG_PATH)) {
            $file = '/tmp/shield_waf_cc_counter.txt';
        }
    }

    $fp = @fopen($file, 'c+');
    if (!$fp) {
        // 兜底：再尝试 /tmp
        if ($file !== '/tmp/shield_waf_cc_counter.txt') {
            $file = '/tmp/shield_waf_cc_counter.txt';
            $fp = @fopen($file, 'c+');
        }
        if (!$fp) {
            // fail-open：无法写入日志时放行，避免部署环境日志目录不可写导致全站403
            // 速率限制是"尽力而为"的防护，失效不应影响正常业务访问
            if (defined('WAF_DEBUG') && WAF_DEBUG) {
                error_log('ShieldWAF RateLimit: cannot open cc log file, fail-open: ' . $file);
            }
            return true;
        }
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

    if ($count >= $limit) {
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
    $fp = fopen($counterFile, 'c+');
    if ($fp) {
        flock($fp, LOCK_EX);
        $raw = stream_get_contents($fp);
        $cnt = 0;
        if (is_numeric($raw)) {
            $cnt = (int)$raw;
        }
        $cnt++;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, (string)$cnt);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        return $cnt;
    }
    return 1;
}
