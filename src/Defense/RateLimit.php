<?php
defined('ABSPATH') || exit;

if (!defined('WAF_CC_LOG')) {
    $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
    define('WAF_CC_LOG', $logDir . '/cc_counter.txt');
}
if (!defined('WAF_CC_WINDOW')) define('WAF_CC_WINDOW', 60);
if (!defined('WAF_CC_LIMIT')) define('WAF_CC_LIMIT', 60);

function waf_cc_check() {
    if (defined('WAF_SKIP_RATELIMIT') && WAF_SKIP_RATELIMIT) {
        return true;
    }

    $ip = waf_get_real_ip();
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

    $new = [];
    $count = 0;
    foreach ($lines as $line) {
        $parts = explode('|', $line, 2);
        $ts = (int)$parts[0];
        $lip = $parts[1] ?? '';
        if ($ts > $now - WAF_CC_WINDOW) {
            if ($lip === $ip) $count++;
            $new[] = $line;
        }
    }

    if ($count >= WAF_CC_LIMIT) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }

    // 净化 IP，防止注入换行符或管道符破坏文件格式
    $cleanIp = filter_var($ip, FILTER_VALIDATE_IP);
    if (!$cleanIp) {
        $cleanIp = '0.0.0.0';
    }
    $cleanIp = str_replace(["\n", "\r", "|"], '', $cleanIp);
    $new[] = "$now|$cleanIp";

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $new) . "\n");
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return true;
}
