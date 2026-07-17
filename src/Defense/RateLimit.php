<?php
defined('ABSPATH') || exit;

function waf_cc_check() {
    // 白名单 IP 跳过速率限制
    if (defined('WAF_SKIP_RATELIMIT') && WAF_SKIP_RATELIMIT) {
        return true;
    }

    $ip = waf_get_real_ip();
    $now = time();
    $file = WAF_CC_LOG;
    $lines = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $new = [];
    $count = 0;
    foreach ($lines as $line) {
        $parts = explode('|', $line);
        $ts = (int)$parts[0];
        $lip = $parts[1] ?? '';
        if ($ts > $now - WAF_CC_WINDOW) {
            if ($lip === $ip) $count++;
            $new[] = $line;
        }
    }
    if ($count >= WAF_CC_LIMIT) return false;
    $new[] = "$now|$ip";
    @file_put_contents($file, implode("\n", $new) . "\n", LOCK_EX);
    return true;
}