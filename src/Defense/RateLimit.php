<?php
defined('ABSPATH') || exit;

function waf_cc_check() {
    if (defined('WAF_SKIP_RATELIMIT') && WAF_SKIP_RATELIMIT) {
        return true;
    }

    $ip = waf_get_real_ip();
    $now = time();
    $file = WAF_CC_LOG;

    $fp = fopen($file, 'c+');
    if (!$fp) return true;

    flock($fp, LOCK_EX);

    $contents = stream_get_contents($fp);
    $lines = $contents ? explode("\n", trim($contents)) : [];

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

    if ($count >= WAF_CC_LIMIT) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }

    $new[] = "$now|$ip";

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $new) . "\n");
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return true;
}