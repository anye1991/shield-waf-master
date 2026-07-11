<?php
defined('ABSPATH') || exit;

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']);
if (!$ok1 || !$ok2) { http_response_code(403); exit; }

// 仪表盘 API 频率限制：每个 IP 每秒最多 1 次
$ip = waf_get_real_ip();
$cache_file = WAF_LOG_PATH . 'dashboard_api_rate';
$prev = is_file($cache_file) ? json_decode(file_get_contents($cache_file), true) : null;
$now = microtime(true);  // 微秒精度
if ($prev && $prev['ip'] === $ip && ($now - $prev['time']) < 1.0) {
    http_response_code(429);
    exit(json_encode(['error' => 'Too many requests']));
}
@file_put_contents($cache_file, json_encode(['ip' => $ip, 'time' => $now]));

require_once __DIR__ . '/stats.php';

$cacheFile = WAF_LOG_PATH . 'dashboard_cache.json';
if (is_file($cacheFile) && time() - filemtime($cacheFile) < WAF_STATS_CACHE_SEC) {
    $json = file_get_contents($cacheFile);
    header('Content-Type: application/json');
    echo $json;
    exit;
}

$attacks = WafStats::getAttacks(7);
$summary = WafStats::summary($attacks);
$json = json_encode($summary, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
@file_put_contents($cacheFile, $json);

header('Content-Type: application/json');
echo $json;
exit;