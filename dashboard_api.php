<?php
defined('ABSPATH') || exit;

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']);
if (!$ok1 || !$ok2) { http_response_code(403); exit; }

$ip = waf_get_real_ip();
$cache_file = WAF_LOG_PATH . 'dashboard_api_rate';
$prev = is_file($cache_file) ? json_decode(file_get_contents($cache_file), true) : null;
$now = microtime(true);
if ($prev && $prev['ip'] === $ip && ($now - $prev['time']) < 1.0) {
    http_response_code(429);
    exit(json_encode(['error' => 'Too many requests']));
}
@file_put_contents($cache_file, json_encode(['ip' => $ip, 'time' => $now]));

require_once __DIR__ . '/stats.php';
require_once __DIR__ . '/ip_manager.php';

header('Content-Type: application/json');

$action = isset($_GET['action']) ? $_GET['action'] : '';

switch ($action) {
    case 'get_banned':
        exit(json_encode(['data' => waf_get_banned_ips()]));

    case 'get_whitelist':
        exit(json_encode(['data' => waf_get_admin_ips()]));

    case 'add_whitelist':
        $ip_input = isset($_POST['ip']) ? trim($_POST['ip']) : '';
        $ttl = isset($_POST['ttl']) ? (int)$_POST['ttl'] : WAF_ADMIN_IP_TTL;
        if (filter_var($ip_input, FILTER_VALIDATE_IP) || preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+$/', $ip_input)) {
            waf_add_admin_ip($ip_input, $ttl);
            exit(json_encode(['success' => true, 'message' => '白名单添加成功']));
        } else {
            exit(json_encode(['success' => false, 'message' => '无效的IP地址']));
        }

    case 'remove_whitelist':
        $ip_input = isset($_POST['ip']) ? trim($_POST['ip']) : '';
        if (!empty($ip_input)) {
            waf_remove_admin_ip($ip_input);
            exit(json_encode(['success' => true, 'message' => '白名单移除成功']));
        } else {
            exit(json_encode(['success' => false, 'message' => '无效的IP地址']));
        }

    case 'ban_ip':
        $ip_input = isset($_POST['ip']) ? trim($_POST['ip']) : '';
        $duration = isset($_POST['duration']) ? (int)$_POST['duration'] : 86400;
        if (filter_var($ip_input, FILTER_VALIDATE_IP)) {
            waf_ban($ip_input, $duration);
            exit(json_encode(['success' => true, 'message' => 'IP封禁成功']));
        } else {
            exit(json_encode(['success' => false, 'message' => '无效的IP地址']));
        }

    case 'unban_ip':
        $ip_input = isset($_POST['ip']) ? trim($_POST['ip']) : '';
        if (filter_var($ip_input, FILTER_VALIDATE_IP)) {
            waf_unban($ip_input);
            exit(json_encode(['success' => true, 'message' => 'IP解封成功']));
        } else {
            exit(json_encode(['success' => false, 'message' => '无效的IP地址']));
        }

    default:
        $cacheFile = WAF_LOG_PATH . 'dashboard_cache.json';
        if (is_file($cacheFile) && time() - filemtime($cacheFile) < WAF_STATS_CACHE_SEC) {
            $json = file_get_contents($cacheFile);
            echo $json;
            exit;
        }

        $attacks = WafStats::getAttacks(7);
        $summary = WafStats::summary($attacks);
        $json = json_encode($summary, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        @file_put_contents($cacheFile, $json);
        echo $json;
        exit;
}
