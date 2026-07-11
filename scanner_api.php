<?php
defined('ABSPATH') || exit;
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']);
if (!$ok1 || !$ok2) { http_response_code(403); exit; }
require_once __DIR__ . '/malware_scanner.php';
header('Content-Type: application/json');
echo json_encode(MalwareScanner::getReport(), JSON_UNESCAPED_UNICODE);
exit;