<?php
/**
 * 盾甲 WAF 沙箱 API (waf-sandbox-api.php)
 * 提供沙箱管理的 RESTful API 接口
 *
 * 接口列表：
 *   GET  ?action=list              - 查看隔离文件列表
 *   GET  ?action=stats             - 查看隔离统计
 *   GET  ?action=locations         - 查看恶意代码精确定位（可传 path 参数）
 *   GET  ?action=scan-history      - 查看扫描历史
 *   POST ?action=scan              - 手动触发全量扫描
 *   POST ?action=analyze&path=xxx  - 分析指定文件（不隔离）
 *   POST ?action=locate&path=xxx  - 精确定位指定文件中的恶意代码
 *   POST ?action=restore&id=xxx   - 恢复指定隔离文件（原路返回）
 *   POST ?action=restore-all      - 恢复所有隔离文件
 *   POST ?action=review&id=xxx&action=approve|false_positive|delete|keep - 人工审核
 *   POST ?action=quarantine&path=xxx - 手动隔离指定文件
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/normalizer.php';
require_once __DIR__ . '/detector.php';
require_once __DIR__ . '/semantic/SemanticEngine.php';
require_once __DIR__ . '/compiler/CompilerEngine.php';
require_once __DIR__ . '/sandbox.php';
require_once __DIR__ . '/malware_scanner.php';

WafNormalizer::init();

header('Content-Type: application/json; charset=utf-8');

// 验证管理员权限
if (!waf_is_admin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized'], JSON_UNESCAPED_UNICODE);
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

try {
    switch ($action) {
        // ====================== 查看 ======================
        case 'list':
            $files = WafSandbox::getQuarantineList();
            echo json_encode(['success' => true, 'count' => count($files), 'files' => $files], JSON_UNESCAPED_UNICODE);
            break;

        case 'stats':
            $stats = WafSandbox::getStats();
            echo json_encode(['success' => true, 'stats' => $stats], JSON_UNESCAPED_UNICODE);
            break;

        case 'locations':
            $path = $_GET['path'] ?? '';
            $locations = WafSandbox::getMaliciousLocations($path);
            echo json_encode(['success' => true, 'locations' => $locations], JSON_UNESCAPED_UNICODE);
            break;

        case 'scan-history':
            $historyFile = WAF_LOG_PATH . 'sandbox/scan_history.json';
            $history = is_file($historyFile) ? json_decode(file_get_contents($historyFile), true) : [];
            echo json_encode(['success' => true, 'history' => $history], JSON_UNESCAPED_UNICODE);
            break;

        // ====================== 扫描 ======================
        case 'scan':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $result = WafSandbox::scanAll();
            echo json_encode([
                'success'          => true,
                'scanned'          => $result['scanned'],
                'malicious_count'  => $result['malicious_count'],
                'quarantined_count'=> $result['quarantined_count'],
                'location_count'   => $result['location_count'],
                'scan_duration'    => $result['scan_duration'],
                'malicious_files'  => $result['malicious_files'],
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'analyze':
            $path = $_GET['path'] ?? $_POST['path'] ?? '';
            if (empty($path) || !is_file($path)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $analysis = WafSandbox::analyzeFile($path);
            echo json_encode(['success' => true, 'analysis' => $analysis], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'locate':
            $path = $_GET['path'] ?? $_POST['path'] ?? '';
            if (empty($path) || !is_file($path)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $locations = WafSandbox::locateMaliciousCode($path);
            echo json_encode([
                'success'   => true,
                'path'      => $path,
                'count'     => count($locations),
                'locations' => $locations,
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        // ====================== 隔离与恢复 ======================
        case 'quarantine':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $path = $_POST['path'] ?? '';
            if (empty($path) || !is_file($path)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $analysis = WafSandbox::analyzeFile($path);
            $id = WafSandbox::quarantineFile($path, "手动隔离", $analysis);
            echo json_encode(['success' => $id !== false, 'id' => $id, 'analysis' => $analysis], JSON_UNESCAPED_UNICODE);
            break;

        case 'restore':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $id = $_POST['id'] ?? '';
            if (empty($id)) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing file id'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $result = WafSandbox::restoreFile($id);
            echo json_encode(['success' => $result, 'id' => $id], JSON_UNESCAPED_UNICODE);
            break;

        case 'restore-all':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $count = WafSandbox::restoreAllFiles();
            echo json_encode(['success' => true, 'restored' => $count], JSON_UNESCAPED_UNICODE);
            break;

        // ====================== 人工审核 ======================
        case 'review':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $id = $_POST['id'] ?? '';
            $reviewAction = $_POST['review_action'] ?? '';
            $reviewer = $_POST['reviewer'] ?? 'admin';
            if (empty($id) || empty($reviewAction)) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing id or review_action'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $validActions = ['approve', 'false_positive', 'delete', 'keep'];
            if (!in_array($reviewAction, $validActions)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid review_action', 'valid' => $validActions], JSON_UNESCAPED_UNICODE);
                break;
            }
            $result = WafSandbox::reviewFile($id, $reviewAction, $reviewer);
            echo json_encode(['success' => $result, 'id' => $id, 'action' => $reviewAction], JSON_UNESCAPED_UNICODE);
            break;

        default:
            http_response_code(404);
            echo json_encode([
                'error' => 'Unknown action',
                'available' => [
                    'GET: list', 'GET: stats', 'GET: locations', 'GET: scan-history',
                    'POST: scan', 'POST: analyze', 'POST: locate',
                    'POST: quarantine', 'POST: restore', 'POST: restore-all',
                    'POST: review',
                ],
            ], JSON_UNESCAPED_UNICODE);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
}
