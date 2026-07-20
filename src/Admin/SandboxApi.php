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
 *   GET  ?action=baseline-info     - 查看基线锁定状态与统计
 *   POST ?action=scan              - 手动触发全量扫描
 *   POST ?action=analyze&path=xxx  - 分析指定文件（不隔离）
 *   POST ?action=locate&path=xxx   - 精确定位指定文件中的恶意代码
 *   POST ?action=restore&id=xxx    - 恢复指定隔离文件（原路返回）
 *   POST ?action=restore-all       - 恢复所有隔离文件
 *   POST ?action=review&id=xxx&action=approve|false_positive|delete|keep - 人工审核
 *   POST ?action=quarantine&path=xxx - 手动隔离指定文件
 *   POST ?action=lock-baseline     - 锁定基线（建立干净文件哈希 + 备份 + 联动冻结 AutoLearn）
 *   POST ?action=unlock-baseline   - 解锁基线（回到学习模式）
 *   POST ?action=surgical-cut&path=xxx - 对指定文件做精准切割（移除恶意行保留原始内容）
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../Support/Functions.php';
require_once __DIR__ . '/../Core/Normalizer.php';
require_once __DIR__ . '/../Core/Detector.php';
require_once __DIR__ . '/../Semantic/SemanticEngine.php';
require_once __DIR__ . '/Sandbox.php';
require_once __DIR__ . '/../Defense/MalwareScanner.php';

function waf_sandbox_validate_path($path)
{
    if (empty($path)) {
        return false;
    }

    if (strpos($path, '..') !== false) {
        return false;
    }

    $realPath = realpath($path);
    if ($realPath === false) {
        return false;
    }

    if (!is_file($realPath) && !is_dir($realPath)) {
        return false;
    }

    $allowedDirs = defined('WAF_SANDBOX_MONITOR_DIRS') ? WAF_SANDBOX_MONITOR_DIRS : [ABSPATH];
    if (!is_array($allowedDirs) || empty($allowedDirs)) {
        $allowedDirs = [ABSPATH];
    }

    foreach ($allowedDirs as $dir) {
        $realDir = realpath($dir);
        if ($realDir === false) {
            continue;
        }
        if (strpos($realPath, $realDir . DIRECTORY_SEPARATOR) === 0 || $realPath === $realDir) {
            return $realPath;
        }
    }

    return false;
}

WafNormalizer::init();

header('Content-Type: application/json; charset=utf-8');

// 验证管理员权限（双重验证 + IP 绑定）
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
$ipOk = isset($_SESSION['waf_ip']) && $_SESSION['waf_ip'] === waf_get_real_ip();
if (!$ok1 || !$ok2 || !$ipOk) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (empty($_SESSION['waf_csrf_token'])) {
    if (function_exists('random_bytes')) {
        $_SESSION['waf_csrf_token'] = bin2hex(random_bytes(16));
    } elseif (function_exists('openssl_random_pseudo_bytes')) {
        $_SESSION['waf_csrf_token'] = bin2hex(openssl_random_pseudo_bytes(16));
    } else {
        $_SESSION['waf_csrf_token'] = bin2hex(mt_rand()) . uniqid();
    }
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

$writeActions = ['scan', 'analyze', 'locate', 'quarantine', 'restore', 'restore-all', 'lock-baseline', 'unlock-baseline', 'surgical-cut', 'review'];
if ($method === 'POST' && in_array($action, $writeActions)) {
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : (isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '');
    if (empty($token) || !hash_equals($_SESSION['waf_csrf_token'], $token)) {
        http_response_code(403);
        echo json_encode(['error' => 'CSRF token validation failed'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

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
            $historyFile = WAF_LOG_PATH . '/sandbox/scan_history.json';
            $history = is_file($historyFile) ? json_decode(file_get_contents($historyFile), true) : [];
            echo json_encode(['success' => true, 'history' => $history], JSON_UNESCAPED_UNICODE);
            break;

        case 'baseline-info':
            $info = WafSandbox::getBaselineInfo();
            // 同时附带 AutoLearn 联动状态
            $autoLearnFrozen = false;
            if (class_exists('AutoLearn', false)) {
                try { $autoLearnFrozen = AutoLearn::isBaselineFrozen(); } catch (\Throwable $e) {}
            }
            $info['autolearn_frozen'] = $autoLearnFrozen;
            $info['coupling_enabled'] = defined('WAF_SANDBOX_LEARN_COUPLING') && WAF_SANDBOX_LEARN_COUPLING;
            echo json_encode(['success' => true, 'baseline' => $info], JSON_UNESCAPED_UNICODE);
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
            $validPath = waf_sandbox_validate_path($path);
            if ($validPath === false || !is_file($validPath)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $analysis = WafSandbox::analyzeFile($validPath);
            echo json_encode(['success' => true, 'analysis' => $analysis], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'locate':
            $path = $_GET['path'] ?? $_POST['path'] ?? '';
            $validPath = waf_sandbox_validate_path($path);
            if ($validPath === false || !is_file($validPath)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $locations = WafSandbox::locateMaliciousCode($validPath);
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
            $validPath = waf_sandbox_validate_path($path);
            if ($validPath === false || !is_file($validPath)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $analysis = WafSandbox::analyzeFile($validPath);
            $id = WafSandbox::quarantineFile($validPath, "手动隔离", $analysis);
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

        // ====================== 基线管理 ======================
        case 'lock-baseline':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $result = WafSandbox::lockBaseline();
            echo json_encode(['success' => $result['success'] ?? true, 'result' => $result], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'unlock-baseline':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $result = WafSandbox::unlockBaseline();
            echo json_encode(['success' => $result['success'] ?? true, 'result' => $result], JSON_UNESCAPED_UNICODE);
            break;

        case 'surgical-cut':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $path = $_POST['path'] ?? '';
            $validPath = waf_sandbox_validate_path($path);
            if ($validPath === false || !is_file($validPath)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid file path'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $result = WafSandbox::surgicalCut($validPath);
            echo json_encode(['success' => $result['success'] ?? false, 'result' => $result], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
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
                    'GET: list', 'GET: stats', 'GET: locations', 'GET: scan-history', 'GET: baseline-info',
                    'POST: scan', 'POST: analyze', 'POST: locate',
                    'POST: quarantine', 'POST: restore', 'POST: restore-all',
                    'POST: lock-baseline', 'POST: unlock-baseline', 'POST: surgical-cut',
                    'POST: review',
                ],
            ], JSON_UNESCAPED_UNICODE);
    }
} catch (Exception $e) {
    http_response_code(500);
    if (!is_dir(WAF_LOG_PATH)) {
        @mkdir(WAF_LOG_PATH, 0700, true);
    }
    $logMsg = '[' . date('Y-m-d H:i:s') . '] [' . waf_get_real_ip() . '] ' . $e->getMessage() . "\n";
    @file_put_contents(WAF_LOG_PATH . '/api_error.log', $logMsg, FILE_APPEND);
    echo json_encode(['error' => 'Internal server error'], JSON_UNESCAPED_UNICODE);
}
