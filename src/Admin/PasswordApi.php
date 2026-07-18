<?php
/**
 * 盾甲 WAF 密码管理 API
 *
 * 接口列表：
 *   GET  ?action=info          - 查看当前密码存储信息（算法/格式/是否需重哈希）
 *   GET  ?action=algos         - 查看当前环境支持的算法
 *   GET  ?action=benchmark     - 性能测试
 *   POST ?action=hash          - 生成双重哈希（明文 → dual$v1$...）
 *       body: { password: "..." }
 *   POST ?action=verify        - 验证明文是否匹配 hash
 *       body: { password: "...", hash: "dual$v1$..." }
 *   POST ?action=migrate       - 用新明文密码覆盖 hash 文件
 *       body: { new_password: "..." }
 *   POST ?action=verify-current - 验证明文是否匹配当前 WAF_PASSWORD_HASH
 *       body: { password: "..." }
 *
 * 安全设计：
 *   - 全部接口需暗门双因子认证（waf_ok1 + waf_ok2）
 *   - hash 接口的密码不落任何日志
 *   - migrate 接口写入 hash 文件前备份旧 hash
 *   - 失败响应不暴露 hash 内容
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../Support/Functions.php';

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

$writeActions = ['hash', 'verify', 'verify-current', 'migrate'];
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
        case 'info':
            $stored = defined('WAF_PASSWORD_HASH') ? WAF_PASSWORD_HASH : '';
            $info = WafPassword::info($stored);
            // 附带迁移文件信息
            $hashFile = WAF_LOG_PATH . 'password_hash.json';
            $fileMeta = [];
            if (is_file($hashFile)) {
                $data = json_decode(file_get_contents($hashFile), true);
                $fileMeta = [
                    'migrated_at'  => $data['migrated_at'] ?? $data['upgraded_at'] ?? null,
                    'source'       => $data['source'] ?? 'unknown',
                    'warning'      => $data['warning'] ?? null,
                ];
            }
            echo json_encode([
                'success'  => true,
                'info'     => $info,
                'file'     => $fileMeta,
                'hash_preview' => $stored ? substr($stored, 0, 20) . '...' : '(empty)',
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'algos':
            echo json_encode([
                'success'  => true,
                'best'     => WafPassword::detectBestPrimaryAlgo(),
                'available'=> WafPassword::getAvailableAlgos(),
                'sodium_loaded' => extension_loaded('sodium'),
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'benchmark':
            // 性能测试可能耗时 1-2 秒
            @set_time_limit(30);
            $result = WafPassword::benchmark();
            echo json_encode(['success' => true, 'benchmark' => $result], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        // ====================== 操作 ======================
        case 'hash':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $password = $_POST['password'] ?? '';
            if (strlen($password) < 6) {
                http_response_code(400);
                echo json_encode(['error' => '密码至少 6 个字符'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $hash = WafPassword::hash($password);
            $info = WafPassword::info($hash);
            echo json_encode([
                'success'  => true,
                'hash'     => $hash,
                'info'     => $info,
                'instruction' => '请将上面的 hash 字符串完整复制到 .env 的 WAF_2FA_PASS= 或保存到控制台',
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'verify':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $password = $_POST['password'] ?? '';
            $hash     = $_POST['hash'] ?? '';
            if ($password === '' || $hash === '') {
                http_response_code(400);
                echo json_encode(['error' => 'Missing password or hash'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $valid = WafPassword::verify($password, $hash);
            echo json_encode([
                'success'  => true,
                'valid'    => $valid,
                'info'     => WafPassword::info($hash),
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'verify-current':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $password = $_POST['password'] ?? '';
            $stored = defined('WAF_PASSWORD_HASH') ? WAF_PASSWORD_HASH : '';
            $valid = WafPassword::verify($password, $stored);
            echo json_encode([
                'success' => true,
                'valid'   => $valid,
                'info'    => WafPassword::info($stored),
            ], JSON_UNESCAPED_UNICODE);
            break;

        case 'migrate':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $newPassword = $_POST['new_password'] ?? '';
            if (strlen($newPassword) < 6) {
                http_response_code(400);
                echo json_encode(['error' => '新密码至少 6 个字符'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $hashFile = WAF_LOG_PATH . 'password_hash.json';
            // 备份旧 hash
            $backup = null;
            if (is_file($hashFile)) {
                $oldData = json_decode(file_get_contents($hashFile), true);
                if (isset($oldData['hash'])) $backup = $oldData['hash'];
            }
            // 写入新 hash
            $newHash = WafPassword::hash($newPassword);
            file_put_contents($hashFile, json_encode([
                'hash' => $newHash,
                'migrated_at' => time(),
                'source' => 'manual-migration-via-api',
                'backup_of_previous' => $backup ? substr($backup, 0, 30) . '...' : null,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            echo json_encode([
                'success'  => true,
                'message'  => '密码已更新为双重哈希',
                'info'     => WafPassword::info($newHash),
                'hash_file'=> $hashFile,
                'instruction' => '建议从 .env 删除 WAF_2FA_PASS 明文以彻底依赖 hash 文件',
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        default:
            http_response_code(404);
            echo json_encode([
                'error' => 'Unknown action',
                'available' => [
                    'GET: info', 'GET: algos', 'GET: benchmark',
                    'POST: hash', 'POST: verify', 'POST: verify-current', 'POST: migrate',
                ],
            ], JSON_UNESCAPED_UNICODE);
    }
} catch (Exception $e) {
    http_response_code(500);
    if (!is_dir(WAF_LOG_PATH)) {
        @mkdir(WAF_LOG_PATH, 0700, true);
    }
    $logMsg = '[' . date('Y-m-d H:i:s') . '] [' . waf_get_real_ip() . '] ' . $e->getMessage() . "\n";
    @file_put_contents(WAF_LOG_PATH . 'api_error.log', $logMsg, FILE_APPEND);
    echo json_encode(['error' => 'Internal server error'], JSON_UNESCAPED_UNICODE);
}
