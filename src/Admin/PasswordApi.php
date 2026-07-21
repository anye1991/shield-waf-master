<?php
/**
 * 盾甲 WAF 密码管理 API（WordPress 简化版）
 *
 * 接口列表：
 *   GET  ?action=info          - 查看当前密码配置
 *   POST ?action=change        - 修改密码（直接设置明文密码）
 *       body: { new_password: "..." }
 *   POST ?action=verify-current - 验证明文是否匹配当前密码
 *       body: { password: "..." }
 *
 * 安全设计：
 *   - 全部接口需暗门双因子认证（waf_ok1 + waf_ok2）
 *   - 密码不落任何日志
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

$writeActions = ['change', 'verify-current'];
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
        case 'info':
            $hasPassword = defined('WAF_PASSWORD') && WAF_PASSWORD !== '' && WAF_PASSWORD !== 'shield-waf-2026';
            echo json_encode([
                'success'    => true,
                'has_custom' => $hasPassword,
                'mode'       => 'simple',
                'note'       => 'WordPress 简化模式：直接使用明文密码',
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'change':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $newPassword = $_POST['new_password'] ?? '';
            if (strlen($newPassword) < 6) {
                http_response_code(400);
                echo json_encode(['error' => '密码至少 6 个字符'], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            $updated = false;
            
            // 1. 尝试更新 auto_key.php（当前密码存储位置）
            $autoKeyFile = WAF_LOG_PATH . '/auto_key.php';
            if (is_file($autoKeyFile)) {
                $autoKeys = @include $autoKeyFile;
                if (is_array($autoKeys)) {
                    $autoKeys['WAF_PASSWORD'] = $newPassword;
                    $content = '<?php return ' . var_export($autoKeys, true) . ';';
                    if (@file_put_contents($autoKeyFile, $content) !== false) {
                        @chmod($autoKeyFile, 0600);
                        $updated = true;
                    }
                }
            }
            
            // 2. 同时更新 config.php 中的硬编码密码（如果有）
            $configFile = __DIR__ . '/../../config.php';
            if (is_file($configFile)) {
                $content = file_get_contents($configFile);
                // 匹配 define('WAF_PASSWORD', 'xxx') 或 define('WAF_PASSWORD', "xxx")
                $pattern = "/define\\('WAF_PASSWORD',\\s*['\"]([^'\"]+)['\"]\\s*\\)/";
                $replacement = "define('WAF_PASSWORD', '" . addslashes(str_replace('$', '$$', $newPassword)) . "')";
                $newContent = preg_replace($pattern, $replacement, $content, -1, $count);
                if ($count > 0) {
                    @file_put_contents($configFile, $newContent);
                }
            }
            
            if (!$updated) {
                http_response_code(500);
                echo json_encode(['error' => '无法更新密码存储文件'], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            echo json_encode([
                'success'  => true,
                'message'  => '密码已更新，立即生效',
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            break;

        case 'verify-current':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode(['error' => 'Method not allowed, use POST'], JSON_UNESCAPED_UNICODE);
                break;
            }
            $password = $_POST['password'] ?? '';
            $stored = defined('WAF_PASSWORD') ? WAF_PASSWORD : '';
            $valid = $stored && hash_equals($stored, $password);
            echo json_encode([
                'success' => true,
                'valid'   => $valid,
            ], JSON_UNESCAPED_UNICODE);
            break;

        default:
            http_response_code(404);
            echo json_encode([
                'error' => 'Unknown action',
                'available' => [
                    'GET: info',
                    'POST: change', 'POST: verify-current',
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
