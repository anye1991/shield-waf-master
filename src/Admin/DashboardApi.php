<?php
defined('ABSPATH') || exit;

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
$ipOk = isset($_SESSION['waf_ip']) && $_SESSION['waf_ip'] === waf_get_real_ip();
if (!$ok1 || !$ok2 || !$ipOk) { http_response_code(403); exit(json_encode(['error' => 'Unauthorized'])); }

if (empty($_SESSION['waf_csrf_token'])) {
    if (function_exists('random_bytes')) {
        $_SESSION['waf_csrf_token'] = bin2hex(random_bytes(16));
    } elseif (function_exists('openssl_random_pseudo_bytes')) {
        $_SESSION['waf_csrf_token'] = bin2hex(openssl_random_pseudo_bytes(16));
    } else {
        $_SESSION['waf_csrf_token'] = bin2hex(mt_rand()) . uniqid();
    }
}

$writeActions = ['add_whitelist', 'remove_whitelist', 'ban_ip', 'unban_ip', 'set_module', 'set_config', 'add_whitelist_url', 'remove_whitelist_url', 'learn_feedback', 'learn_reset', 'learn_freeze', 'learn_unfreeze', 'learn_delete_rule'];
$action = isset($_GET['action']) ? $_GET['action'] : '';
$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'POST' && in_array($action, $writeActions)) {
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : (isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '');
    if (empty($token) || !hash_equals($_SESSION['waf_csrf_token'], $token)) {
        http_response_code(403);
        exit(json_encode(['error' => 'CSRF token validation failed']));
    }
}

$ip = waf_get_real_ip();
$cache_file = WAF_LOG_PATH . '/dashboard_api_rate';
$prev = is_file($cache_file) ? json_decode(file_get_contents($cache_file), true) : null;
$now = microtime(true);
if ($prev && $prev['ip'] === $ip && ($now - $prev['time']) < 1.0) {
    http_response_code(429);
    exit(json_encode(['error' => 'Too many requests']));
}
@file_put_contents($cache_file, json_encode(['ip' => $ip, 'time' => $now]));

require_once __DIR__ . '/../../stats.php';
require_once __DIR__ . '/IpManager.php';
require_once __DIR__ . '/../Learn/AutoLearn.php';

define('WAF_DATA_PATH', __DIR__ . '/../../data/');

function waf_ensure_data_dir() {
    if (!is_dir(WAF_DATA_PATH)) {
        @mkdir(WAF_DATA_PATH, 0700, true);
        @chmod(WAF_DATA_PATH, 0700);
    }
    return is_dir(WAF_DATA_PATH);
}

function waf_read_json_file($filename, $default = null) {
    waf_ensure_data_dir();
    $file = WAF_DATA_PATH . $filename;
    if (!is_file($file)) {
        return $default;
    }
    $content = @file_get_contents($file);
    if ($content === false) {
        return $default;
    }
    $data = json_decode($content, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return $default;
    }
    return $data;
}

function waf_write_json_file($filename, $data) {
    waf_ensure_data_dir();
    $file = WAF_DATA_PATH . $filename;
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($json === false) {
        return false;
    }
    $result = @file_put_contents($file, $json);
    if ($result !== false) {
        @chmod($file, 0600);
    }
    return $result !== false;
}

function waf_get_default_modules() {
    return [
        'sql_injection' => true,
        'xss' => true,
        'file_inclusion' => true,
        'file_upload' => true,
        'command_injection' => true,
        'ssrf' => true,
        'xxe' => true,
        'deserialization' => true,
        'csrf' => true,
        'open_redirect' => true,
        'crlf_injection' => true,
        'nosql_injection' => true,
        'ldap_injection' => true,
        'xpath_injection' => true,
        'template_injection' => true,
        'graphql' => true,
        'api_security' => true,
        'cache_poisoning' => true,
        'request_smuggling' => true,
        'session_hijack' => true,
        'session_fixation' => true,
        'race_condition' => true,
        'websocket' => true,
        'chunked' => true,
        'cors_policy' => true,
        'security_headers' => true,
        'output_filter' => true,
        'idor' => true,
        'jwt_security' => true,
        'malware_scanner' => true,
    ];
}

function waf_get_modules_config() {
    $saved = waf_read_json_file('modules_config.json', []);
    $defaults = waf_get_default_modules();
    if (!is_array($saved)) {
        $saved = [];
    }
    return array_merge($defaults, $saved);
}

header('Content-Type: application/json');

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
        $cacheFile = WAF_LOG_PATH . '/dashboard_cache.json';
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

    // ====================== 沙箱↔AutoLearn 联动信息 ======================
    case 'learn_coupling':
        // 沙箱事件回流的高危 IP 列表
        $blacklistFile = WAF_LOG_PATH . '/sandbox_blacklist.json';
        $blacklist = is_file($blacklistFile) ? json_decode(file_get_contents($blacklistFile), true) : ['ips' => [], 'total_events' => 0];
        // 只返回最近 20 条高危 IP，按 last_seen 倒序
        $ips = $blacklist['ips'] ?? [];
        if (!empty($ips)) {
            uasort($ips, function($a, $b) { return ($b['last_seen'] ?? 0) <=> ($a['last_seen'] ?? 0); });
            $ips = array_slice($ips, 0, 20, true);
            // 每条 IP 只保留最近 5 条事件
            foreach ($ips as $k => $v) {
                if (!empty($v['events']) && count($v['events']) > 5) {
                    $ips[$k]['events'] = array_slice($v['events'], -5);
                }
            }
        }
        // AutoLearn 基线冻结状态
        $alFrozen = false;
        $hotSigCount = 0;
        if (class_exists('AutoLearn', false)) {
            try { $alFrozen = AutoLearn::isBaselineFrozen(); } catch (\Throwable $e) {}
            try { $hotSigCount = count(AutoLearn::getHotSignatures(10, 100)); } catch (\Throwable $e) {}
        }
        exit(json_encode([
            'success' => true,
            'coupling_enabled' => defined('WAF_SANDBOX_LEARN_COUPLING') && WAF_SANDBOX_LEARN_COUPLING,
            'total_events' => $blacklist['total_events'] ?? 0,
            'high_risk_ips' => $ips,
            'autolearn_frozen' => $alFrozen,
            'hot_signatures_count' => $hotSigCount,
        ], JSON_UNESCAPED_UNICODE));

    // ====================== 配置项查询 ======================
    case 'config':
        // 只读返回当前生效的关键配置项（用于设置页面展示）
        $config = [
            'SHIELD_WAF_VERSION' => defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : 'unknown',
            // 沙箱
            'WAF_SANDBOX_MODE' => defined('WAF_SANDBOX_MODE') ? WAF_SANDBOX_MODE : 'learning',
            'WAF_SANDBOX_SCAN_INTERVAL' => defined('WAF_SANDBOX_SCAN_INTERVAL') ? WAF_SANDBOX_SCAN_INTERVAL : 300,
            'WAF_SANDBOX_MALWARE_THRESHOLD' => defined('WAF_SANDBOX_MALWARE_THRESHOLD') ? WAF_SANDBOX_MALWARE_THRESHOLD : 50,
            'WAF_SANDBOX_INSTANT_DELETE_NEW' => defined('WAF_SANDBOX_INSTANT_DELETE_NEW') ? WAF_SANDBOX_INSTANT_DELETE_NEW : true,
            'WAF_SANDBOX_AUTO_QUARANTINE' => defined('WAF_SANDBOX_AUTO_QUARANTINE') ? WAF_SANDBOX_AUTO_QUARANTINE : true,
            'WAF_SANDBOX_LEARN_COUPLING' => defined('WAF_SANDBOX_LEARN_COUPLING') ? WAF_SANDBOX_LEARN_COUPLING : true,
            // 上传
            'WAF_UPLOAD_DETECTION' => defined('WAF_UPLOAD_DETECTION') ? WAF_UPLOAD_DETECTION : true,
            'WAF_UPLOAD_GD_VERIFY' => defined('WAF_UPLOAD_GD_VERIFY') ? WAF_UPLOAD_GD_VERIFY : true,
            'WAF_UPLOAD_ALLOW_SVG' => defined('WAF_UPLOAD_ALLOW_SVG') ? WAF_UPLOAD_ALLOW_SVG : false,
            'WAF_UPLOAD_BLOCK_THRESHOLD' => defined('WAF_UPLOAD_BLOCK_THRESHOLD') ? WAF_UPLOAD_BLOCK_THRESHOLD : 60,
            // 语义/学习
            'WAF_SEMANTIC_ENABLED' => defined('WAF_SEMANTIC_ENABLED') ? WAF_SEMANTIC_ENABLED : true,
            'WAF_SEMANTIC_ENGINE' => defined('WAF_SEMANTIC_ENGINE') ? WAF_SEMANTIC_ENGINE : true,
            'WAF_SEMANTIC_MEMORY' => defined('WAF_SEMANTIC_MEMORY') ? WAF_SEMANTIC_MEMORY : true,
            'WAF_ATTACK_CHAIN' => defined('WAF_ATTACK_CHAIN') ? WAF_ATTACK_CHAIN : true,
            'WAF_AUTOLEARN_ENABLED' => defined('WAF_AUTOLEARN_ENABLED') ? WAF_AUTOLEARN_ENABLED : true,
            // 主动防御
            'WAF_ACTIVE_DEFENSE' => defined('WAF_ACTIVE_DEFENSE') ? WAF_ACTIVE_DEFENSE : true,
            'WAF_HONEYTRAP' => defined('WAF_HONEYTRAP') ? WAF_HONEYTRAP : true,
            'WAF_PATH_PREDICTION' => defined('WAF_PATH_PREDICTION') ? WAF_PATH_PREDICTION : true,
            'WAF_FALSE_POSITIVE_GUARD' => defined('WAF_FALSE_POSITIVE_GUARD') ? WAF_FALSE_POSITIVE_GUARD : true,
            // 评分
            'WAF_SCORER_ENABLED' => defined('WAF_SCORER_ENABLED') ? WAF_SCORER_ENABLED : true,
            'WAF_SCORE_BLOCK' => defined('WAF_SCORE_BLOCK') ? WAF_SCORE_BLOCK : 60,
            'WAF_SCORE_MONITOR' => defined('WAF_SCORE_MONITOR') ? WAF_SCORE_MONITOR : 40,
            // 机器人
            'WAF_BOT_VERIFY_DNS' => defined('WAF_BOT_VERIFY_DNS') ? WAF_BOT_VERIFY_DNS : false,
            // CC 防护
            'WAF_CC_LIMIT' => defined('WAF_CC_LIMIT') ? WAF_CC_LIMIT : 60,
            'WAF_CC_WINDOW' => defined('WAF_CC_WINDOW') ? WAF_CC_WINDOW : 60,
        ];
        exit(json_encode(['success' => true, 'config' => $config], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));

    // ====================== 防护模块管理 ======================
    case 'get_modules':
        $modules = waf_get_modules_config();
        exit(json_encode(['success' => true, 'modules' => $modules], JSON_UNESCAPED_UNICODE));

    case 'set_module':
        $module = isset($_POST['module']) ? trim($_POST['module']) : '';
        $enabled = isset($_POST['enabled']) ? (int)$_POST['enabled'] : 0;
        if (empty($module)) {
            exit(json_encode(['success' => false, 'message' => '模块标识不能为空']));
        }
        $defaults = waf_get_default_modules();
        if (!array_key_exists($module, $defaults)) {
            exit(json_encode(['success' => false, 'message' => '未知模块']));
        }
        $modules = waf_get_modules_config();
        $modules[$module] = (bool)$enabled;
        $result = waf_write_json_file('modules_config.json', $modules);
        exit(json_encode(['success' => $result, 'message' => $result ? '模块状态更新成功' : '保存失败']));

    // ====================== 完整配置管理 ======================
    case 'get_config':
        $config = [
            'SHIELD_WAF_VERSION' => defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : 'unknown',
            'WAF_SANDBOX_MODE' => defined('WAF_SANDBOX_MODE') ? WAF_SANDBOX_MODE : 'learning',
            'WAF_SANDBOX_SCAN_INTERVAL' => defined('WAF_SANDBOX_SCAN_INTERVAL') ? WAF_SANDBOX_SCAN_INTERVAL : 300,
            'WAF_SANDBOX_MALWARE_THRESHOLD' => defined('WAF_SANDBOX_MALWARE_THRESHOLD') ? WAF_SANDBOX_MALWARE_THRESHOLD : 50,
            'WAF_SANDBOX_INSTANT_DELETE_NEW' => defined('WAF_SANDBOX_INSTANT_DELETE_NEW') ? WAF_SANDBOX_INSTANT_DELETE_NEW : true,
            'WAF_SANDBOX_AUTO_QUARANTINE' => defined('WAF_SANDBOX_AUTO_QUARANTINE') ? WAF_SANDBOX_AUTO_QUARANTINE : true,
            'WAF_SANDBOX_LEARN_COUPLING' => defined('WAF_SANDBOX_LEARN_COUPLING') ? WAF_SANDBOX_LEARN_COUPLING : true,
            'WAF_UPLOAD_DETECTION' => defined('WAF_UPLOAD_DETECTION') ? WAF_UPLOAD_DETECTION : true,
            'WAF_UPLOAD_GD_VERIFY' => defined('WAF_UPLOAD_GD_VERIFY') ? WAF_UPLOAD_GD_VERIFY : true,
            'WAF_UPLOAD_ALLOW_SVG' => defined('WAF_UPLOAD_ALLOW_SVG') ? WAF_UPLOAD_ALLOW_SVG : false,
            'WAF_UPLOAD_BLOCK_THRESHOLD' => defined('WAF_UPLOAD_BLOCK_THRESHOLD') ? WAF_UPLOAD_BLOCK_THRESHOLD : 60,
            'WAF_UPLOAD_SCAN_MAX_SIZE' => defined('WAF_UPLOAD_SCAN_MAX_SIZE') ? WAF_UPLOAD_SCAN_MAX_SIZE : 5 * 1024 * 1024,
            'WAF_SEMANTIC_ENABLED' => defined('WAF_SEMANTIC_ENABLED') ? WAF_SEMANTIC_ENABLED : true,
            'WAF_SEMANTIC_ENGINE' => defined('WAF_SEMANTIC_ENGINE') ? WAF_SEMANTIC_ENGINE : true,
            'WAF_SEMANTIC_MEMORY' => defined('WAF_SEMANTIC_MEMORY') ? WAF_SEMANTIC_MEMORY : true,
            'WAF_ATTACK_CHAIN' => defined('WAF_ATTACK_CHAIN') ? WAF_ATTACK_CHAIN : true,
            'WAF_AUTOLEARN_ENABLED' => defined('WAF_AUTOLEARN_ENABLED') ? WAF_AUTOLEARN_ENABLED : true,
            'WAF_ACTIVE_DEFENSE' => defined('WAF_ACTIVE_DEFENSE') ? WAF_ACTIVE_DEFENSE : true,
            'WAF_HONEYTRAP' => defined('WAF_HONEYTRAP') ? WAF_HONEYTRAP : true,
            'WAF_PATH_PREDICTION' => defined('WAF_PATH_PREDICTION') ? WAF_PATH_PREDICTION : true,
            'WAF_FALSE_POSITIVE_GUARD' => defined('WAF_FALSE_POSITIVE_GUARD') ? WAF_FALSE_POSITIVE_GUARD : true,
            'WAF_SCORER_ENABLED' => defined('WAF_SCORER_ENABLED') ? WAF_SCORER_ENABLED : true,
            'WAF_SCORE_BLOCK' => defined('WAF_SCORE_BLOCK') ? WAF_SCORE_BLOCK : 60,
            'WAF_SCORE_MONITOR' => defined('WAF_SCORE_MONITOR') ? WAF_SCORE_MONITOR : 40,
            'WAF_BOT_VERIFY_DNS' => defined('WAF_BOT_VERIFY_DNS') ? WAF_BOT_VERIFY_DNS : false,
            'WAF_CC_LIMIT' => defined('WAF_CC_LIMIT') ? WAF_CC_LIMIT : 60,
            'WAF_CC_WINDOW' => defined('WAF_CC_WINDOW') ? WAF_CC_WINDOW : 60,
            'WAF_MAX_BODY_SIZE' => defined('WAF_MAX_BODY_SIZE') ? WAF_MAX_BODY_SIZE : 1048576,
            'WAF_MAX_PAYLOAD_SIZE' => defined('WAF_MAX_PAYLOAD_SIZE') ? WAF_MAX_PAYLOAD_SIZE : 100000,
            'WAF_ERROR_MASKING' => defined('WAF_ERROR_MASKING') ? WAF_ERROR_MASKING : true,
        ];
        $savedSettings = waf_read_json_file('settings.json', []);
        if (is_array($savedSettings)) {
            foreach ($savedSettings as $key => $value) {
                if (array_key_exists($key, $config)) {
                    $config[$key] = $value;
                }
            }
        }
        $modules = waf_get_modules_config();
        exit(json_encode(['success' => true, 'config' => $config, 'modules' => $modules], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));

    case 'set_config':
        $key = isset($_POST['key']) ? trim($_POST['key']) : '';
        $value = isset($_POST['value']) ? $_POST['value'] : null;
        if (empty($key)) {
            exit(json_encode(['success' => false, 'message' => '配置键不能为空']));
        }
        $allowedKeys = [
            'WAF_SANDBOX_MODE',
            'WAF_SANDBOX_SCAN_INTERVAL',
            'WAF_SANDBOX_MALWARE_THRESHOLD',
            'WAF_SANDBOX_INSTANT_DELETE_NEW',
            'WAF_SANDBOX_AUTO_QUARANTINE',
            'WAF_SANDBOX_LEARN_COUPLING',
            'WAF_UPLOAD_DETECTION',
            'WAF_UPLOAD_GD_VERIFY',
            'WAF_UPLOAD_ALLOW_SVG',
            'WAF_UPLOAD_BLOCK_THRESHOLD',
            'WAF_UPLOAD_SCAN_MAX_SIZE',
            'WAF_SEMANTIC_ENABLED',
            'WAF_SEMANTIC_ENGINE',
            'WAF_SEMANTIC_MEMORY',
            'WAF_ATTACK_CHAIN',
            'WAF_AUTOLEARN_ENABLED',
            'WAF_ACTIVE_DEFENSE',
            'WAF_HONEYTRAP',
            'WAF_PATH_PREDICTION',
            'WAF_FALSE_POSITIVE_GUARD',
            'WAF_SCORER_ENABLED',
            'WAF_SCORE_BLOCK',
            'WAF_SCORE_MONITOR',
            'WAF_BOT_VERIFY_DNS',
            'WAF_CC_LIMIT',
            'WAF_CC_WINDOW',
            'WAF_MAX_BODY_SIZE',
            'WAF_MAX_PAYLOAD_SIZE',
            'WAF_ERROR_MASKING',
        ];
        if (!in_array($key, $allowedKeys)) {
            exit(json_encode(['success' => false, 'message' => '不允许修改此配置项']));
        }
        $settings = waf_read_json_file('settings.json', []);
        if (!is_array($settings)) {
            $settings = [];
        }
        if (is_numeric($value) && strpos($value, '.') === false) {
            $value = (int)$value;
        } elseif ($value === 'true' || $value === 'false') {
            $value = $value === 'true';
        }
        $settings[$key] = $value;
        $result = waf_write_json_file('settings.json', $settings);
        exit(json_encode(['success' => $result, 'message' => $result ? '配置更新成功' : '保存失败']));

    // ====================== URL白名单管理 ======================
    case 'get_whitelist_url':
        $list = waf_read_json_file('whitelist_url.json', []);
        if (!is_array($list)) {
            $list = [];
        }
        exit(json_encode(['success' => true, 'data' => $list], JSON_UNESCAPED_UNICODE));

    case 'add_whitelist_url':
        $url = isset($_POST['url']) ? trim($_POST['url']) : '';
        $type = isset($_POST['type']) ? trim($_POST['type']) : 'exact';
        $note = isset($_POST['note']) ? trim($_POST['note']) : '';
        if (empty($url)) {
            exit(json_encode(['success' => false, 'message' => 'URL不能为空']));
        }
        if (!in_array($type, ['exact', 'prefix', 'regex'])) {
            exit(json_encode(['success' => false, 'message' => '无效的匹配类型']));
        }
        $list = waf_read_json_file('whitelist_url.json', []);
        if (!is_array($list)) {
            $list = [];
        }
        $id = time() . '_' . mt_rand(1000, 9999);
        $item = [
            'id' => $id,
            'url' => $url,
            'type' => $type,
            'note' => $note,
            'created_at' => time(),
        ];
        $list[] = $item;
        $result = waf_write_json_file('whitelist_url.json', $list);
        if ($result) {
            exit(json_encode(['success' => true, 'message' => 'URL白名单添加成功', 'id' => $id]));
        } else {
            exit(json_encode(['success' => false, 'message' => '保存失败']));
        }

    case 'remove_whitelist_url':
        $id = isset($_POST['id']) ? trim($_POST['id']) : '';
        if (empty($id)) {
            exit(json_encode(['success' => false, 'message' => 'ID不能为空']));
        }
        $list = waf_read_json_file('whitelist_url.json', []);
        if (!is_array($list)) {
            $list = [];
        }
        $found = false;
        $newList = [];
        foreach ($list as $item) {
            if (isset($item['id']) && $item['id'] === $id) {
                $found = true;
            } else {
                $newList[] = $item;
            }
        }
        if (!$found) {
            exit(json_encode(['success' => false, 'message' => '未找到该记录']));
        }
        $result = waf_write_json_file('whitelist_url.json', $newList);
        exit(json_encode(['success' => $result, 'message' => $result ? 'URL白名单移除成功' : '保存失败']));

    // ====================== 沙箱扫描任务 ======================
    case 'get_sandbox_tasks':
        $tasks = waf_read_json_file('sandbox_tasks.json', []);
        if (!is_array($tasks)) {
            $tasks = [];
        }
        exit(json_encode(['success' => true, 'data' => $tasks], JSON_UNESCAPED_UNICODE));

    // ====================== AutoLearn 自适应学习 ======================
    case 'learn_report':
        if (!class_exists('AutoLearn', false)) {
            require_once __DIR__ . '/../Learn/AutoLearn.php';
        }
        try {
            $report = AutoLearn::getReport();
            $rules = AutoLearn::getLearnedRules();
            // 只返回前 100 条规则，避免响应过大
            $rules = array_slice($rules, 0, 100);
            exit(json_encode(['success' => true, 'report' => $report, 'rules' => $rules], JSON_UNESCAPED_UNICODE));
        } catch (\Throwable $e) {
            exit(json_encode(['success' => false, 'message' => '获取学习报告失败: ' . $e->getMessage()]));
        }

    case 'learn_feedback':
        // 误报/漏报反馈
        if (!class_exists('AutoLearn', false)) {
            require_once __DIR__ . '/../Learn/AutoLearn.php';
        }
        $payload = isset($_POST['payload']) ? trim($_POST['payload']) : '';
        $isFp    = isset($_POST['is_false_positive']) ? (bool)$_POST['is_false_positive'] : true;
        $type    = isset($_POST['attack_type']) ? trim($_POST['attack_type']) : '';
        if ($payload === '') {
            exit(json_encode(['success' => false, 'message' => 'payload 不能为空']));
        }
        try {
            AutoLearn::provideFeedback($payload, $isFp, $type);
            $action2 = $isFp ? '误报' : '漏报';
            exit(json_encode(['success' => true, 'message' => "{$action2}反馈已记录，权重将自动调整"]));
        } catch (\Throwable $e) {
            exit(json_encode(['success' => false, 'message' => '反馈失败: ' . $e->getMessage()]));
        }

    case 'learn_reset':
        // 重置所有学习数据（高危操作）
        if (!class_exists('AutoLearn', false)) {
            require_once __DIR__ . '/../Learn/AutoLearn.php';
        }
        $files = ['learned_patterns.json', 'attack_stats.json', 'weight_adjustments.json', 'feedback_log.json', 'normal_patterns.json'];
        foreach ($files as $f) {
            $path = WAF_LOG_PATH . '/' . $f;
            if (is_file($path)) @unlink($path);
        }
        exit(json_encode(['success' => true, 'message' => '学习数据已重置']));

    case 'learn_freeze':
        if (!class_exists('AutoLearn', false)) {
            require_once __DIR__ . '/../Learn/AutoLearn.php';
        }
        try {
            $r = AutoLearn::freezeBaseline('manual_dashboard');
            exit(json_encode(['success' => true, 'message' => '行为基线已冻结', 'data' => $r]));
        } catch (\Throwable $e) {
            exit(json_encode(['success' => false, 'message' => $e->getMessage()]));
        }

    case 'learn_unfreeze':
        if (!class_exists('AutoLearn', false)) {
            require_once __DIR__ . '/../Learn/AutoLearn.php';
        }
        try {
            $r = AutoLearn::unfreezeBaseline();
            exit(json_encode(['success' => true, 'message' => '行为基线已解冻', 'data' => $r]));
        } catch (\Throwable $e) {
            exit(json_encode(['success' => false, 'message' => $e->getMessage()]));
        }

    case 'learn_delete_rule':
        // 删除单条学习规则（按规则内容）
        if (!class_exists('AutoLearn', false)) {
            require_once __DIR__ . '/../Learn/AutoLearn.php';
        }
        $pattern = isset($_POST['pattern']) ? trim($_POST['pattern']) : '';
        if ($pattern === '') {
            exit(json_encode(['success' => false, 'message' => 'pattern 不能为空']));
        }
        $file = WAF_LOG_PATH . '/learned_patterns.json';
        $data = is_file($file) ? json_decode(file_get_contents($file), true) : null;
        if (!is_array($data) || !isset($data['rules'])) {
            exit(json_encode(['success' => false, 'message' => '学习规则文件不存在']));
        }
        $removed = 0;
        foreach ($data['rules'] as $key => $rule) {
            if (($rule['pattern'] ?? '') === $pattern) {
                unset($data['rules'][$key]);
                $removed++;
            }
        }
        $data['total_learned'] = count($data['rules']);
        @file_put_contents($file, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        exit(json_encode(['success' => true, 'message' => "已删除 {$removed} 条规则"]));
}
