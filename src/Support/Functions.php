<?php
defined('ABSPATH') || exit;

// ====================== PHP 版本兼容性 polyfill ======================
// array_key_first / array_key_last (PHP 7.3+ 引入)
if (!function_exists('array_key_first')) {
    function array_key_first(array $arr) {
        foreach ($arr as $key => $_) return $key;
        return null;
    }
}
if (!function_exists('array_key_last')) {
    function array_key_last(array $arr) {
        end($arr);
        return key($arr);
    }
}

// str_contains / str_starts_with / str_ends_with (PHP 8.0+ 引入)
if (!function_exists('str_contains')) {
    function str_contains($haystack, $needle) {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with($haystack, $needle) {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with($haystack, $needle) {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }
}

function waf_ensure_dir($dir) {
    if (!is_dir($dir)) {
        return @mkdir($dir, 0700, true);
    }
    return true;
}

/**
 * 日志文件轮转：按大小自动截断，防止单文件无限增长
 * 默认单文件 10MB 上限，超过则截断保留尾部 50% 内容
 * 可通过 WAF_LOG_MAX_SIZE（字节）配置
 */
function waf_log_rotate($file, $maxSize = null) {
    if (!is_file($file)) return;
    if ($maxSize === null) {
        $maxSize = defined('WAF_LOG_MAX_SIZE') ? WAF_LOG_MAX_SIZE : 10485760; // 10MB
    }
    $size = @filesize($file);
    if ($size === false || $size < $maxSize) return;

    // 截断保留尾部 50% 内容
    $keepSize = intval($maxSize / 2);
    $fp = @fopen($file, 'r');
    if (!$fp) return;
    fseek($fp, -$keepSize, SEEK_END);
    $tail = stream_get_contents($fp);
    fclose($fp);

    // 去掉可能截断的不完整首行
    $firstNl = strpos($tail, "\n");
    if ($firstNl !== false) {
        $tail = substr($tail, $firstNl + 1);
    }

    // 原子写入
    $tmp = $file . '.tmp.' . getmypid();
    if (@file_put_contents($tmp, $tail) !== false) {
        @chmod($tmp, 0664);
        @rename($tmp, $file);
    } else {
        @unlink($tmp);
    }
}

function waf_safe_read_json($file, $default = []) {
    if (!is_file($file)) return $default;
    $content = @file_get_contents($file);
    if ($content === false) return $default;
    $data = json_decode($content, true);
    return is_array($data) ? $data : $default;
}

function waf_safe_write_json($file, $data) {
    $dir = dirname($file);
    waf_ensure_dir($dir);
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    return @file_put_contents($file, $json, LOCK_EX) !== false;
}

function waf_get_real_ip() {
    // 缓存结果（单次请求内多次调用）
    static $cachedIp = null;
    if ($cachedIp !== null) return $cachedIp;

    // 如果配置了信任 Cloudflare
    if (defined('WAF_TRUST_CF_IP') && WAF_TRUST_CF_IP && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        // 安全验证：只有当来源 IP 确实属于 Cloudflare 网段时才信任 CF-Connecting-IP
        // 防止非 CF 环境下该头被伪造
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($remoteAddr && waf_is_cloudflare_ip($remoteAddr)) {
            $cachedIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
            return $cachedIp;
        }
        // 来源 IP 不在 CF 段，降级用 REMOTE_ADDR（安全优先）
    }
    // 默认只信任直接连接 IP，防止伪造
    $cachedIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return $cachedIp;
}

/**
 * 检查 IP 是否属于 Cloudflare 官方网段
 * 仅在启用 WAF_TRUST_CF_IP 时调用
 */
function waf_is_cloudflare_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    // Cloudflare 官方 IPv4 段（https://www.cloudflare.com/ips-v4/）
    // 使用 cidr 匹配，避免大段误判
    static $cfCidrs = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ];
    foreach ($cfCidrs as $cidr) {
        if (waf_ip_in_cidr($ip, $cidr)) return true;
    }
    return false;
}

/**
 * 判断 IP 是否在 CIDR 网段内（支持 IPv4）
 */
function waf_ip_in_cidr($ip, $cidr) {
    list($subnet, $mask) = explode('/', $cidr, 2);
    $ipLong = ip2long($ip);
    $subnetLong = ip2long($subnet);
    if ($ipLong === false || $subnetLong === false) return false;
    $mask = (int)$mask;
    if ($mask <= 0) return true;
    if ($mask > 32) return false;
    $maskLong = -1 << (32 - $mask);
    return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
}

function waf_block($msg = '') {
    http_response_code(403);
    $log_ip  = str_replace(["\r", "\n"], '', waf_get_real_ip());
    $log_uri = str_replace(["\r", "\n"], '', $_SERVER['REQUEST_URI'] ?? '');
    $log_msg = str_replace(["\r", "\n"], '', $msg);
    $log_line = date('Y-m-d H:i:s') . ' | IP: ' . $log_ip .
                ' | URI: ' . $log_uri . ' | Msg: ' . $log_msg . "\n";

    // 主日志路径：WAF_LOG_PATH/block_YYYY-MM-DD.log
    $written = false;
    if (defined('WAF_LOG_PATH') && WAF_LOG_PATH) {
        if (!is_dir(WAF_LOG_PATH)) {
            // 尝试创建，0775 让 nginx/php-fpm 都能写入
            @mkdir(WAF_LOG_PATH, 0775, true);
        }
        if (is_dir(WAF_LOG_PATH) && is_writable(WAF_LOG_PATH)) {
            $logFile = WAF_LOG_PATH . '/block_' . date('Y-m-d') . '.log';
            // 写入前检查轮转（1% 概率抽样检查，避免每次都 stat）
            if (rand(1, 100) === 1) {
                waf_log_rotate($logFile);
            }
            $written = (@file_put_contents($logFile, $log_line, FILE_APPEND | LOCK_EX) !== false);
            // 兜底：单文件不可写时改权限
            if (!$written && is_file($logFile)) {
                @chmod($logFile, 0664);
                $written = (@file_put_contents($logFile, $log_line, FILE_APPEND | LOCK_EX) !== false);
            }
        }
    }

    // 兜底1：WAF_LOG_PATH 不可写时（如 nginx/php-fpm 用户无权限），降级到 PHP error_log
    if (!$written) {
        error_log('[ShieldWAF][block] ' . rtrim($log_line));
    }

    // 兜底2：尝试写入系统 /tmp（Web 用户一般可写）作为最后保障
    if (!$written && is_writable('/tmp')) {
        @file_put_contents('/tmp/shield_waf_block.log', $log_line, FILE_APPEND | LOCK_EX);
    }

    if (defined('WAF_WEBHOOK_URL') && WAF_WEBHOOK_URL) {
        waf_send_webhook($msg);
    }
    // 测试模式响应头标记（方便调试和监控）
    if (defined('WAF_TEST_MODE') && WAF_TEST_MODE) {
        @header('X-ShieldWAF-TestMode: 1');
    }

    // 清除所有输出缓冲区（WordPress/插件可能已启动多层 ob_start）
    // 避免美化403页面被附加到已有输出后面，导致页面变形
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    // 确保响应头未被发送（WordPress 可能已发送 header）
    if (!headers_sent()) {
        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        if (defined('WAF_TEST_MODE') && WAF_TEST_MODE) {
            @header('X-ShieldWAF-TestMode: 1');
        }
    }

    if (defined('WAF_403_TEMPLATE') && is_file(WAF_403_TEMPLATE)) {
        $waf_msg = $msg;
        $waf_ip  = waf_get_real_ip();
        $waf_uri = $_SERVER['REQUEST_URI'] ?? '';
        include WAF_403_TEMPLATE;
    } else {
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>403 Forbidden</title>'
           . '<style>body{font-family:sans-serif;text-align:center;padding:50px;color:#333}'
           . 'h1{font-size:48px;color:#c00;margin-bottom:10px}'
           . 'p{font-size:16px;line-height:1.6}</style></head>'
           . '<body><h1>403</h1><p>Your request has been blocked by Shield WAF.</p>'
           . '</body></html>';
    }
    exit;
}

function waf_send_webhook($msg) {
    $payload = json_encode([
        'text' => "🚨 WAF Alert\nIP: " . waf_get_real_ip() .
                  "\nURI: " . ($_SERVER['REQUEST_URI'] ?? '') .
                  "\nMsg: $msg\nTime: " . date('Y-m-d H:i:s')
    ]);
    $url = WAF_WEBHOOK_URL;
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['host'])) return;

    $scheme = $parts['scheme'] ?? 'http';
    $host = $parts['host'];
    $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
    $path = $parts['path'] ?? '/';
    if (isset($parts['query'])) {
        $path .= '?' . $parts['query'];
    }

    $transport = ($scheme === 'https') ? 'tls://' : 'tcp://';
    $remote = $transport . $host . ':' . $port;

    $sock = @stream_socket_client($remote, $errno, $errstr, 2);
    if ($sock) {
        stream_set_timeout($sock, 2);
        $out = "POST " . $path . " HTTP/1.1\r\n";
        $out .= "Host: " . $host . "\r\n";
        $out .= "Content-Type: application/json\r\n";
        $out .= "Content-Length: " . strlen($payload) . "\r\n";
        $out .= "Connection: Close\r\n\r\n";
        $out .= $payload;
        @fwrite($sock, $out);
        @fclose($sock);
    }
}