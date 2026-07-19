<?php
defined('ABSPATH') || exit;

function waf_ensure_dir($dir) {
    if (!is_dir($dir)) {
        return @mkdir($dir, 0700, true);
    }
    return true;
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
    // 如果配置了信任 Cloudflare
    if (defined('WAF_TRUST_CF_IP') && WAF_TRUST_CF_IP && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    // 默认只信任直接连接 IP，防止伪造
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
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
            $logFile = WAF_LOG_PATH . 'block_' . date('Y-m-d') . '.log';
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
    if (defined('WAF_403_TEMPLATE') && is_file(WAF_403_TEMPLATE)) {
        $waf_msg = $msg;
        $waf_ip  = waf_get_real_ip();
        $waf_uri = $_SERVER['REQUEST_URI'] ?? '';
        include WAF_403_TEMPLATE;
    } else {
        header('Content-Type: text/html; charset=utf-8');
        die('403 Forbidden - Your request has been blocked.');
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