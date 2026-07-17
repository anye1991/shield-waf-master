<?php
defined('ABSPATH') || exit;

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
    if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);
    $log_ip  = str_replace(["\r", "\n"], '', waf_get_real_ip());
    $log_uri = str_replace(["\r", "\n"], '', $_SERVER['REQUEST_URI'] ?? '');
    $log_msg = str_replace(["\r", "\n"], '', $msg);
    @file_put_contents(
        WAF_LOG_PATH . 'block_' . date('Y-m-d') . '.log',
        date('Y-m-d H:i:s') . ' | IP: ' . $log_ip .
        ' | URI: ' . $log_uri . ' | Msg: ' . $log_msg . "\n",
        FILE_APPEND
    );
    if (defined('WAF_WEBHOOK_URL') && WAF_WEBHOOK_URL) {
        waf_send_webhook($msg);
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