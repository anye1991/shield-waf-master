<?php
defined('ABSPATH') || exit;

function waf_output_filter_start() {
    if (defined('WAF_ERROR_MASKING') && !WAF_ERROR_MASKING) {
        return;
    }

    $requestUri = $_SERVER['REQUEST_URI'] ?? '';
    if (waf_is_static_resource($requestUri)) {
        return;
    }

    ob_start(function($buffer) {
        if (waf_is_php_error_output($buffer)) {
            waf_error_masking_log($buffer, 'php_error_detected');
            if (!headers_sent()) {
                http_response_code(500);
                header('Content-Type: text/html; charset=utf-8');
            }
            return '<!DOCTYPE html><html><head><title>500 Internal Server Error</title><style>body{font-family:Arial,sans-serif;max-width:600px;margin:100px auto;padding:20px;text-align:center;color:#333;}h1{color:#d9534f;font-size:2em;}p{line-height:1.6;}</style></head><body><h1>内部服务器错误</h1><p>服务器遇到了一些问题，请稍后重试。</p><p>如问题持续存在，请联系网站管理员。</p></body></html>';
        }
        return $buffer;
    });
}

function waf_is_static_resource($uri) {
    static $staticExtensions = [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico',
        '.avif', '.apng',
        '.css', '.js',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.zip', '.rar', '.gz', '.tar',
        '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flv', '.webm',
        '.map', '.txt',
        '.webmanifest', '.xml', '.json',
    ];

    $path = parse_url($uri, PHP_URL_PATH);
    if ($path === false) return false;

    // 如果路径中含 .php 中段（如 /index.php/foo.jpg），不视为静态资源
    // 否则 PHP 动态输出会被错误跳过过滤
    if (preg_match('#/[^/]*\.php(/|$)#i', $path)) return false;

    $lowerPath = strtolower($path);
    foreach ($staticExtensions as $ext) {
        if (substr($lowerPath, -strlen($ext)) === $ext) {
            return true;
        }
    }
    return false;
}

function waf_is_php_error_output($buffer) {
    if (!is_string($buffer) || strlen($buffer) < 10) return false;

    // 只检查 buffer 开头的 2048 字节，避免误伤正文（论坛/博客讨论 PHP 错误信息时不会被误判）
    $head = substr($buffer, 0, 2048);
    $trimmedHead = ltrim($head);
    if ($trimmedHead === '') return false;

    $errorPatterns = [
        '/^(?:<br\s*\/?>\s*<b>)?Fatal error(?:<\/b>)?:.+?\sin\s+.+?\.php\s+on line\s+\d+/i',
        '/^(?:<br\s*\/?>\s*<b>)?Parse error(?:<\/b>)?:.+?\sin\s+.+?\.php\s+on line\s+\d+/i',
        '/^Uncaught\s+\w+Exception[\s\S]{0,200}thrown\s+in\s+.+?\.php\s+on line\s+\d+/i',
        '/^Stack trace:[\s\S]{0,500}/i',
    ];

    foreach ($errorPatterns as $pattern) {
        if (@preg_match($pattern, $trimmedHead)) {
            return true;
        }
    }

    return false;
}

function waf_error_masking_log($buffer, $matchedPattern) {
    if (!defined('WAF_LOG_PATH')) return;

    waf_ensure_dir(WAF_LOG_PATH);

    $logFile = WAF_LOG_PATH . 'error_masking_' . date('Y-m-d') . '.log';
    $logData = [
        'time' => date('Y-m-d H:i:s'),
        'ip' => waf_get_real_ip(),
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
        'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'matched_pattern' => $matchedPattern,
        'error_snippet' => substr($buffer, 0, 500),
    ];

    $logLine = json_encode($logData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
}
