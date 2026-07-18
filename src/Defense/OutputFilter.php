<?php
defined('ABSPATH') || exit;

function waf_output_filter_start() {
    if (defined('WAF_ERROR_MASKING') && !WAF_ERROR_MASKING) {
        return;
    }

    ob_start(function($buffer) {
        $errorPatterns = [
            // PHP 核心错误
            '/Fatal error:/i',
            '/Parse error:/i',
            '/Warning:/i',
            '/Notice:/i',
            '/Deprecated:/i',
            '/Strict Standards:/i',
            '/Uncaught exception/i',
            '/Stack trace:/i',
            '/thrown in\s+[^\s]+\s+on line/i',
            '/on line\s*<b>\d+<\/b>/i',
            '/on line\s+\d+/i',

            // 数据库错误
            '/mysql_error\s*\(/i',
            '/mysqli_error\s*\(/i',
            '/You have an error in your SQL syntax/i',
            '/SQL syntax.*?error/i',
            '/mysql_fetch_array\s*\(/i',
            '/mysql_num_rows\s*\(/i',
            '/mysql_query\s*\(/i',
            '/pg_query\s*\(/i',
            '/pg_last_error/i',
            '/sqlite_error/i',
            '/ORA-\d+/i',
            '/PDOException/i',
            '/SQLSTATE\[/i',

            // 文件路径泄露
            '/in\s+\/[^\s]+\.php\s+on line/i',
            '/in\s+[A-Z]:\\\\[^\s]+\.php\s+on line/i',

            // 其他敏感信息
            '/phpinfo\(\)/i',
            '/PHP Extension/i',
            '/PHP Version/i',
            '/server version/i',
            '/Apache\/\d+/i',
            '/nginx\/\d+/i',
            '/open_basedir restriction in effect/i',
            '/failed to open stream/i',
            '/No such file or directory/i',
            '/Permission denied/i',
        ];

        $matchedPattern = '';
        $isError = false;

        foreach ($errorPatterns as $pattern) {
            if (preg_match($pattern, $buffer, $matches)) {
                $isError = true;
                $matchedPattern = $matches[0] ?? $pattern;
                break;
            }
        }

        if ($isError) {
            waf_error_masking_log($buffer, $matchedPattern);
            http_response_code(500);
            header('Content-Type: text/html; charset=utf-8');
            return '<!DOCTYPE html><html><head><title>500 Internal Server Error</title><style>body{font-family:Arial,sans-serif;max-width:600px;margin:100px auto;padding:20px;text-align:center;color:#333;}h1{color:#d9534f;font-size:2em;}p{line-height:1.6;}</style></head><body><h1>内部服务器错误</h1><p>服务器遇到了一些问题，请稍后重试。</p><p>如问题持续存在，请联系网站管理员。</p></body></html>';
        }

        return $buffer;
    });
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
