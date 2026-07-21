<?php
defined('ABSPATH') || exit;

class RequestSmuggling {
    private static $clTeConflictingHeaders = [
        'content-length',
        'transfer-encoding',
    ];

    private static $chunkedEncodingPatterns = [
        '/^[0-9a-fA-F]+(?:\r\n|\n)/',
        '/0(?:\r\n\r\n|\n\n|\r\n)$/m',
    ];

    public static function check() {
        $result = self::detectSmuggling();
        if ($result['is_smuggling']) {
            waf_block('HTTP Request Smuggling detected - ' . $result['reason']);
        }
    }

    private static function detectSmuggling() {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerName = str_replace('_', '-', strtolower(substr($key, 5)));
                $headers[$headerName] = $value;
            }
        }

        $hasCl = isset($headers['content-length']);
        $hasTe = isset($headers['transfer-encoding']);

        if ($hasCl && $hasTe) {
            $clValue = $headers['content-length'];
            $teValue = $headers['transfer-encoding'];

            if (strtolower($teValue) === 'chunked') {
                return ['is_smuggling' => true, 'reason' => 'Both Content-Length and Transfer-Encoding: chunked present'];
            }

            if (preg_match('/chunked/i', $teValue)) {
                return ['is_smuggling' => true, 'reason' => 'Transfer-Encoding contains chunked with Content-Length'];
            }
        }

        if ($hasTe) {
            $teValue = $headers['transfer-encoding'];
            // 仅当 TE 中出现 2 个或以上 chunked 时才告警；单个 chunked 是合法的，chunked+identity 也是合法组合
            if (preg_match('/chunked[\s,]+[^,]*chunked/i', $teValue)) {
                return ['is_smuggling' => true, 'reason' => 'Multiple chunked values in Transfer-Encoding'];
            }
        }

        if ($hasCl) {
            $clValue = $headers['content-length'];
            if (preg_match('/^\s*\d+\s*(,\s*\d+\s*)+$/', $clValue)) {
                return ['is_smuggling' => true, 'reason' => 'Multiple Content-Length values'];
            }

            if (preg_match('/^\s*\+?\d+\s*$/', $clValue) === false) {
                return ['is_smuggling' => true, 'reason' => 'Invalid Content-Length format'];
            }
        }

        if ($hasTe && strtolower($headers['transfer-encoding']) === 'chunked') {
            $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
            if (!empty($body)) {
                foreach (self::$chunkedEncodingPatterns as $pattern) {
                    if (!preg_match($pattern, $body)) {
                        return ['is_smuggling' => true, 'reason' => 'Invalid chunked encoding format'];
                    }
                }
            }
        }

        $contentType = $headers['content-type'] ?? '';
        if (!empty($contentType) && !empty($headers['content-length'])) {
            $expectedSize = (int)$headers['content-length'];
            $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
            $actualSize = strlen($body);

            // 仅当 body 比 CL 长（差异 > 1024）才告警；body 比 CL 短是常态（连接中断、代理截断、php://input 被上游消费等）
            if ($actualSize > $expectedSize + 1024) {
                return ['is_smuggling' => true, 'reason' => "Content-Length mismatch: expected $expectedSize, got $actualSize"];
            }
        }

        $hostHeader = $headers['host'] ?? '';
        if (!empty($hostHeader)) {
            if (preg_match('/[\r\n]/', $hostHeader)) {
                return ['is_smuggling' => true, 'reason' => 'Host header contains newline characters'];
            }

            if (strpos($hostHeader, ' ') !== false) {
                return ['is_smuggling' => true, 'reason' => 'Host header contains spaces'];
            }
        }

        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n]/', $value)) {
                return ['is_smuggling' => true, 'reason' => "Header '$name' contains newline characters"];
            }
        }

        return ['is_smuggling' => false, 'reason' => ''];
    }
}
