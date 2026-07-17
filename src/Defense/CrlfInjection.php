<?php
defined('ABSPATH') || exit;

class CrlfInjection {
    private static $crlfPatterns = [
        ['pattern' => '/\r\n\r\n/', 'name' => 'Double CRLF (header injection)'],
        ['pattern' => '/\r\n(Location|Set-Cookie|Content-Type|Content-Length|Server|Date|Connection|Cache-Control|Expires|ETag|Vary|Via):/i', 'name' => 'Header injection attempt'],
        ['pattern' => '/\r\nX-[A-Za-z-]+:/i', 'name' => 'X-header injection attempt'],
        ['pattern' => '/\r\nX-Forwarded-(For|Host|Proto|Port|Protocol|Scheme|Server|By):/i', 'name' => 'X-Forwarded header injection'],
        ['pattern' => '/\r\nX-(Real|Client|Originating|Remote)-IP:/i', 'name' => 'IP spoofing header injection'],
        ['pattern' => '/\r\nX-(Host|Requested-With|HTTP-Method-Override):/i', 'name' => 'X-header injection'],
        ['pattern' => '/\r\nX-Custom-IP-Authorization:/i', 'name' => 'Custom IP auth header injection'],
    ];

    private static $newlinePatterns = [
        ['pattern' => '/\r\n/', 'name' => 'CRLF sequence'],
        ['pattern' => '/\r(?!\n)/', 'name' => 'Standalone carriage return'],
        ['pattern' => '/\n(?!\r)/', 'name' => 'Standalone newline'],
        ['pattern' => '/%0d%0a/i', 'name' => 'URL-encoded CRLF'],
        ['pattern' => '/%0d/i', 'name' => 'URL-encoded carriage return'],
        ['pattern' => '/%0a/i', 'name' => 'URL-encoded newline'],
        ['pattern' => '/\\r\\n/', 'name' => 'Escaped CRLF'],
        ['pattern' => '/\\r/', 'name' => 'Escaped carriage return'],
        ['pattern' => '/\\n/', 'name' => 'Escaped newline'],
        ['pattern' => '/\\x0d\\x0a/', 'name' => 'Hex CRLF'],
        ['pattern' => '/\\x0d/', 'name' => 'Hex carriage return'],
        ['pattern' => '/\\x0a/', 'name' => 'Hex newline'],
        ['pattern' => '/\\u000d\\u000a/', 'name' => 'Unicode CRLF'],
        ['pattern' => '/\\u000d/', 'name' => 'Unicode carriage return'],
        ['pattern' => '/\\u000a/', 'name' => 'Unicode newline'],
        ['pattern' => '/\\0d\\0a/', 'name' => 'Octal CRLF'],
        ['pattern' => '/\\0d/', 'name' => 'Octal carriage return'],
        ['pattern' => '/\\0a/', 'name' => 'Octal newline'],
        ['pattern' => '/\x0d\x0a/', 'name' => 'Raw CRLF'],
        ['pattern' => '/\x0d/', 'name' => 'Raw carriage return'],
        ['pattern' => '/\x0a/', 'name' => 'Raw newline'],
    ];

    private static $headerNames = [
        'Location', 'Set-Cookie', 'Content-Type', 'Content-Length',
        'Server', 'Date', 'Connection', 'Cache-Control', 'Expires',
        'ETag', 'Vary', 'Via', 'X-Forwarded-For', 'X-Forwarded-Host',
        'X-Forwarded-Proto', 'X-Real-IP', 'X-Client-IP', 'Host',
        'Referer', 'User-Agent', 'Content-Disposition', 'Transfer-Encoding',
        'Authorization', 'Proxy-Authorization', 'Cookie', 'X-Custom-IP-Authorization'
    ];

    public static function check() {
        $targets = self::collectTargets();
        
        foreach ($targets as $target) {
            foreach (self::$crlfPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $target)) {
                    waf_block('CRLF injection - ' . $pattern['name']);
                }
            }

            foreach (self::$newlinePatterns as $pattern) {
                if (preg_match($pattern['pattern'], $target)) {
                    if (self::isHeaderInjection($target)) {
                        waf_block('CRLF injection - ' . $pattern['name'] . ' (header injection)');
                    }
                }
            }
        }

        self::checkHeaderInjectionInRequest();
    }

    private static function collectTargets() {
        $targets = [];
        
        foreach ($_GET as $v) {
            $targets[] = (string)$v;
        }
        foreach ($_POST as $v) {
            $targets[] = (string)$v;
        }
        foreach ($_COOKIE as $v) {
            $targets[] = (string)$v;
        }

        $body = file_get_contents('php://input');
        if (!empty($body)) {
            $targets[] = $body;
        }

        $headers = getallheaders();
        foreach ($headers as $k => $v) {
            if (in_array($k, self::$headerNames)) {
                $targets[] = (string)$v;
            }
        }

        return $targets;
    }

    private static function isHeaderInjection($value) {
        $headerKeywords = ['Location:', 'Set-Cookie:', 'Content-Type:', 'Content-Length:', 'Server:', 'X-'];
        foreach ($headerKeywords as $keyword) {
            if (stripos($value, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function checkHeaderInjectionInRequest() {
        $body = file_get_contents('php://input');
        if (empty($body)) return;

        foreach (self::$headerNames as $headerName) {
            $pattern = '/\r\n' . preg_quote($headerName, '/') . ':/i';
            if (preg_match($pattern, $body)) {
                waf_block('CRLF injection - header injection via request body');
            }
        }
    }
}