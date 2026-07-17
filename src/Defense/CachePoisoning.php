<?php
defined('ABSPATH') || exit;

class CachePoisoning {
    private static $cacheBypassHeaders = [
        'X-Cache-Bypass', 'X-Cache-Control', 'X-No-Cache', 'X-Pragma',
        'X-Proxy-Cache', 'X-Varnish', 'X-Akamai-Cache-Control',
        'X-Squid-Cache-Control', 'X-CDN-Cache-Control', 'X-Redirect-By',
        'X-Cache-Key', 'X-Cache-Status', 'X-Cache-Tag', 'X-Cache-Vary',
    ];

    private static $dangerousHeaders = [
        'Set-Cookie', 'Content-Type', 'Location', 'Refresh',
        'Content-Disposition', 'X-Content-Type-Options', 'X-XSS-Protection',
        'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security',
    ];

    private static $cachePoisoningPatterns = [
        ['pattern' => '/%0d%0a(?:Set-Cookie|Location|Content-Type):/i', 'name' => 'CRLF injection for cache poisoning'],
        ['pattern' => '/\r\n(?:Set-Cookie|Location|Content-Type):/i', 'name' => 'CRLF injection for cache poisoning'],
        ['pattern' => '/(?=.*\r\n)(?=.*Set-Cookie:)/i', 'name' => 'Potential cache poisoning via Set-Cookie'],
        ['pattern' => '/(?=.*\r\n)(?=.*Location:)/i', 'name' => 'Potential cache poisoning via Location'],
        ['pattern' => '/(?=.*\r\n)(?=.*Content-Type:)/i', 'name' => 'Potential cache poisoning via Content-Type'],
        ['pattern' => '/X-Custom-IP-Authorization:/i', 'name' => 'IP spoofing for cache poisoning'],
        ['pattern' => '/X-Forwarded-For:\s*(?:127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/i', 'name' => 'Private IP in X-Forwarded-For'],
        ['pattern' => '/X-Real-IP:\s*(?:127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/i', 'name' => 'Private IP in X-Real-IP'],
    ];

    private static $varyHeaders = [
        'Accept', 'Accept-Encoding', 'Accept-Language', 'User-Agent',
        'Cookie', 'Referer', 'Authorization', 'Origin',
        'X-Requested-With', 'Content-Type', 'X-CSRF-Token',
    ];

    public static function check() {
        self::checkCacheBypassHeaders();
        self::checkDangerousHeaderInjection();
        self::checkPoisoningPatterns();
        self::checkVaryHeaderManipulation();
        self::checkQueryStringPoisoning();
        self::checkHostHeaderPoisoning();
    }

    private static function checkCacheBypassHeaders() {
        $headers = getallheaders();
        foreach ($headers as $name => $value) {
            if (in_array($name, self::$cacheBypassHeaders)) {
                if (self::isSuspiciousValue($value)) {
                    waf_block('Cache poisoning - suspicious cache bypass header: ' . $name);
                }
            }
        }
    }

    private static function checkDangerousHeaderInjection() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            foreach (self::$dangerousHeaders as $header) {
                if (stripos($value, $header . ':') !== false) {
                    waf_block('Cache poisoning - dangerous header injection: ' . $header);
                }
            }
        }
    }

    private static function checkPoisoningPatterns() {
        $inputs = self::collectInputs();
        $headers = getallheaders();
        
        foreach (array_merge($inputs, $headers) as $value) {
            $value = (string)$value;
            foreach (self::$cachePoisoningPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    waf_block('Cache poisoning - ' . $pattern['name']);
                }
            }
        }
    }

    private static function checkVaryHeaderManipulation() {
        $headers = getallheaders();
        if (isset($headers['Vary'])) {
            $varyValue = $headers['Vary'];
            if (strlen($varyValue) > 500) {
                waf_block('Cache poisoning - Vary header too large');
            }
            
            $parts = array_map('trim', explode(',', $varyValue));
            foreach ($parts as $part) {
                if (!in_array($part, self::$varyHeaders) && !empty($part)) {
                    waf_block('Cache poisoning - suspicious Vary header value: ' . $part);
                }
            }
        }
    }

    private static function checkQueryStringPoisoning() {
        $queryString = $_SERVER['QUERY_STRING'] ?? '';
        if (empty($queryString)) return;

        $params = [];
        parse_str($queryString, $params);
        
        foreach ($params as $key => $value) {
            $key = strtolower($key);
            
            if (strpos($key, 'cache') !== false || strpos($key, 'proxy') !== false) {
                if (self::isSuspiciousValue((string)$value)) {
                    waf_block('Cache poisoning - suspicious cache-related parameter: ' . $key);
                }
            }
            
            if (strpos($key, 'set-cookie') !== false || strpos($key, 'location') !== false) {
                waf_block('Cache poisoning - dangerous parameter name: ' . $key);
            }
        }
    }

    private static function checkHostHeaderPoisoning() {
        $headers = getallheaders();
        $hostHeader = $headers['Host'] ?? ($_SERVER['HTTP_HOST'] ?? '');
        
        if (preg_match('/[\r\n%0d%0a]/i', $hostHeader)) {
            waf_block('Cache poisoning - Host header injection');
        }

        if (preg_match('/^(127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.0\.0\.0)/', $hostHeader)) {
            waf_block('Cache poisoning - private IP in Host header');
        }

        $xForwardedHost = $headers['X-Forwarded-Host'] ?? '';
        if (preg_match('/[\r\n%0d%0a]/i', $xForwardedHost)) {
            waf_block('Cache poisoning - X-Forwarded-Host header injection');
        }
    }

    private static function collectInputs() {
        $inputs = [];
        foreach ($_GET as $v) {
            $inputs[] = (string)$v;
        }
        foreach ($_POST as $v) {
            $inputs[] = (string)$v;
        }
        foreach ($_COOKIE as $v) {
            $inputs[] = (string)$v;
        }
        return $inputs;
    }

    private static function isSuspiciousValue($value) {
        $suspiciousPatterns = [
            '/[\r\n%0d%0a]/i',
            '/<script/i',
            '/javascript:/i',
            '/onload|onerror|onclick/i',
            '/alert\(/i',
            '/document\.cookie/i',
            '/location\.href/i',
            '/eval\(/i',
            '/base64/i',
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        return false;
    }
}