<?php
defined('ABSPATH') || exit;

class CachePoisoning {
    /**
     * 兼容 nginx/php-fpm/CLI：getallheaders() 仅在 Apache/mod_php 或 PHP 7.3+ SAPI 中可用
     * 修复：原实现存在无限递归 bug（self::getAllHeadersCompat() 自调用）
     */
    private static function getAllHeadersCompat(): array {
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (is_array($headers) && !empty($headers)) {
                return $headers;
            }
            // getallheaders() 返回空时（部分 SAPI 行为），回退到 $_SERVER 遍历
        }
        $headers = [];
        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') === 0) {
                $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))));
                $headers[$name] = $v;
            }
        }
        // Content-Type 和 Content-Length 不是 HTTP_ 开头，单独补上
        if (isset($_SERVER['CONTENT_TYPE']) && !isset($headers['Content-Type'])) {
            $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH']) && !isset($headers['Content-Length'])) {
            $headers['Content-Length'] = $_SERVER['CONTENT_LENGTH'];
        }
        return $headers;
    }

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
        ['pattern' => '/X-Forwarded-For:\s*(?:127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/i', 'name' => 'Private IP at start of X-Forwarded-For'],
        ['pattern' => '/X-Real-IP:\s*(?:127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/i', 'name' => 'Private IP in X-Real-IP'],
    ];

    private static $varyHeaders = [
        'Accept', 'Accept-Encoding', 'Accept-Language', 'User-Agent',
        'Cookie', 'Referer', 'Authorization', 'Origin',
        'X-Requested-With', 'Content-Type', 'X-CSRF-Token',
    ];

    // 缓存的合并大正则（首次使用时构建）
    private static $combinedCachePattern = null;

    /**
     * 把所有 cachePoisoningPatterns 合并为单个 alternation 大正则。
     * 原 patterns 全部带 /i 修饰符，统一加 /i 安全。
     */
    private static function getCombinedCachePattern() {
        if (self::$combinedCachePattern !== null) {
            return self::$combinedCachePattern;
        }
        $parts = [];
        foreach (self::$cachePoisoningPatterns as $p) {
            $pattern = $p['pattern'];
            // 解析 /body/flags 形式：精确分离 body 与 flags，避免 trim() 残留 'i' 进 body
            $lastSlash = strrpos($pattern, '/');
            $body = ($lastSlash !== false && $lastSlash > 0)
                ? substr($pattern, 1, $lastSlash - 1)
                : substr($pattern, 1);
            $parts[] = '(?:' . $body . ')';
        }
        self::$combinedCachePattern = '/' . implode('|', $parts) . '/i';
        return self::$combinedCachePattern;
    }

    public static function check() {
        self::checkCacheBypassHeaders();
        self::checkDangerousHeaderInjection();
        self::checkPoisoningPatterns();
        self::checkVaryHeaderManipulation();
        self::checkQueryStringPoisoning();
        self::checkHostHeaderPoisoning();
    }

    private static function checkCacheBypassHeaders() {
        $headers = self::getAllHeadersCompat();
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
            if (!is_string($value)) continue;
            foreach (self::$dangerousHeaders as $header) {
                $needle = $header . ':';
                $pos = stripos($value, $needle);
                while ($pos !== false) {
                    // 仅当前面紧邻 CRLF（真正的头部注入）才告警，避免 multipart 表单字段误报
                    $before = $pos - 2;
                    if ($before >= 0 && substr($value, $before, 2) === "\r\n") {
                        waf_block('Cache poisoning - dangerous header injection: ' . $header);
                    }
                    $pos = stripos($value, $needle, $pos + 1);
                }
            }
        }
    }

    private static function checkPoisoningPatterns() {
        $inputs = self::collectInputs();
        $headers = self::getAllHeadersCompat();

        $combined = self::getCombinedCachePattern();
        foreach (array_merge($inputs, $headers) as $value) {
            if (!is_string($value)) {
                $value = (string)$value;
            }
            if ($value === '') continue;

            // 长度上限：超过 8KB 只扫前 8KB
            if (strlen($value) > 8192) {
                $value = substr($value, 0, 8192);
            }

            // 廉价预筛：cachePoisoningPatterns 全部要求出现 ':' (header 形式)；
            // 此外 CRLF/URL编码分支还需要 \r 或 \n 或 %；纯 X-Header 分支需要 'X-'。
            // 由于所有 patterns 均含 ':'，先检 ':' 即可廉价排除绝大多数安全输入。
            if (strpos($value, ':') === false
                && stripos($value, 'http') === false
                && strpos($value, "\n") === false) {
                continue;
            }

            // 合并大正则做一次廉价筛除
            if (!preg_match($combined, $value)) {
                continue;
            }

            // 大正则命中后逐条匹配以还原具体名称
            foreach (self::$cachePoisoningPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    waf_block('Cache poisoning - ' . $pattern['name']);
                }
            }
        }
    }

    private static function checkVaryHeaderManipulation() {
        $headers = self::getAllHeadersCompat();
        if (isset($headers['Vary'])) {
            $varyValue = $headers['Vary'];
            if (strlen($varyValue) > 500) {
                waf_block('Cache poisoning - Vary header too large');
            }
            
            $parts = array_map('trim', explode(',', $varyValue));
            foreach ($parts as $part) {
                if ($part === '*') continue;
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

            // 使用边界匹配避免子串误报（如 mylocation、geolocation 误报）
            $isCacheParam = preg_match('/(^|[_-])cache($|[_-])/i', $key) === 1
                          || preg_match('/(^|[_-])proxy($|[_-])/i', $key) === 1;
            if ($isCacheParam) {
                if (self::isSuspiciousValue((string)$value)) {
                    waf_block('Cache poisoning - suspicious cache-related parameter: ' . $key);
                }
            }

            $isCookieParam = preg_match('/(^|[_-])set[_-]?cookie($|[_-])/i', $key) === 1;
            $isLocationParam = preg_match('/(^|[_-])location($|[_-])/i', $key) === 1;
            if ($isCookieParam || $isLocationParam) {
                waf_block('Cache poisoning - dangerous parameter name: ' . $key);
            }
        }
    }

    private static function checkHostHeaderPoisoning() {
        $headers = self::getAllHeadersCompat();
        $hostHeader = $headers['Host'] ?? ($_SERVER['HTTP_HOST'] ?? '');

        // 注：原正则 /[\r\n%0d%0a]/i 是字符类，会把 %、0、d、a 当成单独字符匹配，
        // 导致 "localhost" 含 0/d/a 也被命中触发首页403。改为正确字面量匹配 CRLF 编码序列。
        if (preg_match('/(?:\r\n|\n|\r|%0d%0a|%0a%0d|%0d|%0a)/i', $hostHeader)) {
            waf_block('Cache poisoning - Host header injection');
        }

        if (self::isPrivateHost($hostHeader)) {
            waf_block('Cache poisoning - private IP in Host header');
        }

        $xForwardedHost = $headers['X-Forwarded-Host'] ?? '';
        if (preg_match('/(?:\r\n|\n|\r|%0d%0a|%0a%0d|%0d|%0a)/i', $xForwardedHost)) {
            waf_block('Cache poisoning - X-Forwarded-Host header injection');
        }
        if (self::isPrivateHost($xForwardedHost)) {
            waf_block('Cache poisoning - private IP in X-Forwarded-Host');
        }
    }

    /**
     * 检测 Host/X-Forwarded-Host 是否指向内网/回环地址
     * 覆盖：
     *   IPv4: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 0.0.0.0, 169.254.0.0/16
     *   IPv6: ::1, ::, ::ffff:0:0/96 (IPv4-mapped), fc00::/7 (ULA), fe80::/10 (link-local)
     * 兼容可选方括号包裹的 IPv6 文本：[::1] / [::ffff:127.0.0.1]
     */
    private static function isPrivateHost($host) {
        if ($host === '') {
            return false;
        }
        // 去掉 IPv6 字面量的方括号（用于请求行中的 Host: [::1]:80 形式）
        $stripped = $host;
        if ($stripped[0] === '[') {
            $rb = strpos($stripped, ']');
            if ($rb !== false) {
                $stripped = substr($stripped, 1, $rb - 1);
            }
        }
        // 去掉尾部端口
        // IPv4:  host:port   e.g. 127.0.0.1:8080
        // IPv6:  [::1]:port  已剥括号，剩下 "::1:port" 形式；
        //   这里用最末一个 ':' 切分需谨慎。优先看是否含多个 ':'：含则视为 IPv6+端口。
        $colonCount = substr_count($stripped, ':');
        if ($colonCount === 1) {
            // IPv4 + 端口
            $stripped = strstr($stripped, ':', true);
        } elseif ($colonCount > 1) {
            // IPv6 文本 + 端口：最末 ':数字' 是端口
            if (preg_match('/^(.*):(\d+)$/', $stripped, $m)) {
                $stripped = $m[1];
            }
        }

        // IPv4 私网/回环
        if (preg_match('/^(127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.0\.0\.0|169\.254\.)/', $stripped)) {
            return true;
        }

        // IPv6 回环 ::1 / 未指定 ::
        if ($stripped === '::1' || $stripped === '::') {
            return true;
        }
        // IPv4-mapped IPv6: ::ffff:0:0/96 —— 任意 ::ffff:a.b.c.d
        if (preg_match('/^::ffff:[0-9a-fA-F:\.]+$/', $stripped)) {
            // 提取最后的 IPv4 段（最后 4 段以 . 分隔）
            $lastColon = strrpos($stripped, ':');
            $ipv4Part = $lastColon !== false ? substr($stripped, $lastColon + 1) : $stripped;
            if (preg_match('/^(127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.0\.0\.0|169\.254\.)/', $ipv4Part)) {
                return true;
            }
            // 任何 ::ffff: 前缀都算走 IPv4-mapped 段，本身就属于私网映射（攻击面 100%）
            return true;
        }
        // IPv6 ULA fc00::/7  (fc00-fdff)
        if (preg_match('/^f[cd][0-9a-fA-F]{2}:/i', $stripped)) {
            return true;
        }
        // IPv6 link-local fe80::/10
        if (preg_match('/^fe[89ab][0-9a-fA-F]?:/i', $stripped)) {
            return true;
        }
        // 环回主机名
        $lower = strtolower($stripped);
        if ($lower === 'localhost' || strpos($lower, 'localhost.') === 0) {
            return true;
        }
        return false;
    }

    private static function collectInputs() {
        $inputs = [];
        foreach ($_GET as $v) {
            self::flattenInput($v, $inputs);
        }
        foreach ($_POST as $v) {
            self::flattenInput($v, $inputs);
        }
        foreach ($_COOKIE as $v) {
            self::flattenInput($v, $inputs);
        }
        return $inputs;
    }

    private static function flattenInput($value, &$inputs) {
        if (is_array($value)) {
            foreach ($value as $item) {
                self::flattenInput($item, $inputs);
            }
        } elseif (is_string($value)) {
            $inputs[] = $value;
        } else {
            $inputs[] = (string)$value;
        }
    }

    private static function isSuspiciousValue($value) {
        $suspiciousPatterns = [
            // 注：原 /[\r\n%0d%0a]/ 是字符类，会误匹配含 %、0、d、a 的正常值。
            // 改为字面量匹配 CRLF 实际字符或其URL编码序列。
            '/(?:\r\n|\n|\r|%0d%0a|%0a%0d|%0d|%0a)/i',
            '/<script/i',
            '/javascript:/i',
            // 限定为 <... onload= 组合，避免单词 onload 在合法内容中误报
            '/<[^>]*\bonload\s*=/i',
            '/<[^>]*\bonerror\s*=/i',
            '/<[^>]*\bonclick\s*=/i',
            '/alert\(/i',
            '/document\.cookie/i',
            '/location\.href/i',
            '/eval\(/i',
            // 限定为 data:...;base64, 组合，避免 base64 单词误报
            '/data:[^;]*;base64,/i',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        return false;
    }
}