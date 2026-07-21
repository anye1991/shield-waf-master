<?php
defined('ABSPATH') || exit;

class CrlfInjection {
    private static $crlfPatterns = [
        ['pattern' => '/(?:\r\n|\n){2}/', 'name' => 'Double CRLF/LF (header injection)'],
        ['pattern' => '/(?:\r\n|\n)(?:Location|Set-Cookie|Content-Type|Content-Length|Server|Date|Connection|Cache-Control|Expires|ETag|Vary|Via):/i', 'name' => 'Header injection attempt'],
        ['pattern' => '/(?:\r\n|\n)X-[A-Za-z][A-Za-z0-9-]*:/i', 'name' => 'X-header injection attempt'],
        ['pattern' => '/(?:\r\n|\n)X-Forwarded-(For|Host|Proto|Port|Protocol|Scheme|Server|By):/i', 'name' => 'X-Forwarded header injection'],
        ['pattern' => '/(?:\r\n|\n)X-(Real|Client|Originating|Remote)-IP:/i', 'name' => 'IP spoofing header injection'],
        ['pattern' => '/(?:\r\n|\n)X-(Host|Requested-With|HTTP-Method-Override):/i', 'name' => 'X-header injection'],
        ['pattern' => '/(?:\r\n|\n)X-Custom-IP-Authorization:/i', 'name' => 'Custom IP auth header injection'],
    ];

    private static $newlinePatterns = [
        ['pattern' => '/\r\n/', 'name' => 'CRLF sequence'],
        ['pattern' => '/\r(?!\n)/', 'name' => 'Standalone carriage return'],
        ['pattern' => '/(?<!\r)\n/', 'name' => 'Standalone newline'],
        ['pattern' => '/%0d%0a/i', 'name' => 'URL-encoded CRLF'],
        ['pattern' => '/%0d/i', 'name' => 'URL-encoded carriage return'],
        ['pattern' => '/%0a/i', 'name' => 'URL-encoded newline'],
        ['pattern' => '/\\\\r\\\\n/', 'name' => 'Escaped CRLF'],
        ['pattern' => '/\\\\r/', 'name' => 'Escaped carriage return'],
        ['pattern' => '/\\\\n/', 'name' => 'Escaped newline'],
        ['pattern' => '/\\\\x0d\\\\x0a/', 'name' => 'Hex CRLF'],
        ['pattern' => '/\\\\x0d/', 'name' => 'Hex carriage return'],
        ['pattern' => '/\\\\x0a/', 'name' => 'Hex newline'],
        ['pattern' => '/\\\\u000d\\\\u000a/', 'name' => 'Unicode escape CRLF'],
        ['pattern' => '/\\\\u000d/', 'name' => 'Unicode escape carriage return'],
        ['pattern' => '/\\\\u000a/', 'name' => 'Unicode escape newline'],
        ['pattern' => '/\\\\0d\\\\0a/', 'name' => 'Octal CRLF'],
        ['pattern' => '/\\\\0d/', 'name' => 'Octal carriage return'],
        ['pattern' => '/\\\\0a/', 'name' => 'Octal newline'],
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

    // 缓存的合并大正则（首次使用时构建）
    private static $combinedCrlfPattern = null;
    private static $combinedNewlineNoI = null;
    private static $combinedNewlineI = null;

    /**
     * 解析 /body/flags 形式的正则，返回 [body, flags]
     * 用于安全合并：trim($p, '/') 会把带 /i 后缀的 pattern 残留 'i' 进 body，
     * 导致合并大正则中出现裸 '/'，触发 "Unknown modifier" 错误。这里改为
     * 精确分离 body 与 flags。
     */
    private static function splitPatternFlags($pattern) {
        // 第一个字符必须是 '/'，最后一个 '/' 之后是 flags
        $firstSlash = 0; // 已知以 '/' 开头
        $lastSlash = strrpos($pattern, '/');
        if ($lastSlash === false || $lastSlash === 0) {
            return [substr($pattern, 1), ''];
        }
        $body = substr($pattern, 1, $lastSlash - 1);
        $flags = substr($pattern, $lastSlash + 1);
        return [$body, $flags];
    }

    /**
     * 把所有 crlfPatterns 合并为单个 alternation 大正则。
     * crlfPatterns 中第 1 条原无 /i 修饰符，但其内容 (\r\n 字节) 无字母，/i 无副作用；
     * 第 2-7 条原本就有 /i。统一加 /i 安全。
     */
    private static function getCombinedCrlfPattern() {
        if (self::$combinedCrlfPattern !== null) {
            return self::$combinedCrlfPattern;
        }
        $parts = [];
        foreach (self::$crlfPatterns as $p) {
            list($body, $_) = self::splitPatternFlags($p['pattern']);
            $parts[] = '(?:' . $body . ')';
        }
        self::$combinedCrlfPattern = '/' . implode('|', $parts) . '/i';
        return self::$combinedCrlfPattern;
    }

    /**
     * 把 newlinePatterns 按是否有 /i 修饰符分两组分别合并，确保不改变大小写敏感行为。
     * - 带 /i 的 (URL-encoded %0d/%0a 等) 合并到 $combinedNewlineI
     * - 不带 /i 的 (raw/escaped 字节序列) 合并到 $combinedNewlineNoI
     */
    private static function getCombinedNewlineNoI() {
        if (self::$combinedNewlineNoI !== null) {
            return self::$combinedNewlineNoI;
        }
        $parts = [];
        foreach (self::$newlinePatterns as $p) {
            list($body, $flags) = self::splitPatternFlags($p['pattern']);
            // 仅保留不带 i 修饰符的 pattern
            if (strpos($flags, 'i') !== false) {
                continue;
            }
            $parts[] = '(?:' . $body . ')';
        }
        self::$combinedNewlineNoI = '/' . implode('|', $parts) . '/';
        return self::$combinedNewlineNoI;
    }

    private static function getCombinedNewlineI() {
        if (self::$combinedNewlineI !== null) {
            return self::$combinedNewlineI;
        }
        $parts = [];
        foreach (self::$newlinePatterns as $p) {
            list($body, $flags) = self::splitPatternFlags($p['pattern']);
            // 仅保留带 i 修饰符的 pattern
            if (strpos($flags, 'i') === false) {
                continue;
            }
            $parts[] = '(?:' . $body . ')';
        }
        self::$combinedNewlineI = '/' . implode('|', $parts) . '/i';
        return self::$combinedNewlineI;
    }

    public static function check($get = null, $post = null, $headers = '') {
        $targets = self::collectTargets($get, $post);

        foreach ($targets as $target) {
            if (!is_string($target)) continue;

            // 长度上限：超过 8KB 只扫前 8KB
            if (strlen($target) > 8192) {
                $target = substr($target, 0, 8192);
            }

            // 廉价预筛：所有 crlfPatterns 与 newlinePatterns 都要求出现
            //   raw \r 或 \n、或 URL 编码 %、或反斜杠转义 \ 才可能命中
            if (strpos($target, "\r") === false
                && strpos($target, "\n") === false
                && strpos($target, '%') === false
                && strpos($target, '\\') === false) {
                continue;
            }

            // 合并大正则做廉价筛除：crlfPatterns
            if (preg_match(self::getCombinedCrlfPattern(), $target)) {
                foreach (self::$crlfPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $target)) {
                        waf_block('CRLF injection - ' . $pattern['name']);
                    }
                }
            }

            // 合并大正则做廉价筛除：newlinePatterns (按 /i 分两组)
            if (preg_match(self::getCombinedNewlineNoI(), $target)
                || preg_match(self::getCombinedNewlineI(), $target)) {
                foreach (self::$newlinePatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $target)) {
                        if (self::isHeaderInjection($target)) {
                            waf_block('CRLF injection - ' . $pattern['name'] . ' (header injection)');
                        }
                    }
                }
            }
        }

        self::checkHeaderInjectionInRequest();
    }

    private static function collectTargets($get = null, $post = null) {
        $targets = [];

        if ($get !== null) {
            foreach ($get as $v) {
                foreach (self::flattenValue($v) as $fv) {
                    $targets[] = $fv;
                }
            }
        } else {
            foreach ($_GET as $v) {
                foreach (self::flattenValue($v) as $fv) {
                    $targets[] = $fv;
                }
            }
        }

        if ($post !== null) {
            foreach ($post as $v) {
                foreach (self::flattenValue($v) as $fv) {
                    $targets[] = $fv;
                }
            }
        } else {
            foreach ($_POST as $v) {
                foreach (self::flattenValue($v) as $fv) {
                    $targets[] = $fv;
                }
            }
        }

        foreach ($_COOKIE as $v) {
            foreach (self::flattenValue($v) as $fv) {
                $targets[] = $fv;
            }
        }

        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
        if (!empty($body)) {
            $targets[] = $body;
        }

        // 兼容 nginx/php-fpm/CLI：getallheaders() 仅在 Apache/mod_php 或 PHP 7.3+ SAPI 中可用
        // 注意：getallheaders() 返回空数组时也必须走 $_SERVER 回退分支
        $headers = [];
        if (function_exists('getallheaders')) {
            $gh = getallheaders();
            if (is_array($gh)) {
                $headers = $gh;
            }
        }
        if (empty($headers)) {
            foreach ($_SERVER as $k => $v) {
                if (strpos($k, 'HTTP_') === 0) {
                    $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))));
                    $headers[$name] = $v;
                }
            }
        }
        foreach ($headers as $k => $v) {
            if (in_array($k, self::$headerNames)) {
                foreach (self::flattenValue($v) as $fv) {
                    $targets[] = $fv;
                }
            }
        }

        return $targets;
    }

    private static function flattenValue($value) {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $v) {
                foreach (self::flattenValue($v) as $fv) {
                    $out[] = $fv;
                }
            }
            return $out;
        }
        if (is_scalar($value) || (is_object($value) && method_exists($value, '__toString'))) {
            return [(string)$value];
        }
        return [];
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
        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
        if (empty($body)) return;

        foreach (self::$headerNames as $headerName) {
            $pattern = '/\r\n' . preg_quote($headerName, '/') . ':/i';
            if (preg_match($pattern, $body)) {
                waf_block('CRLF injection - header injection via request body');
            }
        }
    }
}