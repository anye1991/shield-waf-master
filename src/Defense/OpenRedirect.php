<?php
defined('ABSPATH') || exit;

class OpenRedirect {
    private static $redirectParamNames = [
        'redirect', 'redirect_url', 'redirect_to', 'redirect_uri',
        'next', 'return', 'return_url', 'return_to',
        'go', 'url', 'link', 'href',
        'callback', 'target', 'dest', 'destination',
        'forward', 'forward_url',
        'continue', 'continue_url',
        'success_url', 'error_url', 'cancel_url',
        'logout_url', 'login_redirect',
        'redirect_url', 'redir', 'redirecturl',
        'page', 'location', 'goto',
        'view', 'path', 'action_url',
    ];

    private static $externalUrlPatterns = [
        ['pattern' => '/^\/\//', 'severity' => 80, 'name' => 'Protocol-relative URL (//)', 'category' => 'external'],
        ['pattern' => '/^https?:\/\//i', 'severity' => 70, 'name' => 'Absolute HTTP/HTTPS URL', 'category' => 'external'],
        ['pattern' => '/^ftp:\/\//i', 'severity' => 65, 'name' => 'Absolute FTP URL', 'category' => 'external'],
        ['pattern' => '/javascript:/i', 'severity' => 90, 'name' => 'JavaScript URI scheme', 'category' => 'external'],
        ['pattern' => '/data:/i', 'severity' => 85, 'name' => 'Data URI scheme', 'category' => 'external'],
        ['pattern' => '/^(?:file|jar|netdoc|vbscript|ldap|php|expect|phar):\/\//i', 'severity' => 60, 'name' => 'Dangerous URI scheme', 'category' => 'external'],
    ];

    private static $encodedUrlPatterns = [
        ['pattern' => '/%68%74%74%70%3a%2f%2f/i', 'severity' => 85, 'name' => 'URL-encoded http://', 'category' => 'encoded'],
        ['pattern' => '/%68%74%74%70%73%3a%2f%2f/i', 'severity' => 85, 'name' => 'URL-encoded https://', 'category' => 'encoded'],
        ['pattern' => '/%2f%2f/i', 'severity' => 60, 'name' => 'URL-encoded double slash //', 'category' => 'encoded'],
        ['pattern' => '/%2f%2f%40/i', 'severity' => 70, 'name' => 'URL-encoded //@', 'category' => 'encoded'],
    ];

    private static $multiJumpPatterns = [
        ['pattern' => '/[?&]redirect[^=]*=[^&]*[?&]redirect/i', 'severity' => 85, 'name' => 'Multi-level redirect (double redirect)', 'category' => 'multijump'],
        ['pattern' => '/[?&]next[^=]*=[^&]*[?&]next/i', 'severity' => 85, 'name' => 'Multi-level redirect (double next)', 'category' => 'multijump'],
        ['pattern' => '/redirect.*redirect/i', 'severity' => 75, 'name' => 'Multiple redirect parameters', 'category' => 'multijump'],
        ['pattern' => '/redirect.*url.*redirect/i', 'severity' => 80, 'name' => 'Nested redirect-redirect pattern', 'category' => 'multijump'],
    ];

    private static $suspiciousDomainPatterns = [
        ['pattern' => '/@/', 'severity' => 75, 'name' => '@ symbol (potential auth bypass)', 'category' => 'suspicious'],
        ['pattern' => '/%40/i', 'severity' => 70, 'name' => 'URL-encoded @ symbol', 'category' => 'suspicious'],
        ['pattern' => '/\.\./', 'severity' => 65, 'name' => 'Path traversal in redirect', 'category' => 'suspicious'],
        ['pattern' => '/\\\\/', 'severity' => 60, 'name' => 'Backslash in URL', 'category' => 'suspicious'],
    ];

    // 缓存的合并大正则（首次使用时构建），覆盖全部 18 条 patterns
    private static $combinedRedirectPattern = null;

    /**
     * 把所有 redirect 相关 patterns 合并为单个 alternation 大正则。
     * 原 patterns 中 `/^\/\//` 和 `/@/` 没有 /i，但内容不含字母，/i 无副作用；
     * 其余均带 /i。统一加 /i 安全（不改变大小写敏感行为）。
     * 注意：`^` 锚点对每个 alternation 分支局部生效，合并后行为不变。
     */
    private static function getCombinedRedirectPattern() {
        if (self::$combinedRedirectPattern !== null) {
            return self::$combinedRedirectPattern;
        }
        $parts = [];
        foreach (self::$externalUrlPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$encodedUrlPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$multiJumpPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$suspiciousDomainPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        self::$combinedRedirectPattern = '/' . implode('|', $parts) . '/i';
        return self::$combinedRedirectPattern;
    }

    /**
     * 解析 /body/flags 形式的正则，仅取 body 部分。避免 trim($p, '/') 把
     * 带 /i 后缀的 pattern 末尾 'i' 残留进 body，导致合并大正则出现裸 '/'。
     */
    private static function patternBody($pattern) {
        $lastSlash = strrpos($pattern, '/');
        if ($lastSlash === false || $lastSlash === 0) {
            return substr($pattern, 1);
        }
        return substr($pattern, 1, $lastSlash - 1);
    }

    public static function detect($inputs) {
        $score = 0;
        $details = [];
        $detected = false;

        if (!is_array($inputs) || empty($inputs)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($inputs as $key => $value) {
            // 递归展开任意深度的数组，避免对数组参数触发 (string) 转换告警
            $flatValues = self::flattenValues($value);
            foreach ($flatValues as $v) {
                $result = self::analyzeValue((string)$key, (string)$v);
                if ($result['score'] > 0) {
                    $score = max($score, $result['score']);
                    $details[] = $result;
                    if ($result['detected']) {
                        $detected = true;
                    }
                }
            }
        }

        return [
            'detected' => $detected,
            'score' => min($score, 100),
            'details' => $details,
        ];
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);
        $lowerKey = strtolower($key);
        $lowerValue = strtolower($value);
        $score = 0;
        $findings = [];

        if (empty($value)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        // 长度上限：超过 8KB 只扫前 8KB
        if (strlen($value) > 8192) {
            $value = substr($value, 0, 8192);
        }

        $isRedirectParam = self::isRedirectParam($lowerKey);
        $paramMultiplier = $isRedirectParam ? 1.0 : 0.45;

        // 廉价预筛：所有 18 条 patterns 都至少需要以下字符/子串之一才可能命中：
        //   externalUrlPatterns: ':' 或 '/'
        //   encodedUrlPatterns:  '%'
        //   multiJumpPatterns:   'redirect' 或 'next' (大小写不敏感)
        //   suspiciousDomainPatterns: '@' '%' '.' '\' 等
        // 若都不包含，直接跳过所有 18 条 preg_match。
        if (strpos($value, ':') === false
            && strpos($value, '/') === false
            && strpos($value, '@') === false
            && strpos($value, '%') === false
            && strpos($value, '\\') === false
            && stripos($value, 'redirect') === false
            && stripos($value, 'next') === false) {
            // 无任何可疑字符，但仍需走 looksLikeExternalDomain 检测（仅含字母+点+域名形式）
            if ($isRedirectParam && self::looksLikeExternalDomain($value)) {
                $domainScore = (int)(55 * $paramMultiplier);
                if ($score < $domainScore) {
                    $score = $domainScore;
                }
                $findings[] = 'Potential external domain in redirect parameter';
            }
            return [
                'detected' => $score >= 50,
                'score' => $score,
                'findings' => $findings,
                'key' => $key,
                'is_redirect_param' => $isRedirectParam,
            ];
        }

        // 合并大正则做一次廉价筛除：未命中则跳过 18 条逐条匹配
        $combined = self::getCombinedRedirectPattern();
        if (preg_match($combined, $value)) {
            foreach (self::$externalUrlPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    // 排除当前域名自己的完整 URL（如 redirect_to=https://duduziy.com/）
                    if ($pattern['category'] === 'external' && self::isCurrentDomainUrl($value)) {
                        continue;
                    }
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }

            foreach (self::$encodedUrlPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }

            foreach (self::$multiJumpPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }

            foreach (self::$suspiciousDomainPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }
        }

        // 循环解码最多 3 次，防止双重/三重编码绕过
        $decodedValue = $value;
        for ($i = 0; $i < 3; $i++) {
            $next = rawurldecode($decodedValue);
            if ($next === $decodedValue) break;
            $decodedValue = $next;
        }
        if ($decodedValue !== $value) {
            // 解码后值同样用合并大正则做廉价筛除
            if (preg_match($combined, $decodedValue)) {
                foreach (self::$externalUrlPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $decodedValue)) {
                        if ($pattern['category'] === 'external' && self::isCurrentDomainUrl($decodedValue)) {
                            continue;
                        }
                        $adjustedScore = (int)($pattern['severity'] * 0.85 * $paramMultiplier);
                        if ($score < $adjustedScore) {
                            $score = $adjustedScore;
                        }
                        $findings[] = 'Decoded: ' . $pattern['name'];
                    }
                }

                foreach (self::$multiJumpPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $decodedValue)) {
                        $adjustedScore = (int)($pattern['severity'] * 0.8 * $paramMultiplier);
                        if ($score < $adjustedScore) {
                            $score = $adjustedScore;
                        }
                        $findings[] = 'Decoded: ' . $pattern['name'];
                    }
                }
            }
        }

        if ($isRedirectParam && self::looksLikeExternalDomain($value)) {
            $domainScore = (int)(55 * $paramMultiplier);
            if ($score < $domainScore) {
                $score = $domainScore;
            }
            $findings[] = 'Potential external domain in redirect parameter';
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_redirect_param' => $isRedirectParam,
        ];
    }

    private static function isRedirectParam($key) {
        foreach (self::$redirectParamNames as $param) {
            if ($key === $param) {
                return true;
            }
            // 使用边界匹配，避免 curlpage、nextpage 等误报
            if (preg_match('/(^|_|-)' . preg_quote($param, '/') . '($|_|-)/', $key)) {
                return true;
            }
        }
        return false;
    }

    private static function flattenValues($value) {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $v) {
                foreach (self::flattenValues($v) as $fv) {
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

    private static function isCurrentDomainUrl($value) {
        $currentHost = $_SERVER['HTTP_HOST'] ?? '';
        if (!$currentHost) return false;
        $parsed = parse_url($value);
        if ($parsed && !empty($parsed['host'])) {
            return strcasecmp($parsed['host'], $currentHost) === 0;
        }
        return false;
    }

    private static function looksLikeExternalDomain($value) {
        $currentHost = $_SERVER['HTTP_HOST'] ?? '';

        // 如果能解析出 host，与当前域名对比
        $parsed = parse_url($value);
        if ($parsed && !empty($parsed['host'])) {
            if (strcasecmp($parsed['host'], $currentHost) === 0) {
                return false;
            }
            return true;
        }

        // 协议头（如 https:）或协议相对 URL（//example.com）
        if (preg_match('/^[a-zA-Z][a-zA-Z0-9+.\-]*:/', $value)) {
            return true;
        }
        if (preg_match('/^\/\//', $value)) {
            return true;
        }

        // 裸域名（不含协议）——排除当前域名本身
        // 兼容 example.com / example.com:8080 / example.com:8080/path / example.com?a=1 / example.com#x
        if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}(:\d+)?([\/\?#]|$)/', $value)) {
            // 提取 host（去除端口/路径），再与当前域名对比
            $bareHost = $value;
            $stop = strlen($bareHost);
            foreach (['/', '?', '#'] as $sep) {
                $p = strpos($bareHost, $sep);
                if ($p !== false && $p < $stop) {
                    $stop = $p;
                }
            }
            $colon = strpos($bareHost, ':', strpos($bareHost, '.') + 1);
            if ($colon !== false && $colon < $stop) {
                $stop = $colon;
            }
            $bareHost = substr($bareHost, 0, $stop);

            if ($currentHost && strcasecmp($bareHost, $currentHost) === 0) {
                return false;
            }
            return true;
        }
        return false;
    }
}
