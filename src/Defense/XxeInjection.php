<?php
defined('ABSPATH') || exit;

class XxeInjection {
    private static $entityPatterns = [
        ['pattern' => '/<!ENTITY/i', 'severity' => 90, 'name' => 'XML ENTITY declaration', 'category' => 'entity'],
        ['pattern' => '/<!DOCTYPE/i', 'severity' => 75, 'name' => 'DOCTYPE declaration', 'category' => 'entity'],
        ['pattern' => '/SYSTEM\s+["\']/i', 'severity' => 85, 'name' => 'SYSTEM entity', 'category' => 'entity'],
        ['pattern' => '/PUBLIC\s+["\']/i', 'severity' => 60, 'name' => 'PUBLIC entity', 'category' => 'entity'],
        ['pattern' => '/<!ENTITY\s+%/i', 'severity' => 95, 'name' => 'Parameter entity declaration', 'category' => 'entity'],
        // %w+; 仅在同时存在 <!ENTITY % 时才计分，单独出现易误报（URL 编码也包含 %xx）
        ['pattern' => '/<!ENTITY\s+%.*?%\w+;/is', 'severity' => 80, 'name' => 'Parameter entity reference %xxx;', 'category' => 'entity'],
    ];

    private static $xincludePatterns = [
        ['pattern' => '/<xi:include/i', 'severity' => 85, 'name' => 'XInclude xi:include', 'category' => 'xinclude'],
    ];

    private static $svgPatterns = [
        ['pattern' => '/xlink:href/i', 'severity' => 70, 'name' => 'SVG xlink:href external reference', 'category' => 'svg'],
        ['pattern' => '/\bexternal\b/i', 'severity' => 50, 'name' => 'external keyword in XML context', 'category' => 'svg'],
    ];

    private static $wrapperPatterns = [
        ['pattern' => '/php:\/\/filter/i', 'severity' => 95, 'name' => 'PHP filter wrapper', 'category' => 'wrapper'],
        ['pattern' => '/expect:\/\//i', 'severity' => 95, 'name' => 'PHP expect wrapper', 'category' => 'wrapper'],
        ['pattern' => '/phar:\/\//i', 'severity' => 90, 'name' => 'PHP phar wrapper', 'category' => 'wrapper'],
        ['pattern' => '/php:\/\/input/i', 'severity' => 90, 'name' => 'PHP input wrapper', 'category' => 'wrapper'],
        ['pattern' => '/data:[\w\/]+/i', 'severity' => 80, 'name' => 'Data URI scheme', 'category' => 'wrapper'],
        ['pattern' => '/zip:\/\//i', 'severity' => 75, 'name' => 'PHP zip wrapper', 'category' => 'wrapper'],
        ['pattern' => '/rar:\/\//i', 'severity' => 75, 'name' => 'PHP rar wrapper', 'category' => 'wrapper'],
        ['pattern' => '/file:\/\//i', 'severity' => 85, 'name' => 'File URI scheme', 'category' => 'wrapper'],
        // http/https/ftp scheme 单独出现不是 XXE 强信号，降级到 30
        ['pattern' => '/http:\/\//i', 'severity' => 30, 'name' => 'HTTP URL (weak signal)', 'category' => 'remote'],
        ['pattern' => '/https:\/\//i', 'severity' => 30, 'name' => 'HTTPS URL (weak signal)', 'category' => 'remote'],
        ['pattern' => '/ftp:\/\//i', 'severity' => 30, 'name' => 'FTP URL (weak signal)', 'category' => 'remote'],
    ];

    private static $fileTargetPatterns = [
        ['pattern' => '/\/etc\/passwd/i', 'severity' => 90, 'name' => '/etc/passwd access attempt', 'category' => 'target'],
        ['pattern' => '/\/etc\/shadow/i', 'severity' => 95, 'name' => '/etc/shadow access attempt', 'category' => 'target'],
        ['pattern' => '/\/proc\//i', 'severity' => 80, 'name' => '/proc/ filesystem access', 'category' => 'target'],
        ['pattern' => '/\.htaccess/i', 'severity' => 75, 'name' => '.htaccess access attempt', 'category' => 'target'],
        ['pattern' => '/config\.php/i', 'severity' => 80, 'name' => 'config.php access attempt', 'category' => 'target'],
        ['pattern' => '/wp-config\.php/i', 'severity' => 85, 'name' => 'wp-config.php access attempt', 'category' => 'target'],
    ];

    private static $xmlParamNames = [
        'xml', 'data', 'body', 'content', 'input', 'payload',
        'file', 'path', 'url', 'uri', 'src', 'source',
        'document', 'doc', 'feed', 'rss', 'sitemap',
    ];

    // 缓存的合并大正则（首次使用时构建），覆盖全部 entity/xinclude/svg/wrapper/target patterns
    private static $combinedXxePattern = null;

    /**
     * 把全部 5 类 patterns 合并为单个 alternation 大正则。
     * 原 patterns 都带 /i；第 12 行的 /<!ENTITY\s+%.*?%\w+;/is 还带 s，
     * 因其 body 含未转义 .*? 需要 . 跨行匹配。其余 patterns 均不含未转义 .，
     * 统一加 /is 不改变其行为。
     */
    private static function getCombinedPattern() {
        if (self::$combinedXxePattern !== null) {
            return self::$combinedXxePattern;
        }
        $parts = [];
        foreach (self::$entityPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$xincludePatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$svgPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$wrapperPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$fileTargetPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        self::$combinedXxePattern = '/' . implode('|', $parts) . '/is';
        return self::$combinedXxePattern;
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

    public static function detect($rawBody, $inputs) {
        $score = 0;
        $details = [];
        $detected = false;

        $allTargets = [];

        if (!empty($rawBody)) {
            $allTargets['raw_body'] = $rawBody;
        }

        if (is_array($inputs)) {
            foreach ($inputs as $key => $value) {
                if (is_array($value)) {
                    foreach ($value as $v) {
                        $allTargets[$key . '[]'] = (string)$v;
                    }
                } else {
                    $allTargets[$key] = (string)$value;
                }
            }
        }

        if (empty($allTargets)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($allTargets as $key => $value) {
            $result = self::analyzeValue((string)$key, (string)$value);
            if ($result['score'] > 0) {
                $score = max($score, $result['score']);
                $details[] = $result;
                if ($result['detected']) {
                    $detected = true;
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
            $lowerValue = strtolower($value);
        }

        $isXmlParam = in_array($lowerKey, self::$xmlParamNames);
        $hasXmlHeader = strpos($lowerValue, '<?xml') !== false;
        // 更精确的 DOCTYPE 判定：要求同时存在 XML 声明、内部 DTD 子集（[）或 SYSTEM 标识
        // 注意：原正则使用 \s+ 要求至少 1 个空白，但 XML 规范允许 0 个或多个空白，
        // 攻击者可构造 <!DOCTYPEfoo[SYSTEM "evil"> 等无空格 payload 绕过。
        // 改为 \s*（零或多个空白）以彻底检测。
        $hasDoctype = (stripos($value, '<!DOCTYPE') !== false) &&
                      (stripos($value, '<?xml') !== false ||
                       preg_match('/<!DOCTYPE\s*\w*\s*\[/i', $value) ||
                       preg_match('/<!DOCTYPE\s*\w*\s*SYSTEM/i', $value));
        $contextMultiplier = ($isXmlParam || $hasXmlHeader || $hasDoctype) ? 1.0 : 0.5;

        // 廉价预筛：所有 5 类 patterns 都至少需要以下字符/子串之一才可能命中
        //   entityPatterns:    '<' (<!ENTITY/<!DOCTYPE) 或 '%' (<!ENTITY %)
        //   xincludePatterns:  '<' (xi:include)
        //   svgPatterns:        'xlink' 或 'external' (大小写不敏感)
        //   wrapperPatterns:   ':' (php://, expect:// 等)
        //   fileTargetPatterns: '/' (路径) 或 '.' (.htaccess / .php)
        // 若均不含，跳过所有 5 类正则与合并大正则
        if (strpos($value, '<') !== false
            || strpos($value, ':') !== false
            || strpos($value, '/') !== false
            || strpos($value, '.') !== false
            || strpos($value, '%') !== false
            || stripos($value, 'external') !== false
            || stripos($value, 'xlink') !== false) {

            // 合并大正则做一次廉价筛除：未命中则跳过 5 类逐条匹配
            if (preg_match(self::getCombinedPattern(), $value)) {
                foreach (self::$entityPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $contextMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }

                foreach (self::$xincludePatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $contextMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }

                foreach (self::$svgPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $contextMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }

                foreach (self::$wrapperPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $contextMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }

                foreach (self::$fileTargetPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $contextMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }
            }
        }

        // 复用 stripos 避免在组合检测里重复调用 preg_match('/<!ENTITY|<!DOCTYPE/i')
        $hasEntity = stripos($value, '<!ENTITY') !== false;
        $hasDoctypeSimple = stripos($value, '<!DOCTYPE') !== false;

        if ($hasXmlHeader && $hasEntity) {
            $comboScore = 95;
            if ($score < $comboScore) {
                $score = $comboScore;
                $findings[] = 'XML declaration + ENTITY combination';
            }
        }

        // 仅在 DOCTYPE/ENTITY 同时存在时，远程 URL 才计高分
        $hasEntityOrDoctype = $hasEntity || $hasDoctypeSimple;
        if ($hasEntityOrDoctype && preg_match('#(https?|ftp)://#i', $value)) {
            $comboScore = 90;
            if ($score < $comboScore) {
                $score = $comboScore;
                $findings[] = 'DOCTYPE/ENTITY + remote URL combination';
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'has_xml_header' => $hasXmlHeader,
            'has_doctype' => $hasDoctype,
        ];
    }
}
