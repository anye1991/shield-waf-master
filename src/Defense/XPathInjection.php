<?php
defined('ABSPATH') || exit;

class XPathInjection {
    private static $classicInjectionPatterns = [
        ['pattern' => "/'\s*or\s*'1'\s*=\s*'1/i", 'severity' => 95, 'name' => "XPath classic injection ' or '1'='1", 'category' => 'classic'],
        ['pattern' => '/"\s*or\s*"1"\s*=\s*"1/i', 'severity' => 95, 'name' => 'XPath classic injection " or "1"="1', 'category' => 'classic'],
        ['pattern' => "/'\s*or\s*true\s*\(\s*\)\s*or\s*'/i", 'severity' => 95, 'name' => "XPath true() injection", 'category' => 'classic'],
        ['pattern' => "/\bor\s+1\s*=\s*1\b/i", 'severity' => 85, 'name' => 'XPath or 1=1 injection', 'category' => 'classic'],
        ['pattern' => "/\band\s+1\s*=\s*1\b/i", 'severity' => 80, 'name' => 'XPath and 1=1 injection', 'category' => 'classic'],
    ];

    private static $axisPatterns = [
        ['pattern' => '/\/\/\s*\*/', 'severity' => 75, 'name' => 'XPath descendant wildcard //*', 'category' => 'axis'],
        ['pattern' => '/\/\s*@\s*\*/', 'severity' => 70, 'name' => 'XPath attribute wildcard /@*', 'category' => 'axis'],
        ['pattern' => '/\/\s*\.\.\s*/', 'severity' => 60, 'name' => 'XPath parent node /..', 'category' => 'axis'],
        ['pattern' => '/\/\s*\*/', 'severity' => 65, 'name' => 'XPath child wildcard /*', 'category' => 'axis'],
        ['pattern' => '/descendant\s*::/i', 'severity' => 70, 'name' => 'XPath descendant axis', 'category' => 'axis'],
        ['pattern' => '/ancestor\s*::/i', 'severity' => 65, 'name' => 'XPath ancestor axis', 'category' => 'axis'],
        ['pattern' => '/following\s*::/i', 'severity' => 60, 'name' => 'XPath following axis', 'category' => 'axis'],
        ['pattern' => '/preceding\s*::/i', 'severity' => 60, 'name' => 'XPath preceding axis', 'category' => 'axis'],
        ['pattern' => '/parent\s*::/i', 'severity' => 55, 'name' => 'XPath parent axis', 'category' => 'axis'],
        ['pattern' => '/self\s*::/i', 'severity' => 50, 'name' => 'XPath self axis', 'category' => 'axis'],
    ];

    private static $functionPatterns = [
        ['pattern' => '/count\s*\(/i', 'severity' => 70, 'name' => 'XPath count() function', 'category' => 'function'],
        ['pattern' => '/string-length\s*\(/i', 'severity' => 75, 'name' => 'XPath string-length() function', 'category' => 'function'],
        ['pattern' => '/substring\s*\(/i', 'severity' => 75, 'name' => 'XPath substring() function', 'category' => 'function'],
        ['pattern' => '/name\s*\(/i', 'severity' => 65, 'name' => 'XPath name() function', 'category' => 'function'],
        ['pattern' => '/local-name\s*\(/i', 'severity' => 65, 'name' => 'XPath local-name() function', 'category' => 'function'],
        ['pattern' => '/namespace-uri\s*\(/i', 'severity' => 60, 'name' => 'XPath namespace-uri() function', 'category' => 'function'],
        ['pattern' => '/concat\s*\(/i', 'severity' => 60, 'name' => 'XPath concat() function', 'category' => 'function'],
        ['pattern' => '/contains\s*\(/i', 'severity' => 55, 'name' => 'XPath contains() function', 'category' => 'function'],
        ['pattern' => '/starts-with\s*\(/i', 'severity' => 55, 'name' => 'XPath starts-with() function', 'category' => 'function'],
        ['pattern' => '/string\s*\(/i', 'severity' => 50, 'name' => 'XPath string() function', 'category' => 'function'],
        ['pattern' => '/number\s*\(/i', 'severity' => 50, 'name' => 'XPath number() function', 'category' => 'function'],
        ['pattern' => '/boolean\s*\(/i', 'severity' => 50, 'name' => 'XPath boolean() function', 'category' => 'function'],
        ['pattern' => '/not\s*\(/i', 'severity' => 55, 'name' => 'XPath not() function', 'category' => 'function'],
        ['pattern' => '/true\s*\(\s*\)/i', 'severity' => 70, 'name' => 'XPath true() function', 'category' => 'function'],
        ['pattern' => '/false\s*\(\s*\)/i', 'severity' => 65, 'name' => 'XPath false() function', 'category' => 'function'],
        ['pattern' => '/position\s*\(\s*\)/i', 'severity' => 55, 'name' => 'XPath position() function', 'category' => 'function'],
        ['pattern' => '/last\s*\(\s*\)/i', 'severity' => 55, 'name' => 'XPath last() function', 'category' => 'function'],
        // XPath 2.0+ 危险函数 doc() / collection() 可加载外部文档
        ['pattern' => '/doc\s*\(/i', 'severity' => 75, 'name' => 'XPath 2.0 doc() function', 'category' => 'function'],
        ['pattern' => '/collection\s*\(/i', 'severity' => 75, 'name' => 'XPath 2.0 collection() function', 'category' => 'function'],
    ];

    private static $xpathParamNames = [
        'xpath', 'query', 'path', 'expression', 'expr',
        'search', 'filter', 'node', 'element', 'attribute',
        'q', 's', 'keyword',
    ];

    public static function detect($inputs) {
        $score = 0;
        $details = [];
        $detected = false;

        if (!is_array($inputs) || empty($inputs)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($inputs as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $result = self::analyzeValue((string)$key, (string)$v);
                    if ($result['score'] > 0) {
                        $score = max($score, $result['score']);
                        $details[] = $result;
                        if ($result['detected']) {
                            $detected = true;
                        }
                    }
                }
            } else {
                $result = self::analyzeValue((string)$key, (string)$value);
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
        $score = 0;
        $findings = [];

        if (empty($value)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        $isXpathParam = in_array($lowerKey, self::$xpathParamNames);
        $paramMultiplier = $isXpathParam ? 1.0 : 0.65;
        // 检查 XPath 路径上下文：要求出现 / 或 :: 才视为 XPath 上下文
        $hasXPathContext = (strpos($value, '/') !== false) || (strpos($value, '::') !== false);

        foreach (self::$classicInjectionPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                // 或 1=1 等模式与 SQL 注入重叠，仅在有 XPath 路径上下文时才计满分
                $contextMul = $hasXPathContext ? 1.0 : 0.5;
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier * $contextMul);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        foreach (self::$axisPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        foreach (self::$functionPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                // 函数名过宽，要求前导 / 或 :: 上下文，或与 = 组合
                $hasFuncContext = $hasXPathContext || (strpos($value, '=') !== false);
                $contextMul = $hasFuncContext ? 1.0 : 0.5;
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier * $contextMul);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        if (preg_match('/^\s*\//', $value) && preg_match('/\//', substr($value, 1))) {
            $pathScore = (int)(30 * $paramMultiplier);
            if ($score < $pathScore) {
                $score = $pathScore;
                $findings[] = 'XPath path-like structure';
            }
        }

        $bracketCount = substr_count($value, '[') + substr_count($value, ']');
        if ($bracketCount >= 4) {
            $bracketScore = (int)(25 * $paramMultiplier);
            if ($score < $bracketScore) {
                $score = $bracketScore;
                $findings[] = 'Multiple XPath predicate brackets';
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_xpath_param' => $isXpathParam,
        ];
    }
}
