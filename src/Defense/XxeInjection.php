<?php
defined('ABSPATH') || exit;

class XxeInjection {
    private static $entityPatterns = [
        ['pattern' => '/<!ENTITY/i', 'severity' => 90, 'name' => 'XML ENTITY declaration', 'category' => 'entity'],
        ['pattern' => '/<!DOCTYPE/i', 'severity' => 75, 'name' => 'DOCTYPE declaration', 'category' => 'entity'],
        ['pattern' => '/\bSYSTEM\b/i', 'severity' => 85, 'name' => 'SYSTEM entity', 'category' => 'entity'],
        ['pattern' => '/\bPUBLIC\b/i', 'severity' => 60, 'name' => 'PUBLIC entity', 'category' => 'entity'],
        ['pattern' => '/<!ENTITY\s+%/i', 'severity' => 95, 'name' => 'Parameter entity declaration', 'category' => 'entity'],
        ['pattern' => '/%\w+;/i', 'severity' => 80, 'name' => 'Parameter entity reference %xxx;', 'category' => 'entity'],
    ];

    private static $xincludePatterns = [
        ['pattern' => '/<xi:include/i', 'severity' => 85, 'name' => 'XInclude xi:include', 'category' => 'xinclude'],
        ['pattern' => '/xinclude/i', 'severity' => 70, 'name' => 'XInclude reference', 'category' => 'xinclude'],
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
        ['pattern' => '/data:\/\//i', 'severity' => 80, 'name' => 'Data URI scheme', 'category' => 'wrapper'],
        ['pattern' => '/zip:\/\//i', 'severity' => 75, 'name' => 'PHP zip wrapper', 'category' => 'wrapper'],
        ['pattern' => '/rar:\/\//i', 'severity' => 75, 'name' => 'PHP rar wrapper', 'category' => 'wrapper'],
        ['pattern' => '/file:\/\//i', 'severity' => 85, 'name' => 'File URI scheme', 'category' => 'wrapper'],
        ['pattern' => '/http:\/\//i', 'severity' => 80, 'name' => 'Remote DTD via HTTP', 'category' => 'remote'],
        ['pattern' => '/https:\/\//i', 'severity' => 80, 'name' => 'Remote DTD via HTTPS', 'category' => 'remote'],
        ['pattern' => '/ftp:\/\//i', 'severity' => 75, 'name' => 'Remote DTD via FTP', 'category' => 'remote'],
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

        $isXmlParam = in_array($lowerKey, self::$xmlParamNames);
        $hasXmlHeader = strpos($lowerValue, '<?xml') !== false;
        $hasDoctype = stripos($value, '<!DOCTYPE') !== false;
        $contextMultiplier = ($isXmlParam || $hasXmlHeader || $hasDoctype) ? 1.0 : 0.5;

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

        if ($hasXmlHeader && preg_match('/<!ENTITY/i', $value)) {
            $comboScore = 95;
            if ($score < $comboScore) {
                $score = $comboScore;
                $findings[] = 'XML declaration + ENTITY combination';
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
