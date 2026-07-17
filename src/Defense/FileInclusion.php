<?php
defined('ABSPATH') || exit;

class FileInclusion {
    private static $lfiPatterns = [
        ['pattern' => '/\.\.\/\.\.\/etc\/passwd/i', 'severity' => 95, 'name' => 'LFI /etc/passwd traversal', 'category' => 'lfi'],
        ['pattern' => '/\.\.\/\.\.\/\.\.\/\.\.\/windows/i', 'severity' => 90, 'name' => 'LFI Windows path traversal', 'category' => 'lfi'],
        ['pattern' => '/php:\/\/filter\/convert\.base64-encode/i', 'severity' => 95, 'name' => 'LFI php://filter base64 encode', 'category' => 'lfi'],
        ['pattern' => '/php:\/\/input/i', 'severity' => 90, 'name' => 'LFI php://input wrapper', 'category' => 'lfi'],
        ['pattern' => '/data:\/\//i', 'severity' => 85, 'name' => 'LFI data:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/expect:\/\//i', 'severity' => 95, 'name' => 'LFI expect:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/phar:\/\//i', 'severity' => 90, 'name' => 'LFI phar:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/zip:\/\//i', 'severity' => 80, 'name' => 'LFI zip:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/rar:\/\//i', 'severity' => 80, 'name' => 'LFI rar:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/php:\/\/filter/i', 'severity' => 85, 'name' => 'LFI php://filter wrapper', 'category' => 'lfi'],
        ['pattern' => '/file:\/\//i', 'severity' => 80, 'name' => 'LFI file:// wrapper', 'category' => 'lfi'],
    ];

    private static $traversalPatterns = [
        ['pattern' => '/\.\.\.\.\/\//i', 'severity' => 80, 'name' => 'Path traversal variant ....//', 'category' => 'traversal'],
        ['pattern' => '/\.\.%2f/i', 'severity' => 75, 'name' => 'URL-encoded path traversal ..%2f', 'category' => 'traversal'],
        ['pattern' => '/%2e%2e%2f/i', 'severity' => 75, 'name' => 'Double URL-encoded traversal %2e%2e%2f', 'category' => 'traversal'],
        ['pattern' => '/\.\.\\\/', 'severity' => 70, 'name' => 'Windows path traversal ..\\', 'category' => 'traversal'],
        ['pattern' => '/\.\.\//', 'severity' => 60, 'name' => 'Standard path traversal ../', 'category' => 'traversal'],
        ['pattern' => '/%252e%252e%252f/i', 'severity' => 70, 'name' => 'Triple URL-encoded traversal', 'category' => 'traversal'],
        ['pattern' => '/\.\.%5c/i', 'severity' => 70, 'name' => 'URL-encoded backslash traversal', 'category' => 'traversal'],
        ['pattern' => '/%2e%2e%5c/i', 'severity' => 70, 'name' => 'URL-encoded backslash dot traversal', 'category' => 'traversal'],
        ['pattern' => '/\.\.\/{2,}/', 'severity' => 80, 'name' => 'Multiple path traversal sequences', 'category' => 'traversal'],
    ];

    private static $rfiPatterns = [
        ['pattern' => '/http:\/\//i', 'severity' => 85, 'name' => 'RFI HTTP URL in include param', 'category' => 'rfi'],
        ['pattern' => '/https:\/\//i', 'severity' => 80, 'name' => 'RFI HTTPS URL in include param', 'category' => 'rfi'],
        ['pattern' => '/ftp:\/\//i', 'severity' => 75, 'name' => 'RFI FTP URL in include param', 'category' => 'rfi'],
    ];

    private static $targetFilePatterns = [
        ['pattern' => '/\/etc\/passwd/i', 'severity' => 90, 'name' => 'Target: /etc/passwd', 'category' => 'target'],
        ['pattern' => '/\/etc\/shadow/i', 'severity' => 95, 'name' => 'Target: /etc/shadow', 'category' => 'target'],
        ['pattern' => '/\/proc\/self\/environ/i', 'severity' => 85, 'name' => 'Target: /proc/self/environ', 'category' => 'target'],
        ['pattern' => '/\.htaccess/i', 'severity' => 75, 'name' => 'Target: .htaccess', 'category' => 'target'],
        ['pattern' => '/config\.php/i', 'severity' => 80, 'name' => 'Target: config.php', 'category' => 'target'],
        ['pattern' => '/wp-config\.php/i', 'severity' => 85, 'name' => 'Target: wp-config.php', 'category' => 'target'],
        ['pattern' => '/\/etc\/hosts/i', 'severity' => 75, 'name' => 'Target: /etc/hosts', 'category' => 'target'],
        ['pattern' => '/\/etc\/group/i', 'severity' => 75, 'name' => 'Target: /etc/group', 'category' => 'target'],
        ['pattern' => '/\/proc\/self\/fd\//i', 'severity' => 80, 'name' => 'Target: /proc/self/fd/', 'category' => 'target'],
        ['pattern' => '/\/proc\/version/i', 'severity' => 70, 'name' => 'Target: /proc/version', 'category' => 'target'],
        ['pattern' => '/\/proc\/cpuinfo/i', 'severity' => 70, 'name' => 'Target: /proc/cpuinfo', 'category' => 'target'],
        ['pattern' => '/\/proc\/mounts/i', 'severity' => 70, 'name' => 'Target: /proc/mounts', 'category' => 'target'],
        ['pattern' => '/boot\.ini/i', 'severity' => 75, 'name' => 'Target: boot.ini', 'category' => 'target'],
        ['pattern' => '/win\.ini/i', 'severity' => 75, 'name' => 'Target: win.ini', 'category' => 'target'],
    ];

    private static $includeParamNames = [
        'file', 'path', 'filename', 'filepath', 'include', 'require',
        'page', 'template', 'view', 'layout', 'module', 'action',
        'lang', 'language', 'theme', 'style', 'css', 'js',
        'img', 'image', 'src', 'source', 'url', 'uri',
        'doc', 'document', 'content', 'data', 'load', 'open',
        'read', 'readfile', 'cat', 'dir', 'directory',
        'redirect', 'redirect_url', 'next', 'return', 'go',
        'link', 'target', 'dest', 'destination', 'forward',
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
        $lowerValue = strtolower($value);
        $score = 0;
        $findings = [];

        if (empty($value)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        $isIncludeParam = in_array($lowerKey, self::$includeParamNames);
        $paramMultiplier = $isIncludeParam ? 1.0 : 0.55;

        foreach (self::$lfiPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        foreach (self::$traversalPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        foreach (self::$rfiPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        foreach (self::$targetFilePatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                $score = max($score, $adjustedScore);
                $findings[] = $pattern['name'];
            }
        }

        $decodedValue = urldecode($value);
        if ($decodedValue !== $value) {
            foreach (self::$lfiPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $decodedValue)) {
                    $adjustedScore = (int)($pattern['severity'] * 0.85 * $paramMultiplier);
                    if ($score < $adjustedScore) {
                        $score = $adjustedScore;
                    }
                    $findings[] = 'URL-decoded: ' . $pattern['name'];
                }
            }
            foreach (self::$traversalPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $decodedValue)) {
                    $adjustedScore = (int)($pattern['severity'] * 0.8 * $paramMultiplier);
                    if ($score < $adjustedScore) {
                        $score = $adjustedScore;
                    }
                    $findings[] = 'URL-decoded: ' . $pattern['name'];
                }
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_include_param' => $isIncludeParam,
        ];
    }
}
