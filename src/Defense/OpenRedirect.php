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
        ['pattern' => '/^[a-zA-Z][a-zA-Z0-9+.\-]*:/i', 'severity' => 50, 'name' => 'Generic URI scheme', 'category' => 'external'],
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
        ['pattern' => '/\\\/', 'severity' => 60, 'name' => 'Backslash in URL', 'category' => 'suspicious'],
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

        $isRedirectParam = self::isRedirectParam($lowerKey);
        $paramMultiplier = $isRedirectParam ? 1.0 : 0.45;

        foreach (self::$externalUrlPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
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

        $decodedValue = urldecode($value);
        if ($decodedValue !== $value) {
            foreach (self::$externalUrlPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $decodedValue)) {
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
            if ($key === $param || strpos($key, $param) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function looksLikeExternalDomain($value) {
        if (preg_match('/^[a-zA-Z][a-zA-Z0-9+.\-]*:/', $value)) {
            return true;
        }
        if (preg_match('/^\/\//', $value)) {
            return true;
        }
        if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}(\/|$)/', $value)) {
            return true;
        }
        return false;
    }
}
