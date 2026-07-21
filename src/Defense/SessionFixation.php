<?php
defined('ABSPATH') || exit;

class SessionFixation {
    private static $sessionParamNames = [
        'PHPSESSID', 'phpsessid', 'sessionid', 'session_id',
        'SID', 'sid', 'SESSID', 'sessid',
        'session', 's', 'token', 'sessionToken',
        'JSESSIONID', 'jsessionid', 'ASPSESSIONID', 'aspsessionid',
        'ASP.NET_SessionId', 'sessionid_cookie',
        'CFID', 'CFTOKEN', 'coldfusion',
        'laravel_session', 'symfony', 'app_session',
        'ci_session', 'wp_session', 'drupal_session',
    ];

    private static $anomalousPatterns = [
        ['pattern' => '/^[a-f0-9]{32}$/i', 'severity' => 30, 'name' => 'Standard MD5 format session ID', 'category' => 'format'],
        ['pattern' => '/^[a-f0-9]{40}$/i', 'severity' => 25, 'name' => 'SHA-1 format session ID', 'category' => 'format'],
        ['pattern' => '/^[a-zA-Z0-9]{26}$/', 'severity' => 25, 'name' => 'Standard PHP session ID format', 'category' => 'format'],
        ['pattern' => '/^[a-zA-Z0-9_\-]{20,}$/', 'severity' => 20, 'name' => 'Generic alphanumeric session ID', 'category' => 'format'],
    ];

    private static $suspiciousIdPatterns = [
        ['pattern' => '/^(admin|root|test|user|guest|demo|12345|abcdef)\b/i', 'severity' => 80, 'name' => 'Predictable session ID value', 'category' => 'suspicious'],
        ['pattern' => '/^[0-9]{1,6}$/', 'severity' => 75, 'name' => 'Short numeric session ID', 'category' => 'suspicious'],
        ['pattern' => '/^[a-z]{1,10}$/i', 'severity' => 70, 'name' => 'Short alphabetic session ID', 'category' => 'suspicious'],
        ['pattern' => '/\.\./', 'severity' => 65, 'name' => 'Path traversal in session ID', 'category' => 'suspicious'],
        ['pattern' => '/[<>"\']/', 'severity' => 60, 'name' => 'Special characters in session ID', 'category' => 'suspicious'],
        ['pattern' => '/^(http|ftp|file|php):/i', 'severity' => 70, 'name' => 'URL scheme in session ID', 'category' => 'suspicious'],
    ];

    public static function detect($cookie = null) {
        $score = 0;
        $details = [];
        $detected = false;

        $urlSessionParams = self::checkUrlSessionParams();
        if ($urlSessionParams['score'] > 0) {
            $score = max($score, $urlSessionParams['score']);
            $details[] = $urlSessionParams;
            if ($urlSessionParams['detected']) {
                $detected = true;
            }
        }

        $refererSession = self::checkRefererSession();
        if ($refererSession['score'] > 0) {
            $score = max($score, $refererSession['score']);
            $details[] = $refererSession;
            if ($refererSession['detected']) {
                $detected = true;
            }
        }

        $getSessionParams = self::checkGetSessionParams();
        if ($getSessionParams['score'] > 0) {
            $score = max($score, $getSessionParams['score']);
            $details[] = $getSessionParams;
            if ($getSessionParams['detected']) {
                $detected = true;
            }
        }

        $formatAnomaly = self::checkSessionIdFormat($cookie);
        if ($formatAnomaly['score'] > 0) {
            $score = max($score, $formatAnomaly['score']);
            $details[] = $formatAnomaly;
            if ($formatAnomaly['detected']) {
                $detected = true;
            }
        }

        return [
            'detected' => $detected,
            'score' => min($score, 100),
            'details' => $details,
        ];
    }

    private static function checkUrlSessionParams() {
        $findings = [];
        $score = 0;
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $queryString = $_SERVER['QUERY_STRING'] ?? '';

        foreach (self::$sessionParamNames as $paramName) {
            if (stripos($queryString, $paramName . '=') !== false) {
                $score = max($score, 70);
                $findings[] = "Session ID in URL query: $paramName";
            }

            if (preg_match('/[?&]' . preg_quote($paramName, '/') . '=/i', $uri)) {
                $score = max($score, 70);
                if (!in_array("Session ID in URL query: $paramName", $findings)) {
                    $findings[] = "Session ID in URL query: $paramName";
                }
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'url_session_params',
        ];
    }

    private static function checkRefererSession() {
        $findings = [];
        $score = 0;
        $referer = $_SERVER['HTTP_REFERER'] ?? '';

        if (empty($referer)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'check' => 'referer_session'];
        }

        $currentHost = $_SERVER['HTTP_HOST'] ?? '';
        $refererHost = parse_url($referer, PHP_URL_HOST) ?? '';

        $isCrossDomain = !empty($currentHost) && !empty($refererHost) && strtolower($refererHost) !== strtolower($currentHost);

        foreach (self::$sessionParamNames as $paramName) {
            if (preg_match('/[?&]' . preg_quote($paramName, '/') . '=/i', $referer)) {
                if ($isCrossDomain) {
                    $score = max($score, 85);
                    $findings[] = "Cross-domain session ID in Referer: $paramName";
                } else {
                    $score = max($score, 45);
                    $findings[] = "Session ID in Referer: $paramName";
                }
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'referer_session',
            'cross_domain' => $isCrossDomain,
        ];
    }

    private static function checkGetSessionParams() {
        $findings = [];
        $score = 0;

        foreach ($_GET as $key => $value) {
            $lowerKey = strtolower((string)$key);
            foreach (self::$sessionParamNames as $paramName) {
                if (strtolower($paramName) === $lowerKey) {
                    $sessionValue = (string)$value;
                    $score = max($score, 70);
                    $findings[] = "Session identifier in GET parameter: $key";

                    foreach (self::$suspiciousIdPatterns as $pattern) {
                        if (preg_match($pattern['pattern'], $sessionValue)) {
                            $score = max($score, $pattern['severity']);
                            $findings[] = $pattern['name'];
                        }
                    }
                    break;
                }
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'get_session_params',
        ];
    }

    private static function checkSessionIdFormat($cookie = null) {
        $findings = [];
        $score = 0;
        $sessionName = session_name() ?: 'PHPSESSID';

        $sessionId = null;
        if ($cookie !== null && isset($cookie[$sessionName])) {
            $sessionId = $cookie[$sessionName];
        } elseif (isset($_COOKIE[$sessionName])) {
            $sessionId = $_COOKIE[$sessionName];
        }

        if ($sessionId === null) {
            foreach (self::$sessionParamNames as $paramName) {
                if (isset($_GET[$paramName])) {
                    $sessionId = $_GET[$paramName];
                    break;
                }
            }
        }

        if ($sessionId === null || empty($sessionId)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'check' => 'session_id_format'];
        }

        $sessionId = (string)$sessionId;

        foreach (self::$suspiciousIdPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $sessionId)) {
                $score = max($score, $pattern['severity']);
                $findings[] = $pattern['name'];
            }
        }

        $len = strlen($sessionId);
        if ($len < 10) {
            $score = max($score, 65);
            $findings[] = 'Very short session ID (< 10 chars)';
        } elseif ($len < 16) {
            $score = max($score, 40);
            $findings[] = 'Short session ID (< 16 chars)';
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'session_id_format',
            'session_id_length' => $len,
        ];
    }
}
