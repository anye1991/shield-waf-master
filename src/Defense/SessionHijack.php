<?php
defined('ABSPATH') || exit;

class SessionHijack {
    private static $sessionKeys = [
        'user_agent'       => '_waf_ua',
        'accept_language'  => '_waf_accept_lang',
        'ip_address'       => '_waf_ip',
        'ip_subnet'        => '_waf_ip_subnet',
        'creation_time'    => '_waf_created',
        'last_activity'    => '_waf_last_active',
        'regeneration_count' => '_waf_regen_count',
    ];

    private static $weightConfig = [
        'user_agent'       => 30,
        'accept_language'  => 15,
        'ip_subnet'        => 35,
        'regeneration'     => 20,
    ];

    public static function detect($cookie = null) {
        $score = 0;
        $details = [];
        $detected = false;

        if (session_status() !== PHP_SESSION_ACTIVE) {
            return [
                'detected' => false,
                'score' => 0,
                'details' => [['check' => 'session_status', 'message' => 'No active session']],
            ];
        }

        $uaResult = self::checkUserAgent();
        if ($uaResult['score'] > 0) {
            $score += $uaResult['score'];
            $details[] = $uaResult;
        }

        $langResult = self::checkAcceptLanguage();
        if ($langResult['score'] > 0) {
            $score += $langResult['score'];
            $details[] = $langResult;
        }

        $ipResult = self::checkIpSubnet();
        if ($ipResult['score'] > 0) {
            $score += $ipResult['score'];
            $details[] = $ipResult;
        }

        $regenResult = self::checkRegenerationFrequency();
        if ($regenResult['score'] > 0) {
            $score += $regenResult['score'];
            $details[] = $regenResult;
        }

        $score = min($score, 100);
        $detected = $score >= 50;

        return [
            'detected' => $detected,
            'score' => $score,
            'details' => $details,
        ];
    }

    private static function checkUserAgent() {
        $findings = [];
        $score = 0;
        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $storedUa = $_SESSION[self::$sessionKeys['user_agent']] ?? '';

        if (empty($storedUa)) {
            $_SESSION[self::$sessionKeys['user_agent']] = $currentUa;
            return ['detected' => false, 'score' => 0, 'findings' => ['First visit, UA stored'], 'check' => 'user_agent'];
        }

        if ($currentUa !== $storedUa) {
            $similarity = self::calculateStringSimilarity($currentUa, $storedUa);

            if ($similarity < 0.3) {
                $score = self::$weightConfig['user_agent'];
                $findings[] = 'User-Agent completely changed';
            } elseif ($similarity < 0.6) {
                $score = (int)(self::$weightConfig['user_agent'] * 0.7);
                $findings[] = 'User-Agent significantly changed';
            } elseif ($similarity < 0.9) {
                $score = (int)(self::$weightConfig['user_agent'] * 0.3);
                $findings[] = 'User-Agent minor change detected';
            }

            $findings[] = "UA similarity: " . round($similarity * 100, 1) . "%";
        }

        return [
            'detected' => $score >= 25,
            'score' => $score,
            'findings' => $findings,
            'check' => 'user_agent',
        ];
    }

    private static function checkAcceptLanguage() {
        $findings = [];
        $score = 0;
        $currentLang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        $storedLang = $_SESSION[self::$sessionKeys['accept_language']] ?? '';

        if (empty($storedLang)) {
            $_SESSION[self::$sessionKeys['accept_language']] = $currentLang;
            return ['detected' => false, 'score' => 0, 'findings' => ['First visit, Accept-Language stored'], 'check' => 'accept_language'];
        }

        if ($currentLang !== $storedLang) {
            $currentPrimary = self::extractPrimaryLanguage($currentLang);
            $storedPrimary = self::extractPrimaryLanguage($storedLang);

            if ($currentPrimary !== $storedPrimary) {
                $score = self::$weightConfig['accept_language'];
                $findings[] = 'Primary language changed';
            } else {
                $score = (int)(self::$weightConfig['accept_language'] * 0.4);
                $findings[] = 'Accept-Language header variant changed';
            }
        }

        return [
            'detected' => $score >= 12,
            'score' => $score,
            'findings' => $findings,
            'check' => 'accept_language',
        ];
    }

    private static function checkIpSubnet() {
        $findings = [];
        $score = 0;
        $currentIp = self::getClientIp();
        $storedSubnet = $_SESSION[self::$sessionKeys['ip_subnet']] ?? '';

        if (empty($storedSubnet)) {
            $_SESSION[self::$sessionKeys['ip_address']] = $currentIp;
            $_SESSION[self::$sessionKeys['ip_subnet']] = self::getIpSubnet($currentIp);
            return ['detected' => false, 'score' => 0, 'findings' => ['First visit, IP stored'], 'check' => 'ip_subnet'];
        }

        $currentSubnet = self::getIpSubnet($currentIp);

        if ($currentSubnet !== $storedSubnet) {
            $score = self::$weightConfig['ip_subnet'];
            $findings[] = "IP subnet changed: $storedSubnet -> $currentSubnet";
        } else {
            $storedIp = $_SESSION[self::$sessionKeys['ip_address']] ?? '';
            if ($currentIp !== $storedIp) {
                $score = (int)(self::$weightConfig['ip_subnet'] * 0.2);
                $findings[] = 'IP changed within same /24 subnet';
            }
        }

        return [
            'detected' => $score >= 25,
            'score' => $score,
            'findings' => $findings,
            'check' => 'ip_subnet',
            'current_ip' => $currentIp,
            'current_subnet' => $currentSubnet,
        ];
    }

    private static function checkRegenerationFrequency() {
        $findings = [];
        $score = 0;
        $now = time();

        if (!isset($_SESSION[self::$sessionKeys['creation_time']])) {
            $_SESSION[self::$sessionKeys['creation_time']] = $now;
            $_SESSION[self::$sessionKeys['regeneration_count']] = 0;
        }

        $_SESSION[self::$sessionKeys['last_activity']] = $now;

        $sessionAge = $now - $_SESSION[self::$sessionKeys['creation_time']];
        $regenCount = $_SESSION[self::$sessionKeys['regeneration_count']] ?? 0;

        if ($sessionAge > 0) {
            $regenRate = $regenCount / ($sessionAge / 3600);
            if ($regenRate > 10) {
                $score = self::$weightConfig['regeneration'];
                $findings[] = "Abnormal session regeneration rate: $regenRate/hr";
            } elseif ($regenRate > 5) {
                $score = (int)(self::$weightConfig['regeneration'] * 0.6);
                $findings[] = "High session regeneration rate: $regenRate/hr";
            }
        }

        if ($regenCount > 20) {
            $score = max($score, (int)(self::$weightConfig['regeneration'] * 0.8));
            $findings[] = "High regeneration count: $regenCount";
        }

        return [
            'detected' => $score >= 15,
            'score' => $score,
            'findings' => $findings,
            'check' => 'regeneration_frequency',
            'session_age_seconds' => $sessionAge,
            'regeneration_count' => $regenCount,
        ];
    }

    private static function getClientIp() {
        $ip = '';
        $headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                break;
            }
        }

        return $ip ?: '0.0.0.0';
    }

    private static function getIpSubnet($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
            }
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            if (count($parts) >= 4) {
                return $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':' . $parts[3] . '::/64';
            }
        }
        return $ip;
    }

    private static function extractPrimaryLanguage($acceptLang) {
        if (empty($acceptLang)) return '';
        $parts = explode(',', $acceptLang);
        $primary = trim($parts[0]);
        $primary = explode(';', $primary)[0];
        $primary = explode('-', $primary)[0];
        return strtolower(trim($primary));
    }

    private static function calculateStringSimilarity($str1, $str2) {
        if ($str1 === $str2) return 1.0;
        $len1 = strlen($str1);
        $len2 = strlen($str2);
        if ($len1 === 0 || $len2 === 0) return 0.0;

        $maxLen = max($len1, $len2);
        $distance = levenshtein($str1, $str2);
        if ($distance === -1) {
            $str1 = substr($str1, 0, 255);
            $str2 = substr($str2, 0, 255);
            $distance = levenshtein($str1, $str2);
            if ($distance === -1) {
                return 0.0;
            }
        }
        return 1.0 - ($distance / $maxLen);
    }
}
