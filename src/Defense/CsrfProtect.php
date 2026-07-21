<?php
defined('ABSPATH') || exit;
class CsrfProtect {
    const TOKEN_SESSION_KEY = 'waf_csrf_token';

    public static function check() {
        if (in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD', 'OPTIONS'])) return;
        if (class_exists('RequestContext') && RequestContext::isHardSkip()) return;

        $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : 
                 (isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? $_SERVER['HTTP_X_CSRF_TOKEN'] : '');

        if (!empty($token)) {
            if (self::validateToken($token)) {
                return;
            }
            waf_block('CSRF check failed: Invalid token');
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        if (!empty($origin)) {
            $originHost = self::extractHost($origin);
            if ($originHost && !self::hostEqual($originHost, $host)) {
                waf_block('CSRF check failed: Origin mismatch');
            }
        } elseif (!empty($referer)) {
            $refererHost = self::extractHost($referer);
            if ($refererHost && !self::hostEqual($refererHost, $host)) {
                waf_block('CSRF check failed: Referer mismatch');
            }
        }
    }

    public static function generateToken() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
        if (!isset($_SESSION[self::TOKEN_SESSION_KEY]) || strlen($_SESSION[self::TOKEN_SESSION_KEY]) < 32) {
            if (function_exists('random_bytes')) {
                $_SESSION[self::TOKEN_SESSION_KEY] = bin2hex(random_bytes(16));
            } elseif (function_exists('openssl_random_pseudo_bytes')) {
                $_SESSION[self::TOKEN_SESSION_KEY] = bin2hex(openssl_random_pseudo_bytes(16));
            } else {
                $_SESSION[self::TOKEN_SESSION_KEY] = bin2hex(mt_rand()) . uniqid();
            }
        }
        return $_SESSION[self::TOKEN_SESSION_KEY];
    }

    public static function validateToken($token) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
        if (!isset($_SESSION[self::TOKEN_SESSION_KEY])) {
            return false;
        }
        return hash_equals($_SESSION[self::TOKEN_SESSION_KEY], $token);
    }

    public static function getToken() {
        return self::generateToken();
    }

    private static function extractHost($url) {
        $parsed = parse_url($url);
        return $parsed['host'] ?? '';
    }

    private static function hostEqual($a, $b) {
        $aHost = preg_replace('/:\d+$/', '', $a);
        $bHost = preg_replace('/:\d+$/', '', $b);
        return strcasecmp($aHost, $bHost) === 0;
    }
}