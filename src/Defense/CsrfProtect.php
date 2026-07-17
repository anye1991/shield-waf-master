<?php
defined('ABSPATH') || exit;
class CsrfProtect {
    public static function check() {
        if (in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD', 'OPTIONS'])) return;
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        if (!empty($origin)) {
            $originHost = parse_url($origin, PHP_URL_HOST);
            if ($originHost && strcasecmp($originHost, $host) !== 0) waf_block('CSRF check failed: Origin mismatch');
        } elseif (!empty($referer)) {
            $refererHost = parse_url($referer, PHP_URL_HOST);
            if ($refererHost && strcasecmp($refererHost, $host) !== 0) waf_block('CSRF check failed: Referer mismatch');
        }
    }
}