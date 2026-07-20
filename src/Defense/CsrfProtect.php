<?php
defined('ABSPATH') || exit;
class CsrfProtect {
    public static function check() {
        if (in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD', 'OPTIONS'])) return;
        // 高可信场景跳过 CSRF 检查（登录/支付回调/表单提交等业务核心路径）
        // 这些场景下 Origin/Referer 在 CDN/反代环境容易误判，且应用自身应有 nonce 机制
        if (class_exists('RequestContext') && RequestContext::isHardSkip()) return;
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