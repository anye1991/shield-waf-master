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

    /**
     * 从 URL 中提取 host（不含端口）
     */
    private static function extractHost($url) {
        $parsed = parse_url($url);
        return $parsed['host'] ?? '';
    }

    /**
     * 比较 host 是否相等（忽略端口差异，处理 CDN/反代场景）
     * 例：example.com == example.com:443 == example.com:80
     */
    private static function hostEqual($a, $b) {
        // 去掉端口部分
        $aHost = preg_replace('/:\d+$/', '', $a);
        $bHost = preg_replace('/:\d+$/', '', $b);
        return strcasecmp($aHost, $bHost) === 0;
    }
}