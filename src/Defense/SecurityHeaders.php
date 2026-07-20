<?php
defined('ABSPATH') || exit;

class SecurityHeaders {
    // 主流 CDN 域名白名单（脚本/样式/字体通用）
    private static $cdnHosts = [
        // 国内 CDN
        'https://cdn.jsdelivr.net', 'https://cdn.staticfile.org',
        'https://at.alicdn.com', 'https://lib.baomitu.com',
        'https://res.wx.qq.com', 'https://gw.alipayobjects.com',
        'https://img.alicdn.com',
        // Google
        'https://fonts.googleapis.com', 'https://fonts.gstatic.com',
        'https://www.google.com', 'https://www.google-analytics.com',
        'https://www.googletagmanager.com', 'https://ajax.googleapis.com',
        'https://maps.googleapis.com', 'https://translate.googleapis.com',
        // jQuery / Bootstrap / Font Awesome
        'https://code.jquery.com', 'https://maxcdn.bootstrapcdn.com',
        'https://use.fontawesome.com', 'https://cdnjs.cloudflare.com',
        'https://unpkg.com',
        // 百度
        'https://hm.baidu.com', 'https://api.map.baidu.com',
        'https://api.t.map.baidu.com',
        // Cloudflare
        'https://cdnjs.cloudflare.com',
        // 微信
        'https://res.wx.qq.com', 'https://mp.weixin.qq.com',
        'https://open.weixin.qq.com',
        // 社交
        'https://connect.facebook.net', 'https://platform.twitter.com',
        'https://platform.linkedin.com',
    ];

    private static $defaultCsp = [
        'default-src' => ["'self'"],
        'script-src' => ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'style-src' => ["'self'", "'unsafe-inline'"],
        'img-src' => ["'self'", 'data:', 'blob:', '*'],
        'font-src' => ["'self'", 'data:'],
        'connect-src' => ["'self'", '*'],
        'object-src' => ["'none'"],
        'base-uri' => ["'self'"],
        'form-action' => ['*'],
        'frame-ancestors' => ["'self'"],
    ];

    private static $defaultPermissions = [
        'geolocation' => '()',
        'microphone' => '()',
        'camera' => '()',
        'speaker' => '()',
        'payment' => '()',
        'usb' => '()',
        'magnetometer' => '()',
        'gyroscope' => '()',
        'accelerometer' => '()',
        'clipboard-read' => '()',
        'clipboard-write' => '()',
        'display-capture' => '()',
        'document-domain' => '()',
        'encrypted-media' => '()',
        'fullscreen' => '()',
        'gamepad' => '()',
        'hid' => '()',
        'idle-detection' => '()',
        'local-fonts' => '()',
        'notifications' => '()',
        'openid-connect' => '()',
        'picture-in-picture' => '()',
        'publickey-credentials-get' => '()',
        'screen-wake-lock' => '()',
        'serial' => '()',
        'shared-autofill' => '()',
        'storage-access' => '()',
        'top-level-storage-access' => '()',
        'unload' => '()',
        'web-share' => '()',
        'window-placement' => '()',
        'xr-spatial-tracking' => '()',
    ];

    public static function apply() {
        self::applyBaseHeaders();
        self::applyCsp();
        self::applyPermissionsPolicy();
        self::applyAdditionalHeaders();
    }

    private static function applyBaseHeaders() {
        self::setHeader('X-Content-Type-Options: nosniff');
        self::setHeader('X-Frame-Options: SAMEORIGIN');
        self::setHeader('X-XSS-Protection: 0');

        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            self::setHeader('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }

        self::setHeader('Referrer-Policy: strict-origin-when-cross-origin');
        self::setHeader('X-Permitted-Cross-Domain-Policies: none');
        self::setHeader('X-Download-Options: noopen');
        // X-Robots-Tag 默认不发送，避免影响搜索引擎收录
        // 如需禁用搜索引擎索引，可在配置中开启
    }

    public static function applyCsp() {
        $csp = self::$defaultCsp;
        $cspConfig = self::getConfig('SHIELD_WAF_CSP', []);
        if (!is_array($cspConfig)) $cspConfig = [];
        $csp = array_merge_recursive($csp, $cspConfig);

        // 自动将 CDN 域名添加到 script-src、style-src 和 font-src
        foreach (['script-src', 'style-src', 'font-src'] as $directive) {
            if (!isset($csp[$directive])) $csp[$directive] = [];
            foreach (self::$cdnHosts as $host) {
                if (!in_array($host, $csp[$directive], true)) {
                    $csp[$directive][] = $host;
                }
            }
        }

        // 构造 CSP 字符串
        $cspString = '';
        foreach ($csp as $directive => $sources) {
            if (is_array($sources) && count($sources) > 0) {
                $cspString .= $directive . ' ' . implode(' ', $sources) . '; ';
            } else {
                $cspString .= $directive . '; ';
            }
        }
        $cspString = rtrim($cspString);

        if (!headers_sent()) {
            header("Content-Security-Policy: {$cspString}");
        }
    }

    private static function applyPermissionsPolicy() {
        $permissions = self::$defaultPermissions;

        $permConfig = self::getConfig('SHIELD_WAF_PERMISSIONS_POLICY', []);
        if (!is_array($permConfig)) $permConfig = [];
        if (!empty($permConfig)) {
            $permissions = array_merge($permissions, $permConfig);
        }

        $permString = '';
        foreach ($permissions as $feature => $policy) {
            $permString .= $feature . '=' . $policy . ', ';
        }
        $permString = rtrim($permString, ', ');

        self::setHeader("Permissions-Policy: {$permString}");
    }

    private static function applyAdditionalHeaders() {
        self::setHeader('Cross-Origin-Opener-Policy: same-origin');

        // 默认改为 same-site，避免阻断合法跨域
        $corp = self::getConfig('SHIELD_WAF_CORP', 'same-site');
        if ($corp && $corp !== 'off') {
            self::setHeader("Cross-Origin-Resource-Policy: $corp");
        }

        // 默认不发送 COEP，仅在配置启用时才发送
        $coep = self::getConfig('SHIELD_WAF_COEP', '');
        if ($coep && $coep !== 'off') {
            self::setHeader("Cross-Origin-Embedder-Policy: $coep");
        }

        // Cache-Control：仅对后台路径设置 no-store，避免破坏前端页面缓存
        // 前端页面正常缓存可提升性能、降低服务器负载
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $isAdminPath = strpos($uri, '/wp-admin') !== false ||
                       strpos($uri, '/admin') !== false ||
                       strpos($uri, '/waf-dashboard') !== false;
        if ($isAdminPath && !self::isStaticResource()) {
            self::setHeader('Cache-Control: no-cache, no-store, must-revalidate');
            self::setHeader('Pragma: no-cache');
            self::setHeader('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        }

        if (self::isApiRequest()) {
            self::setHeader('Access-Control-Allow-Origin: *');
            self::setHeader('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            self::setHeader('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
            self::setHeader('Access-Control-Max-Age: 86400');
        }
    }

    private static function setHeader($headerLine) {
        if (!headers_sent()) {
            header($headerLine);
        }
    }

    private static function generateNonce() {
        return bin2hex(random_bytes(16));
    }

    private static function getConfig($configKey, $default) {
        if (defined($configKey)) {
            $value = constant($configKey);
            if (is_array($value)) return $value;
            if (is_string($value)) {
                $decoded = json_decode($value, true);
                if (is_array($decoded)) return $decoded;
            }
        }
        return $default;
    }

    private static function isApiRequest() {
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        return strpos($requestUri, '/api/') !== false ||
               strpos($requestUri, '/rest/') !== false ||
               strpos($requestUri, '/v1/') !== false ||
               strpos($requestUri, '/v2/') !== false;
    }

    private static function isStaticResource() {
        $uri = strtolower($_SERVER['REQUEST_URI'] ?? '');
        $staticExts = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.webp', '.mp4', '.mp3', '.map', '.txt'];
        foreach ($staticExts as $ext) {
            if (substr($uri, -strlen($ext)) === $ext) return true;
        }
        return false;
    }

    public static function getNonce() {
        return self::generateNonce();
    }

    public static function getCspHeader($nonce = null) {
        $csp = self::$defaultCsp;
        
        if ($nonce) {
            $csp['script-src'][] = "'nonce-{$nonce}'";
            $csp['style-src'][] = "'nonce-{$nonce}'";
        }

        $cspString = '';
        foreach ($csp as $directive => $sources) {
            $cspString .= $directive . ' ';
            foreach ($sources as $source) {
                $cspString .= $source . ' ';
            }
            $cspString .= '; ';
        }

        return $cspString;
    }
}