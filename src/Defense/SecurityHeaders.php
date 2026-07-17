<?php
defined('ABSPATH') || exit;

class SecurityHeaders {
    private static $defaultCsp = [
        'default-src' => ["'self'"],
        'script-src' => ["'self'", "'strict-dynamic'", 'https://cdn.jsdelivr.net'],
        'style-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdn.staticfile.org'],
        'img-src' => ["'self'", 'data:', 'https://*.gravatar.com'],
        'font-src' => ["'self'", 'data:', 'https://cdn.staticfile.org'],
        'connect-src' => ["'self'", 'https://cdn.jsdelivr.net'],
        'object-src' => ["'none'"],
        'base-uri' => ["'self'"],
        'form-action' => ["'self'"],
        'frame-ancestors' => ["'self'"],
        'upgrade-insecure-requests' => [],
        'block-all-mixed-content' => [],
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
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('X-Permitted-Cross-Domain-Policies: none');
        header('X-Download-Options: noopen');
        header('X-Robots-Tag: noindex, nofollow, nosnippet, noarchive');
    }

    private static function applyCsp() {
        $csp = self::$defaultCsp;
        
        $cspConfig = self::getConfig('CSP', []);
        if (!empty($cspConfig)) {
            $csp = array_merge($csp, $cspConfig);
        }

        $cspString = '';
        foreach ($csp as $directive => $sources) {
            $cspString .= $directive . ' ';
            foreach ($sources as $source) {
                $cspString .= $source . ' ';
            }
            $cspString .= '; ';
        }

        header("Content-Security-Policy: {$cspString}");
    }

    private static function applyPermissionsPolicy() {
        $permissions = self::$defaultPermissions;
        
        $permConfig = self::getConfig('PERMISSIONS_POLICY', []);
        if (!empty($permConfig)) {
            $permissions = array_merge($permissions, $permConfig);
        }

        $permString = '';
        foreach ($permissions as $feature => $policy) {
            $permString .= $feature . '=' . $policy . ', ';
        }
        $permString = rtrim($permString, ', ');

        header("Permissions-Policy: {$permString}");
    }

    private static function applyAdditionalHeaders() {
        $nonce = self::generateNonce();
        header("X-Nonce: {$nonce}");
        
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Cross-Origin-Embedder-Policy: require-corp');

        if (!self::isStaticResource()) {
            header('Cache-Control: no-cache, no-store, must-revalidate');
            header('Pragma: no-cache');
            header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        }
        
        if (self::isApiRequest()) {
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
            header('Access-Control-Max-Age: 86400');
        }
    }

    private static function generateNonce() {
        return bin2hex(random_bytes(16));
    }

    private static function getConfig($key, $default) {
        $configKey = 'SHIELD_WAF_' . $key;
        if (defined($configKey)) {
            $value = constant($configKey);
            if (is_array($value)) {
                return $value;
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