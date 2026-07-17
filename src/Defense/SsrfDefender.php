<?php
defined('ABSPATH') || exit;

class SsrfDefender {
    private static $privateRanges = [
        '10.', '10.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
        '192.168.',
        '127.',
        '169.254.',
        '0.',
        '198.18.', '198.19.',
        '100.64.', '100.65.', '100.66.', '100.67.',
        '100.68.', '100.69.', '100.70.', '100.71.',
        '100.72.', '100.73.', '100.74.', '100.75.',
        '100.76.', '100.77.', '100.78.', '100.79.',
        '100.80.', '100.81.', '100.82.', '100.83.',
        '100.84.', '100.85.', '100.86.', '100.87.',
        '100.88.', '100.89.', '100.90.', '100.91.',
        '100.92.', '100.93.', '100.94.', '100.95.',
        '100.96.', '100.97.', '100.98.', '100.99.',
        '100.100.', '100.101.', '100.102.', '100.103.',
        '100.104.', '100.105.', '100.106.', '100.107.',
        '100.108.', '100.109.', '100.110.', '100.111.',
        '100.112.', '100.113.', '100.114.', '100.115.',
        '100.116.', '100.117.', '100.118.', '100.119.',
        '100.120.', '100.121.', '100.122.', '100.123.',
        '100.124.', '100.125.', '100.126.', '100.127.',
    ];

    private static $localhostKeywords = [
        'localhost', 'localhost:', '127.0.0.1', '0.0.0.0',
        '::1', '0:0:0:0:0:0:0:1',
        'internal', 'internal.', 'localhost.localdomain',
        'localhost6.localdomain6', 'ip6-localhost', 'ip6-loopback',
        'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes',
        'ip6-allrouters', 'ip6-allhosts',
    ];

    private static $cloudMetadataEndpoints = [
        'http://169.254.169.254/',
        'http://169.254.169.254/latest/',
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://metadata.google.internal/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://100.100.100.200/',
        'http://localhost:9080/instance/latest/',
    ];

    private static $ssrfParamNames = [
        'url', 'uri', 'path', 'src', 'source',
        'redirect', 'redirect_url', 'redirect_to',
        'callback', 'callback_url', 'return_url',
        'referrer', 'referer', 'next', 'jump',
        'target', 'endpoint', 'api_url', 'api_endpoint',
        'service_url', 'service_endpoint', 'webhook',
        'feed', 'rss', 'xml', 'import', 'fetch',
        'download', 'upload', 'proxy', 'gateway',
    ];

    public static function check() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            $result = self::analyzeValue($key, $value);
            if ($result['is_ssrf']) {
                waf_block('SSRF attack detected - ' . $result['reason']);
            }
        }
    }

    private static function collectInputs() {
        $inputs = [];

        foreach ($_GET as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_POST as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_REQUEST as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_SERVER as $k => $v) {
            if (in_array(strtolower($k), ['http_referer', 'http_origin', 'http_x_forwarded_for', 'http_x_forwarded_host', 'http_x_forwarded_proto', 'http_x_real_ip'])) {
                $inputs[strtolower($k)] = (string)$v;
            }
        }

        return $inputs;
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);
        $lowerValue = strtolower($value);

        if (empty($value)) {
            return ['is_ssrf' => false, 'reason' => ''];
        }

        if (in_array($key, self::$ssrfParamNames)) {
            foreach (self::$cloudMetadataEndpoints as $endpoint) {
                if (strpos($lowerValue, strtolower($endpoint)) === 0) {
                    return ['is_ssrf' => true, 'reason' => "Cloud metadata endpoint: $endpoint"];
                }
            }

            foreach (self::$localhostKeywords as $keyword) {
                if (strpos($lowerValue, $keyword) !== false) {
                    $host = self::extractHost($value);
                    if (self::isPrivateIP($host)) {
                        return ['is_ssrf' => true, 'reason' => "Localhost/Private IP access: $host"];
                    }
                }
            }

            $host = self::extractHost($value);
            if (!empty($host) && self::isPrivateIP($host)) {
                return ['is_ssrf' => true, 'reason' => "Private IP access: $host"];
            }

            if (self::isIPV6Loopback($host)) {
                return ['is_ssrf' => true, 'reason' => "IPv6 loopback: $host"];
            }

            if (self::isNumericIP($value)) {
                return ['is_ssrf' => true, 'reason' => "Direct IP address used: $value"];
            }
        }

        return ['is_ssrf' => false, 'reason' => ''];
    }

    private static function extractHost($url) {
        if (preg_match('/^(?:https?:\/\/)?([^\/:?#]+)/', $url, $matches)) {
            return $matches[1];
        }
        return $url;
    }

    private static function isPrivateIP($host) {
        if (empty($host)) return false;

        foreach (self::$privateRanges as $prefix) {
            if (strpos($host, $prefix) === 0) {
                return true;
            }
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip = ip2long($host);
            if ($ip !== false) {
                if (($ip >= ip2long('10.0.0.0') && $ip <= ip2long('10.255.255.255')) ||
                    ($ip >= ip2long('172.16.0.0') && $ip <= ip2long('172.31.255.255')) ||
                    ($ip >= ip2long('192.168.0.0') && $ip <= ip2long('192.168.255.255')) ||
                    ($ip >= ip2long('127.0.0.0') && $ip <= ip2long('127.255.255.255'))) {
                    return true;
                }
            }
        }

        return false;
    }

    private static function isIPV6Loopback($host) {
        $host = strtolower($host);
        return $host === '::1' || strpos($host, '0:0:0:0:0:0:0:1') !== false;
    }

    private static function isNumericIP($value) {
        if (filter_var($value, FILTER_VALIDATE_IP)) {
            return true;
        }

        if (preg_match('/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/', $value)) {
            return true;
        }

        return false;
    }
}
