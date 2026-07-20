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

    // localhostKeywords 改为用于精确匹配 host 的关键字（不再做子串匹配）
    private static $localhostKeywords = [
        'localhost', 'localhost.localdomain',
        'localhost6.localdomain6', 'ip6-localhost', 'ip6-loopback',
        'ip6-localnet', 'ip6-mcastprefix', 'ip6-allnodes',
        'ip6-allrouters', 'ip6-allhosts',
        'metadata.google.internal',
    ];

    // 必须按 host 完全相等判定的 IP 字面量
    private static $loopbackIpLiterals = [
        '127.0.0.1', '0.0.0.0', '::1', '0:0:0:0:0:0:0:1',
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

        // 读取原始 POST Body，覆盖 JSON/XML 体的 SSRF 检测
        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : @file_get_contents('php://input');
        if (!empty($body)) {
            $inputs['body'] = $body;
            $json = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
                self::extractJsonValues($json, $inputs);
            }
        }

        return $inputs;
    }

    /**
     * 递归从 JSON 体中提取 URL/path 字符串，按字段名作为 key 入 inputs
     */
    private static function extractJsonValues($data, &$inputs, $prefix = '') {
        if (!is_array($data)) {
            return;
        }
        foreach ($data as $k => $v) {
            $key = $prefix === '' ? (string)$k : $prefix . '.' . (string)$k;
            if (is_array($v)) {
                self::extractJsonValues($v, $inputs, $key);
            } elseif (is_string($v) && !empty($v)) {
                $inputs[strtolower($key)] = $v;
            }
        }
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

            $host = self::extractHost($value);
            $lowerHost = $host === '' ? '' : strtolower($host);

            // localhost 关键字精确匹配 host（避免误伤 internal-api 等合法域名）
            if ($host !== '' && in_array($lowerHost, self::$localhostKeywords, true)) {
                return ['is_ssrf' => true, 'reason' => "Localhost keyword access: $host"];
            }

            // 回环 IP 字面量精确匹配
            if ($host !== '' && in_array($lowerHost, self::$loopbackIpLiterals, true)) {
                return ['is_ssrf' => true, 'reason' => "Loopback IP access: $host"];
            }

            if (!empty($host) && self::isPrivateIP($host)) {
                return ['is_ssrf' => true, 'reason' => "Private IP access: $host"];
            }

            if (self::isIPV6Loopback($host)) {
                return ['is_ssrf' => true, 'reason' => "IPv6 loopback: $host"];
            }

            // 只对私网/保留 IP 触发，公网 IP 不拦截
            if (self::isNumericIP($value) && self::isPrivateIP($value)) {
                return ['is_ssrf' => true, 'reason' => "Private IP access: $value"];
            }

            // DNS Rebinding 防护：对非 IP 字面量的域名做 DNS 解析，命中私网则拦截
            if (!empty($host) && !self::isNumericIP($host)) {
                $resolvedIp = @gethostbyname($host);
                if ($resolvedIp && $resolvedIp !== $host) {
                    if (self::isPrivateIP($resolvedIp)) {
                        return ['is_ssrf' => true, 'reason' => "DNS resolves to private IP: $host -> $resolvedIp"];
                    }
                }
            }
        }

        return ['is_ssrf' => false, 'reason' => ''];
    }

    private static function extractHost($url) {
        // 优先 parse_url，正确处理 userinfo 和 IPv6
        $parsed = parse_url($url, PHP_URL_HOST);
        if ($parsed) {
            return $parsed;
        }
        // 降级：正则匹配，处理 userinfo (user:pass@host) 和裸 host
        // 使用 ~ 作为分隔符，避免与 URL 中的 # 冲突
        if (preg_match('~^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?(?:[^/@]*@)?([^/:?#]+)~', $url, $matches)) {
            return $matches[1];
        }
        return '';
    }

    private static function isPrivateIP($host) {
        if (empty($host)) return false;

        $ip = filter_var($host, FILTER_VALIDATE_IP);
        if (!$ip) {
            // 非 IP 格式，可能是域名
            return false;
        }

        // IPv4 私网/保留段检测
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $long = ip2long($ip);
            if ($long === false) return false;
            $privateRanges = [
                [0, 16777215],           // 0.0.0.0/8
                [167772160, 184549375],   // 10.0.0.0/8
                [1681915904, 1686110207], // 100.64.0.0/10 CGNAT
                [2130706432, 2147483647], // 127.0.0.0/8
                [2851995648, 2852061183], // 169.254.0.0/16 链路本地
                [2886729728, 2887778303], // 172.16.0.0/12
                [3221225472, 3221225727], // 192.0.0.0/24
                [3221225984, 3221226239], // 192.0.2.0/24 (TEST-NET-1)
                [3227017984, 3227018239], // 198.51.100.0/24 (TEST-NET-2)
                [3232235520, 3232301055], // 192.168.0.0/16
                [3323068416, 3323199487], // 198.18.0.0/15
                [3325256704, 3325256959], // 203.0.113.0/24 (TEST-NET-3)
            ];
            foreach ($privateRanges as $range) {
                if ($long >= $range[0] && $long <= $range[1]) return true;
            }
            return false;
        }

        // IPv6 私网检测
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // ::1 回环
            if ($ip === '::1') return true;
            $bin = @inet_pton($ip);
            if ($bin !== false && strlen($bin) === 16) {
                $firstByte = ord($bin[0]);
                // fc00::/7 ULA
                if (($firstByte & 0xFE) === 0xFC) return true;
                // fe80::/10 链路本地
                if ($firstByte === 0xFE && (ord($bin[1]) & 0xC0) === 0x80) return true;
            }
            return false;
        }

        return false;
    }

    private static function isIPV6Loopback($host) {
        if (empty($host)) return false;
        $host = strtolower($host);
        if ($host === '::1') return true;
        // 仅做严格匹配，避免误伤含 0:0:0:0:0:0:0:1 子串的合法内容
        return $host === '0:0:0:0:0:0:0:1';
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
