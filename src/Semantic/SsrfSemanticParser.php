<?php
/**
 * SSRF（服务端请求伪造）语义解析器
 * 职责：使用 parse_url 真正解析URL结构，深度识别SSRF攻击，包括危险协议、内网IP、
 *       云平台元数据、编码绕过、DNS重绑定、端口扫描等多种SSRF攻击向量。
 */
defined('ABSPATH') || exit;

class SsrfSemanticParser {

    private static $dangerousSchemes = [
        'file'     => ['level' => 5, 'desc' => '本地文件协议'],
        'gopher'   => ['level' => 5, 'desc' => 'Gopher协议'],
        'dict'     => ['level' => 5, 'desc' => 'Dict协议'],
        'ftp'      => ['level' => 4, 'desc' => 'FTP协议'],
        'ldap'     => ['level' => 4, 'desc' => 'LDAP协议'],
        'tftp'     => ['level' => 4, 'desc' => 'TFTP协议'],
        'sftp'     => ['level' => 4, 'desc' => 'SFTP协议'],
        'smtp'     => ['level' => 4, 'desc' => 'SMTP协议'],
        'pop3'     => ['level' => 4, 'desc' => 'POP3协议'],
        'imap'     => ['level' => 4, 'desc' => 'IMAP协议'],
        'telnet'   => ['level' => 5, 'desc' => 'Telnet协议'],
        'ssh'      => ['level' => 4, 'desc' => 'SSH协议'],
        'php'      => ['level' => 5, 'desc' => 'PHP伪协议'],
        'zlib'     => ['level' => 3, 'desc' => 'Zlib压缩流'],
        'data'     => ['level' => 4, 'desc' => 'Data URI协议'],
        'expect'   => ['level' => 5, 'desc' => 'Expect命令执行协议'],
        'http'     => ['level' => 2, 'desc' => 'HTTP协议'],
        'https'    => ['level' => 2, 'desc' => 'HTTPS协议'],
    ];

    private static $cloudMetadataHosts = [
        '169.254.169.254'      => ['level' => 5, 'desc' => '云平台元数据服务 (AWS/Azure/GCP)'],
        'metadata.google.internal' => ['level' => 5, 'desc' => 'GCP元数据域名'],
        'metadata.internal'    => ['level' => 4, 'desc' => '阿里云元数据域名'],
        '100.100.100.200'      => ['level' => 5, 'desc' => '阿里云元数据服务'],
    ];

    private static $dnsRebindDomains = [
        'nip.io'    => ['level' => 4, 'desc' => 'nip.io DNS重绑定'],
        'sslip.io'  => ['level' => 4, 'desc' => 'sslip.io DNS重绑定'],
        'xip.io'    => ['level' => 4, 'desc' => 'xip.io DNS重绑定'],
        'lvh.me'    => ['level' => 3, 'desc' => 'lvh.me 本地域名'],
        'localtest.me' => ['level' => 3, 'desc' => 'localtest.me 本地域名'],
    ];

    private static $shortUrlServices = [
        't.cn', 'url.cn', 'dwz.cn', 'bit.ly', 'tinyurl.com',
        'goo.gl', 'is.gd', 'buff.ly', 'adf.ly', 'ow.ly',
        'rb.gy', 'j.mp', 'snip.ly', 'shorte.st', 'bc.vc',
    ];

    private static $nonStandardPorts = [
        22     => ['level' => 2, 'desc' => 'SSH端口'],
        23     => ['level' => 3, 'desc' => 'Telnet端口'],
        25     => ['level' => 3, 'desc' => 'SMTP端口'],
        53     => ['level' => 3, 'desc' => 'DNS端口'],
        110    => ['level' => 2, 'desc' => 'POP3端口'],
        143    => ['level' => 2, 'desc' => 'IMAP端口'],
        445    => ['level' => 4, 'desc' => 'SMB端口'],
        3306   => ['level' => 4, 'desc' => 'MySQL端口'],
        5432   => ['level' => 4, 'desc' => 'PostgreSQL端口'],
        6379   => ['level' => 4, 'desc' => 'Redis端口'],
        11211  => ['level' => 4, 'desc' => 'Memcache端口'],
        27017  => ['level' => 4, 'desc' => 'MongoDB端口'],
        9200   => ['level' => 3, 'desc' => 'Elasticsearch端口'],
        9300   => ['level' => 3, 'desc' => 'Elasticsearch传输端口'],
        8080   => ['level' => 1, 'desc' => 'HTTP代理端口'],
        8443   => ['level' => 1, 'desc' => 'HTTPS代理端口'],
        8000   => ['level' => 1, 'desc' => '开发常用端口'],
        3000   => ['level' => 1, 'desc' => '开发常用端口'],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $urlDecoded = urldecode($input);
        $doubleDecoded = urldecode($urlDecoded);

        $testInputs = [
            'original' => $input,
            'urldecoded' => $urlDecoded,
            'double_decoded' => $doubleDecoded,
        ];

        $parsedUrls = [];
        foreach ($testInputs as $key => $testInput) {
            $parsed = self::tryParseUrl($testInput);
            if ($parsed !== null) {
                $parsed['source'] = $key;
                $parsedUrls[] = $parsed;
            }
            $extracted = self::extractUrlsFromString($testInput);
            foreach ($extracted as $extUrl) {
                $p = self::tryParseUrl($extUrl);
                if ($p !== null) {
                    $p['source'] = $key . '_extracted';
                    $parsedUrls[] = $p;
                }
            }
        }

        if (empty($parsedUrls)) {
            $hasAnyIndicator = false;
            foreach ($testInputs as $testInput) {
                if (self::hasIpLikePattern($testInput) || self::hasUrlLikePattern($testInput)) {
                    $hasAnyIndicator = true;
                    break;
                }
            }
            if (!$hasAnyIndicator) {
                return $result;
            }
        }

        $score = 0;
        $indicators = [];
        $dangerousSchemesFound = [];
        $internalIpHits = [];
        $cloudMetadataHits = [];
        $bypassHits = [];
        $dnsRebindHits = [];
        $portScanHits = [];
        $hasAtSignBypass = false;
        $hasNestedUrl = false;
        $hasShortUrl = false;
        $ipNormalized = null;

        foreach ($parsedUrls as $parsed) {
            if (isset($parsed['scheme'])) {
                $schemeLower = strtolower($parsed['scheme']);
                if (isset(self::$dangerousSchemes[$schemeLower])) {
                    if (!isset($dangerousSchemesFound[$schemeLower])) {
                        $dangerousSchemesFound[$schemeLower] = [
                            'scheme' => $schemeLower,
                            'level'  => self::$dangerousSchemes[$schemeLower]['level'],
                            'desc'   => self::$dangerousSchemes[$schemeLower]['desc'],
                            'source' => $parsed['source'],
                        ];
                    }
                }
            }

            if (isset($parsed['host'])) {
                $host = $parsed['host'];

                if (strpos($host, '@') !== false) {
                    $hasAtSignBypass = true;
                    $parts = explode('@', $host);
                    $host = end($parts);
                }

                $hostLower = strtolower($host);

                foreach (self::$cloudMetadataHosts as $metaHost => $metaInfo) {
                    if ($hostLower === strtolower($metaHost) || substr($hostLower, -strlen($metaHost)) === strtolower($metaHost)) {
                        if (!isset($cloudMetadataHits[$metaHost])) {
                            $cloudMetadataHits[$metaHost] = [
                                'type'  => $metaHost,
                                'level' => $metaInfo['level'],
                                'desc'  => $metaInfo['desc'],
                                'source' => $parsed['source'],
                            ];
                        }
                    }
                }

                foreach (self::$dnsRebindDomains as $domain => $domainInfo) {
                    if (substr($hostLower, -strlen($domain)) === $domain) {
                        if (!isset($dnsRebindHits[$domain])) {
                            $dnsRebindHits[$domain] = [
                                'type'  => $domain,
                                'level' => $domainInfo['level'],
                                'desc'  => $domainInfo['desc'],
                                'source' => $parsed['source'],
                            ];
                        }
                    }
                }

                foreach (self::$shortUrlServices as $shortUrl) {
                    if ($hostLower === $shortUrl || substr($hostLower, -strlen('.' . $shortUrl)) === '.' . $shortUrl) {
                        $hasShortUrl = true;
                        break;
                    }
                }

                if (strtolower($host) === 'localhost') {
                    if (!isset($internalIpHits['localhost'])) {
                        $internalIpHits['localhost'] = [
                            'type'   => 'localhost',
                            'level'  => 5,
                            'desc'   => 'localhost 本地主机',
                            'source' => $parsed['source'],
                        ];
                    }
                }

                $ipResult = self::normalizeIp($host);
                if ($ipResult !== null) {
                    $ipNormalized = $ipResult['ip'];
                    if ($ipResult['is_hex'] || $ipResult['is_octal'] || $ipResult['is_decimal']) {
                        $bypassType = '';
                        $bypassLevel = 0;
                        $bypassDesc = '';
                        if ($ipResult['is_hex']) {
                            $bypassType = 'hex_ip';
                            $bypassLevel = 4;
                            $bypassDesc = '十六进制编码IP绕过';
                        } elseif ($ipResult['is_octal']) {
                            $bypassType = 'octal_ip';
                            $bypassLevel = 3;
                            $bypassDesc = '八进制编码IP绕过';
                        } elseif ($ipResult['is_decimal']) {
                            $bypassType = 'decimal_ip';
                            $bypassLevel = 3;
                            $bypassDesc = '十进制整数IP绕过';
                        }
                        if (!isset($bypassHits[$bypassType])) {
                            $bypassHits[$bypassType] = [
                                'type'   => $bypassType,
                                'level'  => $bypassLevel,
                                'desc'   => $bypassDesc,
                                'source' => $parsed['source'],
                            ];
                        }
                    }

                    $internalCheck = self::checkInternalIp($ipNormalized);
                    if ($internalCheck !== null) {
                        $key = $internalCheck['type'];
                        if (!isset($internalIpHits[$key])) {
                            $internalIpHits[$key] = [
                                'type'   => $key,
                                'level'  => $internalCheck['level'],
                                'desc'   => $internalCheck['desc'],
                                'ip'     => $ipNormalized,
                                'source' => $parsed['source'],
                            ];
                        }
                    }
                }

                $nestedCheckParts = [];
                if (isset($parsed['path'])) $nestedCheckParts[] = $parsed['path'];
                if (isset($parsed['query'])) $nestedCheckParts[] = $parsed['query'];
                if (isset($parsed['fragment'])) $nestedCheckParts[] = $parsed['fragment'];
                foreach ($nestedCheckParts as $checkPart) {
                    if (preg_match('/https?:\/\//i', $checkPart) || preg_match('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $checkPart)) {
                        $hasNestedUrl = true;
                        break;
                    }
                }

                if (isset($parsed['port'])) {
                    $port = (int)$parsed['port'];
                    if ($port !== 80 && $port !== 443) {
                        if (isset(self::$nonStandardPorts[$port])) {
                            $portKey = 'port_' . $port;
                            if (!isset($portScanHits[$portKey])) {
                                $portScanHits[$portKey] = [
                                    'port'   => $port,
                                    'level'  => self::$nonStandardPorts[$port]['level'],
                                    'desc'   => self::$nonStandardPorts[$port]['desc'],
                                    'source' => $parsed['source'],
                                ];
                            }
                        } else {
                            $portKey = 'port_' . $port;
                            if (!isset($portScanHits[$portKey])) {
                                $level = ($port < 1024) ? 2 : 1;
                                $portScanHits[$portKey] = [
                                    'port'   => $port,
                                    'level'  => $level,
                                    'desc'   => '非标准端口',
                                    'source' => $parsed['source'],
                                ];
                            }
                        }
                    }
                }
            }
        }

        foreach ($testInputs as $testInput) {
            if (preg_match('/%[0-9a-fA-F]{2}/', $testInput)) {
                if (!isset($bypassHits['url_encoded'])) {
                    $bypassHits['url_encoded'] = [
                        'type'  => 'url_encoded',
                        'level' => 2,
                        'desc'  => 'URL编码',
                    ];
                }
                break;
            }
        }

        foreach ($testInputs as $testInput) {
            if (preg_match('/%25[0-9a-fA-F]{2}/i', $testInput)) {
                if (!isset($bypassHits['double_encode'])) {
                    $bypassHits['double_encode'] = [
                        'type'  => 'double_encode',
                        'level' => 4,
                        'desc'  => '双重URL编码',
                    ];
                }
                break;
            }
        }

        $maxSchemeLevel = 0;
        foreach ($dangerousSchemesFound as $s) {
            if ($s['level'] > $maxSchemeLevel) $maxSchemeLevel = $s['level'];
        }

        $maxInternalLevel = 0;
        foreach ($internalIpHits as $h) {
            if ($h['level'] > $maxInternalLevel) $maxInternalLevel = $h['level'];
        }

        $maxCloudLevel = 0;
        foreach ($cloudMetadataHits as $h) {
            if ($h['level'] > $maxCloudLevel) $maxCloudLevel = $h['level'];
        }

        $maxBypassLevel = 0;
        foreach ($bypassHits as $h) {
            if ($h['level'] > $maxBypassLevel) $maxBypassLevel = $h['level'];
        }

        $maxDnsLevel = 0;
        foreach ($dnsRebindHits as $h) {
            if ($h['level'] > $maxDnsLevel) $maxDnsLevel = $h['level'];
        }

        $maxPortLevel = 0;
        foreach ($portScanHits as $h) {
            if ($h['level'] > $maxPortLevel) $maxPortLevel = $h['level'];
        }

        if ($maxSchemeLevel >= 5) { $score += 30; $indicators[] = 'critical_dangerous_scheme'; }
        elseif ($maxSchemeLevel >= 4) { $score += 22; $indicators[] = 'high_dangerous_scheme'; }
        elseif ($maxSchemeLevel >= 3) { $score += 14; $indicators[] = 'medium_dangerous_scheme'; }
        elseif ($maxSchemeLevel >= 2) { $score += 8; $indicators[] = 'low_scheme'; }

        if ($maxInternalLevel >= 5) { $score += 28; $indicators[] = 'critical_internal_ip'; }
        elseif ($maxInternalLevel >= 4) { $score += 20; $indicators[] = 'high_internal_ip'; }
        elseif ($maxInternalLevel >= 3) { $score += 12; $indicators[] = 'medium_internal_ip'; }

        if ($maxCloudLevel >= 5) { $score += 35; $indicators[] = 'critical_cloud_metadata'; }
        elseif ($maxCloudLevel >= 4) { $score += 25; $indicators[] = 'high_cloud_metadata'; }

        if ($maxBypassLevel >= 5) { $score += 25; $indicators[] = 'critical_bypass_technique'; }
        elseif ($maxBypassLevel >= 4) { $score += 18; $indicators[] = 'high_bypass_technique'; }
        elseif ($maxBypassLevel >= 3) { $score += 12; $indicators[] = 'medium_bypass_technique'; }
        elseif ($maxBypassLevel >= 2) { $score += 6; $indicators[] = 'low_bypass_technique'; }

        if ($maxDnsLevel >= 5) { $score += 25; $indicators[] = 'critical_dns_rebind'; }
        elseif ($maxDnsLevel >= 4) { $score += 18; $indicators[] = 'high_dns_rebind'; }
        elseif ($maxDnsLevel >= 3) { $score += 10; $indicators[] = 'medium_dns_rebind'; }

        if ($maxPortLevel >= 4) { $score += 15; $indicators[] = 'high_risk_port'; }
        elseif ($maxPortLevel >= 3) { $score += 10; $indicators[] = 'medium_risk_port'; }
        elseif ($maxPortLevel >= 2) { $score += 6; $indicators[] = 'low_risk_port'; }
        elseif ($maxPortLevel >= 1) { $score += 3; $indicators[] = 'non_standard_port'; }

        if ($hasAtSignBypass) { $score += 12; $indicators[] = 'at_sign_bypass'; }
        if ($hasNestedUrl) { $score += 20; $indicators[] = 'nested_url_redirect'; }
        if ($hasShortUrl) { $score += 8; $indicators[] = 'short_url_bypass'; }

        if (!empty($internalIpHits) && !empty($cloudMetadataHits)) {
            $score += 10;
            $indicators[] = 'internal_plus_cloud_metadata';
        }

        if (count($bypassHits) >= 2) {
            $score += 8;
            $indicators[] = 'multiple_bypass_techniques';
        }

        if ($maxSchemeLevel >= 4 && !empty($internalIpHits)) {
            $score += 12;
            $indicators[] = 'dangerous_scheme_plus_internal';
        }

        if ($maxSchemeLevel >= 4 && $maxPortLevel >= 3) {
            $score += 10;
            $indicators[] = 'scheme_plus_port_combo';
        }

        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        return [
            'score'              => min(100, $score),
            'risk_level'         => $riskLevel,
            'is_ssrf'            => $score >= 25,
            'has_internal_ip'    => !empty($internalIpHits),
            'has_cloud_metadata' => !empty($cloudMetadataHits),
            'has_dns_rebind'     => !empty($dnsRebindHits),
            'has_at_sign_bypass' => $hasAtSignBypass,
            'has_nested_url'     => $hasNestedUrl,
            'has_short_url'      => $hasShortUrl,
            'normalized_ip'      => $ipNormalized,
            'parsed_url_count'   => count($parsedUrls),
            'dangerous_schemes'  => array_values($dangerousSchemesFound),
            'bypass_techniques'  => array_values($bypassHits),
            'internal_ip_hits'   => array_values($internalIpHits),
            'cloud_metadata_hits'=> array_values($cloudMetadataHits),
            'dns_rebind_hits'    => array_values($dnsRebindHits),
            'port_scan_hits'     => array_values($portScanHits),
            'indicators'         => $indicators,
        ];
    }

    private static function defaultResult(): array {
        return [
            'score'              => 0,
            'risk_level'         => 'clean',
            'is_ssrf'            => false,
            'has_internal_ip'    => false,
            'has_cloud_metadata' => false,
            'has_dns_rebind'     => false,
            'has_at_sign_bypass' => false,
            'has_nested_url'     => false,
            'has_short_url'      => false,
            'normalized_ip'      => null,
            'parsed_url_count'   => 0,
            'dangerous_schemes'  => [],
            'bypass_techniques'  => [],
            'internal_ip_hits'   => [],
            'cloud_metadata_hits'=> [],
            'dns_rebind_hits'    => [],
            'port_scan_hits'     => [],
            'indicators'         => [],
        ];
    }

    private static function tryParseUrl(string $input): ?array {
        $input = trim($input);
        if ($input === '') return null;

        if (!preg_match('/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $input)) {
            return null;
        }

        $parsed = @parse_url($input);
        if ($parsed === false || empty($parsed)) {
            return null;
        }

        if (!isset($parsed['scheme'])) {
            return null;
        }

        return $parsed;
    }

    private static function extractUrlsFromString(string $input): array {
        $urls = [];

        if (preg_match_all('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s"\'<>)]+/', $input, $matches)) {
            foreach ($matches[0] as $match) {
                $match = rtrim($match, '.,;)]}>');
                $urls[] = $match;
            }
        }

        return array_values(array_unique($urls));
    }

    private static function hasUrlLikePattern(string $input): bool {
        if (preg_match('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $input)) return true;
        return false;
    }

    private static function hasIpLikePattern(string $input): bool {
        if (preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $input)) return true;
        if (preg_match('/0x[0-9a-fA-F]{6,}/', $input)) return true;
        if (preg_match('/\b\d{8,10}\b/', $input)) return true;
        if (preg_match('/0[0-7]{9,}/', $input)) return true;
        return false;
    }

    private static function normalizeIp(string $host): ?array {
        $host = trim($host);
        if ($host === '') return null;

        $isHex = false;
        $isOctal = false;
        $isDecimal = false;

        if (preg_match('/^(0x[0-9a-fA-F]+)$/', $host, $m)) {
            $decimal = hexdec($m[1]);
            $isHex = true;
            if ($decimal >= 0 && $decimal <= 4294967295) {
                $ip = long2ip($decimal);
                return ['ip' => $ip, 'is_hex' => true, 'is_octal' => false, 'is_decimal' => false];
            }
        }

        if (preg_match('/^(0[0-7]+)$/', $host, $m)) {
            $decimal = octdec($m[1]);
            $isOctal = true;
            if ($decimal >= 0 && $decimal <= 4294967295) {
                $ip = long2ip($decimal);
                return ['ip' => $ip, 'is_hex' => false, 'is_octal' => true, 'is_decimal' => false];
            }
        }

        if (preg_match('/^(\d{8,10})$/', $host, $m)) {
            $decimal = (int)$m[1];
            $isDecimal = true;
            if ($decimal >= 0 && $decimal <= 4294967295) {
                $ip = long2ip($decimal);
                return ['ip' => $ip, 'is_hex' => false, 'is_octal' => false, 'is_decimal' => true];
            }
        }

        if (preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/', $host, $m)) {
            $parts = [(int)$m[1], (int)$m[2], (int)$m[3], (int)$m[4]];
            $valid = true;
            $hasOctal = false;
            foreach ([$m[1], $m[2], $m[3], $m[4]] as $idx => $part) {
                if (strlen($part) > 1 && $part[0] === '0' && preg_match('/^0[0-7]+$/', $part)) {
                    $hasOctal = true;
                    $parts[$idx] = octdec($part);
                }
                if ($parts[$idx] < 0 || $parts[$idx] > 255) {
                    $valid = false;
                }
            }
            if ($valid) {
                $ip = implode('.', $parts);
                return [
                    'ip' => $ip,
                    'is_hex' => false,
                    'is_octal' => $hasOctal,
                    'is_decimal' => false,
                ];
            }
        }

        if (preg_match('/^(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)$/i', $host, $m)) {
            $parts = [hexdec($m[1]), hexdec($m[2]), hexdec($m[3]), hexdec($m[4])];
            $valid = true;
            foreach ($parts as $p) {
                if ($p < 0 || $p > 255) $valid = false;
            }
            if ($valid) {
                $ip = implode('.', $parts);
                return ['ip' => $ip, 'is_hex' => true, 'is_octal' => false, 'is_decimal' => false];
            }
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ['ip' => $host, 'is_hex' => false, 'is_octal' => false, 'is_decimal' => false];
        }

        return null;
    }

    private static function checkInternalIp(string $ip): ?array {
        $ipLong = ip2long($ip);
        if ($ipLong === false) return null;

        if ($ipLong >= ip2long('127.0.0.0') && $ipLong <= ip2long('127.255.255.255')) {
            return ['type' => '127_loopback', 'level' => 5, 'desc' => '回环地址 127.x.x.x'];
        }

        if ($ipLong >= ip2long('10.0.0.0') && $ipLong <= ip2long('10.255.255.255')) {
            return ['type' => '10_private', 'level' => 4, 'desc' => '10.x.x.x 内网段'];
        }

        if ($ipLong >= ip2long('172.16.0.0') && $ipLong <= ip2long('172.31.255.255')) {
            return ['type' => '172_16_31', 'level' => 4, 'desc' => '172.16-31.x.x 内网段'];
        }

        if ($ipLong >= ip2long('192.168.0.0') && $ipLong <= ip2long('192.168.255.255')) {
            return ['type' => '192_168', 'level' => 4, 'desc' => '192.168.x.x 内网段'];
        }

        if ($ipLong >= ip2long('169.254.0.0') && $ipLong <= ip2long('169.254.255.255')) {
            return ['type' => '169_254', 'level' => 5, 'desc' => '169.254.x.x 链路本地地址'];
        }

        if ($ipLong === ip2long('0.0.0.0')) {
            return ['type' => '0_0_0_0', 'level' => 4, 'desc' => '0.0.0.0 任意地址'];
        }

        return null;
    }
}
