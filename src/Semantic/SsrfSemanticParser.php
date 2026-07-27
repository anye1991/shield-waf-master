<?php
defined('ABSPATH') || exit;

class SsrfSemanticParser {

    const TOKEN_SCHEME       = 'SCHEME';
    const TOKEN_COLON_SLASH  = 'COLON_SLASH';
    const TOKEN_AT           = 'AT';
    const TOKEN_COLON        = 'COLON';
    const TOKEN_SLASH        = 'SLASH';
    const TOKEN_QUESTION     = 'QUESTION';
    const TOKEN_HASH         = 'HASH';
    const TOKEN_EQUALS       = 'EQUALS';
    const TOKEN_AMPERSAND    = 'AMPERSAND';
    const TOKEN_DOT          = 'DOT';
    const TOKEN_USERINFO     = 'USERINFO';
    const TOKEN_HOST         = 'HOST';
    const TOKEN_PORT         = 'PORT';
    const TOKEN_PATH_SEGMENT = 'PATH_SEGMENT';
    const TOKEN_QUERY_KEY    = 'QUERY_KEY';
    const TOKEN_QUERY_VALUE  = 'QUERY_VALUE';
    const TOKEN_FRAGMENT     = 'FRAGMENT';
    const TOKEN_RAW_TEXT     = 'RAW_TEXT';
    const TOKEN_EOF          = 'EOF';

    private static $dangerousSchemes = [
        'file'     => ['level' => 5, 'desc' => '本地文件协议', 'category' => 'file_read'],
        'gopher'   => ['level' => 5, 'desc' => 'Gopher协议', 'category' => 'ssrf'],
        'dict'     => ['level' => 5, 'desc' => 'Dict协议', 'category' => 'ssrf'],
        'ftp'      => ['level' => 4, 'desc' => 'FTP协议', 'category' => 'ssrf'],
        'ldap'     => ['level' => 4, 'desc' => 'LDAP协议', 'category' => 'ssrf'],
        'tftp'     => ['level' => 4, 'desc' => 'TFTP协议', 'category' => 'ssrf'],
        'sftp'     => ['level' => 4, 'desc' => 'SFTP协议', 'category' => 'ssrf'],
        'smtp'     => ['level' => 4, 'desc' => 'SMTP协议', 'category' => 'ssrf'],
        'pop3'     => ['level' => 4, 'desc' => 'POP3协议', 'category' => 'ssrf'],
        'imap'     => ['level' => 4, 'desc' => 'IMAP协议', 'category' => 'ssrf'],
        'telnet'   => ['level' => 5, 'desc' => 'Telnet协议', 'category' => 'code_exec'],
        'ssh'      => ['level' => 4, 'desc' => 'SSH协议', 'category' => 'ssrf'],
        'php'      => ['level' => 5, 'desc' => 'PHP伪协议', 'category' => 'code_exec'],
        'zlib'     => ['level' => 3, 'desc' => 'Zlib压缩流', 'category' => 'file_read'],
        'data'     => ['level' => 4, 'desc' => 'Data URI协议', 'category' => 'file_read'],
        'expect'   => ['level' => 5, 'desc' => 'Expect命令执行协议', 'category' => 'code_exec'],
        'jar'      => ['level' => 4, 'desc' => 'Jar协议', 'category' => 'file_read'],
        'zip'      => ['level' => 4, 'desc' => 'Zip协议', 'category' => 'file_read'],
        'glob'     => ['level' => 4, 'desc' => 'Glob协议', 'category' => 'file_read'],
        'http'     => ['level' => 2, 'desc' => 'HTTP协议', 'category' => 'http'],
        'https'    => ['level' => 2, 'desc' => 'HTTPS协议', 'category' => 'http'],
    ];

    private static $cloudMetadataHosts = [
        '169.254.169.254'      => ['level' => 5, 'desc' => '云平台元数据服务 (AWS/Azure/GCP)'],
        'metadata.google.internal' => ['level' => 5, 'desc' => 'GCP元数据域名'],
        'metadata.internal'    => ['level' => 4, 'desc' => '阿里云元数据域名'],
        '100.100.100.200'      => ['level' => 5, 'desc' => '阿里云元数据服务'],
        'metadata'             => ['level' => 4, 'desc' => '通用元数据域名'],
        '169.254.169.254/latest/meta-data' => ['level' => 5, 'desc' => 'AWS元数据路径'],
    ];

    private static $cloudMetadataPaths = [
        '/latest/meta-data/'    => 5,
        '/computeMetadata/v1/'  => 5,
        '/metadata/v1/'         => 4,
        '/latest/user-data/'    => 5,
        '/instance/attributes/' => 4,
        '/service-accounts/'    => 5,
    ];

    private static $dnsRebindDomains = [
        'nip.io'    => ['level' => 4, 'desc' => 'nip.io DNS重绑定'],
        'sslip.io'  => ['level' => 4, 'desc' => 'sslip.io DNS重绑定'],
        'xip.io'    => ['level' => 4, 'desc' => 'xip.io DNS重绑定'],
        'lvh.me'    => ['level' => 3, 'desc' => 'lvh.me 本地域名'],
        'localtest.me' => ['level' => 3, 'desc' => 'localtest.me 本地域名'],
        'localhost.localdomain' => ['level' => 3, 'desc' => 'localhost别名'],
        'internal'  => ['level' => 3, 'desc' => 'internal域名'],
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

    private static $bypassIndicators = [
        '/%2e%2e/'              => ['level' => 4, 'desc' => 'URL编码路径遍历'],
        '/%2f/'                 => ['level' => 3, 'desc' => 'URL编码斜杠'],
        '/%252e%252e/'          => ['level' => 5, 'desc' => '双重URL编码路径遍历'],
        '/%252f/'               => ['level' => 4, 'desc' => '双重URL编码斜杠'],
        '/\.\./'                => ['level' => 3, 'desc' => '路径遍历'],
        '/@/'                   => ['level' => 3, 'desc' => '@符号绕过'],
        '/%40/'                 => ['level' => 4, 'desc' => 'URL编码@符号'],
        '/localhost/'           => ['level' => 4, 'desc' => 'localhost'],
        '/127\.0\.0\.1/'        => ['level' => 5, 'desc' => '回环地址'],
        '/0\.0\.0\.0/'          => ['level' => 4, 'desc' => '任意地址'],
        '/\[::1\]/'             => ['level' => 5, 'desc' => 'IPv6回环'],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        try {
            $tokens = self::tokenizeUrl($input);
            $result['token_count'] = count($tokens);

            $ast = self::parseUrlTokens($tokens);
            if ($ast !== null) {
                $result['parser_used'] = 'ast';
                $result['ast'] = $ast;
                $result['ast_summary'] = self::summarizeAst($ast);

                $semanticResult = self::analyzeAst($ast);
                $result = array_merge($result, $semanticResult);
            } else {
                $result['parser_used'] = 'fallback';
                $result = array_merge($result, self::regexFallback($input));
            }
        } catch (Exception $e) {
            $result['parser_used'] = 'fallback';
            $result['parse_errors'][] = $e->getMessage();
            $result = array_merge($result, self::regexFallback($input));
        }

        $score = self::calculateScore($result);
        $result['score'] = min(100, $score);
        $result['risk_level'] = self::calculateRiskLevel($score);
        $result['is_ssrf'] = $score >= 25;

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'               => 0,
            'risk_level'          => 'clean',
            'is_ssrf'             => false,
            'parser_used'         => 'ast',
            'token_count'         => 0,
            'ast'                 => null,
            'ast_summary'         => [],
            'parse_errors'        => [],
            'scheme'              => null,
            'host'                => null,
            'port'                => null,
            'has_dangerous_scheme'=> false,
            'has_internal_ip'     => false,
            'has_cloud_metadata'  => false,
            'has_dns_rebind'      => false,
            'has_at_sign_bypass'  => false,
            'has_nested_url'      => false,
            'has_short_url'       => false,
            'has_path_traversal'  => false,
            'normalized_ip'       => null,
            'dangerous_schemes'   => [],
            'bypass_techniques'   => [],
            'internal_ip_hits'    => [],
            'cloud_metadata_hits' => [],
            'dns_rebind_hits'     => [],
            'port_scan_hits'      => [],
            'path_traversal_hits' => [],
            'indicators'          => [],
        ];
    }

    // ==================== Tokenizer ====================

    private static function tokenizeUrl(string $url): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($url);

        while ($pos < $len) {
            $char = $url[$pos];

            if (ctype_space($char)) {
                $pos++;
                continue;
            }

            if (ctype_alpha($char) && $pos === 0) {
                $start = $pos;
                while ($pos < $len && (ctype_alnum($url[$pos]) || $url[$pos] === '+' || $url[$pos] === '-' || $url[$pos] === '.')) {
                    $pos++;
                }
                if ($pos < $len && $url[$pos] === ':') {
                    $scheme = substr($url, $start, $pos - $start);
                    $tokens[] = ['type' => self::TOKEN_SCHEME, 'value' => $scheme, 'pos' => $start];
                    if ($pos + 2 < $len && $url[$pos + 1] === '/' && $url[$pos + 2] === '/') {
                        $tokens[] = ['type' => self::TOKEN_COLON_SLASH, 'value' => '://', 'pos' => $pos];
                        $pos += 3;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_COLON, 'value' => ':', 'pos' => $pos];
                        $pos++;
                    }
                    continue;
                }
                $pos = $start;
            }

            switch ($char) {
                case '@':
                    $tokens[] = ['type' => self::TOKEN_AT, 'value' => '@', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case ':':
                    $tokens[] = ['type' => self::TOKEN_COLON, 'value' => ':', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case '/':
                    $tokens[] = ['type' => self::TOKEN_SLASH, 'value' => '/', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case '?':
                    $tokens[] = ['type' => self::TOKEN_QUESTION, 'value' => '?', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case '#':
                    $tokens[] = ['type' => self::TOKEN_HASH, 'value' => '#', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case '=':
                    $tokens[] = ['type' => self::TOKEN_EQUALS, 'value' => '=', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case '&':
                    $tokens[] = ['type' => self::TOKEN_AMPERSAND, 'value' => '&', 'pos' => $pos];
                    $pos++;
                    continue 2;
                case '.':
                    $tokens[] = ['type' => self::TOKEN_DOT, 'value' => '.', 'pos' => $pos];
                    $pos++;
                    continue 2;
            }

            $start = $pos;
            while ($pos < $len && !in_array($url[$pos], ['@', ':', '/', '?', '#', '=', '&', '.', ' ', "\t", "\n", "\r"])) {
                $pos++;
            }
            if ($pos > $start) {
                $tokens[] = ['type' => self::TOKEN_RAW_TEXT, 'value' => substr($url, $start, $pos - $start), 'pos' => $start];
            } else {
                $pos++;
            }
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    // ==================== Parser ====================

    private static function parseUrlTokens(array $tokens): ?array {
        if (empty($tokens)) return null;

        $state = ['tokens' => $tokens, 'pos' => 0];

        $ast = [
            'type'      => 'url',
            'scheme'    => null,
            'scheme_node' => null,
            'authority' => null,
            'user'      => null,
            'pass'      => null,
            'host'      => null,
            'host_node' => null,
            'port'      => null,
            'path'      => [],
            'path_raw'  => '',
            'path_nodes' => [],
            'query'     => [],
            'query_raw' => null,
            'query_nodes' => [],
            'fragment'  => null,
            'fragment_node' => null,
            'has_at_sign' => false,
        ];

        $token = self::currentToken($state);
        if ($token['type'] === self::TOKEN_SCHEME) {
            $ast['scheme'] = $token['value'];
            $ast['scheme_node'] = $token;
            self::nextToken($state);

            $token = self::currentToken($state);
            if ($token['type'] === self::TOKEN_COLON_SLASH || $token['type'] === self::TOKEN_COLON) {
                self::nextToken($state);
            }
        } else {
            return null;
        }

        $authorityTokens = [];
        $atCount = 0;
        $tempPos = $state['pos'];

        while ($tempPos < count($tokens) - 1) {
            $t = $tokens[$tempPos];
            if ($t['type'] === self::TOKEN_SLASH || $t['type'] === self::TOKEN_QUESTION || $t['type'] === self::TOKEN_HASH || $t['type'] === self::TOKEN_EOF) {
                break;
            }
            if ($t['type'] === self::TOKEN_AT) $atCount++;
            $authorityTokens[] = $t;
            $tempPos++;
        }

        $ast['has_at_sign'] = ($atCount > 0);

        if (!empty($authorityTokens)) {
            $userinfo = null;
            $hostPart = [];

            if ($atCount > 0) {
                $atIndex = 0;
                for ($i = count($authorityTokens) - 1; $i >= 0; $i--) {
                    if ($authorityTokens[$i]['type'] === self::TOKEN_AT) {
                        $atIndex = $i;
                        break;
                    }
                }
                $userinfoTokens = array_slice($authorityTokens, 0, $atIndex);
                $hostTokens = array_slice($authorityTokens, $atIndex + 1);

                $userinfoStr = '';
                foreach ($userinfoTokens as $t) {
                    $userinfoStr .= $t['value'];
                }
                $userinfo = $userinfoStr;

                $colonPos = -1;
                foreach ($userinfoTokens as $idx => $t) {
                    if ($t['type'] === self::TOKEN_COLON) {
                        $colonPos = $idx;
                        break;
                    }
                }
                if ($colonPos >= 0) {
                    $userStr = '';
                    for ($i = 0; $i < $colonPos; $i++) {
                        $userStr .= $userinfoTokens[$i]['value'];
                    }
                    $passStr = '';
                    for ($i = $colonPos + 1; $i < count($userinfoTokens); $i++) {
                        $passStr .= $userinfoTokens[$i]['value'];
                    }
                    $ast['user'] = $userStr;
                    $ast['pass'] = $passStr;
                } else {
                    $ast['user'] = $userinfoStr;
                }
                $hostPart = $hostTokens;
            } else {
                $hostPart = $authorityTokens;
            }

            $portIndex = -1;
            $colonCount = 0;
            foreach ($hostPart as $idx => $t) {
                if ($t['type'] === self::TOKEN_COLON) {
                    $colonCount++;
                    $portIndex = $idx;
                }
            }

            $isIpv6 = ($colonCount > 1);

            if ($colonCount === 1 && !$isIpv6 && $portIndex >= 0) {
                $hostStr = '';
                for ($i = 0; $i < $portIndex; $i++) {
                    $hostStr .= $hostPart[$i]['value'];
                }
                $portStr = '';
                for ($i = $portIndex + 1; $i < count($hostPart); $i++) {
                    $portStr .= $hostPart[$i]['value'];
                }
                $ast['host'] = $hostStr;
                $ast['host_node'] = ['tokens' => array_slice($hostPart, 0, $portIndex)];
                if (ctype_digit($portStr)) {
                    $ast['port'] = (int)$portStr;
                }
            } else {
                $hostStr = '';
                foreach ($hostPart as $t) {
                    $hostStr .= $t['value'];
                }
                $ast['host'] = $hostStr;
                $ast['host_node'] = ['tokens' => $hostPart];
            }

            $state['pos'] = $tempPos;
        }

        $pathSegments = [];
        $pathRaw = '';
        $pathNodes = [];
        if (self::currentToken($state)['type'] === self::TOKEN_SLASH) {
            while (self::currentToken($state)['type'] === self::TOKEN_SLASH) {
                $slashToken = self::currentToken($state);
                self::nextToken($state);
                $pathRaw .= '/';
                $segment = '';
                $segmentTokens = [];

                while (self::currentToken($state)['type'] !== self::TOKEN_EOF &&
                       self::currentToken($state)['type'] !== self::TOKEN_SLASH &&
                       self::currentToken($state)['type'] !== self::TOKEN_QUESTION &&
                       self::currentToken($state)['type'] !== self::TOKEN_HASH) {
                    $segment .= self::currentToken($state)['value'];
                    $segmentTokens[] = self::currentToken($state);
                    self::nextToken($state);
                }
                if ($segment !== '') {
                    $pathSegments[] = $segment;
                    $pathRaw .= $segment;
                    $pathNodes[] = ['type' => 'segment', 'value' => $segment, 'tokens' => $segmentTokens];
                }
            }
        }
        $ast['path'] = $pathSegments;
        $ast['path_raw'] = $pathRaw;
        $ast['path_nodes'] = $pathNodes;

        if (self::currentToken($state)['type'] === self::TOKEN_QUESTION) {
            self::nextToken($state);
            $queryRaw = '';
            $queryParams = [];
            $queryNodes = [];

            while (self::currentToken($state)['type'] !== self::TOKEN_EOF &&
                   self::currentToken($state)['type'] !== self::TOKEN_HASH) {
                $key = '';
                $value = null;
                $keyTokens = [];
                $valueTokens = [];

                while (self::currentToken($state)['type'] !== self::TOKEN_EOF &&
                       self::currentToken($state)['type'] !== self::TOKEN_EQUALS &&
                       self::currentToken($state)['type'] !== self::TOKEN_AMPERSAND &&
                       self::currentToken($state)['type'] !== self::TOKEN_HASH) {
                    $key .= self::currentToken($state)['value'];
                    $keyTokens[] = self::currentToken($state);
                    $queryRaw .= self::currentToken($state)['value'];
                    self::nextToken($state);
                }

                if (self::currentToken($state)['type'] === self::TOKEN_EQUALS) {
                    $queryRaw .= '=';
                    self::nextToken($state);
                    $value = '';
                    while (self::currentToken($state)['type'] !== self::TOKEN_EOF &&
                           self::currentToken($state)['type'] !== self::TOKEN_AMPERSAND &&
                           self::currentToken($state)['type'] !== self::TOKEN_HASH) {
                        $value .= self::currentToken($state)['value'];
                        $valueTokens[] = self::currentToken($state);
                        $queryRaw .= self::currentToken($state)['value'];
                        self::nextToken($state);
                    }
                }

                $queryParams[] = ['key' => $key, 'value' => $value];
                $queryNodes[] = ['type' => 'param', 'key' => $key, 'key_tokens' => $keyTokens, 'value' => $value, 'value_tokens' => $valueTokens];

                if (self::currentToken($state)['type'] === self::TOKEN_AMPERSAND) {
                    $queryRaw .= '&';
                    self::nextToken($state);
                } else {
                    break;
                }
            }
            $ast['query'] = $queryParams;
            $ast['query_raw'] = $queryRaw;
            $ast['query_nodes'] = $queryNodes;
        }

        if (self::currentToken($state)['type'] === self::TOKEN_HASH) {
            self::nextToken($state);
            $fragment = '';
            while (self::currentToken($state)['type'] !== self::TOKEN_EOF) {
                $fragment .= self::currentToken($state)['value'];
                self::nextToken($state);
            }
            $ast['fragment'] = $fragment;
        }

        if ($ast['scheme'] === null) return null;

        return $ast;
    }

    private static function currentToken(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function nextToken(array &$state): void {
        if ($state['pos'] < count($state['tokens']) - 1) $state['pos']++;
    }

    // ==================== AST Semantic Analysis ====================

    private static function analyzeAst(array $ast): array {
        $result = [
            'scheme'              => $ast['scheme'],
            'host'                => $ast['host'],
            'port'                => $ast['port'],
            'has_dangerous_scheme'=> false,
            'has_internal_ip'     => false,
            'has_cloud_metadata'  => false,
            'has_dns_rebind'      => false,
            'has_at_sign_bypass'  => $ast['has_at_sign'],
            'has_nested_url'      => false,
            'has_short_url'       => false,
            'has_path_traversal'  => false,
            'normalized_ip'       => null,
            'dangerous_schemes'   => [],
            'bypass_techniques'   => [],
            'internal_ip_hits'    => [],
            'cloud_metadata_hits' => [],
            'dns_rebind_hits'     => [],
            'port_scan_hits'      => [],
            'path_traversal_hits' => [],
            'indicators'          => [],
        ];

        $schemeLower = strtolower($ast['scheme']);
        if (isset(self::$dangerousSchemes[$schemeLower])) {
            $result['has_dangerous_scheme'] = true;
            $result['dangerous_schemes'][] = [
                'scheme'   => $schemeLower,
                'level'    => self::$dangerousSchemes[$schemeLower]['level'],
                'desc'     => self::$dangerousSchemes[$schemeLower]['desc'],
                'category' => self::$dangerousSchemes[$schemeLower]['category'],
            ];
        }

        if ($ast['host'] !== null) {
            $host = $ast['host'];
            $hostLower = strtolower($host);

            foreach (self::$cloudMetadataHosts as $metaHost => $metaInfo) {
                if ($hostLower === strtolower($metaHost) || strpos($hostLower, strtolower($metaHost)) !== false) {
                    $result['has_cloud_metadata'] = true;
                    $result['cloud_metadata_hits'][] = [
                        'host'   => $metaHost,
                        'level'  => $metaInfo['level'],
                        'desc'   => $metaInfo['desc'],
                    ];
                }
            }

            foreach (self::$dnsRebindDomains as $domain => $domainInfo) {
                if ($hostLower === $domain || substr($hostLower, -strlen('.' . $domain)) === '.' . $domain) {
                    $result['has_dns_rebind'] = true;
                    $result['dns_rebind_hits'][] = [
                        'domain' => $domain,
                        'level'  => $domainInfo['level'],
                        'desc'   => $domainInfo['desc'],
                    ];
                }
            }

            foreach (self::$shortUrlServices as $shortUrl) {
                if ($hostLower === $shortUrl || substr($hostLower, -strlen('.' . $shortUrl)) === '.' . $shortUrl) {
                    $result['has_short_url'] = true;
                    break;
                }
            }

            if ($hostLower === 'localhost') {
                $result['has_internal_ip'] = true;
                $result['internal_ip_hits'][] = ['type' => 'localhost', 'level' => 5, 'desc' => 'localhost 本地主机'];
            }

            $ipResult = self::normalizeIp($host);
            if ($ipResult !== null) {
                $result['normalized_ip'] = $ipResult['ip'];

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
                    $result['bypass_techniques'][] = ['type' => $bypassType, 'level' => $bypassLevel, 'desc' => $bypassDesc];
                }

                $internalCheck = self::checkInternalIp($ipResult['ip']);
                if ($internalCheck !== null) {
                    $result['has_internal_ip'] = true;
                    $result['internal_ip_hits'][] = $internalCheck;
                }
            }

            if ($ast['port'] !== null) {
                $port = $ast['port'];
                if ($port !== 80 && $port !== 443) {
                    if (isset(self::$nonStandardPorts[$port])) {
                        $result['port_scan_hits'][] = [
                            'port' => $port,
                            'level' => self::$nonStandardPorts[$port]['level'],
                            'desc' => self::$nonStandardPorts[$port]['desc'],
                        ];
                    } else {
                        $level = ($port < 1024) ? 2 : 1;
                        $result['port_scan_hits'][] = ['port' => $port, 'level' => $level, 'desc' => '非标准端口'];
                    }
                }
            }
        }

        $fullPath = $ast['path_raw'] ?? '';
        foreach (self::$cloudMetadataPaths as $metaPath => $level) {
            if (strpos($fullPath, $metaPath) !== false) {
                $result['has_cloud_metadata'] = true;
                $result['cloud_metadata_hits'][] = ['path' => $metaPath, 'level' => $level, 'desc' => '云元数据路径'];
            }
        }

        if (self::detectPathTraversal($fullPath)) {
            $result['has_path_traversal'] = true;
            $result['path_traversal_hits'][] = ['type' => 'dot_dot_slash', 'level' => 3, 'desc' => '路径遍历 ../'];
        }

        foreach ($ast['query_nodes'] ?? [] as $paramNode) {
            $value = $paramNode['value'] ?? '';
            if (preg_match('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $value)) {
                $result['has_nested_url'] = true;
                $result['indicators'][] = 'nested_url_in_query';
            }
        }

        if (!empty($ast['fragment'])) {
            if (preg_match('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $ast['fragment'])) {
                $result['has_nested_url'] = true;
                $result['indicators'][] = 'nested_url_in_fragment';
            }
        }

        foreach ($ast['path_nodes'] ?? [] as $segmentNode) {
            $value = $segmentNode['value'] ?? '';
            if (preg_match('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $value)) {
                $result['has_nested_url'] = true;
                $result['indicators'][] = 'nested_url_in_path';
            }
        }

        return $result;
    }

    // ==================== AST Summary ====================

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type'             => $ast['type'],
            'scheme'           => $ast['scheme'],
            'host'             => $ast['host'],
            'port'             => $ast['port'],
            'path_segment_count' => count($ast['path']),
            'query_param_count'  => count($ast['query']),
            'has_fragment'     => !empty($ast['fragment']),
            'has_at_sign'      => $ast['has_at_sign'],
            'has_userinfo'     => ($ast['user'] !== null),
        ];
        return $summary;
    }

    // ==================== Regex Fallback ====================

    private static function regexFallback(string $input): array {
        $result = [
            'has_dangerous_scheme'=> false,
            'has_internal_ip'     => false,
            'has_cloud_metadata'  => false,
            'has_dns_rebind'      => false,
            'has_at_sign_bypass'  => false,
            'has_nested_url'      => false,
            'has_short_url'       => false,
            'has_path_traversal'  => false,
            'normalized_ip'       => null,
            'dangerous_schemes'   => [],
            'bypass_techniques'   => [],
            'internal_ip_hits'    => [],
            'cloud_metadata_hits' => [],
            'dns_rebind_hits'     => [],
            'port_scan_hits'      => [],
            'path_traversal_hits' => [],
            'indicators'          => [],
        ];

        foreach (self::$dangerousSchemes as $scheme => $info) {
            if (preg_match('/\b' . preg_quote($scheme) . ':\b/i', $input)) {
                $result['has_dangerous_scheme'] = true;
                $result['dangerous_schemes'][] = ['scheme' => $scheme, 'level' => $info['level'], 'desc' => $info['desc']];
            }
        }

        foreach (self::$cloudMetadataHosts as $host => $info) {
            if (stripos($input, $host) !== false) {
                $result['has_cloud_metadata'] = true;
                $result['cloud_metadata_hits'][] = ['host' => $host, 'level' => $info['level'], 'desc' => $info['desc']];
            }
        }

        if (stripos($input, 'localhost') !== false) {
            $result['has_internal_ip'] = true;
            $result['internal_ip_hits'][] = ['type' => 'localhost', 'level' => 5, 'desc' => 'localhost'];
        }

        if (preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $input, $matches)) {
            $ipResult = self::checkInternalIp($matches[0]);
            if ($ipResult !== null) {
                $result['has_internal_ip'] = true;
                $result['internal_ip_hits'][] = $ipResult;
            }
        }

        if (preg_match('/@/', $input)) {
            $result['has_at_sign_bypass'] = true;
        }

        if (preg_match('/https?:\/\//i', $input)) {
            $parsed = @parse_url($input);
            if ($parsed && isset($parsed['host'])) {
                foreach (self::$shortUrlServices as $shortUrl) {
                    if (stripos($parsed['host'], $shortUrl) !== false) {
                        $result['has_short_url'] = true;
                        break;
                    }
                }
            }
        }

        if (self::detectPathTraversal($input)) {
            $result['has_path_traversal'] = true;
            $result['path_traversal_hits'][] = ['type' => 'dot_dot_slash', 'level' => 3, 'desc' => '路径遍历'];
        }

        if (preg_match('/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/.*[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $input)) {
            $result['has_nested_url'] = true;
        }

        return $result;
    }

    // ==================== Scoring ====================

    private static function calculateScore(array $result): int {
        $score = 0;

        $maxSchemeLevel = 0;
        foreach ($result['dangerous_schemes'] as $s) {
            if ($s['level'] > $maxSchemeLevel) $maxSchemeLevel = $s['level'];
        }

        if ($maxSchemeLevel >= 5) { $score += 30; $result['indicators'][] = 'critical_dangerous_scheme'; }
        elseif ($maxSchemeLevel >= 4) { $score += 22; $result['indicators'][] = 'high_dangerous_scheme'; }
        elseif ($maxSchemeLevel >= 3) { $score += 14; $result['indicators'][] = 'medium_dangerous_scheme'; }

        $maxInternalLevel = 0;
        foreach ($result['internal_ip_hits'] as $h) {
            if ($h['level'] > $maxInternalLevel) $maxInternalLevel = $h['level'];
        }

        if ($maxInternalLevel >= 5) { $score += 28; $result['indicators'][] = 'critical_internal_ip'; }
        elseif ($maxInternalLevel >= 4) { $score += 20; $result['indicators'][] = 'high_internal_ip'; }
        elseif ($maxInternalLevel >= 3) { $score += 12; $result['indicators'][] = 'medium_internal_ip'; }

        $maxCloudLevel = 0;
        foreach ($result['cloud_metadata_hits'] as $h) {
            if ($h['level'] > $maxCloudLevel) $maxCloudLevel = $h['level'];
        }

        if ($maxCloudLevel >= 5) { $score += 45; $result['indicators'][] = 'critical_cloud_metadata'; }
        elseif ($maxCloudLevel >= 4) { $score += 35; $result['indicators'][] = 'high_cloud_metadata'; }

        $maxBypassLevel = 0;
        foreach ($result['bypass_techniques'] as $h) {
            if ($h['level'] > $maxBypassLevel) $maxBypassLevel = $h['level'];
        }

        if ($maxBypassLevel >= 5) { $score += 25; $result['indicators'][] = 'critical_bypass_technique'; }
        elseif ($maxBypassLevel >= 4) { $score += 18; $result['indicators'][] = 'high_bypass_technique'; }
        elseif ($maxBypassLevel >= 3) { $score += 12; $result['indicators'][] = 'medium_bypass_technique'; }

        $maxDnsLevel = 0;
        foreach ($result['dns_rebind_hits'] as $h) {
            if ($h['level'] > $maxDnsLevel) $maxDnsLevel = $h['level'];
        }

        if ($maxDnsLevel >= 4) { $score += 18; $result['indicators'][] = 'high_dns_rebind'; }
        elseif ($maxDnsLevel >= 3) { $score += 10; $result['indicators'][] = 'medium_dns_rebind'; }

        $maxPortLevel = 0;
        foreach ($result['port_scan_hits'] as $h) {
            if ($h['level'] > $maxPortLevel) $maxPortLevel = $h['level'];
        }

        if ($maxPortLevel >= 4) { $score += 15; $result['indicators'][] = 'high_risk_port'; }
        elseif ($maxPortLevel >= 3) { $score += 10; $result['indicators'][] = 'medium_risk_port'; }

        if ($result['has_at_sign_bypass']) { $score += 12; $result['indicators'][] = 'at_sign_bypass'; }
        if ($result['has_nested_url']) { $score += 20; $result['indicators'][] = 'nested_url_redirect'; }
        if ($result['has_short_url']) { $score += 8; $result['indicators'][] = 'short_url_bypass'; }
        if ($result['has_path_traversal']) { $score += 12; $result['indicators'][] = 'path_traversal'; }

        if (!empty($result['internal_ip_hits']) && !empty($result['cloud_metadata_hits'])) {
            $score += 10;
            $result['indicators'][] = 'internal_plus_cloud_metadata';
        }

        if ($maxSchemeLevel >= 4 && !empty($result['internal_ip_hits'])) {
            $score += 12;
            $result['indicators'][] = 'dangerous_scheme_plus_internal';
        }

        return min(100, $score);
    }

    private static function calculateRiskLevel(int $score): string {
        if ($score >= 70) return 'critical';
        if ($score >= 50) return 'high';
        if ($score >= 30) return 'medium';
        if ($score >= 10) return 'low';
        return 'clean';
    }

    private static function detectPathTraversal(string $path): bool {
        if (strpos($path, '../') !== false || strpos($path, '..\\') !== false) return true;
        if (strpos($path, '%2e%2e%2f') !== false || strpos($path, '%2e%2e/') !== false) return true;
        if (preg_match('/(\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/)/i', $path)) return true;
        return false;
    }

    private static function normalizeIp(string $host): ?array {
        $host = trim($host);
        if ($host === '') return null;

        if (preg_match('/^(0x[0-9a-fA-F]+)$/', $host, $m)) {
            $decimal = hexdec($m[1]);
            if ($decimal >= 0 && $decimal <= 4294967295) {
                return ['ip' => long2ip($decimal), 'is_hex' => true, 'is_octal' => false, 'is_decimal' => false];
            }
        }

        if (preg_match('/^(0[0-7]+)$/', $host, $m)) {
            $decimal = octdec($m[1]);
            if ($decimal >= 0 && $decimal <= 4294967295) {
                return ['ip' => long2ip($decimal), 'is_hex' => false, 'is_octal' => true, 'is_decimal' => false];
            }
        }

        if (preg_match('/^(\d{8,10})$/', $host, $m)) {
            $decimal = (int)$m[1];
            if ($decimal >= 0 && $decimal <= 4294967295) {
                return ['ip' => long2ip($decimal), 'is_hex' => false, 'is_octal' => false, 'is_decimal' => true];
            }
        }

        if (preg_match('/^([0-9a-fA-Fx]+)\.([0-9a-fA-Fx]+)\.([0-9a-fA-Fx]+)\.([0-9a-fA-Fx]+)$/i', $host, $m)) {
            $parts = [0, 0, 0, 0];
            $valid = true;
            $hasOctal = false;
            $hasHex = false;
            foreach ([$m[1], $m[2], $m[3], $m[4]] as $idx => $part) {
                $val = null;
                if (preg_match('/^0x[0-9a-fA-F]+$/i', $part)) {
                    $val = hexdec($part);
                    $hasHex = true;
                } elseif (strlen($part) > 1 && $part[0] === '0' && preg_match('/^0[0-7]+$/', $part)) {
                    $val = octdec($part);
                    $hasOctal = true;
                } elseif (ctype_digit($part)) {
                    $val = (int)$part;
                } else {
                    $valid = false;
                    break;
                }
                if ($val !== null && ($val < 0 || $val > 255)) {
                    $valid = false;
                    break;
                }
                $parts[$idx] = $val;
            }
            if ($valid) {
                return ['ip' => implode('.', $parts), 'is_hex' => $hasHex, 'is_octal' => $hasOctal, 'is_decimal' => false];
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