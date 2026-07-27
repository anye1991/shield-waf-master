<?php
/**
 * CRLF 注入语义解析器
 * 职责：通过构建 HTTP 头 AST（抽象语法树）真正理解 HTTP 头结构，
 *       检测 CRLF 注入、HTTP 头注入、响应拆分等攻击。
 */
defined('ABSPATH') || exit;

class CrlfInjectionSemanticParser {

    const TOKEN_HEADER_NAME  = 'HEADER_NAME';
    const TOKEN_COLON        = 'COLON';
    const TOKEN_HEADER_VALUE = 'HEADER_VALUE';
    const TOKEN_CRLF         = 'CRLF';
    const TOKEN_CR           = 'CR';
    const TOKEN_LF           = 'LF';
    const TOKEN_SPACE        = 'SPACE';
    const TOKEN_COMMA        = 'COMMA';
    const TOKEN_SEMICOLON    = 'SEMICOLON';
    const TOKEN_EQUALS       = 'EQUALS';
    const TOKEN_PARAM_NAME   = 'PARAM_NAME';
    const TOKEN_PARAM_VALUE  = 'PARAM_VALUE';
    const TOKEN_STATUS_LINE  = 'STATUS_LINE';
    const TOKEN_EOF          = 'EOF';

    private static $dangerousHeaders = [
        'SET-COOKIE'           => ['level' => 5, 'desc' => 'Set-Cookie头注入'],
        'LOCATION'             => ['level' => 4, 'desc' => 'Location头注入'],
        'CONTENT-TYPE'         => ['level' => 3, 'desc' => 'Content-Type头注入'],
        'REFRESH'              => ['level' => 3, 'desc' => 'Refresh头注入'],
        'X-FORWARDED-FOR'      => ['level' => 3, 'desc' => 'X-Forwarded-For头注入'],
        'X-FORWARDED-HOST'     => ['level' => 3, 'desc' => 'X-Forwarded-Host头注入(缓存投毒)'],
        'X-FORWARDED-PROTO'    => ['level' => 2, 'desc' => 'X-Forwarded-Proto头注入'],
        'X-REAL-IP'            => ['level' => 2, 'desc' => 'X-Real-IP头注入'],
        'X-XSS-PROTECTION'     => ['level' => 4, 'desc' => 'X-XSS-Protection头注入(绕过)'],
        'CONTENT-SECURITY-POLICY' => ['level' => 5, 'desc' => 'Content-Security-Policy头注入(绕过)'],
        'X-CONTENT-TYPE-OPTIONS' => ['level' => 3, 'desc' => 'X-Content-Type-Options头注入'],
        'ACCESS-CONTROL-ALLOW-ORIGIN' => ['level' => 4, 'desc' => 'CORS头注入'],
        'SET-COOKIE2'          => ['level' => 4, 'desc' => 'Set-Cookie2头注入'],
        'WWW-AUTHENTICATE'     => ['level' => 3, 'desc' => 'WWW-Authenticate头注入'],
        'PROXY-AUTHENTICATE'   => ['level' => 3, 'desc' => 'Proxy-Authenticate头注入'],
        'X-FRAME-OPTIONS'      => ['level' => 3, 'desc' => 'X-Frame-Options头注入'],
        'STRICT-TRANSPORT-SECURITY' => ['level' => 4, 'desc' => 'HSTS头注入'],
    ];

    private static $redirectHeaders = [
        'LOCATION',
        'REFRESH',
        'CONTENT-LOCATION',
        'URI',
    ];

    private static $cachePoisoningHeaders = [
        'X-FORWARDED-HOST',
        'X-FORWARDED-FOR',
        'X-FORWARDED-PROTO',
        'X-HOST',
        'X-ORIGINAL-URL',
        'X-REWRITE-URL',
        'X-REAL-IP',
        'X-PROXY-URL',
        'X-CUSTOM-HEADER',
    ];

    private static $cookieAttributes = [
        'domain', 'path', 'expires', 'max-age', 'secure', 'httponly',
        'samesite', 'priority', 'partitioned', 'samesite',
    ];

    private static $cookieInjectionSignatures = [
        'httponly_bypass' => [
            'pattern' => '/[Hh][Tt][Tt][Pp][Oo][Nn][Ll][Yy]/',
            'level'   => 4,
            'desc'    => 'HTTPOnly属性注入',
        ],
        'secure_bypass' => [
            'pattern' => '/[Ss][Ee][Cc][Uu][Rr][Ee]/',
            'level'   => 4,
            'desc'    => 'Secure属性注入',
        ],
        'domain_injection' => [
            'pattern' => '/[Dd][Oo][Mm][Aa][Ii][Nn]\s*=/',
            'level'   => 5,
            'desc'    => 'Domain属性注入(会话劫持)',
        ],
        'path_injection' => [
            'pattern' => '/[Pp][Aa][Tt][Hh]\s*=/',
            'level'   => 4,
            'desc'    => 'Path属性注入',
        ],
        'samesite_injection' => [
            'pattern' => '/[Ss][Aa][Mm][Ee][Ss][Ii][Tt][Ee]\s*=/',
            'level'   => 4,
            'desc'    => 'SameSite属性注入(CSRF绕过)',
        ],
        'max_age_injection' => [
            'pattern' => '/[Mm][Aa][Xx][\-][Aa][Gg][Ee]\s*=/',
            'level'   => 3,
            'desc'    => 'Max-Age属性注入',
        ],
        'cookie_prefix' => [
            'pattern' => '/^(Secure_|__Secure-|__Host-)/',
            'level'   => 5,
            'desc'    => 'Cookie前缀伪造',
        ],
    ];

    private static $responseBodySignatures = [
        'html_start'        => ['<html', 'HTML内容注入', 4],
        'script_tag'        => ['<script', 'JS脚本注入', 5],
        'iframe_tag'        => ['<iframe', 'iframe注入', 4],
        'img_tag'           => ['<img', '图片注入', 3],
        'meta_refresh'      => ['<meta', 'Meta标签注入', 4],
        'svg_tag'           => ['<svg', 'SVG注入', 4],
        'onload_event'      => ['onload=', '事件处理器注入', 5],
        'javascript_proto'  => ['javascript:', 'JS伪协议', 5],
        'data_uri'          => ['data:', 'Data URI注入', 4],
    ];

    private static $crlfPatterns = [
        'raw_rn'    => ["\r\n", '原始CRLF'],
        'raw_nr'    => ["\n\r", '原始LFCR'],
        'raw_r'     => ["\r", '原始CR'],
        'raw_n'     => ["\n", '原始LF'],
        'url_rn'    => ['%0d%0a', 'URL编码CRLF'],
        'url_nr'    => ['%0a%0d', 'URL编码LFCR'],
        'url_r'     => ['%0d', 'URL编码CR'],
        'url_n'     => ['%0a', 'URL编码LF'],
        'url_upper_rn' => ['%0D%0A', 'URL编码CRLF(大写)'],
        'url_upper_nr' => ['%0A%0D', 'URL编码LFCR(大写)'],
        'url_mixed1' => ['%0d%0A', 'URL编码CRLF(混合)'],
        'url_mixed2' => ['%0D%0a', 'URL编码CRLF(混合)'],
        'double_rn' => ['%250d%250a', '双层URL编码CRLF'],
        'double_nr' => ['%250a%250d', '双层URL编码LFCR'],
        'unicode_r' => ['\u000d', 'Unicode编码CR'],
        'unicode_n' => ['\u000a', 'Unicode编码LF'],
        'hex_r'     => ['\\x0d', '十六进制CR'],
        'hex_n'     => ['\\x0a', '十六进制LF'],
        'html_r'    => ['&#13;', 'HTML实体CR'],
        'html_n'    => ['&#10;', 'HTML实体LF'],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $originalInput = $input;

        $decodeResult = self::multiLayerDecode($input);
        $decodedInput = $decodeResult['decoded'];
        $decodeDepth = $decodeResult['depth'];
        $encodeTypes = $decodeResult['encode_types'];

        $result['decode_depth'] = $decodeDepth;
        $result['encode_types'] = $encodeTypes;

        $crlfResult = self::detectCrlfSequences($decodedInput, $originalInput);
        $result['crlf_count'] = $crlfResult['count'];
        $result['crlf_types'] = $crlfResult['types'];

        try {
            $tokens = self::tokenize($decodedInput);
            $result['token_count'] = count($tokens);

            if (!empty($tokens)) {
                $ast = self::parse($tokens, $decodedInput);

                if (!empty($ast)) {
                    $result['parser_used'] = 'ast';
                    $result['ast_summary'] = self::summarizeAst($ast);

                    $semanticResult = self::analyzeAst($ast, $decodedInput, $originalInput);
                    $result['header_injection_hits'] = $semanticResult['header_injection_hits'];
                    $result['response_splitting'] = $semanticResult['response_splitting'];
                    $result['header_name_injection'] = $semanticResult['header_name_injection'];
                    $result['header_count'] = $semanticResult['header_count'];
                    $result['has_invalid_header_name'] = $semanticResult['has_invalid_header_name'];
                    $result['has_status_line_injection'] = $semanticResult['has_status_line_injection'];
                    $result['has_set_cookie_injection'] = $semanticResult['has_set_cookie_injection'];
                    $result['has_cache_poisoning'] = $semanticResult['has_cache_poisoning'];
                    $result['has_redirect_injection'] = $semanticResult['has_redirect_injection'];
                    $result['has_excessive_headers'] = $semanticResult['has_excessive_headers'];
                    $result['multiline_headers'] = $semanticResult['multiline_headers'];
                } else {
                    $result['parser_used'] = 'regex';
                    self::regexFallback($decodedInput, $originalInput, $result);
                }
            } else {
                $result['parser_used'] = 'regex';
                self::regexFallback($decodedInput, $originalInput, $result);
            }
        } catch (Exception $e) {
            $result['parser_used'] = 'regex';
            $result['indicators'][] = 'parse_error';
            self::regexFallback($decodedInput, $originalInput, $result);
        }

        $score = self::calculateScore($result);
        $result['score'] = min(100, $score);

        if ($result['score'] >= 70) $result['risk_level'] = 'critical';
        elseif ($result['score'] >= 50) $result['risk_level'] = 'high';
        elseif ($result['score'] >= 30) $result['risk_level'] = 'medium';
        elseif ($result['score'] >= 15) $result['risk_level'] = 'low';

        $result['is_crlf'] = $result['score'] >= 15;

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'                      => 0,
            'risk_level'                 => 'clean',
            'is_crlf'                    => false,
            'crlf_count'                 => 0,
            'crlf_types'                 => [],
            'header_injection_hits'      => [],
            'response_splitting'         => false,
            'header_name_injection'      => false,
            'decode_depth'               => 0,
            'encode_types'               => [],
            'indicators'                 => [],
            'parser_used'                => 'none',
            'token_count'                => 0,
            'ast_summary'                => [],
            'header_count'               => 0,
            'has_invalid_header_name'    => false,
            'has_status_line_injection'  => false,
            'has_set_cookie_injection'   => false,
            'has_cache_poisoning'        => false,
            'has_redirect_injection'     => false,
            'has_excessive_headers'      => false,
            'multiline_headers'          => 0,
        ];
    }

    // ==================== Tokenizer ====================

    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);

        while ($pos < $len) {
            $char = $input[$pos];

            if (preg_match('/^HTTP\/\d\.\d/i', substr($input, $pos), $matches)) {
                $tokens[] = [
                    'type'  => self::TOKEN_STATUS_LINE,
                    'value' => $matches[0],
                    'pos'   => $pos,
                ];
                $pos += strlen($matches[0]);
                continue;
            }

            if ($char === "\r" && $pos + 1 < $len && $input[$pos + 1] === "\n") {
                $tokens[] = [
                    'type'  => self::TOKEN_CRLF,
                    'value' => "\r\n",
                    'pos'   => $pos,
                ];
                $pos += 2;
                continue;
            }

            if ($char === "\r") {
                $tokens[] = [
                    'type'  => self::TOKEN_CR,
                    'value' => "\r",
                    'pos'   => $pos,
                ];
                $pos++;
                continue;
            }

            if ($char === "\n") {
                $tokens[] = [
                    'type'  => self::TOKEN_LF,
                    'value' => "\n",
                    'pos'   => $pos,
                ];
                $pos++;
                continue;
            }

            if ($char === ' ' || $char === "\t") {
                $start = $pos;
                while ($pos < $len && ($input[$pos] === ' ' || $input[$pos] === "\t")) {
                    $pos++;
                }
                $tokens[] = [
                    'type'  => self::TOKEN_SPACE,
                    'value' => substr($input, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === ':') {
                $tokens[] = [
                    'type'  => self::TOKEN_COLON,
                    'value' => ':',
                    'pos'   => $pos,
                ];
                $pos++;
                continue;
            }

            if ($char === ',') {
                $tokens[] = [
                    'type'  => self::TOKEN_COMMA,
                    'value' => ',',
                    'pos'   => $pos,
                ];
                $pos++;
                continue;
            }

            if ($char === ';') {
                $tokens[] = [
                    'type'  => self::TOKEN_SEMICOLON,
                    'value' => ';',
                    'pos'   => $pos,
                ];
                $pos++;
                continue;
            }

            if ($char === '=') {
                $tokens[] = [
                    'type'  => self::TOKEN_EQUALS,
                    'value' => '=',
                    'pos'   => $pos,
                ];
                $pos++;
                continue;
            }

            if (self::isTokenChar($char)) {
                $start = $pos;
                while ($pos < $len && self::isTokenChar($input[$pos])) {
                    $pos++;
                }
                $word = substr($input, $start, $pos - $start);

                $tokens[] = [
                    'type'  => self::TOKEN_HEADER_NAME,
                    'value' => $word,
                    'pos'   => $start,
                ];
                continue;
            }

            $start = $pos;
            while ($pos < $len && !in_array($input[$pos], ["\r", "\n", ':', ',', ';', '='], true)) {
                $pos++;
            }
            if ($pos > $start) {
                $tokens[] = [
                    'type'  => self::TOKEN_HEADER_VALUE,
                    'value' => substr($input, $start, $pos - $start),
                    'pos'   => $start,
                ];
            } else {
                $pos++;
            }
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    private static function isTokenChar(string $char): bool {
        $ascii = ord($char);
        if ($ascii < 32 || $ascii > 126) return false;
        if (in_array($char, ['(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', "\t"], true)) {
            return false;
        }
        return true;
    }

    // ==================== Parser ====================

    private static function parse(array $tokens, string $input): ?array {
        if (empty($tokens)) {
            return null;
        }

        $state = [
            'tokens' => $tokens,
            'pos'    => 0,
            'input'  => $input,
        ];

        $ast = self::parseHeaders($state);
        return $ast;
    }

    private static function parseHeaders(array &$state): array {
        $headers = [];
        $hasStatusLine = false;
        $statusLine = null;
        $invalidHeaderNames = [];

        while (!self::isEof($state)) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_CRLF ||
                $token['type'] === self::TOKEN_CR ||
                $token['type'] === self::TOKEN_LF) {
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_STATUS_LINE) {
                $hasStatusLine = true;
                $statusLine = self::parseStatusLine($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_HEADER_NAME) {
                $header = self::parseHeader($state);
                if ($header !== null) {
                    $headers[] = $header;
                    if (!empty($header['invalid_name'])) {
                        $invalidHeaderNames[] = $header['name'];
                    }
                } else {
                    self::next($state);
                }
                continue;
            }

            self::next($state);
        }

        return [
            'type'                 => 'http_headers',
            'headers'              => $headers,
            'header_count'         => count($headers),
            'has_status_line'      => $hasStatusLine,
            'status_line'          => $statusLine,
            'invalid_header_names' => $invalidHeaderNames,
        ];
    }

    private static function parseStatusLine(array &$state): array {
        $token = self::current($state);
        $protocol = $token['value'];
        self::next($state);

        $statusCode = '';
        $reasonPhrase = '';

        self::skipSpace($state);

        if (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_HEADER_VALUE) {
            $statusCode = self::current($state)['value'];
            self::next($state);
            self::skipSpace($state);

            if (!self::isEof($state) &&
                self::current($state)['type'] !== self::TOKEN_CRLF &&
                self::current($state)['type'] !== self::TOKEN_CR &&
                self::current($state)['type'] !== self::TOKEN_LF &&
                self::current($state)['type'] !== self::TOKEN_EOF) {
                $reasonPhrase = self::current($state)['value'];
                self::next($state);
            }
        }

        return [
            'protocol'      => $protocol,
            'status_code'   => $statusCode,
            'reason_phrase' => $reasonPhrase,
        ];
    }

    private static function parseHeader(array &$state): ?array {
        $nameToken = self::current($state);
        $headerName = $nameToken['value'];
        $namePos = $nameToken['pos'];
        self::next($state);

        self::skipSpace($state);

        if (self::isEof($state) || self::current($state)['type'] !== self::TOKEN_COLON) {
            return null;
        }
        self::next($state);

        self::skipSpace($state);

        $valueParts = [];
        $rawValue = '';
        $isMultiline = false;

        while (!self::isEof($state)) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_CRLF ||
                $token['type'] === self::TOKEN_CR ||
                $token['type'] === self::TOKEN_LF) {
                $next = self::peek($state, 1);
                if ($next && ($next['type'] === self::TOKEN_SPACE || $next['type'] === self::TOKEN_HEADER_VALUE)) {
                    $isMultiline = true;
                    self::next($state);
                    if (self::current($state)['type'] === self::TOKEN_SPACE) {
                        $rawValue .= ' ';
                        self::next($state);
                    }
                    continue;
                } else {
                    break;
                }
            }

            if ($token['type'] === self::TOKEN_HEADER_VALUE ||
                $token['type'] === self::TOKEN_HEADER_NAME) {
                $rawValue .= $token['value'];
                $valueParts[] = $token;
                self::next($state);
            } else {
                $rawValue .= $token['value'];
                $valueParts[] = $token;
                self::next($state);
            }
        }

        $value = trim($rawValue);
        $params = self::parseHeaderValueParams($value);
        $invalidName = !self::isValidHeaderName($headerName);

        return [
            'type'         => 'header',
            'name'         => $headerName,
            'name_lower'   => strtolower($headerName),
            'value'        => $value,
            'params'       => $params,
            'is_multiline' => $isMultiline,
            'invalid_name' => $invalidName,
            'name_pos'     => $namePos,
        ];
    }

    private static function parseHeaderValueParams(string $value): array {
        $params = [];
        $parts = preg_split('/;/', $value);

        if (count($parts) <= 1) {
            return [
                'main_value' => $value,
                'params'     => [],
            ];
        }

        $mainValue = trim(array_shift($parts));

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') continue;

            $eqPos = strpos($part, '=');
            if ($eqPos !== false) {
                $pName = trim(substr($part, 0, $eqPos));
                $pValue = trim(substr($part, $eqPos + 1));
                if (strpos($pValue, '"') === 0 && substr($pValue, -1) === '"') {
                    $pValue = substr($pValue, 1, -1);
                }
                $params[] = [
                    'name'  => $pName,
                    'value' => $pValue,
                ];
            } else {
                $params[] = [
                    'name'  => $part,
                    'value' => '',
                ];
            }
        }

        return [
            'main_value' => $mainValue,
            'params'     => $params,
        ];
    }

    private static function isValidHeaderName(string $name): bool {
        if ($name === '') return false;
        $len = strlen($name);
        for ($i = 0; $i < $len; $i++) {
            $ascii = ord($name[$i]);
            if ($ascii < 33 || $ascii > 126) return false;
            if (in_array($name[$i], ['(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}'], true)) {
                return false;
            }
        }
        return true;
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function peek(array &$state, int $offset): ?array {
        return $state['tokens'][$state['pos'] + $offset] ?? null;
    }

    private static function next(array &$state) {
        if ($state['pos'] < count($state['tokens']) - 1) {
            $state['pos']++;
        }
    }

    private static function isEof(array &$state): bool {
        $t = self::current($state);
        return $t['type'] === self::TOKEN_EOF;
    }

    private static function skipSpace(array &$state) {
        while (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_SPACE) {
            self::next($state);
        }
    }

    // ==================== AST Semantic Analysis ====================

    private static function analyzeAst(array $ast, string $decodedInput, string $originalInput): array {
        $result = [
            'header_injection_hits'     => [],
            'response_splitting'        => false,
            'header_name_injection'     => false,
            'header_count'              => 0,
            'has_invalid_header_name'   => false,
            'has_status_line_injection' => false,
            'has_set_cookie_injection'  => false,
            'has_cache_poisoning'       => false,
            'has_redirect_injection'    => false,
            'has_excessive_headers'     => false,
            'multiline_headers'         => 0,
            'cookie_attribute_injections' => [],
            'response_body_injections'     => [],
            'header_value_anomalies'      => [],
            'protocol_confusion'          => [],
        ];

        if (empty($ast) || $ast['type'] !== 'http_headers') {
            return $result;
        }

        $result['header_count'] = $ast['header_count'] ?? 0;
        $result['has_invalid_header_name'] = !empty($ast['invalid_header_names']);
        $result['has_status_line_injection'] = !empty($ast['has_status_line']);

        $multilineCount = 0;
        $cookieValues = [];

        foreach (($ast['headers'] ?? []) as $header) {
            $nameLower = strtoupper($header['name_lower'] ?? '');
            $value = $header['value'] ?? '';

            if (!empty($header['is_multiline'])) {
                $multilineCount++;
            }

            if (isset(self::$dangerousHeaders[$nameLower])) {
                $danger = self::$dangerousHeaders[$nameLower];
                $hit = [
                    'header' => strtolower(str_replace('-', '_', $nameLower)),
                    'level'  => $danger['level'],
                    'desc'   => $danger['desc'],
                    'name'   => $header['name'],
                    'value'  => $header['value'],
                ];
                $result['header_injection_hits'][] = $hit;
            }

            if ($nameLower === 'SET-COOKIE' || $nameLower === 'SET-COOKIE2') {
                $result['has_set_cookie_injection'] = true;
                $cookieValues[] = $value;
                $cookieHits = self::analyzeCookieValue($value);
                $result['cookie_attribute_injections'] = array_merge(
                    $result['cookie_attribute_injections'],
                    $cookieHits
                );
            }

            if (in_array($nameLower, self::$cachePoisoningHeaders, true)) {
                $result['has_cache_poisoning'] = true;
            }

            if (in_array($nameLower, self::$redirectHeaders, true)) {
                $result['has_redirect_injection'] = true;
                self::analyzeRedirectValue($value, $result);
            }

            $anomalies = self::detectHeaderValueAnomalies($nameLower, $value);
            if (!empty($anomalies)) {
                $result['header_value_anomalies'] = array_merge(
                    $result['header_value_anomalies'],
                    $anomalies
                );
            }

            if ($nameLower === 'CONTENT-TYPE') {
                self::analyzeContentType($value, $result);
            }
        }

        $result['multiline_headers'] = $multilineCount;

        if ($result['header_count'] > 20) {
            $result['has_excessive_headers'] = true;
        }

        if ($result['header_count'] >= 2 && self::hasDoubleCrlf($decodedInput, $originalInput)) {
            $result['response_splitting'] = true;
        }

        if ($result['has_status_line_injection'] && $result['header_count'] >= 1) {
            $result['response_splitting'] = true;
        }

        if ($result['header_count'] >= 1 && $result['has_status_line_injection']) {
            $result['header_name_injection'] = true;
        }

        if ($result['header_count'] >= 2) {
            $result['header_name_injection'] = true;
        }

        $bodyHits = self::detectResponseBodyInjections($decodedInput);
        if (!empty($bodyHits)) {
            $result['response_body_injections'] = $bodyHits;
            if ($result['response_splitting']) {
                foreach ($bodyHits as $hit) {
                    $result['header_injection_hits'][] = [
                        'header' => 'response_body',
                        'level'  => $hit['level'],
                        'desc'   => $hit['desc'],
                        'name'   => 'Response-Body',
                        'value'  => $hit['pattern'],
                    ];
                }
            }
        }

        $protocolConfusion = self::detectProtocolConfusion($ast);
        if (!empty($protocolConfusion)) {
            $result['protocol_confusion'] = $protocolConfusion;
            foreach ($protocolConfusion as $pc) {
                $result['header_injection_hits'][] = [
                    'header' => 'protocol_confusion',
                    'level'  => $pc['level'],
                    'desc'   => $pc['desc'],
                    'name'   => 'Protocol',
                    'value'  => $pc['detail'],
                ];
            }
        }

        usort($result['header_injection_hits'], function($a, $b) {
            return $b['level'] - $a['level'];
        });

        return $result;
    }

    private static function analyzeCookieValue(string $value): array {
        $hits = [];

        foreach (self::$cookieInjectionSignatures as $key => $info) {
            if (preg_match($info['pattern'], $value)) {
                $hits[] = [
                    'type'   => $key,
                    'level'  => $info['level'],
                    'desc'   => $info['desc'],
                    'value'  => $value,
                ];
            }
        }

        $parts = explode(';', $value);
        if (count($parts) > 10) {
            $hits[] = [
                'type'   => 'excessive_attributes',
                'level'  => 3,
                'desc'   => 'Cookie属性数量异常',
                'value'  => count($parts),
            ];
        }

        foreach ($parts as $part) {
            $part = trim($part);
            $eqPos = strpos($part, '=');
            if ($eqPos !== false) {
                $attrName = strtolower(trim(substr($part, 0, $eqPos)));
                if (!in_array($attrName, self::$cookieAttributes, true) && strlen($attrName) > 0) {
                    $hits[] = [
                        'type'   => 'unknown_attribute',
                        'level'  => 2,
                        'desc'   => '未知Cookie属性: ' . $attrName,
                        'value'  => $attrName,
                    ];
                }
            }
        }

        return $hits;
    }

    private static function analyzeRedirectValue(string $value, array &$result): void {
        if (stripos($value, 'javascript:') !== false) {
            $result['header_injection_hits'][] = [
                'header' => 'redirect_javascript',
                'level'  => 5,
                'desc'   => '重定向到JavaScript伪协议',
                'name'   => 'Location',
                'value'  => $value,
            ];
        }
        if (stripos($value, 'data:') !== false) {
            $result['header_injection_hits'][] = [
                'header' => 'redirect_data_uri',
                'level'  => 5,
                'desc'   => '重定向到Data URI',
                'name'   => 'Location',
                'value'  => $value,
            ];
        }
        if (preg_match('/^\/\/[^\s\/]+/', $value)) {
            $result['header_injection_hits'][] = [
                'header' => 'redirect_protocol_relative',
                'level'  => 4,
                'desc'   => '协议相对URL重定向',
                'name'   => 'Location',
                'value'  => $value,
            ];
        }
    }

    private static function detectHeaderValueAnomalies(string $headerName, string $value): array {
        $anomalies = [];

        if (strlen($value) > 4096) {
            $anomalies[] = [
                'type'   => 'value_too_long',
                'level'  => 3,
                'desc'   => 'Header值过长: ' . $headerName,
                'length' => strlen($value),
            ];
        }

        if (preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $value)) {
            $anomalies[] = [
                'type'   => 'control_characters',
                'level'  => 4,
                'desc'   => 'Header值包含控制字符: ' . $headerName,
            ];
        }

        if (preg_match('/(%[0-9a-fA-F]{2}){3,}/', $value)) {
            $anomalies[] = [
                'type'   => 'hex_encoded_sequence',
                'level'  => 3,
                'desc'   => 'Header值包含大量十六进制编码: ' . $headerName,
            ];
        }

        $whitespaceCount = preg_match_all('/[\s]/', $value);
        if ($whitespaceCount > 10) {
            $anomalies[] = [
                'type'   => 'excessive_whitespace',
                'level'  => 2,
                'desc'   => 'Header值包含过多空白: ' . $headerName,
            ];
        }

        return $anomalies;
    }

    private static function analyzeContentType(string $value, array &$result): void {
        $valueLower = strtolower($value);

        if (stripos($valueLower, 'text/html') !== false ||
            stripos($valueLower, 'application/javascript') !== false) {
            $result['header_injection_hits'][] = [
                'header' => 'content_type_html_js',
                'level'  => 3,
                'desc'   => 'Content-Type设置为HTML/JS',
                'name'   => 'Content-Type',
                'value'  => $value,
            ];
        }

        if (stripos($valueLower, 'x-') !== false) {
            $result['header_injection_hits'][] = [
                'header' => 'content_type_nonstandard',
                'level'  => 2,
                'desc'   => '非标准Content-Type',
                'name'   => 'Content-Type',
                'value'  => $value,
            ];
        }
    }

    private static function detectResponseBodyInjections(string $decodedInput): array {
        $hits = [];

        foreach (self::$responseBodySignatures as $key => $info) {
            list($pattern, $desc, $level) = $info;
            if (stripos($decodedInput, $pattern) !== false) {
                $hits[] = [
                    'type'    => $key,
                    'pattern' => $pattern,
                    'desc'    => $desc,
                    'level'   => $level,
                ];
            }
        }

        return $hits;
    }

    private static function detectProtocolConfusion(array $ast): array {
        $confusion = [];

        $statusLine = $ast['status_line'] ?? null;
        if ($statusLine !== null) {
            $protocol = strtoupper($statusLine['protocol'] ?? '');
            $statusCode = $statusLine['status_code'] ?? '';

            if (!preg_match('/^HTTP\/[0-9]\.[0-9]$/', $protocol)) {
                $confusion[] = [
                    'type'   => 'invalid_protocol',
                    'level'  => 4,
                    'desc'   => '无效HTTP协议版本',
                    'detail' => $protocol,
                ];
            }

            if (!preg_match('/^[1-5][0-9]{2}$/', $statusCode)) {
                $confusion[] = [
                    'type'   => 'invalid_status_code',
                    'level'  => 4,
                    'desc'   => '无效HTTP状态码',
                    'detail' => $statusCode,
                ];
            }
        }

        $headerNames = [];
        foreach (($ast['headers'] ?? []) as $header) {
            $headerNames[] = strtoupper($header['name'] ?? '');
        }

        if (in_array('HOST', $headerNames) && in_array('X-FORWARDED-HOST', $headerNames)) {
            $confusion[] = [
                'type'   => 'host_header_conflict',
                'level'  => 3,
                'desc'   => 'Host与X-Forwarded-Host冲突',
                'detail' => '双重Host',
            ];
        }

        return $confusion;
    }

    private static function hasDoubleCrlf(string $decodedInput, string $originalInput): bool {
        $doubleCrlfPatterns = [
            "\r\n\r\n",
            "\n\r\n\r",
            "\n\n",
            "\r\r",
            '%0d%0a%0d%0a',
            '%0D%0A%0D%0A',
            '%0a%0d%0a%0d',
            '%0A%0D%0A%0D',
            '%0a%0a',
            '%0A%0A',
            '%0d%0d',
            '%0D%0D',
        ];

        foreach ($doubleCrlfPatterns as $pattern) {
            if (stripos($decodedInput, $pattern) !== false) {
                return true;
            }
            if (stripos($originalInput, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    // ==================== Regex Fallback ====================

    private static function regexFallback(string $decodedInput, string $originalInput, array &$result) {
        $headerInjectionHits = self::detectHeaderInjectionsRegex($decodedInput);
        $responseSplitting = self::detectResponseSplittingRegex($decodedInput, $originalInput);
        $headerNameInjection = self::detectHeaderNameInjectionRegex($decodedInput);

        $result['header_injection_hits'] = $headerInjectionHits;
        $result['response_splitting'] = $responseSplitting;
        $result['header_name_injection'] = $headerNameInjection;
    }

    private static function detectHeaderInjectionsRegex(string $input): array {
        $hits = [];
        $headerInjectionPatterns = [
            'set_cookie'       => ['pattern' => '/Set-Cookie\s*:/i', 'level' => 4, 'desc' => 'Set-Cookie头注入'],
            'location'         => ['pattern' => '/Location\s*:/i', 'level' => 4, 'desc' => 'Location头注入'],
            'content_type'     => ['pattern' => '/Content-Type\s*:/i', 'level' => 3, 'desc' => 'Content-Type头注入'],
            'refresh'          => ['pattern' => '/Refresh\s*:/i', 'level' => 3, 'desc' => 'Refresh头注入'],
            'x_forwarded'      => ['pattern' => '/X-Forwarded-[A-Za-z-]+\s*:/i', 'level' => 2, 'desc' => 'X-Forwarded头注入'],
            'x_forwarded_for'  => ['pattern' => '/X-Forwarded-For\s*:/i', 'level' => 3, 'desc' => 'X-Forwarded-For头注入'],
            'set_cookie_evil'  => ['pattern' => '/Set-Cookie\s*:.*[=;]/i', 'level' => 5, 'desc' => '恶意Set-Cookie注入'],
            'x_xss_protection' => ['pattern' => '/X-XSS-Protection\s*:/i', 'level' => 4, 'desc' => 'X-XSS-Protection头注入(绕过)'],
            'csp'              => ['pattern' => '/Content-Security-Policy\s*:/i', 'level' => 5, 'desc' => 'Content-Security-Policy头注入(绕过)'],
            'x_forwarded_host' => ['pattern' => '/X-Forwarded-Host\s*:/i', 'level' => 3, 'desc' => 'X-Forwarded-Host头注入(缓存投毒)'],
        ];

        foreach ($headerInjectionPatterns as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $hits[] = [
                    'header' => $key,
                    'level'  => $info['level'],
                    'desc'   => $info['desc'],
                ];
            }
        }

        if (preg_match('/[A-Za-z][A-Za-z0-9-]*\s*:/', $input, $matches)) {
            $headerName = $matches[0];
            $standardHeaders = [
                'Content-Type:', 'Content-Length:', 'Set-Cookie:', 'Location:',
                'Refresh:', 'X-Forwarded-For:', 'X-Forwarded-Host:',
                'X-Forwarded-Proto:', 'X-Real-IP:', 'Host:', 'User-Agent:',
                'Accept:', 'Accept-Language:', 'Accept-Encoding:',
                'Connection:', 'Cache-Control:', 'Pragma:',
            ];
            $isStandard = false;
            foreach ($standardHeaders as $sh) {
                if (strcasecmp(trim($headerName), $sh) === 0) {
                    $isStandard = true;
                    break;
                }
            }
            if (!$isStandard && self::hasCrlfBefore($input, $matches[0])) {
                $hits[] = [
                    'header' => 'custom_header',
                    'level'  => 2,
                    'desc'   => '自定义HTTP头注入',
                ];
            }
        }

        usort($hits, function($a, $b) { return $b['level'] - $a['level']; });
        return $hits;
    }

    private static function hasCrlfBefore(string $input, string $headerStr): bool {
        $pos = strpos($input, $headerStr);
        if ($pos === false) return false;
        $before = substr($input, 0, $pos);
        return strpos($before, "\r") !== false || strpos($before, "\n") !== false;
    }

    private static function detectResponseSplittingRegex(string $decodedInput, string $originalInput): bool {
        $doubleCrlfPatterns = [
            "\r\n\r\n",
            "\n\r\n\r",
            "\n\n",
            "\r\r",
            '%0d%0a%0d%0a',
            '%0D%0A%0D%0A',
            '%0a%0d%0a%0d',
            '%0A%0D%0A%0D',
            '%0a%0a',
            '%0A%0A',
            '%0d%0d',
            '%0D%0D',
        ];

        foreach ($doubleCrlfPatterns as $pattern) {
            if (stripos($decodedInput, $pattern) !== false) {
                return true;
            }
            if (stripos($originalInput, $pattern) !== false) {
                return true;
            }
        }

        if (preg_match('/(\r\n|\n\r|\n|\r).*?(\r\n|\n\r|\n|\r).*?HTTP\/\d\.\d/i', $decodedInput)) {
            return true;
        }

        if (preg_match('/(\r\n|\n\r|\n|\r).*?(\r\n|\n\r|\n|\r).*?Content-Type:/i', $decodedInput)) {
            return true;
        }

        return false;
    }

    private static function detectHeaderNameInjectionRegex(string $input): bool {
        if (preg_match('/[\r\n][A-Za-z][A-Za-z0-9-]*\s*:/', $input)) {
            return true;
        }
        if (preg_match('/%0[dD]%0[aA][A-Za-z]/', $input)) {
            return true;
        }
        if (preg_match('/%0[aA]%0[dD][A-Za-z]/', $input)) {
            return true;
        }
        return false;
    }

    // ==================== Scoring ====================

    private static function calculateScore(array $result): int {
        $score = 0;
        $indicators = [];

        $crlfCount = $result['crlf_count'] ?? 0;
        if ($crlfCount >= 4) { $score += 30; $indicators[] = 'multiple_crlf'; }
        elseif ($crlfCount >= 2) { $score += 20; $indicators[] = 'double_crlf'; }
        elseif ($crlfCount >= 1) { $score += 10; $indicators[] = 'single_crlf'; }

        $maxHeaderLevel = 0;
        foreach (($result['header_injection_hits'] ?? []) as $hit) {
            if ($hit['level'] > $maxHeaderLevel) $maxHeaderLevel = $hit['level'];
        }
        if ($maxHeaderLevel >= 5) { $score += 30; $indicators[] = 'critical_header_injection'; }
        elseif ($maxHeaderLevel >= 4) { $score += 22; $indicators[] = 'high_header_injection'; }
        elseif ($maxHeaderLevel >= 3) { $score += 15; $indicators[] = 'medium_header_injection'; }
        elseif ($maxHeaderLevel >= 2) { $score += 8; $indicators[] = 'low_header_injection'; }

        if (!empty($result['response_splitting'])) {
            $score += 35;
            $indicators[] = 'response_splitting';
        }

        if (!empty($result['header_name_injection'])) {
            $score += 15;
            $indicators[] = 'header_name_injection';
        }

        if (!empty($result['has_status_line_injection'])) {
            $score += 25;
            $indicators[] = 'status_line_injection';
        }

        if (!empty($result['has_set_cookie_injection'])) {
            $score += 10;
            $indicators[] = 'set_cookie_injection';
        }

        if (!empty($result['has_cache_poisoning'])) {
            $score += 12;
            $indicators[] = 'cache_poisoning';
        }

        if (!empty($result['has_redirect_injection'])) {
            $score += 10;
            $indicators[] = 'redirect_injection';
        }

        if (!empty($result['has_excessive_headers'])) {
            $score += 8;
            $indicators[] = 'excessive_headers';
        }

        if (!empty($result['has_invalid_header_name'])) {
            $score += 5;
            $indicators[] = 'invalid_header_name';
        }

        if (!empty($result['multiline_headers'])) {
            $score += 5;
            $indicators[] = 'multiline_headers';
        }

        $decodeDepth = $result['decode_depth'] ?? 0;
        if ($decodeDepth >= 3) { $score += 18; $indicators[] = 'multi_layer_encoding'; }
        elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
        elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

        if ($crlfCount > 0 && !empty($result['header_injection_hits'])) {
            $score += 15;
            $indicators[] = 'crlf_plus_header_combo';
        }

        if (!empty($result['response_splitting']) && !empty($result['header_injection_hits'])) {
            $score += 10;
            $indicators[] = 'splitting_plus_header_combo';
        }

        if ($result['parser_used'] === 'ast') {
            $indicators[] = 'ast_parsed';
        }

        $result['indicators'] = array_merge($result['indicators'] ?? [], $indicators);

        return $score;
    }

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type'         => $ast['type'] ?? 'unknown',
            'header_count' => $ast['header_count'] ?? 0,
        ];

        if (!empty($ast['has_status_line'])) {
            $summary['has_status_line'] = true;
        }

        if (!empty($ast['invalid_header_names'])) {
            $summary['invalid_header_count'] = count($ast['invalid_header_names']);
        }

        $dangerousCount = 0;
        $multilineCount = 0;
        foreach (($ast['headers'] ?? []) as $header) {
            $nameUpper = strtoupper($header['name_lower'] ?? '');
            if (isset(self::$dangerousHeaders[$nameUpper])) {
                $dangerousCount++;
            }
            if (!empty($header['is_multiline'])) {
                $multilineCount++;
            }
        }

        $summary['dangerous_header_count'] = $dangerousCount;
        $summary['multiline_header_count'] = $multilineCount;

        return $summary;
    }

    // ==================== Decoding Helpers ====================

    private static function multiLayerDecode(string $input): array {
        $depth = 0;
        $encodeTypes = [];
        $current = $input;

        for ($i = 0; $i < 5; $i++) {
            $decoded = $current;
            $changed = false;

            if (preg_match('/%[0-9a-fA-F]{2}/', $decoded)) {
                $newDecoded = urldecode($decoded);
                if ($newDecoded !== $decoded) {
                    $decoded = $newDecoded;
                    $encodeTypes[] = 'url';
                    $changed = true;
                }
            }

            if (preg_match('/&#\d+;/', $decoded)) {
                $newDecoded = html_entity_decode($decoded, ENT_HTML5);
                if ($newDecoded !== $decoded) {
                    $decoded = $newDecoded;
                    $encodeTypes[] = 'html_entity';
                    $changed = true;
                }
            }

            if (!$changed) break;
            $depth++;
            $current = $decoded;
        }

        return [
            'decoded'      => $current,
            'depth'        => $depth,
            'encode_types' => array_values(array_unique($encodeTypes)),
        ];
    }

    private static function detectCrlfSequences(string $decodedInput, string $originalInput): array {
        $count = 0;
        $types = [];

        foreach (self::$crlfPatterns as $key => $info) {
            list($pattern, $desc) = $info;
            $foundInDecoded = substr_count($decodedInput, $pattern);
            $foundInOriginal = substr_count($originalInput, $pattern);

            if ($foundInDecoded > 0 || $foundInOriginal > 0) {
                $total = max($foundInDecoded, $foundInOriginal);
                $count += $total;
                $types[] = [
                    'type'  => $key,
                    'desc'  => $desc,
                    'count' => $total,
                ];
            }
        }

        $rnCount = substr_count($decodedInput, "\r\n");
        $nrCount = substr_count($decodedInput, "\n\r");
        $rawR = substr_count($decodedInput, "\r");
        $rawN = substr_count($decodedInput, "\n");

        if ($rnCount > 0) {
            $count += $rnCount;
        }
        if ($nrCount > 0) {
            $count += $nrCount;
        }

        return [
            'count' => $count,
            'types' => $types,
        ];
    }
}
