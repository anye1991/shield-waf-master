<?php
defined('ABSPATH') || exit;

class DeserializationSemanticParser {

    const TOKEN_TYPE_INT      = 'TYPE_INT';
    const TOKEN_TYPE_FLOAT    = 'TYPE_FLOAT';
    const TOKEN_TYPE_STRING   = 'TYPE_STRING';
    const TOKEN_TYPE_ARRAY    = 'TYPE_ARRAY';
    const TOKEN_TYPE_OBJECT   = 'TYPE_OBJECT';
    const TOKEN_TYPE_NULL     = 'TYPE_NULL';
    const TOKEN_TYPE_BOOL     = 'TYPE_BOOL';
    const TOKEN_TYPE_REF      = 'TYPE_REF';
    const TOKEN_TYPE_OBJREF   = 'TYPE_OBJREF';
    const TOKEN_TYPE_CUSTOM   = 'TYPE_CUSTOM';
    const TOKEN_COLON         = 'COLON';
    const TOKEN_SEMICOLON     = 'SEMICOLON';
    const TOKEN_LBRACE        = 'LBRACE';
    const TOKEN_RBRACE        = 'RBRACE';
    const TOKEN_QUOTE         = 'QUOTE';
    const TOKEN_INTEGER       = 'INTEGER';
    const TOKEN_STRING_VAL    = 'STRING_VAL';
    const TOKEN_EOF           = 'EOF';

    private static $dangerousClasses = [
        'SoapClient'         => ['level' => 5, 'desc' => 'SSRF/命令执行', 'category' => 'rce'],
        'DirectoryIterator'  => ['level' => 4, 'desc' => '目录遍历', 'category' => 'file'],
        'GlobIterator'       => ['level' => 4, 'desc' => '文件枚举', 'category' => 'file'],
        'SplFileObject'      => ['level' => 4, 'desc' => '文件读取', 'category' => 'file'],
        'SplTempFileObject'  => ['level' => 3, 'desc' => '临时文件操作', 'category' => 'file'],
        'ReflectionClass'    => ['level' => 4, 'desc' => '反射类', 'category' => 'rce'],
        'ReflectionFunction' => ['level' => 4, 'desc' => '反射函数', 'category' => 'rce'],
        'ReflectionMethod'   => ['level' => 4, 'desc' => '反射方法', 'category' => 'rce'],
        'ReflectionObject'   => ['level' => 4, 'desc' => '反射对象', 'category' => 'rce'],
        'SimpleXMLElement'   => ['level' => 4, 'desc' => 'XXE/文件读取', 'category' => 'xxe'],
        'DOMDocument'        => ['level' => 3, 'desc' => 'XXE', 'category' => 'xxe'],
        'PDO'                => ['level' => 3, 'desc' => '数据库操作', 'category' => 'db'],
        'PDOStatement'       => ['level' => 3, 'desc' => 'SQL注入', 'category' => 'db'],
        'mysqli'             => ['level' => 3, 'desc' => 'SQL注入', 'category' => 'db'],
        'PHar'               => ['level' => 4, 'desc' => 'PHAR反序列化', 'category' => 'deserialization'],
        'finfo'              => ['level' => 2, 'desc' => '文件信息', 'category' => 'file'],
        'Exception'          => ['level' => 3, 'desc' => '异常类-魔法方法', 'category' => 'magic'],
        'Error'              => ['level' => 3, 'desc' => '错误类-魔法方法', 'category' => 'magic'],
        'ZipArchive'         => ['level' => 4, 'desc' => 'ZipArchive-文件操作', 'category' => 'file'],
        'GuzzleHttp\Client'  => ['level' => 3, 'desc' => 'HTTP客户端-SSRF', 'category' => 'ssrf'],
        'curl'               => ['level' => 3, 'desc' => 'cURL-SSRF', 'category' => 'ssrf'],
        'StreamSocketClient' => ['level' => 4, 'desc' => 'Socket客户端-SSRF', 'category' => 'ssrf'],
        'Memcached'          => ['level' => 3, 'desc' => 'Memcached-SSRF', 'category' => 'ssrf'],
        'Redis'              => ['level' => 3, 'desc' => 'Redis-SSRF', 'category' => 'ssrf'],
    ];

    private static $magicMethods = [
        '__destruct'   => ['level' => 5, 'desc' => '析构函数-反序列化自动调用', 'trigger' => 'unserialize'],
        '__wakeup'     => ['level' => 5, 'desc' => '反序列化唤醒方法', 'trigger' => 'unserialize'],
        '__toString'   => ['level' => 4, 'desc' => '字符串转换方法', 'trigger' => 'echo/cast'],
        '__get'        => ['level' => 3, 'desc' => '读取不可访问属性', 'trigger' => 'property_read'],
        '__set'        => ['level' => 3, 'desc' => '设置不可访问属性', 'trigger' => 'property_write'],
        '__isset'      => ['level' => 2, 'desc' => 'isset检测不可访问属性', 'trigger' => 'isset'],
        '__unset'      => ['level' => 2, 'desc' => 'unset不可访问属性', 'trigger' => 'unset'],
        '__call'       => ['level' => 4, 'desc' => '调用不可访问方法', 'trigger' => 'method_call'],
        '__callStatic' => ['level' => 3, 'desc' => '静态调用不可访问方法', 'trigger' => 'static_call'],
        '__invoke'     => ['level' => 4, 'desc' => '对象当函数调用', 'trigger' => 'invoke'],
        '__sleep'      => ['level' => 2, 'desc' => '序列化前清理', 'trigger' => 'serialize'],
        '__clone'      => ['level' => 2, 'desc' => '对象克隆', 'trigger' => 'clone'],
        '__set_state'  => ['level' => 4, 'desc' => 'var_export反序列化', 'trigger' => 'var_export'],
        '__debugInfo'  => ['level' => 3, 'desc' => '调试信息输出', 'trigger' => 'var_dump'],
    ];

    private static $stringEscapePatterns = [
        'quote_injection'     => ['level' => 4, 'pattern' => '/s:\d+:"[^"]*";s:\d+:"/', 'desc' => '字符串引号注入'],
        'premature_terminate' => ['level' => 4, 'pattern' => '/s:\d+:"[^"]*";}/', 'desc' => '提前终止结构'],
        'nested_serialize'    => ['level' => 3, 'pattern' => '/s:\d+:"[Oa]:\d+:/', 'desc' => '嵌套序列化字符串'],
        'string_terminator'   => ['level' => 5, 'pattern' => '/s:\d+:"[^"]*";O:/', 'desc' => '字符串终止后紧跟对象'],
        'fake_length'         => ['level' => 5, 'pattern' => '/s:(9[0-9]+|1[0-9]{3,}):"/', 'desc' => '超大字符串长度'],
    ];

    private static $popChainSignatures = [
        'soapclient_call' => [
            'level' => 5,
            'desc' => 'SoapClient __call SSRF链',
            'pattern' => ['SoapClient'],
            'trigger' => '__call',
        ],
        'directoryiterator_tostring' => [
            'level' => 4,
            'desc' => 'DirectoryIterator __toString 文件遍历链',
            'pattern' => ['DirectoryIterator'],
            'trigger' => '__toString',
        ],
        'reflection_chain' => [
            'level' => 5,
            'desc' => '反射类代码执行链',
            'pattern' => ['ReflectionClass', 'ReflectionMethod', 'ReflectionObject'],
            'trigger' => '__invoke',
        ],
        'phar_deserialization' => [
            'level' => 5,
            'desc' => 'PHAR反序列化链',
            'pattern' => ['PHar'],
            'trigger' => '__destruct',
        ],
        'xxe_chain' => [
            'level' => 4,
            'desc' => 'XXE利用链',
            'pattern' => ['SimpleXMLElement', 'DOMDocument'],
            'trigger' => '__destruct',
        ],
        'file_read_chain' => [
            'level' => 4,
            'desc' => '文件读取链',
            'pattern' => ['SplFileObject', 'SplFileInfo'],
            'trigger' => '__toString',
        ],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $originalInput = $input;
        $decodeResult = self::decodeInput($input);
        $decodedInput = $decodeResult['decoded'];
        $decodeDepth = $decodeResult['depth'];
        $encodeTypes = $decodeResult['encode_types'];

        $result['decode_depth'] = $decodeDepth;
        $result['encode_types'] = $encodeTypes;
        $result['total_length'] = strlen($decodedInput);

        if ($decodedInput === '') return $result;

        try {
            $tokens = self::tokenize($decodedInput);
            $result['token_count'] = count($tokens);

            if (empty($tokens)) {
                $result['parser_used'] = 'regex_fallback';
                $regexResult = self::regexFallback($decodedInput, $result);
                return $regexResult;
            }

            $parseResult = self::parseWithAst($tokens, $decodedInput);

            if ($parseResult !== null && ($parseResult['is_valid'] || $parseResult['partial_match'])) {
                $result['parser_used'] = 'ast';
                $result = array_merge($result, self::mapAstResult($parseResult));

                if (!empty($parseResult['ast'])) {
                    $result['ast_summary'] = self::summarizeAst($parseResult['ast']);
                    $result['structure_tree'] = $parseResult['ast'];
                }

                $result = self::analyzeAstSemantically($result, $parseResult);
                $result = self::calculateRisk($result, $parseResult);
            } else {
                $result['parser_used'] = 'regex_fallback';
                $regexResult = self::regexFallback($decodedInput, $result);
                return $regexResult;
            }

        } catch (Exception $e) {
            $result['parser_used'] = 'regex_fallback';
            $result['parse_errors'][] = 'ast_parser_exception: ' . $e->getMessage();
            $regexResult = self::regexFallback($decodedInput, $result);
            return $regexResult;
        }

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'                    => 0,
            'risk_level'               => 'clean',
            'is_deserialization'       => false,
            'structure_valid'          => false,
            'partial_match'            => false,
            'parse_errors'             => [],
            'object_count'             => 0,
            'array_count'              => 0,
            'string_count'             => 0,
            'integer_count'            => 0,
            'bool_count'               => 0,
            'float_count'              => 0,
            'null_count'               => 0,
            'reference_count'          => 0,
            'reference_r_count'        => 0,
            'max_nesting_depth'        => 0,
            'dangerous_classes'        => [],
            'all_classes'              => [],
            'magic_methods_in_classes' => [],
            'length_anomalies'         => [],
            'pop_chain_indicators'     => [],
            'string_escape_indicators' => [],
            'has_pop_chain'            => false,
            'total_length'             => 0,
            'decode_depth'             => 0,
            'encode_types'             => [],
            'indicators'               => [],
            'structure_tree'           => null,
            'ast_summary'              => [],
            'parser_used'              => 'none',
            'token_count'              => 0,
            'prop_values_analysis'     => [],
            'class_hierarchy'          => [],
            'chain_analysis'           => [],
        ];
    }

    // ==================== Input Decoding ====================

    private static function decodeInput(string $input): array {
        $depth = 0;
        $encodeTypes = [];
        $current = $input;

        for ($i = 0; $i < 4; $i++) {
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

            if (preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', trim($decoded)) && strlen($decoded) > 20) {
                $base64Decoded = base64_decode($decoded, true);
                if ($base64Decoded !== false && self::looksLikeSerialized($base64Decoded)) {
                    $decoded = $base64Decoded;
                    $encodeTypes[] = 'base64';
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
            'encode_types' => array_unique($encodeTypes),
        ];
    }

    private static function looksLikeSerialized(string $str): bool {
        $str = trim($str);
        if ($str === '') return false;
        $firstChar = $str[0];
        return in_array($firstChar, ['O', 'a', 's', 'i', 'b', 'd', 'N', 'R', 'r', 'C'], true);
    }

    // ==================== Tokenizer ====================

    private static function tokenize(string $data): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($data);

        while ($pos < $len) {
            $char = $data[$pos];

            if (ctype_space($char)) {
                $pos++;
                continue;
            }

            switch ($char) {
                case 'i':
                    $tokens[] = ['type' => self::TOKEN_TYPE_INT, 'value' => 'i', 'pos' => $pos];
                    $pos++;
                    break;
                case 'd':
                    $tokens[] = ['type' => self::TOKEN_TYPE_FLOAT, 'value' => 'd', 'pos' => $pos];
                    $pos++;
                    break;
                case 's':
                    $stringToken = self::tryTokenizeString($data, $pos, $len);
                    if ($stringToken !== null) {
                        $tokens[] = $stringToken;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_TYPE_STRING, 'value' => 's', 'pos' => $pos];
                        $pos++;
                    }
                    break;
                case 'a':
                    $tokens[] = ['type' => self::TOKEN_TYPE_ARRAY, 'value' => 'a', 'pos' => $pos];
                    $pos++;
                    break;
                case 'O':
                    $objectToken = self::tryTokenizeObjectHeader($data, $pos, $len);
                    if ($objectToken !== null) {
                        $tokens[] = $objectToken;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_TYPE_OBJECT, 'value' => 'O', 'pos' => $pos];
                        $pos++;
                    }
                    break;
                case 'N':
                    $tokens[] = ['type' => self::TOKEN_TYPE_NULL, 'value' => 'N', 'pos' => $pos];
                    $pos++;
                    break;
                case 'b':
                    $tokens[] = ['type' => self::TOKEN_TYPE_BOOL, 'value' => 'b', 'pos' => $pos];
                    $pos++;
                    break;
                case 'R':
                    $tokens[] = ['type' => self::TOKEN_TYPE_REF, 'value' => 'R', 'pos' => $pos];
                    $pos++;
                    break;
                case 'r':
                    $tokens[] = ['type' => self::TOKEN_TYPE_OBJREF, 'value' => 'r', 'pos' => $pos];
                    $pos++;
                    break;
                case 'C':
                    $tokens[] = ['type' => self::TOKEN_TYPE_CUSTOM, 'value' => 'C', 'pos' => $pos];
                    $pos++;
                    break;
                case ':':
                    $tokens[] = ['type' => self::TOKEN_COLON, 'value' => ':', 'pos' => $pos];
                    $pos++;
                    break;
                case ';':
                    $tokens[] = ['type' => self::TOKEN_SEMICOLON, 'value' => ';', 'pos' => $pos];
                    $pos++;
                    break;
                case '{':
                    $tokens[] = ['type' => self::TOKEN_LBRACE, 'value' => '{', 'pos' => $pos];
                    $pos++;
                    break;
                case '}':
                    $tokens[] = ['type' => self::TOKEN_RBRACE, 'value' => '}', 'pos' => $pos];
                    $pos++;
                    break;
                case '"':
                    $tokens[] = ['type' => self::TOKEN_QUOTE, 'value' => '"', 'pos' => $pos];
                    $pos++;
                    break;
                default:
                    if (ctype_digit($char) || ($char === '-' && $pos + 1 < $len && ctype_digit($data[$pos + 1]))) {
                        $start = $pos;
                        if ($char === '-') $pos++;
                        while ($pos < $len && ctype_digit($data[$pos])) $pos++;
                        $tokens[] = ['type' => self::TOKEN_INTEGER, 'value' => substr($data, $start, $pos - $start), 'pos' => $start];
                    } else {
                        $pos++;
                    }
                    break;
            }
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    private static function tryTokenizeString(string $data, int &$pos, int $len): ?array {
        $startPos = $pos;
        $p = $pos + 1;
        if ($p >= $len || $data[$p] !== ':') return null;
        $p++;

        $lenStart = $p;
        while ($p < $len && ctype_digit($data[$p])) $p++;
        if ($p >= $len || $data[$p] !== ':') return null;
        $strLen = (int)substr($data, $lenStart, $p - $lenStart);
        $p++;

        if ($p >= $len || $data[$p] !== '"') return null;
        $p++;

        if ($strLen < 0 || $p + $strLen > $len) return null;
        $content = substr($data, $p, $strLen);
        $p += $strLen;

        if ($p >= $len || $data[$p] !== '"') return null;
        $p++;

        if ($p >= $len || $data[$p] !== ';') return null;
        $p++;

        $pos = $p;
        return [
            'type'            => self::TOKEN_STRING_VAL,
            'value'           => $content,
            'pos'             => $startPos,
            'declared_length' => $strLen,
            'actual_length'   => strlen($content),
        ];
    }

    private static function tryTokenizeObjectHeader(string $data, int &$pos, int $len): ?array {
        $startPos = $pos;
        $p = $pos + 1;
        if ($p >= $len || $data[$p] !== ':') return null;
        $p++;

        $nameLenStart = $p;
        while ($p < $len && ctype_digit($data[$p])) $p++;
        if ($p >= $len || $data[$p] !== ':') return null;
        $nameLen = (int)substr($data, $nameLenStart, $p - $nameLenStart);
        $p++;

        if ($p >= $len || $data[$p] !== '"') return null;
        $p++;

        if ($nameLen < 0 || $p + $nameLen > $len) return null;
        $className = substr($data, $p, $nameLen);
        $p += $nameLen;

        if ($p >= $len || $data[$p] !== '"') return null;
        $p++;

        if ($p >= $len || $data[$p] !== ':') return null;
        $p++;

        $propCountStart = $p;
        while ($p < $len && ctype_digit($data[$p])) $p++;
        if ($p >= $len || $data[$p] !== ':') return null;
        $propCount = (int)substr($data, $propCountStart, $p - $propCountStart);
        $p++;

        if ($p >= $len || $data[$p] !== '{') return null;
        $p++;

        $pos = $p;
        return [
            'type'              => 'OBJECT_HEADER',
            'value'             => $className,
            'pos'               => $startPos,
            'class_name'        => $className,
            'name_length'       => $nameLen,
            'property_count'    => $propCount,
            'header_end_pos'    => $p,
        ];
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function next(array &$state) {
        if ($state['pos'] < count($state['tokens']) - 1) $state['pos']++;
    }

    private static function isEof(array &$state): bool {
        return self::current($state)['type'] === self::TOKEN_EOF;
    }

    private static function matchToken(array &$state, string $type): bool {
        if (self::current($state)['type'] === $type) {
            self::next($state);
            return true;
        }
        return false;
    }

    private static function expectToken(array &$state, string $type, array &$errors, string $errorMsg): bool {
        if (self::current($state)['type'] === $type) {
            self::next($state);
            return true;
        }
        $errors[] = $errorMsg . '_at_pos_' . (self::current($state)['pos'] ?? 'unknown');
        return false;
    }

    // ==================== AST Parser ====================

    private static function parseWithAst(array $tokens, string $data): ?array {
        $state = [
            'tokens'              => $tokens,
            'pos'                 => 0,
            'data'                => $data,
            'errors'              => [],
            'object_count'        => 0,
            'array_count'         => 0,
            'string_count'        => 0,
            'integer_count'       => 0,
            'bool_count'          => 0,
            'float_count'         => 0,
            'null_count'          => 0,
            'reference_count'     => 0,
            'reference_r_count'   => 0,
            'max_depth'           => 0,
            'all_classes'         => [],
            'length_anomalies'    => [],
            'private_props'       => [],
            'protected_props'     => [],
            'references'          => [],
            'obj_refs'            => [],
            'long_strings'        => [],
            'max_string_length'   => 0,
            'has_circular_ref'    => false,
            'prop_value_stats'    => [],
            'class_chain'         => [],
        ];

        $ast = self::parseValue($state, 0);

        $isValid = empty($state['errors']) && $ast !== null && self::isEof($state);
        $partialMatch = !$isValid && $ast !== null;

        if (!$isValid && !$partialMatch) {
            $firstToken = $state['tokens'][0] ?? null;
            if ($firstToken && in_array($firstToken['type'], [
                self::TOKEN_TYPE_OBJECT, self::TOKEN_TYPE_ARRAY, self::TOKEN_TYPE_STRING,
                self::TOKEN_TYPE_INT, self::TOKEN_TYPE_FLOAT, self::TOKEN_TYPE_BOOL,
                self::TOKEN_TYPE_NULL, self::TOKEN_TYPE_REF, self::TOKEN_TYPE_OBJREF,
                self::TOKEN_TYPE_CUSTOM, self::TOKEN_STRING_VAL, 'OBJECT_HEADER'
            ])) {
                $partialMatch = true;
            }
        }

        return [
            'ast'                 => $ast,
            'is_valid'            => $isValid,
            'partial_match'       => $partialMatch,
            'errors'              => $state['errors'],
            'object_count'        => $state['object_count'],
            'array_count'         => $state['array_count'],
            'string_count'        => $state['string_count'],
            'integer_count'       => $state['integer_count'],
            'bool_count'          => $state['bool_count'],
            'float_count'         => $state['float_count'],
            'null_count'          => $state['null_count'],
            'reference_count'     => $state['reference_count'],
            'reference_r_count'   => $state['reference_r_count'],
            'max_depth'           => $state['max_depth'],
            'all_classes'         => $state['all_classes'],
            'length_anomalies'    => $state['length_anomalies'],
            'private_props'       => $state['private_props'],
            'protected_props'     => $state['protected_props'],
            'references'          => $state['references'],
            'obj_refs'            => $state['obj_refs'],
            'long_strings'        => $state['long_strings'],
            'max_string_length'   => $state['max_string_length'],
            'has_circular_ref'    => $state['has_circular_ref'],
            'prop_value_stats'    => $state['prop_value_stats'],
            'class_chain'         => $state['class_chain'],
            'data'                => $data,
        ];
    }

    private static function parseValue(array &$state, int $depth): ?array {
        if ($depth > $state['max_depth']) $state['max_depth'] = $depth;
        if ($depth > 100) { $state['errors'][] = 'max_depth_exceeded'; return null; }

        $token = self::current($state);

        switch ($token['type']) {
            case self::TOKEN_TYPE_INT:
                return self::parseIntegerNode($state);
            case self::TOKEN_TYPE_BOOL:
                return self::parseBoolNode($state);
            case self::TOKEN_TYPE_FLOAT:
                return self::parseFloatNode($state);
            case self::TOKEN_STRING_VAL:
                return self::parseStringNodeFromToken($state);
            case self::TOKEN_TYPE_STRING:
                return self::parseStringNode($state);
            case self::TOKEN_TYPE_ARRAY:
                return self::parseArrayNode($state, $depth);
            case 'OBJECT_HEADER':
                return self::parseObjectNodeFromHeader($state, $depth);
            case self::TOKEN_TYPE_OBJECT:
                return self::parseObjectNode($state, $depth);
            case self::TOKEN_TYPE_NULL:
                return self::parseNullNode($state);
            case self::TOKEN_TYPE_REF:
                return self::parseReferenceNode($state, 'R');
            case self::TOKEN_TYPE_OBJREF:
                return self::parseReferenceNode($state, 'r');
            case self::TOKEN_TYPE_CUSTOM:
                return self::parseCustomObjectNode($state, $depth);
            default:
                $state['errors'][] = 'unexpected_token_' . $token['type'];
                return null;
        }
    }

    private static function parseIntegerNode(array &$state): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'int_missing_colon')) return null;

        $numToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;

        if (!self::expectToken($state, self::TOKEN_SEMICOLON, $state['errors'], 'int_missing_semicolon')) return null;

        $state['integer_count']++;
        return ['node_type' => 'literal', 'type' => 'integer', 'value' => (int)$numToken['value'], 'depth' => 0, 'pos' => $startToken['pos'] ?? 0];
    }

    private static function parseBoolNode(array &$state): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'bool_missing_colon')) return null;

        $valToken = self::current($state);
        if ($valToken['type'] !== self::TOKEN_INTEGER || !in_array($valToken['value'], ['0', '1'])) return null;
        self::next($state);

        if (!self::expectToken($state, self::TOKEN_SEMICOLON, $state['errors'], 'bool_missing_semicolon')) return null;

        $state['bool_count']++;
        return ['node_type' => 'literal', 'type' => 'bool', 'value' => $valToken['value'] === '1', 'depth' => 0, 'pos' => $startToken['pos'] ?? 0];
    }

    private static function parseFloatNode(array &$state): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'float_missing_colon')) return null;

        $numToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;

        if (!self::expectToken($state, self::TOKEN_SEMICOLON, $state['errors'], 'float_missing_semicolon')) return null;

        $state['float_count']++;
        return ['node_type' => 'literal', 'type' => 'float', 'value' => (float)$numToken['value'], 'depth' => 0, 'pos' => $startToken['pos'] ?? 0];
    }

    private static function parseStringNodeFromToken(array &$state): ?array {
        $token = self::current($state);
        self::next($state);

        $declaredLength = $token['declared_length'] ?? 0;
        $stringValue = $token['value'] ?? '';
        $realByteCount = strlen($stringValue);

        if ($realByteCount !== $declaredLength) {
            $state['length_anomalies'][] = [
                'type' => 'length_mismatch',
                'position' => $token['pos'] ?? 0,
                'declared' => $declaredLength,
                'actual' => $realByteCount,
            ];
        }

        if ($declaredLength > $state['max_string_length']) $state['max_string_length'] = $declaredLength;
        if ($declaredLength > 10000) $state['long_strings'][] = ['length' => $declaredLength, 'position' => $token['pos'] ?? 0];

        self::analyzeStringValue($stringValue, $state);

        $state['string_count']++;
        return [
            'node_type' => 'literal', 'type' => 'string', 'value' => $stringValue,
            'declared_length' => $declaredLength, 'actual_length' => $realByteCount,
            'depth' => 0, 'pos' => $token['pos'] ?? 0,
        ];
    }

    private static function parseStringNode(array &$state): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'string_missing_colon1')) return null;

        $lenToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $declaredLength = (int)$lenToken['value'];

        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'string_missing_colon2')) return null;
        if (!self::expectToken($state, self::TOKEN_QUOTE, $state['errors'], 'string_missing_opening_quote')) return null;

        $data = $state['data'];
        $stringStart = $lenToken['pos'] + strlen($lenToken['value']) + 3;
        $stringValue = substr($data, $stringStart, $declaredLength);
        $realByteCount = strlen($stringValue);

        if ($realByteCount !== $declaredLength) {
            $state['length_anomalies'][] = [
                'type' => 'length_mismatch',
                'position' => $startToken['pos'] ?? 0,
                'declared' => $declaredLength,
                'actual' => $realByteCount,
            ];
        }

        if ($declaredLength > $state['max_string_length']) $state['max_string_length'] = $declaredLength;
        if ($declaredLength > 10000) $state['long_strings'][] = ['length' => $declaredLength, 'position' => $startToken['pos'] ?? 0];

        self::analyzeStringValue($stringValue, $state);

        $state['pos'] += 2;

        $state['string_count']++;
        return [
            'node_type' => 'literal', 'type' => 'string', 'value' => $stringValue,
            'declared_length' => $declaredLength, 'actual_length' => $realByteCount,
            'depth' => 0, 'pos' => $startToken['pos'] ?? 0,
        ];
    }

    private static function parseArrayNode(array &$state, int $depth): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'array_missing_colon1')) return null;

        $countToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $elementCount = (int)$countToken['value'];

        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'array_missing_colon2')) return null;
        if (!self::expectToken($state, self::TOKEN_LBRACE, $state['errors'], 'array_missing_opening_brace')) return null;

        $state['array_count']++;
        $elements = [];

        for ($i = 0; $i < $elementCount; $i++) {
            if (self::isEof($state) || self::current($state)['type'] === self::TOKEN_RBRACE) break;
            $key = self::parseValue($state, $depth + 1);
            if ($key === null) break;
            $value = self::parseValue($state, $depth + 1);
            if ($value === null) break;
            $elements[] = ['key' => $key, 'value' => $value];
        }

        self::expectToken($state, self::TOKEN_RBRACE, $state['errors'], 'array_missing_closing_brace');

        return ['node_type' => 'array', 'type' => 'array', 'size' => $elementCount, 'actual_size' => count($elements), 'elements' => $elements, 'depth' => $depth, 'pos' => $startToken['pos'] ?? 0];
    }

    private static function parseObjectNodeFromHeader(array &$state, int $depth): ?array {
        $headerToken = self::current($state);
        self::next($state);

        $className = $headerToken['class_name'] ?? '';
        $propertyCount = $headerToken['property_count'] ?? 0;

        $state['object_count']++;
        $state['all_classes'][] = $className;
        $state['class_chain'][] = ['class' => $className, 'depth' => $depth];

        $properties = [];

        for ($i = 0; $i < $propertyCount; $i++) {
            if (self::isEof($state) || self::current($state)['type'] === self::TOKEN_RBRACE) break;
            $propName = self::parseValue($state, $depth + 1);
            if ($propName === null) break;
            $propValue = self::parseValue($state, $depth + 1);
            if ($propValue === null) break;

            $propNameStr = $propName['value'] ?? '';
            $visibility = 'public';
            if (strpos($propNameStr, "\x00*\x00") === 0) {
                $visibility = 'protected';
                $state['protected_props'][] = ['class' => $className, 'name' => $propNameStr];
            } elseif (strpos($propNameStr, "\x00") !== false) {
                $visibility = 'private';
                $state['private_props'][] = ['class' => $className, 'name' => $propNameStr];
            }

            $properties[] = ['name' => $propName, 'value' => $propValue, 'visibility' => $visibility];
        }

        self::expectToken($state, self::TOKEN_RBRACE, $state['errors'], 'object_missing_closing_brace');

        return [
            'node_type' => 'object', 'type' => 'object', 'class' => $className,
            'props' => $propertyCount, 'actual_props' => count($properties),
            'properties' => $properties, 'depth' => $depth, 'pos' => $headerToken['pos'] ?? 0,
        ];
    }

    private static function parseObjectNode(array &$state, int $depth): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'object_missing_colon1')) return null;

        $nameLenToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $nameLength = (int)$nameLenToken['value'];

        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'object_missing_colon2')) return null;
        if (!self::expectToken($state, self::TOKEN_QUOTE, $state['errors'], 'object_missing_name_opening_quote')) return null;

        $data = $state['data'];
        $nameStartPos = $nameLenToken['pos'] + strlen($nameLenToken['value']) + 3;
        $className = substr($data, $nameStartPos, $nameLength);

        $state['object_count']++;
        $state['all_classes'][] = $className;
        $state['class_chain'][] = ['class' => $className, 'depth' => $depth];

        $state['pos']++;
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'object_missing_colon3')) return null;

        $propCountToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $propertyCount = (int)$propCountToken['value'];

        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'object_missing_colon4')) return null;
        if (!self::expectToken($state, self::TOKEN_LBRACE, $state['errors'], 'object_missing_opening_brace')) return null;

        $properties = [];

        for ($i = 0; $i < $propertyCount; $i++) {
            if (self::isEof($state) || self::current($state)['type'] === self::TOKEN_RBRACE) break;
            $propName = self::parseValue($state, $depth + 1);
            if ($propName === null) break;
            $propValue = self::parseValue($state, $depth + 1);
            if ($propValue === null) break;

            $propNameStr = $propName['value'] ?? '';
            $visibility = 'public';
            if (strpos($propNameStr, "\x00*\x00") === 0) {
                $visibility = 'protected';
            } elseif (strpos($propNameStr, "\x00") !== false) {
                $visibility = 'private';
            }

            $properties[] = ['name' => $propName, 'value' => $propValue, 'visibility' => $visibility];
        }

        self::expectToken($state, self::TOKEN_RBRACE, $state['errors'], 'object_missing_closing_brace');

        return [
            'node_type' => 'object', 'type' => 'object', 'class' => $className,
            'props' => $propertyCount, 'actual_props' => count($properties),
            'properties' => $properties, 'depth' => $depth, 'pos' => $startToken['pos'] ?? 0,
        ];
    }

    private static function parseNullNode(array &$state): ?array {
        $startToken = self::current($state);
        self::next($state);
        self::expectToken($state, self::TOKEN_SEMICOLON, $state['errors'], 'null_missing_semicolon');
        $state['null_count']++;
        return ['node_type' => 'literal', 'type' => 'null', 'value' => null, 'depth' => 0, 'pos' => $startToken['pos'] ?? 0];
    }

    private static function parseReferenceNode(array &$state, string $refType): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'ref_missing_colon')) return null;

        $refToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $refIndex = (int)$refToken['value'];

        self::expectToken($state, self::TOKEN_SEMICOLON, $state['errors'], 'ref_missing_semicolon');

        if ($refType === 'R') {
            $state['reference_count']++;
            $state['references'][] = $refIndex;
        } else {
            $state['reference_r_count']++;
            $state['obj_refs'][] = $refIndex;
        }

        return ['node_type' => 'reference', 'type' => 'reference', 'ref_type' => $refType, 'ref_index' => $refIndex, 'depth' => 0, 'pos' => $startToken['pos'] ?? 0];
    }

    private static function parseCustomObjectNode(array &$state, int $depth): ?array {
        $startToken = self::current($state);
        self::next($state);
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'custom_missing_colon1')) return null;

        $nameLenToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $nameLength = (int)$nameLenToken['value'];

        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'custom_missing_colon2')) return null;
        if (!self::expectToken($state, self::TOKEN_QUOTE, $state['errors'], 'custom_missing_name_quote')) return null;

        $data = $state['data'];
        $nameStartPos = $nameLenToken['pos'] + strlen($nameLenToken['value']) + 3;
        $className = substr($data, $nameStartPos, $nameLength);

        $state['object_count']++;
        $state['all_classes'][] = $className;

        $state['pos']++;
        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'custom_missing_colon3')) return null;

        $dataLenToken = self::current($state);
        if (!self::matchToken($state, self::TOKEN_INTEGER)) return null;
        $dataLength = (int)$dataLenToken['value'];

        if (!self::expectToken($state, self::TOKEN_COLON, $state['errors'], 'custom_missing_colon4')) return null;
        if (!self::expectToken($state, self::TOKEN_LBRACE, $state['errors'], 'custom_missing_opening_brace')) return null;

        $customData = substr($data, $dataLenToken['pos'] + strlen($dataLenToken['value']) + 3, $dataLength);

        $state['pos']++;

        return ['node_type' => 'custom_object', 'type' => 'custom_object', 'class' => $className, 'data_len' => $dataLength, 'data' => $customData, 'depth' => $depth, 'pos' => $startToken['pos'] ?? 0];
    }

    // ==================== String Value Analysis ====================

    private static function analyzeStringValue(string $value, array &$state): void {
        $analysis = [];

        if (strpos($value, '://') !== false || strpos($value, 'http') !== false) {
            $analysis['has_url'] = true;
        }

        if (strpos($value, '/etc/') !== false || strpos($value, 'config') !== false || strpos($value, '.env') !== false) {
            $analysis['has_sensitive_path'] = true;
        }

        if (strpos($value, 'exec') !== false || strpos($value, 'system') !== false || strpos($value, 'shell_exec') !== false) {
            $analysis['has_code_exec'] = true;
        }

        if (strpos($value, 'php://') !== false || strpos($value, 'phar://') !== false) {
            $analysis['has_php_scheme'] = true;
        }

        if (!empty($analysis)) {
            $state['prop_value_stats'][] = $analysis;
        }
    }

    // ==================== AST Semantic Analysis ====================

    private static function analyzeAstSemantically(array $result, array $parseResult): array {
        $classes = $result['all_classes'];
        $result['prop_values_analysis'] = $parseResult['prop_value_stats'];

        $dangerousClasses = self::checkDangerousClasses($classes);
        $result['dangerous_classes'] = $dangerousClasses;

        $magicMethods = self::detectMagicMethodsInClasses($classes);
        $result['magic_methods_in_classes'] = $magicMethods;

        $popChainFeatures = self::detectPopChainFeatures($parseResult);
        $result['pop_chain_indicators'] = $popChainFeatures;
        $result['has_pop_chain'] = !empty($popChainFeatures);

        $escapeFeatures = self::detectStringEscapeFeatures($parseResult);
        $result['string_escape_indicators'] = $escapeFeatures;

        $chainAnalysis = self::analyzeClassChain($parseResult['class_chain'], $dangerousClasses);
        $result['chain_analysis'] = $chainAnalysis;

        return $result;
    }

    private static function analyzeClassChain(array $classChain, array $dangerousClasses): array {
        $analysis = [];
        $dangerousSet = [];
        foreach ($dangerousClasses as $dc) {
            $dangerousSet[$dc['class']] = $dc;
        }

        $consecutiveDangerous = 0;
        $maxConsecutive = 0;

        foreach ($classChain as $entry) {
            $className = $entry['class'];
            if (isset($dangerousSet[$className])) {
                $consecutiveDangerous++;
                if ($consecutiveDangerous > $maxConsecutive) $maxConsecutive = $consecutiveDangerous;
                $analysis[] = ['class' => $className, 'dangerous' => true, 'level' => $dangerousSet[$className]['level']];
            } else {
                $consecutiveDangerous = 0;
                $analysis[] = ['class' => $className, 'dangerous' => false, 'level' => 0];
            }
        }

        if ($maxConsecutive >= 2) {
            $analysis['dangerous_chain'] = true;
            $analysis['chain_length'] = $maxConsecutive;
        }

        return $analysis;
    }

    // ==================== AST Summary ====================

    private static function summarizeAst(array $ast): array {
        $summary = [
            'root_type' => $ast['type'] ?? 'unknown',
            'root_node_type' => $ast['node_type'] ?? 'unknown',
            'depth' => $ast['depth'] ?? 0,
        ];

        if ($ast['node_type'] === 'object') {
            $summary['class'] = $ast['class'] ?? '';
            $summary['prop_count'] = $ast['props'] ?? 0;
        }

        $stats = self::collectAstStats($ast);
        $summary['stats'] = $stats;

        return $summary;
    }

    private static function collectAstStats(array $node): array {
        $stats = ['objects' => 0, 'arrays' => 0, 'strings' => 0, 'integers' => 0, 'bools' => 0, 'floats' => 0, 'nulls' => 0, 'references' => 0, 'obj_references' => 0, 'custom_objects' => 0, 'max_depth' => 0, 'classes' => [], 'total_nodes' => 0];
        self::walkAst($node, $stats, 0);
        return $stats;
    }

    private static function walkAst(array $node, array &$stats, int $currentDepth) {
        $stats['total_nodes']++;
        if ($currentDepth > $stats['max_depth']) $stats['max_depth'] = $currentDepth;

        $nodeType = $node['node_type'] ?? '';
        $valueType = $node['type'] ?? '';

        if ($nodeType === 'literal') {
            switch ($valueType) {
                case 'string': $stats['strings']++; break;
                case 'integer': $stats['integers']++; break;
                case 'bool': $stats['bools']++; break;
                case 'float': $stats['floats']++; break;
                case 'null': $stats['nulls']++; break;
            }
            return;
        }

        if ($nodeType === 'reference') {
            if (($node['ref_type'] ?? '') === 'R') $stats['references']++;
            else $stats['obj_references']++;
            return;
        }

        switch ($nodeType) {
            case 'object':
                $stats['objects']++;
                if (!empty($node['class'])) $stats['classes'][] = $node['class'];
                foreach ($node['properties'] ?? [] as $prop) {
                    if (!empty($prop['name'])) self::walkAst($prop['name'], $stats, $currentDepth + 1);
                    if (!empty($prop['value'])) self::walkAst($prop['value'], $stats, $currentDepth + 1);
                }
                break;
            case 'array':
                $stats['arrays']++;
                foreach ($node['elements'] ?? [] as $elem) {
                    if (!empty($elem['key'])) self::walkAst($elem['key'], $stats, $currentDepth + 1);
                    if (!empty($elem['value'])) self::walkAst($elem['value'], $stats, $currentDepth + 1);
                }
                break;
            case 'custom_object':
                $stats['custom_objects']++;
                if (!empty($node['class'])) $stats['classes'][] = $node['class'];
                break;
        }
    }

    // ==================== Result Mapping & Risk Calculation ====================

    private static function mapAstResult(array $parseResult): array {
        return [
            'is_deserialization' => true,
            'structure_valid' => $parseResult['is_valid'],
            'partial_match' => $parseResult['partial_match'],
            'parse_errors' => $parseResult['errors'],
            'object_count' => $parseResult['object_count'],
            'array_count' => $parseResult['array_count'],
            'string_count' => $parseResult['string_count'],
            'integer_count' => $parseResult['integer_count'],
            'bool_count' => $parseResult['bool_count'],
            'float_count' => $parseResult['float_count'],
            'null_count' => $parseResult['null_count'],
            'reference_count' => $parseResult['reference_count'],
            'reference_r_count' => $parseResult['reference_r_count'],
            'max_nesting_depth' => $parseResult['max_depth'],
            'all_classes' => array_values(array_unique($parseResult['all_classes'])),
            'length_anomalies' => $parseResult['length_anomalies'],
        ];
    }

    private static function calculateRisk(array $result, array $parseResult): array {
        $indicators = [];
        $score = 0;

        $objectCount = $parseResult['object_count'];
        if ($objectCount >= 5) { $score += 20; $indicators[] = 'multiple_objects'; }
        elseif ($objectCount >= 3) { $score += 12; $indicators[] = 'several_objects'; }
        elseif ($objectCount >= 2) { $score += 7; $indicators[] = 'two_objects'; }
        elseif ($objectCount >= 1) { $score += 3; $indicators[] = 'single_object'; }

        $maxDepth = $parseResult['max_depth'];
        if ($maxDepth >= 10) { $score += 25; $indicators[] = 'extreme_nesting'; }
        elseif ($maxDepth >= 6) { $score += 18; $indicators[] = 'deep_nesting'; }
        elseif ($maxDepth >= 4) { $score += 10; $indicators[] = 'moderate_nesting'; }
        elseif ($maxDepth >= 2) { $score += 4; $indicators[] = 'light_nesting'; }

        $maxClassLevel = 0;
        $dangerousCategories = [];
        foreach ($result['dangerous_classes'] as $dc) {
            if ($dc['level'] > $maxClassLevel) $maxClassLevel = $dc['level'];
            if (!in_array($dc['category'], $dangerousCategories)) $dangerousCategories[] = $dc['category'];
        }

        if ($maxClassLevel >= 5) { $score += 35; $indicators[] = 'critical_dangerous_class'; }
        elseif ($maxClassLevel >= 4) { $score += 25; $indicators[] = 'high_dangerous_class'; }
        elseif ($maxClassLevel >= 3) { $score += 15; $indicators[] = 'medium_dangerous_class'; }
        elseif ($maxClassLevel >= 2) { $score += 8; $indicators[] = 'low_dangerous_class'; }

        if (count($result['dangerous_classes']) >= 3) { $score += 15; $indicators[] = 'multiple_dangerous_classes'; }
        elseif (count($result['dangerous_classes']) >= 2) { $score += 10; $indicators[] = 'two_dangerous_classes'; }

        $magicMethodCount = count($result['magic_methods_in_classes']);
        if ($magicMethodCount >= 4) { $score += 25; $indicators[] = 'multiple_magic_methods'; }
        elseif ($magicMethodCount >= 2) { $score += 15; $indicators[] = 'several_magic_methods'; }
        elseif ($magicMethodCount >= 1) { $score += 8; $indicators[] = 'magic_method_present'; }

        $totalRefs = $parseResult['reference_count'] + $parseResult['reference_r_count'];
        if ($totalRefs >= 5) { $score += 18; $indicators[] = 'many_references'; }
        elseif ($totalRefs >= 3) { $score += 12; $indicators[] = 'multiple_references'; }
        elseif ($totalRefs > 0) { $score += 6; $indicators[] = 'reference_present'; }

        if (!empty($parseResult['long_strings'])) {
            if (count($parseResult['long_strings']) >= 3) { $score += 25; $indicators[] = 'many_long_strings'; }
            else { $score += 15; $indicators[] = 'long_string_dos'; }
        }

        if (!empty($parseResult['private_props']) || !empty($parseResult['protected_props'])) {
            $score += 10;
            $indicators[] = 'private_protected_props';
        }

        $anomalyCount = count($parseResult['length_anomalies']);
        if ($anomalyCount >= 3) { $score += 30; $indicators[] = 'multiple_length_anomalies'; }
        elseif ($anomalyCount >= 1) { $score += 20; $indicators[] = 'length_anomaly'; }

        if (!empty($result['pop_chain_indicators'])) {
            $popScore = 0;
            foreach ($result['pop_chain_indicators'] as $pc) {
                $popScore += isset($pc['level']) ? $pc['level'] * 5 : 10;
            }
            $score += min(35, $popScore);
            $indicators[] = 'pop_chain_detected';
        }

        if (!empty($result['string_escape_indicators'])) {
            $escapeScore = 0;
            foreach ($result['string_escape_indicators'] as $ef) {
                if ($ef['level'] >= 5) $escapeScore += 20;
                elseif ($ef['level'] >= 4) $escapeScore += 15;
                else $escapeScore += 8;
            }
            $score += min(30, $escapeScore);
            $indicators[] = 'string_escape_attempt';
        }

        $decodeDepth = $result['decode_depth'];
        if ($decodeDepth >= 3) { $score += 20; $indicators[] = 'multi_layer_encoding'; }
        elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
        elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

        if (in_array('rce', $dangerousCategories) && $objectCount >= 2) {
            $score += 15;
            $indicators[] = 'rce_class_chain';
        }

        if (!empty($result['chain_analysis']) && isset($result['chain_analysis']['dangerous_chain'])) {
            $score += 10;
            $indicators[] = 'dangerous_class_chain_detected';
        }

        $propValueAnalysis = $result['prop_values_analysis'];
        $hasSensitiveValue = false;
        foreach ($propValueAnalysis as $pv) {
            if (isset($pv['has_code_exec']) || isset($pv['has_sensitive_path']) || isset($pv['has_php_scheme'])) {
                $hasSensitiveValue = true;
                break;
            }
        }
        if ($hasSensitiveValue) {
            $score += 15;
            $indicators[] = 'sensitive_property_value';
        }

        if (!$parseResult['is_valid'] && $parseResult['partial_match']) {
            $score += 5;
            $indicators[] = 'malformed_structure';
        }

        $result['score'] = min(100, $score);
        $result['indicators'] = $indicators;

        $riskLevel = 'low';
        if ($result['score'] >= 75) $riskLevel = 'critical';
        elseif ($result['score'] >= 55) $riskLevel = 'high';
        elseif ($result['score'] >= 30) $riskLevel = 'medium';
        $result['risk_level'] = $riskLevel;

        return $result;
    }

    private static function checkDangerousClasses(array $classNames): array {
        $dangerous = [];
        $found = [];

        foreach ($classNames as $className) {
            if (isset($found[$className])) continue;
            $found[$className] = true;

            if (isset(self::$dangerousClasses[$className])) {
                $info = self::$dangerousClasses[$className];
                $dangerous[] = ['class' => $className, 'level' => $info['level'], 'desc' => $info['desc'], 'category' => $info['category']];
            } else {
                foreach (self::$dangerousClasses as $knownClass => $info) {
                    if (stripos($className, $knownClass) !== false || stripos($knownClass, $className) !== false) {
                        if (strlen($className) > 2 && strlen($knownClass) > 2) {
                            $dangerous[] = ['class' => $className, 'level' => max(1, $info['level'] - 2), 'desc' => '疑似危险类: ' . $info['desc'], 'category' => $info['category'], 'similar_to' => $knownClass];
                            break;
                        }
                    }
                }

                if (strpos($className, '\\') !== false) {
                    $parts = explode('\\', $className);
                    $shortName = end($parts);
                    if (isset(self::$dangerousClasses[$shortName])) {
                        $info = self::$dangerousClasses[$shortName];
                        $dangerous[] = ['class' => $className, 'level' => $info['level'], 'desc' => $info['desc'] . ' (命名空间)', 'category' => $info['category'], 'namespace' => true];
                    }
                }
            }
        }

        usort($dangerous, function($a, $b) { return $b['level'] - $a['level']; });
        return $dangerous;
    }

    private static function detectMagicMethodsInClasses(array $classNames): array {
        $found = [];
        $tracked = [];

        foreach ($classNames as $className) {
            $lowerClass = strtolower($className);
            foreach (self::$magicMethods as $method => $info) {
                $key = $method . '|' . $className;
                if (isset($tracked[$key])) continue;
                $tracked[$key] = true;

                $classMethodMap = [
                    'soapclient' => ['__call'],
                    'directoryiterator' => ['__toString'],
                    'globiterator' => ['__toString'],
                    'splfileobject' => ['__toString'],
                    'exception' => ['__destruct', '__toString'],
                    'error' => ['__destruct'],
                ];

                if (isset($classMethodMap[$lowerClass]) && in_array($method, $classMethodMap[$lowerClass])) {
                    $found[] = ['class' => $className, 'method' => $method, 'level' => $info['level'], 'desc' => $info['desc'], 'trigger' => $info['trigger'], 'confirmed' => true];
                }
            }
        }

        if (!empty($classNames)) {
            foreach (self::$magicMethods as $method => $info) {
                if (in_array($method, ['__destruct', '__wakeup'])) {
                    $key = $method . '|*potential*';
                    if (!isset($tracked[$key])) {
                        $tracked[$key] = true;
                        $found[] = ['class' => '(potential)', 'method' => $method, 'level' => max(1, $info['level'] - 3), 'desc' => '潜在魔法方法触发 - ' . $info['desc'], 'trigger' => $info['trigger'], 'confirmed' => false];
                    }
                }
            }
        }

        usort($found, function($a, $b) { return $b['level'] - $a['level']; });
        return $found;
    }

    private static function detectPopChainFeatures(array $parseResult): array {
        $features = [];
        $classes = $parseResult['all_classes'];

        foreach (self::$popChainSignatures as $signature => $info) {
            $matchCount = 0;
            foreach ($info['pattern'] as $patternClass) {
                foreach ($classes as $className) {
                    if (stripos($className, $patternClass) !== false) {
                        $matchCount++;
                        break;
                    }
                }
            }

            if ($matchCount >= count($info['pattern'])) {
                $features[] = ['name' => $signature, 'level' => $info['level'], 'desc' => $info['desc'], 'trigger' => $info['trigger']];
            }
        }

        $objectCount = $parseResult['object_count'];
        if ($objectCount >= 2) $features[] = ['name' => 'multiple_objects', 'level' => 2, 'desc' => '多个对象 - POP链基础特征'];

        if ($objectCount >= 2 && $parseResult['max_depth'] >= 3) {
            $features[] = ['name' => 'nested_object_chain', 'level' => 3, 'desc' => '嵌套对象结构 - POP链构造特征'];
        }

        if (($parseResult['reference_count'] > 0 || $parseResult['reference_r_count'] > 0) && $objectCount >= 2) {
            $features[] = ['name' => 'object_references', 'level' => 3, 'desc' => '对象引用 - POP链指针操作'];
        }

        $dangerousCount = count(self::checkDangerousClasses($classes));
        if ($dangerousCount >= 2) {
            $features[] = ['name' => 'multi_dangerous_classes', 'level' => 4, 'desc' => '多危险类组合 - 完整POP链'];
        }

        if ($parseResult['array_count'] >= 2 && $objectCount >= 2) {
            $features[] = ['name' => 'array_object_mix', 'level' => 2, 'desc' => '数组对象混合 - 复杂利用链'];
        }

        return $features;
    }

    private static function detectStringEscapeFeatures(array $parseResult): array {
        $found = [];
        $data = $parseResult['data'] ?? '';

        $hasAnomaly = !empty($parseResult['length_anomalies']) || !empty($parseResult['errors']) || !$parseResult['is_valid'];

        if ($hasAnomaly && $data) {
            foreach (self::$stringEscapePatterns as $key => $info) {
                if (preg_match($info['pattern'], $data)) {
                    $found[] = ['key' => $key, 'level' => $info['level'], 'desc' => $info['desc']];
                }
            }
        }

        return $found;
    }

    // ==================== Regex Fallback ====================

    private static function regexFallback(string $data, array $baseResult): array {
        $result = $baseResult;

        $structure = self::parseSerializedStructureRegex($data);

        if ($structure['is_valid'] || $structure['partial_match']) {
            $result['is_deserialization'] = true;
            $result['structure_valid'] = $structure['is_valid'];
            $result['partial_match'] = $structure['partial_match'];

            $result['object_count'] = $structure['object_count'];
            $result['array_count'] = $structure['array_count'];
            $result['string_count'] = $structure['string_count'];
            $result['integer_count'] = $structure['integer_count'];
            $result['bool_count'] = $structure['bool_count'];
            $result['float_count'] = $structure['float_count'];
            $result['null_count'] = $structure['null_count'];
            $result['reference_count'] = $structure['reference_count'];
            $result['reference_r_count'] = $structure['reference_r_count'];

            $result['max_nesting_depth'] = $structure['max_depth'];
            $result['dangerous_classes'] = $structure['dangerous_classes'];
            $result['all_classes'] = $structure['all_classes'];
            $result['magic_methods_in_classes'] = self::detectMagicMethodsInClasses($structure['all_classes']);
            $result['length_anomalies'] = $structure['length_anomalies'];

            $popChainFeatures = self::detectPopChainFeatures($structure);
            $result['pop_chain_indicators'] = $popChainFeatures;
            $result['has_pop_chain'] = !empty($popChainFeatures);

            $escapeFeatures = self::detectStringEscapeFeatures($structure);
            $result['string_escape_indicators'] = $escapeFeatures;

            $indicators = [];
            $score = 0;

            $objectCount = $structure['object_count'];
            if ($objectCount >= 5) { $score += 20; $indicators[] = 'multiple_objects'; }
            elseif ($objectCount >= 3) { $score += 12; $indicators[] = 'several_objects'; }
            elseif ($objectCount >= 2) { $score += 7; $indicators[] = 'two_objects'; }
            elseif ($objectCount >= 1) { $score += 3; $indicators[] = 'single_object'; }

            $maxDepth = $structure['max_depth'];
            if ($maxDepth >= 10) { $score += 25; $indicators[] = 'extreme_nesting'; }
            elseif ($maxDepth >= 6) { $score += 18; $indicators[] = 'deep_nesting'; }
            elseif ($maxDepth >= 4) { $score += 10; $indicators[] = 'moderate_nesting'; }
            elseif ($maxDepth >= 2) { $score += 4; $indicators[] = 'light_nesting'; }

            $maxClassLevel = 0;
            foreach ($structure['dangerous_classes'] as $dc) {
                if ($dc['level'] > $maxClassLevel) $maxClassLevel = $dc['level'];
            }
            if ($maxClassLevel >= 5) { $score += 35; $indicators[] = 'critical_dangerous_class'; }
            elseif ($maxClassLevel >= 4) { $score += 25; $indicators[] = 'high_dangerous_class'; }
            elseif ($maxClassLevel >= 3) { $score += 15; $indicators[] = 'medium_dangerous_class'; }
            elseif ($maxClassLevel >= 2) { $score += 8; $indicators[] = 'low_dangerous_class'; }

            if (count($structure['dangerous_classes']) >= 3) { $score += 15; $indicators[] = 'multiple_dangerous_classes'; }
            elseif (count($structure['dangerous_classes']) >= 2) { $score += 10; $indicators[] = 'two_dangerous_classes'; }

            $magicMethodCount = count($result['magic_methods_in_classes']);
            if ($magicMethodCount >= 4) { $score += 25; $indicators[] = 'multiple_magic_methods'; }
            elseif ($magicMethodCount >= 2) { $score += 15; $indicators[] = 'several_magic_methods'; }
            elseif ($magicMethodCount >= 1) { $score += 8; $indicators[] = 'magic_method_present'; }

            $totalRefs = $structure['reference_count'] + $structure['reference_r_count'];
            if ($totalRefs >= 5) { $score += 18; $indicators[] = 'many_references'; }
            elseif ($totalRefs >= 3) { $score += 12; $indicators[] = 'multiple_references'; }
            elseif ($totalRefs > 0) { $score += 6; $indicators[] = 'reference_present'; }

            $anomalyCount = count($structure['length_anomalies']);
            if ($anomalyCount >= 3) { $score += 30; $indicators[] = 'multiple_length_anomalies'; }
            elseif ($anomalyCount >= 1) { $score += 20; $indicators[] = 'length_anomaly'; }

            if (!empty($popChainFeatures)) {
                $popScore = 0;
                foreach ($popChainFeatures as $pc) {
                    $popScore += isset($pc['level']) ? $pc['level'] * 5 : 10;
                }
                $score += min(35, $popScore);
                $indicators[] = 'pop_chain_detected';
            }

            if (!empty($escapeFeatures)) {
                $escapeScore = 0;
                foreach ($escapeFeatures as $ef) {
                    if ($ef['level'] >= 5) $escapeScore += 20;
                    elseif ($ef['level'] >= 4) $escapeScore += 15;
                    else $escapeScore += 8;
                }
                $score += min(30, $escapeScore);
                $indicators[] = 'string_escape_attempt';
            }

            $decodeDepth = $result['decode_depth'];
            if ($decodeDepth >= 3) { $score += 20; $indicators[] = 'multi_layer_encoding'; }
            elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
            elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

            $result['score'] = min(100, $score);
            $result['indicators'] = $indicators;

            $riskLevel = 'low';
            if ($result['score'] >= 75) $riskLevel = 'critical';
            elseif ($result['score'] >= 55) $riskLevel = 'high';
            elseif ($result['score'] >= 30) $riskLevel = 'medium';
            $result['risk_level'] = $riskLevel;

            $result['structure_tree'] = $structure['tree'];
        } else {
            $regexIndicators = self::regexQuickScan($data);
            if (!empty($regexIndicators)) {
                $result['is_deserialization'] = true;
                $result['score'] = 25;
                $result['risk_level'] = 'low';
                $result['indicators'] = ['regex_match'];
            }
        }

        return $result;
    }

    private static function parseSerializedStructureRegex(string $data): array {
        $result = [
            'is_valid' => false, 'partial_match' => false, 'errors' => [],
            'object_count' => 0, 'array_count' => 0, 'string_count' => 0,
            'integer_count' => 0, 'bool_count' => 0, 'float_count' => 0,
            'null_count' => 0, 'reference_count' => 0, 'reference_r_count' => 0,
            'max_depth' => 0, 'dangerous_classes' => [], 'all_classes' => [],
            'length_anomalies' => [], 'tree' => null,
        ];

        $data = trim($data);
        if ($data === '') {
            $result['errors'][] = 'empty_input';
            return $result;
        }

        $offset = 0;
        $depth = 0;
        $maxDepth = 0;

        $parsed = self::parseValueRegex($data, $offset, $depth, $maxDepth, $result);

        $result['max_depth'] = $maxDepth;

        $trimmed = trim(substr($data, $offset));
        if (($offset >= strlen($data) || $trimmed === '') && $parsed !== null && empty($result['errors'])) {
            $result['is_valid'] = true;
        } else {
            if ($parsed !== null) {
                $result['partial_match'] = true;
            } else {
                if (preg_match('/^[OaSidbNRrC]:/', $data)) {
                    $result['partial_match'] = true;
                }
            }
        }

        if ($parsed !== null) $result['tree'] = $parsed;
        $result['dangerous_classes'] = self::checkDangerousClasses($result['all_classes']);

        return $result;
    }

    private static function parseValueRegex(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length) return null;

        if ($depth > $maxDepth) $maxDepth = $depth;

        $type = $data[$offset];
        $offset++;

        switch ($type) {
            case 'i': return self::parseIntegerRegex($data, $offset, $result);
            case 'b': return self::parseBoolRegex($data, $offset, $result);
            case 'd': return self::parseFloatRegex($data, $offset, $result);
            case 's': return self::parseStringRegex($data, $offset, $result);
            case 'a': return self::parseArrayRegex($data, $offset, $depth, $maxDepth, $result);
            case 'O': return self::parseObjectRegex($data, $offset, $depth, $maxDepth, $result);
            case 'N': return self::parseNullRegex($data, $offset, $result);
            case 'R': return self::parseReferenceRegex($data, $offset, $result, 'R');
            case 'r': return self::parseReferenceRegex($data, $offset, $result, 'r');
            case 'C': return self::parseCustomObjectRegex($data, $offset, $depth, $maxDepth, $result);
            default:
                $result['errors'][] = 'unknown_type_' . $type;
                return null;
        }
    }

    private static function parseIntegerRegex(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'integer_missing_colon';
            return null;
        }
        $offset++;

        $start = $offset;
        while ($offset < $length && $data[$offset] !== ';') $offset++;

        if ($offset >= $length) {
            $result['errors'][] = 'integer_unterminated';
            return null;
        }

        $valueStr = substr($data, $start, $offset - $start);
        $offset++;

        if (!preg_match('/^-?\d+$/', $valueStr)) {
            $result['errors'][] = 'invalid_integer_value';
            return null;
        }

        $result['integer_count']++;
        return ['type' => 'integer', 'value' => (int)$valueStr];
    }

    private static function parseBoolRegex(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'bool_missing_colon';
            return null;
        }
        $offset++;

        if ($offset >= $length) {
            $result['errors'][] = 'bool_unterminated';
            return null;
        }

        $value = $data[$offset];
        $offset++;

        if ($offset >= $length || $data[$offset] !== ';') {
            $result['errors'][] = 'bool_missing_semicolon';
            return null;
        }
        $offset++;

        if ($value !== '0' && $value !== '1') {
            $result['errors'][] = 'invalid_bool_value';
            return null;
        }

        $result['bool_count']++;
        return ['type' => 'bool', 'value' => $value === '1'];
    }

    private static function parseFloatRegex(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'float_missing_colon';
            return null;
        }
        $offset++;

        $start = $offset;
        while ($offset < $length && $data[$offset] !== ';') $offset++;

        if ($offset >= $length) {
            $result['errors'][] = 'float_unterminated';
            return null;
        }

        $valueStr = substr($data, $start, $offset - $start);
        $offset++;

        if (!preg_match('/^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?|INF|NAN$/', $valueStr)) {
            $result['errors'][] = 'invalid_float_value';
            return null;
        }

        $result['float_count']++;
        return ['type' => 'float', 'value' => (float)$valueStr];
    }

    private static function parseStringRegex(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'string_missing_colon';
            return null;
        }
        $offset++;

        $lenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'string_length_invalid_char';
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'string_length_unterminated';
            return null;
        }

        $declaredLength = (int)substr($data, $lenStart, $offset - $lenStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'string_missing_opening_quote';
            return null;
        }
        $offset++;

        $stringStart = $offset;
        $offset += $declaredLength;

        $stringValue = substr($data, $stringStart, $declaredLength);

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'string_missing_closing_quote';
            return null;
        }
        $offset++;

        if ($offset >= $length || $data[$offset] !== ';') {
            $result['errors'][] = 'string_missing_semicolon';
            return null;
        }
        $offset++;

        $realByteCount = strlen($stringValue);
        if ($realByteCount !== $declaredLength) {
            $result['length_anomalies'][] = ['type' => 'length_mismatch', 'declared' => $declaredLength, 'actual' => $realByteCount];
        }

        $result['string_count']++;
        return ['type' => 'string', 'value' => $stringValue, 'declared_length' => $declaredLength, 'actual_length' => $realByteCount];
    }

    private static function parseArrayRegex(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'array_missing_colon';
            return null;
        }
        $offset++;

        $countStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'array_count_invalid_char';
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'array_count_unterminated';
            return null;
        }

        $elementCount = (int)substr($data, $countStart, $offset - $countStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '{') {
            $result['errors'][] = 'array_missing_opening_brace';
            return null;
        }
        $offset++;

        $result['array_count']++;
        $elements = [];

        for ($i = 0; $i < $elementCount; $i++) {
            if ($offset >= $length || $data[$offset] === '}') break;
            $key = self::parseValueRegex($data, $offset, $depth + 1, $maxDepth, $result);
            if ($key === null) break;
            $value = self::parseValueRegex($data, $offset, $depth + 1, $maxDepth, $result);
            if ($value === null) break;
            $elements[] = ['key' => $key, 'value' => $value];
        }

        if ($offset < $length && $data[$offset] === '}') $offset++;
        else $result['errors'][] = 'array_missing_closing_brace';

        return ['type' => 'array', 'size' => $elementCount, 'elements' => $elements, 'depth' => $depth];
    }

    private static function parseObjectRegex(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'object_missing_colon';
            return null;
        }
        $offset++;

        $nameLenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'object_namelength_invalid_char';
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'object_namelength_unterminated';
            return null;
        }

        $nameLength = (int)substr($data, $nameLenStart, $offset - $nameLenStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'object_missing_name_opening_quote';
            return null;
        }
        $offset++;

        $className = substr($data, $offset, $nameLength);
        $offset += $nameLength;

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'object_missing_name_closing_quote';
            return null;
        }
        $offset++;

        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'object_missing_colon_after_name';
            return null;
        }
        $offset++;

        $propCountStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'object_propcount_invalid_char';
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'object_propcount_unterminated';
            return null;
        }

        $propertyCount = (int)substr($data, $propCountStart, $offset - $propCountStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '{') {
            $result['errors'][] = 'object_missing_opening_brace';
            return null;
        }
        $offset++;

        $result['object_count']++;
        $result['all_classes'][] = $className;

        $properties = [];

        for ($i = 0; $i < $propertyCount; $i++) {
            if ($offset >= $length || $data[$offset] === '}') break;
            $propName = self::parseValueRegex($data, $offset, $depth + 1, $maxDepth, $result);
            if ($propName === null) break;
            $propValue = self::parseValueRegex($data, $offset, $depth + 1, $maxDepth, $result);
            if ($propValue === null) break;
            $properties[] = ['name' => $propName, 'value' => $propValue];
        }

        if ($offset < $length && $data[$offset] === '}') $offset++;
        else $result['errors'][] = 'object_missing_closing_brace';

        return ['type' => 'object', 'class' => $className, 'props' => $propertyCount, 'properties' => $properties, 'depth' => $depth];
    }

    private static function parseNullRegex(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ';') {
            $result['errors'][] = 'null_missing_semicolon';
            return null;
        }
        $offset++;

        $result['null_count']++;
        return ['type' => 'null', 'value' => null];
    }

    private static function parseReferenceRegex(string $data, int &$offset, array &$result, string $refType) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'reference_missing_colon';
            return null;
        }
        $offset++;

        $start = $offset;
        while ($offset < $length && $data[$offset] !== ';') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'reference_invalid_char';
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'reference_unterminated';
            return null;
        }

        $refValue = (int)substr($data, $start, $offset - $start);
        $offset++;

        if ($refType === 'R') $result['reference_count']++;
        else $result['reference_r_count']++;

        return ['type' => 'reference', 'ref_type' => $refType, 'ref_index' => $refValue];
    }

    private static function parseCustomObjectRegex(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') return null;
        $offset++;

        $nameLenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) return null;
            $offset++;
        }
        if ($offset >= $length) return null;

        $nameLen = (int)substr($data, $nameLenStart, $offset - $nameLenStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '"') return null;
        $offset++;

        $className = substr($data, $offset, $nameLen);
        $offset += $nameLen;

        if ($offset >= $length || $data[$offset] !== '"') return null;
        $offset++;

        if ($offset >= $length || $data[$offset] !== ':') return null;
        $offset++;

        $dataLenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) return null;
            $offset++;
        }
        if ($offset >= $length) return null;

        $dataLen = (int)substr($data, $dataLenStart, $offset - $dataLenStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '{') return null;
        $offset++;

        $result['object_count']++;
        $result['all_classes'][] = $className;

        $customData = substr($data, $offset, min($dataLen, $length - $offset));
        $offset += $dataLen;

        if ($offset < $length && $data[$offset] === '}') $offset++;

        return ['type' => 'custom_object', 'class' => $className, 'data' => $customData, 'depth' => $depth];
    }

    private static function regexQuickScan(string $data): array {
        $indicators = [];

        if (preg_match('/O:\d+:"[A-Za-z_][\w]*"/', $data)) $indicators[] = 'object_found';
        if (preg_match('/a:\d+:{/', $data)) $indicators[] = 'array_found';
        if (preg_match('/R:\d+;/', $data)) $indicators[] = 'reference_found';
        if (preg_match('/r:\d+;/', $data)) $indicators[] = 'reference_r_found';

        $dangerousPattern = '/O:\d+:"(SoapClient|DirectoryIterator|GlobIterator|SplFileObject|SimpleXMLElement|ReflectionClass|PHar)"/i';
        if (preg_match($dangerousPattern, $data)) $indicators[] = 'dangerous_class';

        return $indicators;
    }
}