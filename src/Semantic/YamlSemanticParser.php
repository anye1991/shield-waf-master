<?php
/**
 * YAML 反序列化语义解析器（AST版）
 * 职责：通过 Tokenizer + Parser 构建 YAML 文档 AST，
 *       深度识别 YAML 反序列化漏洞攻击特征，包括危险标签检测、
 *       对象注入检测、锚点别名滥用（Billion Laughs）、嵌套深度分析、
 *       敏感配置键检测、常见 gadget 类识别等。
 */
defined('ABSPATH') || exit;

class YamlSemanticParser {

    // ==================== Token Types ====================
    const TOKEN_DOC_START     = 'DOC_START';
    const TOKEN_DOC_END       = 'DOC_END';
    const TOKEN_INDENT        = 'INDENT';
    const TOKEN_DEDENT        = 'DEDENT';
    const TOKEN_NEWLINE       = 'NEWLINE';
    const TOKEN_MAPPING_KEY   = 'MAPPING_KEY';
    const TOKEN_SEQUENCE_ITEM = 'SEQUENCE_ITEM';
    const TOKEN_SCALAR        = 'SCALAR';
    const TOKEN_SINGLE_QUOTED = 'SINGLE_QUOTED';
    const TOKEN_DOUBLE_QUOTED = 'DOUBLE_QUOTED';
    const TOKEN_LITERAL_BLOCK = 'LITERAL_BLOCK';
    const TOKEN_FOLDED_BLOCK  = 'FOLDED_BLOCK';
    const TOKEN_TAG           = 'TAG';
    const TOKEN_ANCHOR        = 'ANCHOR';
    const TOKEN_ALIAS         = 'ALIAS';
    const TOKEN_FLOW_MAP_START = 'FLOW_MAP_START';
    const TOKEN_FLOW_MAP_END   = 'FLOW_MAP_END';
    const TOKEN_FLOW_SEQ_START = 'FLOW_SEQ_START';
    const TOKEN_FLOW_SEQ_END   = 'FLOW_SEQ_END';
    const TOKEN_FLOW_COMMA     = 'FLOW_COMMA';
    const TOKEN_COMMENT       = 'COMMENT';
    const TOKEN_DIRECTIVE     = 'DIRECTIVE';
    const TOKEN_INDICATOR     = 'INDICATOR';
    const TOKEN_MERGE_KEY     = 'MERGE_KEY';
    const TOKEN_EOF           = 'EOF';

    // ==================== Dangerous Tags ====================
    private static $dangerousTags = [
        '!!php/object'           => ['level' => 5, 'desc' => 'PHP对象注入', 'category' => 'php_object'],
        '!php/object'            => ['level' => 5, 'desc' => 'PHP对象注入', 'category' => 'php_object'],
        '!!php/object:serialize' => ['level' => 5, 'desc' => 'PHP序列化对象注入', 'category' => 'php_object'],
        '!!python/object'        => ['level' => 5, 'desc' => 'Python对象注入', 'category' => 'python_object'],
        '!!python/object/apply'  => ['level' => 5, 'desc' => 'Python对象执行', 'category' => 'python_object'],
        '!!python/object/new'    => ['level' => 5, 'desc' => 'Python对象创建', 'category' => 'python_object'],
        '!!python/object/gen'    => ['level' => 4, 'desc' => 'Python生成器', 'category' => 'python_object'],
        '!ruby/object'           => ['level' => 5, 'desc' => 'Ruby对象注入', 'category' => 'ruby_object'],
        '!!ruby/object'          => ['level' => 5, 'desc' => 'Ruby对象注入', 'category' => 'ruby_object'],
        '!!java/object'          => ['level' => 5, 'desc' => 'Java反序列化', 'category' => 'java_object'],
        '!java/object'           => ['level' => 5, 'desc' => 'Java反序列化', 'category' => 'java_object'],
        '!!binary'               => ['level' => 3, 'desc' => '二进制数据', 'category' => 'binary'],
        '!!set'                  => ['level' => 2, 'desc' => '集合类型', 'category' => 'complex'],
        '!!omap'                 => ['level' => 2, 'desc' => '有序映射', 'category' => 'complex'],
        '!!pairs'                => ['level' => 2, 'desc' => '键值对列表', 'category' => 'complex'],
    ];

    // ==================== Sensitive Keys ====================
    private static $sensitiveKeys = [
        'exec', 'execute', 'command', 'cmd', 'shell', 'system', 'passthru',
        'code', 'eval', 'assert', 'create_function', 'call_user_func',
        'unserialize', 'deserialize', 'load', 'dump', 'import', 'include',
        'require', 'file_get_contents', 'file_put_contents', 'readfile',
        'popen', 'proc_open', 'pcntl_exec', 'shell_exec', 'phpinfo',
        'ini_set', 'ini_get', 'set_include_path', 'get_include_path',
        'rmi', 'ldap', 'jndi', 'rmi://', 'ldap://', 'dns://',
    ];

    // ==================== Gadget Classes ====================
    private static $gadgetClasses = [
        // Symfony
        'Symfony\Component\Process\Process' => ['level' => 5, 'framework' => 'Symfony'],
        'Symfony\Component\Process\InputStream' => ['level' => 4, 'framework' => 'Symfony'],
        'Symfony\Component\Cache\Adapter\AbstractAdapter' => ['level' => 4, 'framework' => 'Symfony'],
        'Symfony\Component\Cache\Adapter\PhpArrayAdapter' => ['level' => 4, 'framework' => 'Symfony'],
        'Symfony\Component\Finder\Finder' => ['level' => 3, 'framework' => 'Symfony'],
        // Laravel
        'Illuminate\Broadcasting\PendingBroadcast' => ['level' => 5, 'framework' => 'Laravel'],
        'Illuminate\Database\Eloquent\Dispatcher' => ['level' => 4, 'framework' => 'Laravel'],
        'Illuminate\Support\Manager' => ['level' => 4, 'framework' => 'Laravel'],
        'Illuminate\View\AppView' => ['level' => 4, 'framework' => 'Laravel'],
        // WordPress
        'WP_HTML_Tag_Processor' => ['level' => 3, 'framework' => 'WordPress'],
        // Monolog
        'Monolog\Handler\SyslogUdpHandler' => ['level' => 4, 'framework' => 'Monolog'],
        'Monolog\Handler\BufferHandler' => ['level' => 3, 'framework' => 'Monolog'],
        // Guzzle
        'GuzzleHttp\Psr7\FnStream' => ['level' => 4, 'framework' => 'Guzzle'],
        'GuzzleHttp\HandlerStack' => ['level' => 3, 'framework' => 'Guzzle'],
        // Swift Mailer
        'Swift_Mailer' => ['level' => 3, 'framework' => 'SwiftMailer'],
        'Swift_Transport_EsmtpTransport' => ['level' => 4, 'framework' => 'SwiftMailer'],
        // PHPSecLib
        'phpseclib\Crypt\RSA' => ['level' => 4, 'framework' => 'PHPSecLib'],
        // TCPDF
        'TCPDF' => ['level' => 3, 'framework' => 'TCPDF'],
        // Doctrine
        'Doctrine\Common\Collections\ArrayCollection' => ['level' => 3, 'framework' => 'Doctrine'],
    ];

    // ==================== Main Entry ====================

    /**
     * 主入口：分析 YAML 输入
     *
     * @param string $input
     * @return array
     */
    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if (trim($input) === '') {
            return $result;
        }

        $originalInput = $input;
        $result['total_length'] = strlen($input);

        try {
            $isYaml = self::detectYaml($input);
            $result['is_yaml'] = $isYaml;

            if (!$isYaml) {
                $regexResult = self::regexFallback($input, $result);
                return $regexResult;
            }

            $yamlExtResult = null;
            if (function_exists('yaml_parse')) {
                $yamlExtResult = self::tryYamlExtension($input);
            }

            $tokens = self::tokenize($input);
            $result['token_count'] = count($tokens);

            $parseResult = self::parseWithAst($tokens, $input);

            if ($parseResult !== null) {
                $result = array_merge($result, self::mapAstResult($parseResult));
                $result['parser_used'] = 'ast';

                if (!empty($parseResult['ast'])) {
                    $result['ast_summary'] = self::summarizeAst($parseResult['ast']);
                }

                $result = self::calculateRisk($result, $parseResult);
            } else {
                $result['parser_used'] = 'regex_fallback';
                $regexResult = self::regexFallback($input, $result);
                return $regexResult;
            }

            if ($yamlExtResult !== null) {
                $result['yaml_ext_parsed'] = $yamlExtResult['parsed'];
                if (!empty($yamlExtResult['dangerous_tags'])) {
                    $result['has_dangerous_tags'] = true;
                    $result['dangerous_tags'] = array_unique(array_merge(
                        $result['dangerous_tags'],
                        $yamlExtResult['dangerous_tags']
                    ));
                }
            }

        } catch (Exception $e) {
            $result['parser_used'] = 'regex_fallback';
            $result['parse_errors'][] = 'ast_parser_exception: ' . $e->getMessage();
            $regexResult = self::regexFallback($input, $result);
            return $regexResult;
        }

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'               => 0,
            'risk_level'          => 'clean',
            'is_yaml'             => false,
            'document_count'      => 0,
            'mapping_count'       => 0,
            'sequence_count'      => 0,
            'nesting_depth'       => 0,
            'has_dangerous_tags'  => false,
            'dangerous_tags'      => [],
            'has_php_object'      => false,
            'has_python_object'   => false,
            'has_ruby_object'     => false,
            'has_java_object'     => false,
            'sensitive_keys'      => [],
            'anchor_count'        => 0,
            'alias_count'         => 0,
            'has_billion_laughs'  => false,
            'gadget_classes'      => [],
            'ast_summary'         => [],
            'indicators'          => [],
            'parse_errors'        => [],
            'total_length'        => 0,
            'token_count'         => 0,
            'parser_used'         => 'none',
            'scalar_count'        => 0,
            'tag_count'           => 0,
        ];
    }

    // ==================== YAML Detection ====================

    private static function detectYaml(string $input): bool {
        $input = trim($input);
        if ($input === '') return false;

        if (strpos($input, '---') === 0) return true;

        if (preg_match('/^\s*#.*\n/', $input)) return true;

        if (preg_match('/^\s*[\w\-]+\s*:/m', $input)) return true;

        if (preg_match('/^\s*-\s+/m', $input)) return true;

        if (strpos($input, '!!') !== false) return true;

        return false;
    }

    // ==================== YAML Extension Fallback ====================

    private static function tryYamlExtension(string $input): ?array {
        $result = [
            'parsed' => false,
            'dangerous_tags' => [],
        ];

        $previous = ini_get('yaml.decode_php');
        ini_set('yaml.decode_php', '0');

        try {
            $parsed = @yaml_parse($input, 0, $count);
            if ($parsed !== false) {
                $result['parsed'] = true;
                $result['document_count'] = $count;
                self::walkParsedYaml($parsed, $result);
            }
        } catch (Exception $e) {
            // ignore
        }

        ini_set('yaml.decode_php', $previous);
        return $result;
    }

    private static function walkParsedYaml($data, array &$result, int $depth = 0) {
        if ($depth > 50) return;

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if (is_string($key)) {
                    if (self::isSensitiveKey($key)) {
                        $result['sensitive_keys'][] = $key;
                    }
                }
                self::walkParsedYaml($value, $result, $depth + 1);
            }
        } elseif (is_object($data)) {
            $className = get_class($data);
            if ($className) {
                $result['dangerous_tags'][] = 'object:' . $className;
            }
        } elseif (is_string($data)) {
            if (self::containsDangerousTagPattern($data)) {
                $result['dangerous_tags'][] = $data;
            }
        }
    }

    // ==================== Tokenizer ====================

    /**
     * YAML 词法分析
     *
     * @param string $input
     * @return array
     */
    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);
        $line = 1;
        $column = 0;
        $indentStack = [0];
        $inBlockScalar = false;
        $blockScalarIndent = 0;
        $blockScalarType = '';

        while ($pos < $len) {
            $char = $input[$pos];
            $lineStart = $pos;
            $currentIndent = 0;

            if (!$inBlockScalar && ($char === ' ' || $char === "\t")) {
                while ($pos < $len && ($input[$pos] === ' ' || $input[$pos] === "\t")) {
                    $currentIndent++;
                    $pos++;
                    $column++;
                }
                if ($pos < $len && $input[$pos] === "\n") {
                    $pos++;
                    $line++;
                    $column = 0;
                    continue;
                }
                if ($pos >= $len) break;
                $char = $input[$pos];

                if ($char === '#') {
                    $start = $pos;
                    while ($pos < $len && $input[$pos] !== "\n") {
                        $pos++;
                    }
                    $tokens[] = [
                        'type'   => self::TOKEN_COMMENT,
                        'value'  => substr($input, $start, $pos - $start),
                        'line'   => $line,
                        'column' => $column,
                    ];
                    continue;
                }

                if ($currentIndent > end($indentStack)) {
                    $indentStack[] = $currentIndent;
                    $tokens[] = [
                        'type'   => self::TOKEN_INDENT,
                        'value'  => $currentIndent,
                        'line'   => $line,
                        'column' => $column,
                    ];
                } elseif ($currentIndent < end($indentStack)) {
                    while ($indentStack && $currentIndent < end($indentStack)) {
                        array_pop($indentStack);
                        $tokens[] = [
                            'type'   => self::TOKEN_DEDENT,
                            'value'  => $currentIndent,
                            'line'   => $line,
                            'column' => $column,
                        ];
                    }
                }
            }

            if ($inBlockScalar) {
                $lineContent = '';
                $startPos = $pos;
                while ($pos < $len && $input[$pos] !== "\n") {
                    $lineContent .= $input[$pos];
                    $pos++;
                    $column++;
                }
                $lineIndent = 0;
                $trimmed = ltrim($lineContent, " \t");
                $lineIndent = strlen($lineContent) - strlen($trimmed);

                if ($pos < $len) {
                    $pos++;
                    $line++;
                    $column = 0;
                }

                $nextLineIndent = self::peekNextLineIndent($input, $pos);

                if ($lineIndent >= $blockScalarIndent || trim($lineContent) === '') {
                    if ($trimmed !== '' || $pos < $len) {
                        continue;
                    }
                }

                $endPos = $pos;
                $scalarValue = substr($input, $startPos - 1, $endPos - $startPos + 1);
                $inBlockScalar = false;
                continue;
            }

            if ($char === "\n") {
                $tokens[] = [
                    'type'   => self::TOKEN_NEWLINE,
                    'value'  => "\n",
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $line++;
                $column = 0;
                continue;
            }

            if ($char === '%') {
                $start = $pos;
                while ($pos < $len && $input[$pos] !== "\n") {
                    $pos++;
                }
                $tokens[] = [
                    'type'   => self::TOKEN_DIRECTIVE,
                    'value'  => substr($input, $start, $pos - $start),
                    'line'   => $line,
                    'column' => $column,
                ];
                continue;
            }

            if ($char === '-' && $pos + 2 < $len &&
                $input[$pos + 1] === '-' && $input[$pos + 2] === '-') {
                $tokens[] = [
                    'type'   => self::TOKEN_DOC_START,
                    'value'  => '---',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos += 3;
                $column += 3;
                continue;
            }

            if ($char === '.' && $pos + 2 < $len &&
                $input[$pos + 1] === '.' && $input[$pos + 2] === '.') {
                $tokens[] = [
                    'type'   => self::TOKEN_DOC_END,
                    'value'  => '...',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos += 3;
                $column += 3;
                continue;
            }

            if ($char === '<' && $pos + 1 < $len && $input[$pos + 1] === '<') {
                $tokens[] = [
                    'type'   => self::TOKEN_MERGE_KEY,
                    'value'  => '<<',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos += 2;
                $column += 2;
                continue;
            }

            if ($char === '-' && ($pos + 1 < $len && $input[$pos + 1] === ' ')) {
                $tokens[] = [
                    'type'   => self::TOKEN_SEQUENCE_ITEM,
                    'value'  => '-',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            if ($char === '!' && !($pos + 1 < $len && $input[$pos + 1] === ' ')) {
                $start = $pos;
                $pos++;
                $column++;
                if ($pos < $len && $input[$pos] === '!') {
                    $pos++;
                    $column++;
                }
                while ($pos < $len && !ctype_space($input[$pos]) &&
                       !in_array($input[$pos], [':', '#', ',', '[', ']', '{', '}'])) {
                    $pos++;
                    $column++;
                }
                $tagValue = substr($input, $start, $pos - $start);
                $tokens[] = [
                    'type'   => self::TOKEN_TAG,
                    'value'  => $tagValue,
                    'line'   => $line,
                    'column' => $column,
                ];
                continue;
            }

            if ($char === '&') {
                $start = $pos;
                $pos++;
                $column++;
                while ($pos < $len && !ctype_space($input[$pos]) &&
                       !in_array($input[$pos], [':', '#', ',', '[', ']', '{', '}'])) {
                    $pos++;
                    $column++;
                }
                $anchorValue = substr($input, $start, $pos - $start);
                $tokens[] = [
                    'type'   => self::TOKEN_ANCHOR,
                    'value'  => $anchorValue,
                    'line'   => $line,
                    'column' => $column,
                ];
                continue;
            }

            if ($char === '*') {
                $start = $pos;
                $pos++;
                $column++;
                while ($pos < $len && !ctype_space($input[$pos]) &&
                       !in_array($input[$pos], [':', '#', ',', '[', ']', '{', '}'])) {
                    $pos++;
                    $column++;
                }
                $aliasValue = substr($input, $start, $pos - $start);
                $tokens[] = [
                    'type'   => self::TOKEN_ALIAS,
                    'value'  => $aliasValue,
                    'line'   => $line,
                    'column' => $column,
                ];
                continue;
            }

            if ($char === '{') {
                $tokens[] = [
                    'type'   => self::TOKEN_FLOW_MAP_START,
                    'value'  => '{',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            if ($char === '}') {
                $tokens[] = [
                    'type'   => self::TOKEN_FLOW_MAP_END,
                    'value'  => '}',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            if ($char === '[') {
                $tokens[] = [
                    'type'   => self::TOKEN_FLOW_SEQ_START,
                    'value'  => '[',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            if ($char === ']') {
                $tokens[] = [
                    'type'   => self::TOKEN_FLOW_SEQ_END,
                    'value'  => ']',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            if ($char === ',') {
                $tokens[] = [
                    'type'   => self::TOKEN_FLOW_COMMA,
                    'value'  => ',',
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            if ($char === "'") {
                $start = $pos;
                $pos++;
                $column++;
                $value = '';
                while ($pos < $len) {
                    if ($input[$pos] === "'") {
                        if ($pos + 1 < $len && $input[$pos + 1] === "'") {
                            $value .= "'";
                            $pos += 2;
                            $column += 2;
                        } else {
                            $pos++;
                            $column++;
                            break;
                        }
                    } elseif ($input[$pos] === "\n") {
                        $value .= "\n";
                        $pos++;
                        $line++;
                        $column = 0;
                    } else {
                        $value .= $input[$pos];
                        $pos++;
                        $column++;
                    }
                }
                $tokens[] = [
                    'type'    => self::TOKEN_SINGLE_QUOTED,
                    'value'   => $value,
                    'raw'     => substr($input, $start, $pos - $start),
                    'line'    => $line,
                    'column'  => $column,
                ];
                continue;
            }

            if ($char === '"') {
                $start = $pos;
                $pos++;
                $column++;
                $value = '';
                while ($pos < $len) {
                    if ($input[$pos] === '"') {
                        $pos++;
                        $column++;
                        break;
                    } elseif ($input[$pos] === '\\' && $pos + 1 < $len) {
                        $next = $input[$pos + 1];
                        switch ($next) {
                            case 'n': $value .= "\n"; break;
                            case 't': $value .= "\t"; break;
                            case 'r': $value .= "\r"; break;
                            case '\\': $value .= '\\'; break;
                            case '"': $value .= '"'; break;
                            case '0': $value .= "\0"; break;
                            case 'x':
                                if ($pos + 3 < $len) {
                                    $hex = substr($input, $pos + 2, 2);
                                    $value .= chr(hexdec($hex));
                                    $pos += 2;
                                    $column += 2;
                                }
                                break;
                            case 'u':
                                if ($pos + 5 < $len) {
                                    $hex = substr($input, $pos + 2, 4);
                                    $value .= self::unicodeChar($hex);
                                    $pos += 4;
                                    $column += 4;
                                }
                                break;
                            default:
                                $value .= $next;
                        }
                        $pos += 2;
                        $column += 2;
                    } elseif ($input[$pos] === "\n") {
                        $value .= "\n";
                        $pos++;
                        $line++;
                        $column = 0;
                    } else {
                        $value .= $input[$pos];
                        $pos++;
                        $column++;
                    }
                }
                $tokens[] = [
                    'type'    => self::TOKEN_DOUBLE_QUOTED,
                    'value'   => $value,
                    'raw'     => substr($input, $start, $pos - $start),
                    'line'    => $line,
                    'column'  => $column,
                ];
                continue;
            }

            if ($char === '|' || $char === '>') {
                $blockType = $char;
                $start = $pos;
                $pos++;
                $column++;

                $chomping = '';
                while ($pos < $len && in_array($input[$pos], ['+', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])) {
                    $chomping .= $input[$pos];
                    $pos++;
                    $column++;
                }

                $tokens[] = [
                    'type'    => $blockType === '|' ? self::TOKEN_LITERAL_BLOCK : self::TOKEN_FOLDED_BLOCK,
                    'value'   => $blockType . $chomping,
                    'line'    => $line,
                    'column'  => $column,
                ];

                if ($pos < $len && $input[$pos] === "\n") {
                    $pos++;
                    $line++;
                    $column = 0;
                }

                $blockScalarIndent = end($indentStack) + 2;
                $inBlockScalar = true;
                $blockScalarType = $blockType;
                continue;
            }

            if ($char === '#') {
                $start = $pos;
                while ($pos < $len && $input[$pos] !== "\n") {
                    $pos++;
                }
                $tokens[] = [
                    'type'   => self::TOKEN_COMMENT,
                    'value'  => substr($input, $start, $pos - $start),
                    'line'   => $line,
                    'column' => $column,
                ];
                continue;
            }

            if ($char === '@' || $char === '`') {
                $tokens[] = [
                    'type'   => self::TOKEN_INDICATOR,
                    'value'  => $char,
                    'line'   => $line,
                    'column' => $column,
                ];
                $pos++;
                $column++;
                continue;
            }

            $scalarStart = $pos;
            $scalarValue = '';
            $isMappingKey = false;

            while ($pos < $len) {
                $c = $input[$pos];

                if ($c === ':' && ($pos + 1 >= $len || ctype_space($input[$pos + 1]) || $input[$pos + 1] === '#')) {
                    $isMappingKey = true;
                    break;
                }

                if ($c === "\n" || $c === '#' || $c === ',' ||
                    $c === '[' || $c === ']' || $c === '{' || $c === '}') {
                    break;
                }

                $scalarValue .= $c;
                $pos++;
                $column++;
            }

            $scalarValue = rtrim($scalarValue);

            if ($scalarValue !== '') {
                if ($isMappingKey) {
                    $tokens[] = [
                        'type'   => self::TOKEN_MAPPING_KEY,
                        'value'  => $scalarValue,
                        'line'   => $line,
                        'column' => $column,
                    ];
                    $pos++;
                    $column++;
                } else {
                    $tokens[] = [
                        'type'   => self::TOKEN_SCALAR,
                        'value'  => $scalarValue,
                        'line'   => $line,
                        'column' => $column,
                    ];
                }
            } else {
                $pos++;
                $column++;
            }
        }

        while (count($indentStack) > 1) {
            array_pop($indentStack);
            $tokens[] = [
                'type'   => self::TOKEN_DEDENT,
                'value'  => 0,
                'line'   => $line,
                'column' => $column,
            ];
        }

        $tokens[] = [
            'type'   => self::TOKEN_EOF,
            'value'  => '',
            'line'   => $line,
            'column' => $column,
        ];

        return $tokens;
    }

    private static function peekNextLineIndent(string $input, int $pos): int {
        $indent = 0;
        $p = $pos;
        $len = strlen($input);
        while ($p < $len && ($input[$p] === ' ' || $input[$p] === "\t")) {
            $indent++;
            $p++;
        }
        if ($p < $len && $input[$p] === "\n") {
            return self::peekNextLineIndent($input, $p + 1);
        }
        return $indent;
    }

    private static function unicodeChar(string $hex): string {
        $code = hexdec($hex);
        if ($code < 0x80) {
            return chr($code);
        } elseif ($code < 0x800) {
            return chr(0xC0 | ($code >> 6)) . chr(0x80 | ($code & 0x3F));
        } elseif ($code < 0x10000) {
            return chr(0xE0 | ($code >> 12)) . chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F));
        } else {
            return chr(0xF0 | ($code >> 18)) . chr(0x80 | (($code >> 12) & 0x3F)) .
                   chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F));
        }
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'line' => -1, 'column' => -1];
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

    private static function matchToken(array &$state, string $type): bool {
        $t = self::current($state);
        if ($t['type'] === $type) {
            self::next($state);
            return true;
        }
        return false;
    }

    private static function skipNewlinesAndComments(array &$state) {
        while (!self::isEof($state)) {
            $t = self::current($state);
            if ($t['type'] === self::TOKEN_NEWLINE || $t['type'] === self::TOKEN_COMMENT) {
                self::next($state);
            } else {
                break;
            }
        }
    }

    // ==================== AST Parser ====================

    private static function parseWithAst(array $tokens, string $input): ?array {
        $state = [
            'tokens'          => $tokens,
            'pos'             => 0,
            'input'           => $input,
            'errors'          => [],
            'document_count'  => 0,
            'mapping_count'   => 0,
            'sequence_count'  => 0,
            'scalar_count'    => 0,
            'tag_count'       => 0,
            'max_depth'       => 0,
            'anchor_count'    => 0,
            'alias_count'     => 0,
            'anchors'         => [],
            'aliases'         => [],
            'dangerous_tags'  => [],
            'sensitive_keys'  => [],
            'gadget_classes'  => [],
            'has_php_object'  => false,
            'has_python_object' => false,
            'has_ruby_object' => false,
            'has_java_object' => false,
            'has_merge_key'   => false,
        ];

        $ast = self::parseDocuments($state);

        return [
            'ast'                => $ast,
            'errors'             => $state['errors'],
            'document_count'     => $state['document_count'],
            'mapping_count'      => $state['mapping_count'],
            'sequence_count'     => $state['sequence_count'],
            'scalar_count'       => $state['scalar_count'],
            'tag_count'          => $state['tag_count'],
            'max_depth'          => $state['max_depth'],
            'anchor_count'       => $state['anchor_count'],
            'alias_count'        => $state['alias_count'],
            'dangerous_tags'     => $state['dangerous_tags'],
            'sensitive_keys'     => $state['sensitive_keys'],
            'gadget_classes'     => $state['gadget_classes'],
            'has_php_object'     => $state['has_php_object'],
            'has_python_object'  => $state['has_python_object'],
            'has_ruby_object'    => $state['has_ruby_object'],
            'has_java_object'    => $state['has_java_object'],
            'has_merge_key'      => $state['has_merge_key'],
            'anchors'            => $state['anchors'],
            'aliases'            => $state['aliases'],
        ];
    }

    private static function parseDocuments(array &$state): array {
        $documents = [];
        self::skipNewlinesAndComments($state);

        while (!self::isEof($state)) {
            $t = self::current($state);

            if ($t['type'] === self::TOKEN_DOC_START) {
                self::next($state);
                $state['document_count']++;
                $docContent = self::parseNode($state, 0);
                $documents[] = [
                    'type'    => 'document',
                    'content' => $docContent,
                ];
            } elseif ($t['type'] === self::TOKEN_DOC_END) {
                self::next($state);
            } elseif ($state['document_count'] === 0) {
                $state['document_count'] = 1;
                $docContent = self::parseNode($state, 0);
                $documents[] = [
                    'type'    => 'document',
                    'content' => $docContent,
                ];
                break;
            } else {
                break;
            }

            self::skipNewlinesAndComments($state);
        }

        return $documents;
    }

    private static function parseNode(array &$state, int $depth): ?array {
        if ($depth > $state['max_depth']) {
            $state['max_depth'] = $depth;
        }

        if ($depth > 100) {
            $state['errors'][] = 'max_depth_exceeded_at_' . $depth;
            return null;
        }

        self::skipNewlinesAndComments($state);

        $t = self::current($state);

        $tag = null;
        $anchor = null;

        if ($t['type'] === self::TOKEN_TAG) {
            $tag = $t['value'];
            $state['tag_count']++;
            self::checkDangerousTag($tag, $state);
            self::next($state);
            self::skipNewlinesAndComments($state);
            $t = self::current($state);
        }

        if ($t['type'] === self::TOKEN_ANCHOR) {
            $anchor = substr($t['value'], 1);
            $state['anchor_count']++;
            $state['anchors'][] = $anchor;
            self::next($state);
            self::skipNewlinesAndComments($state);
            $t = self::current($state);

            if ($t['type'] === self::TOKEN_TAG) {
                $tag = $t['value'];
                $state['tag_count']++;
                self::checkDangerousTag($tag, $state);
                self::next($state);
                self::skipNewlinesAndComments($state);
                $t = self::current($state);
            }
        }

        $node = null;

        switch ($t['type']) {
            case self::TOKEN_ALIAS:
                $aliasName = substr($t['value'], 1);
                $state['alias_count']++;
                $state['aliases'][] = $aliasName;
                self::next($state);
                $node = [
                    'type'  => 'alias',
                    'name'  => $aliasName,
                    'depth' => $depth,
                ];
                break;

            case self::TOKEN_SCALAR:
            case self::TOKEN_SINGLE_QUOTED:
            case self::TOKEN_DOUBLE_QUOTED:
                $node = self::parseScalar($state, $depth);
                break;

            case self::TOKEN_LITERAL_BLOCK:
            case self::TOKEN_FOLDED_BLOCK:
                $node = self::parseBlockScalar($state, $depth);
                break;

            case self::TOKEN_FLOW_MAP_START:
                $node = self::parseFlowMapping($state, $depth);
                break;

            case self::TOKEN_FLOW_SEQ_START:
                $node = self::parseFlowSequence($state, $depth);
                break;

            case self::TOKEN_MAPPING_KEY:
            case self::TOKEN_INDENT:
            case self::TOKEN_MERGE_KEY:
                $node = self::parseBlockMapping($state, $depth);
                break;

            case self::TOKEN_SEQUENCE_ITEM:
                $node = self::parseBlockSequence($state, $depth);
                break;

            default:
                $next = self::peek($state, 1);
                if ($next && $next['type'] === self::TOKEN_MAPPING_KEY) {
                    $node = self::parseBlockMapping($state, $depth);
                } else {
                    $node = [
                        'type'   => 'scalar',
                        'value'  => $t['value'] ?? '',
                        'depth'  => $depth,
                    ];
                    $state['scalar_count']++;
                    self::next($state);
                }
                break;
        }

        if ($node !== null) {
            if ($tag !== null) {
                $node['tag'] = $tag;
            }
            if ($anchor !== null) {
                $node['anchor'] = $anchor;
            }
        }

        return $node;
    }

    private static function parseScalar(array &$state, int $depth): array {
        $t = self::current($state);
        $type = $t['type'];
        $value = $t['value'];

        $subtype = 'plain';
        if ($type === self::TOKEN_SINGLE_QUOTED) {
            $subtype = 'single_quoted';
        } elseif ($type === self::TOKEN_DOUBLE_QUOTED) {
            $subtype = 'double_quoted';
        }

        self::next($state);
        $state['scalar_count']++;

        self::checkScalarForGadgets($value, $state);

        return [
            'type'    => 'scalar',
            'subtype' => $subtype,
            'value'   => $value,
            'depth'   => $depth,
        ];
    }

    private static function parseBlockScalar(array &$state, int $depth): array {
        $t = self::current($state);
        $blockType = $t['type'] === self::TOKEN_LITERAL_BLOCK ? 'literal' : 'folded';
        self::next($state);
        $state['scalar_count']++;

        $value = '';
        $indentLevel = $depth + 1;
        $foundContent = false;
        $contentIndent = null;

        while (!self::isEof($state)) {
            $current = self::current($state);

            if ($current['type'] === self::TOKEN_NEWLINE) {
                $value .= "\n";
                self::next($state);
                continue;
            }

            if ($current['type'] === self::TOKEN_INDENT) {
                self::next($state);
                continue;
            }

            if ($current['type'] === self::TOKEN_DEDENT) {
                if ($foundContent) {
                    break;
                }
                self::next($state);
                continue;
            }

            if ($current['type'] === self::TOKEN_SCALAR ||
                $current['type'] === self::TOKEN_SINGLE_QUOTED ||
                $current['type'] === self::TOKEN_DOUBLE_QUOTED) {
                $value .= $current['value'];
                $foundContent = true;
                self::next($state);
                continue;
            }

            if ($current['type'] === self::TOKEN_COMMENT) {
                self::next($state);
                continue;
            }

            break;
        }

        return [
            'type'    => 'scalar',
            'subtype' => 'block_' . $blockType,
            'value'   => $value,
            'depth'   => $depth,
        ];
    }

    private static function parseBlockMapping(array &$state, int $depth): array {
        $state['mapping_count']++;
        $pairs = [];

        self::skipNewlinesAndComments($state);

        $startedWithIndent = false;
        if (self::current($state)['type'] === self::TOKEN_INDENT) {
            self::next($state);
            $startedWithIndent = true;
        }

        while (!self::isEof($state)) {
            self::skipNewlinesAndComments($state);
            $t = self::current($state);

            if ($t['type'] === self::TOKEN_DEDENT || $t['type'] === self::TOKEN_EOF) {
                break;
            }

            if ($t['type'] === self::TOKEN_DOC_START || $t['type'] === self::TOKEN_DOC_END) {
                break;
            }

            if ($t['type'] === self::TOKEN_SEQUENCE_ITEM) {
                break;
            }

            $key = null;
            if ($t['type'] === self::TOKEN_MERGE_KEY) {
                $state['has_merge_key'] = true;
                self::next($state);
                if (self::current($state)['type'] === self::TOKEN_MAPPING_KEY) {
                    self::next($state);
                }
                $value = self::parseNode($state, $depth + 1);
                $pairs[] = [
                    'key'   => ['type' => 'scalar', 'value' => '<<', 'depth' => $depth],
                    'value' => $value,
                    'merge' => true,
                ];
                continue;
            }

            if ($t['type'] === self::TOKEN_MAPPING_KEY) {
                $keyValue = $t['value'];
                self::next($state);

                if (self::isSensitiveKey($keyValue)) {
                    $state['sensitive_keys'][] = $keyValue;
                }

                $key = [
                    'type'  => 'scalar',
                    'value' => $keyValue,
                    'depth' => $depth,
                ];

                self::skipNewlinesAndComments($state);

                $nextT = self::current($state);
                if ($nextT['type'] === self::TOKEN_NEWLINE) {
                    self::next($state);
                    self::skipNewlinesAndComments($state);
                    $nextT = self::current($state);
                }

                if ($nextT['type'] === self::TOKEN_INDENT) {
                    self::next($state);
                    $value = self::parseNode($state, $depth + 1);
                    $pairs[] = ['key' => $key, 'value' => $value];
                } elseif ($nextT['type'] === self::TOKEN_DEDENT) {
                    $pairs[] = ['key' => $key, 'value' => null];
                } elseif ($nextT['type'] !== self::TOKEN_EOF) {
                    $value = self::parseNode($state, $depth + 1);
                    $pairs[] = ['key' => $key, 'value' => $value];
                } else {
                    $pairs[] = ['key' => $key, 'value' => null];
                }
            } else {
                self::next($state);
            }
        }

        if ($startedWithIndent && self::current($state)['type'] === self::TOKEN_DEDENT) {
            self::next($state);
        }

        return [
            'type'     => 'mapping',
            'style'    => 'block',
            'pairs'    => $pairs,
            'depth'    => $depth,
        ];
    }

    private static function parseBlockSequence(array &$state, int $depth): array {
        $state['sequence_count']++;
        $items = [];

        self::skipNewlinesAndComments($state);

        $startedWithIndent = false;
        if (self::current($state)['type'] === self::TOKEN_INDENT) {
            self::next($state);
            $startedWithIndent = true;
        }

        while (!self::isEof($state)) {
            $t = self::current($state);

            if ($t['type'] === self::TOKEN_DEDENT || $t['type'] === self::TOKEN_EOF) {
                break;
            }

            if ($t['type'] === self::TOKEN_DOC_START || $t['type'] === self::TOKEN_DOC_END) {
                break;
            }

            if ($t['type'] === self::TOKEN_SEQUENCE_ITEM) {
                self::next($state);
                self::skipNewlinesAndComments($state);

                $item = null;
                $nextT = self::current($state);

                if ($nextT['type'] === self::TOKEN_NEWLINE) {
                    self::next($state);
                    self::skipNewlinesAndComments($state);
                    $nextT = self::current($state);
                }

                if ($nextT['type'] === self::TOKEN_INDENT) {
                    self::next($state);
                    $item = self::parseNode($state, $depth + 1);
                } elseif ($nextT['type'] !== self::TOKEN_DEDENT && $nextT['type'] !== self::TOKEN_EOF) {
                    $item = self::parseNode($state, $depth + 1);
                }

                $items[] = $item;
            } elseif ($t['type'] === self::TOKEN_MAPPING_KEY) {
                break;
            } else {
                self::next($state);
            }

            self::skipNewlinesAndComments($state);
        }

        if ($startedWithIndent && self::current($state)['type'] === self::TOKEN_DEDENT) {
            self::next($state);
        }

        return [
            'type'  => 'sequence',
            'style' => 'block',
            'items' => $items,
            'depth' => $depth,
        ];
    }

    private static function parseFlowMapping(array &$state, int $depth): array {
        $state['mapping_count']++;
        $pairs = [];

        self::next($state);

        while (!self::isEof($state)) {
            $t = self::current($state);

            if ($t['type'] === self::TOKEN_FLOW_MAP_END) {
                self::next($state);
                break;
            }

            if ($t['type'] === self::TOKEN_FLOW_COMMA) {
                self::next($state);
                continue;
            }

            if ($t['type'] === self::TOKEN_MAPPING_KEY) {
                $keyValue = $t['value'];
                self::next($state);

                if (self::isSensitiveKey($keyValue)) {
                    $state['sensitive_keys'][] = $keyValue;
                }

                $key = [
                    'type'  => 'scalar',
                    'value' => $keyValue,
                    'depth' => $depth,
                ];

                $value = null;
                $nextT = self::current($state);
                if ($nextT['type'] !== self::TOKEN_FLOW_COMMA &&
                    $nextT['type'] !== self::TOKEN_FLOW_MAP_END) {
                    $value = self::parseNode($state, $depth + 1);
                }

                $pairs[] = ['key' => $key, 'value' => $value];
            } else {
                self::next($state);
            }
        }

        return [
            'type'     => 'mapping',
            'style'    => 'flow',
            'pairs'    => $pairs,
            'depth'    => $depth,
        ];
    }

    private static function parseFlowSequence(array &$state, int $depth): array {
        $state['sequence_count']++;
        $items = [];

        self::next($state);

        while (!self::isEof($state)) {
            $t = self::current($state);

            if ($t['type'] === self::TOKEN_FLOW_SEQ_END) {
                self::next($state);
                break;
            }

            if ($t['type'] === self::TOKEN_FLOW_COMMA) {
                self::next($state);
                continue;
            }

            $item = self::parseNode($state, $depth + 1);
            if ($item !== null) {
                $items[] = $item;
            }
        }

        return [
            'type'  => 'sequence',
            'style' => 'flow',
            'items' => $items,
            'depth' => $depth,
        ];
    }

    // ==================== Semantic Analysis Helpers ====================

    private static function checkDangerousTag(string $tag, array &$state) {
        $tagLower = strtolower($tag);

        foreach (self::$dangerousTags as $dangerousTag => $info) {
            if (strpos($tagLower, strtolower($dangerousTag)) !== false) {
                $state['dangerous_tags'][] = $tag;

                if ($info['category'] === 'php_object') {
                    $state['has_php_object'] = true;
                } elseif ($info['category'] === 'python_object') {
                    $state['has_python_object'] = true;
                } elseif ($info['category'] === 'ruby_object') {
                    $state['has_ruby_object'] = true;
                } elseif ($info['category'] === 'java_object') {
                    $state['has_java_object'] = true;
                }
                break;
            }
        }

        if (preg_match('/!!?php\/object/i', $tag)) {
            $state['has_php_object'] = true;
        }
        if (preg_match('/!!?python\/object/i', $tag)) {
            $state['has_python_object'] = true;
        }
        if (preg_match('/!!?ruby\/object/i', $tag)) {
            $state['has_ruby_object'] = true;
        }
        if (preg_match('/!!?java\/object/i', $tag)) {
            $state['has_java_object'] = true;
        }
    }

    private static function isSensitiveKey(string $key): bool {
        $keyLower = strtolower($key);
        foreach (self::$sensitiveKeys as $sensitiveKey) {
            if ($keyLower === $sensitiveKey || strpos($keyLower, $sensitiveKey) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function checkScalarForGadgets(string $value, array &$state) {
        foreach (self::$gadgetClasses as $className => $info) {
            if (strpos($value, $className) !== false) {
                if (!in_array($className, $state['gadget_classes'])) {
                    $state['gadget_classes'][] = $className;
                }
            }
        }

        if (preg_match('/^O:\d+:/i', $value)) {
            $state['has_php_object'] = true;
            $state['dangerous_tags'][] = 'nested_php_serialized';
        }

        if (stripos($value, 'rmi://') !== false || stripos($value, 'ldap://') !== false ||
            stripos($value, 'ldaps://') !== false || stripos($value, 'jndi:') !== false) {
            $state['has_java_object'] = true;
            $state['dangerous_tags'][] = 'java_jndi_rmi_ldap';
        }
    }

    private static function containsDangerousTagPattern(string $value): bool {
        if (preg_match('/!!?php\/object/i', $value)) return true;
        if (preg_match('/!!?python\/object/i', $value)) return true;
        if (preg_match('/!!?ruby\/object/i', $value)) return true;
        if (preg_match('/!!?java\/object/i', $value)) return true;
        return false;
    }

    // ==================== Result Mapping ====================

    private static function mapAstResult(array $parseResult): array {
        return [
            'document_count'     => $parseResult['document_count'],
            'mapping_count'      => $parseResult['mapping_count'],
            'sequence_count'     => $parseResult['sequence_count'],
            'scalar_count'       => $parseResult['scalar_count'],
            'nesting_depth'      => $parseResult['max_depth'],
            'has_dangerous_tags' => !empty($parseResult['dangerous_tags']),
            'dangerous_tags'     => array_values(array_unique($parseResult['dangerous_tags'])),
            'has_php_object'     => $parseResult['has_php_object'],
            'has_python_object'  => $parseResult['has_python_object'],
            'has_ruby_object'    => $parseResult['has_ruby_object'],
            'has_java_object'    => $parseResult['has_java_object'],
            'sensitive_keys'     => array_values(array_unique($parseResult['sensitive_keys'])),
            'anchor_count'       => $parseResult['anchor_count'],
            'alias_count'        => $parseResult['alias_count'],
            'gadget_classes'     => array_values(array_unique($parseResult['gadget_classes'])),
            'tag_count'          => $parseResult['tag_count'],
        ];
    }

    // ==================== AST Summary ====================

    private static function summarizeAst(array $ast): array {
        $summary = [
            'document_count' => count($ast),
        ];

        $stats = [
            'mappings'    => 0,
            'sequences'   => 0,
            'scalars'     => 0,
            'aliases'     => 0,
            'max_depth'   => 0,
            'total_nodes' => 0,
        ];

        foreach ($ast as $doc) {
            if (!empty($doc['content'])) {
                self::walkAstForSummary($doc['content'], $stats, 0);
            }
        }

        $summary['stats'] = $stats;
        return $summary;
    }

    private static function walkAstForSummary(array $node, array &$stats, int $depth) {
        $stats['total_nodes']++;

        if ($depth > $stats['max_depth']) {
            $stats['max_depth'] = $depth;
        }

        $nodeType = $node['type'] ?? 'unknown';

        switch ($nodeType) {
            case 'mapping':
                $stats['mappings']++;
                if (!empty($node['pairs'])) {
                    foreach ($node['pairs'] as $pair) {
                        if (!empty($pair['key'])) {
                            self::walkAstForSummary($pair['key'], $stats, $depth + 1);
                        }
                        if (!empty($pair['value'])) {
                            self::walkAstForSummary($pair['value'], $stats, $depth + 1);
                        }
                    }
                }
                break;

            case 'sequence':
                $stats['sequences']++;
                if (!empty($node['items'])) {
                    foreach ($node['items'] as $item) {
                        if (!empty($item)) {
                            self::walkAstForSummary($item, $stats, $depth + 1);
                        }
                    }
                }
                break;

            case 'scalar':
                $stats['scalars']++;
                break;

            case 'alias':
                $stats['aliases']++;
                break;
        }
    }

    // ==================== Risk Calculation ====================

    private static function calculateRisk(array $result, array $parseResult): array {
        $score = 0;
        $indicators = [];

        if (!empty($result['dangerous_tags'])) {
            foreach ($result['dangerous_tags'] as $tag) {
                $tagLower = strtolower($tag);
                if (strpos($tagLower, 'php/object') !== false) {
                    $score += 50;
                    $indicators[] = 'php_object_injection';
                } elseif (strpos($tagLower, 'python/object') !== false) {
                    $score += 50;
                    $indicators[] = 'python_object_injection';
                } elseif (strpos($tagLower, 'ruby/object') !== false) {
                    $score += 45;
                    $indicators[] = 'ruby_object_injection';
                } elseif (strpos($tagLower, 'java/object') !== false) {
                    $score += 50;
                    $indicators[] = 'java_deserialization';
                } elseif (strpos($tagLower, 'binary') !== false) {
                    $score += 15;
                    $indicators[] = 'binary_data';
                } else {
                    $score += 10;
                }
            }
        }

        if ($result['has_php_object']) {
            $score += 40;
            $indicators[] = 'php_object';
        }
        if ($result['has_python_object']) {
            $score += 40;
            $indicators[] = 'python_object';
        }
        if ($result['has_ruby_object']) {
            $score += 35;
            $indicators[] = 'ruby_object';
        }
        if ($result['has_java_object']) {
            $score += 40;
            $indicators[] = 'java_object';
        }

        if (!empty($result['sensitive_keys'])) {
            $score += count($result['sensitive_keys']) * 8;
            $indicators[] = 'sensitive_keys:' . count($result['sensitive_keys']);
        }

        if (!empty($result['gadget_classes'])) {
            $score += count($result['gadget_classes']) * 15;
            $indicators[] = 'gadget_classes:' . count($result['gadget_classes']);
        }

        if ($result['anchor_count'] > 5 && $result['alias_count'] > 5) {
            $ratio = $result['alias_count'] / max($result['anchor_count'], 1);
            if ($ratio > 2) {
                $score += 25;
                $result['has_billion_laughs'] = true;
                $indicators[] = 'billion_laughs_pattern';
            }
        }

        if ($result['anchor_count'] > 10) {
            $score += 10;
            $indicators[] = 'excessive_anchors:' . $result['anchor_count'];
        }

        if ($result['nesting_depth'] > 20) {
            $score += 20;
            $indicators[] = 'excessive_nesting:' . $result['nesting_depth'];
        } elseif ($result['nesting_depth'] > 10) {
            $score += 10;
            $indicators[] = 'deep_nesting:' . $result['nesting_depth'];
        }

        if ($result['document_count'] > 3) {
            $score += 5;
            $indicators[] = 'multiple_documents:' . $result['document_count'];
        }

        if ($result['is_yaml'] && $result['tag_count'] > 0) {
            $score += 5;
            $indicators[] = 'custom_tags:' . $result['tag_count'];
        }

        $result['score'] = min($score, 100);
        $result['indicators'] = array_merge($result['indicators'], $indicators);

        if ($result['score'] >= 80) {
            $result['risk_level'] = 'critical';
        } elseif ($result['score'] >= 60) {
            $result['risk_level'] = 'high';
        } elseif ($result['score'] >= 30) {
            $result['risk_level'] = 'medium';
        } elseif ($result['score'] >= 10) {
            $result['risk_level'] = 'low';
        } else {
            $result['risk_level'] = 'clean';
        }

        return $result;
    }

    // ==================== Regex Fallback ====================

    private static function regexFallback(string $input, array $result): array {
        $indicators = [];
        $score = 0;

        if (preg_match('/!!?php\/object/i', $input)) {
            $score += 50;
            $result['has_php_object'] = true;
            $result['dangerous_tags'][] = '!!php/object';
            $indicators[] = 'php_object_injection_regex';
        }

        if (preg_match('/!!?python\/object/i', $input)) {
            $score += 50;
            $result['has_python_object'] = true;
            $result['dangerous_tags'][] = '!!python/object';
            $indicators[] = 'python_object_injection_regex';
        }

        if (preg_match('/!!?ruby\/object/i', $input)) {
            $score += 45;
            $result['has_ruby_object'] = true;
            $result['dangerous_tags'][] = '!ruby/object';
            $indicators[] = 'ruby_object_injection_regex';
        }

        if (preg_match('/!!?java\/object/i', $input)) {
            $score += 50;
            $result['has_java_object'] = true;
            $result['dangerous_tags'][] = '!!java/object';
            $indicators[] = 'java_deserialization_regex';
        }

        if (preg_match('/rmi:\/\/|ldap:\/\/|ldaps:\/\/|jndi:/i', $input)) {
            $score += 40;
            $result['has_java_object'] = true;
            $result['dangerous_tags'][] = 'jndi_rmi_ldap';
            $indicators[] = 'java_jndi_attack';
        }

        if (preg_match('/^O:\d+:"/m', $input)) {
            $score += 35;
            $result['has_php_object'] = true;
            $indicators[] = 'nested_php_serialized';
        }

        $anchorCount = preg_match_all('/&[a-zA-Z0-9_]/', $input);
        $aliasCount = preg_match_all('/\*[a-zA-Z0-9_]/', $input);
        $result['anchor_count'] = $anchorCount;
        $result['alias_count'] = $aliasCount;

        if ($anchorCount > 5 && $aliasCount > $anchorCount * 2) {
            $score += 25;
            $result['has_billion_laughs'] = true;
            $indicators[] = 'billion_laughs_pattern';
        }

        $docCount = preg_match_all('/^---/m', $input);
        $result['document_count'] = max($docCount, 1);
        if ($docCount > 3) {
            $score += 5;
            $indicators[] = 'multiple_documents:' . $docCount;
        }

        foreach (self::$sensitiveKeys as $key) {
            if (preg_match('/^\s*' . preg_quote($key, '/') . '\s*:/mi', $input)) {
                $result['sensitive_keys'][] = $key;
            }
        }
        if (!empty($result['sensitive_keys'])) {
            $score += count($result['sensitive_keys']) * 8;
            $indicators[] = 'sensitive_keys:' . count($result['sensitive_keys']);
        }

        foreach (self::$gadgetClasses as $className => $info) {
            if (strpos($input, $className) !== false) {
                $result['gadget_classes'][] = $className;
            }
        }
        if (!empty($result['gadget_classes'])) {
            $score += count($result['gadget_classes']) * 15;
            $indicators[] = 'gadget_classes:' . count($result['gadget_classes']);
        }

        $result['has_dangerous_tags'] = !empty($result['dangerous_tags']);
        $result['score'] = min($score, 100);
        $result['indicators'] = array_merge($result['indicators'], $indicators);

        if ($result['score'] >= 80) {
            $result['risk_level'] = 'critical';
        } elseif ($result['score'] >= 60) {
            $result['risk_level'] = 'high';
        } elseif ($result['score'] >= 30) {
            $result['risk_level'] = 'medium';
        } elseif ($result['score'] >= 10) {
            $result['risk_level'] = 'low';
        } else {
            $result['risk_level'] = 'clean';
        }

        return $result;
    }
}
