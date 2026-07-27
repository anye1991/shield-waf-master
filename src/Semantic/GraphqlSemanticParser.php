<?php
/**
 * GraphQL 语义解析器
 * 职责：通过构建 GraphQL AST（抽象语法树）真正理解 GraphQL 查询结构，
 *       检测内省查询、深度攻击、批量别名、循环片段、危险指令等攻击模式。
 */
defined('ABSPATH') || exit;

class GraphqlSemanticParser {

    // ==================== Token Types ====================

    const TOKEN_NAME          = 'NAME';
    const TOKEN_INT           = 'INT';
    const TOKEN_FLOAT         = 'FLOAT';
    const TOKEN_STRING        = 'STRING';
    const TOKEN_BRACE_L       = 'BRACE_L';
    const TOKEN_BRACE_R       = 'BRACE_R';
    const TOKEN_PAREN_L       = 'PAREN_L';
    const TOKEN_PAREN_R       = 'PAREN_R';
    const TOKEN_BRACKET_L     = 'BRACKET_L';
    const TOKEN_BRACKET_R     = 'BRACKET_R';
    const TOKEN_COLON         = 'COLON';
    const TOKEN_EQUALS        = 'EQUALS';
    const TOKEN_BANG          = 'BANG';
    const TOKEN_DOLLAR        = 'DOLLAR';
    const TOKEN_AT            = 'AT';
    const TOKEN_SPREAD        = 'SPREAD';
    const TOKEN_PIPE          = 'PIPE';
    const TOKEN_AMPERSAND     = 'AMPERSAND';
    const TOKEN_COMMA         = 'COMMA';
    const TOKEN_EOF           = 'EOF';

    // ==================== Keyword Lists ====================

    private static $operationTypes = [
        'query', 'mutation', 'subscription',
    ];

    private static $fragmentKeywords = [
        'fragment', 'on',
    ];

    private static $booleanValues = [
        'true', 'false',
    ];

    private static $nullValue = 'null';

    private static $introspectionFields = [
        '__schema', '__type', '__typename', '__inputValue',
        '__enumValue', '__field', '__typeKind', '__directive',
        '__schemaType', '__typeType',
    ];

    private static $builtinDirectives = [
        'skip', 'include', 'deprecated', 'specifiedBy',
    ];

    private static $sensitiveFieldNames = [
        'admin', 'password', 'secret', 'token', 'key',
        'apikey', 'api_key', 'access_token', 'refresh_token',
        'private_key', 'public_key', 'credential', 'credentials',
        'auth', 'authentication', 'authorization',
    ];

    private static $dangerousDirectivePatterns = [
        'eval', 'exec', 'system', 'shell', 'command',
        'inject', 'import', 'require', 'include',
    ];

    // ==================== Thresholds ====================

    const MAX_QUERY_DEPTH       = 10;
    const MAX_FIELD_COUNT       = 50;
    const MAX_ALIAS_RATIO       = 0.6;
    const COMPLEXITY_MULTIPLIER = 1;

    // ==================== Public API ====================

    /**
     * 主入口：分析 GraphQL 查询语义
     *
     * @param string $input
     * @return array
     */
    public static function analyze(string $input): array {
        $result = [
            'score'                    => 0,
            'risk_level'               => 'clean',
            'is_graphql'               => false,
            'query_type'               => 'unknown',
            'has_introspection'        => false,
            'introspection_fields'     => [],
            'query_depth'              => 0,
            'field_count'              => 0,
            'alias_count'              => 0,
            'fragment_count'           => 0,
            'has_dangerous_directives' => false,
            'dangerous_directives'     => [],
            'sensitive_fields'         => [],
            'complexity'               => 0,
            'has_circular_fragments'   => false,
            'circular_fragments'       => [],
            'indicators'               => [],
            'ast_summary'              => [],
            'parse_mode'               => 'ast',
        ];

        $trimmed = trim($input);
        if ($trimmed === '') {
            return $result;
        }

        try {
            $tokens = self::tokenize($input);
            if (empty($tokens)) {
                $fallbackResult = self::regexFallback($input);
                return array_merge($result, $fallbackResult);
            }

            $ast = self::parse($tokens, $input);

            if (empty($ast)) {
                $fallbackResult = self::regexFallback($input);
                return array_merge($result, $fallbackResult);
            }

            $result['is_graphql'] = true;
            $result['ast_summary'] = self::summarizeAst($ast);
            $result['query_type'] = self::determineQueryType($ast);

            $walkerResult = self::walkAst($ast, $input);
            $result['has_introspection'] = $walkerResult['has_introspection'];
            $result['introspection_fields'] = $walkerResult['introspection_fields'];
            $result['query_depth'] = $walkerResult['query_depth'];
            $result['field_count'] = $walkerResult['field_count'];
            $result['alias_count'] = $walkerResult['alias_count'];
            $result['fragment_count'] = $walkerResult['fragment_count'];
            $result['has_dangerous_directives'] = $walkerResult['has_dangerous_directives'];
            $result['dangerous_directives'] = $walkerResult['dangerous_directives'];
            $result['sensitive_fields'] = $walkerResult['sensitive_fields'];
            $result['complexity'] = $walkerResult['complexity'];
            $result['has_circular_fragments'] = $walkerResult['has_circular_fragments'];
            $result['circular_fragments'] = $walkerResult['circular_fragments'];
            $result['indicators'] = $walkerResult['indicators'];

            $result['score'] = self::calculateScore($result);
            $result['risk_level'] = self::determineRiskLevel($result['score']);

        } catch (Exception $e) {
            $fallbackResult = self::regexFallback($input);
            $fallbackResult['indicators'][] = 'parse_error_fallback';
            return array_merge($result, $fallbackResult);
        }

        return $result;
    }

    // ==================== Tokenizer ====================

    /**
     * GraphQL 词法分析
     *
     * @param string $input
     * @return array
     */
    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);

        while ($pos < $len) {
            $char = $input[$pos];

            if ($char === ' ' || $char === "\t" || $char === "\n" || $char === "\r" || $char === ',') {
                $pos++;
                continue;
            }

            if ($char === '#' && $pos + 1 < $len) {
                while ($pos < $len && $input[$pos] !== "\n") {
                    $pos++;
                }
                continue;
            }

            if ($char === '"') {
                if ($pos + 2 < $len && $input[$pos + 1] === '"' && $input[$pos + 2] === '"') {
                    $start = $pos;
                    $pos += 3;
                    $value = '';
                    while ($pos < $len - 2) {
                        if ($input[$pos] === '"' && $input[$pos + 1] === '"' && $input[$pos + 2] === '"') {
                            $pos += 3;
                            break;
                        }
                        if ($input[$pos] === '\\' && $pos + 1 < $len) {
                            $value .= $input[$pos] . $input[$pos + 1];
                            $pos += 2;
                        } else {
                            $value .= $input[$pos];
                            $pos++;
                        }
                    }
                    $tokens[] = [
                        'type'  => self::TOKEN_STRING,
                        'value' => $value,
                        'raw'   => substr($input, $start, $pos - $start),
                        'pos'   => $start,
                        'block' => true,
                    ];
                    continue;
                }

                $start = $pos;
                $pos++;
                $value = '';
                while ($pos < $len) {
                    if ($input[$pos] === '"') {
                        $pos++;
                        break;
                    }
                    if ($input[$pos] === '\\' && $pos + 1 < $len) {
                        $value .= $input[$pos] . $input[$pos + 1];
                        $pos += 2;
                    } else {
                        $value .= $input[$pos];
                        $pos++;
                    }
                }
                $tokens[] = [
                    'type'  => self::TOKEN_STRING,
                    'value' => $value,
                    'raw'   => substr($input, $start, $pos - $start),
                    'pos'   => $start,
                    'block' => false,
                ];
                continue;
            }

            if (is_numeric($char) || ($char === '-' && $pos + 1 < $len && is_numeric($input[$pos + 1]))) {
                $start = $pos;
                $isFloat = false;

                if ($char === '-') $pos++;

                while ($pos < $len && is_numeric($input[$pos])) {
                    $pos++;
                }

                if ($pos < $len && $input[$pos] === '.') {
                    $isFloat = true;
                    $pos++;
                    while ($pos < $len && is_numeric($input[$pos])) {
                        $pos++;
                    }
                }

                if ($pos < $len && ($input[$pos] === 'e' || $input[$pos] === 'E')) {
                    $isFloat = true;
                    $pos++;
                    if ($pos < $len && ($input[$pos] === '+' || $input[$pos] === '-')) $pos++;
                    while ($pos < $len && is_numeric($input[$pos])) $pos++;
                }

                $tokens[] = [
                    'type'  => $isFloat ? self::TOKEN_FLOAT : self::TOKEN_INT,
                    'value' => substr($input, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === '.' && $pos + 2 < $len && $input[$pos + 1] === '.' && $input[$pos + 2] === '.') {
                $tokens[] = ['type' => self::TOKEN_SPREAD, 'value' => '...', 'pos' => $pos];
                $pos += 3;
                continue;
            }

            if (ctype_alpha($char) || $char === '_') {
                $start = $pos;
                while ($pos < $len && (ctype_alnum($input[$pos]) || $input[$pos] === '_')) {
                    $pos++;
                }
                $word = substr($input, $start, $pos - $start);
                $tokens[] = [
                    'type'  => self::TOKEN_NAME,
                    'value' => $word,
                    'pos'   => $start,
                ];
                continue;
            }

            switch ($char) {
                case '{':
                    $tokens[] = ['type' => self::TOKEN_BRACE_L, 'value' => '{', 'pos' => $pos];
                    break;
                case '}':
                    $tokens[] = ['type' => self::TOKEN_BRACE_R, 'value' => '}', 'pos' => $pos];
                    break;
                case '(':
                    $tokens[] = ['type' => self::TOKEN_PAREN_L, 'value' => '(', 'pos' => $pos];
                    break;
                case ')':
                    $tokens[] = ['type' => self::TOKEN_PAREN_R, 'value' => ')', 'pos' => $pos];
                    break;
                case '[':
                    $tokens[] = ['type' => self::TOKEN_BRACKET_L, 'value' => '[', 'pos' => $pos];
                    break;
                case ']':
                    $tokens[] = ['type' => self::TOKEN_BRACKET_R, 'value' => ']', 'pos' => $pos];
                    break;
                case ':':
                    $tokens[] = ['type' => self::TOKEN_COLON, 'value' => ':', 'pos' => $pos];
                    break;
                case '=':
                    $tokens[] = ['type' => self::TOKEN_EQUALS, 'value' => '=', 'pos' => $pos];
                    break;
                case '!':
                    $tokens[] = ['type' => self::TOKEN_BANG, 'value' => '!', 'pos' => $pos];
                    break;
                case '$':
                    $tokens[] = ['type' => self::TOKEN_DOLLAR, 'value' => '$', 'pos' => $pos];
                    break;
                case '@':
                    $tokens[] = ['type' => self::TOKEN_AT, 'value' => '@', 'pos' => $pos];
                    break;
                case '|':
                    $tokens[] = ['type' => self::TOKEN_PIPE, 'value' => '|', 'pos' => $pos];
                    break;
                case '&':
                    $tokens[] = ['type' => self::TOKEN_AMPERSAND, 'value' => '&', 'pos' => $pos];
                    break;
            }
            $pos++;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    // ==================== Parser ====================

    /**
     * GraphQL 语法分析，构建 AST
     *
     * @param array $tokens
     * @param string $input
     * @return array|null
     */
    private static function parse(array $tokens, string $input): ?array {
        $state = [
            'tokens' => $tokens,
            'pos'    => 0,
            'input'  => $input,
            'fragments' => [],
        ];

        $definitions = [];

        while (!self::isEof($state)) {
            $def = self::parseDefinition($state);
            if ($def !== null) {
                $definitions[] = $def;
            } else {
                break;
            }
        }

        if (empty($definitions)) {
            return null;
        }

        return [
            'type'        => 'document',
            'definitions' => $definitions,
            'fragments'   => $state['fragments'],
        ];
    }

    private static function parseDefinition(array &$state): ?array {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_BRACE_L) {
            return self::parseOperationDefinition($state, true);
        }

        if ($token['type'] === self::TOKEN_NAME) {
            $value = $token['value'];

            if (in_array($value, self::$operationTypes, true)) {
                return self::parseOperationDefinition($state, false);
            }

            if ($value === 'fragment') {
                return self::parseFragmentDefinition($state);
            }
        }

        return null;
    }

    private static function parseOperationDefinition(array &$state, bool $shorthand): array {
        $operation = 'query';
        $name = null;
        $variableDefinitions = [];
        $directives = [];

        if (!$shorthand) {
            $operation = self::current($state)['value'];
            self::next($state);

            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $name = self::current($state)['value'];
                self::next($state);
            }
        }

        if (self::current($state)['type'] === self::TOKEN_PAREN_L) {
            $variableDefinitions = self::parseVariableDefinitions($state);
        }

        $directives = self::parseDirectives($state);

        $selectionSet = null;
        if (self::current($state)['type'] === self::TOKEN_BRACE_L) {
            $selectionSet = self::parseSelectionSet($state);
        }

        return [
            'kind'                  => 'OperationDefinition',
            'operation'             => $operation,
            'name'                  => $name,
            'variable_definitions'  => $variableDefinitions,
            'directives'            => $directives,
            'selection_set'         => $selectionSet,
        ];
    }

    private static function parseVariableDefinitions(array &$state): array {
        $defs = [];
        self::next($state);

        while (!self::isEof($state) && self::current($state)['type'] !== self::TOKEN_PAREN_R) {
            $defs[] = self::parseVariableDefinition($state);
        }

        if (self::current($state)['type'] === self::TOKEN_PAREN_R) {
            self::next($state);
        }

        return $defs;
    }

    private static function parseVariableDefinition(array &$state): array {
        $variable = null;
        $type = null;
        $defaultValue = null;

        if (self::current($state)['type'] === self::TOKEN_DOLLAR) {
            self::next($state);
            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $variable = self::current($state)['value'];
                self::next($state);
            }
        }

        if (self::current($state)['type'] === self::TOKEN_COLON) {
            self::next($state);
            $type = self::parseType($state);
        }

        if (self::current($state)['type'] === self::TOKEN_EQUALS) {
            self::next($state);
            $defaultValue = self::parseValue($state);
        }

        return [
            'kind'          => 'VariableDefinition',
            'variable'      => $variable,
            'type'          => $type,
            'default_value' => $defaultValue,
        ];
    }

    private static function parseType(array &$state): array {
        $type = null;

        if (self::current($state)['type'] === self::TOKEN_BRACKET_L) {
            self::next($state);
            $innerType = self::parseType($state);
            if (self::current($state)['type'] === self::TOKEN_BRACKET_R) {
                self::next($state);
            }
            $type = [
                'kind' => 'ListType',
                'type' => $innerType,
            ];
        } elseif (self::current($state)['type'] === self::TOKEN_NAME) {
            $type = [
                'kind' => 'NamedType',
                'name' => self::current($state)['value'],
            ];
            self::next($state);
        }

        if (self::current($state)['type'] === self::TOKEN_BANG) {
            self::next($state);
            $type = [
                'kind' => 'NonNullType',
                'type' => $type,
            ];
        }

        return $type;
    }

    private static function parseSelectionSet(array &$state): array {
        $selections = [];
        self::next($state);

        while (!self::isEof($state) && self::current($state)['type'] !== self::TOKEN_BRACE_R) {
            $selection = self::parseSelection($state);
            if ($selection !== null) {
                $selections[] = $selection;
            } else {
                self::next($state);
            }
        }

        if (self::current($state)['type'] === self::TOKEN_BRACE_R) {
            self::next($state);
        }

        return [
            'kind'       => 'SelectionSet',
            'selections' => $selections,
        ];
    }

    private static function parseSelection(array &$state): ?array {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_SPREAD) {
            return self::parseFragment($state);
        }

        if ($token['type'] === self::TOKEN_NAME) {
            return self::parseField($state);
        }

        return null;
    }

    private static function parseField(array &$state): array {
        $alias = null;
        $name = self::current($state)['value'];
        self::next($state);

        if (self::current($state)['type'] === self::TOKEN_COLON) {
            self::next($state);
            $alias = $name;
            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $name = self::current($state)['value'];
                self::next($state);
            }
        }

        $args = [];
        if (self::current($state)['type'] === self::TOKEN_PAREN_L) {
            $args = self::parseArguments($state);
        }

        $directives = self::parseDirectives($state);

        $selectionSet = null;
        if (self::current($state)['type'] === self::TOKEN_BRACE_L) {
            $selectionSet = self::parseSelectionSet($state);
        }

        return [
            'kind'          => 'Field',
            'alias'         => $alias,
            'name'          => $name,
            'arguments'     => $args,
            'directives'    => $directives,
            'selection_set' => $selectionSet,
        ];
    }

    private static function parseArguments(array &$state): array {
        $args = [];
        self::next($state);

        while (!self::isEof($state) && self::current($state)['type'] !== self::TOKEN_PAREN_R) {
            $args[] = self::parseArgument($state);
        }

        if (self::current($state)['type'] === self::TOKEN_PAREN_R) {
            self::next($state);
        }

        return $args;
    }

    private static function parseArgument(array &$state): array {
        $name = null;
        $value = null;

        if (self::current($state)['type'] === self::TOKEN_NAME) {
            $name = self::current($state)['value'];
            self::next($state);
        }

        if (self::current($state)['type'] === self::TOKEN_COLON) {
            self::next($state);
            $value = self::parseValue($state);
        }

        return [
            'kind'  => 'Argument',
            'name'  => $name,
            'value' => $value,
        ];
    }

    private static function parseFragment(array &$state): array {
        self::next($state);

        $token = self::current($state);

        if ($token['type'] === self::TOKEN_NAME && $token['value'] === 'on') {
            self::next($state);
            $typeCondition = null;
            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $typeCondition = self::current($state)['value'];
                self::next($state);
            }
            $directives = self::parseDirectives($state);
            $selectionSet = null;
            if (self::current($state)['type'] === self::TOKEN_BRACE_L) {
                $selectionSet = self::parseSelectionSet($state);
            }
            return [
                'kind'            => 'InlineFragment',
                'type_condition'  => $typeCondition,
                'directives'      => $directives,
                'selection_set'   => $selectionSet,
            ];
        }

        if ($token['type'] === self::TOKEN_NAME) {
            $name = $token['value'];
            self::next($state);
            $directives = self::parseDirectives($state);
            return [
                'kind'       => 'FragmentSpread',
                'name'       => $name,
                'directives' => $directives,
            ];
        }

        return [
            'kind'  => 'FragmentSpread',
            'name'  => '',
            'directives' => [],
        ];
    }

    private static function parseFragmentDefinition(array &$state): array {
        self::next($state);

        $name = null;
        if (self::current($state)['type'] === self::TOKEN_NAME) {
            $name = self::current($state)['value'];
            self::next($state);
        }

        $typeCondition = null;
        if (self::current($state)['type'] === self::TOKEN_NAME && self::current($state)['value'] === 'on') {
            self::next($state);
            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $typeCondition = self::current($state)['value'];
                self::next($state);
            }
        }

        $directives = self::parseDirectives($state);

        $selectionSet = null;
        if (self::current($state)['type'] === self::TOKEN_BRACE_L) {
            $selectionSet = self::parseSelectionSet($state);
        }

        $def = [
            'kind'            => 'FragmentDefinition',
            'name'            => $name,
            'type_condition'  => $typeCondition,
            'directives'      => $directives,
            'selection_set'   => $selectionSet,
        ];

        if ($name !== null) {
            $state['fragments'][$name] = $def;
        }

        return $def;
    }

    private static function parseDirectives(array &$state): array {
        $directives = [];

        while (self::current($state)['type'] === self::TOKEN_AT) {
            $directives[] = self::parseDirective($state);
        }

        return $directives;
    }

    private static function parseDirective(array &$state): array {
        self::next($state);

        $name = null;
        if (self::current($state)['type'] === self::TOKEN_NAME) {
            $name = self::current($state)['value'];
            self::next($state);
        }

        $args = [];
        if (self::current($state)['type'] === self::TOKEN_PAREN_L) {
            $args = self::parseArguments($state);
        }

        return [
            'kind'      => 'Directive',
            'name'      => $name,
            'arguments' => $args,
        ];
    }

    private static function parseValue(array &$state) {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_DOLLAR) {
            self::next($state);
            $name = null;
            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $name = self::current($state)['value'];
                self::next($state);
            }
            return ['kind' => 'Variable', 'name' => $name];
        }

        if ($token['type'] === self::TOKEN_INT) {
            self::next($state);
            return ['kind' => 'IntValue', 'value' => $token['value']];
        }

        if ($token['type'] === self::TOKEN_FLOAT) {
            self::next($state);
            return ['kind' => 'FloatValue', 'value' => $token['value']];
        }

        if ($token['type'] === self::TOKEN_STRING) {
            self::next($state);
            return ['kind' => 'StringValue', 'value' => $token['value']];
        }

        if ($token['type'] === self::TOKEN_NAME) {
            $value = $token['value'];
            if ($value === 'true' || $value === 'false') {
                self::next($state);
                return ['kind' => 'BooleanValue', 'value' => $value === 'true'];
            }
            if ($value === 'null') {
                self::next($state);
                return ['kind' => 'NullValue', 'value' => null];
            }
            self::next($state);
            return ['kind' => 'EnumValue', 'value' => $value];
        }

        if ($token['type'] === self::TOKEN_BRACKET_L) {
            return self::parseListValue($state);
        }

        if ($token['type'] === self::TOKEN_BRACE_L) {
            return self::parseObjectValue($state);
        }

        self::next($state);
        return ['kind' => 'UnknownValue', 'value' => $token['value'] ?? ''];
    }

    private static function parseListValue(array &$state): array {
        $values = [];
        self::next($state);

        while (!self::isEof($state) && self::current($state)['type'] !== self::TOKEN_BRACKET_R) {
            $values[] = self::parseValue($state);
        }

        if (self::current($state)['type'] === self::TOKEN_BRACKET_R) {
            self::next($state);
        }

        return [
            'kind'   => 'ListValue',
            'values' => $values,
        ];
    }

    private static function parseObjectValue(array &$state): array {
        $fields = [];
        self::next($state);

        while (!self::isEof($state) && self::current($state)['type'] !== self::TOKEN_BRACE_R) {
            $name = null;
            $value = null;

            if (self::current($state)['type'] === self::TOKEN_NAME) {
                $name = self::current($state)['value'];
                self::next($state);
            }

            if (self::current($state)['type'] === self::TOKEN_COLON) {
                self::next($state);
                $value = self::parseValue($state);
            }

            if ($name !== null) {
                $fields[] = ['kind' => 'ObjectField', 'name' => $name, 'value' => $value];
            }
        }

        if (self::current($state)['type'] === self::TOKEN_BRACE_R) {
            self::next($state);
        }

        return [
            'kind'   => 'ObjectValue',
            'fields' => $fields,
        ];
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

    // ==================== AST Walker / Semantic Analysis ====================

    /**
     * 遍历 AST，进行语义分析和攻击检测
     */
    private static function walkAst(array $ast, string $input): array {
        $result = [
            'has_introspection'        => false,
            'introspection_fields'     => [],
            'query_depth'              => 0,
            'field_count'              => 0,
            'alias_count'              => 0,
            'fragment_count'           => 0,
            'has_dangerous_directives' => false,
            'dangerous_directives'     => [],
            'sensitive_fields'         => [],
            'complexity'               => 0,
            'has_circular_fragments'   => false,
            'circular_fragments'       => [],
            'indicators'               => [],
        ];

        $fragments = $ast['fragments'] ?? [];
        $result['fragment_count'] = count($fragments);

        $circularResult = self::detectCircularFragments($fragments);
        $result['has_circular_fragments'] = $circularResult['has_circular'];
        $result['circular_fragments'] = $circularResult['cycles'];
        if ($result['has_circular_fragments']) {
            $result['indicators'][] = 'circular_fragments';
        }

        $definitions = $ast['definitions'] ?? [];
        foreach ($definitions as $def) {
            $defKind = $def['kind'] ?? '';

            if ($defKind === 'OperationDefinition') {
                $selectionSet = $def['selection_set'] ?? null;
                if ($selectionSet !== null) {
                    $walkResult = self::walkSelectionSet($selectionSet, $fragments, 0);
                    $result['query_depth'] = max($result['query_depth'], $walkResult['depth']);
                    $result['field_count'] += $walkResult['field_count'];
                    $result['alias_count'] += $walkResult['alias_count'];
                    $result['introspection_fields'] = array_merge(
                        $result['introspection_fields'],
                        $walkResult['introspection_fields']
                    );
                    $result['sensitive_fields'] = array_merge(
                        $result['sensitive_fields'],
                        $walkResult['sensitive_fields']
                    );
                    $result['dangerous_directives'] = array_merge(
                        $result['dangerous_directives'],
                        $walkResult['dangerous_directives']
                    );
                    $result['complexity'] += $walkResult['complexity'];
                }

                $dirResult = self::checkDirectives($def['directives'] ?? []);
                if (!empty($dirResult['dangerous'])) {
                    $result['dangerous_directives'] = array_merge(
                        $result['dangerous_directives'],
                        $dirResult['dangerous']
                    );
                }
            }
        }

        $result['introspection_fields'] = array_values(array_unique($result['introspection_fields']));
        $result['sensitive_fields'] = array_values(array_unique($result['sensitive_fields']));
        $result['dangerous_directives'] = array_values(array_unique($result['dangerous_directives']));
        $result['has_introspection'] = !empty($result['introspection_fields']);
        $result['has_dangerous_directives'] = !empty($result['dangerous_directives']);

        if ($result['has_introspection']) {
            $result['indicators'][] = 'introspection_query:' . implode(',', $result['introspection_fields']);
        }
        if ($result['query_depth'] > self::MAX_QUERY_DEPTH) {
            $result['indicators'][] = 'deep_query:' . $result['query_depth'];
        }
        if ($result['field_count'] > self::MAX_FIELD_COUNT) {
            $result['indicators'][] = 'excessive_fields:' . $result['field_count'];
        }
        if ($result['alias_count'] > 0 && $result['field_count'] > 0) {
            $aliasRatio = $result['alias_count'] / $result['field_count'];
            if ($aliasRatio > self::MAX_ALIAS_RATIO && $result['alias_count'] >= 5) {
                $result['indicators'][] = 'alias_batching:' . $result['alias_count'];
            }
        }
        if ($result['has_dangerous_directives']) {
            $result['indicators'][] = 'dangerous_directives:' . implode(',', $result['dangerous_directives']);
        }
        if (!empty($result['sensitive_fields'])) {
            $result['indicators'][] = 'sensitive_fields:' . implode(',', $result['sensitive_fields']);
        }

        return $result;
    }

    private static function walkSelectionSet(array $selectionSet, array $fragments, int $currentDepth): array {
        $result = [
            'depth'                  => $currentDepth,
            'field_count'            => 0,
            'alias_count'            => 0,
            'introspection_fields'   => [],
            'sensitive_fields'       => [],
            'dangerous_directives'   => [],
            'complexity'             => 0,
        ];

        $selections = $selectionSet['selections'] ?? [];
        $maxChildDepth = $currentDepth;

        foreach ($selections as $selection) {
            $kind = $selection['kind'] ?? '';

            if ($kind === 'Field') {
                $result['field_count']++;
                $fieldName = $selection['name'] ?? '';

                if (!empty($selection['alias'])) {
                    $result['alias_count']++;
                }

                if (self::isIntrospectionField($fieldName)) {
                    $result['introspection_fields'][] = $fieldName;
                }

                if (self::isSensitiveField($fieldName)) {
                    $result['sensitive_fields'][] = $fieldName;
                }

                $dirResult = self::checkDirectives($selection['directives'] ?? []);
                if (!empty($dirResult['dangerous'])) {
                    $result['dangerous_directives'] = array_merge(
                        $result['dangerous_directives'],
                        $dirResult['dangerous']
                    );
                }

                $childSelectionSet = $selection['selection_set'] ?? null;
                if ($childSelectionSet !== null) {
                    $childResult = self::walkSelectionSet($childSelectionSet, $fragments, $currentDepth + 1);
                    $maxChildDepth = max($maxChildDepth, $childResult['depth']);
                    $result['field_count'] += $childResult['field_count'];
                    $result['alias_count'] += $childResult['alias_count'];
                    $result['introspection_fields'] = array_merge(
                        $result['introspection_fields'],
                        $childResult['introspection_fields']
                    );
                    $result['sensitive_fields'] = array_merge(
                        $result['sensitive_fields'],
                        $childResult['sensitive_fields']
                    );
                    $result['dangerous_directives'] = array_merge(
                        $result['dangerous_directives'],
                        $childResult['dangerous_directives']
                    );
                    $result['complexity'] += $childResult['complexity'];
                } else {
                    $result['complexity'] += 1;
                }
            } elseif ($kind === 'FragmentSpread') {
                $fragName = $selection['name'] ?? '';
                if (isset($fragments[$fragName])) {
                    $fragment = $fragments[$fragName];
                    $fragSelectionSet = $fragment['selection_set'] ?? null;
                    if ($fragSelectionSet !== null) {
                        $childResult = self::walkSelectionSet($fragSelectionSet, $fragments, $currentDepth + 1);
                        $maxChildDepth = max($maxChildDepth, $childResult['depth']);
                        $result['field_count'] += $childResult['field_count'];
                        $result['alias_count'] += $childResult['alias_count'];
                        $result['introspection_fields'] = array_merge(
                            $result['introspection_fields'],
                            $childResult['introspection_fields']
                        );
                        $result['sensitive_fields'] = array_merge(
                            $result['sensitive_fields'],
                            $childResult['sensitive_fields']
                        );
                        $result['dangerous_directives'] = array_merge(
                            $result['dangerous_directives'],
                            $childResult['dangerous_directives']
                        );
                        $result['complexity'] += $childResult['complexity'];
                    }

                    $dirResult = self::checkDirectives($selection['directives'] ?? []);
                    if (!empty($dirResult['dangerous'])) {
                        $result['dangerous_directives'] = array_merge(
                            $result['dangerous_directives'],
                            $dirResult['dangerous']
                        );
                    }
                }
            } elseif ($kind === 'InlineFragment') {
                $fragSelectionSet = $selection['selection_set'] ?? null;
                if ($fragSelectionSet !== null) {
                    $childResult = self::walkSelectionSet($fragSelectionSet, $fragments, $currentDepth + 1);
                    $maxChildDepth = max($maxChildDepth, $childResult['depth']);
                    $result['field_count'] += $childResult['field_count'];
                    $result['alias_count'] += $childResult['alias_count'];
                    $result['introspection_fields'] = array_merge(
                        $result['introspection_fields'],
                        $childResult['introspection_fields']
                    );
                    $result['sensitive_fields'] = array_merge(
                        $result['sensitive_fields'],
                        $childResult['sensitive_fields']
                    );
                    $result['dangerous_directives'] = array_merge(
                        $result['dangerous_directives'],
                        $childResult['dangerous_directives']
                    );
                    $result['complexity'] += $childResult['complexity'];
                }

                $dirResult = self::checkDirectives($selection['directives'] ?? []);
                if (!empty($dirResult['dangerous'])) {
                    $result['dangerous_directives'] = array_merge(
                        $result['dangerous_directives'],
                        $dirResult['dangerous']
                    );
                }
            }
        }

        $result['depth'] = $maxChildDepth;
        return $result;
    }

    private static function checkDirectives(array $directives): array {
        $dangerous = [];
        $builtin = [];

        foreach ($directives as $dir) {
            $name = $dir['name'] ?? '';
            if (in_array($name, self::$builtinDirectives, true)) {
                $builtin[] = $name;
            } else {
                $lowerName = strtolower($name);
                foreach (self::$dangerousDirectivePatterns as $pattern) {
                    if (stripos($lowerName, $pattern) !== false) {
                        $dangerous[] = $name;
                        break;
                    }
                }
            }
        }

        return [
            'dangerous' => array_values(array_unique($dangerous)),
            'builtin'   => $builtin,
        ];
    }

    private static function isIntrospectionField(string $name): bool {
        return in_array($name, self::$introspectionFields, true);
    }

    private static function isSensitiveField(string $name): bool {
        $lowerName = strtolower($name);
        foreach (self::$sensitiveFieldNames as $sensitive) {
            if (stripos($lowerName, $sensitive) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检测循环片段引用
     */
    private static function detectCircularFragments(array $fragments): array {
        $cycles = [];
        $visited = [];
        $recursionStack = [];

        foreach ($fragments as $name => $fragment) {
            if (!isset($visited[$name])) {
                $cycleResult = self::dfsFragment($name, $fragments, $visited, $recursionStack, []);
                if (!empty($cycleResult)) {
                    $cycles[] = $cycleResult;
                }
            }
        }

        return [
            'has_circular' => !empty($cycles),
            'cycles'       => $cycles,
        ];
    }

    private static function dfsFragment(string $name, array $fragments, array &$visited, array &$recursionStack, array $path): array {
        if (isset($recursionStack[$name])) {
            $cycleStart = array_search($name, $path);
            if ($cycleStart !== false) {
                return array_slice($path, $cycleStart);
            }
            return [$name];
        }

        if (isset($visited[$name])) {
            return [];
        }

        if (!isset($fragments[$name])) {
            $visited[$name] = true;
            return [];
        }

        $visited[$name] = true;
        $recursionStack[$name] = true;
        $path[] = $name;

        $fragment = $fragments[$name];
        $spreads = self::extractFragmentSpreads($fragment['selection_set'] ?? null);

        foreach ($spreads as $spreadName) {
            $cycle = self::dfsFragment($spreadName, $fragments, $visited, $recursionStack, $path);
            if (!empty($cycle)) {
                unset($recursionStack[$name]);
                return $cycle;
            }
        }

        unset($recursionStack[$name]);
        return [];
    }

    private static function extractFragmentSpreads(?array $selectionSet): array {
        $spreads = [];
        if ($selectionSet === null) return $spreads;

        $selections = $selectionSet['selections'] ?? [];
        foreach ($selections as $sel) {
            $kind = $sel['kind'] ?? '';
            if ($kind === 'FragmentSpread') {
                $spreads[] = $sel['name'] ?? '';
            } elseif ($kind === 'Field' && !empty($sel['selection_set'])) {
                $spreads = array_merge($spreads, self::extractFragmentSpreads($sel['selection_set']));
            } elseif ($kind === 'InlineFragment' && !empty($sel['selection_set'])) {
                $spreads = array_merge($spreads, self::extractFragmentSpreads($sel['selection_set']));
            }
        }

        return $spreads;
    }

    // ==================== Scoring ====================

    private static function calculateScore(array $result): int {
        $score = 0;

        if ($result['has_introspection']) {
            $introScore = 0;
            foreach ($result['introspection_fields'] as $field) {
                if ($field === '__schema' || $field === '__type') {
                    $introScore += 30;
                } else {
                    $introScore += 15;
                }
            }
            $score += min($introScore, 60);
        }

        if ($result['query_depth'] > self::MAX_QUERY_DEPTH) {
            $excess = $result['query_depth'] - self::MAX_QUERY_DEPTH;
            $score += min(15 + $excess * 3, 35);
        }

        if ($result['field_count'] > self::MAX_FIELD_COUNT) {
            $excess = $result['field_count'] - self::MAX_FIELD_COUNT;
            $score += min(10 + (int)($excess / 10) * 2, 30);
        }

        if ($result['alias_count'] > 0 && $result['field_count'] > 0) {
            $aliasRatio = $result['alias_count'] / $result['field_count'];
            if ($aliasRatio > self::MAX_ALIAS_RATIO && $result['alias_count'] >= 5) {
                $score += min($result['alias_count'] * 2, 25);
            }
        }

        if ($result['has_dangerous_directives']) {
            $score += min(count($result['dangerous_directives']) * 20, 40);
        }

        if (!empty($result['sensitive_fields'])) {
            $sensScore = count($result['sensitive_fields']) * 10;
            $score += min($sensScore, 30);
        }

        if ($result['has_circular_fragments']) {
            $score += 25;
        }

        if ($result['fragment_count'] > 10) {
            $score += 10;
        }

        if ($result['complexity'] > 100) {
            $score += 15;
        }

        return min($score, 100);
    }

    private static function determineRiskLevel(int $score): string {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 20) return 'low';
        return 'clean';
    }

    // ==================== Regex Fallback ====================

    /**
     * 正则表达式 fallback：当 AST 解析失败时降级
     */
    private static function regexFallback(string $input): array {
        $result = [
            'is_graphql'               => false,
            'query_type'               => 'unknown',
            'has_introspection'        => false,
            'introspection_fields'     => [],
            'query_depth'              => 0,
            'field_count'              => 0,
            'alias_count'              => 0,
            'fragment_count'           => 0,
            'has_dangerous_directives' => false,
            'dangerous_directives'     => [],
            'sensitive_fields'         => [],
            'complexity'               => 0,
            'has_circular_fragments'   => false,
            'circular_fragments'       => [],
            'indicators'               => ['regex_fallback'],
            'parse_mode'               => 'regex',
        ];

        $hasGraphqlStructure = false;

        if (preg_match('/\b(query|mutation|subscription)\b/i', $input)) {
            $hasGraphqlStructure = true;
            if (preg_match('/\bquery\b/i', $input)) $result['query_type'] = 'query';
            elseif (preg_match('/\bmutation\b/i', $input)) $result['query_type'] = 'mutation';
            elseif (preg_match('/\bsubscription\b/i', $input)) $result['query_type'] = 'subscription';
        }

        if (preg_match('/\{[^{}]*\}/', $input)) {
            $hasGraphqlStructure = true;
        }

        $introMatches = [];
        if (preg_match_all('/__[a-zA-Z_]\w*/', $input, $introMatches)) {
            $result['has_introspection'] = true;
            $result['introspection_fields'] = array_values(array_unique($introMatches[0]));
        }

        $fragmentMatches = [];
        if (preg_match_all('/\bfragment\s+(\w+)\b/i', $input, $fragmentMatches)) {
            $result['fragment_count'] = count(array_unique($fragmentMatches[1]));
        }

        $braceDepth = 0;
        $maxDepth = 0;
        $len = strlen($input);
        for ($i = 0; $i < $len; $i++) {
            if ($input[$i] === '{') {
                $braceDepth++;
                $maxDepth = max($maxDepth, $braceDepth);
            } elseif ($input[$i] === '}') {
                $braceDepth--;
            }
        }
        $result['query_depth'] = $maxDepth;

        $fieldMatches = [];
        if (preg_match_all('/[a-zA-Z_]\w*\s*(?:\(|:\s*\{|\{)/', $input, $fieldMatches)) {
            $result['field_count'] = count($fieldMatches[0]);
        }

        $aliasMatches = [];
        if (preg_match_all('/[a-zA-Z_]\w*\s*:\s*[a-zA-Z_]\w*/', $input, $aliasMatches)) {
            $result['alias_count'] = count($aliasMatches[0]);
        }

        $sensitiveMatches = [];
        $sensitivePattern = '/\b(' . implode('|', self::$sensitiveFieldNames) . ')\b/i';
        if (preg_match_all($sensitivePattern, $input, $sensitiveMatches)) {
            $result['sensitive_fields'] = array_values(array_unique($sensitiveMatches[0]));
        }

        $directiveMatches = [];
        if (preg_match_all('/@([a-zA-Z_]\w*)/', $input, $directiveMatches)) {
            $directives = array_unique($directiveMatches[1]);
            $dangerous = [];
            foreach ($directives as $dir) {
                if (!in_array($dir, self::$builtinDirectives, true)) {
                    $lowerDir = strtolower($dir);
                    foreach (self::$dangerousDirectivePatterns as $pattern) {
                        if (stripos($lowerDir, $pattern) !== false) {
                            $dangerous[] = $dir;
                            break;
                        }
                    }
                }
            }
            if (!empty($dangerous)) {
                $result['has_dangerous_directives'] = true;
                $result['dangerous_directives'] = array_values($dangerous);
            }
        }

        $result['is_graphql'] = $hasGraphqlStructure || $result['has_introspection'] || $result['fragment_count'] > 0;

        $result['complexity'] = $result['field_count'] + $result['query_depth'] * 5;

        $score = 0;
        if ($result['has_introspection']) {
            $score += min(count($result['introspection_fields']) * 20, 50);
        }
        if ($result['query_depth'] > self::MAX_QUERY_DEPTH) {
            $score += 20;
        }
        if ($result['field_count'] > self::MAX_FIELD_COUNT) {
            $score += 15;
        }
        if ($result['has_dangerous_directives']) {
            $score += 25;
        }
        if (!empty($result['sensitive_fields'])) {
            $score += min(count($result['sensitive_fields']) * 8, 20);
        }

        $result['score'] = min($score, 100);
        $result['risk_level'] = self::determineRiskLevel($result['score']);

        return $result;
    }

    // ==================== Helpers ====================

    private static function determineQueryType(array $ast): string {
        $definitions = $ast['definitions'] ?? [];
        foreach ($definitions as $def) {
            if (($def['kind'] ?? '') === 'OperationDefinition') {
                return $def['operation'] ?? 'unknown';
            }
        }
        return 'unknown';
    }

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type'             => $ast['type'] ?? 'unknown',
            'definition_count' => count($ast['definitions'] ?? []),
            'fragment_count'   => count($ast['fragments'] ?? []),
        ];

        $operationTypes = [];
        foreach ($ast['definitions'] ?? [] as $def) {
            if (($def['kind'] ?? '') === 'OperationDefinition') {
                $operationTypes[] = $def['operation'] ?? 'unknown';
            }
        }
        if (!empty($operationTypes)) {
            $summary['operation_types'] = array_values(array_unique($operationTypes));
        }

        return $summary;
    }
}
