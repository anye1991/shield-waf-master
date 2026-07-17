<?php
/**
 * SQL 语义解析器
 * 职责：通过构建 SQL AST（抽象语法树）真正理解 SQL 结构，
 *       而非依赖正则匹配进行注入检测。
 */
defined('ABSPATH') || exit;

class SqlSemanticParser {

    const TOKEN_KEYWORD   = 'KEYWORD';
    const TOKEN_IDENT     = 'IDENT';
    const TOKEN_STRING    = 'STRING';
    const TOKEN_NUMBER    = 'NUMBER';
    const TOKEN_OPERATOR  = 'OPERATOR';
    const TOKEN_PUNCT     = 'PUNCT';
    const TOKEN_COMMENT   = 'COMMENT';
    const TOKEN_EOF       = 'EOF';

    private static $keywords = [
        'SELECT', 'FROM', 'WHERE', 'UNION', 'INSERT', 'UPDATE', 'DELETE',
        'DROP', 'OR', 'AND', 'NOT', 'NULL', 'TRUE', 'FALSE', 'LIKE', 'IN',
        'BETWEEN', 'EXISTS', 'ORDER', 'GROUP', 'BY', 'LIMIT', 'HAVING',
        'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'ON', 'AS', 'INTO',
        'VALUES', 'SET', 'ALTER', 'CREATE', 'TABLE', 'DATABASE', 'SCHEMA',
        'CONCAT', 'SLEEP', 'BENCHMARK', 'LOAD_FILE', 'OUTFILE', 'DUMPFILE',
        'INFORMATION_SCHEMA', 'ALL', 'DISTINCT', 'CASE', 'WHEN', 'THEN',
        'ELSE', 'END', 'IS', 'ASC', 'DESC', 'OFFSET', 'DECLARE', 'EXEC',
        'EXECUTE', 'CAST', 'CONVERT', 'SUBSTRING', 'SUBSTR', 'GROUP_CONCAT',
        'WAITFOR', 'DELAY', 'XP_CMDSHELL', 'TRUNCATE',
    ];

    private static $dangerousFunctions = [
        'SLEEP', 'BENCHMARK', 'LOAD_FILE', 'XP_CMDSHELL',
        'WAITFOR', 'DELAY', 'EXEC', 'EXECUTE', 'SYSTEM',
    ];

    private static $sensitiveTables = [
        'INFORMATION_SCHEMA', 'MYSQL', 'SYSOBJECTS', 'SYSCOLUMNS',
        'MASTER', 'USERS', 'ADMIN', 'PASSWORD', 'ACCOUNTS',
    ];

    /**
     * 主入口：分析 SQL 语句语义
     *
     * @param string $sql
     * @return array
     */
    public static function analyze(string $sql): array {
        $result = [
            'detected'                 => false,
            'score'                    => 0,
            'sql_type'                 => 'unknown',
            'has_tautology'            => false,
            'tautology_type'           => '',
            'has_union'                => false,
            'union_count'              => 0,
            'subquery_depth'           => 0,
            'dangerous_functions'      => [],
            'sensitive_tables'         => [],
            'has_comment_injection'    => false,
            'has_multiple_statements'  => false,
            'where_complexity'         => 0,
            'indicators'               => [],
            'ast_summary'              => [],
        ];

        if (trim($sql) === '') {
            return $result;
        }

        try {
            $tokens = self::tokenize($sql);
            if (empty($tokens)) {
                return $result;
            }

            $ast = self::parse($tokens, $sql);
            if (empty($ast)) {
                return $result;
            }

            $result['sql_type'] = $ast['type'] ?? 'unknown';
            $result['ast_summary'] = self::summarizeAst($ast);
            $result['union_count'] = $ast['union_count'] ?? 0;
            $result['has_union'] = $result['union_count'] > 0;
            $result['subquery_depth'] = $ast['max_subquery_depth'] ?? 0;

            if (!empty($ast['where'])) {
                $tautologyInfo = self::detectTautology($ast['where']);
                if ($tautologyInfo['is_tautology']) {
                    $result['has_tautology'] = true;
                    $result['tautology_type'] = $tautologyInfo['type'];
                    $result['indicators'][] = 'tautology:' . $tautologyInfo['type'];
                }
                $result['where_complexity'] = self::calcWhereComplexity($ast['where']);
            }

            $result['dangerous_functions'] = $ast['dangerous_functions'] ?? [];
            $result['sensitive_tables'] = $ast['sensitive_tables'] ?? [];

            $commentInfo = self::analyzeComments($sql, $ast);
            $result['has_comment_injection'] = $commentInfo['has_injection'];
            if ($commentInfo['has_injection']) {
                $result['indicators'][] = 'comment_injection';
            }

            $result['has_multiple_statements'] = self::detectMultipleStatements($tokens, $sql);
            if ($result['has_multiple_statements']) {
                $result['indicators'][] = 'multiple_statements';
            }

            $result['score'] = self::calculateScore($result);
            $result['detected'] = $result['score'] >= 30;

            if ($result['has_union']) {
                $result['indicators'][] = 'union_injection';
            }
            if (!empty($result['dangerous_functions'])) {
                $result['indicators'][] = 'dangerous_functions:' . implode(',', $result['dangerous_functions']);
            }
            if (!empty($result['sensitive_tables'])) {
                $result['indicators'][] = 'sensitive_tables:' . implode(',', $result['sensitive_tables']);
            }
            if ($result['subquery_depth'] > 2) {
                $result['indicators'][] = 'deep_subquery:' . $result['subquery_depth'];
            }

        } catch (Exception $e) {
            $result['indicators'][] = 'parse_error';
        }

        return $result;
    }

    // ==================== Tokenizer ====================

    /**
     * SQL 词法分析
     *
     * @param string $sql
     * @return array
     */
    private static function tokenize(string $sql): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($sql);
        $keywordMap = array_flip(self::$keywords);

        while ($pos < $len) {
            $char = $sql[$pos];

            if ($char === ' ' || $char === "\t" || $char === "\n" || $char === "\r") {
                $pos++;
                continue;
            }

            if ($char === '-' && $pos + 1 < $len && $sql[$pos + 1] === '-') {
                $start = $pos;
                $pos += 2;
                while ($pos < $len && $sql[$pos] !== "\n") {
                    $pos++;
                }
                $tokens[] = [
                    'type'  => self::TOKEN_COMMENT,
                    'value' => substr($sql, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === '#') {
                $start = $pos;
                $pos++;
                while ($pos < $len && $sql[$pos] !== "\n") {
                    $pos++;
                }
                $tokens[] = [
                    'type'  => self::TOKEN_COMMENT,
                    'value' => substr($sql, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === '/' && $pos + 1 < $len && $sql[$pos + 1] === '*') {
                $start = $pos;
                $pos += 2;
                while ($pos < $len - 1) {
                    if ($sql[$pos] === '*' && $sql[$pos + 1] === '/') {
                        $pos += 2;
                        break;
                    }
                    $pos++;
                }
                $tokens[] = [
                    'type'  => self::TOKEN_COMMENT,
                    'value' => substr($sql, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === "'" || $char === '"') {
                $quote = $char;
                $start = $pos;
                $pos++;
                $value = '';
                while ($pos < $len) {
                    if ($sql[$pos] === $quote) {
                        if ($pos + 1 < $len && $sql[$pos + 1] === $quote) {
                            $value .= $quote;
                            $pos += 2;
                        } else {
                            $pos++;
                            break;
                        }
                    } elseif ($sql[$pos] === '\\' && $pos + 1 < $len) {
                        $value .= $sql[$pos] . $sql[$pos + 1];
                        $pos += 2;
                    } else {
                        $value .= $sql[$pos];
                        $pos++;
                    }
                }
                $tokens[] = [
                    'type'    => self::TOKEN_STRING,
                    'value'   => $value,
                    'raw'     => substr($sql, $start, $pos - $start),
                    'pos'     => $start,
                    'quoted'  => $quote,
                ];
                continue;
            }

            if (is_numeric($char) || ($char === '.' && $pos + 1 < $len && is_numeric($sql[$pos + 1]))) {
                $start = $pos;
                $hasDot = false;
                while ($pos < $len && (is_numeric($sql[$pos]) || ($sql[$pos] === '.' && !$hasDot))) {
                    if ($sql[$pos] === '.') $hasDot = true;
                    $pos++;
                }
                if ($pos < $len && ($sql[$pos] === 'e' || $sql[$pos] === 'E')) {
                    $pos++;
                    if ($pos < $len && ($sql[$pos] === '+' || $sql[$pos] === '-')) $pos++;
                    while ($pos < $len && is_numeric($sql[$pos])) $pos++;
                }
                $tokens[] = [
                    'type'  => self::TOKEN_NUMBER,
                    'value' => substr($sql, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if (ctype_alpha($char) || $char === '_' || $char === '`') {
                $start = $pos;
                $quoted = false;
                if ($char === '`') {
                    $quoted = true;
                    $pos++;
                    while ($pos < $len && $sql[$pos] !== '`') {
                        $pos++;
                    }
                    if ($pos < $len) $pos++;
                } else {
                    while ($pos < $len && (ctype_alnum($sql[$pos]) || $sql[$pos] === '_')) {
                        $pos++;
                    }
                }
                $word = substr($sql, $start, $pos - $start);
                $upper = strtoupper(str_replace('`', '', $word));

                $type = isset($keywordMap[$upper]) ? self::TOKEN_KEYWORD : self::TOKEN_IDENT;
                $tokens[] = [
                    'type'     => $type,
                    'value'    => $upper,
                    'raw'      => $word,
                    'pos'      => $start,
                    'is_quoted' => $quoted,
                ];
                continue;
            }

            $twoChar = substr($sql, $pos, 2);
            $threeChar = substr($sql, $pos, 3);
            if (in_array($threeChar, ['!==', '<=>'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $threeChar, 'pos' => $pos];
                $pos += 3;
                continue;
            }
            if (in_array($twoChar, ['!=', '<>', '<=', '>=', '||', '&&', ':=', '->', '::'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $twoChar, 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if (in_array($char, ['=', '<', '>', '+', '-', '*', '/', '%', '~', '&', '|', '^', '!'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            if (in_array($char, ['(', ')', ',', '.', ';'])) {
                $tokens[] = ['type' => self::TOKEN_PUNCT, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            $pos++;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    // ==================== Parser ====================

    /**
     * SQL 语法分析，构建 AST
     *
     * @param array $tokens
     * @param string $sql
     * @return array|null
     */
    private static function parse(array $tokens, string $sql): ?array {
        $state = [
            'tokens'   => $tokens,
            'pos'      => 0,
            'sql'      => $sql,
            'dangerous_functions' => [],
            'sensitive_tables'    => [],
            'max_subquery_depth'  => 0,
            'union_count'         => 0,
        ];

        $ast = self::parseStatement($state);
        if ($ast === null) {
            return null;
        }

        $ast['dangerous_functions'] = array_values(array_unique($state['dangerous_functions']));
        $ast['sensitive_tables']    = array_values(array_unique($state['sensitive_tables']));
        $ast['max_subquery_depth']  = $state['max_subquery_depth'];
        $ast['union_count']         = $state['union_count'];

        return $ast;
    }

    private static function parseStatement(array &$state): ?array {
        self::skipCommentsAndSemicolons($state);

        if (self::isEof($state)) {
            return null;
        }

        $token = self::current($state);

        switch ($token['value']) {
            case 'SELECT':
                return self::parseSelectStatement($state);
            case 'INSERT':
                return self::parseInsertStatement($state);
            case 'UPDATE':
                return self::parseUpdateStatement($state);
            case 'DELETE':
                return self::parseDeleteStatement($state);
            case 'DROP':
                return self::parseDropStatement($state);
            case 'ALTER':
                return self::parseAlterStatement($state);
            case 'CREATE':
                return self::parseCreateStatement($state);
            default:
                return self::parseUnknownStatement($state);
        }
    }

    private static function parseSelectStatement(array &$state, int $depth = 0): array {
        $ast = [
            'type'        => 'select',
            'select'      => [],
            'from'        => [],
            'where'       => null,
            'group_by'    => [],
            'having'      => null,
            'order_by'    => [],
            'limit'       => null,
        ];

        self::next($state);

        $ast['select'] = self::parseSelectExpressions($state);

        if (self::matchKeyword($state, 'FROM')) {
            $ast['from'] = self::parseFromClause($state, $depth);
        }

        if (self::matchKeyword($state, 'WHERE')) {
            $ast['where'] = self::parseExpression($state, $depth);
        }

        if (self::matchKeyword($state, 'GROUP')) {
            self::matchKeyword($state, 'BY');
            $ast['group_by'] = self::parseExpressionList($state, $depth);
        }

        if (self::matchKeyword($state, 'HAVING')) {
            $ast['having'] = self::parseExpression($state, $depth);
        }

        if (self::matchKeyword($state, 'ORDER')) {
            self::matchKeyword($state, 'BY');
            $ast['order_by'] = self::parseOrderBy($state, $depth);
        }

        if (self::matchKeyword($state, 'LIMIT')) {
            $ast['limit'] = self::parseLimit($state);
        }

        if (self::matchKeyword($state, 'UNION')) {
            $state['union_count']++;
            $isAll = self::matchKeyword($state, 'ALL');
            $ast['has_union'] = true;
            $ast['union_all'] = $isAll;
            $nextSelect = self::parseSelectStatement($state, $depth);
            $ast['union'] = $nextSelect;
            $ast['union_count_total'] = 1 + ($nextSelect['union_count_total'] ?? 0);
            if (isset($nextSelect['union_count_total'])) {
                $state['union_count'] += $nextSelect['union_count_total'];
            }
        }

        $currentDepth = $depth + 1;
        if ($currentDepth > $state['max_subquery_depth']) {
            $state['max_subquery_depth'] = $currentDepth;
        }

        return $ast;
    }

    private static function parseSelectExpressions(array &$state): array {
        $exprs = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_KEYWORD &&
                in_array($token['value'], ['FROM', 'WHERE', 'GROUP', 'ORDER', 'LIMIT', 'HAVING', 'UNION', 'INTO'])) {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ';') {
                break;
            }
            if ($token['type'] === self::TOKEN_EOF) {
                break;
            }

            if (!empty($exprs) && $token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }

            $expr = self::parseExpression($state, 0);
            if ($expr !== null) {
                $exprs[] = $expr;
            } else {
                self::next($state);
            }
        }
        return $exprs;
    }

    private static function parseFromClause(array &$state, int $depth): array {
        $tables = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_KEYWORD &&
                in_array($token['value'], ['WHERE', 'GROUP', 'ORDER', 'LIMIT', 'HAVING', 'UNION', 'INTO'])) {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ';') {
                break;
            }
            if ($token['type'] === self::TOKEN_EOF) {
                break;
            }

            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '(') {
                $subquery = self::parseSubquery($state, $depth + 1);
                if ($subquery !== null) {
                    $tables[] = ['type' => 'subquery', 'query' => $subquery];
                    if (self::matchKeyword($state, 'AS')) {
                        $alias = self::current($state);
                        if ($alias['type'] === self::TOKEN_IDENT || $alias['type'] === self::TOKEN_KEYWORD) {
                            $tables[count($tables) - 1]['alias'] = $alias['value'];
                            self::next($state);
                        }
                    }
                    continue;
                }
            }

            if (in_array($token['value'], ['JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'NATURAL'])) {
                while (!self::isEof($state) &&
                       self::current($state)['type'] === self::TOKEN_KEYWORD &&
                       in_array(self::current($state)['value'], ['JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'NATURAL', 'FULL'])) {
                    self::next($state);
                }
                $table = self::parseTableRef($state, $depth);
                if ($table !== null) {
                    $table['join_type'] = 'join';
                    $tables[] = $table;
                }
                if (self::matchKeyword($state, 'ON')) {
                    $tables[count($tables) - 1]['on'] = self::parseExpression($state, $depth);
                }
                continue;
            }

            $table = self::parseTableRef($state, $depth);
            if ($table !== null) {
                $tables[] = $table;
            } else {
                self::next($state);
            }
        }
        return $tables;
    }

    private static function parseTableRef(array &$state, int $depth): ?array {
        $token = self::current($state);
        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '(') {
            return self::parseSubquery($state, $depth + 1);
        }

        if ($token['type'] !== self::TOKEN_IDENT && $token['type'] !== self::TOKEN_KEYWORD) {
            return null;
        }

        $tableName = $token['value'];
        self::next($state);

        $schema = null;
        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '.') {
            self::next($state);
            $schema = $tableName;
            $t2 = self::current($state);
            if ($t2['type'] === self::TOKEN_IDENT || $t2['type'] === self::TOKEN_KEYWORD) {
                $tableName = $t2['value'];
                self::next($state);
            }
        }

        $fullName = $schema ? $schema . '.' . $tableName : $tableName;
        self::checkSensitiveTable($fullName, $state);

        $alias = null;
        if (self::matchKeyword($state, 'AS')) {
            $a = self::current($state);
            if ($a['type'] === self::TOKEN_IDENT || $a['type'] === self::TOKEN_KEYWORD) {
                $alias = $a['value'];
                self::next($state);
            }
        } elseif (self::current($state)['type'] === self::TOKEN_IDENT) {
            $next = self::peek($state, 1);
            if ($next && !in_array($next['value'], ['WHERE', 'AND', 'OR', 'ON', 'JOIN', ',', 'GROUP', 'ORDER', 'LIMIT', 'HAVING', 'UNION'])) {
                $alias = self::current($state)['value'];
                self::next($state);
            }
        }

        return [
            'type'   => 'table',
            'name'   => $tableName,
            'schema' => $schema,
            'full_name' => $fullName,
            'alias'  => $alias,
        ];
    }

    private static function parseSubquery(array &$state, int $depth): ?array {
        if (self::current($state)['type'] !== self::TOKEN_PUNCT || self::current($state)['value'] !== '(') {
            return null;
        }
        self::next($state);

        $result = null;
        if (self::matchKeyword($state, 'SELECT')) {
            $result = self::parseSelectStatement($state, $depth);
            $result['is_subquery'] = true;
        }

        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
            self::next($state);
        }

        return $result;
    }

    // ==================== Expression Parser ====================

    private static function parseExpression(array &$state, int $depth): ?array {
        return self::parseOrExpr($state, $depth);
    }

    private static function parseOrExpr(array &$state, int $depth): ?array {
        $left = self::parseAndExpr($state, $depth);
        if ($left === null) return null;

        while (true) {
            if (self::matchKeyword($state, 'OR')) {
                $right = self::parseAndExpr($state, $depth);
                $left = [
                    'type'  => 'or',
                    'left'  => $left,
                    'right' => $right,
                ];
            } elseif (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '||') {
                self::next($state);
                $right = self::parseAndExpr($state, $depth);
                $left = [
                    'type'  => 'or',
                    'left'  => $left,
                    'right' => $right,
                ];
            } else {
                break;
            }
        }
        return $left;
    }

    private static function parseAndExpr(array &$state, int $depth): ?array {
        $left = self::parseNotExpr($state, $depth);
        if ($left === null) return null;

        while (true) {
            if (self::matchKeyword($state, 'AND')) {
                $right = self::parseNotExpr($state, $depth);
                $left = [
                    'type'  => 'and',
                    'left'  => $left,
                    'right' => $right,
                ];
            } elseif (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '&&') {
                self::next($state);
                $right = self::parseNotExpr($state, $depth);
                $left = [
                    'type'  => 'and',
                    'left'  => $left,
                    'right' => $right,
                ];
            } else {
                break;
            }
        }
        return $left;
    }

    private static function parseNotExpr(array &$state, int $depth): ?array {
        if (self::matchKeyword($state, 'NOT')) {
            $expr = self::parseNotExpr($state, $depth);
            return ['type' => 'not', 'expr' => $expr];
        }
        if (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '!') {
            self::next($state);
            $expr = self::parseNotExpr($state, $depth);
            return ['type' => 'not', 'expr' => $expr];
        }
        return self::parseComparison($state, $depth);
    }

    private static function parseComparison(array &$state, int $depth): ?array {
        $left = self::parseAddExpr($state, $depth);
        if ($left === null) return null;

        $token = self::current($state);
        $op = null;

        if ($token['type'] === self::TOKEN_OPERATOR &&
            in_array($token['value'], ['=', '!=', '<>', '<', '>', '<=', '>=', '<=>'])) {
            $op = $token['value'];
        } elseif ($token['type'] === self::TOKEN_KEYWORD && in_array($token['value'], ['LIKE', 'IN', 'BETWEEN', 'IS'])) {
            $op = $token['value'];
        }

        if ($op !== null) {
            self::next($state);

            if ($op === 'IN') {
                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '(') {
                    $next = self::peek($state, 1);
                    if ($next && $next['value'] === 'SELECT') {
                        $subquery = self::parseSubquery($state, $depth + 1);
                        return [
                            'type'  => 'in_subquery',
                            'left'  => $left,
                            'query' => $subquery,
                        ];
                    }
                    self::next($state);
                    $values = self::parseExpressionList($state, $depth);
                    if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                        self::next($state);
                    }
                    return [
                        'type'   => 'in',
                        'left'   => $left,
                        'values' => $values,
                    ];
                }
            }

            if ($op === 'BETWEEN') {
                $low = self::parseAddExpr($state, $depth);
                self::matchKeyword($state, 'AND');
                $high = self::parseAddExpr($state, $depth);
                return [
                    'type' => 'between',
                    'left' => $left,
                    'low'  => $low,
                    'high' => $high,
                ];
            }

            if ($op === 'IS') {
                self::matchKeyword($state, 'NOT');
                $right = self::parsePrimary($state, $depth);
                return [
                    'type' => 'is',
                    'left' => $left,
                    'right' => $right,
                    'not'  => self::current($state - 1)['value'] === 'NOT',
                ];
            }

            $right = self::parseAddExpr($state, $depth);
            return [
                'type'  => 'comparison',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }

        return $left;
    }

    private static function parseAddExpr(array &$state, int $depth): ?array {
        $left = self::parseMulExpr($state, $depth);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['+', '-', '||'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseMulExpr($state, $depth);
            $left = [
                'type'  => 'binary_op',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    private static function parseMulExpr(array &$state, int $depth): ?array {
        $left = self::parseUnary($state, $depth);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['*', '/', '%'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseUnary($state, $depth);
            $left = [
                'type'  => 'binary_op',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    private static function parseUnary(array &$state, int $depth): ?array {
        if (self::current($state)['type'] === self::TOKEN_OPERATOR &&
            in_array(self::current($state)['value'], ['+', '-', '~', '!'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $expr = self::parseUnary($state, $depth);
            return ['type' => 'unary_op', 'op' => $op, 'expr' => $expr];
        }
        return self::parsePrimary($state, $depth);
    }

    private static function parsePrimary(array &$state, int $depth): ?array {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_NUMBER) {
            self::next($state);
            return ['type' => 'literal', 'subtype' => 'number', 'value' => $token['value']];
        }

        if ($token['type'] === self::TOKEN_STRING) {
            self::next($state);
            return ['type' => 'literal', 'subtype' => 'string', 'value' => $token['value']];
        }

        if ($token['type'] === self::TOKEN_KEYWORD) {
            if ($token['value'] === 'NULL') {
                self::next($state);
                return ['type' => 'literal', 'subtype' => 'null', 'value' => null];
            }
            if ($token['value'] === 'TRUE') {
                self::next($state);
                return ['type' => 'literal', 'subtype' => 'bool', 'value' => true];
            }
            if ($token['value'] === 'FALSE') {
                self::next($state);
                return ['type' => 'literal', 'subtype' => 'bool', 'value' => false];
            }
            if ($token['value'] === 'EXISTS') {
                self::next($state);
                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '(') {
                    $subquery = self::parseSubquery($state, $depth + 1);
                    return ['type' => 'exists', 'query' => $subquery];
                }
            }
            if ($token['value'] === 'CASE') {
                return self::parseCaseExpr($state, $depth);
            }
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '(') {
            $next = self::peek($state, 1);
            if ($next && $next['value'] === 'SELECT') {
                return self::parseSubquery($state, $depth + 1);
            }
            self::next($state);
            $expr = self::parseExpression($state, $depth);
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                self::next($state);
            }
            return $expr;
        }

        if ($token['type'] === self::TOKEN_IDENT || $token['type'] === self::TOKEN_KEYWORD) {
            $next = self::peek($state, 1);
            if ($next && $next['type'] === self::TOKEN_PUNCT && $next['value'] === '(') {
                return self::parseFunctionCall($state, $depth);
            }

            $name = $token['value'];
            self::next($state);

            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '.') {
                self::next($state);
                $col = self::current($state);
                if ($col['type'] === self::TOKEN_IDENT || $col['type'] === self::TOKEN_KEYWORD) {
                    self::next($state);
                    $fullName = $name . '.' . $col['value'];
                    self::checkSensitiveTable($name, $state);
                    return ['type' => 'column', 'table' => $name, 'name' => $col['value'], 'full_name' => $fullName];
                }
            }

            return ['type' => 'identifier', 'value' => $name];
        }

        return null;
    }

    private static function parseFunctionCall(array &$state, int $depth): array {
        $funcName = self::current($state)['value'];
        self::next($state);
        self::next($state);

        self::checkDangerousFunction($funcName, $state);

        $args = [];
        if (self::current($state)['type'] !== self::TOKEN_PUNCT || self::current($state)['value'] !== ')') {
            $args = self::parseExpressionList($state, $depth);
        }

        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
            self::next($state);
        }

        return [
            'type'      => 'function_call',
            'name'      => $funcName,
            'arguments' => $args,
        ];
    }

    private static function parseCaseExpr(array &$state, int $depth): array {
        self::next($state);
        $cases = [];
        $default = null;

        while (!self::isEof($state) && self::current($state)['value'] !== 'END') {
            if (self::matchKeyword($state, 'WHEN')) {
                $condition = self::parseExpression($state, $depth);
                self::matchKeyword($state, 'THEN');
                $result = self::parseExpression($state, $depth);
                $cases[] = ['when' => $condition, 'then' => $result];
            } elseif (self::matchKeyword($state, 'ELSE')) {
                $default = self::parseExpression($state, $depth);
            } else {
                break;
            }
        }
        self::matchKeyword($state, 'END');

        return [
            'type'    => 'case',
            'cases'   => $cases,
            'default' => $default,
        ];
    }

    private static function parseExpressionList(array &$state, int $depth): array {
        $exprs = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ')') {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_KEYWORD &&
                in_array($token['value'], ['FROM', 'WHERE', 'GROUP', 'ORDER', 'LIMIT', 'HAVING', 'UNION'])) {
                break;
            }

            $expr = self::parseExpression($state, $depth);
            if ($expr !== null) {
                $exprs[] = $expr;
            } else {
                break;
            }
        }
        return $exprs;
    }

    private static function parseOrderBy(array &$state, int $depth): array {
        $items = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_KEYWORD && in_array($token['value'], ['LIMIT', 'UNION', 'INTO', 'FOR'])) {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ';') {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }

            $expr = self::parseExpression($state, $depth);
            if ($expr === null) break;

            $dir = 'ASC';
            if (self::matchKeyword($state, 'ASC')) {
                $dir = 'ASC';
            } elseif (self::matchKeyword($state, 'DESC')) {
                $dir = 'DESC';
            }

            $items[] = ['expr' => $expr, 'dir' => $dir];
        }
        return $items;
    }

    private static function parseLimit(array &$state): ?array {
        $offset = null;
        $count = null;

        $t1 = self::current($state);
        if ($t1['type'] === self::TOKEN_NUMBER) {
            $val1 = $t1['value'];
            self::next($state);

            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ',') {
                self::next($state);
                $offset = $val1;
                $t2 = self::current($state);
                if ($t2['type'] === self::TOKEN_NUMBER) {
                    $count = $t2['value'];
                    self::next($state);
                }
            } elseif (self::matchKeyword($state, 'OFFSET')) {
                $count = $val1;
                $t2 = self::current($state);
                if ($t2['type'] === self::TOKEN_NUMBER) {
                    $offset = $t2['value'];
                    self::next($state);
                }
            } else {
                $count = $val1;
            }
        }

        return ['offset' => $offset, 'count' => $count];
    }

    // ==================== Other Statement Parsers ====================

    private static function parseInsertStatement(array &$state): array {
        $ast = ['type' => 'insert', 'table' => null, 'columns' => [], 'values' => []];
        self::next($state);
        self::matchKeyword($state, 'INTO');

        $table = self::parseTableRef($state, 0);
        $ast['table'] = $table;

        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '(') {
            self::next($state);
            $ast['columns'] = self::parseExpressionList($state, 0);
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                self::next($state);
            }
        }

        if (self::matchKeyword($state, 'VALUES')) {
            $ast['values'] = self::parseValueLists($state);
        } elseif (self::matchKeyword($state, 'SELECT')) {
            $ast['select'] = self::parseSelectStatement($state, 0);
        }

        return $ast;
    }

    private static function parseValueLists(array &$state): array {
        $lists = [];
        while (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '(') {
            self::next($state);
            $values = self::parseExpressionList($state, 0);
            $lists[] = $values;
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                self::next($state);
            }
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ',') {
                self::next($state);
            } else {
                break;
            }
        }
        return $lists;
    }

    private static function parseUpdateStatement(array &$state): array {
        $ast = ['type' => 'update', 'table' => null, 'set' => [], 'where' => null];
        self::next($state);

        $table = self::parseTableRef($state, 0);
        $ast['table'] = $table;

        if (self::matchKeyword($state, 'SET')) {
            $setItems = [];
            while (!self::isEof($state)) {
                $token = self::current($state);
                if ($token['type'] === self::TOKEN_KEYWORD && $token['value'] === 'WHERE') break;
                if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ';') break;
                if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                    self::next($state);
                    continue;
                }

                $col = self::parseExpression($state, 0);
                $op = null;
                if (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '=') {
                    $op = '=';
                    self::next($state);
                }
                $val = self::parseExpression($state, 0);
                $setItems[] = ['column' => $col, 'value' => $val, 'op' => $op];

                if (self::current($state)['type'] !== self::TOKEN_PUNCT || self::current($state)['value'] !== ',') {
                    break;
                }
            }
            $ast['set'] = $setItems;
        }

        if (self::matchKeyword($state, 'WHERE')) {
            $ast['where'] = self::parseExpression($state, 0);
        }

        return $ast;
    }

    private static function parseDeleteStatement(array &$state): array {
        $ast = ['type' => 'delete', 'table' => null, 'where' => null];
        self::next($state);
        self::matchKeyword($state, 'FROM');

        $table = self::parseTableRef($state, 0);
        $ast['table'] = $table;

        if (self::matchKeyword($state, 'WHERE')) {
            $ast['where'] = self::parseExpression($state, 0);
        }

        return $ast;
    }

    private static function parseDropStatement(array &$state): array {
        $ast = ['type' => 'drop', 'object_type' => null, 'object_name' => null];
        self::next($state);

        $token = self::current($state);
        if ($token['type'] === self::TOKEN_KEYWORD && in_array($token['value'], ['TABLE', 'DATABASE', 'SCHEMA', 'INDEX', 'VIEW'])) {
            $ast['object_type'] = strtolower($token['value']);
            self::next($state);
        }

        $name = self::current($state);
        if ($name['type'] === self::TOKEN_IDENT || $name['type'] === self::TOKEN_KEYWORD) {
            $ast['object_name'] = $name['value'];
            self::checkSensitiveTable($name['value'], $state);
            self::next($state);
        }

        return $ast;
    }

    private static function parseAlterStatement(array &$state): array {
        $ast = ['type' => 'alter', 'object_type' => null, 'object_name' => null];
        self::next($state);

        $token = self::current($state);
        if ($token['type'] === self::TOKEN_KEYWORD && in_array($token['value'], ['TABLE', 'DATABASE', 'SCHEMA'])) {
            $ast['object_type'] = strtolower($token['value']);
            self::next($state);
        }

        $name = self::current($state);
        if ($name['type'] === self::TOKEN_IDENT || $name['type'] === self::TOKEN_KEYWORD) {
            $ast['object_name'] = $name['value'];
            self::checkSensitiveTable($name['value'], $state);
            self::next($state);
        }

        return $ast;
    }

    private static function parseCreateStatement(array &$state): array {
        $ast = ['type' => 'create', 'object_type' => null, 'object_name' => null];
        self::next($state);

        $token = self::current($state);
        if ($token['type'] === self::TOKEN_KEYWORD && in_array($token['value'], ['TABLE', 'DATABASE', 'SCHEMA', 'INDEX', 'VIEW', 'FUNCTION', 'PROCEDURE'])) {
            $ast['object_type'] = strtolower($token['value']);
            self::next($state);
        }

        $name = self::current($state);
        if ($name['type'] === self::TOKEN_IDENT || $name['type'] === self::TOKEN_KEYWORD) {
            $ast['object_name'] = $name['value'];
            self::next($state);
        }

        return $ast;
    }

    private static function parseUnknownStatement(array &$state): array {
        $ast = ['type' => 'unknown', 'tokens' => []];
        while (!self::isEof($state)) {
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ';') {
                break;
            }
            $ast['tokens'][] = self::current($state);
            self::next($state);
        }
        return $ast;
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function peek(array &$state, int $offset): ?array {
        return $state['tokens'][$state['pos'] + $offset] ?? null;
    }

    private static function next(array &$state): void {
        if ($state['pos'] < count($state['tokens']) - 1) {
            $state['pos']++;
        }
    }

    private static function isEof(array &$state): bool {
        $t = self::current($state);
        return $t['type'] === self::TOKEN_EOF;
    }

    private static function matchKeyword(array &$state, string $keyword): bool {
        $t = self::current($state);
        if ($t['type'] === self::TOKEN_KEYWORD && $t['value'] === strtoupper($keyword)) {
            self::next($state);
            return true;
        }
        return false;
    }

    private static function skipCommentsAndSemicolons(array &$state): void {
        while (!self::isEof($state)) {
            $t = self::current($state);
            if ($t['type'] === self::TOKEN_COMMENT) {
                self::next($state);
            } elseif ($t['type'] === self::TOKEN_PUNCT && $t['value'] === ';') {
                self::next($state);
            } else {
                break;
            }
        }
    }

    // ==================== Semantic Analysis ====================

    /**
     * 恒真条件检测
     */
    private static function detectTautology(?array $expr): array {
        if ($expr === null) {
            return ['is_tautology' => false, 'type' => ''];
        }

        $result = self::evalTautology($expr);
        return $result;
    }

    private static function evalTautology(?array $expr): array {
        if ($expr === null) {
            return ['is_tautology' => false, 'type' => ''];
        }

        $type = $expr['type'] ?? '';

        if ($type === 'or') {
            $left = self::evalTautology($expr['left'] ?? null);
            $right = self::evalTautology($expr['right'] ?? null);

            if ($left['is_tautology'] || $right['is_tautology']) {
                return ['is_tautology' => true, 'type' => 'or_injection'];
            }
            return ['is_tautology' => false, 'type' => ''];
        }

        if ($type === 'and') {
            $left = self::evalTautology($expr['left'] ?? null);
            $right = self::evalTautology($expr['right'] ?? null);

            if ($left['is_tautology'] && $right['is_tautology']) {
                return ['is_tautology' => true, 'type' => $left['type']];
            }
            return ['is_tautology' => false, 'type' => ''];
        }

        if ($type === 'not') {
            $inner = self::evalTautology($expr['expr'] ?? null);
            if ($inner['is_tautology'] && $inner['type'] === 'always_true') {
                return ['is_tautology' => false, 'type' => ''];
            }
            if (isset($expr['expr']['type']) && $expr['expr']['type'] === 'literal' && $expr['expr']['subtype'] === 'null') {
                return ['is_tautology' => false, 'type' => ''];
            }
            return ['is_tautology' => false, 'type' => ''];
        }

        if ($type === 'comparison') {
            $op = $expr['op'] ?? '';
            $left = $expr['left'] ?? null;
            $right = $expr['right'] ?? null;

            if ($op === '=' && $left && $right) {
                $leftLit = self::extractLiteralValue($left);
                $rightLit = self::extractLiteralValue($right);

                if ($leftLit !== null && $rightLit !== null) {
                    if ($leftLit['type'] === 'number' && $rightLit['type'] === 'number') {
                        if ($leftLit['value'] == $rightLit['value']) {
                            return ['is_tautology' => true, 'type' => 'numeric_equal'];
                        }
                    }
                    if ($leftLit['type'] === 'string' && $rightLit['type'] === 'string') {
                        if ($leftLit['value'] === $rightLit['value']) {
                            return ['is_tautology' => true, 'type' => 'string_equal'];
                        }
                    }
                }

                $leftIdent = self::extractIdentifier($left);
                $rightIdent = self::extractIdentifier($right);
                if ($leftIdent !== null && $rightIdent !== null && $leftIdent === $rightIdent) {
                    return ['is_tautology' => true, 'type' => 'column_equal'];
                }
            }

            if (in_array($op, ['!=', '<>']) && $left && $right) {
                $leftLit = self::extractLiteralValue($left);
                $rightLit = self::extractLiteralValue($right);
                if ($leftLit !== null && $rightLit !== null) {
                    if ($leftLit['type'] === 'number' && $rightLit['type'] === 'number') {
                        if ($leftLit['value'] != $rightLit['value']) {
                            return ['is_tautology' => true, 'type' => 'numeric_unequal'];
                        }
                    }
                }
            }
        }

        if ($type === 'literal') {
            $subtype = $expr['subtype'] ?? '';
            if ($subtype === 'bool' && $expr['value'] === true) {
                return ['is_tautology' => true, 'type' => 'always_true'];
            }
            if ($subtype === 'number') {
                $val = $expr['value'];
                if (is_numeric($val) && $val != 0) {
                    return ['is_tautology' => true, 'type' => 'always_true'];
                }
            }
        }

        if ($type === 'is') {
            $right = $expr['right'] ?? null;
            if ($right && $right['type'] === 'literal' && $right['subtype'] === 'null') {
                if (!empty($expr['not'])) {
                    return ['is_tautology' => false, 'type' => ''];
                }
            }
        }

        if ($type === 'between') {
            return ['is_tautology' => false, 'type' => ''];
        }

        if ($type === 'binary_op') {
            return ['is_tautology' => false, 'type' => ''];
        }

        return ['is_tautology' => false, 'type' => ''];
    }

    private static function extractLiteralValue(array $expr): ?array {
        if ($expr['type'] === 'literal') {
            return [
                'type'  => $expr['subtype'] ?? 'unknown',
                'value' => $expr['value'],
            ];
        }
        if ($expr['type'] === 'unary_op' && $expr['op'] === '-') {
            $inner = self::extractLiteralValue($expr['expr']);
            if ($inner && $inner['type'] === 'number') {
                return ['type' => 'number', 'value' => -$inner['value']];
            }
        }
        return null;
    }

    private static function extractIdentifier(array $expr): ?string {
        if ($expr['type'] === 'identifier') {
            return $expr['value'];
        }
        if ($expr['type'] === 'column') {
            return $expr['full_name'] ?? $expr['name'];
        }
        return null;
    }

    /**
     * 注释分析
     */
    private static function analyzeComments(string $sql, array $ast): array {
        $hasInjection = false;
        $commentCount = 0;
        $commentPositions = [];

        $tokens = self::tokenize($sql);
        $whereEndPos = null;
        $statementEndPos = null;

        foreach ($tokens as $i => $token) {
            if ($token['type'] === self::TOKEN_COMMENT) {
                $commentCount++;
                $commentPositions[] = $token['pos'];
            }
        }

        foreach ($tokens as $i => $token) {
            if ($token['type'] === self::TOKEN_KEYWORD && $token['value'] === 'WHERE') {
                for ($j = $i + 1; $j < count($tokens); $j++) {
                    if ($tokens[$j]['type'] === self::TOKEN_COMMENT) {
                        $commentText = $tokens[$j]['value'];
                        if (strpos($commentText, '--') === 0 || strpos($commentText, '#') === 0) {
                            $hasInjection = true;
                            break 2;
                        }
                    }
                    if ($tokens[$j]['type'] === self::TOKEN_KEYWORD &&
                        in_array($tokens[$j]['value'], ['GROUP', 'ORDER', 'LIMIT', 'HAVING', 'UNION'])) {
                        break;
                    }
                    if ($tokens[$j]['type'] === self::TOKEN_PUNCT && $tokens[$j]['value'] === ';') {
                        break;
                    }
                    if ($tokens[$j]['type'] === self::TOKEN_EOF) {
                        break;
                    }
                }
            }
        }

        $lastSignificantToken = null;
        foreach ($tokens as $token) {
            if ($token['type'] !== self::TOKEN_COMMENT && $token['type'] !== self::TOKEN_EOF) {
                if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ';') {
                    continue;
                }
                $lastSignificantToken = $token;
            }
        }

        $lastCommentPos = -1;
        foreach ($tokens as $token) {
            if ($token['type'] === self::TOKEN_COMMENT) {
                $lastCommentPos = $token['pos'];
            }
        }

        if ($lastSignificantToken && $lastCommentPos > $lastSignificantToken['pos']) {
            foreach ($tokens as $token) {
                if ($token['type'] === self::TOKEN_COMMENT && $token['pos'] == $lastCommentPos) {
                    $commentText = $token['value'];
                    if (strpos($commentText, '--') === 0 || strpos($commentText, '#') === 0) {
                        $hasInjection = true;
                    }
                    break;
                }
            }
        }

        if (preg_match_all('/\/\*[\s\S]*?\*\//', $sql, $blockMatches)) {
            foreach ($blockMatches[0] as $block) {
                $inner = substr($block, 2, -2);
                if (preg_match('/\b(?:SELECT|UNION|DROP|INSERT|UPDATE|DELETE|SLEEP|BENCHMARK)\b/i', $inner)) {
                    $hasInjection = true;
                    break;
                }
            }
        }

        return [
            'has_injection'     => $hasInjection,
            'comment_count'     => $commentCount,
            'comment_positions' => $commentPositions,
        ];
    }

    /**
     * 多语句检测
     */
    private static function detectMultipleStatements(array $tokens, string $sql): bool {
        $semicolonCount = 0;
        $foundSignificantStatement = false;

        foreach ($tokens as $token) {
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ';') {
                $semicolonCount++;
                if ($foundSignificantStatement && $semicolonCount >= 2) {
                    return true;
                }
            }
            if ($token['type'] === self::TOKEN_KEYWORD &&
                in_array($token['value'], ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE'])) {
                if ($semicolonCount > 0) {
                    return true;
                }
                $foundSignificantStatement = true;
            }
        }

        return $semicolonCount >= 2;
    }

    /**
     * WHERE 条件复杂度计算
     */
    private static function calcWhereComplexity(?array $expr): int {
        if ($expr === null) return 0;

        $type = $expr['type'] ?? '';
        $complexity = 1;

        if ($type === 'and' || $type === 'or') {
            $complexity += self::calcWhereComplexity($expr['left'] ?? null);
            $complexity += self::calcWhereComplexity($expr['right'] ?? null);
            $complexity += 2;
        } elseif ($type === 'not') {
            $complexity += self::calcWhereComplexity($expr['expr'] ?? null);
            $complexity += 1;
        } elseif (isset($expr['left']) && isset($expr['right'])) {
            $complexity += self::calcWhereComplexity($expr['left'] ?? null);
            $complexity += self::calcWhereComplexity($expr['right'] ?? null);
        }

        return $complexity;
    }

    // ==================== Helpers ====================

    private static function checkDangerousFunction(string $name, array &$state): void {
        $upper = strtoupper($name);
        foreach (self::$dangerousFunctions as $func) {
            if ($upper === $func || strpos($upper, $func) !== false) {
                $state['dangerous_functions'][] = $upper;
                break;
            }
        }
    }

    private static function checkSensitiveTable(string $name, array &$state): void {
        $upper = strtoupper($name);
        foreach (self::$sensitiveTables as $table) {
            if ($upper === $table || strpos($upper, $table) !== false) {
                $state['sensitive_tables'][] = $upper;
                break;
            }
        }
    }

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type' => $ast['type'] ?? 'unknown',
        ];

        if (isset($ast['union_count'])) {
            $summary['union_count'] = $ast['union_count'];
        }
        if (isset($ast['max_subquery_depth'])) {
            $summary['subquery_depth'] = $ast['max_subquery_depth'];
        }
        if (!empty($ast['where'])) {
            $summary['has_where'] = true;
        }
        if (!empty($ast['from'])) {
            $summary['table_count'] = count($ast['from']);
        }

        return $summary;
    }

    /**
     * 计算危险分数
     */
    private static function calculateScore(array $result): int {
        $score = 0;

        if ($result['has_tautology']) {
            switch ($result['tautology_type']) {
                case 'numeric_equal':
                case 'string_equal':
                case 'column_equal':
                    $score += 35;
                    break;
                case 'always_true':
                    $score += 30;
                    break;
                case 'or_injection':
                    $score += 45;
                    break;
                default:
                    $score += 25;
            }
        }

        if ($result['has_union']) {
            $score += 30 + min($result['union_count'] * 10, 30);
        }

        if (!empty($result['dangerous_functions'])) {
            $funcScore = 0;
            foreach ($result['dangerous_functions'] as $func) {
                switch ($func) {
                    case 'SLEEP':
                    case 'BENCHMARK':
                        $funcScore += 30;
                        break;
                    case 'LOAD_FILE':
                        $funcScore += 35;
                        break;
                    case 'XP_CMDSHELL':
                        $funcScore += 50;
                        break;
                    default:
                        $funcScore += 20;
                }
            }
            $score += min($funcScore, 60);
        }

        if (!empty($result['sensitive_tables'])) {
            $tableScore = 0;
            foreach ($result['sensitive_tables'] as $table) {
                if (strpos($table, 'INFORMATION_SCHEMA') !== false) {
                    $tableScore += 30;
                } elseif (strpos($table, 'PASSWORD') !== false || strpos($table, 'USERS') !== false) {
                    $tableScore += 25;
                } else {
                    $tableScore += 15;
                }
            }
            $score += min($tableScore, 50);
        }

        if ($result['has_comment_injection']) {
            $score += 20;
        }

        if ($result['has_multiple_statements']) {
            $score += 35;
        }

        if ($result['subquery_depth'] > 3) {
            $score += 15;
        }

        if ($result['sql_type'] === 'drop') {
            $score += 25;
        }

        return min($score, 100);
    }
}
