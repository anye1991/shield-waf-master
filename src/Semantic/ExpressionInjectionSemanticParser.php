<?php
/**
 * 表达式注入语义解析器
 * 职责：通过构建表达式 AST（抽象语法树）真正理解表达式结构，
 *       检测表达式注入攻击，而非依赖简单正则匹配。
 *       同时保留 XPath/LDAP/NoSQL 正则检测作为 fallback。
 */
defined('ABSPATH') || exit;

class ExpressionInjectionSemanticParser {

    const TOKEN_IDENT     = 'IDENT';
    const TOKEN_STRING    = 'STRING';
    const TOKEN_NUMBER    = 'NUMBER';
    const TOKEN_OPERATOR  = 'OPERATOR';
    const TOKEN_PUNCT     = 'PUNCT';
    const TOKEN_KEYWORD   = 'KEYWORD';
    const TOKEN_EOF       = 'EOF';

    private static $keywords = [
        'true', 'false', 'null', 'TRUE', 'FALSE', 'NULL',
        'and', 'or', 'not', 'AND', 'OR', 'NOT',
        'instanceof', 'new', 'clone', 'echo', 'print',
        'return', 'break', 'continue', 'if', 'else',
        'while', 'for', 'foreach', 'function', 'class',
    ];

    private static $dangerousFunctions = [
        'eval', 'assert', 'system', 'exec', 'shell_exec',
        'passthru', 'preg_replace', 'create_function',
        'call_user_func', 'call_user_func_array',
        'array_map', 'array_filter', 'array_reduce',
        'usort', 'uasort', 'uksort',
        'file_get_contents', 'file_put_contents',
        'readfile', 'fopen', 'fwrite',
        'unlink', 'rmdir', 'mkdir',
        'include', 'require', 'include_once', 'require_once',
        'phpinfo', 'getenv', 'putenv',
        'posix_getpwuid', 'posix_kill',
        'proc_open', 'popen', 'pcntl_exec',
        'python', 'perl', 'ruby', 'bash', 'sh',
        'Function', 'constructor', '__construct',
    ];

    private static $dangerousProperties = [
        '__class__', '__mro__', '__subclasses__',
        '__builtins__', '__globals__', '__import__',
        '__init__', '__del__', '__call__',
        '__getattr__', '__setattr__', '__delattr__',
        '__getitem__', '__setitem__', '__delitem__',
        '__iter__', '__next__', '__len__',
        '__contains__', '__enter__', '__exit__',
        '__reduce__', '__reduce_ex__',
        '__getstate__', '__setstate__',
        '__dict__', '__bases__', '__base__',
        '__class__',
    ];

    private static $dangerousVariables = [
        '$GLOBALS', '$_SERVER', '$_GET', '$_POST',
        '$_REQUEST', '$_FILES', '$_ENV', '$_COOKIE',
        '$_SESSION', '$http_response_header',
    ];

    private static $xpathPatterns = [
        'axis_descendant'     => ['pattern' => '~//~', 'level' => 2, 'desc' => 'XPath后代轴'],
        'attribute_select'    => ['pattern' => '~@[\w]+~', 'level' => 2, 'desc' => 'XPath属性选择'],
        'predicate'           => ['pattern' => '~\[[^\]]+\]~', 'level' => 3, 'desc' => 'XPath谓词'],
        'contains_func'       => ['pattern' => '~contains\s*\(~i', 'level' => 3, 'desc' => 'XPath contains函数'],
        'starts_with_func'    => ['pattern' => '~starts-with\s*\(~i', 'level' => 3, 'desc' => 'XPath starts-with函数'],
        'ends_with_func'      => ['pattern' => '~ends-with\s*\(~i', 'level' => 3, 'desc' => 'XPath ends-with函数'],
        'concat_func'         => ['pattern' => '~concat\s*\(~i', 'level' => 2, 'desc' => 'XPath concat函数'],
        'string_length'       => ['pattern' => '~string-length\s*\(~i', 'level' => 2, 'desc' => 'XPath string-length函数'],
        'substring_func'      => ['pattern' => '~substring\s*\(~i', 'level' => 2, 'desc' => 'XPath substring函数'],
        'normalize_space'     => ['pattern' => '~normalize-space\s*\(~i', 'level' => 2, 'desc' => 'XPath normalize-space函数'],
        'translate_func'      => ['pattern' => '~translate\s*\(~i', 'level' => 2, 'desc' => 'XPath translate函数'],
        'not_func'            => ['pattern' => '~not\s*\(~i', 'level' => 2, 'desc' => 'XPath not函数'],
        'count_func'          => ['pattern' => '~count\s*\(~i', 'level' => 2, 'desc' => 'XPath count函数'],
        'position_func'       => ['pattern' => '~position\s*\(\s*\)~i', 'level' => 2, 'desc' => 'XPath position函数'],
        'last_func'           => ['pattern' => '~last\s*\(\s*\)~i', 'level' => 2, 'desc' => 'XPath last函数'],
        'name_func'           => ['pattern' => '~name\s*\(\s*\)~i', 'level' => 2, 'desc' => 'XPath name函数'],
        'text_func'           => ['pattern' => '~text\s*\(\s*\)~i', 'level' => 2, 'desc' => 'XPath text()函数'],
        'node_func'           => ['pattern' => '~node\s*\(\s*\)~i', 'level' => 2, 'desc' => 'XPath node()函数'],
        'or_tautology'        => ['pattern' => "~'?\s*or\s*'?\d+'?\s*=\s*'?\d+~i", 'level' => 5, 'desc' => 'XPath OR永真式'],
        'or_1_eq_1'           => ['pattern' => '~or\s+1\s*=\s*1~i', 'level' => 5, 'desc' => 'XPath OR 1=1'],
        'string_or_tautology' => ['pattern' => "~['\"]\s*or\s*['\"][^'\"]*['\"]\s*=\s*['\"]~i", 'level' => 5, 'desc' => "XPath ' or '1'='1 永真式"],
        'and_tautology'       => ['pattern' => '~and\s+\d+\s*=\s*\d+~i', 'level' => 4, 'desc' => 'XPath AND永真式'],
        'union_op'            => ['pattern' => '~\|\s*~', 'level' => 2, 'desc' => 'XPath并集操作符'],
        'ancestor_axis'       => ['pattern' => '~ancestor::~i', 'level' => 2, 'desc' => 'XPath ancestor轴'],
        'parent_axis'         => ['pattern' => '~parent::~i', 'level' => 2, 'desc' => 'XPath parent轴'],
        'child_axis'          => ['pattern' => '~child::~i', 'level' => 2, 'desc' => 'XPath child轴'],
        'following_axis'      => ['pattern' => '~following::~i', 'level' => 2, 'desc' => 'XPath following轴'],
        'preceding_axis'      => ['pattern' => '~preceding::~i', 'level' => 2, 'desc' => 'XPath preceding轴'],
        'self_axis'           => ['pattern' => '~self::~i', 'level' => 2, 'desc' => 'XPath self轴'],
        'attribute_axis'      => ['pattern' => '~attribute::~i', 'level' => 2, 'desc' => 'XPath attribute轴'],
    ];

    private static $ldapPatterns = [
        'wildcard'              => ['pattern' => '~\*~', 'level' => 1, 'desc' => 'LDAP通配符'],
        'filter_open'           => ['pattern' => '~\(~', 'level' => 2, 'desc' => 'LDAP过滤器开始'],
        'filter_close'          => ['pattern' => '~\)~', 'level' => 2, 'desc' => 'LDAP过滤器结束'],
        'and_filter'            => ['pattern' => '~\(&~', 'level' => 3, 'desc' => 'LDAP AND过滤器'],
        'or_filter'             => ['pattern' => '~\(\|~', 'level' => 3, 'desc' => 'LDAP OR过滤器'],
        'not_filter'            => ['pattern' => '~\(!~', 'level' => 3, 'desc' => 'LDAP NOT过滤器'],
        'nested_filter'         => ['pattern' => '~\(\s*[&|!]?\s*\(~', 'level' => 4, 'desc' => 'LDAP嵌套过滤器'],
        'equal_match'           => ['pattern' => '~[a-zA-Z][\w-]*\s*=[^)]+~', 'level' => 2, 'desc' => 'LDAP等式匹配'],
        'approx_match'          => ['pattern' => '/[a-zA-Z][\w-]*\s*~=\s*/', 'level' => 2, 'desc' => 'LDAP近似匹配'],
        'greater_equal'         => ['pattern' => '~[a-zA-Z][\w-]*\s*>=\s*~', 'level' => 2, 'desc' => 'LDAP大于等于'],
        'less_equal'            => ['pattern' => '~[a-zA-Z][\w-]*\s*<=\s*~', 'level' => 2, 'desc' => 'LDAP小于等于'],
        'extensible_match'      => ['pattern' => '~:dn:~', 'level' => 3, 'desc' => 'LDAP可扩展匹配'],
        'object_class'          => ['pattern' => '~objectClass\s*=~i', 'level' => 2, 'desc' => 'LDAP objectClass'],
        'dc_component'          => ['pattern' => '~dc\s*=~i', 'level' => 2, 'desc' => 'LDAP dc组件'],
        'ou_component'          => ['pattern' => '~ou\s*=~i', 'level' => 2, 'desc' => 'LDAP ou组件'],
        'cn_component'          => ['pattern' => '~cn\s*=~i', 'level' => 2, 'desc' => 'LDAP cn组件'],
        'uid_component'         => ['pattern' => '~uid\s*=~i', 'level' => 2, 'desc' => 'LDAP uid组件'],
        'sn_component'          => ['pattern' => '~sn\s*=~i', 'level' => 2, 'desc' => 'LDAP sn组件'],
        'givenname_component'   => ['pattern' => '~givenName\s*=~i', 'level' => 2, 'desc' => 'LDAP givenName组件'],
        'mail_component'        => ['pattern' => '~mail\s*=~i', 'level' => 2, 'desc' => 'LDAP mail组件'],
        'or_tautology'          => ['pattern' => '~\(\|\s*\([^)]+\)\s*\([^)]+\)\s*\)~', 'level' => 4, 'desc' => 'LDAP OR永真式'],
        'wildcard_injection'    => ['pattern' => "~['\"]?\*['\"]?\s*\)~", 'level' => 4, 'desc' => 'LDAP通配符注入'],
        'filter_escape'         => ['pattern' => '~\\\[\da-fA-F]{2}~', 'level' => 3, 'desc' => 'LDAP转义字符'],
    ];

    private static $nosqlPatterns = [
        'gt_operator'           => ['pattern' => '~\$gt\b~', 'level' => 3, 'desc' => 'MongoDB $gt操作符'],
        'lt_operator'           => ['pattern' => '~\$lt\b~', 'level' => 3, 'desc' => 'MongoDB $lt操作符'],
        'gte_operator'          => ['pattern' => '~\$gte\b~', 'level' => 3, 'desc' => 'MongoDB $gte操作符'],
        'lte_operator'          => ['pattern' => '~\$lte\b~', 'level' => 3, 'desc' => 'MongoDB $lte操作符'],
        'ne_operator'           => ['pattern' => '~\$ne\b~', 'level' => 3, 'desc' => 'MongoDB $ne操作符'],
        'eq_operator'           => ['pattern' => '~\$eq\b~', 'level' => 2, 'desc' => 'MongoDB $eq操作符'],
        'in_operator'           => ['pattern' => '~\$in\b~', 'level' => 3, 'desc' => 'MongoDB $in操作符'],
        'nin_operator'          => ['pattern' => '~\$nin\b~', 'level' => 3, 'desc' => 'MongoDB $nin操作符'],
        'regex_operator'        => ['pattern' => '~\$regex\b~', 'level' => 4, 'desc' => 'MongoDB $regex操作符'],
        'where_operator'        => ['pattern' => '~\$where\b~', 'level' => 5, 'desc' => 'MongoDB $where操作符'],
        'exists_operator'       => ['pattern' => '~\$exists\b~', 'level' => 2, 'desc' => 'MongoDB $exists操作符'],
        'type_operator'         => ['pattern' => '~\$type\b~', 'level' => 2, 'desc' => 'MongoDB $type操作符'],
        'size_operator'         => ['pattern' => '~\$size\b~', 'level' => 2, 'desc' => 'MongoDB $size操作符'],
        'mod_operator'          => ['pattern' => '~\$mod\b~', 'level' => 2, 'desc' => 'MongoDB $mod操作符'],
        'text_operator'         => ['pattern' => '~\$text\b~', 'level' => 2, 'desc' => 'MongoDB $text操作符'],
        'all_operator'          => ['pattern' => '~\$all\b~', 'level' => 2, 'desc' => 'MongoDB $all操作符'],
        'elemMatch_operator'    => ['pattern' => '~\$elemMatch\b~', 'level' => 2, 'desc' => 'MongoDB $elemMatch操作符'],
        'or_operator'           => ['pattern' => '~\$or\b~', 'level' => 3, 'desc' => 'MongoDB $or操作符'],
        'and_operator'          => ['pattern' => '~\$and\b~', 'level' => 3, 'desc' => 'MongoDB $and操作符'],
        'not_operator'          => ['pattern' => '~\$not\b~', 'level' => 3, 'desc' => 'MongoDB $not操作符'],
        'nor_operator'          => ['pattern' => '~\$nor\b~', 'level' => 3, 'desc' => 'MongoDB $nor操作符'],
        'set_operator'          => ['pattern' => '~\$set\b~', 'level' => 2, 'desc' => 'MongoDB $set操作符'],
        'unset_operator'        => ['pattern' => '~\$unset\b~', 'level' => 2, 'desc' => 'MongoDB $unset操作符'],
        'inc_operator'          => ['pattern' => '~\$inc\b~', 'level' => 2, 'desc' => 'MongoDB $inc操作符'],
        'push_operator'         => ['pattern' => '~\$push\b~', 'level' => 2, 'desc' => 'MongoDB $push操作符'],
        'pull_operator'         => ['pattern' => '~\$pull\b~', 'level' => 2, 'desc' => 'MongoDB $pull操作符'],
        'addToSet_operator'     => ['pattern' => '~\$addToSet\b~', 'level' => 2, 'desc' => 'MongoDB $addToSet操作符'],
        'pop_operator'          => ['pattern' => '~\$pop\b~', 'level' => 2, 'desc' => 'MongoDB $pop操作符'],
        'rename_operator'       => ['pattern' => '~\$rename\b~', 'level' => 2, 'desc' => 'MongoDB $rename操作符'],
        'aggregate_operator'    => ['pattern' => '~\$aggregate\b~', 'level' => 3, 'desc' => 'MongoDB $aggregate操作符'],
        'lookup_operator'       => ['pattern' => '~\$lookup\b~', 'level' => 3, 'desc' => 'MongoDB $lookup操作符'],
        'match_operator'        => ['pattern' => '~\$match\b~', 'level' => 2, 'desc' => 'MongoDB $match操作符'],
        'group_operator'        => ['pattern' => '~\$group\b~', 'level' => 2, 'desc' => 'MongoDB $group操作符'],
        'project_operator'      => ['pattern' => '~\$project\b~', 'level' => 2, 'desc' => 'MongoDB $project操作符'],
        'sort_operator'         => ['pattern' => '~\$sort\b~', 'level' => 2, 'desc' => 'MongoDB $sort操作符'],
        'limit_operator'        => ['pattern' => '~\$limit\b~', 'level' => 2, 'desc' => 'MongoDB $limit操作符'],
        'skip_operator'         => ['pattern' => '~\$skip\b~', 'level' => 2, 'desc' => 'MongoDB $skip操作符'],
        'func_constructor'      => ['pattern' => '~new\s+Function\s*\(~i', 'level' => 5, 'desc' => 'JavaScript Function构造器'],
        'eval_call'             => ['pattern' => '~\beval\s*\(~i', 'level' => 5, 'desc' => 'JavaScript eval调用'],
        'array_injection'       => ['pattern' => '~\[[\'"][$\w]+[\'"]\s*:~', 'level' => 4, 'desc' => 'MongoDB数组注入'],
        'object_injection'      => ['pattern' => '~\{[\s]*[\'"][$\w]+[\'"]\s*:~', 'level' => 4, 'desc' => 'MongoDB对象注入'],
        'json_dollar_key'       => ['pattern' => '~["\']\$[a-zA-Z]+["\']\s*:~', 'level' => 4, 'desc' => 'JSON $键注入'],
    ];

    /**
     * 主入口：分析表达式注入风险
     *
     * @param string $input
     * @return array
     */
    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $xpathIndicators = [];
        $ldapIndicators = [];
        $nosqlIndicators = [];

        $xpathScore = self::calculateXpathScore($input, $xpathIndicators);
        $ldapScore = self::calculateLdapScore($input, $ldapIndicators);
        $nosqlScore = self::calculateNosqlScore($input, $nosqlIndicators);

        $xpathStructureScore = self::analyzeXpathStructure($input);
        $ldapStructureScore = self::analyzeLdapStructure($input);
        $nosqlStructureScore = self::analyzeNosqlStructure($input);

        $xpathTotal = $xpathScore + $xpathStructureScore;
        $ldapTotal = $ldapScore + $ldapStructureScore;
        $nosqlTotal = $nosqlScore + $nosqlStructureScore;

        $regexScore = max($xpathTotal, $ldapTotal, $nosqlTotal);
        $regexIndicators = [];
        $injectionType = 'none';

        if ($xpathTotal >= $ldapTotal && $xpathTotal >= $nosqlTotal && $xpathTotal > 0) {
            $injectionType = 'xpath';
            $regexIndicators = array_merge($regexIndicators, $xpathIndicators);
        }
        if ($ldapTotal >= $xpathTotal && $ldapTotal >= $nosqlTotal && $ldapTotal > 0) {
            $injectionType = $injectionType === 'none' ? 'ldap' : 'mixed';
            $regexIndicators = array_merge($regexIndicators, $ldapIndicators);
        }
        if ($nosqlTotal >= $xpathTotal && $nosqlTotal >= $ldapTotal && $nosqlTotal > 0) {
            $injectionType = $injectionType === 'none' ? 'nosql' : 'mixed';
            $regexIndicators = array_merge($regexIndicators, $nosqlIndicators);
        }

        if ($xpathTotal > 0 && $ldapTotal > 0) {
            $regexScore += 5;
            $regexIndicators[] = 'multi_type_suspicion';
        }
        if ($xpathTotal > 0 && $nosqlTotal > 0) {
            $regexScore += 5;
            $regexIndicators[] = 'multi_type_suspicion';
        }
        if ($ldapTotal > 0 && $nosqlTotal > 0) {
            $regexScore += 5;
            $regexIndicators[] = 'multi_type_suspicion';
        }

        $astResult = self::analyzeWithAst($input);
        $astScore = $astResult['score'] ?? 0;
        $astIndicators = $astResult['indicators'] ?? [];

        $finalScore = max($regexScore, $astScore);
        $allIndicators = array_values(array_unique(array_merge($regexIndicators, $astIndicators)));

        if ($astScore > $regexScore) {
            $injectionType = 'expression';
        } elseif ($astScore > 0 && $regexScore > 0) {
            $injectionType = 'mixed';
        }

        $riskLevel = 'low';
        if ($finalScore >= 70) $riskLevel = 'critical';
        elseif ($finalScore >= 50) $riskLevel = 'high';
        elseif ($finalScore >= 30) $riskLevel = 'medium';

        return [
            'score'                      => min(100, $finalScore),
            'risk_level'                 => $riskLevel,
            'is_expression_injection'    => $finalScore >= 20,
            'injection_type'             => $injectionType,
            'parser_used'                => $astResult['parser_used'] ?? 'regex',
            'token_count'                => $astResult['token_count'] ?? 0,
            'ast_summary'                => $astResult['ast_summary'] ?? [],
            'xpath_score'                => $xpathTotal,
            'ldap_score'                 => $ldapTotal,
            'nosql_score'                => $nosqlTotal,
            'xpath_structure_score'      => $xpathStructureScore,
            'ldap_structure_score'       => $ldapStructureScore,
            'nosql_structure_score'      => $nosqlStructureScore,
            'ast_score'                  => $astScore,
            'indicators'                 => $allIndicators,
        ];
    }

    /**
     * 使用 AST 解析器分析表达式
     */
    private static function analyzeWithAst(string $input): array {
        $result = [
            'score'         => 0,
            'indicators'    => [],
            'parser_used'   => 'regex',
            'token_count'   => 0,
            'ast_summary'   => [],
        ];

        try {
            $tokens = self::tokenize($input);
            $result['token_count'] = count($tokens);

            $hasVariableVar = false;
            foreach ($tokens as $t) {
                if (($t['dollar_count'] ?? 0) >= 2) {
                    $hasVariableVar = true;
                    break;
                }
            }

            if (count($tokens) <= 2 && !$hasVariableVar) {
                return $result;
            }

            $hasMeaningful = self::hasMeaningfulExpressionTokens($tokens);
            if (!$hasMeaningful) {
                return $result;
            }

            $state = [
                'tokens'  => $tokens,
                'pos'     => 0,
                'input'   => $input,
            ];

            $ast = self::parseExpression($state);

            if ($ast === null) {
                return $result;
            }

            $result['parser_used'] = 'ast';
            $result['ast_summary'] = self::summarizeAst($ast);

            $walkerResult = self::walkAst($ast);
            $result['score'] = $walkerResult['score'];
            $result['indicators'] = $walkerResult['indicators'];

            $complexity = self::calcExpressionComplexity($ast);
            if ($complexity['depth'] >= 8) {
                $result['score'] += 15;
                $result['indicators'][] = 'deep_nesting:' . $complexity['depth'];
            } elseif ($complexity['depth'] >= 5) {
                $result['score'] += 8;
                $result['indicators'][] = 'moderate_nesting:' . $complexity['depth'];
            }

            if ($complexity['operator_count'] >= 15) {
                $result['score'] += 10;
                $result['indicators'][] = 'high_operator_count:' . $complexity['operator_count'];
            } elseif ($complexity['operator_count'] >= 8) {
                $result['score'] += 5;
            }

            $semicolonCount = substr_count($input, ';');
            if ($semicolonCount >= 2) {
                $result['score'] += 15;
                $result['indicators'][] = 'multiple_statements';
            } elseif ($semicolonCount >= 1) {
                $result['score'] += 5;
                $result['indicators'][] = 'semicolon_present';
            }

        } catch (Exception $e) {
            $result['indicators'][] = 'parse_error';
        }

        return $result;
    }

    // ==================== Tokenizer ====================

    /**
     * 表达式词法分析
     */
    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);
        $keywordMap = array_flip(self::$keywords);

        while ($pos < $len) {
            $char = $input[$pos];

            if ($char === ' ' || $char === "\t" || $char === "\n" || $char === "\r") {
                $pos++;
                continue;
            }

            if ($char === '#' || ($char === '/' && $pos + 1 < $len && $input[$pos + 1] === '/')) {
                $start = $pos;
                while ($pos < $len && $input[$pos] !== "\n") {
                    $pos++;
                }
                continue;
            }

            if ($char === '/' && $pos + 1 < $len && $input[$pos + 1] === '*') {
                $pos += 2;
                while ($pos < $len - 1) {
                    if ($input[$pos] === '*' && $input[$pos + 1] === '/') {
                        $pos += 2;
                        break;
                    }
                    $pos++;
                }
                continue;
            }

            if ($char === "'" || $char === '"') {
                $quote = $char;
                $start = $pos;
                $pos++;
                $value = '';
                while ($pos < $len) {
                    if ($input[$pos] === $quote) {
                        if ($pos + 1 < $len && $input[$pos + 1] === $quote) {
                            $value .= $quote;
                            $pos += 2;
                        } else {
                            $pos++;
                            break;
                        }
                    } elseif ($input[$pos] === '\\' && $pos + 1 < $len) {
                        $value .= $input[$pos] . $input[$pos + 1];
                        $pos += 2;
                    } else {
                        $value .= $input[$pos];
                        $pos++;
                    }
                }
                $tokens[] = [
                    'type'    => self::TOKEN_STRING,
                    'value'   => $value,
                    'raw'     => substr($input, $start, $pos - $start),
                    'pos'     => $start,
                    'quoted'  => $quote,
                ];
                continue;
            }

            if (is_numeric($char) || ($char === '.' && $pos + 1 < $len && is_numeric($input[$pos + 1]))) {
                $start = $pos;
                $hasDot = false;
                while ($pos < $len && (is_numeric($input[$pos]) || ($input[$pos] === '.' && !$hasDot))) {
                    if ($input[$pos] === '.') $hasDot = true;
                    $pos++;
                }
                if ($pos < $len && ($input[$pos] === 'e' || $input[$pos] === 'E')) {
                    $pos++;
                    if ($pos < $len && ($input[$pos] === '+' || $input[$pos] === '-')) $pos++;
                    while ($pos < $len && is_numeric($input[$pos])) $pos++;
                }
                $tokens[] = [
                    'type'  => self::TOKEN_NUMBER,
                    'value' => substr($input, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === '$' || ctype_alpha($char) || $char === '_' || $char === '\\') {
                $start = $pos;
                $dollarCount = 0;
                while ($pos < $len && $input[$pos] === '$') {
                    $dollarCount++;
                    $pos++;
                }
                while ($pos < $len && (ctype_alnum($input[$pos]) || $input[$pos] === '_' || $input[$pos] === '\\')) {
                    $pos++;
                }
                $word = substr($input, $start, $pos - $start);
                $lower = strtolower($word);

                $type = isset($keywordMap[$word]) || isset($keywordMap[$lower]) ? self::TOKEN_KEYWORD : self::TOKEN_IDENT;
                $tokens[] = [
                    'type'          => $type,
                    'value'         => $word,
                    'raw'           => $word,
                    'pos'           => $start,
                    'lower'         => $lower,
                    'dollar_count'  => $dollarCount,
                ];
                continue;
            }

            $threeChar = substr($input, $pos, 3);
            $twoChar = substr($input, $pos, 2);

            if (in_array($threeChar, ['===', '!==', '<=>', '...'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $threeChar, 'pos' => $pos];
                $pos += 3;
                continue;
            }
            if (in_array($twoChar, ['==', '!=', '<>', '<=', '>=', '||', '&&', '++', '--', '=>', '::', '->', '**'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $twoChar, 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if (in_array($char, ['=', '<', '>', '+', '-', '*', '/', '%', '~', '&', '|', '^', '!', '?', '.'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            if (in_array($char, ['(', ')', '[', ']', '{', '}', ',', ':', ';'])) {
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
     * 解析完整表达式（三目运算符优先级最低）
     */
    private static function parseExpression(array &$state): ?array {
        return self::parseTernary($state);
    }

    /**
     * 三目运算符 (?:)
     */
    private static function parseTernary(array &$state): ?array {
        $expr = self::parseOr($state);
        if ($expr === null) return null;

        if (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '?') {
            self::next($state);
            $trueExpr = self::parseTernary($state);
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ':') {
                self::next($state);
                $falseExpr = self::parseTernary($state);
                return [
                    'type'     => 'ternary',
                    'condition' => $expr,
                    'true'     => $trueExpr,
                    'false'    => $falseExpr,
                ];
            }
        }

        return $expr;
    }

    /**
     * 逻辑或 (||, or)
     */
    private static function parseOr(array &$state): ?array {
        $left = self::parseAnd($state);
        if ($left === null) return null;

        while (true) {
            $token = self::current($state);
            $isOr = false;
            if ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '||') {
                $isOr = true;
            } elseif ($token['type'] === self::TOKEN_KEYWORD && strtolower($token['value']) === 'or') {
                $isOr = true;
            }

            if ($isOr) {
                self::next($state);
                $right = self::parseAnd($state);
                $left = [
                    'type'  => 'logical_or',
                    'left'  => $left,
                    'right' => $right,
                ];
            } else {
                break;
            }
        }
        return $left;
    }

    /**
     * 逻辑与 (&&, and)
     */
    private static function parseAnd(array &$state): ?array {
        $left = self::parseBitwiseOr($state);
        if ($left === null) return null;

        while (true) {
            $token = self::current($state);
            $isAnd = false;
            if ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '&&') {
                $isAnd = true;
            } elseif ($token['type'] === self::TOKEN_KEYWORD && strtolower($token['value']) === 'and') {
                $isAnd = true;
            }

            if ($isAnd) {
                self::next($state);
                $right = self::parseBitwiseOr($state);
                $left = [
                    'type'  => 'logical_and',
                    'left'  => $left,
                    'right' => $right,
                ];
            } else {
                break;
            }
        }
        return $left;
    }

    /**
     * 按位或 (|)
     */
    private static function parseBitwiseOr(array &$state): ?array {
        $left = self::parseBitwiseAnd($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '|') {
            self::next($state);
            $right = self::parseBitwiseAnd($state);
            $left = [
                'type'  => 'binary_op',
                'op'    => '|',
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    /**
     * 按位与 (&)
     */
    private static function parseBitwiseAnd(array &$state): ?array {
        $left = self::parseEquality($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '&') {
            self::next($state);
            $right = self::parseEquality($state);
            $left = [
                'type'  => 'binary_op',
                'op'    => '&',
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    /**
     * 相等比较 (==, !=, ===, !==, <>)
     */
    private static function parseEquality(array &$state): ?array {
        $left = self::parseRelational($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['==', '!=', '===', '!==', '<>'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseRelational($state);
            $left = [
                'type'  => 'comparison',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    /**
     * 关系比较 (<, >, <=, >=)
     */
    private static function parseRelational(array &$state): ?array {
        $left = self::parseAdditive($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['<', '>', '<=', '>='])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseAdditive($state);
            $left = [
                'type'  => 'comparison',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    /**
     * 加减运算与字符串拼接 (+ - .)
     */
    private static function parseAdditive(array &$state): ?array {
        $left = self::parseMultiplicative($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['+', '-', '.'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseMultiplicative($state);
            $left = [
                'type'  => 'binary_op',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    /**
     * 乘除模运算 (* / %)
     */
    private static function parseMultiplicative(array &$state): ?array {
        $left = self::parseUnary($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['*', '/', '%', '**'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseUnary($state);
            $left = [
                'type'  => 'binary_op',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    /**
     * 一元运算 (! - ~)
     */
    private static function parseUnary(array &$state): ?array {
        $token = self::current($state);
        if ($token['type'] === self::TOKEN_OPERATOR && in_array($token['value'], ['!', '-', '+', '~'])) {
            $op = $token['value'];
            self::next($state);
            $expr = self::parseUnary($state);
            return ['type' => 'unary_op', 'op' => $op, 'expr' => $expr];
        }

        if ($token['type'] === self::TOKEN_KEYWORD && strtolower($token['value']) === 'not') {
            self::next($state);
            $expr = self::parseUnary($state);
            return ['type' => 'unary_op', 'op' => 'not', 'expr' => $expr];
        }

        return self::parsePostfix($state);
    }

    /**
     * 后缀运算（函数调用、数组访问、属性访问）
     */
    private static function parsePostfix(array &$state): ?array {
        $expr = self::parsePrimary($state);
        if ($expr === null) return null;

        while (true) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '(') {
                $expr = self::parseFunctionCallArgs($state, $expr);
                continue;
            }

            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '[') {
                self::next($state);
                $index = self::parseExpression($state);
                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ']') {
                    self::next($state);
                }
                $expr = [
                    'type'   => 'array_access',
                    'array'  => $expr,
                    'index'  => $index,
                ];
                continue;
            }

            if ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '->') {
                $op = $token['value'];
                self::next($state);
                $propToken = self::current($state);
                $propName = null;
                if ($propToken['type'] === self::TOKEN_IDENT || $propToken['type'] === self::TOKEN_KEYWORD) {
                    $propName = $propToken['value'];
                    self::next($state);
                }
                $expr = [
                    'type'     => 'property_access',
                    'object'   => $expr,
                    'property' => $propName,
                    'operator' => $op,
                ];
                continue;
            }

            if ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '.') {
                $nextToken = self::peek($state);
                $isPureIdent = false;
                if ($nextToken && ($nextToken['type'] === self::TOKEN_IDENT || $nextToken['type'] === self::TOKEN_KEYWORD)) {
                    $val = $nextToken['value'];
                    if (strpos($val, '$') !== 0) {
                        $isPureIdent = true;
                    }
                }

                if ($isPureIdent) {
                    $op = $token['value'];
                    self::next($state);
                    $propToken = self::current($state);
                    $propName = $propToken['value'];
                    self::next($state);
                    $expr = [
                        'type'     => 'property_access',
                        'object'   => $expr,
                        'property' => $propName,
                        'operator' => $op,
                    ];
                    continue;
                } else {
                    break;
                }
            }

            break;
        }

        return $expr;
    }

    /**
     * 解析函数调用参数
     */
    private static function parseFunctionCallArgs(array &$state, array $funcExpr): array {
        self::next($state);

        $args = [];
        if (self::current($state)['type'] !== self::TOKEN_PUNCT || self::current($state)['value'] !== ')') {
            $args = self::parseArgumentList($state);
        }

        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
            self::next($state);
        }

        $funcName = '';
        if ($funcExpr['type'] === 'identifier') {
            $funcName = $funcExpr['value'];
        } elseif ($funcExpr['type'] === 'property_access') {
            $funcName = $funcExpr['property'] ?? '';
        }

        return [
            'type'      => 'function_call',
            'callee'    => $funcExpr,
            'name'      => $funcName,
            'arguments' => $args,
        ];
    }

    /**
     * 解析参数列表
     */
    private static function parseArgumentList(array &$state): array {
        $args = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ')') {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }

            $expr = self::parseExpression($state);
            if ($expr !== null) {
                $args[] = $expr;
            } else {
                break;
            }
        }
        return $args;
    }

    /**
     * 基本表达式（字面量、标识符、括号表达式）
     */
    private static function parsePrimary(array &$state): ?array {
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
            $lower = strtolower($token['value']);
            if ($lower === 'true') {
                self::next($state);
                return ['type' => 'literal', 'subtype' => 'bool', 'value' => true];
            }
            if ($lower === 'false') {
                self::next($state);
                return ['type' => 'literal', 'subtype' => 'bool', 'value' => false];
            }
            if ($lower === 'null') {
                self::next($state);
                return ['type' => 'literal', 'subtype' => 'null', 'value' => null];
            }
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '(') {
            self::next($state);
            $expr = self::parseExpression($state);
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                self::next($state);
            }
            return $expr;
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '[') {
            return self::parseArrayLiteral($state);
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '{') {
            return self::parseObjectLiteral($state);
        }

        if ($token['type'] === self::TOKEN_IDENT || $token['type'] === self::TOKEN_KEYWORD) {
            $name = $token['value'];
            $dollarCount = $token['dollar_count'] ?? 0;
            self::next($state);
            return ['type' => 'identifier', 'value' => $name, 'dollar_count' => $dollarCount];
        }

        return null;
    }

    /**
     * 解析数组字面量 [elem1, elem2, ...]
     */
    private static function parseArrayLiteral(array &$state): array {
        self::next($state);
        $elements = [];

        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ']') {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }

            $expr = self::parseExpression($state);
            if ($expr !== null) {
                $elements[] = $expr;
            } else {
                break;
            }
        }

        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ']') {
            self::next($state);
        }

        return [
            'type'     => 'array_literal',
            'elements' => $elements,
        ];
    }

    /**
     * 解析对象字面量 {key1: val1, key2: val2, ...}
     */
    private static function parseObjectLiteral(array &$state): array {
        self::next($state);
        $properties = [];

        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '}') {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }

            $key = null;
            if ($token['type'] === self::TOKEN_STRING || $token['type'] === self::TOKEN_IDENT || $token['type'] === self::TOKEN_KEYWORD || $token['type'] === self::TOKEN_NUMBER) {
                $key = $token['value'];
                self::next($state);
            }

            if (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === ':') {
                self::next($state);
            }

            $value = self::parseExpression($state);
            if ($key !== null || $value !== null) {
                $properties[] = ['key' => $key, 'value' => $value];
            } else {
                break;
            }
        }

        if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '}') {
            self::next($state);
        }

        return [
            'type'       => 'object_literal',
            'properties' => $properties,
        ];
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function next(array &$state) {
        if ($state['pos'] < count($state['tokens']) - 1) {
            $state['pos']++;
        }
    }

    private static function peek(array &$state, int $offset = 1): ?array {
        return $state['tokens'][$state['pos'] + $offset] ?? null;
    }

    private static function isEof(array &$state): bool {
        $t = self::current($state);
        return $t['type'] === self::TOKEN_EOF;
    }

    // ==================== AST Walker / Semantic Analysis ====================

    /**
     * 遍历 AST 进行语义分析
     */
    private static function walkAst(?array $ast): array {
        $result = [
            'score'                  => 0,
            'indicators'             => [],
            'dangerous_functions'    => [],
            'dangerous_properties'   => [],
            'has_string_concat'      => false,
            'has_dynamic_variable'   => false,
            'has_callback_pattern'   => false,
        ];

        if ($ast === null) {
            return $result;
        }

        self::walkNode($ast, $result);

        if (!empty($result['dangerous_functions'])) {
            $result['indicators'][] = 'dangerous_functions:' . implode(',', array_unique($result['dangerous_functions']));
        }
        if (!empty($result['dangerous_properties'])) {
            $result['indicators'][] = 'dangerous_properties:' . implode(',', array_unique($result['dangerous_properties']));
        }
        if ($result['has_string_concat']) {
            $result['indicators'][] = 'string_concat_bypass';
        }
        if ($result['has_dynamic_variable']) {
            $result['indicators'][] = 'dynamic_variable';
        }
        if ($result['has_callback_pattern']) {
            $result['indicators'][] = 'callback_pattern';
        }

        return $result;
    }

    /**
     * 递归遍历单个节点
     */
    private static function walkNode(?array $node, array &$result) {
        if ($node === null || !is_array($node)) {
            return;
        }

        $type = $node['type'] ?? '';

        switch ($type) {
            case 'function_call':
                self::checkDangerousFunction($node, $result);
                self::checkCallbackPattern($node, $result);
                if (!empty($node['callee'])) {
                    self::walkNode($node['callee'], $result);
                }
                if (!empty($node['arguments']) && is_array($node['arguments'])) {
                    foreach ($node['arguments'] as $arg) {
                        self::walkNode($arg, $result);
                    }
                }
                break;

            case 'property_access':
                self::checkDangerousProperty($node, $result);
                if (!empty($node['object'])) {
                    self::walkNode($node['object'], $result);
                }
                break;

            case 'array_access':
                if (!empty($node['array'])) {
                    self::walkNode($node['array'], $result);
                }
                if (!empty($node['index'])) {
                    self::walkNode($node['index'], $result);
                }
                self::checkDynamicVariable($node, $result);
                break;

            case 'identifier':
                self::checkDangerousVariable($node, $result);
                break;

            case 'binary_op':
                self::checkStringConcat($node, $result);
                if (!empty($node['left'])) {
                    self::walkNode($node['left'], $result);
                }
                if (!empty($node['right'])) {
                    self::walkNode($node['right'], $result);
                }
                break;

            case 'unary_op':
                if (!empty($node['expr'])) {
                    self::walkNode($node['expr'], $result);
                }
                break;

            case 'ternary':
                if (!empty($node['condition'])) {
                    self::walkNode($node['condition'], $result);
                }
                if (!empty($node['true'])) {
                    self::walkNode($node['true'], $result);
                }
                if (!empty($node['false'])) {
                    self::walkNode($node['false'], $result);
                }
                break;

            case 'logical_or':
            case 'logical_and':
            case 'comparison':
                if (!empty($node['left'])) {
                    self::walkNode($node['left'], $result);
                }
                if (!empty($node['right'])) {
                    self::walkNode($node['right'], $result);
                }
                break;

            case 'array_literal':
                if (!empty($node['elements']) && is_array($node['elements'])) {
                    foreach ($node['elements'] as $elem) {
                        self::walkNode($elem, $result);
                    }
                }
                break;

            case 'object_literal':
                if (!empty($node['properties']) && is_array($node['properties'])) {
                    foreach ($node['properties'] as $prop) {
                        if (!empty($prop['value'])) {
                            self::walkNode($prop['value'], $result);
                        }
                    }
                }
                self::checkObjectLiteralInjection($node, $result);
                break;

            case 'literal':
                break;
        }
    }

    /**
     * 检查危险函数调用
     */
    private static function checkDangerousFunction(array $node, array &$result) {
        $funcName = strtolower($node['name'] ?? '');

        $dangerMap = array_flip(array_map('strtolower', self::$dangerousFunctions));

        if (isset($dangerMap[$funcName])) {
            $result['dangerous_functions'][] = $funcName;

            $highRisk = ['eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'];
            if (in_array($funcName, $highRisk)) {
                $result['score'] += 40;
            } else {
                $result['score'] += 20;
            }

            if ($funcName === 'preg_replace') {
                $args = $node['arguments'] ?? [];
                if (count($args) >= 1) {
                    $firstArg = $args[0];
                    if ($firstArg['type'] === 'literal' && $firstArg['subtype'] === 'string') {
                        $pattern = $firstArg['value'];
                        if (preg_match('/[eE]\s*$/', $pattern)) {
                            $result['score'] += 20;
                            $result['indicators'][] = 'preg_replace_e_modifier';
                        }
                    }
                }
            }
        }

        if ($funcName === 'function' || $funcName === 'Function') {
            $result['score'] += 35;
            $result['dangerous_functions'][] = 'function_constructor';
        }
    }

    /**
     * 检查危险属性访问
     */
    private static function checkDangerousProperty(array $node, array &$result) {
        $prop = strtolower($node['property'] ?? '');

        $dangerMap = array_flip(array_map('strtolower', self::$dangerousProperties));

        if (isset($dangerMap[$prop])) {
            $result['dangerous_properties'][] = $prop;
            $result['score'] += 30;
        }
    }

    /**
     * 检查字符串拼接绕过
     */
    private static function checkStringConcat(array $node, array &$result) {
        $op = $node['op'] ?? '';

        if ($op === '.' || $op === '+') {
            $left = $node['left'] ?? null;
            $right = $node['right'] ?? null;

            $hasString = false;
            $hasIdentifier = false;

            if ($left && $left['type'] === 'literal' && ($left['subtype'] ?? '') === 'string') {
                $hasString = true;
            }
            if ($right && $right['type'] === 'literal' && ($right['subtype'] ?? '') === 'string') {
                $hasString = true;
            }

            if ($left && $left['type'] === 'identifier') {
                $hasIdentifier = true;
            }
            if ($right && $right['type'] === 'identifier') {
                $hasIdentifier = true;
            }

            if ($hasString && $hasIdentifier) {
                $result['has_string_concat'] = true;
                $result['score'] += 8;
            }

            if ($op === '.') {
                $concatCount = self::countConcatChain($node);
                if ($concatCount >= 4) {
                    $result['has_string_concat'] = true;
                    $result['score'] += 5;
                }
            }
        }
    }

    /**
     * 统计字符串拼接链的长度
     */
    private static function countConcatChain(?array $node): int {
        if ($node === null) return 0;
        if (($node['type'] ?? '') !== 'binary_op') return 0;
        if (($node['op'] ?? '') !== '.' && ($node['op'] ?? '') !== '+') return 0;

        return 1 + self::countConcatChain($node['left'] ?? null) + self::countConcatChain($node['right'] ?? null);
    }

    /**
     * 检查动态变量/可变变量
     */
    private static function checkDynamicVariable(array $node, array &$result) {
        $array = $node['array'] ?? null;
        $index = $node['index'] ?? null;

        if ($array && $array['type'] === 'identifier') {
            $name = $array['value'] ?? '';
            if (strpos($name, '$') === 0 || strpos($name, '_') === 0) {
                $result['has_dynamic_variable'] = true;
                $result['score'] += 10;
            }
        }

        if ($index && $index['type'] === 'identifier') {
            $name = $index['value'] ?? '';
            if (strpos($name, '$') === 0) {
                $result['has_dynamic_variable'] = true;
                $result['score'] += 10;
            }
        }
    }

    /**
     * 检查危险变量（超全局变量等）
     */
    private static function checkDangerousVariable(array $node, array &$result) {
        $name = $node['value'] ?? '';
        $lower = strtolower($name);
        $dollarCount = $node['dollar_count'] ?? 0;

        if ($dollarCount >= 2) {
            $result['score'] += 15;
            $result['has_dynamic_variable'] = true;
            return;
        }

        $dangerVars = array_map('strtolower', self::$dangerousVariables);
        if (in_array($lower, $dangerVars)) {
            $result['score'] += 10;
            $result['has_dynamic_variable'] = true;
        }
    }

    /**
     * 检查回调函数模式
     */
    private static function checkCallbackPattern(array $node, array &$result) {
        $funcName = strtolower($node['name'] ?? '');
        $callbackFuncs = ['array_map', 'array_filter', 'array_reduce', 'usort', 'uasort', 'uksort', 'call_user_func', 'call_user_func_array'];

        if (in_array($funcName, $callbackFuncs)) {
            $args = $node['arguments'] ?? [];
            foreach ($args as $arg) {
                if ($arg['type'] === 'identifier' || $arg['type'] === 'literal') {
                    $result['has_callback_pattern'] = true;
                    $result['score'] += 5;
                    break;
                }
            }
        }
    }

    /**
     * 检查对象字面量注入（如 MongoDB $ 操作符）
     */
    private static function checkObjectLiteralInjection(array $node, array &$result) {
        $properties = $node['properties'] ?? [];
        $hasDollarKey = false;

        foreach ($properties as $prop) {
            $key = $prop['key'] ?? '';
            if (is_string($key) && strpos($key, '$') === 0) {
                $hasDollarKey = true;

                $dollarOps = ['$gt', '$lt', '$gte', '$lte', '$ne', '$eq', '$in', '$nin', '$regex', '$where'];
                if (in_array($key, $dollarOps)) {
                    $result['score'] += 10;
                }

                if ($key === '$where') {
                    $result['score'] += 20;
                }
            }
        }

        if ($hasDollarKey) {
            $result['score'] += 5;
            $result['indicators'][] = 'object_dollar_keys';
        }
    }

    // ==================== AST Utilities ====================

    /**
     * 生成 AST 摘要
     */
    private static function summarizeAst(?array $ast): array {
        if ($ast === null) {
            return [];
        }

        $summary = [
            'root_type'         => $ast['type'] ?? 'unknown',
            'max_depth'         => 0,
            'node_count'        => 0,
            'function_calls'    => [],
            'operators'         => [],
            'has_comparison'    => false,
            'has_logic'         => false,
        ];

        self::summarizeNode($ast, $summary, 0);

        $summary['function_calls'] = array_values(array_unique($summary['function_calls']));
        $summary['operators'] = array_values(array_unique($summary['operators']));

        return $summary;
    }

    private static function summarizeNode(?array $node, array &$summary, int $depth) {
        if ($node === null || !is_array($node)) {
            return;
        }

        $summary['node_count']++;
        if ($depth > $summary['max_depth']) {
            $summary['max_depth'] = $depth;
        }

        $type = $node['type'] ?? '';

        switch ($type) {
            case 'function_call':
                $summary['function_calls'][] = $node['name'] ?? 'anonymous';
                if (!empty($node['callee'])) {
                    self::summarizeNode($node['callee'], $summary, $depth + 1);
                }
                if (!empty($node['arguments']) && is_array($node['arguments'])) {
                    foreach ($node['arguments'] as $arg) {
                        self::summarizeNode($arg, $summary, $depth + 1);
                    }
                }
                break;

            case 'property_access':
                $summary['operators'][] = '.';
                if (!empty($node['object'])) {
                    self::summarizeNode($node['object'], $summary, $depth + 1);
                }
                break;

            case 'array_access':
                $summary['operators'][] = '[]';
                if (!empty($node['array'])) {
                    self::summarizeNode($node['array'], $summary, $depth + 1);
                }
                if (!empty($node['index'])) {
                    self::summarizeNode($node['index'], $summary, $depth + 1);
                }
                break;

            case 'binary_op':
                $summary['operators'][] = $node['op'] ?? '';
                if (!empty($node['left'])) {
                    self::summarizeNode($node['left'], $summary, $depth + 1);
                }
                if (!empty($node['right'])) {
                    self::summarizeNode($node['right'], $summary, $depth + 1);
                }
                break;

            case 'unary_op':
                $summary['operators'][] = $node['op'] ?? '';
                if (!empty($node['expr'])) {
                    self::summarizeNode($node['expr'], $summary, $depth + 1);
                }
                break;

            case 'comparison':
                $summary['has_comparison'] = true;
                $summary['operators'][] = $node['op'] ?? '';
                if (!empty($node['left'])) {
                    self::summarizeNode($node['left'], $summary, $depth + 1);
                }
                if (!empty($node['right'])) {
                    self::summarizeNode($node['right'], $summary, $depth + 1);
                }
                break;

            case 'logical_or':
            case 'logical_and':
                $summary['has_logic'] = true;
                if (!empty($node['left'])) {
                    self::summarizeNode($node['left'], $summary, $depth + 1);
                }
                if (!empty($node['right'])) {
                    self::summarizeNode($node['right'], $summary, $depth + 1);
                }
                break;

            case 'ternary':
                $summary['operators'][] = '?:';
                if (!empty($node['condition'])) {
                    self::summarizeNode($node['condition'], $summary, $depth + 1);
                }
                if (!empty($node['true'])) {
                    self::summarizeNode($node['true'], $summary, $depth + 1);
                }
                if (!empty($node['false'])) {
                    self::summarizeNode($node['false'], $summary, $depth + 1);
                }
                break;

            case 'array_literal':
                if (!empty($node['elements']) && is_array($node['elements'])) {
                    foreach ($node['elements'] as $elem) {
                        self::summarizeNode($elem, $summary, $depth + 1);
                    }
                }
                break;

            case 'object_literal':
                if (!empty($node['properties']) && is_array($node['properties'])) {
                    foreach ($node['properties'] as $prop) {
                        if (!empty($prop['value'])) {
                            self::summarizeNode($prop['value'], $summary, $depth + 1);
                        }
                    }
                }
                break;

            case 'identifier':
            case 'literal':
                break;
        }
    }

    /**
     * 计算表达式复杂度
     */
    private static function calcExpressionComplexity(?array $ast): array {
        $result = [
            'depth'           => 0,
            'operator_count'  => 0,
            'function_count'  => 0,
        ];

        if ($ast === null) {
            return $result;
        }

        self::calcComplexityRecursive($ast, $result, 1);
        return $result;
    }

    private static function calcComplexityRecursive(?array $node, array &$result, int $depth) {
        if ($node === null || !is_array($node)) {
            return;
        }

        if ($depth > $result['depth']) {
            $result['depth'] = $depth;
        }

        $type = $node['type'] ?? '';

        if (in_array($type, ['binary_op', 'unary_op', 'comparison'])) {
            $result['operator_count']++;
        }

        if ($type === 'function_call') {
            $result['function_count']++;
        }

        $childNodes = [];
        switch ($type) {
            case 'function_call':
                $childNodes[] = $node['callee'] ?? null;
                if (!empty($node['arguments']) && is_array($node['arguments'])) {
                    foreach ($node['arguments'] as $arg) {
                        $childNodes[] = $arg;
                    }
                }
                break;
            case 'property_access':
            case 'array_access':
                $childNodes[] = $node['object'] ?? $node['array'] ?? null;
                $childNodes[] = $node['index'] ?? null;
                break;
            case 'binary_op':
            case 'comparison':
            case 'logical_or':
            case 'logical_and':
                $childNodes[] = $node['left'] ?? null;
                $childNodes[] = $node['right'] ?? null;
                break;
            case 'unary_op':
                $childNodes[] = $node['expr'] ?? null;
                break;
            case 'ternary':
                $childNodes[] = $node['condition'] ?? null;
                $childNodes[] = $node['true'] ?? null;
                $childNodes[] = $node['false'] ?? null;
                break;
            case 'array_literal':
                if (!empty($node['elements']) && is_array($node['elements'])) {
                    foreach ($node['elements'] as $elem) {
                        $childNodes[] = $elem;
                    }
                }
                break;
            case 'object_literal':
                if (!empty($node['properties']) && is_array($node['properties'])) {
                    foreach ($node['properties'] as $prop) {
                        $childNodes[] = $prop['value'] ?? null;
                    }
                }
                break;
        }

        foreach ($childNodes as $child) {
            if ($child !== null) {
                self::calcComplexityRecursive($child, $result, $depth + 1);
            }
        }
    }

    /**
     * 检查 token 是否包含有意义的表达式结构
     */
    private static function hasMeaningfulExpressionTokens(array $tokens): bool {
        $identCount = 0;
        $opCount = 0;
        $parenCount = 0;
        $bracketCount = 0;
        $hasComp = false;
        $hasFunctionCall = false;
        $hasVariableVar = false;
        $compOps = ['==', '!=', '===', '!==', '<', '>', '<=', '>=', '<>'];

        for ($i = 0; $i < count($tokens); $i++) {
            $t = $tokens[$i];
            if ($t['type'] === self::TOKEN_IDENT || $t['type'] === self::TOKEN_KEYWORD) {
                $identCount++;
                if (($t['dollar_count'] ?? 0) >= 2) {
                    $hasVariableVar = true;
                }
            }
            if ($t['type'] === self::TOKEN_OPERATOR) {
                $opCount++;
                if (in_array($t['value'], $compOps, true)) $hasComp = true;
            }
            if ($t['type'] === self::TOKEN_PUNCT) {
                if ($t['value'] === '(') {
                    $parenCount++;
                    if ($i > 0) {
                        $prev = $tokens[$i - 1];
                        if ($prev['type'] === self::TOKEN_IDENT || $prev['type'] === self::TOKEN_KEYWORD) {
                            $hasFunctionCall = true;
                        }
                    }
                }
                if ($t['value'] === '[') $bracketCount++;
            }
        }

        if ($hasVariableVar) return true;
        if ($identCount >= 1 && $opCount >= 1) return true;
        if ($identCount >= 1 && $hasFunctionCall) return true;
        if ($identCount >= 2 && $parenCount >= 1) return true;
        if ($hasComp) return true;
        if ($opCount >= 2 && $identCount >= 1) return true;
        if ($parenCount >= 2 && $identCount >= 1) return true;
        if ($bracketCount >= 1 && $identCount >= 1) return true;

        return false;
    }

    // ==================== Regex Fallback Methods ====================

    private static function defaultResult(): array {
        return [
            'score'                      => 0,
            'risk_level'                 => 'clean',
            'is_expression_injection'    => false,
            'injection_type'             => 'none',
            'parser_used'                => 'regex',
            'token_count'                => 0,
            'ast_summary'                => [],
            'xpath_score'                => 0,
            'ldap_score'                 => 0,
            'nosql_score'                => 0,
            'xpath_structure_score'      => 0,
            'ldap_structure_score'       => 0,
            'nosql_structure_score'      => 0,
            'ast_score'                  => 0,
            'indicators'                 => [],
        ];
    }

    private static function calculateXpathScore(string $input, array &$indicators): int {
        $score = 0;
        $indicators = [];

        foreach (self::$xpathPatterns as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $score += $info['level'] * 2;
                $indicators[] = 'xpath_' . $key;
            }
        }

        return $score;
    }

    private static function calculateLdapScore(string $input, array &$indicators): int {
        $score = 0;
        $indicators = [];

        foreach (self::$ldapPatterns as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $score += $info['level'] * 2;
                $indicators[] = 'ldap_' . $key;
            }
        }

        return $score;
    }

    private static function calculateNosqlScore(string $input, array &$indicators): int {
        $score = 0;
        $indicators = [];

        foreach (self::$nosqlPatterns as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $score += $info['level'] * 2;
                $indicators[] = 'nosql_' . $key;
            }
        }

        return $score;
    }

    private static function analyzeXpathStructure(string $input): int {
        $score = 0;

        $predicateCount = preg_match_all('~\[[^\]]+\]~', $input);
        if ($predicateCount >= 3) { $score += 15; }
        elseif ($predicateCount >= 2) { $score += 10; }
        elseif ($predicateCount >= 1) { $score += 5; }

        $axisCount = preg_match_all('~(//|::)~', $input);
        if ($axisCount >= 3) { $score += 10; }
        elseif ($axisCount >= 2) { $score += 6; }
        elseif ($axisCount >= 1) { $score += 3; }

        $funcCount = preg_match_all('~[a-zA-Z-]+\s*\(~', $input);
        if ($funcCount >= 4) { $score += 12; }
        elseif ($funcCount >= 3) { $score += 8; }
        elseif ($funcCount >= 2) { $score += 5; }

        if (preg_match("~'?\s*or\s*'?\d+'?\s*=\s*'?\d+~i", $input)) {
            $score += 20;
        }
        if (preg_match("~['\"]\s*or\s*['\"][^'\"]*['\"]\s*=\s*['\"]~i", $input)) {
            $score += 20;
        }

        $slashCount = substr_count($input, '/');
        if ($slashCount >= 5) { $score += 8; }
        elseif ($slashCount >= 3) { $score += 5; }

        $atCount = substr_count($input, '@');
        if ($atCount >= 3) { $score += 6; }
        elseif ($atCount >= 2) { $score += 4; }

        return $score;
    }

    private static function analyzeLdapStructure(string $input): int {
        $score = 0;

        $openParen = substr_count($input, '(');
        $closeParen = substr_count($input, ')');
        $parenBalance = $openParen - $closeParen;
        $parenTotal = min($openParen, $closeParen);

        if ($parenTotal >= 5) { $score += 15; }
        elseif ($parenTotal >= 3) { $score += 10; }
        elseif ($parenTotal >= 2) { $score += 6; }

        if (preg_match('~\(\s*[&|!]~', $input)) {
            $score += 10;
        }

        $nestedCount = 0;
        $depth = 0;
        $maxDepth = 0;
        for ($i = 0; $i < strlen($input); $i++) {
            if ($input[$i] === '(') {
                $depth++;
                if ($depth > $maxDepth) $maxDepth = $depth;
                if ($depth >= 2) $nestedCount++;
            } elseif ($input[$i] === ')') {
                $depth--;
            }
        }
        if ($maxDepth >= 4) { $score += 15; }
        elseif ($maxDepth >= 3) { $score += 10; }
        elseif ($maxDepth >= 2) { $score += 5; }

        $attrCount = preg_match_all('~[a-zA-Z][\w-]*\s*=~', $input);
        if ($attrCount >= 5) { $score += 10; }
        elseif ($attrCount >= 3) { $score += 6; }
        elseif ($attrCount >= 2) { $score += 3; }

        $wildcardCount = substr_count($input, '*');
        if ($wildcardCount >= 5) { $score += 10; }
        elseif ($wildcardCount >= 3) { $score += 6; }
        elseif ($wildcardCount >= 2) { $score += 3; }

        if (preg_match('~\(\|\s*\([^)]+\)\s*\([^)]+\)~', $input)) {
            $score += 15;
        }

        if ($parenBalance > 0 || $parenBalance < 0) {
            $score += 5;
        }

        return $score;
    }

    private static function analyzeNosqlStructure(string $input): int {
        $score = 0;

        $dollarCount = preg_match_all('~\$[a-zA-Z]+~', $input);
        if ($dollarCount >= 6) { $score += 20; }
        elseif ($dollarCount >= 4) { $score += 15; }
        elseif ($dollarCount >= 3) { $score += 10; }
        elseif ($dollarCount >= 2) { $score += 5; }

        $openBrace = substr_count($input, '{');
        $closeBrace = substr_count($input, '}');
        $openBracket = substr_count($input, '[');
        $closeBracket = substr_count($input, ']');

        $bracesTotal = min($openBrace, $closeBrace);
        $bracketsTotal = min($openBracket, $closeBracket);

        if ($bracesTotal >= 3) { $score += 10; }
        elseif ($bracesTotal >= 2) { $score += 6; }
        elseif ($bracesTotal >= 1) { $score += 3; }

        if ($bracketsTotal >= 3) { $score += 10; }
        elseif ($bracketsTotal >= 2) { $score += 6; }
        elseif ($bracketsTotal >= 1) { $score += 3; }

        $nestingDepth = self::calculateNestingDepth($input);
        if ($nestingDepth >= 4) { $score += 15; }
        elseif ($nestingDepth >= 3) { $score += 10; }
        elseif ($nestingDepth >= 2) { $score += 5; }

        $comparisonOps = preg_match_all('~\$(gt|lt|gte|lte|ne|eq|in|nin)\b~', $input);
        if ($comparisonOps >= 4) { $score += 12; }
        elseif ($comparisonOps >= 3) { $score += 8; }
        elseif ($comparisonOps >= 2) { $score += 5; }

        $logicalOps = preg_match_all('~\$(or|and|not|nor)\b~', $input);
        if ($logicalOps >= 3) { $score += 12; }
        elseif ($logicalOps >= 2) { $score += 8; }
        elseif ($logicalOps >= 1) { $score += 5; }

        if (preg_match('~\$where\b~', $input) && preg_match('~[;=()]~', $input)) {
            $score += 15;
        }

        if (preg_match('~\$regex\b~', $input)) {
            $score += 10;
        }

        if (preg_match('~["\']\$[a-zA-Z]+["\']\s*:~', $input)) {
            $score += 10;
        }

        return $score;
    }

    private static function calculateNestingDepth(string $input): int {
        $maxDepth = 0;
        $currentDepth = 0;
        $inString = false;
        $stringChar = '';

        for ($i = 0; $i < strlen($input); $i++) {
            $char = $input[$i];

            if ($inString) {
                if ($char === '\\') {
                    $i++;
                    continue;
                }
                if ($char === $stringChar) {
                    $inString = false;
                }
                continue;
            }

            if ($char === '"' || $char === "'") {
                $inString = true;
                $stringChar = $char;
                continue;
            }

            if ($char === '{' || $char === '[') {
                $currentDepth++;
                if ($currentDepth > $maxDepth) {
                    $maxDepth = $currentDepth;
                }
            } elseif ($char === '}' || $char === ']') {
                if ($currentDepth > 0) {
                    $currentDepth--;
                }
            }
        }

        return $maxDepth;
    }
}
