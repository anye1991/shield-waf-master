<?php
/**
 * 表达式注入语义解析器
 * 职责：检测 XPath、LDAP、NoSQL（MongoDB）等表达式注入攻击，
 *       通过语法结构分析而非简单关键词匹配。
 */
defined('ABSPATH') || exit;

class ExpressionInjectionSemanticParser {

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

        $score = max($xpathTotal, $ldapTotal, $nosqlTotal);
        $indicators = [];
        $injectionType = 'none';

        if ($xpathTotal >= $ldapTotal && $xpathTotal >= $nosqlTotal && $xpathTotal > 0) {
            $injectionType = 'xpath';
            $indicators = array_merge($indicators, $xpathIndicators);
        }
        if ($ldapTotal >= $xpathTotal && $ldapTotal >= $nosqlTotal && $ldapTotal > 0) {
            $injectionType = $injectionType === 'none' ? 'ldap' : 'mixed';
            $indicators = array_merge($indicators, $ldapIndicators);
        }
        if ($nosqlTotal >= $xpathTotal && $nosqlTotal >= $ldapTotal && $nosqlTotal > 0) {
            $injectionType = $injectionType === 'none' ? 'nosql' : 'mixed';
            $indicators = array_merge($indicators, $nosqlIndicators);
        }

        if ($xpathTotal > 0 && $ldapTotal > 0) {
            $score += 5;
            $indicators[] = 'multi_type_suspicion';
        }
        if ($xpathTotal > 0 && $nosqlTotal > 0) {
            $score += 5;
            $indicators[] = 'multi_type_suspicion';
        }
        if ($ldapTotal > 0 && $nosqlTotal > 0) {
            $score += 5;
            $indicators[] = 'multi_type_suspicion';
        }

        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        return [
            'score'                  => min(100, $score),
            'risk_level'             => $riskLevel,
            'is_expression_injection' => $score >= 20,
            'injection_type'         => $injectionType,
            'xpath_score'            => $xpathTotal,
            'ldap_score'             => $ldapTotal,
            'nosql_score'            => $nosqlTotal,
            'xpath_structure_score'  => $xpathStructureScore,
            'ldap_structure_score'   => $ldapStructureScore,
            'nosql_structure_score'  => $nosqlStructureScore,
            'indicators'             => array_values(array_unique($indicators)),
        ];
    }

    private static function defaultResult(): array {
        return [
            'score'                  => 0,
            'risk_level'             => 'clean',
            'is_expression_injection' => false,
            'injection_type'         => 'none',
            'xpath_score'            => 0,
            'ldap_score'             => 0,
            'nosql_score'            => 0,
            'xpath_structure_score'  => 0,
            'ldap_structure_score'   => 0,
            'nosql_structure_score'  => 0,
            'indicators'             => [],
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
