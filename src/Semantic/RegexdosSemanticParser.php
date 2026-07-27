<?php
/**
 * 正则表达式 DoS (ReDoS) 语义解析器
 * 职责：通过构建正则表达式 AST 真正理解正则结构，
 *       检测灾难性回溯风险，评估正则表达式的安全等级。
 */
defined('ABSPATH') || exit;

class RegexdosSemanticParser {

    const TOKEN_LITERAL       = 'LITERAL';
    const TOKEN_ESCAPE        = 'ESCAPE';
    const TOKEN_QUANTIFIER    = 'QUANTIFIER';
    const TOKEN_LAZY          = 'LAZY';
    const TOKEN_POSSESSIVE    = 'POSSESSIVE';
    const TOKEN_GROUP_START   = 'GROUP_START';
    const TOKEN_GROUP_END     = 'GROUP_END';
    const TOKEN_ALTERNATION   = 'ALTERNATION';
    const TOKEN_CLASS_START   = 'CLASS_START';
    const TOKEN_CLASS_END     = 'CLASS_END';
    const TOKEN_CLASS_RANGE   = 'CLASS_RANGE';
    const TOKEN_CLASS_NEGATE  = 'CLASS_NEGATE';
    const TOKEN_ANCHOR        = 'ANCHOR';
    const TOKEN_BACKREF       = 'BACKREF';
    const TOKEN_NAMED_BACKREF = 'NAMED_BACKREF';
    const TOKEN_MODIFIER      = 'MODIFIER';
    const TOKEN_ANY           = 'ANY';
    const TOKEN_EOF           = 'EOF';

    const GROUP_CAPTURE         = 'capture';
    const GROUP_NON_CAPTURE     = 'non_capture';
    const GROUP_POSITIVE_LOOKAHEAD  = 'positive_lookahead';
    const GROUP_NEGATIVE_LOOKAHEAD  = 'negative_lookahead';
    const GROUP_POSITIVE_LOOKBEHIND = 'positive_lookbehind';
    const GROUP_NEGATIVE_LOOKBEHIND = 'negative_lookbehind';
    const GROUP_NAMED           = 'named';
    const GROUP_ATOMIC          = 'atomic';
    const GROUP_COMMENT         = 'comment';
    const GROUP_MODIFIER        = 'modifier';
    const GROUP_RECURSION       = 'recursion';

    const RISK_CLEAN     = 'clean';
    const RISK_LOW       = 'low';
    const RISK_MEDIUM    = 'medium';
    const RISK_HIGH      = 'high';
    const RISK_CRITICAL  = 'critical';

    const COMPLEXITY_POLYNOMIAL  = 'polynomial';
    const COMPLEXITY_EXPONENTIAL = 'exponential';

    /**
     * 预定义转义字符映射
     */
    private static $escapeMap = [
        'd' => 'digit',
        'D' => 'non_digit',
        'w' => 'word',
        'W' => 'non_word',
        's' => 'whitespace',
        'S' => 'non_whitespace',
        'b' => 'word_boundary',
        'B' => 'non_word_boundary',
        'n' => 'newline',
        'r' => 'carriage_return',
        't' => 'tab',
        'f' => 'form_feed',
        'v' => 'vertical_tab',
        '0' => 'null',
        'a' => 'alarm',
        'e' => 'escape',
        '.' => 'dot',
        '\\' => 'backslash',
        '+' => 'plus',
        '*' => 'star',
        '?' => 'question',
        '[' => 'bracket',
        ']' => 'bracket_close',
        '(' => 'paren',
        ')' => 'paren_close',
        '{' => 'brace',
        '}' => 'brace_close',
        '|' => 'pipe',
        '^' => 'caret',
        '$' => 'dollar',
    ];

    /**
     * 锚点字符映射
     */
    private static $anchorMap = [
        '^' => 'start',
        '$' => 'end',
        'A' => 'start_absolute',
        'z' => 'end_absolute',
        'Z' => 'end_newline',
        'G' => 'prev_match_end',
    ];

    /**
     * 主入口：分析正则表达式 ReDoS 风险
     *
     * @param string $input
     * @return array
     */
    public static function analyze(string $input): array {
        $result = [
            'score'                  => 0,
            'risk_level'             => self::RISK_CLEAN,
            'is_regex'               => false,
            'has_redos_risk'         => false,
            'redos_patterns'         => [],
            'star_height'            => 0,
            'nesting_depth'          => 0,
            'group_count'            => 0,
            'quantifier_count'       => 0,
            'alternation_count'      => 0,
            'backref_count'          => 0,
            'estimated_complexity'   => self::COMPLEXITY_POLYNOMIAL,
            'longest_input_estimate' => 0,
            'ast_summary'            => [],
            'indicators'             => [],
        ];

        if (trim($input) === '') {
            return $result;
        }

        $inputLen = strlen($input);

        try {
            $tokens = self::tokenize($input);
            if (empty($tokens)) {
                return $result;
            }

            $ast = self::parse($tokens, $input);
            if (empty($ast)) {
                $result = self::fallbackRegexAnalysis($input, $result);
                return $result;
            }

            $result['is_regex'] = true;

            $stats = self::collectStats($ast);
            $result['group_count']        = $stats['group_count'];
            $result['quantifier_count']   = $stats['quantifier_count'];
            $result['alternation_count']  = $stats['alternation_count'];
            $result['backref_count']      = $stats['backref_count'];
            $result['star_height']        = $stats['star_height'];
            $result['nesting_depth']      = $stats['nesting_depth'];

            $redosResult = self::detectRedosPatterns($ast);
            $result['redos_patterns'] = $redosResult['patterns'];
            $result['has_redos_risk'] = !empty($redosResult['patterns']);

            $result['estimated_complexity'] = $redosResult['complexity'];
            $result['longest_input_estimate'] = self::estimateLongestInput($ast, $result);

            $result['ast_summary'] = self::summarizeAst($ast);

            if ($inputLen > 1000) {
                $result['indicators'][] = 'very_long_regex';
            }

            if ($result['group_count'] > 50) {
                $result['indicators'][] = 'excessive_groups';
            }

            if ($result['backref_count'] > 10) {
                $result['indicators'][] = 'excessive_backrefs';
            }

            $result['score'] = self::calculateScore($result);
            $result['risk_level'] = self::determineRiskLevel($result['score']);

            if ($result['has_redos_risk']) {
                $result['indicators'][] = 'redos_risk_detected';
            }

            if ($result['star_height'] >= 2) {
                $result['indicators'][] = 'high_star_height';
            }

            if ($result['nesting_depth'] >= 3) {
                $result['indicators'][] = 'deep_nesting';
            }

            if ($result['estimated_complexity'] === self::COMPLEXITY_EXPONENTIAL) {
                $result['indicators'][] = 'exponential_complexity';
            }

        } catch (Exception $e) {
            $result['indicators'][] = 'parse_error';
            $result = self::fallbackRegexAnalysis($input, $result);
        }

        return $result;
    }

    // ==================== Tokenizer ====================

    /**
     * 正则表达式词法分析
     *
     * @param string $input
     * @return array
     */
    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);
        $inCharClass = false;

        while ($pos < $len) {
            $char = $input[$pos];

            if ($inCharClass) {
                if ($char === ']' && $pos > 0 && $input[$pos - 1] !== '\\') {
                    $tokens[] = ['type' => self::TOKEN_CLASS_END, 'value' => ']', 'pos' => $pos];
                    $inCharClass = false;
                    $pos++;
                    continue;
                }

                if ($char === '^' && $pos > 0 && $input[$pos - 1] === '[') {
                    $tokens[] = ['type' => self::TOKEN_CLASS_NEGATE, 'value' => '^', 'pos' => $pos];
                    $pos++;
                    continue;
                }

                if ($char === '-' && $pos > 0 && $input[$pos - 1] !== '\\' && $pos + 1 < $len && $input[$pos + 1] !== ']') {
                    $tokens[] = ['type' => self::TOKEN_CLASS_RANGE, 'value' => '-', 'pos' => $pos];
                    $pos++;
                    continue;
                }

                if ($char === '\\' && $pos + 1 < $len) {
                    $next = $input[$pos + 1];
                    $escapeType = self::$escapeMap[$next] ?? 'hex';
                    if ($next === 'x' || $next === 'u' || $next === 'c' || $next === 'p' || $next === 'P') {
                        $escapeSeq = self::readComplexEscape($input, $pos, $len);
                        $tokens[] = ['type' => self::TOKEN_ESCAPE, 'value' => $escapeSeq['seq'], 'subtype' => $escapeSeq['type'], 'pos' => $pos];
                        $pos = $escapeSeq['end'];
                    } else {
                        $tokens[] = ['type' => self::TOKEN_ESCAPE, 'value' => '\\' . $next, 'subtype' => $escapeType, 'pos' => $pos];
                        $pos += 2;
                    }
                    continue;
                }

                $tokens[] = ['type' => self::TOKEN_LITERAL, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '[') {
                $tokens[] = ['type' => self::TOKEN_CLASS_START, 'value' => '[', 'pos' => $pos];
                $inCharClass = true;
                $pos++;
                continue;
            }

            if ($char === '(') {
                $groupInfo = self::parseGroupStart($input, $pos, $len);
                $tokens[] = [
                    'type'     => self::TOKEN_GROUP_START,
                    'value'    => $groupInfo['raw'],
                    'group_type' => $groupInfo['type'],
                    'name'     => $groupInfo['name'] ?? null,
                    'modifiers' => $groupInfo['modifiers'] ?? null,
                    'pos'      => $pos,
                ];
                $pos = $groupInfo['end'];
                continue;
            }

            if ($char === ')') {
                $tokens[] = ['type' => self::TOKEN_GROUP_END, 'value' => ')', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '|') {
                $tokens[] = ['type' => self::TOKEN_ALTERNATION, 'value' => '|', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '.' ) {
                $tokens[] = ['type' => self::TOKEN_ANY, 'value' => '.', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '^' || $char === '$') {
                $tokens[] = ['type' => self::TOKEN_ANCHOR, 'value' => $char, 'subtype' => self::$anchorMap[$char] ?? $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '*' || $char === '+' || $char === '?') {
                $quantType = self::TOKEN_QUANTIFIER;
                $quantMode = 'greedy';
                $raw = $char;
                $min = $char === '+' ? 1 : 0;
                $max = $char === '?' ? 1 : null;

                if ($pos + 1 < $len && $input[$pos + 1] === '?') {
                    $quantType = self::TOKEN_LAZY;
                    $quantMode = 'lazy';
                    $raw .= '?';
                    $pos++;
                } elseif ($pos + 1 < $len && $input[$pos + 1] === '+') {
                    $quantType = self::TOKEN_POSSESSIVE;
                    $quantMode = 'possessive';
                    $raw .= '+';
                    $pos++;
                }

                $tokens[] = [
                    'type'  => $quantType,
                    'value' => $raw,
                    'mode'  => $quantMode,
                    'min'   => $min,
                    'max'   => $max,
                    'pos'   => $pos - strlen($raw) + 1,
                ];
                $pos++;
                continue;
            }

            if ($char === '{') {
                $quantResult = self::parseBraceQuantifier($input, $pos, $len);
                if ($quantResult !== null) {
                    $tokens[] = $quantResult['token'];
                    $pos = $quantResult['end'];
                    continue;
                }
                $tokens[] = ['type' => self::TOKEN_LITERAL, 'value' => '{', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '\\' && $pos + 1 < $len) {
                $next = $input[$pos + 1];

                if (isset(self::$anchorMap[$next])) {
                    $tokens[] = ['type' => self::TOKEN_ANCHOR, 'value' => '\\' . $next, 'subtype' => self::$anchorMap[$next], 'pos' => $pos];
                    $pos += 2;
                    continue;
                }

                if ($next === 'b' || $next === 'B') {
                    $tokens[] = ['type' => self::TOKEN_ANCHOR, 'value' => '\\' . $next, 'subtype' => self::$escapeMap[$next], 'pos' => $pos];
                    $pos += 2;
                    continue;
                }

                if ($next >= '1' && $next <= '9') {
                    $backrefResult = self::parseBackreference($input, $pos, $len);
                    $tokens[] = $backrefResult['token'];
                    $pos = $backrefResult['end'];
                    continue;
                }

                if ($next === 'k') {
                    $namedBackrefResult = self::parseNamedBackreference($input, $pos, $len);
                    if ($namedBackrefResult !== null) {
                        $tokens[] = $namedBackrefResult['token'];
                        $pos = $namedBackrefResult['end'];
                        continue;
                    }
                }

                if (isset(self::$escapeMap[$next])) {
                    $tokens[] = ['type' => self::TOKEN_ESCAPE, 'value' => '\\' . $next, 'subtype' => self::$escapeMap[$next], 'pos' => $pos];
                    $pos += 2;
                    continue;
                }

                if ($next === 'x' || $next === 'u' || $next === 'c' || $next === 'p' || $next === 'P') {
                    $escapeSeq = self::readComplexEscape($input, $pos, $len);
                    $tokens[] = ['type' => self::TOKEN_ESCAPE, 'value' => $escapeSeq['seq'], 'subtype' => $escapeSeq['type'], 'pos' => $pos];
                    $pos = $escapeSeq['end'];
                    continue;
                }

                $tokens[] = ['type' => self::TOKEN_ESCAPE, 'value' => '\\' . $next, 'subtype' => 'unknown', 'pos' => $pos];
                $pos += 2;
                continue;
            }

            $tokens[] = ['type' => self::TOKEN_LITERAL, 'value' => $char, 'pos' => $pos];
            $pos++;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    /**
     * 解析分组起始符
     */
    private static function parseGroupStart(string $input, int $pos, int $len): array {
        $result = [
            'type' => self::GROUP_CAPTURE,
            'raw'  => '(',
            'name' => null,
            'end'  => $pos + 1,
        ];

        if ($pos + 1 >= $len || $input[$pos + 1] !== '?') {
            return $result;
        }

        $pos2 = $pos + 2;
        if ($pos2 >= $len) {
            return $result;
        }

        $char = $input[$pos2];

        if ($char === ':') {
            $result['type'] = self::GROUP_NON_CAPTURE;
            $result['raw'] = '(?:';
            $result['end'] = $pos2 + 1;
            return $result;
        }

        if ($char === '=') {
            $result['type'] = self::GROUP_POSITIVE_LOOKAHEAD;
            $result['raw'] = '(?=';
            $result['end'] = $pos2 + 1;
            return $result;
        }

        if ($char === '!') {
            $result['type'] = self::GROUP_NEGATIVE_LOOKAHEAD;
            $result['raw'] = '(?!';
            $result['end'] = $pos2 + 1;
            return $result;
        }

        if ($char === '<') {
            if ($pos2 + 1 < $len) {
                $nextChar = $input[$pos2 + 1];
                if ($nextChar === '=') {
                    $result['type'] = self::GROUP_POSITIVE_LOOKBEHIND;
                    $result['raw'] = '(?<=';
                    $result['end'] = $pos2 + 2;
                    return $result;
                }
                if ($nextChar === '!') {
                    $result['type'] = self::GROUP_NEGATIVE_LOOKBEHIND;
                    $result['raw'] = '(?<!';
                    $result['end'] = $pos2 + 2;
                    return $result;
                }
                if (ctype_alpha($nextChar) || $nextChar === '_') {
                    $nameEnd = $pos2 + 2;
                    while ($nameEnd < $len && (ctype_alnum($input[$nameEnd]) || $input[$nameEnd] === '_')) {
                        $nameEnd++;
                    }
                    if ($nameEnd < $len && $input[$nameEnd] === '>') {
                        $name = substr($input, $pos2 + 1, $nameEnd - $pos2 - 1);
                        $result['type'] = self::GROUP_NAMED;
                        $result['name'] = $name;
                        $result['raw'] = substr($input, $pos, $nameEnd - $pos + 1);
                        $result['end'] = $nameEnd + 1;
                        return $result;
                    }
                }
            }
        }

        if ($char === '>') {
            $result['type'] = self::GROUP_ATOMIC;
            $result['raw'] = '(?>';
            $result['end'] = $pos2 + 1;
            return $result;
        }

        if ($char === '#') {
            $commentEnd = $pos2 + 1;
            while ($commentEnd < $len && $input[$commentEnd] !== ')') {
                $commentEnd++;
            }
            $result['type'] = self::GROUP_COMMENT;
            $result['raw'] = substr($input, $pos, $commentEnd - $pos + 1);
            $result['end'] = $commentEnd + 1;
            return $result;
        }

        if ($char === 'R') {
            $result['type'] = self::GROUP_RECURSION;
            $result['raw'] = '(?R';
            $result['end'] = $pos2 + 1;
            return $result;
        }

        if (ctype_alpha($char) || $char === '-') {
            $modEnd = $pos2;
            while ($modEnd < $len && (ctype_alpha($input[$modEnd]) || $input[$modEnd] === '-')) {
                $modEnd++;
            }
            if ($modEnd < $len && $input[$modEnd] === ':') {
                $modifiers = substr($input, $pos2, $modEnd - $pos2);
                $result['type'] = self::GROUP_MODIFIER;
                $result['modifiers'] = $modifiers;
                $result['raw'] = substr($input, $pos, $modEnd - $pos + 1);
                $result['end'] = $modEnd + 1;
                return $result;
            }
            if ($modEnd < $len && $input[$modEnd] === ')') {
                $modifiers = substr($input, $pos2, $modEnd - $pos2);
                $result['type'] = self::GROUP_MODIFIER;
                $result['modifiers'] = $modifiers;
                $result['raw'] = substr($input, $pos, $modEnd - $pos + 1);
                $result['end'] = $modEnd + 1;
                return $result;
            }
        }

        return $result;
    }

    /**
     * 解析大括号量词 {n} {n,} {n,m}
     */
    private static function parseBraceQuantifier(string $input, int $pos, int $len): ?array {
        $start = $pos;
        $pos++;

        if ($pos >= $len || !ctype_digit($input[$pos])) {
            return null;
        }

        $minStr = '';
        while ($pos < $len && ctype_digit($input[$pos])) {
            $minStr .= $input[$pos];
            $pos++;
        }

        if ($pos >= $len) {
            return null;
        }

        $maxStr = null;
        if ($input[$pos] === ',') {
            $pos++;
            $maxStr = '';
            while ($pos < $len && ctype_digit($input[$pos])) {
                $maxStr .= $input[$pos];
                $pos++;
            }
            if ($maxStr === '') {
                $maxStr = null;
            }
        }

        if ($pos >= $len || $input[$pos] !== '}') {
            return null;
        }

        $pos++;
        $mode = 'greedy';
        $type = self::TOKEN_QUANTIFIER;

        if ($pos < $len && $input[$pos] === '?') {
            $mode = 'lazy';
            $type = self::TOKEN_LAZY;
            $pos++;
        } elseif ($pos < $len && $input[$pos] === '+') {
            $mode = 'possessive';
            $type = self::TOKEN_POSSESSIVE;
            $pos++;
        }

        $raw = substr($input, $start, $pos - $start);
        $min = (int)$minStr;
        $max = $maxStr !== null ? (int)$maxStr : null;

        return [
            'token' => [
                'type'  => $type,
                'value' => $raw,
                'mode'  => $mode,
                'min'   => $min,
                'max'   => $max,
                'pos'   => $start,
            ],
            'end' => $pos,
        ];
    }

    /**
     * 解析数字反向引用
     */
    private static function parseBackreference(string $input, int $pos, int $len): array {
        $start = $pos;
        $pos += 2;
        $numStr = $input[$start + 1];

        while ($pos < $len && ctype_digit($input[$pos])) {
            $numStr .= $input[$pos];
            $pos++;
        }

        return [
            'token' => [
                'type'  => self::TOKEN_BACKREF,
                'value' => substr($input, $start, $pos - $start),
                'number' => (int)$numStr,
                'pos'   => $start,
            ],
            'end' => $pos,
        ];
    }

    /**
     * 解析命名反向引用 \k<name>
     */
    private static function parseNamedBackreference(string $input, int $pos, int $len): ?array {
        $start = $pos;
        if ($pos + 2 >= $len) {
            return null;
        }
        if ($input[$pos + 2] !== '<') {
            return null;
        }

        $pos += 3;
        $name = '';
        while ($pos < $len && $input[$pos] !== '>') {
            $name .= $input[$pos];
            $pos++;
        }

        if ($pos >= $len || $name === '') {
            return null;
        }

        $pos++;
        return [
            'token' => [
                'type'  => self::TOKEN_NAMED_BACKREF,
                'value' => substr($input, $start, $pos - $start),
                'name'  => $name,
                'pos'   => $start,
            ],
            'end' => $pos,
        ];
    }

    /**
     * 读取复杂转义序列 \x \u \c \p
     */
    private static function readComplexEscape(string $input, int $pos, int $len): array {
        $start = $pos;
        $type = $input[$pos + 1];
        $pos += 2;

        if ($type === 'x') {
            while ($pos < $len && ctype_xdigit($input[$pos]) && $pos - $start - 2 < 2) {
                $pos++;
            }
            $seqType = 'hex';
        } elseif ($type === 'u') {
            if ($pos < $len && $input[$pos] === '{') {
                $pos++;
                while ($pos < $len && $input[$pos] !== '}') {
                    $pos++;
                }
                if ($pos < $len) $pos++;
            } else {
                while ($pos < $len && ctype_xdigit($input[$pos]) && $pos - $start - 2 < 4) {
                    $pos++;
                }
            }
            $seqType = 'unicode';
        } elseif ($type === 'c') {
            if ($pos < $len) {
                $pos++;
            }
            $seqType = 'control';
        } elseif ($type === 'p' || $type === 'P') {
            if ($pos < $len && $input[$pos] === '{') {
                while ($pos < $len && $input[$pos] !== '}') {
                    $pos++;
                }
                if ($pos < $len) $pos++;
            } elseif ($pos < $len) {
                $pos++;
            }
            $seqType = 'property';
        } else {
            $seqType = 'unknown';
        }

        return [
            'seq'  => substr($input, $start, $pos - $start),
            'type' => $seqType,
            'end'  => $pos,
        ];
    }

    // ==================== Parser ====================

    /**
     * 正则表达式语法分析，构建 AST
     *
     * @param array $tokens
     * @param string $input
     * @return array|null
     */
    private static function parse(array $tokens, string $input): ?array {
        $state = [
            'tokens'             => $tokens,
            'pos'                => 0,
            'input'              => $input,
            'group_count'        => 0,
            'capture_count'      => 0,
            'named_groups'       => [],
            'quantifier_count'   => 0,
            'alternation_count'  => 0,
            'backref_count'      => 0,
            'max_nesting_depth'  => 0,
        ];

        $ast = self::parseRegex($state, 0);
        if ($ast === null) {
            return null;
        }

        $ast['group_count']        = $state['group_count'];
        $ast['capture_count']      = $state['capture_count'];
        $ast['named_groups']       = $state['named_groups'];
        $ast['quantifier_count']   = $state['quantifier_count'];
        $ast['alternation_count']  = $state['alternation_count'];
        $ast['backref_count']      = $state['backref_count'];
        $ast['max_nesting_depth']  = $state['max_nesting_depth'];

        return $ast;
    }

    /**
     * 解析完整正则表达式（可含多个分支）
     */
    private static function parseRegex(array &$state, int $depth): ?array {
        $branches = [];

        $branch = self::parseBranch($state, $depth);
        if ($branch === null) {
            return null;
        }
        $branches[] = $branch;

        while (self::current($state)['type'] === self::TOKEN_ALTERNATION) {
            self::next($state);
            $state['alternation_count']++;
            $branch = self::parseBranch($state, $depth);
            if ($branch !== null) {
                $branches[] = $branch;
            } else {
                $branches[] = ['type' => 'branch', 'items' => []];
            }
        }

        if (count($branches) === 1) {
            return $branches[0];
        }

        return [
            'type'     => 'alternation',
            'branches' => $branches,
        ];
    }

    /**
     * 解析分支（多个项的序列）
     */
    private static function parseBranch(array &$state, int $depth): ?array {
        $items = [];

        while (!self::isEof($state)) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_ALTERNATION ||
                $token['type'] === self::TOKEN_GROUP_END ||
                $token['type'] === self::TOKEN_EOF) {
                break;
            }

            $item = self::parseItem($state, $depth);
            if ($item === null) {
                break;
            }
            $items[] = $item;
        }

        return [
            'type'  => 'branch',
            'items' => $items,
        ];
    }

    /**
     * 解析项（原子 + 可选取量词）
     */
    private static function parseItem(array &$state, int $depth): ?array {
        $atom = self::parseAtom($state, $depth);
        if ($atom === null) {
            return null;
        }

        $token = self::current($state);
        if (in_array($token['type'], [self::TOKEN_QUANTIFIER, self::TOKEN_LAZY, self::TOKEN_POSSESSIVE], true)) {
            $state['quantifier_count']++;
            $quantifier = [
                'type'  => 'quantifier',
                'mode'  => $token['mode'],
                'min'   => $token['min'],
                'max'   => $token['max'],
                'raw'   => $token['value'],
            ];
            self::next($state);

            return [
                'type'       => 'item',
                'atom'       => $atom,
                'quantifier' => $quantifier,
            ];
        }

        return [
            'type'       => 'item',
            'atom'       => $atom,
            'quantifier' => null,
        ];
    }

    /**
     * 解析原子
     */
    private static function parseAtom(array &$state, int $depth): ?array {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_LITERAL) {
            self::next($state);
            return ['type' => 'literal', 'value' => $token['value']];
        }

        if ($token['type'] === self::TOKEN_ESCAPE) {
            self::next($state);
            return [
                'type'    => 'escape',
                'subtype' => $token['subtype'] ?? 'unknown',
                'value'   => $token['value'],
            ];
        }

        if ($token['type'] === self::TOKEN_ANY) {
            self::next($state);
            return ['type' => 'any', 'value' => '.'];
        }

        if ($token['type'] === self::TOKEN_ANCHOR) {
            self::next($state);
            return [
                'type'    => 'anchor',
                'subtype' => $token['subtype'] ?? 'unknown',
                'value'   => $token['value'],
            ];
        }

        if ($token['type'] === self::TOKEN_BACKREF) {
            $state['backref_count']++;
            self::next($state);
            return [
                'type'   => 'backreference',
                'number' => $token['number'],
                'value'  => $token['value'],
            ];
        }

        if ($token['type'] === self::TOKEN_NAMED_BACKREF) {
            $state['backref_count']++;
            self::next($state);
            return [
                'type'  => 'named_backreference',
                'name'  => $token['name'],
                'value' => $token['value'],
            ];
        }

        if ($token['type'] === self::TOKEN_CLASS_START) {
            return self::parseCharacterClass($state, $depth);
        }

        if ($token['type'] === self::TOKEN_GROUP_START) {
            return self::parseGroup($state, $depth);
        }

        return null;
    }

    /**
     * 解析字符类
     */
    private static function parseCharacterClass(array &$state, int $depth): array {
        self::next($state);

        $negated = false;
        if (self::current($state)['type'] === self::TOKEN_CLASS_NEGATE) {
            $negated = true;
            self::next($state);
        }

        $members = [];
        while (!self::isEof($state) && self::current($state)['type'] !== self::TOKEN_CLASS_END) {
            $member = self::parseClassMember($state);
            if ($member !== null) {
                $members[] = $member;
            } else {
                break;
            }
        }

        if (self::current($state)['type'] === self::TOKEN_CLASS_END) {
            self::next($state);
        }

        return [
            'type'    => 'character_class',
            'negated' => $negated,
            'members' => $members,
        ];
    }

    /**
     * 解析字符类成员
     */
    private static function parseClassMember(array &$state): ?array {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_LITERAL) {
            $first = $token['value'];
            self::next($state);

            if (self::current($state)['type'] === self::TOKEN_CLASS_RANGE) {
                self::next($state);
                $nextToken = self::current($state);
                if ($nextToken['type'] === self::TOKEN_LITERAL || $nextToken['type'] === self::TOKEN_ESCAPE) {
                    $second = $nextToken['value'];
                    self::next($state);
                    return [
                        'type'  => 'range',
                        'start' => $first,
                        'end'   => $second,
                    ];
                }
                return ['type' => 'char', 'value' => $first];
            }

            return ['type' => 'char', 'value' => $first];
        }

        if ($token['type'] === self::TOKEN_ESCAPE) {
            $escapeType = $token['subtype'] ?? 'unknown';
            $value = $token['value'];
            self::next($state);

            if (self::current($state)['type'] === self::TOKEN_CLASS_RANGE) {
                self::next($state);
                $nextToken = self::current($state);
                if ($nextToken['type'] === self::TOKEN_LITERAL || $nextToken['type'] === self::TOKEN_ESCAPE) {
                    $second = $nextToken['value'];
                    self::next($state);
                    return [
                        'type'  => 'range',
                        'start' => $value,
                        'end'   => $second,
                    ];
                }
            }

            return [
                'type'    => 'escape',
                'subtype' => $escapeType,
                'value'   => $value,
            ];
        }

        return null;
    }

    /**
     * 解析分组
     */
    private static function parseGroup(array &$state, int $depth): ?array {
        $startToken = self::current($state);
        $groupType = $startToken['group_type'] ?? self::GROUP_CAPTURE;
        $groupName = $startToken['name'] ?? null;
        $modifiers = $startToken['modifiers'] ?? null;

        $state['group_count']++;
        if ($groupType === self::GROUP_CAPTURE || $groupType === self::GROUP_NAMED) {
            $state['capture_count']++;
            if ($groupName !== null) {
                $state['named_groups'][] = $groupName;
            }
        }

        $currentDepth = $depth + 1;
        if ($currentDepth > $state['max_nesting_depth']) {
            $state['max_nesting_depth'] = $currentDepth;
        }

        self::next($state);

        if ($groupType === self::GROUP_COMMENT) {
            return [
                'type'      => 'group',
                'group_type' => $groupType,
                'content'   => null,
            ];
        }

        if ($groupType === self::GROUP_POSITIVE_LOOKAHEAD ||
            $groupType === self::GROUP_NEGATIVE_LOOKAHEAD ||
            $groupType === self::GROUP_POSITIVE_LOOKBEHIND ||
            $groupType === self::GROUP_NEGATIVE_LOOKBEHIND ||
            $groupType === self::GROUP_ATOMIC) {
            $inner = self::parseRegex($state, $currentDepth);
            if (self::current($state)['type'] === self::TOKEN_GROUP_END) {
                self::next($state);
            }
            return [
                'type'       => 'group',
                'group_type' => $groupType,
                'content'    => $inner,
            ];
        }

        $inner = self::parseRegex($state, $currentDepth);

        if (self::current($state)['type'] === self::TOKEN_GROUP_END) {
            self::next($state);
        }

        return [
            'type'       => 'group',
            'group_type' => $groupType,
            'name'       => $groupName,
            'modifiers'  => $modifiers,
            'content'    => $inner,
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

    private static function isEof(array &$state): bool {
        $t = self::current($state);
        return $t['type'] === self::TOKEN_EOF;
    }

    // ==================== Semantic Analysis ====================

    /**
     * 收集统计信息
     */
    private static function collectStats(array $ast): array {
        $stats = [
            'group_count'       => $ast['group_count'] ?? 0,
            'quantifier_count'  => $ast['quantifier_count'] ?? 0,
            'alternation_count' => $ast['alternation_count'] ?? 0,
            'backref_count'     => $ast['backref_count'] ?? 0,
            'star_height'       => 0,
            'nesting_depth'     => $ast['max_nesting_depth'] ?? 0,
        ];

        $stats['star_height'] = self::calcStarHeight($ast);

        return $stats;
    }

    /**
     * 计算星高（star height）
     */
    private static function calcStarHeight(?array $node): int {
        if ($node === null) {
            return 0;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item') {
            $atomHeight = self::calcStarHeight($node['atom'] ?? null);
            if (!empty($node['quantifier'])) {
                $quant = $node['quantifier'];
                $isStarLike = ($quant['max'] === null || $quant['max'] > 1);
                if ($isStarLike) {
                    return 1 + $atomHeight;
                }
            }
            return $atomHeight;
        }

        if ($type === 'group') {
            return self::calcStarHeight($node['content'] ?? null);
        }

        if ($type === 'alternation') {
            $maxH = 0;
            foreach ($node['branches'] ?? [] as $branch) {
                $h = self::calcStarHeight($branch);
                if ($h > $maxH) $maxH = $h;
            }
            return $maxH;
        }

        if ($type === 'branch') {
            $maxH = 0;
            foreach ($node['items'] ?? [] as $item) {
                $h = self::calcStarHeight($item);
                if ($h > $maxH) $maxH = $h;
            }
            return $maxH;
        }

        if ($type === 'character_class') {
            return 0;
        }

        return 0;
    }

    /**
     * 检测 ReDoS 模式
     */
    private static function detectRedosPatterns(array $ast): array {
        $patterns = [];
        $complexity = self::COMPLEXITY_POLYNOMIAL;

        $nestedResult = self::detectNestedQuantifiers($ast);
        if (!empty($nestedResult)) {
            foreach ($nestedResult as $p) {
                $patterns[] = $p;
            }
            $complexity = self::COMPLEXITY_EXPONENTIAL;
        }

        $overlapAlternation = self::detectOverlappingAlternation($ast);
        if (!empty($overlapAlternation)) {
            foreach ($overlapAlternation as $p) {
                $patterns[] = $p;
            }
            if ($complexity !== self::COMPLEXITY_EXPONENTIAL) {
                $complexity = self::COMPLEXITY_EXPONENTIAL;
            }
        }

        $adjacentOverlap = self::detectAdjacentOverlapping($ast);
        if (!empty($adjacentOverlap)) {
            foreach ($adjacentOverlap as $p) {
                $patterns[] = $p;
            }
            if (count($adjacentOverlap) >= 2 && $complexity !== self::COMPLEXITY_EXPONENTIAL) {
                $complexity = self::COMPLEXITY_EXPONENTIAL;
            }
        }

        $optionalQuant = self::detectOptionalQuantifierCombo($ast);
        if (!empty($optionalQuant)) {
            foreach ($optionalQuant as $p) {
                $patterns[] = $p;
            }
        }

        $multiLevel = self::detectMultiLevelBacktracking($ast);
        if (!empty($multiLevel)) {
            foreach ($multiLevel as $p) {
                $patterns[] = $p;
            }
            $complexity = self::COMPLEXITY_EXPONENTIAL;
        }

        $classQuantBacktrack = self::detectClassQuantifierBacktrack($ast);
        if (!empty($classQuantBacktrack)) {
            foreach ($classQuantBacktrack as $p) {
                $patterns[] = $p;
            }
        }

        return [
            'patterns'   => array_values(array_unique($patterns)),
            'complexity' => $complexity,
        ];
    }

    /**
     * 检测嵌套量词 (a+)+ (a*)* (a?)?
     */
    private static function detectNestedQuantifiers(?array $node, int $depth = 0): array {
        $patterns = [];
        if ($node === null) {
            return $patterns;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item' && !empty($node['quantifier'])) {
            $quant = $node['quantifier'];
            $isRepeating = ($quant['max'] === null || $quant['max'] > 1);
            if ($isRepeating) {
                $hasInnerRepeating = self::hasRepeatingQuantifier($node['atom'] ?? null);
                if ($hasInnerRepeating) {
                    $patterns[] = 'nested_quantifier';
                }
            }
        }

        if ($type === 'item') {
            $patterns = array_merge($patterns, self::detectNestedQuantifiers($node['atom'] ?? null, $depth));
        }

        if ($type === 'group') {
            $patterns = array_merge($patterns, self::detectNestedQuantifiers($node['content'] ?? null, $depth + 1));
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                $patterns = array_merge($patterns, self::detectNestedQuantifiers($branch, $depth));
            }
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                $patterns = array_merge($patterns, self::detectNestedQuantifiers($item, $depth));
            }
        }

        return array_unique($patterns);
    }

    /**
     * 检查节点内部是否包含重复量词
     */
    private static function hasRepeatingQuantifier(?array $node): bool {
        if ($node === null) {
            return false;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item') {
            if (!empty($node['quantifier'])) {
                $quant = $node['quantifier'];
                if ($quant['max'] === null || $quant['max'] > 1) {
                    return true;
                }
            }
            return self::hasRepeatingQuantifier($node['atom'] ?? null);
        }

        if ($type === 'group') {
            $groupType = $node['group_type'] ?? '';
            if (in_array($groupType, [
                self::GROUP_CAPTURE,
                self::GROUP_NON_CAPTURE,
                self::GROUP_NAMED,
                self::GROUP_ATOMIC,
            ], true)) {
                return self::hasRepeatingQuantifier($node['content'] ?? null);
            }
            return false;
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                if (self::hasRepeatingQuantifier($branch)) {
                    return true;
                }
            }
            return false;
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                if (self::hasRepeatingQuantifier($item)) {
                    return true;
                }
            }
            return false;
        }

        return false;
    }

    /**
     * 检测重叠选择分支 (a|a)+ (a|aa)+
     */
    private static function detectOverlappingAlternation(?array $node): array {
        $patterns = [];
        if ($node === null) {
            return $patterns;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item' && !empty($node['quantifier'])) {
            $atom = $node['atom'] ?? null;
            if ($atom && $atom['type'] === 'group') {
                $content = $atom['content'] ?? null;
                if ($content && $content['type'] === 'alternation') {
                    if (self::hasOverlappingBranches($content)) {
                        $patterns[] = 'overlapping_alternation';
                    }
                }
            }
        }

        if ($type === 'item') {
            $patterns = array_merge($patterns, self::detectOverlappingAlternation($node['atom'] ?? null));
        }

        if ($type === 'group') {
            $patterns = array_merge($patterns, self::detectOverlappingAlternation($node['content'] ?? null));
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                $patterns = array_merge($patterns, self::detectOverlappingAlternation($branch));
            }
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                $patterns = array_merge($patterns, self::detectOverlappingAlternation($item));
            }
        }

        return array_unique($patterns);
    }

    /**
     * 检查分支是否重叠
     */
    private static function hasOverlappingBranches(array $alternation): bool {
        $branches = $alternation['branches'] ?? [];
        if (count($branches) < 2) {
            return false;
        }

        $signatures = [];
        foreach ($branches as $branch) {
            $sig = self::getBranchCharacterSignature($branch);
            $signatures[] = $sig;
        }

        for ($i = 0; $i < count($signatures); $i++) {
            for ($j = $i + 1; $j < count($signatures); $j++) {
                if (self::signaturesOverlap($signatures[$i], $signatures[$j])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 获取分支的字符特征
     */
    private static function getBranchCharacterSignature(array $branch): array {
        $sig = [
            'any'           => false,
            'digits'        => false,
            'word_chars'    => false,
            'whitespace'    => false,
            'literals'      => [],
            'can_be_empty'  => true,
        ];

        $items = $branch['items'] ?? [];
        foreach ($items as $item) {
            $atom = $item['atom'] ?? null;
            $quant = $item['quantifier'] ?? null;

            if ($atom) {
                $atomSig = self::getAtomCharacterSignature($atom);
                $sig['any']        = $sig['any'] || $atomSig['any'];
                $sig['digits']     = $sig['digits'] || $atomSig['digits'];
                $sig['word_chars'] = $sig['word_chars'] || $atomSig['word_chars'];
                $sig['whitespace'] = $sig['whitespace'] || $atomSig['whitespace'];
                $sig['literals']   = array_merge($sig['literals'], $atomSig['literals']);
            }

            if ($quant === null || ($quant['min'] ?? 0) > 0) {
                $sig['can_be_empty'] = false;
            }
        }

        return $sig;
    }

    /**
     * 获取原子的字符特征
     */
    private static function getAtomCharacterSignature(array $atom): array {
        $sig = [
            'any'        => false,
            'digits'     => false,
            'word_chars' => false,
            'whitespace' => false,
            'literals'   => [],
        ];

        $type = $atom['type'] ?? '';

        if ($type === 'any') {
            $sig['any'] = true;
        } elseif ($type === 'literal') {
            $sig['literals'][] = $atom['value'] ?? '';
        } elseif ($type === 'escape') {
            $subtype = $atom['subtype'] ?? '';
            if ($subtype === 'digit') {
                $sig['digits'] = true;
            } elseif ($subtype === 'word') {
                $sig['word_chars'] = true;
            } elseif ($subtype === 'whitespace') {
                $sig['whitespace'] = true;
            } elseif ($subtype === 'non_digit' || $subtype === 'non_word' || $subtype === 'non_whitespace') {
                $sig['any'] = true;
            } else {
                $sig['literals'][] = $atom['value'] ?? '';
            }
        } elseif ($type === 'character_class') {
            $sig = self::getClassSignature($atom, $sig);
        } elseif ($type === 'group') {
            $content = $atom['content'] ?? null;
            if ($content) {
                $contentSig = self::getBranchCharacterSignature($content['type'] === 'branch' ? $content : ['items' => [$content]]);
                $sig['any']        = $sig['any'] || $contentSig['any'];
                $sig['digits']     = $sig['digits'] || $contentSig['digits'];
                $sig['word_chars'] = $sig['word_chars'] || $contentSig['word_chars'];
                $sig['whitespace'] = $sig['whitespace'] || $contentSig['whitespace'];
                $sig['literals']   = array_merge($sig['literals'], $contentSig['literals']);
            }
        }

        return $sig;
    }

    /**
     * 获取字符类的特征
     */
    private static function getClassSignature(array $class, array $sig): array {
        $negated = !empty($class['negated']);
        $members = $class['members'] ?? [];

        $hasAny = false;
        $hasDigit = false;
        $hasWord = false;
        $hasWhitespace = false;
        $literalCount = 0;

        foreach ($members as $member) {
            $mType = $member['type'] ?? '';
            if ($mType === 'range') {
                $literalCount += 2;
                $start = $member['start'] ?? '';
                $end = $member['end'] ?? '';
                if (strlen($start) === 1 && strlen($end) === 1) {
                    $s = ord($start);
                    $e = ord($end);
                    if ($s <= ord('9') && $e >= ord('0')) $hasDigit = true;
                    if ($s <= ord('z') && $e >= ord('a')) $hasWord = true;
                    if ($s <= ord('Z') && $e >= ord('A')) $hasWord = true;
                    if ($e - $s > 10) $hasAny = true;
                }
            } elseif ($mType === 'escape') {
                $subtype = $member['subtype'] ?? '';
                if ($subtype === 'digit') $hasDigit = true;
                elseif ($subtype === 'word') $hasWord = true;
                elseif ($subtype === 'whitespace') $hasWhitespace = true;
                else $literalCount++;
            } else {
                $literalCount++;
            }
        }

        if ($negated) {
            $sig['any'] = true;
        } else {
            $sig['any']        = $hasAny;
            $sig['digits']     = $hasDigit;
            $sig['word_chars'] = $hasWord;
            $sig['whitespace'] = $hasWhitespace;
        }

        return $sig;
    }

    /**
     * 检查两个特征是否重叠
     */
    private static function signaturesOverlap(array $sig1, array $sig2): bool {
        if ($sig1['any'] || $sig2['any']) {
            return true;
        }

        if ($sig1['digits'] && $sig2['digits']) return true;
        if ($sig1['word_chars'] && $sig2['word_chars']) return true;
        if ($sig1['whitespace'] && $sig2['whitespace']) return true;

        if (!empty($sig1['literals']) && !empty($sig2['literals'])) {
            $intersect = array_intersect($sig1['literals'], $sig2['literals']);
            if (!empty($intersect)) return true;
        }

        if ($sig1['can_be_empty'] && $sig2['can_be_empty']) {
            return true;
        }

        return false;
    }

    /**
     * 检测相邻重叠量词 a+a+ \d+\d+
     */
    private static function detectAdjacentOverlapping(?array $node): array {
        $patterns = [];
        if ($node === null) {
            return $patterns;
        }

        $type = $node['type'] ?? '';

        if ($type === 'branch') {
            $items = $node['items'] ?? [];
            for ($i = 0; $i < count($items) - 1; $i++) {
                $item1 = $items[$i];
                $item2 = $items[$i + 1];

                if (!empty($item1['quantifier']) && !empty($item2['quantifier'])) {
                    $q1 = $item1['quantifier'];
                    $q2 = $item2['quantifier'];

                    $isRepeating1 = ($q1['max'] === null || $q1['max'] > 1);
                    $isRepeating2 = ($q2['max'] === null || $q2['max'] > 1);

                    if ($isRepeating1 && $isRepeating2) {
                        $sig1 = self::getAtomCharacterSignature($item1['atom'] ?? []);
                        $sig2 = self::getAtomCharacterSignature($item2['atom'] ?? []);
                        if (self::signaturesOverlap($sig1, $sig2)) {
                            $patterns[] = 'adjacent_overlapping_quantifiers';
                            break;
                        }
                    }
                }
            }
        }

        if ($type === 'item') {
            $patterns = array_merge($patterns, self::detectAdjacentOverlapping($node['atom'] ?? null));
        }

        if ($type === 'group') {
            $patterns = array_merge($patterns, self::detectAdjacentOverlapping($node['content'] ?? null));
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                $patterns = array_merge($patterns, self::detectAdjacentOverlapping($branch));
            }
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                $patterns = array_merge($patterns, self::detectAdjacentOverlapping($item));
            }
        }

        return array_unique($patterns);
    }

    /**
     * 检测可选+量词组合 (a?)* (a+)?
     */
    private static function detectOptionalQuantifierCombo(?array $node): array {
        $patterns = [];
        if ($node === null) {
            return $patterns;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item' && !empty($node['quantifier'])) {
            $quant = $node['quantifier'];
            $outerIsOptional = ($quant['min'] ?? 0) === 0;
            if ($outerIsOptional) {
                $hasInnerRepeating = self::hasRepeatingQuantifier($node['atom'] ?? null);
                if ($hasInnerRepeating) {
                    $patterns[] = 'optional_quantifier_combo';
                }
            }
        }

        if ($type === 'item') {
            $patterns = array_merge($patterns, self::detectOptionalQuantifierCombo($node['atom'] ?? null));
        }

        if ($type === 'group') {
            $patterns = array_merge($patterns, self::detectOptionalQuantifierCombo($node['content'] ?? null));
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                $patterns = array_merge($patterns, self::detectOptionalQuantifierCombo($branch));
            }
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                $patterns = array_merge($patterns, self::detectOptionalQuantifierCombo($item));
            }
        }

        return array_unique($patterns);
    }

    /**
     * 检测多级回溯 ((a+)+)+
     */
    private static function detectMultiLevelBacktracking(?array $node, int $level = 0): array {
        $patterns = [];
        if ($node === null) {
            return $patterns;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item' && !empty($node['quantifier'])) {
            $quant = $node['quantifier'];
            $isRepeating = ($quant['max'] === null || $quant['max'] > 1);
            if ($isRepeating) {
                $innerLevels = self::countNestedRepeatingLevels($node['atom'] ?? null);
                if ($innerLevels >= 2) {
                    $patterns[] = 'multi_level_backtracking';
                }
            }
        }

        if ($type === 'item') {
            $patterns = array_merge($patterns, self::detectMultiLevelBacktracking($node['atom'] ?? null, $level));
        }

        if ($type === 'group') {
            $patterns = array_merge($patterns, self::detectMultiLevelBacktracking($node['content'] ?? null, $level + 1));
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                $patterns = array_merge($patterns, self::detectMultiLevelBacktracking($branch, $level));
            }
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                $patterns = array_merge($patterns, self::detectMultiLevelBacktracking($item, $level));
            }
        }

        return array_unique($patterns);
    }

    /**
     * 计算嵌套重复层数
     */
    private static function countNestedRepeatingLevels(?array $node): int {
        if ($node === null) {
            return 0;
        }

        $type = $node['type'] ?? '';

        if ($type === 'item') {
            $innerLevels = self::countNestedRepeatingLevels($node['atom'] ?? null);
            if (!empty($node['quantifier'])) {
                $quant = $node['quantifier'];
                $isRepeating = ($quant['max'] === null || $quant['max'] > 1);
                if ($isRepeating) {
                    return 1 + $innerLevels;
                }
            }
            return $innerLevels;
        }

        if ($type === 'group') {
            $groupType = $node['group_type'] ?? '';
            if (in_array($groupType, [
                self::GROUP_CAPTURE,
                self::GROUP_NON_CAPTURE,
                self::GROUP_NAMED,
                self::GROUP_ATOMIC,
            ], true)) {
                return self::countNestedRepeatingLevels($node['content'] ?? null);
            }
            return 0;
        }

        if ($type === 'alternation') {
            $maxL = 0;
            foreach ($node['branches'] ?? [] as $branch) {
                $l = self::countNestedRepeatingLevels($branch);
                if ($l > $maxL) $maxL = $l;
            }
            return $maxL;
        }

        if ($type === 'branch') {
            $maxL = 0;
            foreach ($node['items'] ?? [] as $item) {
                $l = self::countNestedRepeatingLevels($item);
                if ($l > $maxL) $maxL = $l;
            }
            return $maxL;
        }

        return 0;
    }

    /**
     * 检测字符类+量词+回溯点模式 [\s\S]*?[\s\S]*
     */
    private static function detectClassQuantifierBacktrack(?array $node): array {
        $patterns = [];
        if ($node === null) {
            return $patterns;
        }

        $type = $node['type'] ?? '';

        if ($type === 'branch') {
            $items = $node['items'] ?? [];
            $greedyClasses = [];
            $lazyClasses = [];

            foreach ($items as $item) {
                $atom = $item['atom'] ?? null;
                $quant = $item['quantifier'] ?? null;

                if ($atom && $quant) {
                    $isBroadMatch = self::isBroadMatchingAtom($atom);
                    if ($isBroadMatch && ($quant['max'] === null || $quant['max'] > 10)) {
                        if ($quant['mode'] === 'greedy') {
                            $greedyClasses[] = $item;
                        } elseif ($quant['mode'] === 'lazy') {
                            $lazyClasses[] = $item;
                        }
                    }
                }
            }

            if (count($greedyClasses) >= 2) {
                $patterns[] = 'multiple_greedy_broad_match';
            }

            if (!empty($greedyClasses) && !empty($lazyClasses)) {
                $patterns[] = 'mixed_greedy_lazy_broad_match';
            }
        }

        if ($type === 'item') {
            $patterns = array_merge($patterns, self::detectClassQuantifierBacktrack($node['atom'] ?? null));
        }

        if ($type === 'group') {
            $patterns = array_merge($patterns, self::detectClassQuantifierBacktrack($node['content'] ?? null));
        }

        if ($type === 'alternation') {
            foreach ($node['branches'] ?? [] as $branch) {
                $patterns = array_merge($patterns, self::detectClassQuantifierBacktrack($branch));
            }
        }

        if ($type === 'branch') {
            foreach ($node['items'] ?? [] as $item) {
                $patterns = array_merge($patterns, self::detectClassQuantifierBacktrack($item));
            }
        }

        return array_unique($patterns);
    }

    /**
     * 判断是否为宽匹配原子（能匹配多种字符）
     */
    private static function isBroadMatchingAtom(array $atom): bool {
        $type = $atom['type'] ?? '';

        if ($type === 'any') {
            return true;
        }

        if ($type === 'character_class') {
            $members = $atom['members'] ?? [];
            $negated = !empty($atom['negated']);
            if ($negated) return true;
            if (count($members) >= 5) return true;
            foreach ($members as $member) {
                $mType = $member['type'] ?? '';
                if ($mType === 'range') return true;
                if ($mType === 'escape') {
                    $subtype = $member['subtype'] ?? '';
                    if (in_array($subtype, ['digit', 'word', 'whitespace'])) return true;
                }
            }
            return false;
        }

        if ($type === 'escape') {
            $subtype = $atom['subtype'] ?? '';
            return in_array($subtype, ['digit', 'word', 'whitespace', 'non_digit', 'non_word', 'non_whitespace']);
        }

        return false;
    }

    // ==================== Complexity Estimation ====================

    /**
     * 估算最长输入（触发回溯的输入长度估算）
     */
    private static function estimateLongestInput(array $ast, array $result): int {
        $starHeight = $result['star_height'] ?? 0;
        $quantCount = $result['quantifier_count'] ?? 0;
        $hasExponential = $result['estimated_complexity'] === self::COMPLEXITY_EXPONENTIAL;

        if ($hasExponential && $starHeight >= 2) {
            return 50;
        }
        if ($hasExponential) {
            return 100;
        }
        if ($starHeight >= 2) {
            return 200;
        }
        if ($quantCount >= 5) {
            return 500;
        }
        return 1000;
    }

    // ==================== Scoring ====================

    /**
     * 计算危险分数
     */
    private static function calculateScore(array $result): int {
        $score = 0;

        $patterns = $result['redos_patterns'] ?? [];

        if (in_array('nested_quantifier', $patterns, true)) {
            $score += 40;
        }
        if (in_array('multi_level_backtracking', $patterns, true)) {
            $score += 50;
        }
        if (in_array('overlapping_alternation', $patterns, true)) {
            $score += 35;
        }
        if (in_array('adjacent_overlapping_quantifiers', $patterns, true)) {
            $score += 25;
        }
        if (in_array('optional_quantifier_combo', $patterns, true)) {
            $score += 20;
        }
        if (in_array('multiple_greedy_broad_match', $patterns, true)) {
            $score += 20;
        }
        if (in_array('mixed_greedy_lazy_broad_match', $patterns, true)) {
            $score += 15;
        }

        if ($result['estimated_complexity'] === self::COMPLEXITY_EXPONENTIAL) {
            $score += 20;
        }

        $starHeight = $result['star_height'] ?? 0;
        if ($starHeight >= 3) {
            $score += 25;
        } elseif ($starHeight >= 2) {
            $score += 15;
        } elseif ($starHeight >= 1) {
            $score += 5;
        }

        $nestingDepth = $result['nesting_depth'] ?? 0;
        if ($nestingDepth >= 5) {
            $score += 15;
        } elseif ($nestingDepth >= 3) {
            $score += 8;
        }

        $groupCount = $result['group_count'] ?? 0;
        if ($groupCount > 50) {
            $score += 10;
        } elseif ($groupCount > 20) {
            $score += 5;
        }

        $quantCount = $result['quantifier_count'] ?? 0;
        if ($quantCount > 20) {
            $score += 10;
        } elseif ($quantCount > 10) {
            $score += 5;
        }

        $alternationCount = $result['alternation_count'] ?? 0;
        if ($alternationCount > 10) {
            $score += 8;
        } elseif ($alternationCount > 5) {
            $score += 4;
        }

        $backrefCount = $result['backref_count'] ?? 0;
        if ($backrefCount > 10) {
            $score += 10;
        } elseif ($backrefCount > 5) {
            $score += 5;
        }

        if (in_array('very_long_regex', $result['indicators'] ?? [], true)) {
            $score += 15;
        }

        if (in_array('excessive_groups', $result['indicators'] ?? [], true)) {
            $score += 10;
        }

        return min($score, 100);
    }

    /**
     * 确定危险等级
     */
    private static function determineRiskLevel(int $score): string {
        if ($score >= 80) {
            return self::RISK_CRITICAL;
        }
        if ($score >= 60) {
            return self::RISK_HIGH;
        }
        if ($score >= 35) {
            return self::RISK_MEDIUM;
        }
        if ($score >= 10) {
            return self::RISK_LOW;
        }
        return self::RISK_CLEAN;
    }

    // ==================== AST Summary ====================

    /**
     * 生成 AST 摘要
     */
    private static function summarizeAst(array $ast): array {
        $summary = [
            'type'               => $ast['type'] ?? 'unknown',
            'group_count'        => $ast['group_count'] ?? 0,
            'capture_count'      => $ast['capture_count'] ?? 0,
            'quantifier_count'   => $ast['quantifier_count'] ?? 0,
            'alternation_count'  => $ast['alternation_count'] ?? 0,
            'backref_count'      => $ast['backref_count'] ?? 0,
            'max_nesting_depth'  => $ast['max_nesting_depth'] ?? 0,
        ];
        return $summary;
    }

    // ==================== Fallback Analysis ====================

    /**
     * 正则 fallback 分析（基于简单正则匹配）
     */
    private static function fallbackRegexAnalysis(string $input, array $result): array {
        $len = strlen($input);
        $patterns = [];
        $score = 0;

        if (preg_match('/\([^()]*\+[?+]?\)\+[?+]?/', $input)) {
            $patterns[] = 'nested_quantifier';
            $score += 35;
        }

        if (preg_match('/\([^()]*\*[?+]?\)\*[?+]?/', $input)) {
            $patterns[] = 'nested_quantifier';
            $score += 35;
        }

        if (preg_match('/\([^()]*\?[?+]?\)\?[?+]?/', $input)) {
            $patterns[] = 'optional_quantifier_combo';
            $score += 15;
        }

        if (preg_match('/\([^()]*\|[^()]*\)\+/', $input)) {
            $patterns[] = 'alternation_plus';
            $score += 20;
        }

        if (preg_match('/(\+|\*|\?|\{\d+,?\d*\})\s*(\+|\*|\?|\{\d+,?\d*\})/', $input)) {
            $patterns[] = 'adjacent_quantifiers';
            $score += 15;
        }

        $starCount = substr_count($input, '*');
        $plusCount = substr_count($input, '+');
        $questionCount = substr_count($input, '?');
        $parenCount = substr_count($input, '(');
        $pipeCount = substr_count($input, '|');

        $quantCount = $starCount + $plusCount;
        if ($quantCount > 10) {
            $score += 10;
        }

        if ($parenCount > 20) {
            $score += 8;
        }

        if ($pipeCount > 5) {
            $score += 5;
        }

        if ($len > 1000) {
            $score += 10;
        }

        $result['is_regex'] = self::looksLikeRegex($input);
        $result['redos_patterns'] = array_values(array_unique($patterns));
        $result['has_redos_risk'] = !empty($patterns);
        $result['group_count'] = $parenCount;
        $result['quantifier_count'] = $quantCount;
        $result['alternation_count'] = $pipeCount;
        $result['score'] = min($score, 100);
        $result['risk_level'] = self::determineRiskLevel($result['score']);
        $result['indicators'][] = 'fallback_analysis';

        if ($len > 1000) {
            $result['indicators'][] = 'very_long_regex';
        }

        return $result;
    }

    /**
     * 简单判断输入是否像正则表达式
     */
    private static function looksLikeRegex(string $input): bool {
        $regexChars = ['*', '+', '?', '|', '^', '$', '\\', '[', ']', '(', ')', '{', '}'];
        $count = 0;
        foreach ($regexChars as $c) {
            $count += substr_count($input, $c);
        }
        if ($count >= 3) return true;

        if (preg_match('/\\\[dwsbDW]/', $input)) return true;

        return false;
    }
}
