<?php
/**
 * L6 逻辑推理引擎
 * 职责：对输入文本进行深度逻辑分析，识别攻击载荷中的逻辑模式，
 *       包括恒真式、恒假式、逻辑组合攻击、时间盲注、报错注入等。
 *       逻辑推理是检测高级 SQL 注入和逻辑漏洞的关键。
 */
defined('ABSPATH') || exit;

class LogicInference {
    /**
     * 恒真式模式（条件永真）
     */
    private static $tautology_patterns = [
        '/\b(?:or|and)\b\s+\d+\s*=\s*\d+/iu',
        '/\b(?:or|and)\b\s+[\'"]?([^\'"]+)[\'"]?\s*=\s*[\'"]?\1[\'"]?/iu',
        '/\b(?:or|and)\b\s+[\'"]?[\w]+[\'"]?\s*(?:like|rlike)\s*[\'"]?[\w]+[\'"]?/iu',
        '/\b(?:or|and)\b\s+(?:true|false|1|0)\b/iu',
        '/\b(?:or|and)\b\s+\(\s*\d+\s*=\s*\d+\s*\)/iu',
        '/\b(?:or|and)\b\s+(?:null|not\s+null)\b/iu',
        '/\b(?:or|and)\b\s+(?:exists|not\s+exists)\s*\(/iu',
        '/\b(?:or|and)\b\s+(?:length|count|char_length)\s*\([^)]+\)\s*>\s*0/iu',
        '/\b(?:or|and)\b\s+(?:substring|substr|mid)\s*\([^)]+\)\s*!=\s*[\'"]?[\w]+[\'"]?/iu',
    ];

    /**
     * 恒假式模式（条件永假）
     */
    private static $contradiction_patterns = [
        '/\b(?:or|and)\b\s+\d+\s*!=\s*\d+/iu',
        '/\b(?:or|and)\b\s+\d+\s*<\s*\d+\s+and\s+\d+\s*>\s*\d+/iu',
        '/\b(?:or|and)\b\s+(?:false|0)\s*=\s*(?:true|1)/iu',
        '/\b(?:or|and)\b\s+(?:null\s+is\s+not\s+null|null\s*=\s*[^nN])/iu',
    ];

    /**
     * 逻辑组合攻击模式
     */
    private static $logic_combination_patterns = [
        '/\b(?:or|and)\b[\s\S]{0,100}?(?:or|and)\b[\s\S]{0,100}?(?:or|and)\b/iu',
        '/\b(?:or|and)\b[\s\S]{0,50}?(?:union\s+select|select\s+\*)/iu',
        '/\b(?:or|and)\b[\s\S]{0,50}?(?:sleep|benchmark|waitfor)\b/iu',
        '/\b(?:or|and)\b[\s\S]{0,50}?(?:load_file|into\s+outfile)\b/iu',
        '/\b(?:case|when)\b[\s\S]{0,100}?(?:then|else)\b[\s\S]{0,100}?(?:end)\b/iu',
        '/\b(?:if|else)\b[\s\S]{0,80}?(?:then|endif)\b/iu',
        '/\b(?:coalesce|nullif)\s*\([^)]+\s*,\s*[^)]+\)/iu',
    ];

    /**
     * 时间盲注模式
     */
    private static $time_blind_patterns = [
        '/\bsleep\s*\(\s*[\d.]+(?:\s*,\s*[\d.]+)?\s*\)/iu',
        '/\bbenchmark\s*\(\s*\d+\s*,\s*[^)]+\s*\)/iu',
        '/\bwaitfor\s+delay\s+[\'"]\d+:\d+:\d+[\'"]/iu',
        '/\bsleep\s*\(\s*(?:select|case|if)\b/iu',
        '/\b(?:or|and)\b\s+(?:sleep|benchmark|waitfor)\b/iu',
        '/\bpg_sleep\s*\(\s*[\d.]+\s*\)/iu',
        '/\b(?:dbms_lock\.sleep|sys_context)\b/iu',
    ];

    /**
     * 报错注入模式
     */
    private static $error_based_patterns = [
        '/\b(?:extractvalue|updatexml)\s*\(\s*[^,]+,\s*[^)]+\s*\)/iu',
        '/\b(?:floor|rand)\s*\(\s*0\s*\)\s*\*\s*[^\s]+\s*\b(?:from|limit)/iu',
        '/\b(?:exp|sqrt|log)\s*\(\s*-\d+\s*\)/iu',
        '/\b(?:geometrycollection|multipoint|polygon)\s*\(\s*[^)]+\)/iu',
        '/\b(?:st_linefromtext|st_polyfromtext)\s*\(\s*[^)]+\)/iu',
        '/\b(?:concat|concat_ws)\s*\(\s*[^)]+\s*\)\s*~\s*0/iu',
        '/\b(?:mysql_error|pg_last_error|sqlserver_error)\b/iu',
        '/\b(?:@@version|version\(\)|@@global\.version)\b/iu',
        '/\b(?:group_concat|concat)\s*\(\s*[^)]+\s*\)/iu',
    ];

    /**
     * 布尔盲注模式
     */
    private static $boolean_blind_patterns = [
        '/\b(?:length|char_length|octet_length)\s*\([^)]+\)\s*>\s*\d+/iu',
        '/\b(?:substring|substr|mid|left|right)\s*\([^)]+\)\s*(?:=|!=|<|>)\s*[\'"]?[\w]+[\'"]?/iu',
        '/\b(?:ascii|ord|conv|cast)\s*\([^)]+\)\s*(?:=|!=|<|>)\s*\d+/iu',
        '/\b(?:if|case)\s*\([^)]+\s*,\s*[\d\w]+[^)]+\)/iu',
        '/\b(?:like|rlike|regexp)\s*[\'"]?[^"\']+[\'"]?/iu',
        '/\b(?:between|in)\s*\([^)]+\)/iu',
    ];

    /**
     * 逻辑推理分析
     *
     * @param string $text 归一化后的文本
     * @return array{score:int, patterns:array, logic_type:string, details:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return [
                'score'       => 0,
                'logic_type'  => 'none',
                'patterns'    => [],
                'details'     => [],
                'tautology_count'      => 0,
                'contradiction_count'  => 0,
                'logic_comb_count'     => 0,
                'time_blind_count'     => 0,
                'error_based_count'    => 0,
                'boolean_blind_count'  => 0,
            ];
        }

        $score = 0;
        $patterns = [];
        $details = [];
        $logicType = 'none';

        $tautologyCount = 0;
        foreach (self::$tautology_patterns as $pat) {
            if (@preg_match($pat, $text)) {
                $tautologyCount++;
                $patterns[] = 'tautology';
                $score += 25;
            }
        }
        if ($tautologyCount > 0) {
            $logicType = 'tautology';
            $details[] = "恒真式检测: {$tautologyCount} 个";
        }

        $contradictionCount = 0;
        foreach (self::$contradiction_patterns as $pat) {
            if (@preg_match($pat, $text)) {
                $contradictionCount++;
                $patterns[] = 'contradiction';
                $score += 20;
            }
        }
        if ($contradictionCount > 0) {
            if ($logicType === 'none') $logicType = 'contradiction';
            $details[] = "恒假式检测: {$contradictionCount} 个";
        }

        $logicCombCount = 0;
        foreach (self::$logic_combination_patterns as $pat) {
            if (@preg_match($pat, $text)) {
                $logicCombCount++;
                $patterns[] = 'logic_combination';
                $score += 15;
            }
        }
        if ($logicCombCount > 0) {
            if ($logicType === 'none') $logicType = 'logic_combination';
            $details[] = "逻辑组合攻击: {$logicCombCount} 个";
        }

        $timeBlindCount = 0;
        foreach (self::$time_blind_patterns as $pat) {
            if (@preg_match($pat, $text)) {
                $timeBlindCount++;
                $patterns[] = 'time_blind';
                $score += 30;
            }
        }
        if ($timeBlindCount > 0) {
            $logicType = 'time_blind';
            $details[] = "时间盲注: {$timeBlindCount} 个";
        }

        $errorBasedCount = 0;
        foreach (self::$error_based_patterns as $pat) {
            if (@preg_match($pat, $text)) {
                $errorBasedCount++;
                $patterns[] = 'error_based';
                $score += 25;
            }
        }
        if ($errorBasedCount > 0) {
            if ($logicType === 'none' || $logicType === 'tautology') $logicType = 'error_based';
            $details[] = "报错注入: {$errorBasedCount} 个";
        }

        $booleanBlindCount = 0;
        foreach (self::$boolean_blind_patterns as $pat) {
            if (@preg_match($pat, $text)) {
                $booleanBlindCount++;
                $patterns[] = 'boolean_blind';
                $score += 18;
            }
        }
        if ($booleanBlindCount > 0) {
            if ($logicType === 'none') $logicType = 'boolean_blind';
            $details[] = "布尔盲注: {$booleanBlindCount} 个";
        }

        // 逻辑链长度加成
        $totalPatterns = $tautologyCount + $contradictionCount + $logicCombCount + $timeBlindCount + $errorBasedCount + $booleanBlindCount;
        if ($totalPatterns >= 4) {
            $score += 20;
            $details[] = '多逻辑模式组合';
        } elseif ($totalPatterns >= 2) {
            $score += 10;
        }

        // 嵌套逻辑加成
        $nestedLogic = preg_match_all('/\((?:[^()]+|\([^()]*\))+\)/', $text, $matches);
        if ($nestedLogic >= 3) {
            $score += 12;
            $details[] = "深度嵌套逻辑: {$nestedLogic} 层";
        }

        $score = min(100, (int)round($score));

        return [
            'score'              => $score,
            'logic_type'         => $logicType,
            'logic_type_label'   => self::getLogicTypeLabel($logicType),
            'patterns'           => array_values(array_unique($patterns)),
            'details'            => $details,
            'tautology_count'    => $tautologyCount,
            'contradiction_count' => $contradictionCount,
            'logic_comb_count'   => $logicCombCount,
            'time_blind_count'   => $timeBlindCount,
            'error_based_count'  => $errorBasedCount,
            'boolean_blind_count' => $booleanBlindCount,
            'total_patterns'     => $totalPatterns,
        ];
    }

    /**
     * 获取逻辑类型中文标签
     */
    private static function getLogicTypeLabel(string $type): string {
        $labels = [
            'none'              => '无逻辑攻击',
            'tautology'         => '恒真式注入',
            'contradiction'     => '恒假式注入',
            'logic_combination' => '逻辑组合攻击',
            'time_blind'        => '时间盲注',
            'error_based'       => '报错注入',
            'boolean_blind'     => '布尔盲注',
        ];
        return $labels[$type] ?? $type;
    }
}
