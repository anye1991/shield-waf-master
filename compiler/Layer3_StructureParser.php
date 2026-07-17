<?php
defined('ABSPATH') || exit;

/**
 * Layer3：结构解析层
 *
 * 对输入文本进行 SQL / HTML / JS 结构解析，识别查询结构、DOM 结构、
 * 嵌套深度和复杂度，从而判断是否存在结构性注入特征。
 */
class Layer3_StructureParser {

    /**
     * 分析输入的语法结构
     *
     * @param string $text 待分析文本
     * @return array ['score'=>0-100, 'structures'=>[...]]
     */
    public static function analyze(string $text): array {
        $result = [
            'score'      => 0,
            'structures' => [],
        ];

        if ($text === '') {
            return $result;
        }

        $score = 0;

        // 1. SQL 结构解析
        $sqlStruct = self::parseSqlStructure($text);
        if ($sqlStruct['detected']) {
            $result['structures'][] = $sqlStruct;
            $score += $sqlStruct['risk'];
        }

        // 2. HTML 结构解析
        $htmlStruct = self::parseHtmlStructure($text);
        if ($htmlStruct['detected']) {
            $result['structures'][] = $htmlStruct;
            $score += $htmlStruct['risk'];
        }

        // 3. JS 结构解析
        $jsStruct = self::parseJsStructure($text);
        if ($jsStruct['detected']) {
            $result['structures'][] = $jsStruct;
            $score += $jsStruct['risk'];
        }

        // 4. PHP 结构解析
        $phpStruct = self::parsePhpStructure($text);
        if ($phpStruct['detected']) {
            $result['structures'][] = $phpStruct;
            $score += $phpStruct['risk'];
        }

        $result['score'] = max(0, min(100, (int) round($score)));
        return $result;
    }

    /**
     * 解析 SQL 查询结构
     */
    private static function parseSqlStructure(string $text): array {
        $struct = [
            'type'     => 'sql',
            'detected' => false,
            'clauses'  => [],
            'depth'    => 0,
            'risk'     => 0,
        ];

        $lower = strtolower($text);

        // 关键子句识别
        $clausePatterns = [
            'select'  => '/\bselect\b/i',
            'union'   => '/\bunion\s+(?:all\s+)?select\b/i',
            'from'    => '/\bfrom\b/i',
            'where'   => '/\bwhere\b/i',
            'group'   => '/\bgroup\s+by\b/i',
            'order'   => '/\border\s+by\b/i',
            'having'  => '/\bhaving\b/i',
            'insert'  => '/\binsert\s+into\b/i',
            'update'  => '/\bupdate\b.*\bset\b/is',
            'delete'  => '/\bdelete\s+from\b/i',
            'drop'    => '/\bdrop\s+(?:table|database)\b/i',
            'alter'   => '/\balter\s+table\b/i',
            'subquery'=> '/\bselect\b.*\(\s*select\b/is',
        ];

        $clauseCount = 0;
        foreach ($clausePatterns as $name => $p) {
            if (preg_match($p, $text)) {
                $struct['clauses'][] = $name;
                $clauseCount++;
            }
        }

        if ($clauseCount === 0) {
            return $struct;
        }

        $struct['detected'] = true;

        // 计算嵌套深度（括号嵌套）
        $depth = 0;
        $maxDepth = 0;
        for ($i = 0; $i < strlen($text); $i++) {
            $c = $text[$i];
            if ($c === '(') {
                $depth++;
                if ($depth > $maxDepth) {
                    $maxDepth = $depth;
                }
            } elseif ($c === ')') {
                if ($depth > 0) {
                    $depth--;
                }
            }
        }
        $struct['depth'] = $maxDepth;

        // 风险评估
        $risk = 0;
        if (in_array('union', $struct['clauses'])) {
            $risk += 25;
        }
        if (in_array('subquery', $struct['clauses'])) {
            $risk += 20;
        }
        if (in_array('drop', $struct['clauses']) || in_array('alter', $struct['clauses'])) {
            $risk += 25;
        }
        if (in_array('insert', $struct['clauses']) || in_array('delete', $struct['clauses']) || in_array('update', $struct['clauses'])) {
            $risk += 18;
        }
        // 多子句组合（完整 SQL 语句结构）
        if ($clauseCount >= 4) {
            $risk += 15;
        } elseif ($clauseCount >= 2) {
            $risk += 8;
        }
        // 嵌套深度风险
        if ($maxDepth >= 3) {
            $risk += 15;
        } elseif ($maxDepth >= 2) {
            $risk += 8;
        }
        // 检测注释截断
        if (preg_match('/--|#|\/\*/', $text)) {
            $risk += 10;
        }

        $struct['risk'] = min($risk, 60);
        return $struct;
    }

    /**
     * 解析 HTML DOM 结构
     */
    private static function parseHtmlStructure(string $text): array {
        $struct = [
            'type'     => 'html',
            'detected' => false,
            'tags'     => [],
            'depth'    => 0,
            'risk'     => 0,
        ];

        // 提取所有标签
        if (!preg_match_all('/<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/u', $text, $m)) {
            return $struct;
        }

        $struct['detected'] = true;
        $struct['tags'] = array_map('strtolower', $m[1]);

        // 高危标签
        $dangerousTags = ['script', 'iframe', 'svg', 'object', 'embed', 'img', 'video', 'audio', 'meta', 'base', 'form', 'input'];
        $hitDangerous = 0;
        foreach ($struct['tags'] as $tag) {
            if (in_array($tag, $dangerousTags)) {
                $hitDangerous++;
            }
        }

        // 计算标签嵌套深度
        $depth = 0;
        $maxDepth = 0;
        foreach ($m[0] as $tagStr) {
            if ($tagStr[1] !== '/') {
                // 开标签（自闭合不计）
                if (substr($tagStr, -2) !== '/>' && !in_array(strtolower($tagStr), ['<img', '<br>', '<hr>', '<input', '<meta', '<link'])) {
                    $depth++;
                    if ($depth > $maxDepth) {
                        $maxDepth = $depth;
                    }
                }
            } else {
                if ($depth > 0) {
                    $depth--;
                }
            }
        }
        $struct['depth'] = $maxDepth;

        // 检测事件处理器
        $eventCount = preg_match_all('/\bon\w+\s*=/iu', $text);
        // 检测伪协议
        $pseudoCount = preg_match_all('/(?:javascript|vbscript|data)\s*:/iu', $text);

        $risk = 0;
        if ($hitDangerous > 0) {
            $risk += min($hitDangerous * 12, 30);
        }
        if ($eventCount > 0) {
            $risk += min($eventCount * 10, 25);
        }
        if ($pseudoCount > 0) {
            $risk += min($pseudoCount * 12, 20);
        }
        if ($maxDepth >= 3) {
            $risk += 10;
        }

        $struct['risk'] = min($risk, 50);
        return $struct;
    }

    /**
     * 解析 JS 结构
     */
    private static function parseJsStructure(string $text): array {
        $struct = [
            'type'     => 'js',
            'detected' => false,
            'constructs' => [],
            'depth'    => 0,
            'risk'     => 0,
        ];

        $constructs = [];
        if (preg_match('/<script\b/i', $text)) {
            $constructs[] = 'script_tag';
        }
        if (preg_match('/\bfunction\s+\w+\s*\(/i', $text) || preg_match('/\bfunction\s*\(/i', $text)) {
            $constructs[] = 'function_decl';
        }
        if (preg_match('/\b(?:var|let|const)\s+\w+/i', $text)) {
            $constructs[] = 'variable_decl';
        }
        if (preg_match('/\beval\s*\(/i', $text)) {
            $constructs[] = 'eval_call';
        }
        if (preg_match('/\bdocument\./i', $text)) {
            $constructs[] = 'dom_access';
        }
        if (preg_match('/\bwindow\./i', $text)) {
            $constructs[] = 'window_access';
        }
        if (preg_match('/\bnew\s+Function\b/i', $text)) {
            $constructs[] = 'function_constructor';
        }

        if (!$constructs) {
            return $struct;
        }

        $struct['detected'] = true;
        $struct['constructs'] = $constructs;

        // 括号深度
        $depth = 0;
        $maxDepth = 0;
        for ($i = 0; $i < strlen($text); $i++) {
            if ($text[$i] === '{') {
                $depth++;
                if ($depth > $maxDepth) {
                    $maxDepth = $depth;
                }
            } elseif ($text[$i] === '}') {
                if ($depth > 0) {
                    $depth--;
                }
            }
        }
        $struct['depth'] = $maxDepth;

        $risk = 0;
        if (in_array('eval_call', $constructs)) {
            $risk += 25;
        }
        if (in_array('function_constructor', $constructs)) {
            $risk += 22;
        }
        if (in_array('dom_access', $constructs)) {
            $risk += 15;
        }
        if (in_array('script_tag', $constructs)) {
            $risk += 12;
        }
        if (count($constructs) >= 3) {
            $risk += 10;
        }

        $struct['risk'] = min($risk, 50);
        return $struct;
    }

    /**
     * 解析 PHP 结构
     */
    private static function parsePhpStructure(string $text): array {
        $struct = [
            'type'     => 'php',
            'detected' => false,
            'constructs' => [],
            'depth'    => 0,
            'risk'     => 0,
        ];

        $constructs = [];
        if (preg_match('/<\?(?:php|=)?/i', $text)) {
            $constructs[] = 'php_tag';
        }
        if (preg_match('/\b(?:eval|system|exec|shell_exec|passthru|assert|proc_open|popen)\s*\(/i', $text)) {
            $constructs[] = 'dangerous_call';
        }
        if (preg_match('/\b(?:include|require)(?:_once)?\s*[\(\s]/i', $text)) {
            $constructs[] = 'file_inclusion';
        }
        if (preg_match('/\b(?:file_get_contents|fopen|readfile|fwrite|file_put_contents)\s*\(/i', $text)) {
            $constructs[] = 'file_operation';
        }
        if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/i', $text)) {
            $constructs[] = 'superglobal';
        }

        if (!$constructs) {
            return $struct;
        }

        $struct['detected'] = true;
        $struct['constructs'] = $constructs;

        $risk = 0;
        if (in_array('dangerous_call', $constructs)) {
            $risk += 30;
        }
        if (in_array('file_inclusion', $constructs)) {
            $risk += 25;
        }
        if (in_array('php_tag', $constructs)) {
            $risk += 15;
        }
        if (in_array('superglobal', $constructs)) {
            $risk += 10;
        }

        $struct['risk'] = min($risk, 60);
        return $struct;
    }
}
