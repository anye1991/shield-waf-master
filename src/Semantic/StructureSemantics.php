<?php
/**
 * 结构语义分析引擎
 * 职责：从整体结构层面识别输入是否构成可执行的代码结构、SQL 结构、命令行结构或路径结构。
 *       结构比单点字符 / 词汇更具攻击意图证明力。
 */
defined('ABSPATH') || exit;

class StructureSemantics {
    /**
     * 结构化模式规则
     * 每项：pattern(正则) => [类型, 权重, 描述]
     */
    private static $structure_patterns = [
        // ---- SQL 结构 ----
        '/\bselect\b[\s\S]{1,200}?\bfrom\b/iu'                                         => ['sql_select', 30, 'SELECT...FROM查询结构'],
        '/\bunion\b[\s\S]{0,60}?\bselect\b/iu'                                          => ['sql_union', 35, 'UNION SELECT联合查询结构'],
        '/\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|alter\s+table|truncate\s+table)\b/iu' => ['sql_dml', 30, 'SQL DML/DDL结构'],
        '/\bwhere\b[\s\S]{0,200}?(?:=|like|>|<|in\s*\()/iu'                             => ['sql_where', 20, 'WHERE条件结构'],
        '/\b(?:or|and)\b\s+[\'"\d]?[\w\'"]+\s*=\s*[\'"\d]?[\w\'"]+/iu'                  => ['sql_logic_chain', 25, 'SQL逻辑永真/永假链'],
        '/--\s|\/\*[\s\S]*?\*\//u'                                                       => ['sql_comment', 12, 'SQL注释结构'],
        '/\binformation_schema\.\w+/iu'                                                  => ['sql_meta_query', 25, '元数据查询结构'],

        // ---- HTML / JS 结构 ----
        '/<\w+[^>]*>/iu'                                                                  => ['html_tag', 10, 'HTML标签结构'],
        '/<\w+[^>]*\bon\w+\s*=/iu'                                                        => ['html_event_handler', 25, 'HTML事件处理器结构'],
        '/<script\b[\s\S]*?<\/script>/iu'                                                => ['js_script_block', 30, 'script脚本块结构'],
        '/javascript:\s*[\w\W]/iu'                                                       => ['js_pseudo_protocol', 22, 'JavaScript伪协议结构'],
        '/<svg\b/iu'                                                                      => ['svg_payload', 18, 'SVG载荷结构'],
        '/<iframe\b/iu'                                                                   => ['iframe_payload', 18, 'iframe载荷结构'],
        '/<img\b[^>]*\bon\w+\s*=/iu'                                                      => ['img_event_xss', 22, 'img事件XSS结构'],

        // ---- 命令行结构 ----
        '/;\s*\w+/u'                                                                      => ['cmd_chain_semicolon', 12, '分号命令链结构'],
        '/&&|\|\|/u'                                                                      => ['cmd_chain_logical', 15, '逻辑命令链结构'],
        '/\|\s*\w+/u'                                                                     => ['cmd_pipe', 15, '管道命令结构'],
        '/`[^`]+`/u'                                                                      => ['cmd_backtick', 18, '反引号命令替换结构'],
        '/\$\([^)]+\)/u'                                                                  => ['cmd_subshell', 18, '$()命令替换结构'],

        // ---- 路径结构 ----
        '/\.\.[\/\\\\]/u'                                                                 => ['path_traversal', 20, '路径遍历结构'],
        '/(?:\/etc\/|\/proc\/|\/var\/|\/root\/|\/tmp\/)\w+/iu'                           => ['unix_path', 18, 'Unix敏感路径结构'],
        '/[a-z]:\\\\(?:windows|users|program|system32)/iu'                                => ['windows_path', 18, 'Windows敏感路径结构'],
        '/php:\/\/(?:input|filter|data)/iu'                                              => ['php_wrapper', 25, 'PHP流封装结构'],
        '/data:text\/html/iu'                                                             => ['data_uri', 18, 'data URI结构'],

        // ---- 编码 / 混淆结构 ----
        '/[A-Za-z0-9+\/]{40,}={0,2}/'                                                    => ['base64_blob', 10, 'Base64长串结构'],
        '/%[0-9a-f]{2}/iu'                                                                => ['url_encoded', 8, 'URL编码结构'],
        '/0x[0-9a-f]{4,}/iu'                                                              => ['hex_blob', 10, '十六进制长串结构'],
    ];

    /**
     * 结构语义分析
     *
     * @param string $text
     * @return array{score:int, structures:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return ['score' => 0, 'structures' => []];
        }

        $structures = [];
        $score = 0;
        $hitTypes = [];

        foreach (self::$structure_patterns as $pattern => $info) {
            $type = $info[0];
            $weight = $info[1];
            $desc = $info[2];
            $matches = 0;
            if (@preg_match($pattern, $text)) {
                // 统计出现次数，封顶3次
                $full = @preg_match_all($pattern, $text);
                $matches = $full ? min(3, $full) : 1;
            }
            if ($matches > 0) {
                $hitTypes[$type] = $matches;
                $structures[] = [
                    'type'  => $type,
                    'desc'  => $desc,
                    'count' => $matches,
                    'weight'=> $weight,
                ];
                // 多次命中递增收益递减
                $score += $weight + ($matches - 1) * min(5, (int) floor($weight / 3));
            }
        }

        // ---- 结构组合加成：同一次请求中出现多类别结构，攻击意图更强 ----
        $catTypes = ['sql' => [], 'html' => [], 'cmd' => [], 'path' => []];
        foreach (array_keys($hitTypes) as $t) {
            if (strpos($t, 'sql') === 0) {
                $catTypes['sql'][] = $t;
            } elseif (in_array($t, ['html_tag', 'html_event_handler', 'js_script_block', 'js_pseudo_protocol', 'svg_payload', 'iframe_payload', 'img_event_xss'], true)) {
                $catTypes['html'][] = $t;
            } elseif (strpos($t, 'cmd') === 0) {
                $catTypes['cmd'][] = $t;
            } elseif (strpos($t, 'path') === 0 || strpos($t, 'unix') === 0 || strpos($t, 'windows') === 0 || strpos($t, 'php_wrapper') === 0 || strpos($t, 'data_uri') === 0) {
                $catTypes['path'][] = $t;
            }
        }
        $activeCats = 0;
        foreach ($catTypes as $types) {
            if (!empty($types)) {
                $activeCats++;
            }
        }
        if ($activeCats >= 2) {
            $score += 12;
            $structures[] = ['type' => 'multi_category', 'desc' => '多类别结构混合', 'count' => $activeCats, 'weight' => 12];
        }

        // ---- 结构嵌套深度（括号层数）作为代码结构指标 ----
        $depth = self::maxBracketDepth($text);
        if ($depth >= 4) {
            $score += 10;
            $structures[] = ['type' => 'deep_nesting', 'desc' => '深层括号嵌套(代码结构)', 'count' => $depth, 'weight' => 10];
        } elseif ($depth >= 2) {
            $score += 4;
        }

        $score = max(0, min(100, (int) round($score)));
        return ['score' => $score, 'structures' => $structures];
    }

    /**
     * 计算括号最大嵌套深度（综合 () [] {}）
     */
    private static function maxBracketDepth(string $text): int {
        $depth = 0;
        $max = 0;
        $len = strlen($text);
        for ($i = 0; $i < $len; $i++) {
            $c = $text[$i];
            if ($c === '(' || $c === '[' || $c === '{') {
                $depth++;
                if ($depth > $max) {
                    $max = $depth;
                }
            } elseif ($c === ')' || $c === ']' || $c === '}') {
                if ($depth > 0) {
                    $depth--;
                }
            }
        }
        return $max;
    }
}
