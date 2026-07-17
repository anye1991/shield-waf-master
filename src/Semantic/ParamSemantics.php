<?php
/**
 * 参数语义分析引擎
 * 职责：对单个参数（key/value）进行分类与预期类型推断，
 *       检测参数值与其语义预期不符的情况（如 id 参数中出现 SQL 语句）。
 */
defined('ABSPATH') || exit;

class ParamSemantics {
    /**
     * 参数名到预期类别的映射规则
     * 每项：pattern(正则) => 类别
     */
    private static $key_rules = [
        '/^(id|uid|gid|pid|cid|aid|fid|tid|nid|rid|sid|eid)$/i'    => 'identifier',
        '/_id$|id_\d+$/i'                                            => 'identifier',
        '/^(name|username|user|uname|login|account|author|nickname)$/i' => 'name',
        '/^(title|subject|topic|caption|headline)$/i'                => 'content',
        '/^(content|body|text|message|comment|desc|description|detail|bio|about)$/i' => 'content',
        '/^(q|query|keyword|keywords|search|kw|term|terms)$/i'       => 'search',
        '/^(page|p|limit|offset|size|count|num|number|qty|quantity|amount)$/i' => 'numeric',
        '/^(action|cmd|command|op|do|task|method|func|function)$/i'  => 'action',
        '/^(type|t|category|cat|tag|tags|status|state|level|mode)$/i' => 'flag',
        '/^(enabled|disabled|active|checked|selected|remember|agree|subscribe|remember_me)$/i' => 'flag',
        '/^(password|passwd|pwd|pass|token|secret|apikey|api_key|signature|sign|hash|captcha)$/i' => 'credential',
        '/^(email|mail|phone|tel|mobile|url|website|ip|address)$/i'  => 'contact',
        '/^(file|upload|attachment|avatar|image|img|logo|pic|photo)$/i' => 'file',
        '/^(redirect|redirect_to|return|returnurl|next|callback|target|to)$/i' => 'redirect',
    ];

    /**
     * 各类别预期值特征（用于检测不匹配）
     */
    private static $category_expect = [
        'identifier' => ['type' => 'numeric',   'desc' => '应为纯数字ID'],
        'numeric'    => ['type' => 'numeric',   'desc' => '应为数字'],
        'flag'       => ['type' => 'enum',      'desc' => '应为枚举标志值'],
        'action'     => ['type' => 'word',      'desc' => '应为单一动作词'],
        'name'       => ['type' => 'word',      'desc' => '应为普通名称'],
        'search'     => ['type' => 'freetext',  'desc' => '搜索词（自由文本但不应含代码）'],
        'content'    => ['type' => 'freetext',  'desc' => '富文本内容'],
        'contact'    => ['type' => 'format',    'desc' => '应为对应格式（邮箱/URL等）'],
        'file'       => ['type' => 'filename',  'desc' => '应为文件名'],
        'redirect'   => ['type' => 'path',      'desc' => '应为相对路径'],
        'credential' => ['type' => 'freetext',  'desc' => '凭证字符串'],
    ];

    /**
     * 危险特征检测（用于评估分数与不匹配判定）
     */
    private static $danger_patterns = [
        'sql'        => '/\b(?:union\s+(?:all\s+)?select|select\s+.*\s+from|\bdrop\s+table|information_schema)\b/iu',
        'sqli_logic' => '/[\'"][\s\S]{0,80}?\b(?:or|and)\b\s+\d+\s*=\s*\d+/iu',
        'rce'        => '/\b(?:eval|system|exec|shell_exec|passthru|assert)\s*\(/iu',
        'xss'        => '/<\w+[^>]*\bon\w+\s*=|<script\b|javascript:/iu',
        'path'       => '/\.\.[\/\\\\]|\/etc\/|php:\/\/(?:input|filter)/iu',
        'cmd'        => '/[;|&`]\s*\w+|\$\([^)]+\)/u',
        'html'       => '/<\w+[^>]*>/u',
    ];

    /**
     * 参数语义分析
     *
     * @param string $key 参数名
     * @param string $value 参数值
     * @return array{score:int, category:string, mismatch:bool}
     */
    public static function analyze(string $key, string $value): array {
        $category = 'unknown';
        $score = 0;
        $mismatch = false;
        $reasons = [];

        // ---- 1. 推断参数类别 ----
        foreach (self::$key_rules as $pattern => $cat) {
            if (preg_match($pattern, $key)) {
                $category = $cat;
                break;
            }
        }
        // 未命中规则时按值特征粗分
        if ($category === 'unknown') {
            if ($value !== '' && ctype_digit($value)) {
                $category = 'numeric';
            } elseif (in_array(strtolower($value), ['true', 'false', '1', '0', 'yes', 'no', 'on', 'off'], true)) {
                $category = 'flag';
            } else {
                $category = 'content';
            }
        }

        // ---- 2. 危险特征检测 ----
        $dangerHits = [];
        foreach (self::$danger_patterns as $type => $pat) {
            if (@preg_match($pat, $value)) {
                $dangerHits[] = $type;
                $score += 25;
            }
        }

        // ---- 3. 预期类型匹配检查 ----
        $expect = self::$category_expect[$category] ?? null;
        if ($expect) {
            $expType = $expect['type'];
            $valueLen = strlen($value);
            $isNumeric = ($value !== '' && preg_match('/^-?\d+(\.\d+)?$/', $value));

            switch ($expType) {
                case 'numeric':
                    if (!$isNumeric) {
                        $mismatch = true;
                        $score += 30;
                        $reasons[] = 'expected_numeric_but_got_other';
                    }
                    break;
                case 'enum':
                    $validEnums = ['0', '1', 'true', 'false', 'yes', 'no', 'on', 'off', 'enabled', 'disabled', 'active', 'inactive'];
                    if ($value !== '' && !in_array(strtolower($value), $validEnums, true)) {
                        // 枚举值预期，但出现长串 / 特殊字符
                        if ($valueLen > 20 || preg_match('/[<>\'"\\\]/', $value)) {
                            $mismatch = true;
                            $score += 20;
                            $reasons[] = 'expected_enum_but_got_complex';
                        }
                    }
                    break;
                case 'word':
                    // 名称类不应包含代码结构字符
                    if (preg_match('/[<>\'"`;|&`$(){}\[\]\\\\]/', $value)) {
                        $mismatch = true;
                        $score += 20;
                        $reasons[] = 'expected_word_but_got_special_chars';
                    }
                    break;
                case 'filename':
                    // 文件名不应包含路径分隔符或遍历
                    if (preg_match('/[\/\\\\]|\.\./', $value)) {
                        $mismatch = true;
                        $score += 25;
                        $reasons[] = 'expected_filename_but_got_path';
                    }
                    break;
                case 'path':
                    // 重定向参数不应指向危险伪协议
                    if (preg_match('/^(javascript|data|vbscript):/i', $value)) {
                        $mismatch = true;
                        $score += 25;
                        $reasons[] = 'redirect_to_dangerous_protocol';
                    }
                    break;
                case 'format':
                    // 邮箱 / URL 等格式校验
                    if ($key === 'email' || $key === 'mail') {
                        if ($value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                            // 邮箱格式异常但未必攻击；仅当含危险字符时计分
                            if (preg_match('/[<>\'"`;|&]/', $value)) {
                                $mismatch = true;
                                $score += 15;
                                $reasons[] = 'malformed_email_with_special_chars';
                            }
                        }
                    }
                    break;
                case 'freetext':
                    // 自由文本不应出现命令 / SQL 结构（已在危险特征中计分）
                    if (in_array('sql', $dangerHits, true) || in_array('rce', $dangerHits, true)) {
                        $mismatch = true;
                        $reasons[] = 'freetext_contains_code_structure';
                    }
                    break;
            }
        }

        // ---- 4. 长度异常（短参数名携带超长值，常见于注入载荷） ----
        if (strlen($key) <= 4 && strlen($value) > 200) {
            $score += 8;
            $reasons[] = 'short_key_long_value';
        }

        $score = max(0, min(100, (int) round($score)));
        return [
            'score'    => $score,
            'category' => $category,
            'mismatch' => $mismatch,
            'reasons'  => $reasons,
        ];
    }
}
