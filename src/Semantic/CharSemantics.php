<?php
/**
 * 字符级攻击意图推理引擎
 *
 * 职责：从字符层面推理攻击意图，而非简单的字符频率统计。
 * 包括：字符序列模式推理、字符分布异常检测、字符级编码链检测、
 *       字符上下文语义、零宽字符位置分析、同形字检测等。
 *
 * 升级说明：从 substr_count + 熵值的浅层统计，升级为字符序列意图、
 *           分布模式、编码链、上下文角色四维联合推理。
 */
defined('ABSPATH') || exit;

class CharSemantics {
    /**
     * 危险特殊字符及其单字符权重（保留，但降为辅助指标）
     * @var array<string,int>
     */
    private static $danger_chars = [
        '<' => 3, '>' => 3,   // HTML/JS 标签
        '\'' => 4, '"' => 4,   // 字符串 / SQL 闭合符
        ';' => 3,              // 语句分隔 / 命令链
        '|' => 5, '&' => 4,    // 命令管道与后台符
        '`' => 5,              // 命令替换
        '$' => 4,              // 变量引用
        '(' => 2, ')' => 2,    // 函数调用
        '{' => 2, '}' => 2,    // 代码块
        '\\' => 3,             // 转义 / 路径
        '/' => 2,              // 路径 / 正则
        '%' => 3,              // 编码 / 通配
        '#' => 2,              // 注释
        '=' => 2,              // 赋值
        '*' => 2,              // 通配 / SQL
        '?' => 1,              // 查询串 / PHP
        '!' => 1,
    ];

    /**
     * 零宽字符与不可见 Unicode 字符（UTF-8 字节序列）
     * 这些字符在正常输入中几乎不应出现，命中即高可疑。
     * @var array<string,string>
     */
    private static $invisible_chars = [
        "\u{200B}" => 'ZWSP', // 零宽空格
        "\u{200C}" => 'ZWNJ', // 零宽非连接符
        "\u{200D}" => 'ZWJ',  // 零宽连接符
        "\u{FEFF}" => 'BOM',  // 字节顺序标记
        "\u{2060}" => 'WJ',   // 字连接符
        "\u{00AD}" => 'SHY',  // 软连字符
    ];

    /**
     * 字符集区间（用于识别混用字符集 / 同形字混淆）
     * 每项：名称 => [起始码点, 结束码点]
     */
    private static $script_ranges = [
        'latin'    => [0x0041, 0x024F], // 拉丁字母（含扩展）
        'cyrillic' => [0x0400, 0x04FF],
        'greek'    => [0x0370, 0x03FF],
        'cjk'      => [0x4E00, 0x9FFF],
        'arabic'   => [0x0600, 0x06FF],
        'hebrew'   => [0x0590, 0x05FF],
    ];

    /**
     * SQL 关键词（小写），用于上下文语义判断
     * @var string[]
     */
    private static $sql_keywords = [
        'select', 'union', 'from', 'where', 'and', 'or', 'insert',
        'update', 'delete', 'drop', 'exec', 'concat', 'sleep',
        'benchmark', 'load_file', 'into', 'outfile', 'having',
        'null', 'true', 'false',
    ];

    /**
     * 零宽字符出现于其中的可疑关键词集合（用于位置语义分析）
     * @var string[]
     */
    private static $zw_sensitive_keywords = [
        'select', 'union', 'script', 'alert', 'onerror', 'onload',
        'javascript', 'eval', 'document', 'iframe', 'onclick',
    ];

    /**
     * 函数调用模式：标识符 + (
     */
    public const FUNC_NAME_PATTERN = '/[a-zA-Z_][a-zA-Z0-9_]*\s*\(/';

    /**
     * 字符级攻击意图推理入口
     *
     * @param string $text 待分析文本
     * @return array{score:int, indicators:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return ['score' => 0, 'indicators' => []];
        }

        $indicators = [];
        $lower = strtolower($text);
        $hits = []; // 收集各维度命中分值，用于交叉加成

        // ============== 1. 字符序列模式推理 ==============
        $seq = self::detectSequencePatterns($text, $lower);
        foreach ($seq['indicators'] as $ind) {
            $indicators[] = $ind;
        }
        if ($seq['score'] > 0) {
            $hits['sequence'] = $seq['score'];
        }

        // ============== 2. 字符分布异常检测 ==============
        $dist = self::detectDistributionAnomaly($text);
        foreach ($dist['indicators'] as $ind) {
            $indicators[] = $ind;
        }
        if ($dist['score'] > 0) {
            $hits['distribution'] = $dist['score'];
        }

        // ============== 3. 字符级编码链检测 ==============
        $enc = self::detectEncodingChain($text);
        foreach ($enc['indicators'] as $ind) {
            $indicators[] = $ind;
        }
        if ($enc['score'] > 0) {
            $hits['encoding_chain'] = $enc['score'];
        }

        // ============== 4. 字符上下文语义 ==============
        $ctx = self::detectContextSemantics($text, $lower);
        foreach ($ctx['indicators'] as $ind) {
            $indicators[] = $ind;
        }
        if ($ctx['score'] > 0) {
            $hits['context'] = $ctx['score'];
        }

        // ============== 5. 基础辅助能力（保留原有，降为辅助） ==============
        $base = self::detectBaseFeatures($text, strlen($text));
        foreach ($base['indicators'] as $ind) {
            $indicators[] = $ind;
        }
        if ($base['score'] > 0) {
            $hits['base'] = $base['score'];
        }

        // ============== 6. 评分汇总与交叉加成 ==============
        $score = array_sum($hits);

        $hitCount = count($hits);
        if ($hitCount >= 4) {
            $score += 15;
            $indicators[] = 'cross_bonus:4dims+';
        } elseif ($hitCount === 3) {
            $score += 8;
            $indicators[] = 'cross_bonus:3dims';
        } elseif ($hitCount === 2) {
            $score += 3;
        }

        $score = max(0, min(100, (int) round($score)));
        return ['score' => $score, 'indicators' => $indicators];
    }

    // ====================================================================
    // 1. 字符序列模式推理：分析字符序列的攻击意图（而非单字符统计）
    // ====================================================================
    private static function detectSequencePatterns(string $text, string $lower): array {
        $indicators = [];
        $score = 0;

        // SQL 注入闭合序列：')(' 或 '...)' 这类引号+括号闭合
        if (strpos($text, "')(") !== false
            || preg_match('#[\'"`]\s*\)\s*[\'"`]?#', $text)
            || preg_match('#\)\s*[\'"`]#', $text)) {
            $score += 22;
            $indicators[] = 'seq:sql_closure_paren_quote';
        }

        // HTML 标签闭合序列：</
        if (strpos($text, '</') !== false) {
            $score += 18;
            $indicators[] = 'seq:html_tag_close';
        }

        // 模板注入 / 变量插值序列：${
        if (strpos($text, '${') !== false) {
            $score += 20;
            $indicators[] = 'seq:template_interpolation';
        }

        // 编码逃逸序列：\x \u \X \U 后接十六进制
        if (preg_match('#\\\\[xuXU][0-9a-fA-F]#', $text)) {
            $score += 18;
            $indicators[] = 'seq:escape_encoding_chain';
        }

        // URL 编码序列：%XX
        $urlEncCount = preg_match_all('#%[0-9a-fA-F]{2}#', $text);
        if ($urlEncCount >= 1) {
            $score += $urlEncCount >= 3 ? 22 : 15;
            $indicators[] = 'seq:url_encoding:' . $urlEncCount;
        }

        // 语句分隔序列：;\n 或多个;
        if (preg_match('#;\s*[\r\n]#', $text) || substr_count($text, ';') >= 2) {
            $score += 16;
            $indicators[] = 'seq:statement_separator';
        }

        // 命令管道序列：| 后接字母（命令）
        if (preg_match('#\|\s*[a-zA-Z]#', $text)) {
            $score += 18;
            $indicators[] = 'seq:command_pipeline';
        }

        // 命令替换序列：反引号（成对更可疑）
        $btCount = substr_count($text, '`');
        if ($btCount >= 2 && $btCount % 2 === 0) {
            $score += 20;
            $indicators[] = 'seq:command_substitution';
        } elseif ($btCount >= 1) {
            $score += 12;
            $indicators[] = 'seq:backtick_present';
        }

        // HTML 注释注入序列：<!--
        if (strpos($text, '<!--') !== false) {
            $score += 18;
            $indicators[] = 'seq:html_comment_injection';
        }

        // SQL 注释注入序列：'-- 或 -- 或 # 注释
        if (preg_match('#[\'"`]\s*--#', $text)
            || preg_match('#--\s#', $text)
            || preg_match('~\s#\s~', $text)
            || preg_match('~#\s*$~', $text)) {
            $score += 20;
            $indicators[] = 'seq:sql_comment_injection';
        }

        // 零宽字符位置分析：出现在关键词中间 → 混淆意图
        $zwMidHit = self::detectZeroWidthInKeyword($text);
        if ($zwMidHit !== null) {
            $score += 22;
            $indicators[] = $zwMidHit;
        }

        // 路径穿越序列：../ 或 ..\
        if (strpos($text, '../') !== false || strpos($text, '..\\') !== false) {
            $score += 18;
            $indicators[] = 'seq:path_traversal';
        }

        // PHP 标签序列：<? 或 <?php / <% / <%= （代码注入意图）
        if (strpos($text, '<?') !== false || strpos($text, '<%') !== false) {
            $score += 20;
            $indicators[] = 'seq:server_code_tag';
        }

        return ['score' => min(65, $score), 'indicators' => $indicators];
    }

    /**
     * 零宽字符位置语义：判断零宽字符是否出现在敏感关键词中间（混淆意图）
     * 出现在关键词中间 → 混淆；出现在末尾 → 可能正常
     */
    private static function detectZeroWidthInKeyword(string $text): ?string {
        $zwChars = ["\u{200B}", "\u{200C}", "\u{200D}", "\u{FEFF}", "\u{2060}"];
        foreach ($zwChars as $zw) {
            $pos = strpos($text, $zw);
            while ($pos !== false) {
                // 取零宽字符前后各 8 字节作为上下文窗口
                $start = max(0, $pos - 8);
                $ctx = substr($text, $start, 16 + strlen($zw));
                $cleaned = str_replace($zw, '', $ctx);
                foreach (self::$zw_sensitive_keywords as $kw) {
                    if (stripos($cleaned, $kw) !== false) {
                        return 'seq:zero_width_in_keyword';
                    }
                }
                $pos = strpos($text, $zw, $pos + strlen($zw));
            }
        }
        return null;
    }

    // ====================================================================
    // 2. 字符分布异常检测：分布的"不自然性"、局部聚集、交替模式、字符集跳变
    // ====================================================================
    private static function detectDistributionAnomaly(string $text): array {
        $indicators = [];
        $score = 0;
        $len = strlen($text);
        if ($len < 8) {
            return ['score' => 0, 'indicators' => []];
        }

        // 2a. Zipf 定律偏离：自然文本字符频率应近似幂律分布；
        //     攻击载荷（编码串、长 payload）往往"扁平化"或"尖峰"
        $letterOnly = [];
        $lower = strtolower($text);
        for ($i = 0; $i < $len; $i++) {
            $o = ord($lower[$i]);
            if ($o >= 0x61 && $o <= 0x7A) { // a-z
                $letterOnly[$o] = ($letterOnly[$o] ?? 0) + 1;
            }
        }
        if (count($letterOnly) >= 8) {
            $freqVals = array_values($letterOnly);
            rsort($freqVals, SORT_NUMERIC);
            $total = array_sum($freqVals);
            if ($total > 0) {
                $top4Ratio = (array_sum(array_slice($freqVals, 0, 4))) / $total;
                // 自然英文 top4 (e,t,a,o) 约 0.36-0.40；偏离过远 → 异常
                if ($top4Ratio < 0.18 || $top4Ratio > 0.85) {
                    $score += 12;
                    $indicators[] = 'dist:zipf_deviation:' . round($top4Ratio, 2);
                }
            }
        }

        // 2b. 特殊字符局部聚集度：特殊字符集中在前 1/3 或紧密相邻 → 注入点定位
        $specialPositions = [];
        for ($i = 0; $i < $len; $i++) {
            if (isset(self::$danger_chars[$text[$i]])) {
                $specialPositions[] = $i;
            }
        }
        $spCount = count($specialPositions);
        if ($spCount >= 3) {
            $gaps = [];
            for ($i = 1; $i < $spCount; $i++) {
                $gaps[] = $specialPositions[$i] - $specialPositions[$i - 1];
            }
            sort($gaps);
            $medianGap = $gaps[(int) floor(count($gaps) / 2)] ?? 0;
            if ($medianGap <= 2) {
                $score += 14;
                $indicators[] = 'dist:local_clustering:' . $medianGap;
            }
            $firstThird = $len / 3;
            $inFirst = 0;
            foreach ($specialPositions as $p) {
                if ($p < $firstThird) $inFirst++;
            }
            if ($inFirst / $spCount > 0.7) {
                $score += 10;
                $indicators[] = 'dist:injection_point_front';
            }
        }

        // 2c. 字符交替模式：字母-符号-字母-符号 (例如 a'OR'1'='1)
        $altScore = self::detectAlternationPattern($text);
        if ($altScore > 0) {
            $score += $altScore;
            $indicators[] = 'dist:letter_symbol_alternation';
        }

        // 2d. 字符集跳变频率：在不同字符集间高频跳转 → 混淆
        $jumpScore = self::detectCharSetJumps($text);
        if ($jumpScore > 0) {
            $score += $jumpScore;
            $indicators[] = 'dist:charset_jumps_high';
        }

        return ['score' => min(20, $score), 'indicators' => $indicators];
    }

    /**
     * 检测字母-符号-字母交替模式（注入特征，如 a'OR'1'='1）
     */
    private static function detectAlternationPattern(string $text): int {
        $len = strlen($text);
        if ($len < 6) return 0;
        $transitions = 0;
        $prevClass = null;
        for ($i = 0; $i < $len; $i++) {
            $ch = $text[$i];
            $o = ord($ch);
            if (($o >= 0x41 && $o <= 0x5A) || ($o >= 0x61 && $o <= 0x7A) || $o >= 0x80) {
                $cls = 'A';
            } elseif ($o >= 0x30 && $o <= 0x39) {
                $cls = 'D';
            } elseif (isset(self::$danger_chars[$ch])) {
                $cls = 'S';
            } else {
                $cls = 'O';
            }
            if ($prevClass !== null && $cls !== $prevClass) {
                $transitions++;
            }
            $prevClass = $cls;
        }
        $density = $transitions / $len;
        if ($density > 0.5 && $len > 10) {
            return 15;
        } elseif ($density > 0.35) {
            return 10;
        }
        return 0;
    }

    /**
     * 检测字符集跳变频率（字母/数字/符号/控制之间高频跳转）
     */
    private static function detectCharSetJumps(string $text): int {
        $len = strlen($text);
        if ($len < 10) return 0;
        $jumps = 0;
        $prev = null;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($text[$i]);
            if (($o >= 0x41 && $o <= 0x5A) || ($o >= 0x61 && $o <= 0x7A)) {
                $cls = 'A';
            } elseif ($o >= 0x30 && $o <= 0x39) {
                $cls = 'D';
            } elseif ($o < 0x20 && $o !== 0x09 && $o !== 0x0A && $o !== 0x0D) {
                $cls = 'C';
            } else {
                $cls = 'S';
            }
            if ($prev !== null && $cls !== $prev) {
                $jumps++;
            }
            $prev = $cls;
        }
        $jumpRatio = $jumps / $len;
        return $jumpRatio > 0.45 ? 12 : 0;
    }

    // ====================================================================
    // 3. 字符级编码链检测：嵌套编码、混合编码、分片编码、Base64
    // ====================================================================
    private static function detectEncodingChain(string $text): array {
        $indicators = [];
        $score = 0;

        // 3a. 双重 URL 编码：%25 后接 XX（解码后为 %XX 再解码）
        $doubleUrl = preg_match_all('#%25[0-9a-fA-F]{2}#', $text);
        if ($doubleUrl >= 1) {
            $score += $doubleUrl >= 2 ? 28 : 22;
            $indicators[] = 'enc:double_url_encoding:' . $doubleUrl;
        }

        // 3b. HTML 十六进制实体序列（分片编码）：&#x6a;&#x61;
        $hexEntity = preg_match_all('~&#[xX][0-9a-fA-F]{2,4};~', $text);
        if ($hexEntity >= 2) {
            $score += $hexEntity >= 4 ? 28 : 22;
            $indicators[] = 'enc:html_hex_entity_seq:' . $hexEntity;
        } elseif ($hexEntity === 1) {
            $score += 12;
            $indicators[] = 'enc:html_hex_entity_single';
        }

        // 3c. HTML 十进制实体序列
        $decEntity = preg_match_all('~&#\d{2,4};~', $text);
        if ($decEntity >= 2) {
            $score += 20;
            $indicators[] = 'enc:html_dec_entity_seq:' . $decEntity;
        }

        // 3d. 混合编码：URL编码 + HTML实体 + 十六进制 等同时出现
        $mixScore = 0;
        if (preg_match('#%[0-9a-fA-F]{2}#', $text)) $mixScore++;
        if (preg_match('~&#[xX]?\w+;~', $text)) $mixScore++;
        if (preg_match('#\\\\x[0-9a-fA-F]{2}#', $text)) $mixScore++;
        if (preg_match('#0x[0-9a-fA-F]+#', $text)) $mixScore++;
        if (preg_match('#\\\\u[0-9a-fA-F]{4}#', $text)) $mixScore++;
        if ($mixScore >= 3) {
            $score += 30;
            $indicators[] = 'enc:mixed_encoding:' . $mixScore;
        } elseif ($mixScore === 2) {
            $score += 18;
            $indicators[] = 'enc:partial_mixed_encoding';
        }

        // 3e. Base64 特征：高密度 Base64 字符 + 长度 4 倍数 + 末尾 = 填充
        $b64Score = self::detectBase64Payload($text);
        if ($b64Score > 0) {
            $score += $b64Score;
            $indicators[] = 'enc:base64_signature';
        }

        // 3f. Unicode 转义序列：\uXXXX
        if (preg_match_all('#\\\\u[0-9a-fA-F]{4}#', $text)) {
            $score += 20;
            $indicators[] = 'enc:unicode_escape_seq';
        }

        // 3g. 八进制转义：\NNN
        if (preg_match_all('#\\\\[0-3][0-7]{2}#', $text)) {
            $score += 18;
            $indicators[] = 'enc:octal_escape_seq';
        }

        return ['score' => min(55, $score), 'indicators' => $indicators];
    }

    /**
     * Base64 载荷特征检测
     */
    private static function detectBase64Payload(string $text): int {
        $len = strlen($text);
        if ($len < 16) return 0;

        if (!preg_match('#[A-Za-z0-9+/]{16,}={0,2}#', $text, $m)) {
            return 0;
        }
        $candidate = $m[0];
        $cLen = strlen($candidate);

        // 严格 Base64：长度必须是 4 的倍数
        if ($cLen % 4 !== 0) {
            return 0;
        }

        // 字符多样性：Base64 应包含大小写字母+数字
        $hasUpper = preg_match('#[A-Z]#', $candidate);
        $hasLower = preg_match('#[a-z]#', $candidate);
        $hasDigit = preg_match('#[0-9]#', $candidate);
        $variety = ($hasUpper ? 1 : 0) + ($hasLower ? 1 : 0) + ($hasDigit ? 1 : 0);
        if ($variety < 2) return 0;

        $entropy = self::shannonEntropy($candidate);
        if ($entropy > 4.5 && $cLen >= 20) {
            return 25;
        } elseif ($entropy > 4.0) {
            return 18;
        }
        return 0;
    }

    // ====================================================================
    // 4. 字符上下文语义：字符在上下文中的角色（不是孤立看每个字符）
    // ====================================================================
    private static function detectContextSemantics(string $text, string $lower): array {
        $indicators = [];
        $score = 0;

        // 4a. 引号在 SQL 关键词附近 → SQL 注入上下文
        if (preg_match('#[\'"`]#', $text)) {
            foreach (self::$sql_keywords as $kw) {
                $quoted = preg_quote($kw, '#');
                if (preg_match('#[\'"`][^\'"`]{0,12}' . $quoted . '#', $lower)
                    || preg_match('#' . $quoted . '[^\'"`]{0,12}[\'"`]#', $lower)) {
                    $score += 20;
                    $indicators[] = 'ctx:quote_near_sql:' . $kw;
                    break;
                }
            }
        }

        // 4b. 尖括号在函数名附近 → XSS 上下文
        if (strpos($text, '<') !== false
            && preg_match('#<[a-zA-Z_][a-zA-Z0-9_]*\s*#', $text)
            && preg_match(self::FUNC_NAME_PATTERN, $text)) {
            $score += 18;
            $indicators[] = 'ctx:angle_bracket_near_func';
        }

        // 4c. 分号在文件路径附近 → 路径注入上下文
        if (strpos($text, ';') !== false) {
            if (preg_match('#[/\\\\][a-zA-Z0-9_\-.]+\s*;#', $text)
                || preg_match('#;\s*[/\\\\][a-zA-Z0-9_\-.]+#', $text)) {
                $score += 15;
                $indicators[] = 'ctx:semicolon_near_path';
            }
        }

        // 4d. 美元符号在花括号前 → 模板注入上下文
        if (strpos($text, '$') !== false && strpos($text, '{') !== false) {
            if (preg_match('#\$\{#', $text) || preg_match('#\$\w+\{#', $text)) {
                $score += 18;
                $indicators[] = 'ctx:dollar_before_brace';
            }
        }

        // 4e. 反斜杠在字母前 → 转义/编码上下文
        if (preg_match('#\\\\[a-zA-Z]#', $text)) {
            $score += 12;
            $indicators[] = 'ctx:backslash_before_alpha';
        }

        // 4f. 引号+等号+引号 链 → 注入赋值链
        if (preg_match('#[\'"`]\s*=\s*[\'"`]#', $text) || substr_count($text, '=') >= 3) {
            $score += 12;
            $indicators[] = 'ctx:equality_chain';
        }

        // 4g. on* 事件处理器属性 → XSS 上下文
        if (preg_match('#\bon[a-z]+\s*=#i', $text)) {
            $score += 18;
            $indicators[] = 'ctx:event_handler_attr';
        }

        // 4h. 危险伪协议 → XSS / SSRF 上下文
        // javascript:/vbscript:/expect: 后跟任意非空白字符即可；
        // data:/file:/php: 需紧跟字母数字或斜杠，避免误伤 "data: field" 这类正常文本
        if (preg_match('#\b(javascript|vbscript|expect)\s*:\s*\S#i', $text)
            || preg_match('#\b(data|file|php)\s*:[/\\\\a-zA-Z0-9]#i', $text)) {
            $score += 18;
            $indicators[] = 'ctx:dangerous_protocol';
        }

        // 4i. 引号+OR/AND 关键词（SQL 布尔注入）
        if (preg_match('#[\'"`]\s*(or|and)\s+[\'"`]?#i', $text)) {
            $score += 16;
            $indicators[] = 'ctx:quote_logic_injection';
        }

        return ['score' => min(45, $score), 'indicators' => $indicators];
    }

    // ====================================================================
    // 5. 基础辅助能力（保留原有能力，降为辅助指标）
    // ====================================================================
    private static function detectBaseFeatures(string $text, int $len): array {
        $indicators = [];
        $score = 0;

        // 5a. 特殊字符密度（辅助）
        $specialCount = 0;
        foreach (self::$danger_chars as $ch => $w) {
            $specialCount += substr_count($text, $ch);
        }
        $specialRatio = $len > 0 ? $specialCount / $len : 0;
        if ($specialRatio > 0.30) {
            $score += 8;
            $indicators[] = 'base:special_char_density:' . round($specialRatio, 2);
        } elseif ($specialRatio > 0.15) {
            $score += 4;
        }

        // 5b. 不可打印字符 / NUL 字节
        $nonPrintable = 0;
        $nulCount = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($text[$i]);
            if ($o === 0) {
                $nulCount++;
                $nonPrintable++;
                continue;
            }
            if (($o < 0x20 && $o !== 0x09 && $o !== 0x0A && $o !== 0x0D) || $o === 0x7F) {
                $nonPrintable++;
            }
        }
        if ($nulCount > 0) {
            $score += min(12, $nulCount * 6);
            $indicators[] = 'base:null_byte:' . $nulCount;
        }
        if ($nonPrintable > 0 && $nulCount === 0) {
            $npRatio = $nonPrintable / $len;
            if ($npRatio > 0.10) {
                $score += 6;
                $indicators[] = 'base:non_printable_high:' . round($npRatio, 3);
            }
        }

        // 5c. 零宽字符（位置分析已在序列检测中处理，这里仅基础命中）
        $invisibleHits = [];
        foreach (self::$invisible_chars as $seq => $name) {
            $c = substr_count($text, $seq);
            if ($c > 0) {
                $invisibleHits[$name] = $c;
            }
        }
        if (!empty($invisibleHits)) {
            $total = array_sum($invisibleHits);
            $score += min(8, $total * 3);
            $indicators[] = 'base:invisible_chars:' . json_encode($invisibleHits, JSON_UNESCAPED_UNICODE);
        }

        // 5d. 同形字 / 混用字符集
        $scriptsFound = [];
        $codePoints = self::utf8CodePoints($text);
        foreach ($codePoints as $cp) {
            foreach (self::$script_ranges as $name => $range) {
                if ($cp >= $range[0] && $cp <= $range[1]) {
                    $scriptsFound[$name] = ($scriptsFound[$name] ?? 0) + 1;
                    break;
                }
            }
        }
        $suspiciousMix = 0;
        if (isset($scriptsFound['latin'])) {
            foreach (['cyrillic', 'greek'] as $s) {
                if (!empty($scriptsFound[$s])) {
                    $suspiciousMix += $scriptsFound[$s];
                }
            }
        }
        if ($suspiciousMix > 0) {
            $score += min(10, $suspiciousMix * 3);
            $indicators[] = 'base:homoglyph_mix:' . json_encode($scriptsFound, JSON_UNESCAPED_UNICODE);
        }

        // 5e. Shannon 熵（辅助）
        $entropy = self::shannonEntropy($text);
        if ($entropy > 4.5 && $len > 20) {
            $score += 6;
            $indicators[] = 'base:high_entropy:' . round($entropy, 2);
        }

        return ['score' => min(20, $score), 'indicators' => $indicators];
    }

    /**
     * 计算 Shannon 熵（按字节）
     */
    private static function shannonEntropy(string $text): float {
        $len = strlen($text);
        if ($len === 0) {
            return 0.0;
        }
        $freq = count_chars($text, 1);
        $entropy = 0.0;
        foreach ($freq as $cnt) {
            $p = $cnt / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    /**
     * 将 UTF-8 文本解码为码点数组（手动解码，保证兼容性且为 O(n)）
     * @return int[]
     */
    private static function utf8CodePoints(string $text): array {
        $codePoints = [];
        $bytes = unpack('C*', $text);
        if (!$bytes) {
            return $codePoints;
        }
        $n = count($bytes);
        for ($i = 1; $i <= $n; $i++) {
            $b = $bytes[$i];
            if ($b < 0x80) {
                $codePoints[] = $b;
            } elseif (($b & 0xE0) === 0xC0) {
                $cp = ($b & 0x1F) << 6;
                if (isset($bytes[$i + 1])) {
                    $cp |= ($bytes[$i + 1] & 0x3F);
                }
                $codePoints[] = $cp;
                $i += 1;
            } elseif (($b & 0xF0) === 0xE0) {
                $cp = ($b & 0x0F) << 12;
                if (isset($bytes[$i + 1])) {
                    $cp |= ($bytes[$i + 1] & 0x3F) << 6;
                }
                if (isset($bytes[$i + 2])) {
                    $cp |= ($bytes[$i + 2] & 0x3F);
                }
                $codePoints[] = $cp;
                $i += 2;
            } elseif (($b & 0xF8) === 0xF0) {
                $cp = ($b & 0x07) << 18;
                if (isset($bytes[$i + 1])) {
                    $cp |= ($bytes[$i + 1] & 0x3F) << 12;
                }
                if (isset($bytes[$i + 2])) {
                    $cp |= ($bytes[$i + 2] & 0x3F) << 6;
                }
                if (isset($bytes[$i + 3])) {
                    $cp |= ($bytes[$i + 3] & 0x3F);
                }
                $codePoints[] = $cp;
                $i += 3;
            }
            // 非法字节直接跳过
        }
        return $codePoints;
    }
}
