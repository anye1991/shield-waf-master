<?php
/**
 * 对抗样本防御引擎（L10 - 深度重写版）
 *
 * 从"混淆关键词匹配"升级为"混淆还原 + 对抗样本检测"。
 * 核心能力：
 *   A. recursiveDecode       —— 多层编码递归还原（URL/HTML/Base64/Hex/Octal，最大深度 5）
 *   B. detectObfuscation      —— 混淆模式识别（注释分隔/大小写混合/CHAR()/字符串拼接/空白替换）
 *   C. detectAdversarialPayload —— 对抗样本检测（同形字/零宽字符/WAF 绕过 payload 结构）
 *   D. analyzeEncodingChain   —— 编码链分析（不自然编码组合/深度异常/混合编码）
 *   E. comparePrePostDecode   —— 还原前后对比（原文本看似无害但还原后含攻击 payload）
 *   F. scoreObfuscationComplexity —— 混淆复杂度评分（0-100）
 *
 * 关键突破：recursiveDecode() 真正递归还原多层嵌套编码，而非单次 urldecode。
 * 公共 API 保持不变：analyze() 返回 ['score' => 0-100, ...]
 */
defined('ABSPATH') || exit;

class AdversarialDefense {
    /** 递归解码最大深度 */
    private const MAX_DECODE_DEPTH = 5;

    /** 已知攻击 payload 结构特征（结构化模式，非单个关键词） */
    private static $attack_payload_patterns = [
        'sql_tautology_num' => '/\b(?:or|and)\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i',
        'sql_tautology_str' => '/\b(?:or|and)\b\s+[\'"][^\'"]{1,20}[\'"]\s*=\s*[\'"][^\'"]{1,20}[\'"]/i',
        'sql_union_select'  => '/\bunion\b[\s\S]{0,40}\bselect\b/i',
        'sql_comment_trail' => '/[\'"`]\s*(?:--|#)\s/',
        'sql_stacked_query' => '/;\s*(?:drop|insert|update|delete|select|exec|alter|create)\b/i',
        'sql_meta_probe'    => '/\binformation_schema\b|\bsysobjects\b|\bmysql\.\w+/i',
        'sql_time_blind'    => '/\b(?:sleep|benchmark|waitfor\s+delay)\s*\(/i',
        'sql_danger_func'   => '/\b(?:load_file|outfile|dumpfile|xp_cmdshell|extractvalue|updatexml)\s*\(/i',
        'xss_script_tag'    => '/<\s*script\b/i',
        'xss_event_handler' => '/\bon[a-z]+\s*=\s*[\'"]?[^\'">\s]+/i',
        'xss_js_protocol'   => '/\bjavascript:\s*\S/i',
        'xss_svg_payload'   => '/<\s*svg\b[\s\S]{0,80}?\bon[a-z]+\s*=/i',
        'cmd_pipe'          => '/\|\s*(?:sh|bash|cat|ls|id|whoami|nc|wget|curl)\b/i',
        'cmd_backtick'      => '/`[^`]{1,100}`/',
        'cmd_dollar_paren'  => '/\$\([^)]{1,100}\)/',
        'php_eval_chain'    => '/\b(?:eval|assert|system|exec|shell_exec|passthru)\s*\(/i',
        'php_code_tag'      => '/<\?(?:php)?|<%/',
    ];

    /** WAF 绕过专用 payload 结构（高级对抗样本特征） */
    private static $waf_bypass_patterns = [
        'comment_split_keyword' => '/[a-zA-Z]+\s*\/\*!?\d*\s*[\s\S]{0,40}?\*\/\s*[a-zA-Z]+/i',
        'string_concat_chain'   => '/[\'"][a-zA-Z0-9_]{1,8}[\'"]\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"](?:\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"])+/',
        'char_function'         => '/\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}\s*\)/i',
        'whitespace_subst'      => '/[\x0b\x0c]\s*(?:union|select|from|where|or|and)\b/i',
        'versioned_comment'     => '/\/\*!\d{4,}\s*[\s\S]*?\*\//i',
    ];

    /** 零宽字符与不可见 Unicode 字符（UTF-8 字节序列） */
    private static $zero_width_chars = [
        "\u{200B}" => 'ZWSP', "\u{200C}" => 'ZWNJ', "\u{200D}" => 'ZWJ',
        "\u{FEFF}" => 'BOM',  "\u{2060}" => 'WJ',
    ];

    /** 同形字映射：西里尔/希腊字母 → 拉丁字母 */
    private static $homoglyph_map = [
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c',
        'у' => 'y', 'х' => 'x', 'А' => 'A', 'В' => 'B', 'Е' => 'E',
        'К' => 'K', 'М' => 'M', 'Н' => 'H', 'О' => 'O', 'Р' => 'P',
        'С' => 'C', 'Т' => 'T', 'Х' => 'X', 'і' => 'i', 'І' => 'I',
        'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H',
        'Ι' => 'I', 'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O',
        'Ρ' => 'P', 'Τ' => 'T', 'Υ' => 'Y', 'Χ' => 'X',
    ];

    /**
     * 对抗样本检测分析入口。
     *
     * @param string $text              归一化后的文本
     * @param string $rawText           原始未归一化文本
     * @param array  $normalizerContext 归一化引擎上下文
     * @param array  $multiVectorResult 多向量融合结果
     * @return array{score:int, threats:array, threat_names:array, patterns:array, decoded:string, decode_depth:int, decode_path:array, is_adversarial:bool, risk_level:string, recommendation:string}
     */
    public static function analyze(
        string $text,
        string $rawText = '',
        array $normalizerContext = [],
        array $multiVectorResult = []
    ): array {
        $inputForDecode = $rawText !== '' ? $rawText : $text;

        // A. 多层编码递归还原
        $decodeResult = self::recursiveDecode($inputForDecode, 0);
        // B. 混淆模式识别
        $obfResult = self::detectObfuscation($inputForDecode);
        // C. 对抗样本检测
        $advResult = self::detectAdversarialPayload($inputForDecode);
        // D. 编码链分析
        $chainResult = self::analyzeEncodingChain($inputForDecode, $decodeResult);
        // E. 还原前后对比
        $compareBefore = $text !== '' ? $text : $inputForDecode;
        $compareResult = self::comparePrePostDecode($compareBefore, $decodeResult['decoded']);

        $features = [
            'decode_depth'        => $decodeResult['depth'],
            'decode_path'         => $decodeResult['path'],
            'obfuscation_count'   => count($obfResult['techniques']),
            'adversarial_count'   => count($advResult['features']),
            'chain_anomaly'       => $chainResult['anomaly'],
            'decoded_has_payload' => $compareResult['has_payload'],
        ];

        // F. 混淆复杂度评分
        $score = self::scoreObfuscationComplexity($features);

        // 组装 threats
        $threats = [];
        if ($decodeResult['depth'] >= 2) {
            $threats[] = ['type' => 'recursive_encoding', 'name' => '多层嵌套编码还原',
                'score' => $decodeResult['depth'] * 10,
                'matched' => ['depth:' . $decodeResult['depth'], 'path:' . implode('->', $decodeResult['path'])]];
        }
        foreach ($obfResult['techniques'] as $tech) {
            $threats[] = ['type' => 'obfuscation', 'name' => '混淆模式: ' . $tech, 'score' => 8, 'matched' => [$tech]];
        }
        foreach ($advResult['features'] as $feat) {
            $threats[] = ['type' => 'adversarial', 'name' => '对抗样本特征: ' . $feat, 'score' => 15, 'matched' => [$feat]];
        }
        if (!empty($chainResult['anomaly'])) {
            $threats[] = ['type' => 'encoding_chain', 'name' => '编码链异常: ' . implode(',', $chainResult['types']),
                'score' => $chainResult['score'], 'matched' => $chainResult['types']];
        }
        if ($compareResult['has_payload']) {
            $threats[] = ['type' => 'decoded_payload', 'name' => '还原后检出攻击 payload',
                'score' => 30, 'matched' => $compareResult['payload_types']];
        }

        $patterns = array_merge($obfResult['techniques'], $advResult['features'], $chainResult['types'], $compareResult['payload_types']);

        return [
            'score'          => $score,
            'threats'        => $threats,
            'threat_names'   => array_column($threats, 'name'),
            'patterns'       => array_values(array_unique($patterns)),
            'decoded'        => $decodeResult['decoded'],
            'decode_depth'   => $decodeResult['depth'],
            'decode_path'    => $decodeResult['path'],
            'is_adversarial' => $score >= 30,
            'risk_level'     => $score >= 60 ? 'high' : ($score >= 30 ? 'medium' : 'low'),
            'recommendation' => self::generateRecommendation($threats, $score),
        ];
    }

    // === A. 多层编码递归还原 ===

    /**
     * 逐层尝试 URL / HTML / Base64 / Hex escape / Octal escape / 0x hex literal
     * 解码，直至稳定或达到最大深度（5）。返回还原后文本 + 还原路径 + 编码层数。
     */
    private static function recursiveDecode(string $text, int $depth = 0): array {
        $path = [];
        $current = $text;
        $totalDepth = 0;
        while ($totalDepth < self::MAX_DECODE_DEPTH) {
            $step = self::applyDecodeLayer($current);
            if (!$step['changed']) break;
            $current = $step['text'];
            $path = array_merge($path, $step['applied']);
            $totalDepth++;
        }
        return ['decoded' => $current, 'depth' => $totalDepth, 'path' => $path];
    }

    /**
     * 单层解码尝试：依次应用 URL / HTML / Base64 / \xHH / \NNN / 0xNN 解码。
     * 同一层可应用多种解码，统一记录到 applied。
     */
    private static function applyDecodeLayer(string $text): array {
        $applied = [];
        $changed = false;

        // 1. URL 编码：rawurldecode 还原 %XX
        if (preg_match('#%[0-9a-fA-F]{2}#', $text)) {
            $decoded = rawurldecode($text);
            if ($decoded !== $text && $decoded !== '' && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'urldecode'; $changed = true;
            }
        }
        // 2. HTML 实体解码（含 &amp;#x27; 双重编码场景：&amp; 先解再解 &#x27;）
        if (preg_match('/&#|&[a-zA-Z]+;|&amp;/', $text)) {
            $before = $text;
            $text = self::decodeHtmlEntities($text);
            if ($text !== $before) { $applied[] = 'html_entity'; $changed = true; }
        }
        // 3. Base64：仅当文本整体是合法 Base64 时尝试
        $b64 = self::tryBase64Decode($text);
        if ($b64 !== null) { $text = $b64; $applied[] = 'base64'; $changed = true; }
        // 4. \xHH 十六进制转义
        if (preg_match('/\\\\x[0-9a-fA-F]{2}/', $text)) {
            $decoded = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', function ($m) {
                return chr(hexdec($m[1]));
            }, $text);
            if ($decoded !== null && $decoded !== $text) { $text = $decoded; $applied[] = 'hex_escape'; $changed = true; }
        }
        // 5. \NNN 八进制转义（仅 0-3 起始，避免误伤普通文本）
        if (preg_match('/\\\\[0-3][0-7]{2}/', $text)) {
            $decoded = preg_replace_callback('/\\\\([0-3][0-7]{2})/', function ($m) {
                return chr(octdec($m[1]));
            }, $text);
            if ($decoded !== null && $decoded !== $text) { $text = $decoded; $applied[] = 'octal_escape'; $changed = true; }
        }
        // 6. 0xNN 十六进制字面量（SQL/代码上下文，要求至少 4 位以减少误判）
        if (preg_match('/\b0x[0-9a-fA-F]{4,}\b/', $text)) {
            $decoded = preg_replace_callback('/\b0x([0-9a-fA-F]{4,})\b/', function ($m) {
                $hex = $m[1];
                if (strlen($hex) % 2 !== 0) return $m[0];
                $str = '';
                for ($i = 0; $i < strlen($hex); $i += 2) {
                    $str .= chr(hexdec(substr($hex, $i, 2)));
                }
                return $str;
            }, $text);
            if ($decoded !== null && $decoded !== $text) { $text = $decoded; $applied[] = 'hex_literal'; $changed = true; }
        }
        // 7. Unicode %uXXXX 编码（IIS经典）
        if (preg_match('/%u[0-9a-fA-F]{4}/', $text)) {
            $decoded = preg_replace_callback('/%u([0-9a-fA-F]{4})/', function ($m) {
                $cp = hexdec($m[1]);
                if ($cp < 0x80) return chr($cp);
                if ($cp < 0x800) return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
                return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
            }, $text);
            if ($decoded !== null && $decoded !== $text && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'unicode_percent_u'; $changed = true;
            }
        }
        // 8. UTF-8超集编码（2字节表示ASCII字符，路径遍历常用绕过）
        //    注意：检查已经URL解码后的二进制字节（[\xC0-\xE0][\x80-\xBF]模式）
        if (preg_match('/[\xC0-\xE0][\x80-\xBF]/', $text)) {
            $before = $text;
            $decoded = self::decodeOverlongUtf8($text);
            if ($decoded !== $before && $decoded !== '' && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'utf8_overlong'; $changed = true;
            }
        }
        return ['text' => $text, 'applied' => $applied, 'changed' => $changed];
    }

    /**
     * 自定义 HTML 实体解码：处理 &#xNN; &#NN; 命名实体（含 &amp; 双重编码场景）。
     * 注：&amp; 必须最先解，以便 &amp;#x27; 在 strtr 后变成 &#x27; 再被 hex 解码。
     */
    private static function decodeHtmlEntities(string $text): string {
        $named = ['&amp;' => '&', '&apos;' => "'", '&quot;' => '"', '&lt;' => '<', '&gt;' => '>'];
        $text = strtr($text, $named);
        $text = preg_replace_callback('/&#[xX]([0-9a-fA-F]+);/', function ($m) {
            return self::cpToUtf8(hexdec($m[1]));
        }, $text);
        $text = preg_replace_callback('/&#(\d+);/', function ($m) {
            return self::cpToUtf8((int)$m[1]);
        }, $text);
        return $text;
    }

    /** 码点转 UTF-8（PHP 7.0 兼容，不依赖 mbstring） */
    private static function cpToUtf8(int $cp): string {
        if ($cp < 0x80) return chr($cp);
        if ($cp < 0x800) return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x110000) {
            return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F))
                . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return '';
    }

    /** 解码UTF-8超集编码（2字节序列表示的ASCII字符，路径遍历常用绕过） */
    private static function decodeOverlongUtf8(string $text): string {
        $result = '';
        $len = strlen($text);
        $i = 0;
        while ($i < $len) {
            $byte = ord($text[$i]);
            if ($byte < 0x80) {
                $result .= chr($byte);
                $i++;
            } elseif (($byte & 0xE0) === 0xC0 && $i + 1 < $len) {
                $byte2 = ord($text[$i + 1]);
                if (($byte2 & 0xC0) === 0x80) {
                    $cp = (($byte & 0x1F) << 6) | ($byte2 & 0x3F);
                    if ($cp < 0x80) {
                        $result .= chr($cp);
                    } else {
                        $result .= chr($byte) . chr($byte2);
                    }
                    $i += 2;
                } else {
                    $result .= chr($byte);
                    $i++;
                }
            } elseif (($byte & 0xF0) === 0xE0 && $i + 2 < $len) {
                $byte2 = ord($text[$i + 1]);
                $byte3 = ord($text[$i + 2]);
                if (($byte2 & 0xC0) === 0x80 && ($byte3 & 0xC0) === 0x80) {
                    $cp = (($byte & 0x0F) << 12) | (($byte2 & 0x3F) << 6) | ($byte3 & 0x3F);
                    if ($cp < 0x800) {
                        if ($cp < 0x80) {
                            $result .= chr($cp);
                        } else {
                            $result .= chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
                        }
                    } else {
                        $result .= chr($byte) . chr($byte2) . chr($byte3);
                    }
                    $i += 3;
                } else {
                    $result .= chr($byte);
                    $i++;
                }
            } else {
                $result .= chr($byte);
                $i++;
            }
        }
        return $result;
    }

    /** 尝试 Base64 解码：仅当整体文本是合法 Base64 且解码后可读 */
    private static function tryBase64Decode(string $text): ?string {
        $trimmed = trim($text);
        $len = strlen($trimmed);
        if ($len < 8 || $len % 4 !== 0) return null;
        if (!preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $trimmed)) return null;
        $decoded = base64_decode($trimmed, true);
        if ($decoded === false || $decoded === '' || strlen($decoded) < 3) return null;
        if (!self::isPrintableEnough($decoded)) return null;
        return $decoded;
    }

    /** 判断文本是否"足够可打印"——避免对乱码循环解码 */
    private static function isPrintableEnough(string $text): bool {
        $len = strlen($text);
        if ($len === 0) return false;
        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($text[$i]);
            if ($o === 9 || $o === 10 || $o === 13 || ($o >= 32 && $o <= 126) || $o >= 0x80) $printable++;
        }
        return ($printable / $len) >= 0.6;
    }

    // === B. 混淆模式识别（结构模式，非关键词匹配） ===

    private static function detectObfuscation(string $text): array {
        $techniques = [];
        // 1. 注释分隔：UNION/**/SELECT
        if (preg_match('/[a-zA-Z]+\s*\/\*[\s\S]{0,40}?\*\/\s*[a-zA-Z]+/', $text)) $techniques[] = 'comment_separator';
        // 2. 关键词拆分：UN/**/ION
        if (preg_match('/\bUN\s*\/\*[\s\S]{0,20}?\*\/\s*ION\b/i', $text)
            || preg_match('/\bSEL\s*\/\*[\s\S]{0,20}?\*\/\s*ECT\b/i', $text)
            || preg_match('/\bINS\s*\/\*[\s\S]{0,20}?\*\/\s*ERT\b/i', $text)
            || preg_match('/\bUPD\s*\/\*[\s\S]{0,20}?\*\/\s*ATE\b/i', $text)) {
            $techniques[] = 'keyword_split';
        }
        // 3. MySQL 版本注释：/*!50000UNION*/
        if (preg_match('/\/\*!\d{4,}\s*[\s\S]*?\*\//i', $text)) $techniques[] = 'versioned_comment';
        // 4. 大小写混合：UnIoN sElEcT
        if (self::hasMixedCaseKeyword($text)) $techniques[] = 'case_mixing';
        // 5. 字符串拼接：'a'+'d'+'m'+'i'+'n'
        if (preg_match('/[\'"][a-zA-Z0-9_]{1,8}[\'"]\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"]\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"]/', $text)) {
            $techniques[] = 'string_concat';
        }
        // 6. CHAR() 函数构造字符串
        if (preg_match('/\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}\s*\)/i', $text)) $techniques[] = 'char_function';
        // 7. 空白字符替换：垂直制表符/换页符代替空格出现在关键词周围
        if (preg_match('/[\x0b\x0c][\s\S]{0,5}?(?:union|select|from|where|or|and|insert|update|delete|drop)\b/i', $text)
            || preg_match('/\b(?:union|select|from|where|or|and|insert|update|delete|drop)[\x0b\x0c]/i', $text)) {
            $techniques[] = 'whitespace_substitution';
        }
        // 8. SQL 注释截断：'-- 或 '#
        if (preg_match('/[\'"`]\s*--\s/', $text) || preg_match('/[\'"`]\s*#/', $text)) $techniques[] = 'comment_truncate';
        // 9. URL 双重编码
        if (preg_match('#%25[0-9a-fA-F]{2}#', $text)) $techniques[] = 'double_url_encoding';
        // 10. HTML 实体编码序列
        if (preg_match_all('/&#[xX][0-9a-fA-F]{2,4};/', $text) >= 2) $techniques[] = 'html_entity_encoding';
        return ['techniques' => array_values(array_unique($techniques))];
    }

    /** 检测攻击关键词内部是否混用大小写（如 UnIoN, sElEcT） */
    private static function hasMixedCaseKeyword(string $text): bool {
        $keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'from', 'where'];
        foreach ($keywords as $kw) {
            if (preg_match_all('/' . $kw . '/i', $text, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $hit) {
                    if (self::hasInternalMixedCase($hit[0])) return true;
                }
            }
        }
        return false;
    }

    /** 判断单词内部是否有大小写交替（排除 UNION / union 这种纯大小写） */
    private static function hasInternalMixedCase(string $word): bool {
        if (!preg_match('/[a-z]/', $word) || !preg_match('/[A-Z]/', $word)) return false;
        $inner = substr($word, 1);
        if (!preg_match('/[A-Z]/', $inner) || !preg_match('/[a-z]/', $inner)) return false;
        $transitions = 0;
        $prevUpper = null;
        $len = strlen($word);
        for ($i = 0; $i < $len; $i++) {
            $o = ord($word[$i]);
            $isUpper = ($o >= 0x41 && $o <= 0x5A);
            if ($prevUpper !== null && $isUpper !== $prevUpper) $transitions++;
            $prevUpper = $isUpper;
        }
        return $transitions >= 2;
    }

    // === C. 对抗样本检测（专门针对 WAF 绕过设计的 payload） ===

    private static function detectAdversarialPayload(string $text): array {
        $features = [];
        // 1. 已知 WAF 绕过 payload 结构
        foreach (self::$waf_bypass_patterns as $name => $pattern) {
            if (@preg_match($pattern, $text)) $features[] = 'waf_bypass:' . $name;
        }
        // 2. 零宽字符插入
        $zwHits = [];
        foreach (self::$zero_width_chars as $seq => $name) {
            $c = substr_count($text, $seq);
            if ($c > 0) $zwHits[$name] = $c;
        }
        if (!empty($zwHits)) $features[] = 'zero_width:' . implode(',', array_keys($zwHits));
        // 3. 同形字攻击
        $homoglyphHits = self::detectHomoglyphs($text);
        if (!empty($homoglyphHits)) $features[] = 'homoglyph:' . count($homoglyphHits);
        // 4. 字符集异常
        $anomalyCount = self::detectCharsetAnomaly($text);
        if ($anomalyCount > 0) $features[] = 'charset_anomaly:' . $anomalyCount;
        // 5. 多变体检测（自动化绕过工具特征）
        $variantCount = self::countPayloadVariants($text);
        if ($variantCount >= 2) $features[] = 'multi_variant:' . $variantCount;
        // 6. 极端编码深度（3+ 层 URL 编码）
        $encDepth = self::countUrlEncodingDepth($text);
        if ($encDepth >= 3) $features[] = 'deep_encoding:' . $encDepth;
        return ['features' => $features];
    }

    /** 同形字检测：在拉丁文本中发现西里尔/希腊字母 */
    private static function detectHomoglyphs(string $text): array {
        if (!preg_match('/[a-zA-Z]/', $text)) return []; // 避免误判纯西里尔文本
        $hits = [];
        foreach (self::$homoglyph_map as $cyr => $lat) {
            if (strpos($text, $cyr) !== false) $hits[] = $cyr . '->' . $lat;
        }
        return $hits;
    }

    /** 字符集异常检测：非常规 Unicode 字符（私用区/数学符号/全角等）出现频度 */
    private static function detectCharsetAnomaly(string $text): int {
        $len = strlen($text);
        if ($len < 4) return 0;
        $bytes = unpack('C*', $text);
        if (!$bytes) return 0;
        $anomaly = 0;
        $i = 1;
        $n = count($bytes);
        while ($i <= $n) {
            $b = $bytes[$i];
            if ($b < 0x80) { $i++; continue; }
            $cp = 0;
            if (($b & 0xE0) === 0xC0) {
                $cp = ($b & 0x1F) << 6;
                if (isset($bytes[$i + 1])) $cp |= ($bytes[$i + 1] & 0x3F);
                $i += 2;
            } elseif (($b & 0xF0) === 0xE0) {
                $cp = ($b & 0x0F) << 12;
                if (isset($bytes[$i + 1])) $cp |= ($bytes[$i + 1] & 0x3F) << 6;
                if (isset($bytes[$i + 2])) $cp |= ($bytes[$i + 2] & 0x3F);
                $i += 3;
            } elseif (($b & 0xF8) === 0xF0) {
                $i += 4; continue;
            } else {
                $i++; continue;
            }
            // 异常区域：通用标点 / 字母式符号 / 数学运算符 / 制表符几何形状 / 全角半角 / 私用区
            if (($cp >= 0x2000 && $cp <= 0x206F) || ($cp >= 0x2100 && $cp <= 0x214F)
                || ($cp >= 0x2200 && $cp <= 0x22FF) || ($cp >= 0x2500 && $cp <= 0x27BF)
                || ($cp >= 0xFF00 && $cp <= 0xFFEF) || ($cp >= 0xE000 && $cp <= 0xF8FF)) {
                $anomaly++;
            }
        }
        return $anomaly;
    }

    /** 多变体计数：检测同一攻击关键词的多种大小写形态 */
    private static function countPayloadVariants(string $text): int {
        $variants = 0;
        foreach (['union', 'select', 'or', 'and', 'script'] as $kw) {
            $forms = [];
            if (preg_match_all('/' . $kw . '/i', $text, $m)) {
                foreach ($m[0] as $w) $forms[$w] = true;
                if (count($forms) >= 2) $variants++;
            }
        }
        return $variants;
    }

    /** 独立计算 URL 编码深度（用于检测 3+ 层 URL 编码） */
    private static function countUrlEncodingDepth(string $text): int {
        $depth = 0;
        $t = $text;
        while ($depth < 6 && preg_match('#%[0-9a-fA-F]{2}#', $t)) {
            $decoded = rawurldecode($t);
            if ($decoded === $t || $decoded === '' || !self::isPrintableEnough($decoded)) break;
            $t = $decoded;
            $depth++;
        }
        return $depth;
    }

    // === D. 编码链分析（检测不自然的编码组合） ===

    private static function analyzeEncodingChain(string $text, array $decodeResult): array {
        $types = [];
        $anomaly = false;
        $score = 0;
        // 检测出现的编码类型
        if (preg_match('#%[0-9a-fA-F]{2}#', $text))       $types[] = 'url';
        if (preg_match('/&#|&[a-zA-Z]+;/', $text))          $types[] = 'html_entity';
        if (preg_match('/\\\\x[0-9a-fA-F]{2}/', $text))     $types[] = 'hex_escape';
        if (preg_match('/\b0x[0-9a-fA-F]{4,}\b/', $text))   $types[] = 'hex_literal';
        if (preg_match('/\\\\[0-3][0-7]{2}/', $text))       $types[] = 'octal_escape';
        if (preg_match('/\\\\u[0-9a-fA-F]{4}/', $text))     $types[] = 'unicode_escape';
        if (self::tryBase64Decode($text) !== null)          $types[] = 'base64';
        // URL 多重编码（2 层以上即异常）
        $urlDepth = self::countUrlEncodingDepth($text);
        if ($urlDepth >= 2) {
            $types[] = 'url_multi:' . $urlDepth;
            $anomaly = true; $score += 15;
        }
        // 混合编码：3 种以上不同编码同时出现
        $uniqueCount = count(array_unique($types));
        if ($uniqueCount >= 3) { $anomaly = true; $score += 20; }
        elseif ($uniqueCount === 2) { $score += 8; }
        // 递归还原深度异常（≥3 层）
        if ($decodeResult['depth'] >= 3) { $anomaly = true; $score += 15; }
        // 编码后内容包含攻击结构（高度可疑）
        $decoded = $decodeResult['decoded'];
        if ($decoded !== $text) {
            foreach (self::$attack_payload_patterns as $name => $pattern) {
                if (@preg_match($pattern, $decoded)) {
                    $types[] = 'decoded_contains:' . $name;
                    $anomaly = true; $score += 10;
                    break;
                }
            }
        }
        return ['types' => array_values(array_unique($types)), 'anomaly' => $anomaly, 'score' => min(40, $score)];
    }

    // === E. 还原前后对比分析 ===

    /**
     * 还原前：text（可能已部分解码）；还原后：rawText 的递归还原结果。
     * 若还原后内容包含攻击 payload 而原文本看似无害 → 强证据。
     */
    private static function comparePrePostDecode(string $before, string $after): array {
        $payloadTypes = [];
        $changed = ($before !== $after);
        if (!$changed) {
            // 未变化：直接检查原文本是否含 payload
            foreach (self::$attack_payload_patterns as $name => $pattern) {
                if (@preg_match($pattern, $before)) $payloadTypes[] = $name;
            }
            return ['has_payload' => !empty($payloadTypes), 'payload_types' => $payloadTypes, 'changed' => false];
        }
        // 还原后文本中检测攻击 payload
        foreach (self::$attack_payload_patterns as $name => $pattern) {
            if (@preg_match($pattern, $after)) $payloadTypes[] = $name;
        }
        // 强证据：原文本看似无害但还原后含攻击 payload
        if (!empty($payloadTypes) && !self::looksLikeAttack($before)) {
            $payloadTypes[] = 'hidden_payload_strong';
        }
        return ['has_payload' => !empty($payloadTypes), 'payload_types' => $payloadTypes, 'changed' => true];
    }

    /** 粗判文本是否看起来像攻击（用于"原文本看似无害"的对比） */
    private static function looksLikeAttack(string $text): bool {
        foreach (self::$attack_payload_patterns as $pattern) {
            if (@preg_match($pattern, $text)) return true;
        }
        return false;
    }

    // === F. 混淆复杂度评分 ===

    /**
     * 规则：编码层数 +10/层；混淆技术 +8/种；对抗样本特征 +15/种；
     *       编码链异常 +10；还原后含攻击 payload +30；多维交叉加成（2维+10/3维+20/4+维+30）。
     */
    private static function scoreObfuscationComplexity(array $features): int {
        $score = 0;
        $score += ($features['decode_depth'] ?? 0) * 10;
        $score += ($features['obfuscation_count'] ?? 0) * 8;
        $score += ($features['adversarial_count'] ?? 0) * 15;
        if (!empty($features['chain_anomaly']))       $score += 10;
        if (!empty($features['decoded_has_payload'])) $score += 30;
        // 多维混淆交叉加成
        $dimCount = 0;
        if (!empty($features['decode_depth']))         $dimCount++;
        if (!empty($features['obfuscation_count']))    $dimCount++;
        if (!empty($features['adversarial_count']))    $dimCount++;
        if (!empty($features['chain_anomaly']))        $dimCount++;
        if (!empty($features['decoded_has_payload']))  $dimCount++;
        if ($dimCount >= 4)      $score += 30;
        elseif ($dimCount === 3) $score += 20;
        elseif ($dimCount === 2) $score += 10;
        return min(100, max(0, $score));
    }

    // === 防御建议生成 ===

    private static function generateRecommendation(array $threats, int $score): string {
        if (empty($threats)) return '无对抗攻击特征';
        $types = array_column($threats, 'type');
        if (in_array('decoded_payload', $types, true))     return '还原后检出攻击 payload，强烈建议拦截并告警';
        if (in_array('recursive_encoding', $types, true))  return '检测到多层嵌套编码，建议启用深度递归还原并重新评估';
        if (in_array('adversarial', $types, true))         return '检测到对抗样本特征（同形字/零宽字符/WAF 绕过结构），建议拦截并告警';
        if (in_array('encoding_chain', $types, true))      return '检测到不自然编码链，建议加强编码一致性校验';
        if (in_array('obfuscation', $types, true))         return '检测到混淆模式，建议启用混淆归一化后重新评估';
        if ($score >= 50) return '高置信度对抗攻击，建议立即拦截并告警';
        return '检测到疑似对抗攻击特征，建议加强观察';
    }
}
