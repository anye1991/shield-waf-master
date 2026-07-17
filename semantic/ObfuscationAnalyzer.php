<?php
/**
 * 混淆深度评估引擎
 * 职责：量化评估输入内容的混淆程度和绕过意图，
 *       包括编码层数、编码多样性、字符集混淆、结构打乱、反检测特征等维度。
 *       混淆深度越高，攻击意图和绕过意愿越强。
 */
defined('ABSPATH') || exit;

class ObfuscationAnalyzer {
    /**
     * 混淆技术类型及其权重
     */
    private static $obfuscation_types = [
        'encoding_multilayer' => ['name' => '多层编码嵌套', 'weight' => 30],
        'encoding_diversity'  => ['name' => '编码方式多样', 'weight' => 15],
        'homoglyph'           => ['name' => '同形字符混淆', 'weight' => 20],
        'invisible_chars'     => ['name' => '不可见字符', 'weight' => 15],
        'structure_break'     => ['name' => '结构打乱', 'weight' => 20],
        'comment_injection'   => ['name' => '注释注入', 'weight' => 12],
        'case_mixing'         => ['name' => '大小写混合', 'weight' => 5],
        'whitespace_injection' => ['name' => '空白字符注入', 'weight' => 8],
        'double_encoding'     => ['name' => '双重编码', 'weight' => 25],
        'hex_obfuscation'     => ['name' => '十六进制混淆', 'weight' => 18],
        'string_concat'       => ['name' => '字符串拼接', 'weight' => 15],
        'variable_variable'   => ['name' => '可变变量', 'weight' => 20],
    ];

    /**
     * 混淆深度分析
     *
     * @param string $text 原始文本
     * @param array  $normalizerContext 归一化引擎上下文
     * @return array{score:int, depth:string, techniques:array, indicators:array}
     */
    public static function analyze(string $text, array $normalizerContext = []): array {
        if ($text === '') {
            return [
                'score'      => 0,
                'depth'      => 'none',
                'techniques' => [],
                'indicators' => [],
                'bypass_intent' => 0,
            ];
        }

        $score = 0;
        $techniques = [];
        $indicators = [];

        // ---- 1. 编码深度（来自归一化引擎） ----
        $encodingDepth = $normalizerContext['encoding_depth'] ?? 0;
        $transformCount = $normalizerContext['transform_count'] ?? 0;
        $encodingTypes = $normalizerContext['encoding_types'] ?? [];
        $doubleEncoding = !empty($normalizerContext['double_encoding_detected']);

        if ($encodingDepth >= 4) {
            $score += 30;
            $techniques[] = 'encoding_multilayer';
            $indicators[] = 'encoding_depth:' . $encodingDepth;
        } elseif ($encodingDepth >= 2) {
            $score += 15;
            $techniques[] = 'encoding_multilayer';
            $indicators[] = 'encoding_depth:' . $encodingDepth;
        }

        $uniqueEncodingCount = is_array($encodingTypes) ? count($encodingTypes) : 0;
        if ($uniqueEncodingCount >= 4) {
            $score += 15;
            $techniques[] = 'encoding_diversity';
            $indicators[] = 'encoding_types:' . $uniqueEncodingCount;
        } elseif ($uniqueEncodingCount >= 2) {
            $score += 8;
        }

        if ($doubleEncoding) {
            $score += 25;
            $techniques[] = 'double_encoding';
            $indicators[] = 'double_encoding_detected';
        }

        // ---- 2. 同形字符混淆 ----
        $mixedScripts = self::countMixedScripts($text);
        if ($mixedScripts >= 3) {
            $score += 20;
            $techniques[] = 'homoglyph';
            $indicators[] = 'mixed_scripts:' . $mixedScripts;
        } elseif ($mixedScripts >= 2) {
            $score += 10;
        }

        // 检测西里尔/希腊字母混入拉丁
        $cyrillicInLatin = preg_match_all('/[\x{0400}-\x{04FF}]/u', $text);
        $greekInLatin = preg_match_all('/[\x{0370}-\x{03FF}]/u', $text);
        $latinCount = preg_match_all('/[a-zA-Z]/', $text);
        if ($latinCount > 10 && ($cyrillicInLatin > 0 || $greekInLatin > 0)) {
            $score += 15;
            if (!in_array('homoglyph', $techniques)) {
                $techniques[] = 'homoglyph';
            }
            $indicators[] = 'homoglyph_latin_mix';
        }

        // ---- 3. 不可见字符 ----
        $invisibleCount = self::countInvisibleChars($text);
        if ($invisibleCount >= 5) {
            $score += 15;
            $techniques[] = 'invisible_chars';
            $indicators[] = 'invisible_chars:' . $invisibleCount;
        } elseif ($invisibleCount >= 1) {
            $score += 8;
        }

        // NUL字节
        $nulCount = substr_count($text, "\0");
        if ($nulCount > 0) {
            $score += min(20, $nulCount * 8);
            $indicators[] = 'null_bytes:' . $nulCount;
        }

        // ---- 4. 注释注入混淆 ----
        $sqlComments = preg_match_all('/\/\*[\s\S]*?\*\//', $text);
        $htmlComments = preg_match_all('/<!--[\s\S]*?-->/', $text);
        $totalComments = $sqlComments + $htmlComments;
        if ($totalComments >= 3) {
            $score += 12;
            $techniques[] = 'comment_injection';
            $indicators[] = 'comment_injection:' . $totalComments;
        } elseif ($totalComments >= 1) {
            $score += 5;
        }

        // ---- 5. 大小写混合混淆 ----
        $upperCount = preg_match_all('/[A-Z]/', $text);
        $lowerCount = preg_match_all('/[a-z]/', $text);
        $totalAlpha = $upperCount + $lowerCount;
        if ($totalAlpha > 20) {
            $upperRatio = $upperCount / $totalAlpha;
            if ($upperRatio > 0.3 && $upperRatio < 0.7) {
                $score += 5;
                $techniques[] = 'case_mixing';
                $indicators[] = 'case_mix_ratio:' . round($upperRatio, 2);
            }
        }

        // ---- 6. 空白字符注入 ----
        $origLen = strlen($text);
        $noSpaceLen = strlen(preg_replace('/\s+/', '', $text));
        $whitespaceRatio = $origLen > 0 ? ($origLen - $noSpaceLen) / $origLen : 0;
        if ($whitespaceRatio > 0.3) {
            $score += 8;
            $techniques[] = 'whitespace_injection';
            $indicators[] = 'whitespace_ratio:' . round($whitespaceRatio, 2);
        }

        // ---- 7. 十六进制混淆 ----
        $hexStrings = preg_match_all('/0x[0-9a-fA-F]{4,}/', $text);
        $escapedHex = preg_match_all('/\\\\x[0-9a-fA-F]{2}/', $text);
        $totalHex = $hexStrings + $escapedHex;
        if ($totalHex >= 3) {
            $score += 18;
            $techniques[] = 'hex_obfuscation';
            $indicators[] = 'hex_obfuscation:' . $totalHex;
        } elseif ($totalHex >= 1) {
            $score += 8;
        }

        // ---- 8. 字符串拼接混淆 ----
        $concatPatterns = [
            '/\.\s*\$/',
            '/\$\w+\s*\.\s*["\']/',
            '/["\']\s*\.\s*\$/',
            '/concat\s*\(/iu',
            '/group_concat\s*\(/iu',
        ];
        $concatHits = 0;
        foreach ($concatPatterns as $pat) {
            if (@preg_match($pat, $text)) {
                $concatHits++;
            }
        }
        if ($concatHits >= 2) {
            $score += 15;
            $techniques[] = 'string_concat';
            $indicators[] = 'string_concat:' . $concatHits;
        } elseif ($concatHits >= 1) {
            $score += 8;
        }

        // ---- 9. 结构打乱检测 ----
        // 关键词被注释/空白/特殊字符打断
        $structBreakCount = 0;
        if (preg_match('/s\/\*[\s\S]*?\*\/e\s*l\s*e\s*c\s*t/i', $text)) {
            $structBreakCount++;
        }
        if (preg_match('/un\s*\/\*[\s\S]*?\*\/i\s*o\s*n/i', $text)) {
            $structBreakCount++;
        }
        if ($structBreakCount > 0) {
            $score += 20;
            $techniques[] = 'structure_break';
            $indicators[] = 'structure_break:' . $structBreakCount;
        }

        // ---- 10. 高熵值检测 ----
        $entropy = self::calcEntropy($text);
        if ($entropy > 5.5 && strlen($text) > 30) {
            $score += 10;
            $indicators[] = 'high_entropy:' . round($entropy, 2);
        }

        // ---- 计算绕过意图强度 ----
        $bypassIntent = 0;
        $highRiskTechniques = ['encoding_multilayer', 'double_encoding', 'structure_break', 'homoglyph'];
        foreach ($highRiskTechniques as $t) {
            if (in_array($t, $techniques)) {
                $bypassIntent += 20;
            }
        }
        if (count($techniques) >= 4) {
            $bypassIntent += 20;
        }
        $bypassIntent = min(100, $bypassIntent);

        // ---- 混淆等级 ----
        $score = min(100, (int)round($score));
        if ($score >= 70) {
            $depth = 'extreme';
        } elseif ($score >= 50) {
            $depth = 'heavy';
        } elseif ($score >= 30) {
            $depth = 'moderate';
        } elseif ($score >= 10) {
            $depth = 'light';
        } else {
            $depth = 'none';
        }

        return [
            'score'         => $score,
            'depth'         => $depth,
            'depth_label'   => self::getDepthLabel($depth),
            'techniques'    => $techniques,
            'technique_names' => array_map(function($t) {
                return self::$obfuscation_types[$t]['name'] ?? $t;
            }, $techniques),
            'indicators'    => $indicators,
            'bypass_intent' => $bypassIntent,
            'encoding_depth' => $encodingDepth,
            'transform_count' => $transformCount,
        ];
    }

    /**
     * 统计混用字符集数量
     */
    private static function countMixedScripts(string $text): int {
        $scripts = 0;
        if (preg_match('/[a-zA-Z]/', $text)) $scripts++;
        if (preg_match('/[\x{0400}-\x{04FF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0370}-\x{03FF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0530}-\x{058F}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0600}-\x{06FF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{4E00}-\x{9FFF}]/u', $text)) $scripts++;
        return $scripts;
    }

    /**
     * 统计不可见字符数量
     */
    private static function countInvisibleChars(string $text): int {
        $count = 0;
        $invisible = ["\u{200B}", "\u{200C}", "\u{200D}", "\u{FEFF}", "\u{2060}", "\u{00AD}", "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}"];
        foreach ($invisible as $ch) {
            $c = substr_count($text, $ch);
            if ($c > 0) $count += $c;
        }
        return $count;
    }

    /**
     * 计算 Shannon 熵
     */
    private static function calcEntropy(string $text): float {
        $len = strlen($text);
        if ($len === 0) return 0.0;
        $freq = count_chars($text, 1);
        $entropy = 0.0;
        foreach ($freq as $cnt) {
            $p = $cnt / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    /**
     * 获取混淆等级中文标签
     */
    private static function getDepthLabel(string $depth): string {
        $labels = [
            'none'     => '无混淆',
            'light'    => '轻度混淆',
            'moderate' => '中度混淆',
            'heavy'    => '重度混淆',
            'extreme'  => '极端混淆',
        ];
        return $labels[$depth] ?? $depth;
    }
}
