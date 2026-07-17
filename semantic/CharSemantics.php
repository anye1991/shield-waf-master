<?php
/**
 * 字符语义分析引擎
 * 职责：分析输入文本在字符层面的可疑特征，识别攻击者常用的字符意图模式。
 * 包括：特殊字符频率、不可打印字符比例、混用字符集（同形字混淆）、
 *       控制字符与零宽字符、字符熵等。
 */
defined('ABSPATH') || exit;

class CharSemantics {
    /**
     * 需要重点关注的危险特殊字符及其单字符权重
     * @var array<string,int>
     */
    private static $danger_chars = [
        '<' => 3, '>' => 3,   // HTML/JS 标签
        '\'' => 4, '"' => 4,  // 字符串 / SQL 闭合符
        ';' => 3,             // 语句分隔 / 命令链
        '|' => 5, '&' => 4,   // 命令管道与后台符
        '`' => 5,             // 命令替换
        '$' => 4,             // 变量引用
        '(' => 2, ')' => 2,   // 函数调用
        '{' => 2, '}' => 2,   // 代码块
        '\\' => 3,            // 转义 / 路径
        '/' => 2,             // 路径 / 正则
        '%' => 3,             // 编码 / 通配
        '#' => 2,             // 注释
        '=' => 2,             // 赋值
        '*' => 2,             // 通配 / SQL
        '?' => 1,             // 查询串 / PHP
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
     * 分析字符意图，识别可疑字符模式
     *
     * @param string $text 待分析文本
     * @return array{score:int, indicators:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return ['score' => 0, 'indicators' => []];
        }

        $indicators = [];
        $score = 0;
        $len = strlen($text);

        // ---- 1. 特殊字符频率分析 ----
        $specialCount = 0;
        $specialWeightSum = 0;
        foreach (self::$danger_chars as $ch => $w) {
            $c = substr_count($text, $ch);
            if ($c > 0) {
                $specialCount += $c;
                $specialWeightSum += $c * $w;
            }
        }
        $specialRatio = $len > 0 ? $specialCount / $len : 0;
        if ($specialRatio > 0.30) {
            $score += 35;
            $indicators[] = 'special_char_density_high:' . round($specialRatio, 2);
        } elseif ($specialRatio > 0.15) {
            $score += 20;
            $indicators[] = 'special_char_density_medium:' . round($specialRatio, 2);
        } elseif ($specialRatio > 0.05) {
            $score += 8;
        }
        // 高权重字符（引号、管道、反引号等）累计命中加分
        if ($specialWeightSum >= 20) {
            $score += 20;
            $indicators[] = 'high_weight_special_chars:' . $specialWeightSum;
        } elseif ($specialWeightSum >= 10) {
            $score += 10;
        }

        // ---- 2. 不可打印字符比例（含 NUL / 控制字符） ----
        $nonPrintable = 0;
        $nulCount = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($text[$i]);
            if ($o === 0) {
                $nulCount++;
                $nonPrintable++;
                continue;
            }
            // 制表/换行/回车(0x09-0x0D)视为可接受，其余 < 0x20 或 0x7F 视为不可打印
            if (($o < 0x20 && $o !== 0x09 && $o !== 0x0A && $o !== 0x0D) || $o === 0x7F) {
                $nonPrintable++;
            }
        }
        if ($nonPrintable > 0) {
            $npRatio = $nonPrintable / $len;
            if ($npRatio > 0.10) {
                $score += 25;
                $indicators[] = 'non_printable_high:' . round($npRatio, 3);
            } elseif ($npRatio > 0.02) {
                $score += 12;
                $indicators[] = 'non_printable_medium:' . round($npRatio, 3);
            } else {
                $score += 5;
                $indicators[] = 'non_printable_low:' . $nonPrintable;
            }
        }
        // NUL 字节用于截断绕过，极其可疑，单独加重
        if ($nulCount > 0) {
            $score += min(20, $nulCount * 10);
            $indicators[] = 'null_byte:' . $nulCount;
        }

        // ---- 3. 控制字符与零宽字符（Unicode 不可见字符） ----
        $invisibleHits = [];
        foreach (self::$invisible_chars as $seq => $name) {
            $c = substr_count($text, $seq);
            if ($c > 0) {
                $invisibleHits[$name] = $c;
            }
        }
        if (!empty($invisibleHits)) {
            $zwHits = 0;
            foreach (['ZWSP', 'ZWNJ', 'ZWJ', 'WJ', 'BOM', 'SHY'] as $k) {
                if (!empty($invisibleHits[$k])) {
                    $zwHits += $invisibleHits[$k];
                }
            }
            if ($zwHits > 0) {
                $score += min(25, $zwHits * 8);
                $indicators[] = 'zero_width_chars:' . json_encode($invisibleHits, JSON_UNESCAPED_UNICODE);
            }
        }

        // ---- 4. 混用字符集（同形字混淆） ----
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
        // 拉丁是正常基础集；若同时出现西里尔/希腊等视觉相似集，则可能为同形字混淆
        $suspiciousMix = 0;
        if (isset($scriptsFound['latin'])) {
            foreach (['cyrillic', 'greek'] as $s) {
                if (!empty($scriptsFound[$s])) {
                    $suspiciousMix += $scriptsFound[$s];
                }
            }
        }
        if ($suspiciousMix > 0) {
            $score += min(30, $suspiciousMix * 6);
            $indicators[] = 'mixed_script_homoglyph:' . json_encode($scriptsFound, JSON_UNESCAPED_UNICODE);
        }

        // ---- 5. 字符熵（高熵可能为编码混淆 / 随机串） ----
        $entropy = self::shannonEntropy($text);
        if ($entropy > 4.5 && $len > 20) {
            $score += 10;
            $indicators[] = 'high_entropy:' . round($entropy, 2);
        }

        $score = max(0, min(100, (int) round($score)));
        return ['score' => $score, 'indicators' => $indicators];
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
