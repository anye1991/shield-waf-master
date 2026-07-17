<?php
defined('ABSPATH') || exit;

/**
 * Layer1：字符语义分析层
 *
 * 从字符粒度对输入进行统计分析，包括字符频率分布、信息熵计算、
 * 异常字符比例检测等。这些指标可用于识别混淆、编码绕过等行为。
 */
class Layer1_CharSemantics {

    /**
     * 分析文本的字符级语义特征
     *
     * @param string $text 待分析文本
     * @return array ['score'=>0-100, 'entropy'=>float, 'anomalies'=>[...]]
     */
    public static function analyze(string $text): array {
        $result = [
            'score'     => 0,
            'entropy'   => 0.0,
            'anomalies' => [],
        ];

        if ($text === '') {
            return $result;
        }

        $len = strlen($text);
        $bytes = [];
        for ($i = 0; $i < $len; $i++) {
            $b = ord($text[$i]);
            if (!isset($bytes[$b])) {
                $bytes[$b] = 0;
            }
            $bytes[$b]++;
        }

        // 1. 计算香农信息熵
        $entropy = 0.0;
        foreach ($bytes as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }
        $result['entropy'] = round($entropy, 4);

        // 熵值越高越可疑（随机化/混淆的特征）
        // 普通文本熵约 3.5-4.5，高熵（>4.5）通常是编码或加密载荷
        if ($entropy > 4.8) {
            $result['anomalies'][] = ['type' => 'high_entropy', 'value' => round($entropy, 2), 'desc' => '高熵载荷，疑似编码/加密混淆'];
        }

        // 2. 字符频率分布：统计各类字符的比例
        $stats = [
            'printable' => 0,   // 可打印 ASCII (32-126)
            'digit'     => 0,   // 数字 0-9
            'alpha'     => 0,   // 字母 a-zA-Z
            'symbol'    => 0,   // 符号
            'space'     => 0,   // 空白
            'ctrl'      => 0,   // 控制字符
            'high'      => 0,   // 高位字节 (>127)
            'quote'     => 0,   // 引号类
            'paren'     => 0,   // 括号类
        ];

        for ($i = 0; $i < $len; $i++) {
            $b = ord($text[$i]);
            if ($b === 0x20 || $b === 0x09 || $b === 0x0A || $b === 0x0D) {
                $stats['space']++;
            } elseif ($b >= 0x30 && $b <= 0x39) {
                $stats['digit']++;
                $stats['printable']++;
            } elseif (($b >= 0x41 && $b <= 0x5A) || ($b >= 0x61 && $b <= 0x7A)) {
                $stats['alpha']++;
                $stats['printable']++;
            } elseif ($b >= 0x20 && $b <= 0x7E) {
                $stats['symbol']++;
                $stats['printable']++;
                if ($b === 0x22 || $b === 0x27 || $b === 0x60) {
                    $stats['quote']++;
                }
                if ($b === 0x28 || $b === 0x29 || $b === 0x5B || $b === 0x5D || $b === 0x7B || $b === 0x7D) {
                    $stats['paren']++;
                }
            } elseif ($b < 0x20) {
                $stats['ctrl']++;
            } else {
                $stats['high']++;
            }
        }

        // 3. 异常字符比例检测
        $score = 0;

        $ctrlRatio = $stats['ctrl'] / $len;
        if ($ctrlRatio > 0.05) {
            $score += 25;
            $result['anomalies'][] = ['type' => 'ctrl_chars', 'ratio' => round($ctrlRatio, 3), 'desc' => '控制字符比例过高'];
        }

        $highRatio = $stats['high'] / $len;
        if ($highRatio > 0.3) {
            $score += 20;
            $result['anomalies'][] = ['type' => 'high_bytes', 'ratio' => round($highRatio, 3), 'desc' => '高位字节占比异常，可能为二进制/多字节编码载荷'];
        }

        $quoteRatio = $stats['quote'] / $len;
        if ($quoteRatio > 0.1) {
            $score += 20;
            $result['anomalies'][] = ['type' => 'quote_density', 'ratio' => round($quoteRatio, 3), 'desc' => '引号密度异常，疑似注入闭合尝试'];
        }

        $parenRatio = $stats['paren'] / $len;
        if ($parenRatio > 0.08) {
            $score += 15;
            $result['anomalies'][] = ['type' => 'paren_density', 'ratio' => round($parenRatio, 3), 'desc' => '括号密度异常，疑似函数调用或表达式注入'];
        }

        // 4. 检测特殊字符序列：连续的非字母数字字符（混淆特征）
        if (preg_match_all('/[^a-zA-Z0-9\s]{6,}/', $text, $m)) {
            $seqCount = count($m[0]);
            $score += min($seqCount * 8, 25);
            $result['anomalies'][] = ['type' => 'symbol_run', 'count' => $seqCount, 'desc' => '检测到长符号序列，疑似混淆载荷'];
        }

        // 5. 检测十六进制/八进制编码特征
        $hexCount = preg_match_all('/0x[0-9a-f]+/i', $text);
        if ($hexCount > 0) {
            $score += min($hexCount * 6, 20);
            $result['anomalies'][] = ['type' => 'hex_encoding', 'count' => $hexCount, 'desc' => '检测到十六进制编码'];
        }

        $escCount = preg_match_all('/\\\\x[0-9a-fA-F]{2}/', $text);
        if ($escCount > 0) {
            $score += min($escCount * 6, 20);
            $result['anomalies'][] = ['type' => 'escape_seq', 'count' => $escCount, 'desc' => '检测到转义序列'];
        }

        // 6. 熵值贡献分
        if ($entropy > 4.8) {
            $score += min(($entropy - 4.8) * 30, 25);
        }

        $result['score'] = max(0, min(100, (int) round($score)));
        return $result;
    }
}
