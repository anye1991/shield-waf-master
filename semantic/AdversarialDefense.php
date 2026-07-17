<?php
/**
 * 对抗样本防御引擎
 * 职责：检测针对语义分析引擎本身的对抗攻击，
 *       包括语义分析绕过、评分系统欺骗、归一化引擎欺骗等。
 *       攻击者可能针对性地构造载荷以绕过语义检测，本引擎专门识别此类对抗行为。
 */
defined('ABSPATH') || exit;

class AdversarialDefense {
    /**
     * 对抗攻击类型及检测模式
     */
    private static $adversarial_patterns = [
        // 语义分析绕过：故意混入大量正常文本以稀释语义分数
        'semantic_dilution' => [
            'name' => '语义稀释攻击',
            'weight' => 25,
            'patterns' => [
                'long_normal_prefix' => '/^[\w\s]{100,}(?:union|select|insert|update|delete)/iu',
                'comment_dilution'   => '/\/\*[\s\S]{200,}\*\/(?:union|select)/iu',
                'html_comment_dilution' => '/<!--[\s\S]{100,}-->(?:script|javascript)/iu',
                'noise_injection'    => '/(?:\w{20,}\s+){5,}(?:union|select|eval)/iu',
            ],
        ],
        // 评分欺骗：构造刚好低于阈值的载荷
        'threshold_evasion' => [
            'name' => '阈值规避攻击',
            'weight' => 20,
            'patterns' => [
                'just_below_threshold' => '/(?:union|select).*?LIMIT\s+0(?:\s*,\s*1)?/iu',
                'minimal_payload'      => '/\b(?:or|and)\b\s+1\s*=\s*1\s*$/iu',
                'fragmented_keywords'  => '/u\s*n\s*i\s*o\s*n|s\s*e\s*l\s*e\s*c\s*t/iu',
            ],
        ],
        // 归一化引擎欺骗：利用归一化漏洞
        'normalizer_deception' => [
            'name' => '归一化欺骗',
            'weight' => 30,
            'patterns' => [
                'double_encoding'      => '/%25[0-9a-fA-F]{2}/u',
                'triple_encoding'      => '/%2525[0-9a-fA-F]{2}/u',
                'unicode_overlong'     => '/%[cC]0%[aA]f/u',
                'null_byte_encoding'   => '/%00|%2500|%252500/u',
                'encoding_mismatch'    => '/%[0-9a-fA-F]{2}.*&#x[0-9a-fA-F]+;/iu',
                'bom_injection'        => '/\xEF\xBB\xBF|\xFE\xFF|\xFF\xFE/',
            ],
        ],
        // 上下文切换：利用不同编码上下文
        'context_switching' => [
            'name' => '上下文切换攻击',
            'weight' => 20,
            'patterns' => [
                'json_to_sql'      => '/\{.*["\']query["\']\s*:\s*["\'].*(?:union|select)/iu',
                'xml_to_sql'       => '/<\w+>.*(?:union|select).*<\/\w+>/iu',
                'base64_nested'    => '/[A-Za-z0-9+\/]{100,}={0,2}.*[A-Za-z0-9+\/]{100,}={0,2}/u',
                'multipart_inject' => '/Content-Disposition.*form-data.*(?:php|eval)/iu',
            ],
        ],
        // 时间分散：利用请求间隔规避频率检测
        'temporal_evasion' => [
            'name' => '时间分散攻击',
            'weight' => 15,
            'patterns' => [
                // 主要通过行为分析检测，这里标记特征
                'slow_probe'       => '/\b(?:sleep|benchmark)\s*\(\s*0\.\d+\s*\)/iu',
                'conditional_delay'=> '/\b(?:case|if)\b.*\bsleep\b/iu',
            ],
        ],
        // 多向量协同：分散载荷到多个向量
        'multi_vector_evasion' => [
            'name' => '多向量协同绕过',
            'weight' => 25,
            'patterns' => [
                'header_param_split' => '/(?:X-Custom-Header|X-Forwarded-For).*[:;].*(?:union|select)/iu',
                'cookie_param_split' => '/(?:Cookie|Set-Cookie).*[:=].*[^;]*(?:union|select)/iu',
            ],
        ],
    ];

    /**
     * 对抗样本检测分析
     *
     * @param string $text 归一化后的文本
     * @param string $rawText 原始未归一化文本
     * @param array  $normalizerContext 归一化引擎上下文
     * @param array  $multiVectorResult 多向量融合结果
     * @return array{score:int, threats:array, patterns:array, recommendation:string}
     */
    public static function analyze(
        string $text,
        string $rawText = '',
        array $normalizerContext = [],
        array $multiVectorResult = []
    ): array {
        $score = 0;
        $threats = [];
        $patterns = [];
        $combined = $rawText !== '' ? $rawText : $text;

        foreach (self::$adversarial_patterns as $type => $config) {
            $typeScore = 0;
            $typeHits = 0;
            $typeMatched = [];

            foreach ($config['patterns'] as $patName => $pattern) {
                if (@preg_match($pattern, $combined)) {
                    $typeHits++;
                    $typeMatched[] = $patName;
                    $typeScore += 100 / count($config['patterns']);
                }
            }

            if ($typeHits > 0) {
                $bonus = $typeHits >= 2 ? 1.3 : 1.0;
                $finalScore = min(100, (int)round($typeScore * $bonus * ($config['weight'] / 100)));
                if ($finalScore > 0) {
                    $threats[] = [
                        'type'       => $type,
                        'name'       => $config['name'],
                        'score'      => $finalScore,
                        'matched'    => $typeMatched,
                    ];
                    $patterns = array_merge($patterns, $typeMatched);
                    $score += $finalScore;
                }
            }
        }

        // 归一化前后差异分析（检测归一化绕过）
        if ($rawText !== '' && $text !== '') {
            $rawLen = strlen($rawText);
            $normLen = strlen($text);
            $ratio = $rawLen > 0 ? $normLen / $rawLen : 1;

            // 归一化后急剧变短 => 可能是编码绕过
            if ($ratio < 0.3 && $rawLen > 50) {
                $score += 15;
                $threats[] = [
                    'type'    => 'normalizer_bypass',
                    'name'    => '归一化前后差异过大',
                    'score'   => 15,
                    'matched' => ['normalization_ratio:' . round($ratio, 2)],
                ];
            }

            // 归一化深度异常
            $encodingDepth = $normalizerContext['encoding_depth'] ?? 0;
            if ($encodingDepth >= 5) {
                $score += 20;
                $threats[] = [
                    'type'    => 'deep_encoding_bypass',
                    'name'    => '极端编码深度规避',
                    'score'   => 20,
                    'matched' => ['encoding_depth:' . $encodingDepth],
                ];
            }
        }

        // 多向量分数异常：单一向量高分但其他向量异常低 => 可能分散载荷
        $vectorScores = $multiVectorResult['vector_scores'] ?? [];
        if (!empty($vectorScores)) {
            $maxScore = max($vectorScores);
            $avgScore = array_sum($vectorScores) / count($vectorScores);
            if ($maxScore >= 40 && $avgScore < 10) {
                $score += 12;
                $threats[] = [
                    'type'    => 'vector_imbalance',
                    'name'    => '向量分数分布异常',
                    'score'   => 12,
                    'matched' => ['max:' . $maxScore . '_avg:' . round($avgScore, 1)],
                ];
            }
        }

        // 纯噪声检测（大量无意义字符+少量有效载荷）
        if (strlen($text) > 200) {
            $printableRatio = self::calcPrintableRatio($text);
            if ($printableRatio < 0.3) {
                $score += 10;
                $threats[] = [
                    'type'    => 'noise_camouflage',
                    'name'    => '噪声伪装',
                    'score'   => 10,
                    'matched' => ['printable_ratio:' . round($printableRatio, 2)],
                ];
            }
        }

        $score = min(100, $score);

        // 生成防御建议
        $recommendation = self::generateRecommendation($threats, $score);

        return [
            'score'          => $score,
            'threats'        => $threats,
            'threat_names'   => array_column($threats, 'name'),
            'patterns'       => array_values(array_unique($patterns)),
            'recommendation' => $recommendation,
            'is_adversarial' => $score >= 30,
            'risk_level'     => $score >= 60 ? 'high' : ($score >= 30 ? 'medium' : 'low'),
        ];
    }

    /**
     * 生成防御建议
     */
    private static function generateRecommendation(array $threats, int $score): string {
        if (empty($threats)) return '无对抗攻击特征';

        $typeMap = array_column($threats, 'type');

        if (in_array('normalizer_deception', $typeMap)) {
            return '检测到归一化欺骗，建议启用更深层归一化并校验编码一致性';
        }
        if (in_array('semantic_dilution', $typeMap)) {
            return '检测到语义稀释攻击，建议启用局部语义聚焦分析';
        }
        if (in_array('threshold_evasion', $typeMap)) {
            return '检测到阈值规避，建议动态调整评分阈值并启用行为分析';
        }
        if (in_array('multi_vector_evasion', $typeMap)) {
            return '检测到多向量协同绕过，建议启用全向量联合分析';
        }
        if ($score >= 50) {
            return '高置信度对抗攻击，建议立即拦截并告警';
        }

        return '检测到疑似对抗攻击特征，建议加强观察';
    }

    /**
     * 计算可打印字符比例
     */
    private static function calcPrintableRatio(string $text): float {
        $len = strlen($text);
        if ($len === 0) return 1.0;
        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $ord = ord($text[$i]);
            if ($ord >= 32 && $ord <= 126) {
                $printable++;
            }
        }
        return $printable / $len;
    }
}
