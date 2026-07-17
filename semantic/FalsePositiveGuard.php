<?php
/**
 * 误报控制引擎
 * 职责：多层确认机制，确保不误杀正常请求。
 *       通过白名单豁免、上下文确认、行为基线、业务验证等多层过滤，
 *       将误报率降到理论极限。核心理念：宁可漏网，绝不误杀。
 */
defined('ABSPATH') || exit;

class FalsePositiveGuard {
    /**
     * 可信业务模式白名单
     */
    private static $trusted_patterns = [
        'search_query' => [
            'name' => '搜索查询',
            'conditions' => [
                'uri' => '/(?:search|query|keyword|q)\b/i',
                'params' => ['q', 'query', 'keyword', 's', 'search'],
                'safe_chars' => ['+', '-', '*', '"', '~', '(', ')'],
            ],
        ],
        'url_encoded' => [
            'name' => 'URL编码参数',
            'conditions' => [
                'param_keys' => ['url', 'link', 'redirect', 'next', 'return_url'],
                'safe_pattern' => '/^https?:\/\/[\w\-\.]+(?:\/[\w\-\.\/?%&=]*)?$/i',
            ],
        ],
        'markdown_content' => [
            'name' => 'Markdown内容',
            'conditions' => [
                'uri' => '/(?:edit|post|content|write|blog)\b/i',
                'safe_chars' => ['#', '*', '_', '`', '[', ']', '(', ')', '>', '-', '+'],
            ],
        ],
        'code_snippet' => [
            'name' => '代码片段',
            'conditions' => [
                'uri' => '/(?:code|gist|snippet|paste)\b/i',
                'safe_patterns' => ['<\?php', '</script>', 'function ', 'class ', 'import '],
            ],
        ],
        'json_data' => [
            'name' => 'JSON数据',
            'conditions' => [
                'content_type' => '/application\/json/i',
                'safe_pattern' => '/^\s*\{[\s\S]*\}\s*$/',
            ],
        ],
        'xml_data' => [
            'name' => 'XML数据',
            'conditions' => [
                'content_type' => '/application\/xml|text\/xml/i',
                'safe_pattern' => '/^\s*<\?xml/',
            ],
        ],
        'file_upload' => [
            'name' => '文件上传',
            'conditions' => [
                'uri' => '/(?:upload|file)\b/i',
                'method' => 'POST',
                'content_type' => '/multipart\/form-data/i',
            ],
        ],
        'api_request' => [
            'name' => 'API请求',
            'conditions' => [
                'uri' => '/(?:api|v1|v2|v3)\b/i',
                'accept' => '/application\/json/i',
                'headers' => ['Authorization', 'X-API-Key', 'X-Request-ID'],
            ],
        ],
        'login_request' => [
            'name' => '登录请求',
            'conditions' => [
                'uri' => '/(?:login|signin|auth)\b/i',
                'params' => ['username', 'email', 'password', 'captcha'],
            ],
        ],
        'normal_form' => [
            'name' => '普通表单',
            'conditions' => [
                'method' => 'POST',
                'content_type' => '/application\/x-www-form-urlencoded/i',
                'param_count_max' => 10,
            ],
        ],
    ];

    /**
     * 可信参数名白名单（这些参数的值可以包含特殊字符）
     */
    private static $trusted_param_names = [
        'q', 'query', 'keyword', 'search', 's',
        'url', 'link', 'redirect', 'next', 'return_url', 'callback',
        'content', 'body', 'message', 'text', 'description', 'comment',
        'code', 'gist', 'snippet', 'paste', 'script',
        'data', 'json', 'xml', 'payload',
        'file', 'file_name', 'upload',
        'username', 'email', 'password', 'captcha', 'token',
        'title', 'name', 'tags', 'category',
        'filters', 'options', 'settings', 'config',
    ];

    /**
     * 误报控制分析
     *
     * @param string $uri 请求URI
     * @param string $method 请求方法
     * @param array $params 参数数组
     * @param array $headers 请求头
     * @param array $semanticResult 语义分析结果
     * @param string $ip 请求IP
     * @return array{is_false_positive:bool, confidence:int, reason:string, recommendations:array}
     */
    public static function analyze(
        string $uri,
        string $method = 'GET',
        array $params = [],
        array $headers = [],
        array $semanticResult = [],
        string $ip = ''
    ): array {
        $isFalsePositive = false;
        $confidence = 0;
        $reason = '';
        $recommendations = [];
        $totalScore = $semanticResult['total_score'] ?? 0;

        // ---- 第1层：业务模式匹配 ----
        $matchedPattern = self::matchTrustedPattern($uri, $method, $params, $headers);
        if ($matchedPattern) {
            $confidence += 30;
            $reason = "匹配可信业务模式: {$matchedPattern}";
            $recommendations[] = '业务模式匹配';
        }

        // ---- 第2层：参数名白名单 ----
        $trustedParamRatio = self::checkTrustedParams($params);
        if ($trustedParamRatio >= 0.8) {
            $confidence += 25;
            $reason .= ($reason ? '; ' : '') . '参数名全为可信';
            $recommendations[] = '参数名白名单';
        } elseif ($trustedParamRatio >= 0.5) {
            $confidence += 10;
            $recommendations[] = '部分参数可信';
        }

        // ---- 第3层：语义指标质量检查 ----
        $indicatorQuality = self::checkIndicatorQuality($semanticResult);
        if ($indicatorQuality === 'weak') {
            $confidence += 20;
            $reason .= ($reason ? '; ' : '') . '语义指标质量弱';
            $recommendations[] = '弱指标';
        }

        // ---- 第4层：行为基线检查 ----
        if (!empty($ip)) {
            $baselineCheck = self::checkBehaviorBaseline($ip, $semanticResult);
            if ($baselineCheck['is_consistent']) {
                $confidence += 15;
                $reason .= ($reason ? '; ' : '') . '符合行为基线';
                $recommendations[] = '行为基线正常';
            }
        }

        // ---- 第5层：语义维度一致性检查 ----
        $dimensionConsistency = self::checkDimensionConsistency($semanticResult);
        if ($dimensionConsistency === 'inconsistent') {
            $confidence += 15;
            $reason .= ($reason ? '; ' : '') . '语义维度不一致';
            $recommendations[] = '维度不一致';
        }

        // ---- 第6层：危险特征缺失检查 ----
        $hasDangerousFeatures = self::hasDangerousFeatures($semanticResult);
        if (!$hasDangerousFeatures) {
            $confidence += 20;
            $reason .= ($reason ? '; ' : '') . '无高危特征';
            $recommendations[] = '无高危特征';
        }

        // ---- 第7层：编码归一化检查 ----
        $normalizationCheck = self::checkNormalization($semanticResult);
        if ($normalizationCheck === 'clean') {
            $confidence += 10;
            $recommendations[] = '归一化后干净';
        }

        // ---- 最终判定 ----
        $isFalsePositive = $confidence >= 50;

        // 低分数直接放行
        if ($totalScore < 20) {
            $isFalsePositive = true;
            $confidence = 100;
            $reason = '分数低于阈值';
        }

        // 高置信度误报直接放行
        if ($confidence >= 80) {
            $isFalsePositive = true;
        }

        // 高分数但高置信度误报 => 需要二次确认
        $needsVerification = $totalScore >= 60 && $confidence >= 50 && $confidence < 80;

        return [
            'is_false_positive' => $isFalsePositive,
            'confidence' => $confidence,
            'reason' => $reason ?: ($isFalsePositive ? '综合判定为正常请求' : '综合判定为攻击'),
            'recommendations' => $recommendations,
            'needs_verification' => $needsVerification,
            'trusted_pattern' => $matchedPattern,
            'trusted_param_ratio' => $trustedParamRatio,
            'indicator_quality' => $indicatorQuality,
        ];
    }

    /**
     * 匹配可信业务模式
     */
    private static function matchTrustedPattern(string $uri, string $method, array $params, array $headers): ?string {
        $lowerHeaders = array_change_key_case($headers, CASE_LOWER);

        foreach (self::$trusted_patterns as $key => $pattern) {
            $matched = true;

            if (isset($pattern['uri']) && !preg_match($pattern['uri'], $uri)) {
                $matched = false;
            }
            if (isset($pattern['method']) && strtoupper($method) !== $pattern['method']) {
                $matched = false;
            }
            if (isset($pattern['content_type']) && !isset($lowerHeaders['content-type'])) {
                $matched = false;
            }
            if (isset($pattern['content_type']) && isset($lowerHeaders['content-type']) &&
                !preg_match($pattern['content_type'], $lowerHeaders['content-type'])) {
                $matched = false;
            }
            if (isset($pattern['accept']) && !isset($lowerHeaders['accept'])) {
                $matched = false;
            }
            if (isset($pattern['accept']) && isset($lowerHeaders['accept']) &&
                !preg_match($pattern['accept'], $lowerHeaders['accept'])) {
                $matched = false;
            }
            if (isset($pattern['params'])) {
                $hasAnyParam = false;
                foreach ($pattern['params'] as $p) {
                    if (isset($params[$p])) {
                        $hasAnyParam = true;
                        break;
                    }
                }
                if (!$hasAnyParam) {
                    $matched = false;
                }
            }
            if (isset($pattern['param_keys'])) {
                $hasAllKeys = true;
                foreach ($pattern['param_keys'] as $pk) {
                    if (!isset($params[$pk])) {
                        $hasAllKeys = false;
                        break;
                    }
                }
                if (!$hasAllKeys) {
                    $matched = false;
                }
            }
            if (isset($pattern['headers'])) {
                $hasAnyHeader = false;
                foreach ($pattern['headers'] as $h) {
                    if (isset($lowerHeaders[strtolower($h)])) {
                        $hasAnyHeader = true;
                        break;
                    }
                }
                if (!$hasAnyHeader) {
                    $matched = false;
                }
            }
            if (isset($pattern['safe_pattern']) && !empty($params)) {
                $hasValidValue = false;
                foreach ($params as $v) {
                    if (preg_match($pattern['safe_pattern'], (string)$v)) {
                        $hasValidValue = true;
                        break;
                    }
                }
                if (!$hasValidValue) {
                    $matched = false;
                }
            }

            if ($matched) {
                return $pattern['name'];
            }
        }

        return null;
    }

    /**
     * 检查参数名是否可信
     */
    private static function checkTrustedParams(array $params): float {
        if (empty($params)) return 0.0;
        $trusted = 0;
        foreach (array_keys($params) as $k) {
            if (in_array(strtolower($k), self::$trusted_param_names)) {
                $trusted++;
            }
        }
        return $trusted / count($params);
    }

    /**
     * 检查语义指标质量
     */
    private static function checkIndicatorQuality(array $result): string {
        $indicators = $result['indicators'] ?? [];

        // 只有低权重指标
        $hasHighWeight = false;
        foreach ($indicators as $ind) {
            if (preg_match('/\[L(6|7|8|10)\]/', $ind)) {
                $hasHighWeight = true;
                break;
            }
        }

        if (!$hasHighWeight && count($indicators) <= 2) {
            return 'weak';
        }

        return 'strong';
    }

    /**
     * 检查行为基线
     */
    private static function checkBehaviorBaseline(string $ip, array $semanticResult): array {
        if (!class_exists('SemanticMemoryPool')) {
            return ['is_consistent' => true];
        }

        $profile = SemanticMemoryPool::getProfile($ip);
        if (!$profile['exists']) {
            return ['is_consistent' => true];
        }

        $currentScore = $semanticResult['total_score'] ?? 0;
        $avgScore = $profile['avg_score'] ?? 0;

        if ($avgScore < 10 && $currentScore < 30) {
            return ['is_consistent' => true];
        }

        return ['is_consistent' => false];
    }

    /**
     * 检查维度一致性
     */
    private static function checkDimensionConsistency(array $result): string {
        $lScores = [
            $result['l1_char_score'] ?? 0,
            $result['l2_word_score'] ?? 0,
            $result['l3_structure_score'] ?? 0,
            $result['l4_param_score'] ?? 0,
            $result['l5_business_score'] ?? 0,
            $result['l6_logic_score'] ?? 0,
            $result['l7_intent_score'] ?? 0,
            $result['l8_chain_score'] ?? 0,
        ];

        $highCount = count(array_filter($lScores, fn($s) => $s >= 40));
        $totalScore = $result['total_score'] ?? 0;

        // 总分高但大部分维度低 => 可能是误报
        if ($totalScore >= 40 && $highCount <= 1) {
            return 'inconsistent';
        }

        return 'consistent';
    }

    /**
     * 检查是否有高危特征
     */
    private static function hasDangerousFeatures(array $result): bool {
        $logicType = $result['logic_type'] ?? '';
        $attackPhase = $result['attack_phase'] ?? '';
        $chainDetected = $result['chain_detected'] ?? null;

        $dangerousLogic = ['tautology', 'time_blind', 'error_based', 'boolean_blind'];
        $dangerousPhase = ['attack', 'exploit'];

        if (in_array($logicType, $dangerousLogic)) return true;
        if (in_array($attackPhase, $dangerousPhase)) return true;
        if ($chainDetected !== null) return true;

        return false;
    }

    /**
     * 检查归一化结果
     */
    private static function checkNormalization(array $result): string {
        $adversarialScore = $result['l10_adversarial_score'] ?? 0;
        $encodingDepth = $result['encoding_depth'] ?? 0;

        if ($adversarialScore < 20 && $encodingDepth <= 2) {
            return 'clean';
        }

        return 'suspicious';
    }
}
