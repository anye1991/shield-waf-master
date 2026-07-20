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
        // ========== WordPress 特有业务模式 ==========
        'wp_post_edit' => [
            'name' => 'WordPress文章编辑',
            'conditions' => [
                'uri' => '/wp-admin\/(?:post|post-new|page|page-new)\.php/i',
                'method' => 'POST',
                'params' => ['post_title', 'post_content', 'post_excerpt', 'content'],
            ],
        ],
        'wp_comment' => [
            'name' => 'WordPress评论提交',
            'conditions' => [
                'uri' => '/wp-comments-post\.php/i',
                'method' => 'POST',
                'params' => ['comment', 'author', 'email', 'url'],
            ],
        ],
        'wp_theme_customize' => [
            'name' => 'WordPress主题自定义',
            'conditions' => [
                'uri' => '/wp-admin\/customize\.php/i',
                'method' => 'POST',
                'params' => ['customized', 'wp_customize'],
            ],
        ],
        'wp_ajax' => [
            'name' => 'WordPress AJAX请求',
            'conditions' => [
                'uri' => '/(?:admin-ajax|wp-json)\b/i',
                'method' => 'POST',
                'params' => ['action', '_ajax_nonce', 'nonce'],
            ],
        ],
        'wp_rest_api' => [
            'name' => 'WordPress REST API',
            'conditions' => [
                'uri' => '/wp-json\/wp\/v\d+/i',
                'headers' => ['X-WP-Nonce'],
            ],
        ],
        'wp_media_upload' => [
            'name' => 'WordPress媒体上传',
            'conditions' => [
                'uri' => '/wp-admin\/(?:async-upload|media-new|upload)\.php/i',
                'method' => 'POST',
                'content_type' => '/multipart\/form-data/i',
            ],
        ],
        'wp_plugin_settings' => [
            'name' => 'WordPress插件设置',
            'conditions' => [
                'uri' => '/wp-admin\/(?:options|settings|plugins|themes)\.php/i',
                'method' => 'POST',
            ],
        ],
    ];

    /**
     * 可信参数名白名单（这些参数的值可以包含特殊字符）
     */
    private static $trusted_param_names = [
        // 通用参数
        'q', 'query', 'keyword', 'search', 's',
        'url', 'link', 'redirect', 'next', 'return_url', 'callback',
        'content', 'body', 'message', 'text', 'description', 'comment',
        'code', 'gist', 'snippet', 'paste', 'script',
        'data', 'json', 'xml', 'payload',
        'file', 'file_name', 'upload',
        'username', 'email', 'password', 'captcha', 'token',
        'title', 'name', 'tags', 'category',
        'filters', 'options', 'settings', 'config',
        // ========== WordPress 特有参数 ==========
        'post_title', 'post_content', 'post_excerpt', 'post_status',
        'post_author', 'post_date', 'post_category', 'post_tags',
        'comment', 'comment_content', 'comment_author', 'comment_author_email',
        'customized', 'wp_customize', 'customize_changeset_uuid',
        'action', '_ajax_nonce', 'nonce', '_wpnonce',
        'meta', 'meta_value', 'meta_key',
        'attachment', 'attachments', 'file_upload',
        'widget', 'sidebar', 'menu', 'nav_menu',
        'theme', 'stylesheet', 'template',
        'plugin', 'plugins', 'activate', 'deactivate',
        'option', 'option_value', 'option_name',
        'user_login', 'user_email', 'user_pass', 'display_name',
        'role', 'capabilities', 'all_roles',
        'taxonomy', 'term', 'term_id', 'parent',
        'ping_status', 'comment_status', 'post_password',
        'post_name', 'post_parent', 'menu_order',
        'page_template', 'page_options',
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

        // ---- 高分保护：攻击评分极高时不轻易判定为误报 ----
        $highScoreProtection = $totalScore >= 80;

        // ---- 第1层：业务模式匹配（权重降低，防止业务页面放行真实攻击） ----
        $matchedPattern = self::matchTrustedPattern($uri, $method, $params, $headers);
        if ($matchedPattern && !$highScoreProtection) {
            $confidence += 10;
            $reason = "匹配可信业务模式: {$matchedPattern}";
            $recommendations[] = '业务模式匹配';
        }

        // ---- 第2层：参数名白名单（权重降低） ----
        $trustedParamRatio = self::checkTrustedParams($params);
        if ($trustedParamRatio >= 0.8 && !$highScoreProtection) {
            $confidence += 10;
            $reason .= ($reason ? '; ' : '') . '参数名全为可信';
            $recommendations[] = '参数名白名单';
        } elseif ($trustedParamRatio >= 0.5) {
            $confidence += 5;
            $recommendations[] = '部分参数可信';
        }

        // ---- 第3层：语义指标质量检查 ----
        $indicatorQuality = self::checkIndicatorQuality($semanticResult);
        if ($indicatorQuality === 'weak') {
            $confidence += 15;
            $reason .= ($reason ? '; ' : '') . '语义指标质量弱';
            $recommendations[] = '弱指标';
        }

        // ---- 第4层：行为基线检查 ----
        if (!empty($ip)) {
            $baselineCheck = self::checkBehaviorBaseline($ip, $semanticResult);
            if ($baselineCheck['is_consistent']) {
                $confidence += $baselineCheck['confidence_add'] ?? 15;
                $reason .= ($reason ? '; ' : '') . '符合行为基线';
                $recommendations[] = '行为基线正常';
            }
        }

        // ---- 第5层：语义维度一致性检查（含L1-L10及11个深度解析器） ----
        $dimensionConsistency = self::checkDimensionConsistency($semanticResult);
        if ($dimensionConsistency === 'inconsistent') {
            $confidence += 10;
            $reason .= ($reason ? '; ' : '') . '语义维度不一致';
            $recommendations[] = '维度不一致';
        }

        // ---- 第6层：危险特征缺失检查 ----
        $hasDangerousFeatures = self::hasDangerousFeatures($semanticResult);
        if (!$hasDangerousFeatures) {
            $confidence += 15;
            $reason .= ($reason ? '; ' : '') . '无高危特征';
            $recommendations[] = '无高危特征';
        }

        // ---- 第7层：编码归一化检查 ----
        $normalizationCheck = self::checkNormalization($semanticResult);
        if ($normalizationCheck === 'clean') {
            $confidence += 10;
            $recommendations[] = '归一化后干净';
        }

        // ---- 高分保护强制覆盖 ----
        if ($highScoreProtection) {
            // 攻击评分 >=80 时，要求极高置信度才能判定为误报
            $confidence = min($confidence, 40);
            $reason .= ($reason ? '; ' : '') . '高分保护生效，置信度受限';
        }

        // ---- 最终判定 ----
        $isFalsePositive = $confidence >= 60;

        // 极低分数直接放行（明确不是攻击）
        // 注：必须排除含明确攻击关键字的短载荷，否则 system(ls)/eval() 等短攻击会被误判为正常请求
        if ($totalScore < 10 && !self::containsAttackKeyword($semanticResult)) {
            $isFalsePositive = true;
            $confidence = 100;
            $reason = '分数极低，明确为正常请求';
        }

        // 高置信度误报直接放行（但高分保护时不放行）
        if ($confidence >= 85 && !$highScoreProtection) {
            $isFalsePositive = true;
        }

        // 需要二次确认：中高分数 + 中等置信度 => 不放行，要求多引擎交叉验证
        $needsVerification = $totalScore >= 50 && $confidence >= 40 && $confidence < 70;

        return [
            'is_false_positive' => $isFalsePositive,
            'confidence' => $confidence,
            'reason' => $reason ?: ($isFalsePositive ? '综合判定为正常请求' : '综合判定为攻击'),
            'recommendations' => $recommendations,
            'needs_verification' => $needsVerification,
            'trusted_pattern' => $matchedPattern,
            'trusted_param_ratio' => $trustedParamRatio,
            'indicator_quality' => $indicatorQuality,
            'high_score_protection' => $highScoreProtection,
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
            return ['is_consistent' => false, 'confidence_add' => 0];
        }

        $profile = SemanticMemoryPool::getProfile($ip);
        if (!$profile['exists']) {
            return ['is_consistent' => false, 'confidence_add' => 0];
        }

        $currentScore = $semanticResult['total_score'] ?? 0;
        $avgScore = $profile['avg_score'] ?? 0;

        if ($avgScore < 10 && $currentScore < 30) {
            return ['is_consistent' => true, 'confidence_add' => 15];
        }

        return ['is_consistent' => false, 'confidence_add' => 0];
    }

    /**
     * 检查维度一致性（含L1-L10及11个深度解析器）
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
            $result['l9_memory_score'] ?? 0,
            $result['l10_adversarial_score'] ?? 0,
            // 11个深度解析器
            $result['sql_parser_score'] ?? 0,
            $result['html_parser_score'] ?? 0,
            $result['php_parser_score'] ?? 0,
            $result['path_parser_score'] ?? 0,
            $result['command_parser_score'] ?? 0,
            $result['xxe_parser_score'] ?? 0,
            $result['ssrf_parser_score'] ?? 0,
            $result['ssti_parser_score'] ?? 0,
            $result['deser_parser_score'] ?? 0,
            $result['crlf_parser_score'] ?? 0,
            $result['expr_parser_score'] ?? 0,
        ];

        $highCount = count(array_filter($lScores, function($s) { return $s >= 40; }));
        $totalScore = $result['total_score'] ?? 0;

        // 总分高但大部分维度低 => 可能是误报
        if ($totalScore >= 40 && $highCount <= 1) {
            return 'inconsistent';
        }

        return 'consistent';
    }

    /**
     * 检查语义结果是否包含明确攻击证据（短载荷攻击防护）
     * 即使语义总分极低，只要任一深度解析器检测到明确攻击特征，就不应被判定为误报
     * 使用解析器的布尔标志位而非文本匹配，避免误判
     */
    private static function containsAttackKeyword(array $result): bool {
        // 1. PHP 代码执行攻击
        $phpParser = $result['php_parser_result'] ?? [];
        if (is_array($phpParser)) {
            if (!empty($phpParser['has_eval'])) return true;
            if (!empty($phpParser['has_command_exec'])) return true;
            if (!empty($phpParser['has_superglobal_danger'])) return true;
            if (!empty($phpParser['dangerous_functions']) && is_array($phpParser['dangerous_functions'])) return true;
        }

        // 2. SQL 注入
        $sqlParser = $result['sql_parser_result'] ?? [];
        if (is_array($sqlParser)) {
            if (!empty($sqlParser['has_tautology'])) return true;
            if (!empty($sqlParser['has_union'])) return true;
            if (!empty($sqlParser['dangerous_functions']) && is_array($sqlParser['dangerous_functions'])) return true;
            if (!empty($sqlParser['sensitive_tables']) && is_array($sqlParser['sensitive_tables'])) return true;
        }

        // 3. XSS 攻击
        $htmlParser = $result['html_parser_result'] ?? [];
        if (is_array($htmlParser)) {
            if (!empty($htmlParser['has_script'])) return true;
            if (!empty($htmlParser['has_event_handler'])) return true;
            if (!empty($htmlParser['has_javascript_protocol'])) return true;
            if (!empty($htmlParser['has_svg_payload'])) return true;
        }

        // 4. 路径遍历
        $pathParser = $result['path_parser_result'] ?? [];
        if (is_array($pathParser)) {
            if (!empty($pathParser['is_path_traversal'])) return true;
        }

        // 5. 文件包含
        if (!empty($result['l1_char_score']) && $result['l1_char_score'] >= 30) {
            // 文件包含协议可能由 l1 字符层检测
            $indicators = $result['indicators'] ?? [];
            foreach ($indicators as $ind) {
                if (!is_string($ind)) continue;
                $lower = strtolower($ind);
                if (strpos($lower, 'php://') !== false) return true;
                if (strpos($lower, 'data://') !== false) return true;
                if (strpos($lower, 'file://') !== false) return true;
            }
        }

        // 6. XXE 实体注入
        $xxeParser = $result['xxe_parser_result'] ?? [];
        if (is_array($xxeParser) && !empty($xxeParser['has_xxe'])) return true;

        return false;
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
        if ($chainDetected === true) return true;

        // 深度解析器命中视为高危特征
        $parserScores = [
            $result['sql_parser_score'] ?? 0,
            $result['html_parser_score'] ?? 0,
            $result['php_parser_score'] ?? 0,
            $result['path_parser_score'] ?? 0,
            $result['command_parser_score'] ?? 0,
            $result['xxe_parser_score'] ?? 0,
            $result['ssrf_parser_score'] ?? 0,
            $result['ssti_parser_score'] ?? 0,
            $result['deser_parser_score'] ?? 0,
            $result['crlf_parser_score'] ?? 0,
            $result['expr_parser_score'] ?? 0,
        ];
        foreach ($parserScores as $ps) {
            if ($ps >= 40) return true;
        }

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
