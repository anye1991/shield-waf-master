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
        // ========== 增强业务模式（v2 深度增强） ==========
        'wp_heartbeat' => [
            'name' => 'WordPress心跳',
            'conditions' => [
                'uri' => '/\/wp-admin\/admin-ajax\.php/i',
                'method' => 'POST',
                'params' => ['action'],
            ],
        ],
        'graphql_request' => [
            'name' => 'GraphQL请求',
            'conditions' => [
                'uri' => '/\/(?:api\/)?graphql\b/i',
                'method' => 'POST',
                'content_type' => '/application\/json/i',
            ],
        ],
        'api_pagination' => [
            'name' => '分页API',
            'conditions' => [
                'params' => ['page', 'per_page', 'p', 'offset', 'limit', 'pagesize'],
            ],
        ],
        'i18n_param' => [
            'name' => '国际化参数',
            'conditions' => [
                'params' => ['lang', 'language', 'locale'],
            ],
        ],
        'csrf_token_param' => [
            'name' => 'CSRF令牌参数',
            'conditions' => [
                'params' => ['_token', 'csrf_token', '_csrf', '_csrf_token'],
            ],
        ],
        'wp_cron' => [
            'name' => 'WordPress定时任务',
            'conditions' => [
                'uri' => '/\/wp-cron\.php/i',
                'params' => ['doing_wp_cron'],
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
     * 运行时学习的业务模式（持久化到 logs/learned_patterns.json）
     * 结构：['pattern_id' => ['name' => ..., 'conditions' => ..., 'sample_count' => ..., 'false_positive_count' => ...]]
     */
    private static $learnedPatterns = [];

    /**
     * 动态参数名白名单（基于历史行为观察）
     * 结构：['param_name' => ['safe_count' => int, 'block_count' => int, 'confidence' => float]]
     */
    private static $paramWhitelist = [];

    /**
     * 学习模式是否已从磁盘加载（避免同一请求内重复 I/O）
     */
    private static $learnedPatternsLoaded = false;

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

        // 初始化 v2 新增字段（保证返回结构稳定，避免分支未命中时未定义）
        $learnedMatch = null;
        $paramWhitelistHits = [];
        $paramWhitelistHit = false;
        $contextConsistency = ['is_consistent' => true, 'inconsistency_score' => 0, 'reason' => '未检查'];
        $reductionApplied = ['reduced_score' => $totalScore, 'reduction_reason' => '未应用', 'reduction_ratio' => 1.0];

        // ---- 高分保护：攻击评分极高时不轻易判定为误报 ----
        $highScoreProtection = $totalScore >= 80;

        // ---- 第1层：业务模式匹配（权重降低，防止业务页面放行真实攻击） ----
        $matchedPattern = self::matchTrustedPattern($uri, $method, $params, $headers);
        if ($matchedPattern && !$highScoreProtection) {
            $confidence += 10;
            $reason = "匹配可信业务模式: {$matchedPattern}";
            $recommendations[] = '业务模式匹配';
        }

        // ---- 第1.5层：运行时学习业务模式匹配（豁免分 +15） ----
        $learnedMatch = self::matchLearnedPattern($uri, $method, $params, $headers);
        if ($learnedMatch && !$highScoreProtection) {
            $confidence += 15;
            $reason .= ($reason ? '; ' : '') . '匹配学习业务模式: ' . ($learnedMatch['name'] ?? '');
            $recommendations[] = '学习模式匹配';
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

        // ---- 第2.5层：动态参数白名单（基于历史观察，豁免分 +10） ----
        foreach (array_keys($params) as $paramName) {
            if (self::isParamWhitelisted((string)$paramName)) {
                $paramWhitelistHits[] = $paramName;
            }
        }
        $paramWhitelistHit = !empty($paramWhitelistHits);
        if ($paramWhitelistHit && !$highScoreProtection) {
            $confidence += 10;
            $reason .= ($reason ? '; ' : '') . '命中动态参数白名单: ' . implode(',', $paramWhitelistHits);
            $recommendations[] = '动态参数白名单';
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

        // ---- 第7.5层：上下文一致性检查（高分但上下文不匹配 => 可能误报） ----
        $contextConsistency = self::checkContextConsistency($semanticResult, $uri, $method);
        if (!$contextConsistency['is_consistent'] && !$highScoreProtection) {
            $confidence += $contextConsistency['inconsistency_score'];
            $reason .= ($reason ? '; ' : '') . '上下文不一致: ' . $contextConsistency['reason'];
            $recommendations[] = '上下文不一致';
        }

        // ---- 高分保护强制覆盖 ----
        if ($highScoreProtection) {
            // 攻击评分 >=80 时，要求极高置信度才能判定为误报
            $confidence = min($confidence, 40);
            $reason .= ($reason ? '; ' : '') . '高分保护生效，置信度受限';
        }

        // ---- 智能降分策略（基于上下文降分，而非简单豁免） ----
        $reductionContext = [
            'matched_pattern' => $matchedPattern,
            'learned_pattern_match' => $learnedMatch,
            'param_whitelist_match' => $paramWhitelistHit,
            'indicator_quality' => $indicatorQuality,
        ];
        $reductionApplied = self::smartScoreReduction($semanticResult, $reductionContext);
        // 降分比例 <=0.5 时，说明上下文强烈指向误报，额外加置信度
        if ($reductionApplied['reduction_ratio'] <= 0.5 && !$highScoreProtection) {
            $confidence += 10;
            $reason .= ($reason ? '; ' : '') . '智能降分: ' . $reductionApplied['reduction_reason'];
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
            // v2 新增字段
            'learned_pattern_match' => $learnedMatch,
            'param_whitelist_match' => $paramWhitelistHit,
            'context_consistency' => $contextConsistency,
            'reduction_applied' => $reductionApplied,
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

    // ========================================================================
    // v2 深度增强：业务模式自学习 / 动态参数白名单 / 上下文一致性 / 智能降分
    // ========================================================================

    /**
     * 加载运行时学习的业务模式与动态参数白名单
     * 持久化文件：WAF_LOG_PATH . '/learned_patterns.json'
     *
     * @return void
     */
    private static function loadLearnedPatterns(): void {
        if (self::$learnedPatternsLoaded) {
            return;
        }
        self::$learnedPatternsLoaded = true;

        if (!defined('WAF_LOG_PATH')) {
            return;
        }

        $file = WAF_LOG_PATH . '/learned_patterns.json';
        if (!is_file($file)) {
            return;
        }

        $content = @file_get_contents($file);
        if ($content === false || $content === '') {
            return;
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return;
        }

        if (isset($data['learned_patterns']) && is_array($data['learned_patterns'])) {
            self::$learnedPatterns = $data['learned_patterns'];
        }
        if (isset($data['param_whitelist']) && is_array($data['param_whitelist'])) {
            self::$paramWhitelist = $data['param_whitelist'];
        }
    }

    /**
     * 持久化运行时学习的业务模式与动态参数白名单
     *
     * @return void
     */
    private static function saveLearnedPatterns(): void {
        if (!defined('WAF_LOG_PATH')) {
            return;
        }

        $dir = WAF_LOG_PATH;
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }

        $file = $dir . '/learned_patterns.json';
        $data = [
            'learned_patterns' => self::$learnedPatterns,
            'param_whitelist' => self::$paramWhitelist,
            'updated_at' => date('Y-m-d H:i:s'),
        ];

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return;
        }

        @file_put_contents($file, $json, LOCK_EX);
    }

    /**
     * 从请求中提取业务模式特征签名
     * 通过将 URI 中的数字 ID 归一化为 {id}，并收集排序后的参数键，生成稳定的模式 ID
     *
     * @param string $uri 请求URI
     * @param string $method 请求方法
     * @param array $params 参数数组
     * @return array|null 签名信息或 null
     */
    private static function extractPatternSignature(string $uri, string $method, array $params): ?array {
        if ($uri === '') {
            return null;
        }

        // 去除 query string
        $uriPath = preg_replace('/\?.*$/', '', $uri);
        // 将 URI 中的数字 ID 替换为 {id}，提高模式泛化能力
        $uriTemplate = preg_replace('/\/\d+(?=\/|$)/', '/{id}', $uriPath);
        if (empty($uriTemplate)) {
            return null;
        }

        // 提取参数键并排序，保证同一模式签名稳定
        $paramKeys = array_keys($params);
        $paramKeys = array_map('strval', $paramKeys);
        sort($paramKeys);

        // 构造 URI 正则：将 {id} 转为 \d+，其他字符转义
        $regex = '/^' . str_replace('\{id\}', '\d+', preg_quote($uriTemplate, '/')) . '/i';

        $signature = strtoupper($method) . '|' . $uriTemplate . '|' . implode(',', $paramKeys);
        $id = md5($signature);

        return [
            'id' => $id,
            'uri_template' => $uriTemplate,
            'uri_regex' => $regex,
            'param_keys' => $paramKeys,
            'signature' => $signature,
        ];
    }

    /**
     * 业务模式自学习：从正常请求中提取业务模式
     * 当请求被识别为正常（score<30 且非攻击）时，累计该模式样本数
     * 样本数 >=10 后，模式启用；同一模式误报触发 >=3 次后降级（不再使用）
     *
     * @param string $uri 请求URI
     * @param string $method 请求方法
     * @param array $params 参数数组
     * @param array $headers 请求头
     * @param array $baseResult 基础分析结果
     * @return void
     */
    public static function learnPattern(string $uri, string $method, array $params, array $headers, array $baseResult): void {
        $totalScore = $baseResult['total_score'] ?? 0;

        // 仅当请求被识别为正常（score<30 且非攻击）时学习
        if ($totalScore >= 30) {
            return;
        }
        if (self::containsAttackKeyword($baseResult)) {
            return;
        }

        $signature = self::extractPatternSignature($uri, $method, $params);
        if (!$signature) {
            return;
        }

        $patternId = $signature['id'];

        self::loadLearnedPatterns();

        if (!isset(self::$learnedPatterns[$patternId])) {
            self::$learnedPatterns[$patternId] = [
                'name' => '学习模式:' . $signature['uri_template'],
                'conditions' => [
                    'uri' => $signature['uri_regex'],
                    'method' => strtoupper($method),
                    'param_keys' => $signature['param_keys'],
                ],
                'sample_count' => 0,
                'false_positive_count' => 0,
                'created_at' => date('Y-m-d H:i:s'),
                'source' => 'auto',
            ];
        }

        self::$learnedPatterns[$patternId]['sample_count']++;
        self::$learnedPatterns[$patternId]['last_seen'] = date('Y-m-d H:i:s');

        // 同一模式误报触发 >=3 次后降级（不再使用）
        if ((self::$learnedPatterns[$patternId]['false_positive_count'] ?? 0) >= 3) {
            self::$learnedPatterns[$patternId]['degraded'] = true;
        }

        self::saveLearnedPatterns();
    }

    /**
     * 匹配运行时学习的业务模式
     * 匹配成功时豁免分 +15（在 analyze 中体现）
     *
     * @param string $uri 请求URI
     * @param string $method 请求方法
     * @param array $params 参数数组
     * @param array $headers 请求头
     * @return array|null 匹配的模式信息或 null
     */
    private static function matchLearnedPattern(string $uri, string $method, array $params, array $headers): ?array {
        self::loadLearnedPatterns();

        if (empty(self::$learnedPatterns)) {
            return null;
        }

        $upperMethod = strtoupper($method);
        $paramKeys = array_keys($params);

        foreach (self::$learnedPatterns as $patternId => $pattern) {
            // 降级模式不使用
            if (!empty($pattern['degraded'])) {
                continue;
            }
            // 样本数不足（<10）不启用
            if (($pattern['sample_count'] ?? 0) < 10) {
                continue;
            }

            $conditions = $pattern['conditions'] ?? [];

            // 检查方法
            if (isset($conditions['method']) && $upperMethod !== $conditions['method']) {
                continue;
            }

            // 检查 URI
            if (isset($conditions['uri']) && !preg_match($conditions['uri'], $uri)) {
                continue;
            }

            // 检查参数键（至少 80% 匹配）
            if (isset($conditions['param_keys']) && is_array($conditions['param_keys']) && !empty($conditions['param_keys'])) {
                $expectedKeys = $conditions['param_keys'];
                $intersection = array_intersect($expectedKeys, $paramKeys);
                $ratio = count($intersection) / count($expectedKeys);
                if ($ratio < 0.8) {
                    continue;
                }
            }

            return [
                'pattern_id' => $patternId,
                'name' => $pattern['name'] ?? 'learned',
                'sample_count' => $pattern['sample_count'] ?? 0,
                'source' => $pattern['source'] ?? 'auto',
            ];
        }

        return null;
    }

    /**
     * 观察参数历史行为，动态调整参数白名单可信度
     * - safe_count >=20 且 block_count=0 -> confidence=1.0（高可信）
     * - safe_count >=5 且 block_count=0 -> confidence=0.7（中可信）
     *
     * @param string $name 参数名
     * @param bool $wasSafe 该参数历史是否被判定为安全
     * @return void
     */
    public static function observeParam(string $name, bool $wasSafe): void {
        if ($name === '') {
            return;
        }

        $name = strtolower($name);

        self::loadLearnedPatterns();

        if (!isset(self::$paramWhitelist[$name])) {
            self::$paramWhitelist[$name] = [
                'safe_count' => 0,
                'block_count' => 0,
                'confidence' => 0.0,
            ];
        }

        if ($wasSafe) {
            self::$paramWhitelist[$name]['safe_count']++;
        } else {
            self::$paramWhitelist[$name]['block_count']++;
        }

        // 重新计算 confidence
        $safe = self::$paramWhitelist[$name]['safe_count'];
        $block = self::$paramWhitelist[$name]['block_count'];

        if ($safe >= 20 && $block === 0) {
            self::$paramWhitelist[$name]['confidence'] = 1.0;
        } elseif ($safe >= 5 && $block === 0) {
            self::$paramWhitelist[$name]['confidence'] = 0.7;
        } else {
            // 有拦截记录或样本不足，confidence 归零
            self::$paramWhitelist[$name]['confidence'] = 0.0;
        }

        self::$paramWhitelist[$name]['updated_at'] = date('Y-m-d H:i:s');

        self::saveLearnedPatterns();
    }

    /**
     * 检查参数名是否在动态白名单中（confidence >=0.7）
     *
     * @param string $name 参数名
     * @return bool
     */
    private static function isParamWhitelisted(string $name): bool {
        $name = strtolower($name);

        self::loadLearnedPatterns();

        if (!isset(self::$paramWhitelist[$name])) {
            return false;
        }

        return (self::$paramWhitelist[$name]['confidence'] ?? 0.0) >= 0.7;
    }

    /**
     * 上下文一致性检查
     * 检测评分与上下文是否一致，返回不一致评分（0-30）
     * 例如：高分但 URI 是静态资源路径 -> 不一致，建议降分
     * 例如：高分但参数全是已知业务参数 -> 不一致，建议降分
     *
     * @param array $baseResult 基础分析结果
     * @param string $uri 请求URI
     * @param string $method 请求方法
     * @return array{is_consistent:bool, inconsistency_score:int, reason:string}
     */
    private static function checkContextConsistency(array $baseResult, string $uri, string $method): array {
        $totalScore = $baseResult['total_score'] ?? 0;
        $inconsistencyScore = 0;
        $reason = '';

        // 低分请求无需检查一致性
        if ($totalScore < 30) {
            return [
                'is_consistent' => true,
                'inconsistency_score' => 0,
                'reason' => '低分请求，无需一致性检查',
            ];
        }

        // 1. 高分但 URI 是静态资源路径 -> 不一致
        if ($totalScore >= 50 && preg_match('/\.(css|js|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|map|webp|mp4|mp3)(\?|$)/i', $uri)) {
            $inconsistencyScore += 20;
            $reason .= ($reason ? '; ' : '') . '静态资源路径出现高分攻击评分';
        }

        // 2. 高分但仅浅层指标高，无深度解析器命中 -> 不一致
        $parserScores = [
            $baseResult['sql_parser_score'] ?? 0,
            $baseResult['html_parser_score'] ?? 0,
            $baseResult['php_parser_score'] ?? 0,
            $baseResult['path_parser_score'] ?? 0,
            $baseResult['command_parser_score'] ?? 0,
            $baseResult['xxe_parser_score'] ?? 0,
            $baseResult['ssrf_parser_score'] ?? 0,
            $baseResult['ssti_parser_score'] ?? 0,
            $baseResult['deser_parser_score'] ?? 0,
        ];
        $maxParser = !empty($parserScores) ? max($parserScores) : 0;
        $l1 = $baseResult['l1_char_score'] ?? 0;
        $l2 = $baseResult['l2_word_score'] ?? 0;
        $l3 = $baseResult['l3_structure_score'] ?? 0;

        if ($totalScore >= 50 && $maxParser < 20 && ($l1 + $l2 + $l3) >= 60) {
            $inconsistencyScore += 15;
            $reason .= ($reason ? '; ' : '') . '仅浅层指标高，无深度解析器命中';
        }

        // 3. 高分但语义维度不一致 -> 不一致
        $dimensionConsistency = self::checkDimensionConsistency($baseResult);
        if ($totalScore >= 40 && $dimensionConsistency === 'inconsistent') {
            $inconsistencyScore += 15;
            $reason .= ($reason ? '; ' : '') . '语义维度不一致';
        }

        // 4. 极高分但 GET 公开页面 -> 不一致
        if ($totalScore >= 60 && strtoupper($method) === 'GET'
            && preg_match('/^\/(?:index|home|about|contact|products|services)\b/i', $uri)) {
            $inconsistencyScore += 10;
            $reason .= ($reason ? '; ' : '') . '公开页面 GET 请求出现极高分';
        }

        // 5. 极高分但无高危特征 -> 不一致
        if ($totalScore >= 50 && !self::hasDangerousFeatures($baseResult)) {
            $inconsistencyScore += 10;
            $reason .= ($reason ? '; ' : '') . '高分但无高危特征';
        }

        $inconsistencyScore = min(30, $inconsistencyScore);
        $isConsistent = $inconsistencyScore < 10;

        return [
            'is_consistent' => $isConsistent,
            'inconsistency_score' => $inconsistencyScore,
            'reason' => $reason ?: '上下文一致',
        ];
    }

    /**
     * 误报反馈机制
     * 用户/管理员反馈误报：自动学习该请求为业务模式，并持久化
     *
     * @param string $uri 请求URI
     * @param string $method 请求方法
     * @param array $params 参数数组
     * @param string $reason 反馈原因
     * @return void
     */
    public static function reportFalsePositive(string $uri, string $method, array $params, string $reason = ''): void {
        $signature = self::extractPatternSignature($uri, $method, $params);
        if (!$signature) {
            return;
        }

        $patternId = $signature['id'];

        self::loadLearnedPatterns();

        if (!isset(self::$learnedPatterns[$patternId])) {
            self::$learnedPatterns[$patternId] = [
                'name' => '反馈学习:' . $signature['uri_template'],
                'conditions' => [
                    'uri' => $signature['uri_regex'],
                    'method' => strtoupper($method),
                    'param_keys' => $signature['param_keys'],
                ],
                'sample_count' => 0,
                'false_positive_count' => 0,
                'created_at' => date('Y-m-d H:i:s'),
                'source' => 'feedback',
            ];
        }

        // 反馈触发的学习直接达到启用阈值（sample_count >= 10）
        if ((self::$learnedPatterns[$patternId]['sample_count'] ?? 0) < 10) {
            self::$learnedPatterns[$patternId]['sample_count'] = 10;
        }
        self::$learnedPatterns[$patternId]['last_feedback'] = date('Y-m-d H:i:s');
        self::$learnedPatterns[$patternId]['feedback_reason'] = $reason;
        self::$learnedPatterns[$patternId]['degraded'] = false;

        self::saveLearnedPatterns();
    }

    /**
     * 统计强证据解析器命中数（score >= 40）
     *
     * @param array $baseResult 基础分析结果
     * @return int
     */
    private static function countStrongParsers(array $baseResult): int {
        $parserScores = [
            $baseResult['sql_parser_score'] ?? 0,
            $baseResult['html_parser_score'] ?? 0,
            $baseResult['php_parser_score'] ?? 0,
            $baseResult['path_parser_score'] ?? 0,
            $baseResult['command_parser_score'] ?? 0,
            $baseResult['xxe_parser_score'] ?? 0,
            $baseResult['ssrf_parser_score'] ?? 0,
            $baseResult['ssti_parser_score'] ?? 0,
            $baseResult['deser_parser_score'] ?? 0,
            $baseResult['crlf_parser_score'] ?? 0,
            $baseResult['expr_parser_score'] ?? 0,
        ];
        $count = 0;
        foreach ($parserScores as $score) {
            if ($score >= 40) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * 智能降分策略
     * 基于上下文智能降分，而非简单豁免
     * - 高可信业务模式 + 单一弱证据 -> 降 50%（而非完全豁免）
     * - 高可信业务模式 + 多维强证据 -> 降 20%（保留检测）
     * - 中可信业务模式 -> 降 30%
     *
     * @param array $baseResult 基础分析结果
     * @param array $context 上下文信息（matched_pattern / learned_pattern_match / param_whitelist_match / indicator_quality）
     * @return array{reduced_score:int, reduction_reason:string, reduction_ratio:float}
     */
    private static function smartScoreReduction(array $baseResult, array $context): array {
        $totalScore = $baseResult['total_score'] ?? 0;

        // 分数过低无需降分
        if ($totalScore < 20) {
            return [
                'reduced_score' => $totalScore,
                'reduction_reason' => '原始分数已很低，无需降分',
                'reduction_ratio' => 1.0,
            ];
        }

        // 默认不降分
        $reductionRatio = 1.0;
        $reason = '无可应用降分策略';

        $matchedPattern = $context['matched_pattern'] ?? null;
        $learnedMatch = $context['learned_pattern_match'] ?? null;
        $paramWhitelistHit = $context['param_whitelist_match'] ?? false;
        $indicatorQuality = $context['indicator_quality'] ?? 'strong';

        // 统计业务模式命中数
        $businessSignalCount = 0;
        if ($matchedPattern !== null) $businessSignalCount++;
        if ($learnedMatch !== null) $businessSignalCount++;
        if ($paramWhitelistHit) $businessSignalCount++;

        // 判断证据强度
        $hasStrongEvidence = self::hasDangerousFeatures($baseResult) || $totalScore >= 60;
        $hasMultipleStrongEvidence = !empty($baseResult['chain_detected'])
            || $totalScore >= 80
            || self::countStrongParsers($baseResult) >= 2;

        // 高可信业务模式：至少 2 个业务信号
        $highConfidence = $businessSignalCount >= 2;
        // 中可信业务模式：至少 1 个业务信号
        $mediumConfidence = $businessSignalCount >= 1;

        if ($highConfidence) {
            if ($hasMultipleStrongEvidence) {
                // 高可信 + 多维强证据 -> 降 20%
                $reductionRatio = 0.8;
                $reason = '高可信业务模式+多维强证据，降20%';
            } elseif ($hasStrongEvidence) {
                // 高可信 + 单一证据 -> 降 50%
                $reductionRatio = 0.5;
                $reason = '高可信业务模式+单一证据，降50%';
            } else {
                // 高可信 + 无强证据 -> 降 70%
                $reductionRatio = 0.3;
                $reason = '高可信业务模式+无强证据，降70%';
            }
        } elseif ($mediumConfidence) {
            if ($hasMultipleStrongEvidence) {
                // 中可信 + 多维强证据 -> 降 10%
                $reductionRatio = 0.9;
                $reason = '中可信业务模式+多维强证据，降10%';
            } else {
                // 中可信 -> 降 30%
                $reductionRatio = 0.7;
                $reason = '中可信业务模式，降30%';
            }
        }

        // 弱指标额外降分（无业务模式命中时也可应用）
        if ($businessSignalCount === 0 && $indicatorQuality === 'weak' && !$hasStrongEvidence) {
            $reductionRatio = min($reductionRatio, 0.7);
            if ($reason === '无可应用降分策略') {
                $reason = '弱指标+无强证据，降30%';
            }
        }

        $reducedScore = (int)round($totalScore * $reductionRatio);

        return [
            'reduced_score' => $reducedScore,
            'reduction_reason' => $reason,
            'reduction_ratio' => $reductionRatio,
        ];
    }
}
