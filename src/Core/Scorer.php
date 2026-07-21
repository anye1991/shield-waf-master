<?php
/**
 * 盾甲 WAF 智能评分系统 (Scorer.php) - 极致优化版
 *
 * 四维基础评分 + 编码绕过专项加成：
 *   - 熵值分析 (Entropy, 权重 15%): 信息熵与特殊字符比例
 *   - 语义分析 (Semantic, 权重 40%): 10维语义 + 11大深度解析器
 *   - 编译偏差分析 (Compiler, 权重 20%): URI/参数结构异常
 *   - 偏离分析 (Deviation, 权重 15%): 与历史正常请求对比
 *   - 编码绕过加成 (+0~40分): 14层解码深度 + 混淆技术 + 对抗样本特征
 *
 * 评分阈值：
 *   0-30   → 通过
 *   30-50  → 记录日志
 *   50-70  → 观察
 *   70+    → 拦截
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/../Semantic/SemanticEngine.php';
require_once __DIR__ . '/../Learn/AutoLearn.php';
require_once __DIR__ . '/../Semantic/FalsePositiveGuard.php';
require_once __DIR__ . '/../Semantic/SemanticMemoryPool.php';

class WafScorer {
    private static $weights = [
        'entropy'   => 0.10,  // 降低：熵值容易误判正常内容（Base64图片、加密字符串）
        'semantic'  => 0.45,  // 提高：语义分析是核心检测能力，类似雷池智能语义引擎
        'compiler'  => 0.20,  // 保持：URI/参数结构异常检测
        'deviation' => 0.15,  // 保持：行为基线偏离分析
    ];

    // 阈值层级必须严格递增，否则中间层（如 observe）会被 block 短路而失效
    // 0-30 pass / 30-50 log / 50-75 observe / 75+ block
    // 注：block 从 70 提升到 75，减少边缘误报（WordPress 富文本/代码场景）
    private static $thresholds = [
        'pass'    => 30,
        'log'     => 30,
        'observe' => 50,
        'block'   => 75,
    ];

    /**
     * 对请求进行四维评分
     * @param string $payload 归一化后的请求载荷
     * @param string $uri     请求URI
     * @param array  $params  请求参数键值对
     * @param array $normalizerContext 归一化引擎返回的上下文数据
     * @param string $ip      请求IP地址（用于攻击链关联）
     * @return array 评分结果
     */
    public static function score($payload, $uri = '', $params = [], $normalizerContext = [], $ip = '', $body = '', $contentType = '') {
        $entropyScore   = self::calcEntropy($payload);
        $semanticResult  = self::calcSemantic($payload, $uri, $params, $normalizerContext, $ip, $body, $contentType);
        $semanticScore   = $semanticResult['total_score'] ?? 0;
        $compilerScore   = self::calcCompiler($payload, $uri, $params);
        $deviationScore  = self::calcDeviation($uri, $params, $normalizerContext);

        $totalScore = $entropyScore * self::$weights['entropy']
                    + $semanticScore * self::$weights['semantic']
                    + $compilerScore * self::$weights['compiler']
                    + $deviationScore * self::$weights['deviation'];

        $encodeBypassBonus = self::calcEncodeBypassBonus($semanticResult, $normalizerContext);
        $totalScore += $encodeBypassBonus;

        $totalScore = min(round($totalScore, 1), 100);

        // ====== 误报控制：FalsePositiveGuard 7层防御 ======
        $fpResult = FalsePositiveGuard::analyze(
            $uri,
            $_SERVER['REQUEST_METHOD'] ?? 'GET',
            $params,
            function_exists('getallheaders') ? (getallheaders() ?: []) : [],
            $semanticResult,
            $ip
        );

        $fpAdjustment = 0;
        if ($fpResult['is_false_positive']) {
            if ($fpResult['confidence'] >= 90) {
                $fpAdjustment = -30; // 极高置信度误报，大幅降分
            } elseif ($fpResult['confidence'] >= 75) {
                $fpAdjustment = -15; // 高置信度误报，中幅降分
            } else {
                $fpAdjustment = -5; // 低置信度误报，小幅降分
            }
            $totalScore = max(0, $totalScore + $fpAdjustment);
        }

        // 需要二次验证的（高分但疑似误报），降低一个级别
        if (!empty($fpResult['needs_verification'])) {
            $totalScore = max(0, $totalScore - 10);
        }

        // ====== 明确攻击证据强化加成（在 FP 调整之后应用） ======
        // 当深度解析器检测到明确的攻击布尔标志位（has_eval / has_command_exec /
        // has_script / has_union / is_path_traversal 等）时，给予总分级保底，
        // 防止 system(ls) / eval(...) / <script>... 等短载荷攻击因 FP 调整漏检。
        // 注：此加成只触发于解析器明确的攻击特征（非启发式评分），误报风险极低。
        $clearAttackEvidenceBonus = self::calcClearAttackEvidenceBonus($semanticResult);
        if ($clearAttackEvidenceBonus > 0) {
            $totalScore = max($totalScore, $clearAttackEvidenceBonus);
        }

        $action = self::decideAction($totalScore);

        // ====== 自动学习：记录请求到记忆池，建立行为基线 ======
        if (!empty($ip)) {
            $memFeatures = array_merge($semanticResult, [
                'risk_level' => self::getRiskLevel($totalScore),
            ]);
            SemanticMemoryPool::record($ip, $payload, $uri, $params, $memFeatures);
            
            // 行为基线偏离分析（有基线才加分，无基线不加分）
            $evolutionResult = SemanticMemoryPool::analyzeEvolution($ip, $memFeatures);
            if (!empty($evolutionResult['baseline_exists']) && $evolutionResult['score'] > 0) {
                $behaviorBonus = min(25, $evolutionResult['score'] * 0.3);
                $totalScore += $behaviorBonus;
                $action = self::decideAction($totalScore);
            }
        }

        // ====== 自动学习：记录正常请求 / 攻击载荷 ======
        if ($totalScore < 20) {
            AutoLearn::recordNormal($uri, array_keys($params));
        } elseif ($totalScore >= 50) {
            $attackResult = [
                'risk_level' => self::getRiskLevel($totalScore),
                'attack_type_scores' => self::extractAttackTypeScores($semanticResult),
            ];
            AutoLearn::recordAttack($semanticResult['decoded_text'] ?? $payload, $attackResult);
        }

        return [
            'total_score'     => $totalScore,
            'entropy_score'   => $entropyScore,
            'semantic_score'  => $semanticScore,
            'compiler_score'  => $compilerScore,
            'deviation_score' => $deviationScore,
            'encode_bypass_bonus' => $encodeBypassBonus,
            'action'          => $action,
            'risk_level'      => self::getRiskLevel($totalScore),
            'is_attack'       => $totalScore >= self::$thresholds['block'],
            'semantic_detail' => $semanticResult,
            'fp_guard'        => $fpResult,
            'fp_adjustment'   => $fpAdjustment,
            'memory_pool'     => $evolutionResult ?? null,
            'learned'        => [
                'behavior_baseline_exists' => !empty($evolutionResult['baseline_exists']),
                'evolution_score' => $evolutionResult['score'] ?? 0,
            ],
            'components'      => [
                'entropy'   => ['score' => $entropyScore, 'weight' => self::$weights['entropy']],
                'semantic'  => ['score' => $semanticScore, 'weight' => self::$weights['semantic']],
                'compiler'  => ['score' => $compilerScore, 'weight' => self::$weights['compiler']],
                'deviation' => ['score' => $deviationScore, 'weight' => self::$weights['deviation']],
                'encode_bypass' => ['bonus' => $encodeBypassBonus],
            ],
        ];
    }

    // ====================== 熵值分析 (15%) ======================

    /**
     * 计算信息熵分数
     * 高熵值通常表示编码或混淆内容
     */
    private static function calcEntropy($text) {
        if (empty($text)) return 0;

        $len = strlen($text);
        if ($len <= 1) return 0;

        // 计算字符频率
        $freq = [];
        for ($i = 0; $i < $len; $i++) {
            $char = $text[$i];
            $freq[$char] = ($freq[$char] ?? 0) + 1;
        }

        // Shannon 熵
        $entropy = 0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        // 归一化到 0-100（最大熵为8 bits/char）
        $normalizedEntropy = min($entropy / 8 * 100, 100);

        // 特殊字符比例
        $specialRatio = 0;
        $specialChars = '<>"\'%;|&`$(){}\\/*%#=*?!';
        for ($i = 0; $i < $len; $i++) {
            if (strpos($specialChars, $text[$i]) !== false) $specialRatio++;
        }
        $specialRatio = ($specialRatio / $len) * 100;

        // 综合分数
        $score = $normalizedEntropy * 0.5 + $specialRatio * 1.5;
        return min(round($score, 1), 100);
    }

    // ====================== 语义分析 (30%) ======================

    /**
     * 调用语义引擎分析
     */
    private static function calcSemantic($text, $uri, $params, $normalizerContext = [], $ip = '', $body = '', $contentType = '') {
        $multiVectorData = [
            'raw_text'         => $text,
            'uri_path'         => parse_url($uri, PHP_URL_PATH) ?: $uri,
            'query_count'      => count($_GET),
            'post_count'       => count($_POST),
            'header_anomalies' => 0,
            'cookie_count'     => count($_COOKIE),
            'uri'              => $uri,
            'get'              => $_GET,
            'post'             => $_POST,
            'headers'          => self::extractHeaders(),
            'ua'               => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'referer'          => $_SERVER['HTTP_REFERER'] ?? '',
            'cookie'           => !empty($_COOKIE) ? http_build_query($_COOKIE) : '',
            'raw_body'         => defined('WAF_RAW_BODY') ? WAF_RAW_BODY : '',
        ];

        $result = SemanticEngine::analyze($text, $uri, $params, $normalizerContext, $ip, $multiVectorData, self::extractHeaders(), $_SERVER['REQUEST_METHOD'] ?? 'GET', $body, $contentType);
        return $result;
    }

    /**
     * 从 $_SERVER 中提取 HTTP 头
     */
    private static function extractHeaders(): array {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerName = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                $headers[$headerName] = $value;
            }
        }
        return $headers;
    }

    // ====================== 编译偏差分析 (25%) ======================

    /**
     * 内置结构分析（原 CompilerEngine 整合）
     * 通过 URI 路径、参数键值对的结构特征评分。
     */
    private static function calcCompiler($text, $uri, $params) {
        $score = 0;

        // 1. URI 异常结构
        $uri = (string)$uri;
        if (strlen($uri) > 200)                       $score += 15;
        if (substr_count($uri, '/') > 8)              $score += 10;
        if (preg_match('/\.\.\//', $uri))             $score += 20;
        if (preg_match('/\.(php|asp|jsp|cgi|env|sql)$/i', $uri)) $score += 10;
        if (preg_match('/(?:union|select|concat|script|onerror|javascript:)/i', $uri)) $score += 25;

        // 2. 参数键名异常
        $suspiciousKeys = ['cmd', 'exec', 'command', 'shell', 'eval', 'code', 'file', 'path', 'url', 'redirect', 'return', 'jump', 'include', 'require'];
        foreach ($params as $k => $v) {
            $lk = strtolower((string)$k);
            foreach ($suspiciousKeys as $s) {
                if (strpos($lk, $s) !== false) { $score += 8; break; }
            }
        }

        // 3. 参数值结构异常
        $val = is_array($params) ? implode(' ', array_map('strval', $params)) : (string)$params;
        $len = strlen($val);
        if ($len > 0) {
            $upperRatio = strlen(preg_replace('/[^A-Z]/', '', $val)) / max($len, 1);
            $digitRatio = strlen(preg_replace('/[^0-9]/', '', $val)) / max($len, 1);
            $symRatio   = strlen(preg_replace('/[a-zA-Z0-9\s]/', '', $val)) / max($len, 1);
            if ($upperRatio > 0.5 && $digitRatio > 0.3) $score += 15;
            if ($symRatio > 0.4)                          $score += 15;
        }

        return min(round($score, 1), 100);
    }

    // ====================== 偏离分析 (30%) ======================

    /**
     * 与历史正常请求对比，检测异常偏离
     */
    private static function calcDeviation($uri, $params, $normalizerContext) {
        $score = 0;

        // 从 AutoLearn 获取偏离分数
        $paramKeys = array_keys($params);
        $deviation = AutoLearn::getDeviationScore($uri, $paramKeys);
        $score += $deviation * 60;

        // 编码复杂度偏离
        $encodingComplexity = $normalizerContext['encoding_complexity'] ?? 0;
        if ($encodingComplexity > 50) {
            $score += 25;
        } elseif ($encodingComplexity > 30) {
            $score += 15;
        } elseif ($encodingComplexity > 10) {
            $score += 5;
        }

        // 编码深度偏离
        $encodingDepth = $normalizerContext['encoding_depth'] ?? 0;
        if ($encodingDepth >= 4) {
            $score += 20;
        } elseif ($encodingDepth >= 2) {
            $score += 10;
        }

        // 双重编码偏离
        if (!empty($normalizerContext['double_encoding_detected'])) {
            $score += 15;
        }

        return min(round($score, 1), 100);
    }

    /**
     * 从语义结果中提取攻击类型分数（用于学习系统记录）
     */
    private static function extractAttackTypeScores(array $semanticResult): array {
        $scores = [];
        $logicType = $semanticResult['logic_type'] ?? '';
        if ($logicType) {
            $scores[$logicType] = $semanticResult['total_score'] ?? 50;
        }
        if (!empty($semanticResult['parser_results'])) {
            foreach ($semanticResult['parser_results'] as $type => $result) {
                if (is_array($result) && isset($result['score'])) {
                    $scores[$type] = $result['score'];
                }
            }
        }
        return $scores;
    }

    // ====================== 明确攻击证据强化加成 ======================

    /**
     * 当深度解析器检测到明确的攻击布尔标志位时，给予总分级保底。
     * 此加成只触发于解析器明确的攻击特征（非启发式评分），误报风险极低。
     * 保底值低于 block(70)，但能将短载荷攻击推到 observe(50) 级别，
     * 配合其他加成可触发 block。
     */
    private static function calcClearAttackEvidenceBonus(array $semanticResult): float {
        $bonus = 0;

        // PHP 代码执行（最高危）
        $phpParser = $semanticResult['php_parser_result'] ?? [];
        if (is_array($phpParser)) {
            if (!empty($phpParser['has_command_exec'])) $bonus = max($bonus, 75); // system/exec/shell_exec
            if (!empty($phpParser['has_eval']))         $bonus = max($bonus, 72); // eval()
            if (!empty($phpParser['has_superglobal_danger'])) $bonus = max($bonus, 55);
        }

        // SQL 注入
        $sqlParser = $semanticResult['sql_parser_result'] ?? [];
        if (is_array($sqlParser)) {
            if (!empty($sqlParser['has_tautology'])) $bonus = max($bonus, 72); // OR 1=1
            if (!empty($sqlParser['has_union']))     $bonus = max($bonus, 72); // UNION SELECT
        }

        // XSS 攻击
        $htmlParser = $semanticResult['html_parser_result'] ?? [];
        if (is_array($htmlParser)) {
            if (!empty($htmlParser['has_script']))              $bonus = max($bonus, 72);
            if (!empty($htmlParser['has_javascript_protocol'])) $bonus = max($bonus, 65);
            if (!empty($htmlParser['has_event_handler']))       $bonus = max($bonus, 55);
        }

        // 路径遍历
        $pathParser = $semanticResult['path_parser_result'] ?? [];
        if (is_array($pathParser) && !empty($pathParser['is_path_traversal'])) {
            $bonus = max($bonus, 72);
        }

        // XXE 实体注入
        $xxeParser = $semanticResult['xxe_parser_result'] ?? [];
        if (is_array($xxeParser) && !empty($xxeParser['has_xxe'])) {
            $bonus = max($bonus, 72);
        }

        return (float)$bonus;
    }

    // ====================== 编码绕过专项加成 (+0~40分) ======================

    /**
     * 编码绕过专项加成：14层解码深度 + 混淆技术 + 对抗样本特征
     * 核心思想：刻意编码绕过WAF的攻击，其危害等级远高于明文攻击
     */
    private static function calcEncodeBypassBonus(array $semanticResult, array $normalizerContext): float {
        $bonus = 0;

        $decodeDepth = $semanticResult['decode_depth'] ?? 0;
        $decodePath = $semanticResult['decode_path'] ?? [];
        $adversarialScore = $semanticResult['l10_adversarial_score'] ?? 0;
        $encodeBypassScore = $semanticResult['encode_bypass_score'] ?? 0;
        $semanticScore = $semanticResult['total_score'] ?? 0;

        if ($decodeDepth <= 0 || $semanticScore < 20) {
            return 0;
        }

        // 1. 解码深度加成（层数越深，绕过意图越强）
        if ($decodeDepth >= 4) $bonus += 12;
        elseif ($decodeDepth >= 3) $bonus += 8;
        elseif ($decodeDepth >= 2) $bonus += 5;
        elseif ($decodeDepth >= 1) $bonus += 2;

        // 2. 高级混淆技术加成（每种技术 +3~10分）
        $highValueTechs = [
            'base64' => 10,
            'utf8_overlong' => 9,
            'unicode_percent_u' => 7,
            'homoglyph_normalize' => 7,
            'zero_width_remove' => 6,
            'fullwidth_normalize' => 5,
            'html_numeric_entity' => 4,
            'html_named_entity' => 4,
            'hex_escape' => 5,
            'octal_escape' => 5,
            'unicode_escape' => 5,
        ];
        foreach ($highValueTechs as $tech => $points) {
            if (in_array($tech, $decodePath)) {
                $bonus += $points;
            }
        }

        // 3. 对抗样本评分加成
        if ($adversarialScore >= 70) $bonus += 8;
        elseif ($adversarialScore >= 50) $bonus += 5;
        elseif ($adversarialScore >= 30) $bonus += 3;

        // 4. 语义引擎编码绕过评分加成
        if ($encodeBypassScore >= 20) $bonus += 6;
        elseif ($encodeBypassScore >= 10) $bonus += 3;

        // 5. 组合加成：高语义分 + 编码 = 强证据（刻意隐藏的攻击）
        if ($semanticScore >= 60 && $decodeDepth >= 2) $bonus += 8;
        elseif ($semanticScore >= 40 && $decodeDepth >= 1) $bonus += 4;

        // 6. 多混淆技术交叉加成（同时使用2种以上混淆技术）
        $obfuscationTechs = array_intersect(array_keys($highValueTechs), $decodePath);
        if (count($obfuscationTechs) >= 3) $bonus += 6;
        elseif (count($obfuscationTechs) >= 2) $bonus += 3;

        return min(50, round($bonus, 1));
    }

    // ====================== 决策 ======================

    private static function decideAction($score) {
        if ($score >= self::$thresholds['block']) return 'block';
        if ($score >= self::$thresholds['observe']) return 'observe';
        if ($score >= self::$thresholds['log']) return 'log';
        return 'pass';
    }

    public static function getRiskLevel($score) {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 20) return 'low';
        return 'clean';
    }

    /**
     * 获取阈值配置
     */
    public static function getThresholds() {
        return self::$thresholds;
    }

    /**
     * 设置阈值（可从 config 覆盖）
     */
    public static function setThresholds($thresholds) {
        self::$thresholds = array_merge(self::$thresholds, $thresholds);
    }
}
