<?php
/**
 * 语义分析总引擎（终极版本 - 全球顶级深度语义解析）
 * 职责：整合10维语义分析 + 3大深度解析器 + 误报控制 + 路径预判 + 主动防御，
 *       实现"预判路径围追堵截"的革命性安全战略。
 *
 * 核心架构：
 *   L1-L10: 10维语义分析（基础特征层）
 *   SQL/HTML/PHP 3大深度解析器（真正语法分析，不是正则匹配）
 *   FP Guard: 误报控制（确保不误杀）
 *   Path Predictor: 路径预判（提前布防）
 *   Active Defense: 主动防御（围追堵截）
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/CharSemantics.php';
require_once __DIR__ . '/WordSemantics.php';
require_once __DIR__ . '/StructureSemantics.php';
require_once __DIR__ . '/ParamSemantics.php';
require_once __DIR__ . '/BusinessSemantics.php';
require_once __DIR__ . '/LogicInference.php';
require_once __DIR__ . '/IntentInference.php';
require_once __DIR__ . '/IntentAnalyzer.php';
require_once __DIR__ . '/ObfuscationAnalyzer.php';
require_once __DIR__ . '/AttackChainAnalyzer.php';
require_once __DIR__ . '/SemanticMemoryPool.php';
require_once __DIR__ . '/AdversarialDefense.php';
require_once __DIR__ . '/MultiVectorFusion.php';
require_once __DIR__ . '/FalsePositiveGuard.php';
require_once __DIR__ . '/AttackPathPredictor.php';
require_once __DIR__ . '/ActiveDefense.php';
require_once __DIR__ . '/SqlSemanticParser.php';
require_once __DIR__ . '/HtmlSemanticParser.php';
require_once __DIR__ . '/PhpCodeSemanticParser.php';
require_once __DIR__ . '/PathTraversalSemanticParser.php';
require_once __DIR__ . '/CommandInjectionSemanticParser.php';
require_once __DIR__ . '/AttackPatternLibrary.php';
require_once __DIR__ . '/XxeSemanticParser.php';
require_once __DIR__ . '/SsrfSemanticParser.php';
require_once __DIR__ . '/SstiSemanticParser.php';
require_once __DIR__ . '/DeserializationSemanticParser.php';
require_once __DIR__ . '/CrlfInjectionSemanticParser.php';
require_once __DIR__ . '/ExpressionInjectionSemanticParser.php';
require_once __DIR__ . '/ParamPositionAnalyzer.php';
require_once __DIR__ . '/RequestContextAnalyzer.php';

class SemanticEngine {
    private static $weights = [
        'char'        => 0.02,
        'word'        => 0.02,
        'structure'   => 0.04,
        'param'       => 0.03,
        'business'    => 0.03,
        'logic'       => 0.05,
        'intent'      => 0.07,
        'chain'       => 0.04,
        'memory'      => 0.03,
        'adversarial' => 0.04,
        'sql_parser'        => 0.10,
        'html_parser'       => 0.08,
        'php_parser'        => 0.08,
        'path_parser'       => 0.08,
        'command_parser'    => 0.08,
        'xxe_parser'        => 0.07,
        'ssrf_parser'       => 0.07,
        'ssti_parser'       => 0.07,
        'deser_parser'      => 0.07,
        'crlf_parser'       => 0.05,
        'expr_parser'       => 0.06,
        // 上下文分析器（新增）
        'param_position'    => 0.05,   // 参数位置语义分析
        'request_context'   => 0.06,   // 跨请求上下文分析
    ];

    /**
     * 完整语义分析（含围堵策略）
     */
    public static function analyze(
        string $text,
        string $uri = '',
        array $params = [],
        array $normalizerContext = [],
        string $ip = '',
        array $multiVectorData = [],
        array $headers = [],
        string $method = 'GET',
        string $body = '',
        string $contentType = ''
    ): array {
        if ($text === '' && empty($params) && empty($multiVectorData)) {
            return self::emptyResult();
        }

        // ---- 基础10维分析（含内容类型感知路由） ----
        $baseResult = self::baseAnalyze($text, $uri, $params, $normalizerContext, $ip, $multiVectorData, $body, $contentType, $headers);

        // ---- 误报控制检查 ----
        $fpResult = FalsePositiveGuard::analyze($uri, $method, $params, $headers, $baseResult, $ip);

        // ---- 攻击路径预判 ----
        $prediction = AttackPathPredictor::predict(
            $baseResult['attack_phase'] ?? 'none',
            self::guessAttackType($baseResult),
            $uri,
            [],
            $ip
        );

        // ---- 主动防御决策 ----
        $defenseResult = ActiveDefense::defend(
            $uri,
            $ip,
            $prediction,
            $baseResult,
            [
                'chain_detected' => $baseResult['chain_detected'],
                'chain_name' => $baseResult['chain_name'],
                'chain_progress' => $baseResult['chain_progress'],
                'chain_risk' => $baseResult['chain_risk'],
            ]
        );

        // ---- 综合决策 ----
        $finalResult = self::combineResults($baseResult, $fpResult, $prediction, $defenseResult);

        return $finalResult;
    }

    /**
     * 基础10维分析
     */
    private static function baseAnalyze(string $text, string $uri, array $params, array $normalizerContext, string $ip, array $multiVectorData, string $body = '', string $contentType = '', array $headers = []): array {
        $multiVectorResult = [];
        if (!empty($multiVectorData)) {
            $multiVectorResult = MultiVectorFusion::analyze(
                $multiVectorData['uri'] ?? $uri,
                $multiVectorData['get'] ?? [],
                $multiVectorData['post'] ?? [],
                $multiVectorData['headers'] ?? [],
                $multiVectorData['ua'] ?? '',
                $multiVectorData['referer'] ?? '',
                $multiVectorData['cookie'] ?? '',
                $multiVectorData['raw_body'] ?? ''
            );
        }

        $adversarialResult = AdversarialDefense::analyze(
            $text,
            $multiVectorData['raw_text'] ?? $text,
            $normalizerContext,
            $multiVectorResult
        );
        $adversarialScore = $adversarialResult['score'];

        $decodedText = $text;
        $decodeDepth = 0;
        if (!empty($adversarialResult['decoded']) && $adversarialResult['decode_depth'] > 0) {
            $decodedText = $adversarialResult['decoded'];
            $decodeDepth = $adversarialResult['decode_depth'];
        }

        $charResult      = CharSemantics::analyze($decodedText);
        $wordResult      = WordSemantics::analyze($decodedText);
        $structResult    = StructureSemantics::analyze($decodedText);

        $paramScore = 0;
        $paramMismatches = [];
        if (!empty($params)) {
            foreach ($params as $k => $v) {
                $pr = ParamSemantics::analyze((string)$k, (string)$v);
                if ($pr['score'] > $paramScore) $paramScore = $pr['score'];
                if (!empty($pr['mismatch'])) $paramMismatches[] = (string)$k;
            }
        } else {
            $pr = ParamSemantics::analyze('content', $text);
            $paramScore = $pr['score'];
        }

        $businessResult = BusinessSemantics::analyze($uri, $params);
        $logicResult    = LogicInference::analyze($decodedText);
        $intentResult   = IntentInference::analyze($decodedText, $uri, $params);
        $intentAnalyzerResult = IntentAnalyzer::analyze($decodedText, $uri, $params);
        $obfuscationResult = ObfuscationAnalyzer::analyze($decodedText, $normalizerContext);

        $chainScore = 0;
        $chainInfo = [];
        if (!empty($ip)) {
            AttackChainAnalyzer::recordRequest($ip, $uri, $params, $wordResult['roles'][0] ?? '', $intentResult['phase'], $logicResult['score']);
            $chainPrediction = AttackChainAnalyzer::getPrediction($ip);
            $chainInfo = $chainPrediction;
            $chainScore = self::calcChainScore($chainPrediction);
        }

        $memoryScore = 0;
        $memoryAnomalies = [];
        if (!empty($ip)) {
            SemanticMemoryPool::record($ip, $text, $uri, $params, array_merge(
                ['risk_level' => 'clean', 'attack_phase' => 'none', 'logic_type' => 'none', 'word_roles' => [], 'indicators' => []],
                [
                    'l1_char_score' => $charResult['score'],
                    'l2_word_score' => $wordResult['score'],
                    'l3_structure_score' => $structResult['score'],
                    'l4_param_score' => $paramScore,
                    'l5_business_score' => $businessResult['score'],
                    'l6_logic_score' => $logicResult['score'],
                    'l7_intent_score' => $intentResult['score'],
                    'l8_chain_score' => $chainScore,
                ]
            ));
            $evolution = SemanticMemoryPool::analyzeEvolution($ip, [
                'l1_char_score' => $charResult['score'],
                'risk_level' => self::riskFromScores($charResult['score'], $wordResult['score'], $structResult['score'], $paramScore, $businessResult['score'], $logicResult['score'], $intentResult['score'], $chainScore),
                'attack_phase' => $intentResult['phase'] ?? 'none',
                'indicators' => array_merge($charResult['indicators'] ?? [], $wordResult['keywords'] ?? [], $logicResult['details'] ?? []),
            ]);
            $memoryScore = $evolution['score'];
            $memoryAnomalies = $evolution['anomalies'];
        }

        $intentScore = max($intentResult['score'], $intentAnalyzerResult['score']);

        $obfuscationScore = $obfuscationResult['score'];

        // ---- 深度语义解析器（内容类型感知路由，不再无脑全部分析同一段文本） ----
        $route = self::routeParsers($contentType, $headers, $body, $params, $uri, $decodedText);

        // SQL解析器：分析URI参数值 + POST body中的字符串值
        $sqlParserResult = !empty($route['sql']) ? SqlSemanticParser::analyze($route['sql']) : self::emptyParserResult();

        // HTML解析器：分析Body（当Content-Type为html时重点分析）
        $htmlParserResult = !empty($route['html']) ? HtmlSemanticParser::analyze($route['html']) : self::emptyParserResult();

        // PHP解析器：分析Body + 文件上传相关参数
        $phpParserResult = !empty($route['php']) ? PhpCodeSemanticParser::analyze($route['php']) : self::emptyParserResult();

        // 路径遍历：分析URI参数值 + 文件相关参数
        $pathParserResult = !empty($route['path']) ? PathTraversalSemanticParser::analyze($route['path']) : self::emptyParserResult();

        // 命令注入：分析URI参数值 + Body字符串
        $commandParserResult = !empty($route['command']) ? CommandInjectionSemanticParser::analyze($route['command']) : self::emptyParserResult();

        // XXE解析器：分析Body（仅当Content-Type为xml时）
        $xxeParserResult = !empty($route['xxe']) ? XxeSemanticParser::analyze($route['xxe']) : self::emptyParserResult();

        // SSRF解析器：分析URI中的URL参数 + Body中的URL
        $ssrfParserResult = !empty($route['ssrf']) ? SsrfSemanticParser::analyze($route['ssrf']) : self::emptyParserResult();

        // SSTI：分析URI参数 + Body
        $sstiParserResult = !empty($route['ssti']) ? SstiSemanticParser::analyze($route['ssti']) : self::emptyParserResult();

        // 反序列化：分析Body（当Content-Type包含序列化特征时）
        $deserParserResult = !empty($route['deser']) ? DeserializationSemanticParser::analyze($route['deser']) : self::emptyParserResult();

        // CRLF：分析Headers + URI参数
        $crlfParserResult = !empty($route['crlf']) ? CrlfInjectionSemanticParser::analyze($route['crlf']) : self::emptyParserResult();

        // 表达式注入：分析URI参数 + Body
        $exprParserResult = !empty($route['expr']) ? ExpressionInjectionSemanticParser::analyze($route['expr']) : self::emptyParserResult();

        $sqlParserScore  = $sqlParserResult['score'] ?? 0;
        $htmlParserScore = $htmlParserResult['score'] ?? 0;
        $phpParserScore  = $phpParserResult['score'] ?? 0;
        $pathParserScore = $pathParserResult['score'] ?? 0;
        $commandParserScore = $commandParserResult['score'] ?? 0;
        $xxeParserScore  = $xxeParserResult['score'] ?? 0;
        $ssrfParserScore = $ssrfParserResult['score'] ?? 0;
        $sstiParserScore = $sstiParserResult['score'] ?? 0;
        $deserParserScore = $deserParserResult['score'] ?? 0;
        $crlfParserScore = $crlfParserResult['score'] ?? 0;
        $exprParserScore = $exprParserResult['score'] ?? 0;

        // ---- 参数位置上下文分析（L11）：同 payload 在不同位置威胁不同 ----
        $paramPositionResult = ['score' => 0, 'positions' => [], 'position_anomalies' => [], 'cross_position_patterns' => [], 'high_risk_params' => []];
        if (!defined('WAF_PARAM_POSITION_ANALYZER') || WAF_PARAM_POSITION_ANALYZER) {
            $paramPositionResult = ParamPositionAnalyzer::analyze(
                $multiVectorData['get'] ?? [],
                $multiVectorData['post'] ?? [],
                $multiVectorData['cookie_array'] ?? [],
                $multiVectorData['headers'] ?? [],
                [],  // JSON Body（已由 body 解析器处理，这里传空避免重复）
                $uri
            );
        }
        $paramPositionScore = $paramPositionResult['score'] ?? 0;

        // ---- 跨请求上下文分析（L12）：CSRF/重放/会话/时序/API滥用 ----
        $ctxMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $requestContextResult = [
            'score' => 0, 'csrf_risk' => [], 'replay_risk' => [], 'session_anomaly' => [],
            'timing_anomaly' => [], 'api_abuse' => [], 'cross_request_patterns' => [],
        ];
        if (!defined('WAF_REQUEST_CONTEXT_ANALYZER') || WAF_REQUEST_CONTEXT_ANALYZER) {
            $requestContextResult = RequestContextAnalyzer::analyze(
                $ip,
                $uri,
                $ctxMethod,
                $multiVectorData['headers'] ?? $headers,
                $params,
                session_id() ?: ''
            );
        }
        $requestContextScore = $requestContextResult['score'] ?? 0;

        // ---- 攻击模式泛化匹配（结构相似度，非字符串匹配） ----
        $patternMatchResult = AttackPatternLibrary::match($text, $decodedText);
        $patternMatchScore = 0;
        if ($patternMatchResult['is_attack_like'] && !empty($patternMatchResult['best_match'])) {
            $sim = $patternMatchResult['best_match']['similarity'];
            $patternMatchScore = (int)round($sim * 40);
        }

        // 加权计算
        $total = 0;
        $total += $charResult['score']        * self::$weights['char'];
        $total += $wordResult['score']        * self::$weights['word'];
        $total += $structResult['score']      * self::$weights['structure'];
        $total += $paramScore                 * self::$weights['param'];
        $total += $businessResult['score']    * self::$weights['business'];
        $total += $logicResult['score']       * self::$weights['logic'];
        $total += $intentScore                * self::$weights['intent'];
        $total += $chainScore                 * self::$weights['chain'];
        $total += $memoryScore                * self::$weights['memory'];
        $total += $adversarialScore           * self::$weights['adversarial'];
        $total += $sqlParserScore             * self::$weights['sql_parser'];
        $total += $htmlParserScore            * self::$weights['html_parser'];
        $total += $phpParserScore             * self::$weights['php_parser'];
        $total += $pathParserScore            * self::$weights['path_parser'];
        $total += $commandParserScore         * self::$weights['command_parser'];
        $total += $xxeParserScore             * self::$weights['xxe_parser'];
        $total += $ssrfParserScore            * self::$weights['ssrf_parser'];
        $total += $sstiParserScore            * self::$weights['ssti_parser'];
        $total += $deserParserScore           * self::$weights['deser_parser'];
        $total += $crlfParserScore            * self::$weights['crlf_parser'];
        $total += $exprParserScore            * self::$weights['expr_parser'];
        $total += $paramPositionScore         * self::$weights['param_position'];
        $total += $requestContextScore        * self::$weights['request_context'];

        $multiVectorScore = $multiVectorResult['fusion_score'] ?? 0;
        if ($multiVectorScore >= 30) {
            $total += $multiVectorScore * 0.08;
        }

        if ($obfuscationScore >= 50) {
            $total += $obfuscationScore * 0.12;
        } elseif ($obfuscationScore >= 30) {
            $total += $obfuscationScore * 0.06;
        }

        // 交叉证据加成
        $highDimensions = self::countHighDimensions([
            $charResult['score'], $wordResult['score'], $structResult['score'], $paramScore,
            $businessResult['score'], $logicResult['score'], $intentResult['score'], $chainScore,
            $memoryScore, $adversarialScore, $sqlParserScore, $htmlParserScore, $phpParserScore,
            $pathParserScore, $commandParserScore, $xxeParserScore, $ssrfParserScore,
            $sstiParserScore, $deserParserScore, $crlfParserScore, $exprParserScore,
            $paramPositionScore, $requestContextScore,
        ]);

        if ($highDimensions >= 6) $total += 18;
        elseif ($highDimensions >= 5) $total += 15;
        elseif ($highDimensions >= 4) $total += 10;
        elseif ($highDimensions >= 3) $total += 6;
        elseif ($highDimensions >= 2) $total += 3;

        // 特殊组合加成
        if ($logicResult['score'] >= 60 && $intentResult['score'] >= 60) $total += 10;
        if (!empty($chainInfo['chain_detected']) && ($chainInfo['chain_progress'] ?? 0) >= 40) $total += 12;
        if ($adversarialResult['is_adversarial'] && $intentResult['score'] >= 40) $total += 15;
        if ($memoryScore >= 40 && $intentResult['score'] >= 40) $total += 10;

        // 深度解析器+意图双证加成（11大深度解析器各有强证据通道）
        $primaryIntent = $intentResult['primary_intent'] ?? 'unknown';
        if ($primaryIntent === 'path_traversal' && $pathParserScore >= 30) $total += 15;
        if ($primaryIntent === 'command_injection' && $commandParserScore >= 25) $total += 15;
        if ($primaryIntent === 'sql_injection' && $sqlParserScore >= 30) $total += 12;
        if ($primaryIntent === 'xss' && $htmlParserScore >= 15) $total += 12;
        if ($primaryIntent === 'webshell' && $phpParserScore >= 30) $total += 15;
        if ($primaryIntent === 'xxe' && $xxeParserScore >= 30) $total += 12;
        if ($primaryIntent === 'ssrf' && $ssrfParserScore >= 30) $total += 12;
        if ($primaryIntent === 'ssti' && $sstiParserScore >= 30) $total += 12;
        if ($primaryIntent === 'deserialization' && $deserParserScore >= 30) $total += 15;
        if ($primaryIntent === 'crlf_injection' && $crlfParserScore >= 30) $total += 10;

        // 算术/逻辑恒真双证加成（LogicInference + SQLParser 都检测到恒真）
        $logicHasTaut = ($logicResult['logic_type'] ?? '') === 'tautology'
            || !empty($logicResult['tautology_count'])
            || !empty($logicResult['has_tautology']);
        $sqlHasTaut = !empty($sqlParserResult['has_tautology']);
        if ($logicHasTaut && $sqlHasTaut) $total += 15;
        elseif ($logicHasTaut || $sqlHasTaut) $total += 5;

        // 深度解析器强证据加成（真正的语法分析命中，不是正则）
        if ($sqlParserScore >= 50 && $logicResult['score'] >= 40) $total += 12;
        if ($htmlParserScore >= 50 && $structResult['score'] >= 40) $total += 10;
        if ($phpParserScore >= 50 && $adversarialScore >= 40) $total += 15;
        if ($pathParserScore >= 50 && $intentResult['score'] >= 40) $total += 12;
        if ($commandParserScore >= 50 && $intentResult['score'] >= 40) $total += 12;
        if ($xxeParserScore >= 50) $total += 12;
        if ($ssrfParserScore >= 50) $total += 12;
        if ($sstiParserScore >= 50) $total += 12;
        if ($deserParserScore >= 50) $total += 15;
        if ($crlfParserScore >= 50) $total += 10;
        if ($exprParserScore >= 50) $total += 12;
        $parserCount = 0;
        if ($sqlParserScore >= 30) $parserCount++;
        if ($htmlParserScore >= 30) $parserCount++;
        if ($phpParserScore >= 30) $parserCount++;
        if ($pathParserScore >= 30) $parserCount++;
        if ($commandParserScore >= 30) $parserCount++;
        if ($xxeParserScore >= 30) $parserCount++;
        if ($ssrfParserScore >= 30) $parserCount++;
        if ($sstiParserScore >= 30) $parserCount++;
        if ($deserParserScore >= 30) $parserCount++;
        if ($crlfParserScore >= 30) $parserCount++;
        if ($exprParserScore >= 30) $parserCount++;
        if ($parserCount >= 5) $total += 25;
        elseif ($parserCount >= 4) $total += 20;
        elseif ($parserCount >= 3) $total += 15;
        elseif ($parserCount >= 2) $total += 10;

        // 攻击模式泛化加成（结构相似度作为辅助增强，需有其他层证据支撑）
        if ($patternMatchScore >= 25 && $intentScore >= 40) {
            $total += (int)round($patternMatchScore * 0.2);
        }

        // 编码绕过意图加成（核心思想：编码越深+解码后攻击得分越高=刻意绕过意图越强）
        // 注：effectiveAttackScore 取综合分与单项解析器加权分最大值，
        // 但单项解析器对参数名/短字符串敏感，容易误判，因此系数保守
        $effectiveAttackScore = max(
            $total,
            $sqlParserScore * 0.6,
            $htmlParserScore * 0.6,
            $commandParserScore * 0.6,
            $phpParserScore * 0.5,
            $pathParserScore * 0.4
        );
        $encodeBypassScore = self::calcEncodeBypassScore(
            $decodeDepth, $adversarialScore, $total, $adversarialResult, $effectiveAttackScore
        );
        if ($encodeBypassScore > 0) {
            $total += $encodeBypassScore;
        }

        // 高置信度明文攻击保底加成（仅在专项解析器有强烈攻击证据时才加成）
        // 注：门槛提高到 60/75，避免参数名误判（如 ?p=1 触发 pathParser 50 分）导致误拦截
        if ($decodeDepth === 0) {
            $maxParserScore = max(
                $sqlParserScore,
                $htmlParserScore,
                $commandParserScore,
                $phpParserScore,
                $pathParserScore
            );
            if ($maxParserScore >= 75) {
                $total += 15;
            } elseif ($maxParserScore >= 60) {
                $total += 8;
            }
        }

        // ===== 解析器布尔标志位保底加成 =====
        // 即使 parser 得分因模型保守而偏低，只要解析器检测到明确的攻击特征标志位
        // （has_eval / has_command_exec / has_script / has_union / is_path_traversal 等），
        // 就给予保底分数，防止短载荷攻击（如 system(ls) / eval(...) / <script>...）漏检
        $parserFlagBonus = 0;

        // PHP 代码执行：eval() / system() / exec() 等
        $phpParserResult = $phpParserResult ?? [];
        if (!empty($phpParserResult['has_eval'])) $parserFlagBonus = max($parserFlagBonus, 65);
        if (!empty($phpParserResult['has_command_exec'])) $parserFlagBonus = max($parserFlagBonus, 75);
        if (!empty($phpParserResult['has_superglobal_danger'])) $parserFlagBonus = max($parserFlagBonus, 60);
        if (!empty($phpParserResult['dangerous_functions'])) $parserFlagBonus = max($parserFlagBonus, 60);

        // SQL 注入：UNION / tautology
        $sqlParserResult = $sqlParserResult ?? [];
        if (!empty($sqlParserResult['has_union'])) $parserFlagBonus = max($parserFlagBonus, 70);
        if (!empty($sqlParserResult['has_tautology'])) $parserFlagBonus = max($parserFlagBonus, 75);

        // XSS 攻击：script / event handler / javascript 协议
        $htmlParserResult = $htmlParserResult ?? [];
        if (!empty($htmlParserResult['has_script'])) $parserFlagBonus = max($parserFlagBonus, 70);
        if (!empty($htmlParserResult['has_event_handler'])) $parserFlagBonus = max($parserFlagBonus, 60);
        if (!empty($htmlParserResult['has_javascript_protocol'])) $parserFlagBonus = max($parserFlagBonus, 65);
        if (!empty($htmlParserResult['has_svg_payload'])) $parserFlagBonus = max($parserFlagBonus, 60);

        // 路径遍历
        $pathParserResult = $pathParserResult ?? [];
        if (!empty($pathParserResult['is_path_traversal'])) $parserFlagBonus = max($parserFlagBonus, 65);

        // CRLF 注入：原始CRLF序列、HTTP头注入、响应拆分
        // 注意：CRLF 的 \r\n 会被 Normalizer 的 layerWhitespace 规范化为空格，
        // 所以 signatureBonus 检测不到。这里通过 CRLF 解析器的标志位兜底。
        // CRLF 解析器分析的是 route['crlf']（来自原始 body + URI 参数 + headers），能看到真实 \r\n
        $crlfParserResult = $crlfParserResult ?? [];
        if (!empty($crlfParserResult['is_crlf'])) $parserFlagBonus = max($parserFlagBonus, 50);
        if (!empty($crlfParserResult['header_injection_hits'])) $parserFlagBonus = max($parserFlagBonus, 65);
        if (!empty($crlfParserResult['response_splitting'])) $parserFlagBonus = max($parserFlagBonus, 75);

        // 应用保底加成：取当前总分与"标志位保底分"的最大值
        if ($parserFlagBonus > $total) {
            $total = $parserFlagBonus;
        }

        // ===== 上下文分析器强证据加成 =====
        // 参数位置异常 + 注入证据 -> 跨位置注入意图
        if ($paramPositionScore >= 50 && $intentScore >= 40) $total += 10;
        if (!empty($paramPositionResult['cross_position_patterns'])) $total += 8;
        // 跨请求上下文强证据：CSRF/重放/会话劫持 -> 直接加成
        if (!empty($requestContextResult['csrf_risk']['is_csrf'])) $total += 12;
        if (!empty($requestContextResult['replay_risk']['is_replay'])) $total += 10;
        if (!empty($requestContextResult['session_anomaly']['is_anomaly'])) $total += 12;
        if (!empty($requestContextResult['timing_anomaly']['is_anomaly'])) $total += 8;
        if (!empty($requestContextResult['api_abuse']['is_abuse'])) $total += 10;

        // ===== 明确攻击签名兜底加成 =====
        // 当解析器得分偏低但归一化后的文本包含明确的攻击签名时，给予兜底分数
        // 防止短payload或变形payload因解析器保守而漏检
        $signatureBonus = self::calcSignatureBonus($decodedText, $total);
        if ($signatureBonus > $total) {
            $total = $signatureBonus;
        }

        $total = max(0, min(100, (int)round($total)));

        return [
            'total_score'           => $total,
            'risk_level'            => self::getRiskLevel($total),
            'l1_char_score'         => $charResult['score'],
            'l2_word_score'         => $wordResult['score'],
            'l3_structure_score'    => $structResult['score'],
            'l4_param_score'        => $paramScore,
            'l5_business_score'     => $businessResult['score'],
            'l6_logic_score'        => $logicResult['score'],
            'l7_intent_score'       => $intentScore,
            'l8_chain_score'        => $chainScore,
            'l9_memory_score'       => $memoryScore,
            'l10_adversarial_score' => $adversarialScore,
            'sql_parser_score'      => $sqlParserScore,
            'html_parser_score'     => $htmlParserScore,
            'php_parser_score'      => $phpParserScore,
            'path_parser_score'     => $pathParserScore,
            'command_parser_score'  => $commandParserScore,
            'xxe_parser_score'      => $xxeParserScore,
            'ssrf_parser_score'     => $ssrfParserScore,
            'ssti_parser_score'     => $sstiParserScore,
            'deser_parser_score'    => $deserParserScore,
            'crlf_parser_score'     => $crlfParserScore,
            'expr_parser_score'     => $exprParserScore,
            'param_position_score'  => $paramPositionScore,
            'request_context_score' => $requestContextScore,
            'param_position_result' => [
                'position_count'        => count($paramPositionResult['positions'] ?? []),
                'position_anomaly_count' => count($paramPositionResult['position_anomalies'] ?? []),
                'cross_position_count'  => count($paramPositionResult['cross_position_patterns'] ?? []),
                'high_risk_param_count' => count($paramPositionResult['high_risk_params'] ?? []),
            ],
            'request_context_result' => [
                'csrf_risk'         => $requestContextResult['csrf_risk']['risk_score'] ?? 0,
                'is_csrf'           => $requestContextResult['csrf_risk']['is_csrf'] ?? false,
                'replay_risk'       => $requestContextResult['replay_risk']['risk_score'] ?? 0,
                'is_replay'         => $requestContextResult['replay_risk']['is_replay'] ?? false,
                'session_anomaly'   => $requestContextResult['session_anomaly']['risk_score'] ?? 0,
                'is_session_anomaly' => $requestContextResult['session_anomaly']['is_anomaly'] ?? false,
                'timing_anomaly'    => $requestContextResult['timing_anomaly']['risk_score'] ?? 0,
                'timing_pattern'    => $requestContextResult['timing_anomaly']['pattern'] ?? 'human',
                'api_abuse'         => $requestContextResult['api_abuse']['risk_score'] ?? 0,
                'is_api_abuse'      => $requestContextResult['api_abuse']['is_abuse'] ?? false,
                'cross_request_patterns' => count($requestContextResult['cross_request_patterns']['patterns'] ?? []),
            ],
            'sql_parser_result'     => [
                'has_tautology'       => $sqlParserResult['has_tautology'] ?? false,
                'tautology_type'      => $sqlParserResult['tautology_type'] ?? '',
                'has_union'           => $sqlParserResult['has_union'] ?? false,
                'union_count'         => $sqlParserResult['union_count'] ?? 0,
                'subquery_depth'      => $sqlParserResult['subquery_depth'] ?? 0,
                'dangerous_functions' => $sqlParserResult['dangerous_functions'] ?? [],
                'sensitive_tables'    => $sqlParserResult['sensitive_tables'] ?? [],
                'sql_type'            => $sqlParserResult['sql_type'] ?? 'unknown',
            ],
            'html_parser_result'    => [
                'parser_used'           => $htmlParserResult['parser_used'] ?? 'regex',
                'has_script'            => $htmlParserResult['has_script'] ?? false,
                'has_event_handler'     => $htmlParserResult['has_event_handler'] ?? false,
                'has_javascript_proto'  => $htmlParserResult['has_javascript_protocol'] ?? false,
                'has_svg_payload'       => $htmlParserResult['has_svg_payload'] ?? false,
                'event_handler_count'   => count($htmlParserResult['event_handlers'] ?? []),
                'max_nesting_depth'     => $htmlParserResult['max_nesting_depth'] ?? 0,
            ],
            'php_parser_result'     => [
                'parser_used'            => $phpParserResult['parser_used'] ?? 'regex',
                'has_eval'               => $phpParserResult['has_eval'] ?? false,
                'has_command_exec'       => $phpParserResult['has_command_exec'] ?? false,
                'has_superglobal_danger' => $phpParserResult['has_superglobal_in_danger'] ?? false,
                'obfuscation_level'      => $phpParserResult['obfuscation_level'] ?? 0,
                'dangerous_func_count'   => count($phpParserResult['dangerous_functions'] ?? []),
                'code_complexity'        => $phpParserResult['code_complexity'] ?? 0,
            ],
            'path_parser_result'    => [
                'is_path_traversal'    => $pathParserResult['is_path_traversal'] ?? false,
                'traversal_depth'      => $pathParserResult['traversal_depth'] ?? 0,
                'decode_depth'         => $pathParserResult['decode_depth'] ?? 0,
                'os_type'              => $pathParserResult['os_type'] ?? 'unknown',
                'sensitive_hits_count' => count($pathParserResult['sensitive_hits'] ?? []),
                'has_null_byte'        => $pathParserResult['has_null_byte'] ?? false,
                'has_unicode_bypass'   => $pathParserResult['has_unicode_bypass'] ?? false,
            ],
            'command_parser_result' => [
                'is_command_injection'   => $commandParserResult['is_command_injection'] ?? false,
                'command_count'          => $commandParserResult['command_count'] ?? 0,
                'dangerous_cmd_count'    => count($commandParserResult['dangerous_commands'] ?? []),
                'categories'             => $commandParserResult['categories'] ?? [],
                'has_command_substitution' => $commandParserResult['has_command_substitution'] ?? false,
                'has_wildcard_bypass'    => $commandParserResult['has_wildcard_bypass'] ?? false,
            ],
            'xxe_parser_result' => [
                'is_xxe'               => $xxeParserResult['is_xxe'] ?? false,
                'has_doctype'          => $xxeParserResult['has_doctype'] ?? false,
                'has_external_ref'     => $xxeParserResult['has_external_ref'] ?? false,
                'has_parameter_entity' => $xxeParserResult['has_parameter_entity'] ?? false,
                'is_blind_xxe'         => $xxeParserResult['is_blind_xxe'] ?? false,
                'entity_count'         => $xxeParserResult['entity_count'] ?? 0,
            ],
            'ssrf_parser_result' => [
                'is_ssrf'              => $ssrfParserResult['is_ssrf'] ?? false,
                'has_internal_ip'      => $ssrfParserResult['has_internal_ip'] ?? false,
                'has_cloud_metadata'   => $ssrfParserResult['has_cloud_metadata'] ?? false,
                'dangerous_scheme_count' => count($ssrfParserResult['dangerous_schemes'] ?? []),
                'has_bypass_technique' => !empty($ssrfParserResult['bypass_techniques']),
            ],
            'ssti_parser_result' => [
                'is_ssti'              => $sstiParserResult['is_ssti'] ?? false,
                'detected_engines'     => $sstiParserResult['detected_engines'] ?? [],
                'expression_depth'     => $sstiParserResult['expression_depth'] ?? 0,
                'has_mixed_engines'    => $sstiParserResult['has_mixed_engines'] ?? false,
                'payload_hits_count'   => count($sstiParserResult['payload_hits'] ?? []),
            ],
            'deser_parser_result' => [
                'is_deserialization'   => $deserParserResult['is_deserialization'] ?? false,
                'object_count'         => $deserParserResult['object_count'] ?? 0,
                'array_count'          => $deserParserResult['array_count'] ?? 0,
                'max_nesting_depth'    => $deserParserResult['max_nesting_depth'] ?? 0,
                'dangerous_classes'    => $deserParserResult['dangerous_classes'] ?? [],
                'has_pop_chain'        => $deserParserResult['has_pop_chain_feature'] ?? false,
            ],
            'crlf_parser_result' => [
                'is_crlf'              => $crlfParserResult['is_crlf'] ?? false,
                'crlf_count'           => $crlfParserResult['crlf_count'] ?? 0,
                'has_header_injection' => $crlfParserResult['has_header_injection'] ?? false,
                'has_response_splitting' => $crlfParserResult['has_response_splitting'] ?? false,
                'decode_depth'         => $crlfParserResult['decode_depth'] ?? 0,
            ],
            'expr_parser_result' => [
                'is_expression_injection' => $exprParserResult['is_expression_injection'] ?? false,
                'injection_type'        => $exprParserResult['injection_type'] ?? 'none',
                'xpath_score'           => $exprParserResult['xpath_score'] ?? 0,
                'ldap_score'            => $exprParserResult['ldap_score'] ?? 0,
                'nosql_score'           => $exprParserResult['nosql_score'] ?? 0,
            ],
            'pattern_match_score'   => $patternMatchScore,
            'pattern_best_match'    => $patternMatchResult['best_match'] ?? null,
            'pattern_match_count'   => count($patternMatchResult['matches'] ?? []),
            'obfuscation_score'     => $obfuscationScore,
            'encode_bypass_score'   => $encodeBypassScore,
            'decode_depth'          => $decodeDepth,
            'decode_path'           => $adversarialResult['decode_path'] ?? [],
            'scene'                 => $businessResult['scene'] ?? 'unknown',
            'business_valid'        => $businessResult['valid'] ?? true,
            'word_roles'            => $wordResult['roles'] ?? [],
            'logic_type'            => $logicResult['logic_type'] ?? 'none',
            'logic_type_label'      => $logicResult['logic_type_label'] ?? '',
            'attack_phase'          => $intentResult['phase'] ?? 'none',
            'attack_phase_name'     => $intentResult['phase_name'] ?? '未知',
            'attack_progress'       => IntentInference::getAttackProgress($intentResult['phase'] ?? 'none'),
            'intent_confidence'     => $intentResult['phase_confidence'] ?? 0,
            'primary_intent'        => $intentAnalyzerResult['primary_intent'] ?? 'unknown',
            'primary_intent_name'   => $intentAnalyzerResult['primary_name'] ?? '未知',
            'intent_analyzer_score' => $intentAnalyzerResult['score'] ?? 0,
            'intent_names'          => $intentAnalyzerResult['intent_names'] ?? [],
            'obfuscation_depth'     => $obfuscationResult['depth'] ?? 'none',
            'obfuscation_depth_label' => $obfuscationResult['depth_label'] ?? '无混淆',
            'obfuscation_techniques' => $obfuscationResult['technique_names'] ?? [],
            'obfuscation_bypass_intent' => $obfuscationResult['bypass_intent'] ?? 0,
            'chain_detected'        => $chainInfo['chain_detected'] ?? null,
            'chain_name'            => $chainInfo['chain_name'] ?? '',
            'chain_desc'            => $chainInfo['chain_desc'] ?? '',
            'chain_risk'            => $chainInfo['chain_risk'] ?? '',
            'chain_progress'        => $chainInfo['chain_progress'] ?? 0,
            'chain_predicted'       => $chainInfo['predicted_next'] ?? [],
            'should_block_early'    => $ip ? AttackChainAnalyzer::shouldBlockEarly($ip) : false,
            'memory_anomalies'      => $memoryAnomalies,
            'adversarial_threats'   => $adversarialResult['threat_names'] ?? [],
            'adversarial_is_attack' => $adversarialResult['is_adversarial'] ?? false,
            'multi_vector_score'    => $multiVectorScore,
            'high_dimensions'       => $highDimensions,
            'indicators'            => self::buildBaseIndicators($charResult, $wordResult, $structResult, $paramMismatches, $businessResult, $logicResult, $intentResult, $intentAnalyzerResult, $obfuscationResult, $chainInfo, $memoryAnomalies, $adversarialResult, $multiVectorResult),
        ];
    }

    /**
     * 组合所有结果
     */
    private static function combineResults(array $base, array $fp, array $prediction, array $defense): array {
        $finalAction = 'allow';
        $finalReason = '';
        $finalBlocked = false;

        // 如果主动防御决定拦截
        if ($defense['blocked']) {
            $finalAction = $defense['action'];
            $finalReason = $defense['reason'];
            $finalBlocked = true;
        }
        // 如果误报控制判定为正常
        elseif ($fp['is_false_positive']) {
            $finalAction = 'allow';
            $finalReason = $fp['reason'];
            $finalBlocked = false;
        }
        // 根据分数决定
        else {
            $score = $base['total_score'];
            if ($score >= 70) {
                $finalAction = 'block';
                $finalReason = "风险分数: {$score}/100";
                $finalBlocked = true;
            } elseif ($score >= 40) {
                $finalAction = 'monitor';
                $finalReason = "风险分数: {$score}/100";
                $finalBlocked = false;
            }
        }

        return array_merge($base, [
            'fp_is_false_positive' => $fp['is_false_positive'],
            'fp_confidence' => $fp['confidence'],
            'fp_reason' => $fp['reason'],
            'fp_recommendations' => $fp['recommendations'],
            'predicted_paths' => $prediction['predicted_paths'],
            'predicted_params' => $prediction['predicted_params'],
            'attacker_profile' => $prediction['attacker_profile'],
            'attacker_profile_name' => $prediction['attacker_profile_name'],
            'prediction_confidence' => $prediction['confidence'],
            'prediction_recommendations' => $prediction['recommendations'],
            'defense_action' => $defense['action'],
            'defense_reason' => $defense['reason'],
            'defense_honeytrap' => $defense['honeytrap'],
            'defense_recommendation' => $defense['recommendation'],
            'final_action' => $finalAction,
            'final_reason' => $finalReason,
            'should_block' => $finalBlocked,
        ]);
    }

    private static function guessAttackType(array $result): string {
        $indicators = $result['indicators'] ?? [];
        $logicType = $result['logic_type'] ?? '';

        if (strpos(implode(',', $indicators), 'union') !== false || in_array($logicType, ['tautology', 'time_blind', 'error_based'])) {
            return 'sql_injection';
        }
        if (strpos(implode(',', $indicators), 'script') !== false || strpos(implode(',', $indicators), 'XSS') !== false) {
            return 'xss';
        }
        if (strpos(implode(',', $indicators), 'path_traversal') !== false) {
            return 'path_traversal';
        }
        if (strpos(implode(',', $indicators), 'eval') !== false || strpos(implode(',', $indicators), 'system') !== false) {
            return 'command_execution';
        }
        if (strpos(implode(',', $indicators), 'upload') !== false) {
            return 'file_upload';
        }

        return '';
    }

    private static function countHighDimensions(array $scores): int {
        return count(array_filter($scores, function($s) { return $s >= 50; }));
    }

    private static function emptyResult(): array {
        return array_merge(self::baseEmpty(), [
            'fp_is_false_positive' => false, 'fp_confidence' => 0, 'fp_reason' => '',
            'predicted_paths' => [], 'predicted_params' => [], 'attacker_profile' => '',
            'defense_action' => 'allow', 'defense_reason' => '', 'defense_honeytrap' => false,
            'final_action' => 'allow', 'final_reason' => '', 'should_block' => false,
        ]);
    }

    private static function baseEmpty(): array {
        return [
            'total_score' => 0, 'risk_level' => 'clean',
            'l1_char_score' => 0, 'l2_word_score' => 0, 'l3_structure_score' => 0,
            'l4_param_score' => 0, 'l5_business_score' => 0, 'l6_logic_score' => 0,
            'l7_intent_score' => 0, 'l8_chain_score' => 0, 'l9_memory_score' => 0,
            'l10_adversarial_score' => 0, 'indicators' => [],
            // 上下文分析器空结果
            'param_position_score' => 0, 'request_context_score' => 0,
            'param_position_result' => [
                'position_count' => 0, 'position_anomaly_count' => 0,
                'cross_position_count' => 0, 'high_risk_param_count' => 0,
            ],
            'request_context_result' => [
                'csrf_risk' => 0, 'is_csrf' => false,
                'replay_risk' => 0, 'is_replay' => false,
                'session_anomaly' => 0, 'is_session_anomaly' => false,
                'timing_anomaly' => 0, 'timing_pattern' => 'human',
                'api_abuse' => 0, 'is_api_abuse' => false,
                'cross_request_patterns' => 0,
            ],
        ];
    }

    private static function riskFromScores(...$scores): string {
        $avg = array_sum($scores) / count($scores);
        if ($avg >= 75) return 'critical';
        if ($avg >= 55) return 'high';
        if ($avg >= 35) return 'medium';
        if ($avg >= 15) return 'low';
        return 'clean';
    }

    private static function getRiskLevel(int $total): string {
        if ($total >= 80) return 'critical';
        if ($total >= 60) return 'high';
        if ($total >= 40) return 'medium';
        if ($total >= 15) return 'low';
        return 'clean';
    }

    /**
     * 编码绕过意图评分
     * 核心思想：编码层数越深 + 解码后攻击得分越高 = 刻意编码绕过的意图越强
     * 这是"编码前后差异分析"的等效实现——原始文本可能看起来无害，但解码后是攻击payload
     */
    private static function calcEncodeBypassScore(
        int $decodeDepth,
        int $adversarialScore,
        float $currentTotal,
        array $adversarialResult,
        float $effectiveAttackScore = 0
    ): int {
        $attackScore = max($currentTotal, $effectiveAttackScore);
        if ($decodeDepth <= 0 || $attackScore < 15) {
            return 0;
        }

        $score = 0;
        $indicators = [];

        if ($decodeDepth >= 4) { $score += 18; $indicators[] = 'extreme_encode_depth'; }
        elseif ($decodeDepth >= 3) { $score += 12; $indicators[] = 'high_encode_depth'; }
        elseif ($decodeDepth >= 2) { $score += 7; $indicators[] = 'double_encode'; }
        elseif ($decodeDepth >= 1) { $score += 3; $indicators[] = 'single_encode'; }

        if ($adversarialScore >= 70) { $score += 10; }
        elseif ($adversarialScore >= 50) { $score += 6; }
        elseif ($adversarialScore >= 30) { $score += 3; }

        if ($attackScore >= 60 && $decodeDepth >= 2) {
            $score += 12;
            $indicators[] = 'encoded_high_severity_combo';
        } elseif ($attackScore >= 40 && $decodeDepth >= 1) {
            $score += 5;
            $indicators[] = 'encoded_medium_severity_combo';
        }

        $decodePath = $adversarialResult['decode_path'] ?? [];
        if (in_array('base64', $decodePath) && $attackScore >= 30) {
            $score += 8;
            $indicators[] = 'base64_plus_payload';
        }
        if (in_array('utf8_overlong', $decodePath) && $attackScore >= 20) {
            $score += 10;
            $indicators[] = 'overlong_utf8_bypass';
        }
        if (in_array('unicode_percent_u', $decodePath) && $attackScore >= 20) {
            $score += 8;
            $indicators[] = 'unicode_percent_u_bypass';
        }
        if ((in_array('html_numeric_entity', $decodePath) || in_array('html_named_entity', $decodePath)) && $attackScore >= 20) {
            $score += 7;
            $indicators[] = 'html_entity_bypass';
        }
        // HTML 实体编码是明确的人工混淆（非浏览器自动编码），单独加成
        if ((in_array('html_numeric_entity', $decodePath) || in_array('html_named_entity', $decodePath)) && $attackScore >= 25) {
            $score += 10;
            $indicators[] = 'html_entity_keyword_obfuscation';
        }
        // 高置信攻击 + 编码隐藏 = 强绕过意图
        // 注：门槛 attackScore≥50 且 decodeDepth≥2，避免浏览器自动 URL 编码触发误判
        if ($attackScore >= 50 && $decodeDepth >= 2) {
            $score += 10;
            $indicators[] = 'high_confidence_encoded_attack';
        }
        // SQL/HTML/命令关键字被编码 = 明确的绕过意图（追加专项加成）
        // 注：门槛 attackScore≥40 且 decodeDepth≥2，需要深度编码而非浏览器自动编码
        if ($attackScore >= 40 && $decodeDepth >= 2) {
            $hasKeywordEncode = false;
            foreach (['html_numeric_entity', 'html_named_entity', 'homoglyph_normalize', 'fullwidth_normalize', 'zero_width_remove', 'unicode_percent_u', 'utf8_overlong'] as $tech) {
                if (in_array($tech, $decodePath)) {
                    $hasKeywordEncode = true;
                    break;
                }
            }
            if ($hasKeywordEncode) {
                $score += 5;
                $indicators[] = 'keyword_obfuscation_technique';
            }
        }
        if (in_array('homoglyph_normalize', $decodePath) && $attackScore >= 20) {
            $score += 6;
            $indicators[] = 'homoglyph_bypass';
        }
        if (in_array('zero_width_remove', $decodePath) && $attackScore >= 20) {
            $score += 6;
            $indicators[] = 'zero_width_bypass';
        }
        if (in_array('fullwidth_normalize', $decodePath) && $attackScore >= 20) {
            $score += 5;
            $indicators[] = 'fullwidth_bypass';
        }

        return min(30, $score);
    }

    private static function calcChainScore(array $prediction): int {
        if (!$prediction['chain_detected']) return 0;
        $riskMap = ['critical' => 100, 'high' => 80, 'medium' => 60];
        $riskScore = $riskMap[$prediction['chain_risk']] ?? 0;
        $progress = $prediction['chain_progress'] / 100;
        $score = (int)round($riskScore * $progress);
        $totalRequests = $prediction['total_requests'] ?? 0;
        if ($totalRequests >= 5) $score += 10;
        elseif ($totalRequests >= 3) $score += 5;
        return min(100, $score);
    }

    private static function buildBaseIndicators(array $charResult, array $wordResult, array $structResult, array $paramMismatches, array $businessResult, array $logicResult, array $intentResult, array $intentAnalyzerResult, array $obfuscationResult, array $chainInfo, array $memoryAnomalies, array $adversarialResult, array $multiVectorResult): array {
        $indicators = [];
        foreach ($charResult['indicators'] ?? [] as $ind) $indicators[] = '[L1] ' . $ind;
        foreach ($wordResult['keywords'] ?? [] as $kw) $indicators[] = '[L2] ' . $kw;
        foreach ($structResult['structures'] ?? [] as $s) $indicators[] = '[L3] ' . ($s['type'] ?? '') . ':' . ($s['desc'] ?? '');
        foreach ($paramMismatches as $pm) $indicators[] = '[L4] mismatch:' . $pm;
        if (!empty($businessResult['violations'])) foreach ($businessResult['violations'] as $v) $indicators[] = '[L5] ' . $v;
        foreach ($logicResult['details'] ?? [] as $d) $indicators[] = '[L6] ' . $d;
        if (!empty($intentResult['phase']) && $intentResult['phase'] !== 'none') $indicators[] = '[L7] ' . $intentResult['phase_name'];
        if (!empty($intentAnalyzerResult['primary_intent']) && $intentAnalyzerResult['primary_intent'] !== 'unknown') {
            $indicators[] = '[L7] intent:' . ($intentAnalyzerResult['primary_name'] ?? $intentAnalyzerResult['primary_intent']);
        }
        if (!empty($obfuscationResult['techniques'])) {
            foreach ($obfuscationResult['technique_names'] ?? [] as $ot) {
                $indicators[] = '[OBF] obfuscation:' . $ot;
            }
        }
        if (!empty($obfuscationResult['depth']) && $obfuscationResult['depth'] !== 'none') {
            $indicators[] = '[OBF] depth:' . ($obfuscationResult['depth_label'] ?? $obfuscationResult['depth']);
        }
        if (!empty($chainInfo['chain_detected'])) $indicators[] = '[L8] ' . $chainInfo['chain_name'];
        foreach ($memoryAnomalies as $ma) $indicators[] = '[L9] evolution:' . $ma;
        foreach ($adversarialResult['threat_names'] ?? [] as $at) $indicators[] = '[L10] adversarial:' . $at;
        foreach ($multiVectorResult['cross_indicators'] ?? [] as $mvi) $indicators[] = '[MV] ' . $mvi;
        return $indicators;
    }

    public static function getWeights(): array {
        return self::$weights;
    }

    /**
     * 内容类型感知路由：根据 Content-Type 和输入来源，
     * 决定哪些解析器激活、分析哪段文本，避免所有解析器无脑分析同一段混合文本。
     */
    private static function routeParsers(string $contentType, array $headers, string $body, array $params, string $uri, string $decodedText): array {
        $route = [
            'sql'     => '',
            'html'    => '',
            'php'     => '',
            'path'    => '',
            'command' => '',
            'xxe'     => '',
            'ssrf'    => '',
            'ssti'    => '',
            'deser'   => '',
            'crlf'    => '',
            'expr'    => '',
        ];

        $ct = strtolower($contentType);
        $uriParamsText = '';
        foreach ($params as $k => $v) {
            $uriParamsText .= (string)$k . '=' . (string)$v . ' ';
        }

        // 提取Body中的字符串值（用于SQL/命令/SSTI分析）
        $bodyStrings = '';
        if (!empty($body)) {
            $bodyStrings = $body;
            // JSON body：提取所有字符串值
            if (strpos($ct, 'application/json') !== false) {
                $json = json_decode($body, true);
                if (is_array($json)) {
                    $bodyStrings = self::extractStringValues($json);
                }
            }
        }

        // SQL解析器：URI参数 + Body字符串值（SQL注入通常发生在参数和body中）
        $route['sql'] = trim($uriParamsText . ' ' . $bodyStrings);
        if ($route['sql'] === '') $route['sql'] = $decodedText;

        // HTML解析器：仅在Content-Type为html或body包含HTML标签时
        if (strpos($ct, 'text/html') !== false || strpos($body, '<') !== false) {
            $route['html'] = !empty($body) ? $body : $decodedText;
        }

        // PHP解析器：Body + 文件上传参数 + URI参数
        $fileParams = '';
        foreach ($params as $k => $v) {
            if (stripos((string)$k, 'file') !== false || stripos((string)$k, 'upload') !== false || stripos((string)$k, 'path') !== false) {
                $fileParams .= (string)$v . ' ';
            }
        }
        $route['php'] = trim($bodyStrings . ' ' . $fileParams);
        if ($route['php'] === '') $route['php'] = $decodedText;

        // 路径遍历：URI参数 + 文件相关参数 + URI路径
        $route['path'] = trim($uriParamsText . ' ' . $fileParams . ' ' . $uri);
        if ($route['path'] === '') $route['path'] = $decodedText;

        // 命令注入：URI参数 + Body字符串
        $route['command'] = trim($uriParamsText . ' ' . $bodyStrings);
        if ($route['command'] === '') $route['command'] = $decodedText;

        // XXE解析器：仅在Content-Type为xml或body包含XML特征时
        if (strpos($ct, 'xml') !== false || strpos($body, '<?xml') !== false || strpos($body, '<!DOCTYPE') !== false) {
            $route['xxe'] = !empty($body) ? $body : $decodedText;
        }

        // SSRF解析器：URI中的URL参数 + Body中的URL + 所有参数值（SSRF可能藏在任意参数中）
        $urlParams = '';
        foreach ($params as $k => $v) {
            $val = (string)$v;
            $keyLower = strtolower((string)$k);
            // URL相关参数名优先
            if (strpos($keyLower, 'url') !== false || strpos($keyLower, 'link') !== false || strpos($keyLower, 'redirect') !== false || strpos($keyLower, 'host') !== false || strpos($keyLower, 'target') !== false) {
                $urlParams .= $val . ' ';
            }
            // 参数值本身是URL（以http://、https://、file://等开头）
            if (preg_match('#^(https?|file|gopher|dict|ldap|ftp|ssh|telnet)://#i', $val)) {
                $urlParams .= $val . ' ';
            }
        }
        $route['ssrf'] = trim($urlParams . ' ' . $bodyStrings);
        if ($route['ssrf'] === '') $route['ssrf'] = $decodedText;

        // SSTI：URI参数 + Body
        $route['ssti'] = trim($uriParamsText . ' ' . $bodyStrings);
        if ($route['ssti'] === '') $route['ssti'] = $decodedText;

        // 反序列化：检查Content-Type或body包含序列化特征时
        $isSerialized = false;
        if (strpos($ct, 'java-serialized-object') !== false || strpos($ct, 'phpserialized') !== false) {
            $isSerialized = true;
        }
        // PHP序列化格式：O:N:、a:N:、s:N:、i:、b:、d: 等
        if (preg_match('/^[Oa]:\d+:/i', $body) || preg_match('/\b[Oa]:\d+:"[^"]*":\d+:/i', $body)) {
            $isSerialized = true;
        }
        // Java序列化：以 rO0AB 开头的Base64
        if (strpos($body, 'rO0AB') === 0) {
            $isSerialized = true;
        }
        // JSON中嵌套序列化字符串
        if (preg_match('/"data"\s*:\s*"[Oa]:\d+:/i', $body)) {
            $isSerialized = true;
        }
        if ($isSerialized) {
            $route['deser'] = $body;
        }

        // CRLF：Headers + URI参数 + Body（CRLF可能出现在任何输入中）
        $headerText = '';
        foreach ($headers as $k => $v) {
            $headerText .= (string)$k . ': ' . (string)$v . ' ';
        }
        $route['crlf'] = trim($headerText . ' ' . $uriParamsText . ' ' . $bodyStrings);
        if ($route['crlf'] === '') $route['crlf'] = $decodedText;

        // 表达式注入：URI参数 + Body
        $route['expr'] = trim($uriParamsText . ' ' . $bodyStrings);
        if ($route['expr'] === '') $route['expr'] = $decodedText;

        return $route;
    }

    /**
     * 从嵌套数组中提取所有字符串值（用于JSON body分析）
     */
    private static function extractStringValues(array $data): string {
        $result = '';
        foreach ($data as $k => $v) {
            if (is_string($v)) {
                $result .= $v . ' ';
            } elseif (is_array($v)) {
                $result .= self::extractStringValues($v);
            }
        }
        return $result;
    }

    /**
     * 返回空的解析器结果（当路由决定该解析器不激活时）
     */
    private static function emptyParserResult(): array {
        return ['score' => 0, 'detected' => false];
    }

    /**
     * 明确攻击签名兜底加成
     * 当解析器得分偏低但文本包含明确攻击签名时，给予兜底分数
     */
    private static function calcSignatureBonus(string $text, int $currentScore): int {
        if ($currentScore >= 70) return $currentScore;
        
        $bonus = 0;
        $textLower = strtolower($text);
        
        // SQL注入签名
        if (preg_match('/\bunion\s+(all\s+)?select\b/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/\b(or|and)\s+\d+\s*=\s*\d+/i', $text)) $bonus = max($bonus, 60);
        if (preg_match("/\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?/i", $text)) $bonus = max($bonus, 55);
        if (preg_match('/\bwaitfor\s+delay\b/i', $text)) $bonus = max($bonus, 70);
        if (preg_match('/\bsleep\s*\(/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/\bextractvalue\s*\(/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/\bdrop\s+table\b/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/\binformation_schema\b/i', $text)) $bonus = max($bonus, 55);
        if (preg_match('/\bgroup_concat\s*\(/i', $text)) $bonus = max($bonus, 55);
        if (preg_match('/;\s*(drop|delete|update|insert)\b/i', $text)) $bonus = max($bonus, 60);
        
        // XSS签名
        if (preg_match('/<script\b/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/on(load|error|click|mouseover|focus|blur|change|submit)\s*=/i', $text)) $bonus = max($bonus, 55);
        if (preg_match('/javascript:/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/<svg\b/i', $text) && preg_match('/on\w+\s*=/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/<body\b/i', $text) && preg_match('/on\w+\s*=/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/<iframe\b/i', $text)) $bonus = max($bonus, 55);
        if (preg_match('/document\.cookie/i', $text)) $bonus = max($bonus, 55);
        if (preg_match('/eval\s*\(/i', $text) && preg_match('/string\.fromcharcode/i', $text)) $bonus = max($bonus, 70);
        
        // 命令注入签名
        if (preg_match('/;\s*(cat|ls|id|whoami|uname|wget|curl|rm|cp|mv)\b/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/\|\s*(cat|ls|id|whoami|uname|wget|curl)\b/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/`[^`]+`/', $text)) $bonus = max($bonus, 60);
        if (preg_match('/\$\([^)]+\)/', $text)) $bonus = max($bonus, 60);
        if (preg_match('/&&\s*(cat|ls|id|whoami|uname|wget|curl|rm)\b/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i', $text)) $bonus = max($bonus, 70);
        
        // 路径遍历签名
        if (preg_match('/\.\.[\/\\\\]/', $text)) $bonus = max($bonus, 60);
        if (preg_match('/\/etc\/passwd/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/\/etc\/shadow/i', $text)) $bonus = max($bonus, 70);
        
        // XXE签名
        if (preg_match('/<!ENTITY\b/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/<!DOCTYPE\b/i', $text) && preg_match('/SYSTEM\b/i', $text)) $bonus = max($bonus, 60);
        
        // SSRF签名
        if (preg_match('#https?://127\.0\.0\.1#i', $text)) $bonus = max($bonus, 65);
        if (preg_match('#https?://localhost#i', $text)) $bonus = max($bonus, 60);
        if (preg_match('#https?://169\.254\.169\.254#i', $text)) $bonus = max($bonus, 65);
        if (preg_match('#file:///#i', $text)) $bonus = max($bonus, 65);
        if (preg_match('#gopher://#i', $text)) $bonus = max($bonus, 65);
        if (preg_match('#dict://#i', $text)) $bonus = max($bonus, 60);
        
        // SSTI签名
        if (preg_match('/\{\{.*?\}\}/s', $text)) $bonus = max($bonus, 60);
        if (preg_match('/\$\{.*?\}/s', $text)) $bonus = max($bonus, 60);
        
        // 模板注入签名
        if (preg_match('/<%\s*=?\s*(Execute|Response|Request)/i', $text)) $bonus = max($bonus, 60); // ASP
        if (preg_match('/<\?=\s*system\s*\(/i', $text)) $bonus = max($bonus, 65); // PHP短标签
        if (preg_match('/\{system\s*\(/i', $text)) $bonus = max($bonus, 65); // Smarty
        
        // CRLF签名
        if (preg_match('/[\r\n]\s*(Set-Cookie|Location|Content-Type|Set-Location)/i', $text)) $bonus = max($bonus, 60);
        if (preg_match('/%0[dD]%0[aA]/i', $text)) $bonus = max($bonus, 55);
        
        // 反序列化签名
        if (preg_match('/^[Oa]:\d+:/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/O:\d+:"[^"]+":\d+:/i', $text)) $bonus = max($bonus, 65);
        if (preg_match('/PHP_Object_Injection/i', $text)) $bonus = max($bonus, 65);
        
        // OpenRedirect签名
        if (preg_match('#redirect\s*=\s*https?://(?!' . preg_quote($_SERVER['HTTP_HOST'] ?? 'localhost', '#') . ')#i', $text)) $bonus = max($bonus, 55);
        if (preg_match('#redirect\s*=\s*//#i', $text)) $bonus = max($bonus, 55);
        if (preg_match('#@[\w.-]+\s*$#i', $text) && preg_match('#https?://#i', $text)) $bonus = max($bonus, 55);
        
        return $bonus;
    }
}
