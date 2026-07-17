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
        'sql_parser'        => 0.07,
        'html_parser'       => 0.05,
        'php_parser'        => 0.05,
        'path_parser'       => 0.06,
        'command_parser'    => 0.06,
        'xxe_parser'        => 0.05,
        'ssrf_parser'       => 0.05,
        'ssti_parser'       => 0.05,
        'deser_parser'      => 0.05,
        'crlf_parser'       => 0.04,
        'expr_parser'       => 0.05,
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
        string $method = 'GET'
    ): array {
        if ($text === '' && empty($params) && empty($multiVectorData)) {
            return self::emptyResult();
        }

        // ---- 基础10维分析 ----
        $baseResult = self::baseAnalyze($text, $uri, $params, $normalizerContext, $ip, $multiVectorData);

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
    private static function baseAnalyze(string $text, string $uri, array $params, array $normalizerContext, string $ip, array $multiVectorData): array {
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

        // ---- 深度语义解析器（真正的语法分析，不是正则匹配） ----
        $sqlParserResult = SqlSemanticParser::analyze($decodedText);
        $htmlParserResult = HtmlSemanticParser::analyze($decodedText);
        $phpParserResult = PhpCodeSemanticParser::analyze($decodedText);
        $pathParserResult = PathTraversalSemanticParser::analyze($decodedText);
        $commandParserResult = CommandInjectionSemanticParser::analyze($decodedText);
        $xxeParserResult = XxeSemanticParser::analyze($decodedText);
        $ssrfParserResult = SsrfSemanticParser::analyze($decodedText);
        $sstiParserResult = SstiSemanticParser::analyze($decodedText);
        $deserParserResult = DeserializationSemanticParser::analyze($decodedText);
        $crlfParserResult = CrlfInjectionSemanticParser::analyze($decodedText);
        $exprParserResult = ExpressionInjectionSemanticParser::analyze($decodedText);

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
        return count(array_filter($scores, fn($s) => $s >= 50));
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
}
