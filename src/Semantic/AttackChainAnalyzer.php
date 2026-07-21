<?php
/**
 * L8 攻击链时序关联分析引擎
 *
 * 职责：跨请求时序关联分析，构建攻击者行为画像，识别攻击链模式。
 *       通过分析同一IP的多步攻击行为序列，结合阶段状态机、时序模式、
 *       链模板匹配、序列相似度等多维能力，实现前瞻性威胁检测。
 *
 * 核心能力：
 *   A. 攻击阶段状态机 - RECON→SCAN→ENUM→INJECT→EXPLOIT→PERSIST→EXFIL
 *   B. 时序模式识别 - Burst/Sustained/Stealth 多时间窗口分析
 *   C. 攻击链模板库 - SQL注入侦察链/XSS投递链/认证绕过链/路径遍历链/Webshell链
 *   D. 行为序列相似度 - LCS最长公共子序列比较
 *   E. 阶段进展评估 - 当前步数/完成度/下一步预判
 *   F. 多维度风险评分 - 链匹配度+阶段深度+时序异常+复杂度
 *   G. 多链关联检测 - 并行多链/链切换识别（高级攻击者特征）
 *   H. 精细化时序窗口 - 短(60s)/中(600s)/长(3600s) 三窗口 Burst/Sustained/SlowBurn 分析
 *   I. 横向移动检测 - 跨 URI 路径的攻击链关联（A→B→C 系统渗透）
 *   J. 阶段转移概率 - 7x7 转移矩阵驱动的跳跃/回退异常评分
 *   K. 增强评分整合 - 多链+时序+横向+转移异常融合的综合评分
 */
defined('ABSPATH') || exit;

class AttackChainAnalyzer {

    /** @var int 每IP最大请求记录数 */
    const MAX_REQUESTS_PER_IP = 100;

    /** @var int 不活跃过期时间（秒）- 30分钟 */
    const INACTIVITY_TIMEOUT = 1800;

    /**
     * 攻击阶段定义及顺序
     * @var array<int,string>
     */
    private static $phaseOrder = [
        'RECON',     // 侦察阶段 - 信息收集、端口扫描、目录探测
        'SCAN',      // 扫描阶段 - 漏洞扫描、参数探测
        'ENUM',      // 枚举阶段 - 数据枚举、用户枚举
        'INJECT',    // 注入阶段 - 注入测试、Payload投递
        'EXPLOIT',   // 利用阶段 - 漏洞利用、权限获取
        'PERSIST',   // 持久化 - 后门植入、权限维持
        'EXFIL',     // 数据外泄 - 数据窃取、文件外传
    ];

    /**
     * 阶段转移条件：从哪些阶段可以转移到下一阶段
     * 允许正向推进，允许同阶段停留，允许跳过少量阶段
     *
     * @var array<string,array<string>>
     */
    private static $phaseTransitions = [
        'RECON'   => ['RECON', 'SCAN', 'ENUM'],
        'SCAN'    => ['RECON', 'SCAN', 'ENUM', 'INJECT'],
        'ENUM'    => ['SCAN', 'ENUM', 'INJECT', 'EXPLOIT'],
        'INJECT'  => ['ENUM', 'INJECT', 'EXPLOIT', 'PERSIST'],
        'EXPLOIT' => ['INJECT', 'EXPLOIT', 'PERSIST', 'EXFIL'],
        'PERSIST' => ['EXPLOIT', 'PERSIST', 'EXFIL'],
        'EXFIL'   => ['PERSIST', 'EXFIL'],
    ];

    /**
     * 攻击链模板库
     * 每条链包含：名称、描述、阶段节点序列、风险等级
     *
     * @var array<string,array>
     */
    private static $chainTemplates = [
        'sql_injection_recon' => [
            'name'        => 'SQL注入侦察链',
            'desc'        => '从参数探测到SQL注入利用的完整流程',
            'phases'      => ['RECON', 'SCAN', 'ENUM', 'INJECT', 'EXPLOIT', 'EXFIL'],
            'risk_level'  => 'critical',
            'keywords'    => ['select', 'union', 'information_schema', 'load_file', 'outfile'],
        ],
        'xss_delivery' => [
            'name'        => 'XSS投递链',
            'desc'        => '从XSS探测到脚本投递的攻击流程',
            'phases'      => ['RECON', 'SCAN', 'INJECT', 'EXPLOIT'],
            'risk_level'  => 'high',
            'keywords'    => ['script', 'onerror', 'javascript', 'cookie', 'document'],
        ],
        'auth_bypass' => [
            'name'        => '认证绕过链',
            'desc'        => '从登录探测到认证绕过的攻击流程',
            'phases'      => ['RECON', 'SCAN', 'ENUM', 'EXPLOIT'],
            'risk_level'  => 'high',
            'keywords'    => ['admin', 'login', 'password', 'or 1=1', 'union select'],
        ],
        'path_traversal' => [
            'name'        => '路径遍历链',
            'desc'        => '从目录探测到敏感文件读取的流程',
            'phases'      => ['RECON', 'SCAN', 'ENUM', 'EXPLOIT'],
            'risk_level'  => 'high',
            'keywords'    => ['../', 'etc/passwd', '..%2f', 'php://', 'file://'],
        ],
        'webshell_deploy' => [
            'name'        => 'Webshell部署链',
            'desc'        => '从上传探测到后门部署的完整流程',
            'phases'      => ['RECON', 'SCAN', 'INJECT', 'EXPLOIT', 'PERSIST'],
            'risk_level'  => 'critical',
            'keywords'    => ['upload', 'eval', 'assert', 'base64_decode', 'webshell'],
        ],
        // === 增强模板（v2 横向/提权/撞库）===
        'lateral_movement_chain' => [
            'name'        => '横向移动链',
            'desc'        => '跨系统渗透链：A系统注入 → B系统Webshell → C系统数据外传',
            'phases'      => ['RECON', 'SCAN', 'INJECT', 'EXPLOIT', 'PERSIST', 'EXFIL'],
            'risk_level'  => 'critical',
            'keywords'    => ['shell', 'ssh', 'psexec', 'lateral', 'pivot', 'internal'],
        ],
        'ssrf_to_rce_chain' => [
            'name'        => 'SSRF提权链',
            'desc'        => 'SSRF探测到内网RCE提权的攻击流程',
            'phases'      => ['RECON', 'SCAN', 'INJECT', 'EXPLOIT', 'PERSIST'],
            'risk_level'  => 'high',
            'keywords'    => ['localhost', '127.0.0.1', '169.254', 'metadata', 'gopher', 'dict'],
        ],
        'credential_stuffing_chain' => [
            'name'        => '撞库攻击链',
            'desc'        => '从登录枚举到撞库注入的认证攻击流程',
            'phases'      => ['RECON', 'SCAN', 'ENUM', 'INJECT'],
            'risk_level'  => 'high',
            'keywords'    => ['login', 'password', 'account', 'admin', 'signin', 'auth'],
        ],
    ];

    /**
     * 内存存储 - IP请求历史
     * 结构: [ip => ['requests' => [...], 'last_activity' => time, 'current_phase' => 'RECON']]
     *
     * @var array<string,array>
     */
    private static $ipHistory = [];

    /**
     * 活跃攻击链列表（多链关联检测用）
     * 结构: [ip => [['name'=>key, 'display'=>名称, 'progress'=>int, 'similarity'=>float, 'first_seen'=>ts, 'last_seen'=>ts], ...]]
     *
     * @var array<string,array>
     */
    private static $activeChains = [];

    /**
     * 阶段转移概率矩阵（7x7）
     * 行：源阶段；列：目标阶段。每行概率和≈1.0
     *
     * 异常判定规则：
     *   - 跳跃推进（如 RECON→EXPLOIT）概率 0.01，触发时 anomaly +20
     *   - 反向回退概率 0.05-0.1，触发时 anomaly +10
     *   - 极低概率/未知转移 anomaly +30
     *
     * @var array<string,array<string,float>>
     */
    private static $phaseTransitionProbabilities = [
        'RECON'   => ['RECON' => 0.40, 'SCAN' => 0.40, 'ENUM' => 0.15, 'INJECT' => 0.04, 'EXPLOIT' => 0.01, 'PERSIST' => 0.00, 'EXFIL' => 0.00],
        'SCAN'    => ['RECON' => 0.10, 'SCAN' => 0.35, 'ENUM' => 0.30, 'INJECT' => 0.20, 'EXPLOIT' => 0.04, 'PERSIST' => 0.01, 'EXFIL' => 0.00],
        'ENUM'    => ['RECON' => 0.05, 'SCAN' => 0.10, 'ENUM' => 0.30, 'INJECT' => 0.40, 'EXPLOIT' => 0.13, 'PERSIST' => 0.01, 'EXFIL' => 0.01],
        'INJECT'  => ['RECON' => 0.02, 'SCAN' => 0.03, 'ENUM' => 0.10, 'INJECT' => 0.30, 'EXPLOIT' => 0.45, 'PERSIST' => 0.08, 'EXFIL' => 0.02],
        'EXPLOIT' => ['RECON' => 0.01, 'SCAN' => 0.02, 'ENUM' => 0.03, 'INJECT' => 0.10, 'EXPLOIT' => 0.30, 'PERSIST' => 0.45, 'EXFIL' => 0.09],
        'PERSIST' => ['RECON' => 0.01, 'SCAN' => 0.01, 'ENUM' => 0.02, 'INJECT' => 0.05, 'EXPLOIT' => 0.15, 'PERSIST' => 0.40, 'EXFIL' => 0.36],
        'EXFIL'   => ['RECON' => 0.01, 'SCAN' => 0.01, 'ENUM' => 0.01, 'INJECT' => 0.03, 'EXPLOIT' => 0.05, 'PERSIST' => 0.15, 'EXFIL' => 0.74],
    ];

    /**
     * 记录请求到攻击链分析器
     *
     * @param string $ip         客户端IP
     * @param string $uri        请求URI
     * @param array  $params     请求参数
     * @param string $wordRole   词汇角色标注
     * @param string $intentPhase 意图阶段（来自IntentInference）
     * @param int    $logicScore 逻辑推理分数
     * @return void
     */
    public static function recordRequest(
        string $ip,
        string $uri,
        array $params = [],
        string $wordRole = '',
        string $intentPhase = '',
        int $logicScore = 0
    ) {
        $now = time();

        if (!isset(self::$ipHistory[$ip])) {
            self::$ipHistory[$ip] = [
                'requests'       => [],
                'last_activity'  => $now,
                'current_phase'  => 'RECON',
                'phase_counts'   => [],
                'start_time'     => $now,
            ];
        }

        $normalizedPhase = self::normalizePhase($intentPhase);

        $entry = [
            'time'         => $now,
            'uri'          => $uri,
            'params_count' => count($params),
            'word_role'    => $wordRole,
            'phase'        => $normalizedPhase,
            'logic_score'  => $logicScore,
            'param_sample' => self::extractParamSample($params),
        ];

        self::$ipHistory[$ip]['requests'][] = $entry;
        self::$ipHistory[$ip]['last_activity'] = $now;

        if (!isset(self::$ipHistory[$ip]['phase_counts'][$normalizedPhase])) {
            self::$ipHistory[$ip]['phase_counts'][$normalizedPhase] = 0;
        }
        self::$ipHistory[$ip]['phase_counts'][$normalizedPhase]++;

        $currentPhase = self::$ipHistory[$ip]['current_phase'];
        $currentIdx = self::phaseIndex($currentPhase);
        $newIdx = self::phaseIndex($normalizedPhase);
        if ($newIdx > $currentIdx) {
            self::$ipHistory[$ip]['current_phase'] = $normalizedPhase;
        }

        if (count(self::$ipHistory[$ip]['requests']) > self::MAX_REQUESTS_PER_IP) {
            self::$ipHistory[$ip]['requests'] = array_slice(
                self::$ipHistory[$ip]['requests'],
                -self::MAX_REQUESTS_PER_IP
            );
        }

        self::cleanupExpired();
    }

    /**
     * 获取IP的攻击链预测结果
     *
     * @param string $ip 客户端IP
     * @return array{
     *     score:int,
     *     phase:string,
     *     progress:int,
     *     risk:string,
     *     chain_name:string,
     *     chain_detected:?string,
     *     chain_progress:int,
     *     chain_risk:string,
     *     temporal_pattern:string,
     *     total_requests:int,
     *     phase_sequence:array,
     *     predicted_next:array,
     *     start_time:int,
     *     last_activity:int,
     *     active_chain_count:int,
     *     timing_pattern:array,
     *     lateral_movement:array,
     *     transition_anomaly:int
     * }
     */
    public static function getPrediction(string $ip): array {
        if (!isset(self::$ipHistory[$ip])) {
            return [
                'score'            => 0,
                'phase'            => 'RECON',
                'progress'         => 0,
                'risk'             => 'clean',
                'chain_name'       => '',
                'chain_detected'   => null,
                'chain_progress'   => 0,
                'chain_risk'       => 'none',
                'temporal_pattern' => 'normal',
                'total_requests'   => 0,
                'phase_sequence'   => [],
                'predicted_next'   => [],
                'start_time'       => 0,
                'last_activity'    => 0,
                // 增强字段（无数据时为零值/空数组）
                'active_chain_count' => 0,
                'timing_pattern'     => [],
                'lateral_movement'   => [],
                'transition_anomaly' => 0,
            ];
        }

        $history = self::$ipHistory[$ip];
        $requests = $history['requests'];
        $totalRequests = count($requests);

        $phaseSequence = self::extractPhaseSequence($requests);
        $currentPhase = $history['current_phase'];
        $phaseIndex = self::phaseIndex($currentPhase);
        $phaseProgress = (int)round(($phaseIndex + 1) / count(self::$phaseOrder) * 100);

        $temporalInfo = self::analyzeTemporalPattern($requests);
        $temporalPattern = $temporalInfo['pattern'];

        $chainMatch = self::matchBestChain($phaseSequence, $requests);
        $chainDetected = $chainMatch['chain_key'];
        $chainName = $chainMatch['chain_name'];
        $chainProgress = $chainMatch['progress'];
        $chainSimilarity = $chainMatch['similarity'];
        $chainRisk = $chainMatch['risk_level'];

        $riskScore = self::calculateRiskScore(
            $phaseIndex,
            $totalRequests,
            $chainSimilarity,
            $chainProgress,
            $temporalInfo,
            $requests
        );

        $predictedNext = self::predictNextPhase($currentPhase, $chainMatch);

        // 增强评分：多链关联 + 时序窗口 + 横向移动 + 阶段转移异常
        $enhanced = self::calcEnhancedScore($ip, [
            'base_score'    => $riskScore,
            'current_phase' => $currentPhase,
        ]);
        $riskScore = $enhanced['enhanced_score'];
        $riskLevel = self::scoreToRiskLevel($riskScore);

        return [
            'score'            => $riskScore,
            'phase'            => $currentPhase,
            'progress'         => $phaseProgress,
            'risk'             => $riskLevel,
            'chain_name'       => $chainName,
            'chain_detected'   => $chainDetected,
            'chain_progress'   => $chainProgress,
            'chain_risk'       => $chainRisk,
            'temporal_pattern' => $temporalPattern,
            'total_requests'   => $totalRequests,
            'phase_sequence'   => $phaseSequence,
            'predicted_next'   => $predictedNext,
            'start_time'       => $history['start_time'],
            'last_activity'    => $history['last_activity'],
            // 增强字段（多链关联/时序窗口/横向移动/转移异常）
            'active_chain_count' => $enhanced['active_chain_count'],
            'timing_pattern'     => $enhanced['timing_pattern'],
            'lateral_movement'   => $enhanced['lateral_movement'],
            'transition_anomaly' => $enhanced['transition_anomaly'],
        ];
    }

    /**
     * 判断是否应提前拦截
     *
     * @param string $ip 客户端IP
     * @return bool
     */
    public static function shouldBlockEarly(string $ip): bool {
        $prediction = self::getPrediction($ip);
        if ($prediction['score'] >= 70) {
            return true;
        }
        if ($prediction['chain_detected'] && $prediction['chain_progress'] >= 50) {
            $highRisk = ['critical', 'high'];
            if (in_array($prediction['chain_risk'], $highRisk, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 清理过期的IP记录
     *
     * @return void
     */
    public static function cleanupExpired() {
        $now = time();
        foreach (self::$ipHistory as $ip => $history) {
            if ($now - $history['last_activity'] > self::INACTIVITY_TIMEOUT) {
                unset(self::$ipHistory[$ip]);
                unset(self::$activeChains[$ip]);
            }
        }
    }

    /**
     * 清除指定IP的记录
     *
     * @param string $ip 客户端IP
     * @return void
     */
    public static function clearChain(string $ip) {
        unset(self::$ipHistory[$ip]);
        unset(self::$activeChains[$ip]);
    }

    // ====================================================================
    // A. 攻击阶段状态机
    // ====================================================================

    /**
     * 归一化阶段名称到标准7阶段模型
     *
     * @param string $phase 原始阶段名称
     * @return string 标准阶段名
     */
    private static function normalizePhase(string $phase): string {
        $phase = strtoupper(trim($phase));
        if ($phase === '' || $phase === 'NONE' || $phase === 'UNKNOWN') {
            return 'RECON';
        }

        $map = [
            'RECON'       => 'RECON',
            'RECONNAIS'   => 'RECON',
            'RECONNAISSANCE' => 'RECON',
            'SCAN'        => 'SCAN',
            'SCANNING'    => 'SCAN',
            'PROBE'       => 'SCAN',
            'PROBING'     => 'SCAN',
            'ENUM'        => 'ENUM',
            'ENUMERATION' => 'ENUM',
            'FINGERPRINT' => 'ENUM',
            'INJECT'      => 'INJECT',
            'INJECTION'   => 'INJECT',
            'ATTACK'      => 'INJECT',
            'ATTEMPT'     => 'INJECT',
            'EXPLOIT'     => 'EXPLOIT',
            'EXPLOITATION' => 'EXPLOIT',
            'BYPASS'      => 'EXPLOIT',
            'PERSIST'     => 'PERSIST',
            'PERSISTENCE' => 'PERSIST',
            'MAINTAIN'    => 'PERSIST',
            'EXFIL'       => 'EXFIL',
            'EXFILTRATION' => 'EXFIL',
            'DATA_THEFT'  => 'EXFIL',
            'DUMP'        => 'EXFIL',
        ];

        if (isset($map[$phase])) {
            return $map[$phase];
        }

        foreach ($map as $key => $value) {
            if (strpos($phase, $key) !== false) {
                return $value;
            }
        }

        return 'RECON';
    }

    /**
     * 获取阶段索引（0-based）
     *
     * @param string $phase 阶段名
     * @return int
     */
    private static function phaseIndex(string $phase): int {
        $idx = array_search($phase, self::$phaseOrder, true);
        return $idx !== false ? $idx : 0;
    }

    /**
     * 判断阶段转移是否有效
     *
     * @param string $from 源阶段
     * @param string $to   目标阶段
     * @return bool
     */
    private static function isValidTransition(string $from, string $to): bool {
        if (!isset(self::$phaseTransitions[$from])) {
            return true;
        }
        return in_array($to, self::$phaseTransitions[$from], true);
    }

    // ====================================================================
    // B. 时序模式识别
    // ====================================================================

    /**
     * 分析请求时序模式
     *
     * @param array $requests 请求列表
     * @return array{pattern:string, anomaly_score:int, request_rate:float, burst_count:int}
     */
    private static function analyzeTemporalPattern(array $requests): array {
        $count = count($requests);
        if ($count < 2) {
            return [
                'pattern'       => 'normal',
                'anomaly_score' => 0,
                'request_rate'  => 0.0,
                'burst_count'   => 0,
            ];
        }

        $intervals = [];
        for ($i = 1; $i < $count; $i++) {
            $delta = $requests[$i]['time'] - $requests[$i - 1]['time'];
            if ($delta >= 0) {
                $intervals[] = $delta;
            }
        }

        if (empty($intervals)) {
            return [
                'pattern'       => 'normal',
                'anomaly_score' => 0,
                'request_rate'  => 0.0,
                'burst_count'   => 0,
            ];
        }

        $totalTime = end($requests)['time'] - reset($requests)['time'];
        $avgInterval = $totalTime > 0 ? $totalTime / ($count - 1) : 0;
        $requestRate = $totalTime > 0 ? $count / $totalTime : 0;

        $burstCount = 0;
        $shortIntervalCount = 0;
        foreach ($intervals as $iv) {
            if ($iv <= 1) {
                $shortIntervalCount++;
            }
        }

        $burstThreshold = max(3, (int)($count * 0.3));
        if ($shortIntervalCount >= $burstThreshold) {
            $burstCount = $shortIntervalCount;
        }

        $pattern = 'normal';
        $anomalyScore = 0;

        if ($count >= 20 && $avgInterval <= 2) {
            $pattern = 'burst';
            $anomalyScore = 15;
        } elseif ($count >= 10 && $avgInterval <= 5) {
            $pattern = 'burst';
            $anomalyScore = 10;
        } elseif ($count >= 50 && $avgInterval <= 30) {
            $pattern = 'sustained';
            $anomalyScore = 8;
        } elseif ($count >= 20 && $avgInterval <= 60) {
            $pattern = 'sustained';
            $anomalyScore = 5;
        } elseif ($count >= 5 && $count <= 15 && $avgInterval >= 30 && $avgInterval <= 300) {
            $pattern = 'stealth';
            $anomalyScore = 3;
        }

        return [
            'pattern'       => $pattern,
            'anomaly_score' => $anomalyScore,
            'request_rate'  => $requestRate,
            'burst_count'   => $burstCount,
            'avg_interval'  => $avgInterval,
        ];
    }

    // ====================================================================
    // C. 攻击链模板库 & D. 行为序列相似度 (LCS)
    // ====================================================================

    /**
     * 从请求中提取阶段序列
     *
     * @param array $requests 请求列表
     * @return string[] 阶段序列
     */
    private static function extractPhaseSequence(array $requests): array {
        $sequence = [];
        $lastPhase = '';
        foreach ($requests as $req) {
            $phase = $req['phase'] ?? 'RECON';
            if ($phase !== $lastPhase) {
                $sequence[] = $phase;
                $lastPhase = $phase;
            }
        }
        return $sequence;
    }

    /**
     * 匹配最佳攻击链模板
     *
     * @param array $phaseSequence 阶段序列
     * @param array $requests      请求列表
     * @return array{chain_key:?string, chain_name:string, similarity:float, progress:int, risk_level:string}
     */
    private static function matchBestChain(array $phaseSequence, array $requests): array {
        $bestKey = null;
        $bestName = '';
        $bestSimilarity = 0.0;
        $bestProgress = 0;
        $bestRisk = 'none';

        if (count($phaseSequence) < 2) {
            return [
                'chain_key'    => null,
                'chain_name'   => '',
                'similarity'   => 0.0,
                'progress'     => 0,
                'risk_level'   => 'none',
            ];
        }

        foreach (self::$chainTemplates as $key => $template) {
            $templatePhases = $template['phases'];
            $lcsLength = self::lcsLength($phaseSequence, $templatePhases);

            $templateLen = count($templatePhases);
            $seqLen = count($phaseSequence);
            $maxLen = max($templateLen, $seqLen);
            $similarity = $maxLen > 0 ? $lcsLength / $maxLen : 0.0;

            if ($lcsLength >= 2 && $similarity > $bestSimilarity) {
                $bestKey = $key;
                $bestName = $template['name'];
                $bestSimilarity = $similarity;
                $bestProgress = (int)round($lcsLength / $templateLen * 100);
                $bestRisk = $template['risk_level'];
            }
        }

        if ($bestSimilarity < 0.3) {
            return [
                'chain_key'    => null,
                'chain_name'   => '',
                'similarity'   => 0.0,
                'progress'     => 0,
                'risk_level'   => 'none',
            ];
        }

        return [
            'chain_key'    => $bestKey,
            'chain_name'   => $bestName,
            'similarity'   => $bestSimilarity,
            'progress'     => $bestProgress,
            'risk_level'   => $bestRisk,
        ];
    }

    /**
     * 计算两个序列的最长公共子序列（LCS）长度
     *
     * @param array $seqA 序列A
     * @param array $seqB 序列B
     * @return int LCS长度
     */
    private static function lcsLength(array $seqA, array $seqB): int {
        $lenA = count($seqA);
        $lenB = count($seqB);

        if ($lenA === 0 || $lenB === 0) {
            return 0;
        }

        $prev = array_fill(0, $lenB + 1, 0);
        $curr = array_fill(0, $lenB + 1, 0);

        for ($i = 1; $i <= $lenA; $i++) {
            for ($j = 1; $j <= $lenB; $j++) {
                if ($seqA[$i - 1] === $seqB[$j - 1]) {
                    $curr[$j] = $prev[$j - 1] + 1;
                } else {
                    $curr[$j] = max($prev[$j], $curr[$j - 1]);
                }
            }
            $temp = $prev;
            $prev = $curr;
            $curr = $temp;
            for ($k = 0; $k <= $lenB; $k++) {
                $curr[$k] = 0;
            }
        }

        return $prev[$lenB];
    }

    // ====================================================================
    // E. 阶段进展评估
    // ====================================================================

    /**
     * 预测下一阶段
     *
     * @param string $currentPhase 当前阶段
     * @param array  $chainMatch   链匹配结果
     * @return string[] 预判的下一阶段
     */
    private static function predictNextPhase(string $currentPhase, array $chainMatch): array {
        $predictions = [];
        $currentIdx = self::phaseIndex($currentPhase);

        $nextIdx = $currentIdx + 1;
        if ($nextIdx < count(self::$phaseOrder)) {
            $predictions[] = self::$phaseOrder[$nextIdx];
        }

        if (!empty($chainMatch['chain_key'])) {
            $template = self::$chainTemplates[$chainMatch['chain_key']];
            $phases = $template['phases'];
            foreach ($phases as $i => $phase) {
                if ($phase === $currentPhase && $i + 1 < count($phases)) {
                    $nextChainPhase = $phases[$i + 1];
                    if (!in_array($nextChainPhase, $predictions, true)) {
                        $predictions[] = $nextChainPhase;
                    }
                    break;
                }
            }
        }

        return $predictions;
    }

    // ====================================================================
    // F. 多维度风险评分
    // ====================================================================

    /**
     * 计算综合风险分数
     *
     * 评分规则：
     * - 单阶段：10-20 分
     * - 跨阶段推进：30-50 分
     * - 链部分匹配（相似度30%-60%）：40-60 分
     * - 链高相似（相似度60%+）：70-90 分
     * - 时序异常：5-15 分
     * - 上限：100 分
     *
     * @param int   $phaseIndex     当前阶段索引
     * @param int   $totalRequests  总请求数
     * @param float $chainSim       链相似度 (0-1)
     * @param int   $chainProgress  链进展 (0-100)
     * @param array $temporalInfo   时序信息
     * @param array $requests       请求列表
     * @return int 风险分数 (0-100)
     */
    private static function calculateRiskScore(
        $phaseIndex,
        $totalRequests,
        $chainSim,
        $chainProgress,
        array $temporalInfo,
        array $requests
    ): int {
        $score = 0;

        $phaseCount = count(self::$phaseOrder);
        $phaseRatio = ($phaseIndex + 1) / $phaseCount;

        if ($phaseIndex === 0) {
            $phaseScore = 10;
        } elseif ($phaseIndex <= 2) {
            $phaseScore = 20;
        } elseif ($phaseIndex <= 4) {
            $phaseScore = 35;
        } else {
            $phaseScore = 50;
        }
        $score += $phaseScore;

        if ($chainSim >= 0.6) {
            $chainScore = 70 + (int)(($chainSim - 0.6) / 0.4 * 20);
            $score = max($score, $chainScore);
        } elseif ($chainSim >= 0.3) {
            $chainScore = 40 + (int)(($chainSim - 0.3) / 0.3 * 20);
            $score = max($score, $chainScore);
        }

        $temporalAnomaly = $temporalInfo['anomaly_score'] ?? 0;
        $score += $temporalAnomaly;

        $highScoreCount = 0;
        foreach ($requests as $req) {
            if (($req['logic_score'] ?? 0) >= 40) {
                $highScoreCount++;
            }
        }
        if ($highScoreCount >= 5) {
            $score += 10;
        } elseif ($highScoreCount >= 3) {
            $score += 5;
        }

        $score = min(100, $score);
        $score = max(0, $score);

        return (int)$score;
    }

    /**
     * 分数转风险等级
     *
     * @param int $score 分数
     * @return string 风险等级
     */
    private static function scoreToRiskLevel($score): string {
        if ($score >= 80) {
            return 'critical';
        }
        if ($score >= 60) {
            return 'high';
        }
        if ($score >= 40) {
            return 'medium';
        }
        if ($score >= 15) {
            return 'low';
        }
        return 'clean';
    }

    // ====================================================================
    // 辅助方法
    // ====================================================================

    /**
     * 从参数中提取样本（用于关键词匹配）
     *
     * @param array $params 参数数组
     * @return string 参数样本字符串
     */
    private static function extractParamSample(array $params): string {
        if (empty($params)) {
            return '';
        }
        $sample = [];
        foreach ($params as $key => $value) {
            if (is_string($value)) {
                $sample[] = $key . '=' . substr($value, 0, 50);
            }
            if (count($sample) >= 5) {
                break;
            }
        }
        return implode('&', $sample);
    }

    /**
     * 获取所有攻击链模板定义
     *
     * @return array
     */
    public static function getAllChainPatterns(): array {
        return self::$chainTemplates;
    }

    /**
     * 获取当前所有活跃IP记录数
     *
     * @return int
     */
    public static function getActiveIpCount(): int {
        self::cleanupExpired();
        return count(self::$ipHistory);
    }

    // ====================================================================
    // G. 多链关联检测（并行多链 / 链切换识别）
    // ====================================================================

    /**
     * 多链关联检测
     *
     * 分析 IP 历史请求中并存的多个攻击链，识别链切换行为：
     *   - 多并行链（>=2）→ 切换异常 +20 分（高级攻击者特征）
     *   - 链切换（前半段匹配A链，后半段匹配B链）→ +15 分
     *
     * 副作用：刷新 self::$activeChains[$ip] 缓存
     *
     * @param string $ip 客户端IP
     * @return array{
     *     chain_count:int,
     *     active_chains:array,
     *     switch_detected:bool,
     *     switch_anomaly:int
     * }
     */
    private static function detectMultiChains(string $ip): array {
        $empty = [
            'chain_count'     => 0,
            'active_chains'   => [],
            'switch_detected' => false,
            'switch_anomaly'  => 0,
        ];

        if (!isset(self::$ipHistory[$ip])) {
            self::$activeChains[$ip] = [];
            return $empty;
        }

        $requests = self::$ipHistory[$ip]['requests'];
        $phaseSequence = self::extractPhaseSequence($requests);

        if (count($phaseSequence) < 2) {
            self::$activeChains[$ip] = [];
            return $empty;
        }

        $now = time();
        $firstSeen = $requests[0]['time'] ?? $now;
        $lastSeen = $requests[count($requests) - 1]['time'] ?? $now;

        // 对每个模板计算 LCS 相似度，识别并行活跃链
        $activeChains = [];
        foreach (self::$chainTemplates as $key => $template) {
            $templatePhases = $template['phases'];
            $lcsLen = self::lcsLength($phaseSequence, $templatePhases);
            if ($lcsLen < 2) {
                continue;
            }
            $maxLen = max(count($templatePhases), count($phaseSequence));
            $similarity = $maxLen > 0 ? $lcsLen / $maxLen : 0.0;
            if ($similarity < 0.3) {
                continue;
            }
            $progress = (int)round($lcsLen / count($templatePhases) * 100);
            $activeChains[] = [
                'name'       => $key,
                'display'    => $template['name'],
                'progress'   => $progress,
                'similarity' => round($similarity, 3),
                'first_seen' => $firstSeen,
                'last_seen'  => $lastSeen,
            ];
        }

        // 链切换检测：将请求序列按时间分前后两半，分别找最佳匹配链
        $switchDetected = false;
        if (count($requests) >= 6 && count($activeChains) >= 1) {
            $mid = (int)(count($requests) / 2);
            $earlySeq = self::extractPhaseSequence(array_slice($requests, 0, $mid));
            $lateSeq  = self::extractPhaseSequence(array_slice($requests, $mid));
            $earlyBest = self::findDominantChainKey($earlySeq);
            $lateBest  = self::findDominantChainKey($lateSeq);
            if ($earlyBest !== null && $lateBest !== null && $earlyBest !== $lateBest) {
                $switchDetected = true;
            }
        }

        // 异常分：多并行链 +20，链切换 +15（上限 40）
        $switchAnomaly = 0;
        if (count($activeChains) >= 2) {
            $switchAnomaly += 20;
        }
        if ($switchDetected) {
            $switchAnomaly += 15;
        }
        $switchAnomaly = min(40, $switchAnomaly);

        // 刷新缓存
        self::$activeChains[$ip] = $activeChains;

        return [
            'chain_count'     => count($activeChains),
            'active_chains'   => $activeChains,
            'switch_detected' => $switchDetected,
            'switch_anomaly'  => $switchAnomaly,
        ];
    }

    /**
     * 找出阶段序列的最佳匹配链 key
     *
     * @param array $phaseSequence 阶段序列
     * @return string|null 链 key（相似度<0.3 返回 null）
     */
    private static function findDominantChainKey(array $phaseSequence): ?string {
        if (count($phaseSequence) < 2) {
            return null;
        }
        $bestKey = null;
        $bestSim = 0.0;
        foreach (self::$chainTemplates as $key => $template) {
            $templatePhases = $template['phases'];
            $lcsLen = self::lcsLength($phaseSequence, $templatePhases);
            if ($lcsLen < 2) {
                continue;
            }
            $maxLen = max(count($templatePhases), count($phaseSequence));
            $sim = $maxLen > 0 ? $lcsLen / $maxLen : 0.0;
            if ($sim > $bestSim) {
                $bestSim = $sim;
                $bestKey = $key;
            }
        }
        return $bestSim >= 0.3 ? $bestKey : null;
    }

    // ====================================================================
    // H. 精细化时序窗口分析（短/中/长三窗口）
    // ====================================================================

    /**
     * 精细化时序模式分析
     *
     * 基于三时间窗口检测攻击者的时序行为模式：
     *   - 短窗口（60秒）：>20 请求/分钟 → Burst 暴力模式，anomaly 25-40
     *   - 中窗口（600秒）：>60 请求/10分钟 → Sustained 持续渗透，anomaly 15-25
     *   - 长窗口（3600秒）：分散请求避开短窗告警 → Slow Burn 隐身模式
     *
     * Slow Burn + 阶段推进 → is_stealth=true，异常分 +15（隐身攻击者）
     *
     * @param string $ip 客户端IP
     * @return array{
     *     pattern:string,
     *     rate_per_minute:float,
     *     anomaly_score:int,
     *     is_stealth:bool
     * }
     */
    private static function analyzeTimingPattern(string $ip): array {
        $empty = [
            'pattern'         => 'normal',
            'rate_per_minute' => 0.0,
            'anomaly_score'   => 0,
            'is_stealth'      => false,
        ];

        if (!isset(self::$ipHistory[$ip])) {
            return $empty;
        }

        $requests = self::$ipHistory[$ip]['requests'];
        if (count($requests) < 2) {
            return $empty;
        }

        $now = time();
        $shortCount = 0;  // 60s 窗口
        $midCount   = 0;  // 600s 窗口
        $longCount  = 0;  // 3600s 窗口
        foreach ($requests as $req) {
            $age = $now - (int)($req['time'] ?? $now);
            if ($age <= 60)   $shortCount++;
            if ($age <= 600)  $midCount++;
            if ($age <= 3600) $longCount++;
        }

        $pattern       = 'normal';
        $anomaly       = 0;
        $isStealth     = false;
        $ratePerMinute = 0.0;

        $currentPhase  = self::$ipHistory[$ip]['current_phase'];
        $phaseAdvanced = self::phaseIndex($currentPhase) > 0;

        if ($shortCount > 20) {
            // Burst 暴力模式：25-40 分（随强度递增）
            $pattern = 'burst';
            $anomaly = 25 + min(15, (int)(($shortCount - 20) / 4));
            $ratePerMinute = (float)$shortCount; // 60s 窗口 → 直接为每分钟数
        } elseif ($midCount > 60) {
            // Sustained 持续渗透：15-25 分
            $pattern = 'sustained';
            $anomaly = 15 + min(10, (int)(($midCount - 60) / 12));
            $ratePerMinute = $midCount / 10.0;
        } elseif ($longCount >= 5 && $shortCount <= 5 && $midCount <= 30) {
            // Slow Burn 隐身模式：长窗有活动，短/中窗稀疏（避开告警）
            $pattern = 'slow_burn';
            $anomaly = 5;
            $ratePerMinute = $longCount / 60.0;
            // 隐身攻击者：阶段已推进却仍保持低速 → +15
            if ($phaseAdvanced) {
                $isStealth = true;
                $anomaly += 15;
            }
        } else {
            // normal：仍给出基于短窗的速率参考
            if ($shortCount > 0) {
                $ratePerMinute = (float)$shortCount;
            } elseif ($midCount > 0) {
                $ratePerMinute = $midCount / 10.0;
            } elseif ($longCount > 0) {
                $ratePerMinute = $longCount / 60.0;
            }
        }

        return [
            'pattern'         => $pattern,
            'rate_per_minute' => round($ratePerMinute, 2),
            'anomaly_score'   => $anomaly,
            'is_stealth'      => $isStealth,
        ];
    }

    // ====================================================================
    // I. 横向移动检测（跨 URI 路径的攻击链关联）
    // ====================================================================

    /**
     * 横向移动检测
     *
     * 分析同一 IP 在不同 URI 路径上的攻击链活动，识别横向移动模式：
     *   A系统SQL注入 → B系统Webshell → C系统数据外传
     *
     * 当 2 个及以上 URI 路径前缀出现 INJECT/EXPLOIT/PERSIST/EXFIL 活动，
     * 判定为横向移动，movement_score 30-50。
     *
     * @param string $ip 客户端IP
     * @return array{
     *     is_lateral:bool,
     *     affected_paths:array,
     *     movement_score:int
     * }
     */
    private static function detectLateralMovement(string $ip): array {
        $empty = [
            'is_lateral'     => false,
            'affected_paths' => [],
            'movement_score' => 0,
        ];

        if (!isset(self::$ipHistory[$ip])) {
            return $empty;
        }

        $requests = self::$ipHistory[$ip]['requests'];
        if (count($requests) < 2) {
            return $empty;
        }

        // 按 URI 前缀分组统计阶段
        $pathPhaseMap = [];  // [path_prefix => [phase => count]]
        foreach ($requests as $req) {
            $prefix = self::extractUriPathPrefix($req['uri'] ?? '');
            $phase  = $req['phase'] ?? 'RECON';
            if (!isset($pathPhaseMap[$prefix])) {
                $pathPhaseMap[$prefix] = [];
            }
            if (!isset($pathPhaseMap[$prefix][$phase])) {
                $pathPhaseMap[$prefix][$phase] = 0;
            }
            $pathPhaseMap[$prefix][$phase]++;
        }

        // 识别有"深度阶段"活动（INJECT 及之后）的路径
        $deepPhases = ['INJECT', 'EXPLOIT', 'PERSIST', 'EXFIL'];
        $affectedPaths = [];
        foreach ($pathPhaseMap as $prefix => $phaseCounts) {
            foreach ($deepPhases as $dp) {
                if (!empty($phaseCounts[$dp])) {
                    $affectedPaths[] = $prefix;
                    break;
                }
            }
        }

        $affectedCount = count($affectedPaths);
        if ($affectedCount < 2) {
            return $empty;
        }

        // 30-50 分：基础 30 + 每多一个路径 +5（上限 50）
        $score = 30 + min(20, ($affectedCount - 2) * 5);

        return [
            'is_lateral'     => true,
            'affected_paths' => $affectedPaths,
            'movement_score' => $score,
        ];
    }

    /**
     * 提取 URI 路径前缀（第一段）
     * 例：/api/v1/login → /api；/admin/users → /admin
     *
     * @param string $uri 原始 URI
     * @return string 路径前缀
     */
    private static function extractUriPathPrefix(string $uri): string {
        $path = parse_url($uri, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return '/';
        }
        $parts = explode('/', trim($path, '/'));
        $first = $parts[0] ?? '';
        return $first === '' ? '/' : '/' . $first;
    }

    // ====================================================================
    // J. 阶段转移概率异常评分
    // ====================================================================

    /**
     * 计算阶段转移异常分（基于 7x7 概率矩阵）
     *
     * 评分规则：
     *   - 概率 >= 0.20：正常推进，0 分
     *   - 概率 0.10-0.20：轻度异常，5 分
     *   - 概率 0.05-0.10：反向回退或小跳，10 分
     *   - 概率 0.01-0.05：跳跃推进（如 RECON→EXPLOIT），20 分
     *   - 概率 < 0.01 或未知：极低概率，30 分
     *
     * @param string $from 源阶段
     * @param string $to   目标阶段
     * @return int 异常分（0-30）
     */
    private static function calcTransitionAnomaly(string $from, string $to): int {
        $from = strtoupper(trim($from));
        $to   = strtoupper(trim($to));

        // 同阶段停留：无异常
        if ($from === $to) {
            return 0;
        }

        if (!isset(self::$phaseTransitionProbabilities[$from][$to])) {
            return 30;  // 未知转移
        }

        $prob = (float)self::$phaseTransitionProbabilities[$from][$to];

        if ($prob >= 0.20) {
            return 0;
        } elseif ($prob >= 0.10) {
            return 5;
        } elseif ($prob >= 0.05) {
            return 10;  // 反向回退
        } elseif ($prob >= 0.01) {
            return 20;  // 跳跃推进
        }
        return 30;  // 极低概率
    }

    // ====================================================================
    // K. 增强评分整合
    // ====================================================================

    /**
     * 增强评分整合
     *
     * 在基础评分（calculateRiskScore）之上，叠加多链关联、精细化时序、
     * 横向移动、阶段转移异常四类增强信号，输出最终综合分数（上限 100）。
     *
     * 评分叠加：
     *   - 多链并行异常：+10-40（switch_anomaly）
     *   - 时序模式异常：+15-40（timing anomaly_score）
     *   - 横向移动异常：+30-50（movement_score）
     *   - 阶段转移异常：+0-30（transition anomaly）
     *
     * chain_risk 字段语义（low/medium/high/critical）由 scoreToRiskLevel 保持不变。
     *
     * @param string $ip              客户端IP
     * @param array  $basePrediction  基础预测数据（含 base_score/current_phase）
     * @return array{
     *     enhanced_score:int,
     *     active_chain_count:int,
     *     timing_pattern:array,
     *     lateral_movement:array,
     *     transition_anomaly:int
     * }
     */
    private static function calcEnhancedScore(string $ip, array $basePrediction): array {
        $baseScore    = (int)($basePrediction['base_score'] ?? 0);

        $emptyResult = [
            'enhanced_score'     => $baseScore,
            'active_chain_count' => 0,
            'timing_pattern'     => [],
            'lateral_movement'   => [],
            'transition_anomaly' => 0,
        ];

        if (!isset(self::$ipHistory[$ip])) {
            return $emptyResult;
        }

        // 1. 多链关联异常
        $multiChain    = self::detectMultiChains($ip);
        $switchAnomaly = (int)$multiChain['switch_anomaly'];

        // 2. 精细化时序窗口异常
        $timing        = self::analyzeTimingPattern($ip);
        $timingAnomaly = (int)$timing['anomaly_score'];

        // 3. 横向移动异常
        $lateral       = self::detectLateralMovement($ip);
        $lateralScore  = (int)$lateral['movement_score'];

        // 4. 阶段转移异常（基于最后一次阶段切换）
        $transitionAnomaly = 0;
        $requests          = self::$ipHistory[$ip]['requests'];
        $phaseSequence     = self::extractPhaseSequence($requests);
        $seqCount          = count($phaseSequence);
        if ($seqCount >= 2) {
            $from = $phaseSequence[$seqCount - 2];
            $to   = $phaseSequence[$seqCount - 1];
            $transitionAnomaly = self::calcTransitionAnomaly($from, $to);
        }

        // 整合评分（上限 100）
        $enhancedScore = $baseScore + $switchAnomaly + $timingAnomaly + $lateralScore + $transitionAnomaly;
        $enhancedScore = max(0, min(100, $enhancedScore));

        return [
            'enhanced_score'     => $enhancedScore,
            'active_chain_count' => (int)$multiChain['chain_count'],
            'timing_pattern'     => $timing,
            'lateral_movement'   => $lateral,
            'transition_anomaly' => $transitionAnomaly,
        ];
    }
}
