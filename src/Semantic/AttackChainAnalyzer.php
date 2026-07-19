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
    ];

    /**
     * 内存存储 - IP请求历史
     * 结构: [ip => ['requests' => [...], 'last_activity' => time, 'current_phase' => 'RECON']]
     *
     * @var array<string,array>
     */
    private static $ipHistory = [];

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
     *     last_activity:int
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
}
