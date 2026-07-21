<?php
/**
 * 语义记忆池引擎（L9 - 行为基线偏差检测）
 *
 * 从"文件匹配计数"升级为"行为基线偏差检测"。为每个 IP 建立正常行为基线
 * （常用 URI、参数模式、请求频率、活跃时段、复杂度等），通过六大能力识别真实威胁：
 *   A. 行为基线建模 B. 多维偏差检测 C. 行为漂移检测
 *   D. 异常累积评分 E. 攻击者识别  F. 群体行为对比
 *
 * 评分：单维度偏差 10-20；多维交叉（2维+5, 3维+10, 4+维+15）；漂移 15-25；
 *       攻击者加成 5-15；总分上限 100；新 IP（无基线）0 分。
 *
 * 公共 API：
 *   record($ip, $text, $uri, $params, $features): void
 *   analyzeEvolution($ip, $currentFeatures): array  // ['score' => int, 'anomalies' => array]
 */
defined('ABSPATH') || exit;

class SemanticMemoryPool {
    const MAX_HISTORY_PER_IP = 100;
    const BASELINE_MIN_SAMPLES = 5;
    const BASELINE_WINDOW = 10;
    const INACTIVE_TTL = 1800;
    const FREQ_WINDOW = 60;
    const ACCUM_HALFLIFE = 600;
    const PERSIST_DIR = '/tmp/shield_memory';
    const PERSIST_FILE = 'memory_pool.json';
    const PERSIST_INTERVAL = 30;

    /** @var array<string,array> IP 行为历史记录 */
    private static $histories = [];
    /** @var array<string,array> IP 行为基线（基于历史，不含当前请求） */
    private static $baselines = [];
    /** @var array<string,array> IP 异常累积器（时间衰减累积评分） */
    private static $anomalyAccumulator = [];
    /** @var array<string,string> IP 攻击者画像 */
    private static $actorProfiles = [];
    /** 是否已从持久化存储加载 */
    private static $loaded = false;
    /** 内存中是否有未持久化的修改 */
    private static $dirty = false;
    /** 上次持久化时间 */
    private static $lastPersistTime = 0;
    /** shutdown函数是否已注册 */
    private static $shutdownRegistered = false;

    /** 注册 shutdown 函数，确保请求结束时持久化 */
    private static function registerShutdown() {
        if (self::$shutdownRegistered) return;
        self::$shutdownRegistered = true;
        register_shutdown_function(function () {
            if (self::$dirty) {
                self::persist();
            }
        });
    }

    /** 记录一次请求到记忆池，并基于历史（不含当前）重建基线。 */
    public static function record(string $ip, string $text, string $uri, array $params, array $features) {
        self::ensureLoaded();
        $now = microtime(true);

        if (!isset(self::$histories[$ip])) {
            self::$histories[$ip] = [
                'first_seen' => $now, 'last_seen' => $now,
                'total_requests' => 0, 'records' => [],
            ];
        }

        // 先用历史（不含当前请求）构建基线，确保偏差检测对比的是"过去 vs 当前"
        self::$baselines[$ip] = self::buildBaseline($ip);

        // 再追加当前请求记录
        self::$histories[$ip]['records'][] = self::buildRecord($text, $uri, $params, $features, $now);
        self::$histories[$ip]['last_seen'] = $now;
        self::$histories[$ip]['total_requests']++;

        if (count(self::$histories[$ip]['records']) > self::MAX_HISTORY_PER_IP) {
            self::$histories[$ip]['records'] = array_slice(
                self::$histories[$ip]['records'], -self::MAX_HISTORY_PER_IP
            );
        }

        self::cleanupIfStale($now);

        self::$dirty = true;
        self::registerShutdown();
    }

    /** 行为演化分析：对比当前请求与历史基线，输出异常分数与异常标签。 @return array{score:int, anomalies:array} */
    public static function analyzeEvolution(string $ip, array $currentFeatures): array {
        self::ensureLoaded();

        // 新 IP 或基线样本不足 → 0 分（无基线不可靠）
        if (!isset(self::$histories[$ip])
            || self::$histories[$ip]['total_requests'] < self::BASELINE_MIN_SAMPLES
            || !isset(self::$baselines[$ip])
            || (self::$baselines[$ip]['sample_count'] ?? 0) < self::BASELINE_MIN_SAMPLES) {
            return ['score' => 0, 'anomalies' => [], 'baseline_exists' => false];
        }

        $history = self::$histories[$ip];
        $anomalies = [];

        // B. 多维偏差检测（核心）
        $deviations = self::detectDeviations($ip, $currentFeatures);
        foreach ($deviations['labels'] as $label) {
            $anomalies[] = $label;
        }
        // C. 行为漂移检测
        $drift = self::detectDrift($ip, $history);
        foreach ($drift['labels'] as $label) {
            $anomalies[] = $label;
        }
        // D. 异常累积评分（仅统计过去，不含当前，避免双重计分）
        $accumulated = self::accumulateAnomalyScore($ip, $deviations);
        // E. 攻击者识别加成
        $actor = self::identifyActor($ip, $history);
        if ($actor['bonus'] > 0) {
            $anomalies[] = 'actor:' . $actor['type'];
        }
        // F. 群体行为对比（可选，数据不足跳过）
        $cohort = self::compareWithCohort($ip);
        if ($cohort['deviation'] > 0) {
            $anomalies[] = 'cohort_outlier';
        }

        // === 深度增强检测（L9+） ===

        // G. 基线漂移精细化检测（多维基线模型）
        $baselineDrift = self::detectBaselineDrift($ip, $currentFeatures);
        if ($baselineDrift['is_abnormal']) {
            $anomalies[] = 'drift:multidim';
            foreach ($baselineDrift['drift_dimensions'] as $dim) {
                $anomalies[] = 'drift_dim:' . $dim;
            }
        }

        // H. 多维特征向量距离检测
        $featureDistance = 0.0;
        $hasFeatureDistance = false;
        $records = self::$histories[$ip]['records'];
        $last = end($records);
        if ($last !== false && isset($last['feature_vector']) && is_array($last['feature_vector'])) {
            $baselineFv = self::computeAvgFeatureVector($ip);
            if ($baselineFv !== null) {
                $featureDistance = self::calcFeatureDistance($last['feature_vector'], $baselineFv);
                $hasFeatureDistance = true;
                if ($featureDistance > 0.5) {
                    $anomalies[] = 'feature_distance';
                }
            }
        }

        // I. 群体离群点检测（全局群体对比）
        $population = self::compareWithPopulation($ip);
        if ($population['is_outlier']) {
            $anomalies[] = 'population_outlier';
        }

        // J. 行为序列模式异常
        $behaviorAnomaly = self::detectBehaviorAnomaly($ip);
        if ($behaviorAnomaly['pattern_changed']) {
            $anomalies[] = 'behavior_pattern_change';
        }

        // K. 加权异常累积（维度差异化权重：drift 0.5x / pattern 0.8x / velocity 0.6x）
        $weightedAccum = self::accumulateWithWeights($ip, $anomalies);

        // 评分汇总 + 多维交叉加成：2维+5, 3维+10, 4+维+15
        $devScore = $deviations['score'];
        $dimCount = $deviations['dimension_count'];
        if ($dimCount >= 4) {
            $devScore += 15;
        } elseif ($dimCount === 3) {
            $devScore += 10;
        } elseif ($dimCount === 2) {
            $devScore += 5;
        }

        $total = $devScore
            + $drift['score']
            + $accumulated['score']
            + $actor['bonus']
            + $cohort['deviation']
            + $baselineDrift['drift_score']
            + ($featureDistance > 0.5 ? 15 : 0)
            + ($population['is_outlier'] ? 20 : 0)
            + $behaviorAnomaly['change_score']
            + $weightedAccum;
        $total = max(0, min(100, (int) round($total)));

        $result = [
            'score' => $total,
            'anomalies' => array_values(array_unique($anomalies)),
            'baseline_exists' => true,
        ];

        // 新增字段（仅在数据充足时填充）
        if ($baselineDrift['drift_score'] > 0 || !empty($baselineDrift['drift_dimensions'])) {
            $result['drift_score'] = $baselineDrift['drift_score'];
            $result['drift_dimensions'] = $baselineDrift['drift_dimensions'];
        }
        if ($hasFeatureDistance) {
            $result['feature_distance'] = round($featureDistance, 4);
        }
        if ($population['is_outlier'] || $population['deviation'] > 0.0) {
            $result['is_outlier'] = $population['is_outlier'];
        }
        if ($behaviorAnomaly['change_score'] > 0) {
            $result['behavior_change_score'] = $behaviorAnomaly['change_score'];
        }

        return $result;
    }

    /** A. 行为基线建模：最近 BASELINE_WINDOW 条加权样本（越近权重越大），含 URI/参数/频率/时段/复杂度/风险等统计量。 */
    private static function buildBaseline(string $ip): array {
        $records = self::$histories[$ip]['records'] ?? [];
        $n = count($records);
        if ($n === 0) {
            return ['sample_count' => 0];
        }

        $window = array_slice($records, -self::BASELINE_WINDOW);
        $wCount = count($window);
        $weights = [];
        $wSum = 0.0;
        for ($i = 0; $i < $wCount; $i++) {
            $w = 0.5 + 0.5 * ($i + 1) / $wCount; // 线性 0.5→1.0
            $weights[$i] = $w;
            $wSum += $w;
        }

        $uriSet = []; $paramKeysSet = [];
        $sumParamCount = 0.0; $sumTextLength = 0.0; $sumEntropy = 0.0;
        $sumSpecial = 0.0; $sumComplexity = 0.0; $sumRiskScore = 0.0; $sumIndicators = 0.0;
        $sumLScores = ['l1' => 0.0, 'l2' => 0.0, 'l3' => 0.0, 'l4' => 0.0,
                       'l5' => 0.0, 'l6' => 0.0, 'l7' => 0.0, 'l8' => 0.0];
        $riskLevels = ['clean' => 0.0, 'low' => 0.0, 'medium' => 0.0, 'high' => 0.0, 'critical' => 0.0];
        $activeHours = []; $intervals = []; $prevTs = null;

        foreach ($window as $idx => $rec) {
            $w = $weights[$idx];
            $uriSet[$rec['uri_hash']] = ($uriSet[$rec['uri_hash']] ?? 0.0) + $w;
            foreach ($rec['param_keys'] as $pk) {
                $paramKeysSet[$pk] = ($paramKeysSet[$pk] ?? 0.0) + $w;
            }
            $sumParamCount += $rec['param_count'] * $w;
            $sumTextLength += $rec['text_length'] * $w;
            $sumEntropy    += $rec['char_entropy'] * $w;
            $sumSpecial    += $rec['special_ratio'] * $w;
            $sumComplexity += $rec['complexity'] * $w;
            $sumRiskScore  += $rec['risk_score'] * $w;
            $sumIndicators += $rec['indicators_count'] * $w;
            foreach ($sumLScores as $lk => $_) {
                $sumLScores[$lk] += ($rec['l_scores'][$lk] ?? 0) * $w;
            }
            $rl = $rec['risk_level'];
            if (isset($riskLevels[$rl])) {
                $riskLevels[$rl] += $w;
            }
            $hour = (int) gmdate('G', (int) $rec['ts']);
            $activeHours[$hour] = ($activeHours[$hour] ?? 0.0) + $w;
            if ($prevTs !== null) {
                $intervals[] = max(0.0, $rec['ts'] - $prevTs);
            }
            $prevTs = $rec['ts'];
        }

        arsort($riskLevels);
        $riskMode = 'clean';
        foreach ($riskLevels as $lvl => $cnt) {
            if ($cnt > 0) { $riskMode = $lvl; break; }
        }
        $avgInterval = count($intervals) > 0 ? array_sum($intervals) / count($intervals) : 0.0;
        $avgLScores = [];
        foreach ($sumLScores as $lk => $v) {
            $avgLScores[$lk] = $wSum > 0 ? $v / $wSum : 0.0;
        }

        return [
            'sample_count'      => $n,
            'window_count'      => $wCount,
            'uri_set'           => $uriSet,
            'param_keys_set'    => $paramKeysSet,
            'avg_param_count'   => $wSum > 0 ? $sumParamCount / $wSum : 0.0,
            'avg_text_length'   => $wSum > 0 ? $sumTextLength / $wSum : 0.0,
            'avg_char_entropy'  => $wSum > 0 ? $sumEntropy / $wSum : 0.0,
            'avg_special_ratio' => $wSum > 0 ? $sumSpecial / $wSum : 0.0,
            'avg_complexity'    => $wSum > 0 ? $sumComplexity / $wSum : 0.0,
            'avg_risk_score'    => $wSum > 0 ? $sumRiskScore / $wSum : 0.0,
            'avg_indicators'    => $wSum > 0 ? $sumIndicators / $wSum : 0.0,
            'avg_l_scores'      => $avgLScores,
            'avg_interval'      => $avgInterval,
            'active_hours'      => $activeHours,
            'risk_level_mode'   => $riskMode,
            'built_at'          => microtime(true),
        ];
    }

    /** B. 多维偏差检测：URI / 参数 / 频率 / 时段 / 复杂度 / 风险分数 / 指标。 @return array{score:int, dimension_count:int, labels:array} */
    private static function detectDeviations(string $ip, array $currentFeatures): array {
        $baseline = self::$baselines[$ip];
        $records = self::$histories[$ip]['records'];
        $last = end($records);
        if ($last === false) {
            return ['score' => 0, 'dimension_count' => 0, 'labels' => []];
        }

        $score = 0; $dimCount = 0; $labels = [];

        // B1. URI 偏差：访问从未在基线中出现过的端点
        if (!isset($baseline['uri_set'][$last['uri_hash']])) {
            $score += 12; $dimCount++; $labels[] = 'dev:new_uri';
        }
        // B2. 参数偏差：新增未知参数键 或 参数数量显著变化
        $newParamKeys = 0;
        foreach ($last['param_keys'] as $pk) {
            if (!isset($baseline['param_keys_set'][$pk])) {
                $newParamKeys++;
            }
        }
        $paramCountDelta = abs($last['param_count'] - $baseline['avg_param_count']);
        $paramThreshold = max(2, $baseline['avg_param_count']);
        if ($newParamKeys > 0 || $paramCountDelta > $paramThreshold) {
            $score += $newParamKeys > 0 ? 12 : 10;
            $dimCount++; $labels[] = 'dev:param_set_change';
        }
        // B3. 频率偏差：请求速率突增（当前最近窗口 vs 基线平均间隔）
        $recentCount = self::countRecent($records, self::FREQ_WINDOW);
        $avgInterval = $baseline['avg_interval'];
        if ($avgInterval > 0) {
            $baselineFreqPerMin = 60.0 / $avgInterval;
            $ratio = $baselineFreqPerMin > 0 ? $recentCount / $baselineFreqPerMin : 0.0;
            if ($ratio >= 10 && $recentCount >= 5) {
                $score += 20; $dimCount++; $labels[] = 'dev:freq_burst';
            } elseif ($ratio >= 3 && $recentCount >= 5) {
                $score += 15; $dimCount++; $labels[] = 'dev:freq_burst';
            }
        } elseif ($recentCount >= 10) {
            $score += 15; $dimCount++; $labels[] = 'dev:freq_burst';
        }
        // B4. 时段偏差：在基线从未活跃过的时段请求
        $currentHour = (int) gmdate('G', (int) $last['ts']);
        $activeHours = $baseline['active_hours'];
        $totalHourWeight = array_sum($activeHours);
        if ($totalHourWeight > 0 && ($baseline['window_count'] ?? 0) >= 5) {
            if (($activeHours[$currentHour] ?? 0.0) <= 0.0) {
                $score += 10; $dimCount++; $labels[] = 'dev:off_hours';
            }
        }
        // B5. 复杂度偏差：请求复杂度突增
        $currentComplexity = $last['complexity'];
        $baselineComplexity = $baseline['avg_complexity'];
        if ($baselineComplexity > 0 && $currentComplexity >= $baselineComplexity * 3 && $currentComplexity >= 30) {
            $score += 15; $dimCount++; $labels[] = 'dev:complexity_spike';
        } elseif ($baselineComplexity > 0 && $currentComplexity >= $baselineComplexity * 2 && $currentComplexity >= 25) {
            $score += 12; $dimCount++; $labels[] = 'dev:complexity_spike';
        }
        // B6. 风险分数偏差：风险分数突然升高
        $currentRiskScore = $last['risk_score'];
        $baselineRiskScore = $baseline['avg_risk_score'];
        if ($currentRiskScore >= 50 && $baselineRiskScore <= 15) {
            $score += 20; $dimCount++; $labels[] = 'dev:risk_score_spike';
        } elseif ($currentRiskScore >= 30 && $baselineRiskScore <= 10) {
            $score += 15; $dimCount++; $labels[] = 'dev:risk_score_spike';
        }
        // B7. 指标偏差：攻击指标数量突增
        if ($last['indicators_count'] >= 3 && $baseline['avg_indicators'] <= 1) {
            $score += 12; $dimCount++; $labels[] = 'dev:indicators_burst';
        }

        return [
            'score' => min(100, $score),
            'dimension_count' => $dimCount,
            'labels' => $labels,
        ];
    }

    /** C. 行为漂移检测：URI 多样性渐升、风险分数趋势、攻击阶段递进、行为熵突增。 @return array{score:int, labels:array} */
    private static function detectDrift(string $ip, array $history): array {
        $records = $history['records'];
        $n = count($records);
        if ($n < self::BASELINE_MIN_SAMPLES) {
            return ['score' => 0, 'labels' => []];
        }
        $score = 0; $labels = [];

        // C1. URI 多样性渐升：历史分前后两半对比
        $half = (int) floor($n / 2);
        if ($half >= 3) {
            $firstUris = []; $secondUris = [];
            foreach (array_slice($records, 0, $half) as $r) {
                $firstUris[$r['uri_hash']] = true;
            }
            foreach (array_slice($records, $half) as $r) {
                $secondUris[$r['uri_hash']] = true;
            }
            $firstDiv = count($firstUris) / $half;
            $secondDiv = count($secondUris) / count($secondUris) > 0 ? count($secondUris) / (count($records) - $half) : 0;
            if ($secondDiv > $firstDiv * 2 && count($secondUris) >= 4) {
                $score += 15; $labels[] = 'drift:uri_diversity_rising';
            }
        }
        // C2. 风险分数渐升趋势：最近 5 条线性回归斜率为正且终点高于起点
        $recent5 = array_slice($records, -5);
        if (count($recent5) >= 4) {
            $riskScores = [];
            foreach ($recent5 as $r) {
                $riskScores[] = $r['risk_score'];
            }
            $trend = self::linearTrend($riskScores);
            if ($trend > 0.5 && end($riskScores) > reset($riskScores) + 15) {
                $score += 15; $labels[] = 'drift:risk_rising';
            }
        }
        // C3. 攻击阶段递进：最近窗口后半段阶段高于前半段
        $phaseProgress = ['none' => 0, 'recon' => 1, 'probe' => 2,
                          'attempt' => 3, 'attack' => 4, 'exploit' => 5];
        $recentPhases = [];
        foreach (array_slice($records, -6) as $r) {
            $recentPhases[] = $phaseProgress[$r['attack_phase']] ?? 0;
        }
        if (count($recentPhases) >= 4) {
            $cut = (int) floor(count($recentPhases) / 2);
            $firstAvg = array_sum(array_slice($recentPhases, 0, $cut)) / $cut;
            $lastSlice = array_slice($recentPhases, $cut);
            $lastAvg = array_sum($lastSlice) / count($lastSlice);
            if ($lastAvg > $firstAvg && $lastAvg >= 2) {
                $score += 15; $labels[] = 'drift:phase_escalation';
            }
        }
        // C4. 行为熵突增：最近 10 条 URI 分布的 Shannon 熵
        $recentUris = [];
        foreach (array_slice($records, -10) as $r) {
            $recentUris[$r['uri_hash']] = ($recentUris[$r['uri_hash']] ?? 0) + 1;
        }
        $recentEntropy = self::shannonEntropyCounts(array_values($recentUris));
        if ($recentEntropy > 2.5 && count($recentUris) >= 6) {
            $score += 10; $labels[] = 'drift:behavior_entropy_spike';
        }

        return ['score' => min(25, $score), 'labels' => $labels];
    }

    /** D. 异常累积评分：多次小偏差累积，时间衰减（半衰期 10 分钟）；仅统计过去累积避免双重计分。 @return array{score:int} */
    private static function accumulateAnomalyScore(string $ip, array $deviations): array {
        $now = microtime(true);
        if (!isset(self::$anomalyAccumulator[$ip])) {
            self::$anomalyAccumulator[$ip] = [];
        }
        // 清理过期累积记录
        $cutoff = $now - self::INACTIVE_TTL;
        self::$anomalyAccumulator[$ip] = array_values(array_filter(
            self::$anomalyAccumulator[$ip],
            function ($a) use ($cutoff) { return $a['ts'] >= $cutoff; }
        ));
        // 仅统计过去累积（不含当前），折扣 0.15 避免与当前 devScore 重复计分
        $accumScore = 0.0;
        foreach (self::$anomalyAccumulator[$ip] as $a) {
            $ageSec = $now - $a['ts'];
            $decay = exp(-$ageSec / self::ACCUM_HALFLIFE * log(2));
            $accumScore += $a['score'] * $decay * 0.15;
        }
        // 累积次数加成：3 次以上小偏差累积 → 额外加成
        $count = count(self::$anomalyAccumulator[$ip]);
        $countBonus = 0;
        if ($count >= 5) {
            $countBonus = 10;
        } elseif ($count >= 3) {
            $countBonus = 5;
        }
        // 将当前偏差记入累积器供未来请求使用
        if ($deviations['dimension_count'] > 0) {
            self::$anomalyAccumulator[$ip][] = [
                'ts' => $now, 'score' => $deviations['score'],
                'dims' => $deviations['dimension_count'],
            ];
        }
        return ['score' => min(20, (int) round($accumScore) + $countBonus)];
    }

    /** E. 攻击者识别：扫描器（高频+高 URI 覆盖）/ 爬虫（高频全 clean）/ 手动攻击者（低频+侦察+高风险）。 @return array{type:string, bonus:int} */
    private static function identifyActor(string $ip, array $history): array {
        $records = $history['records'];
        $n = count($records);
        if ($n < 3) {
            return ['type' => 'unknown', 'bonus' => 0];
        }
        $recent60 = self::countRecent($records, 60);
        $uriSet = []; $riskHigh = 0; $phaseRecon = 0; $allClean = true;
        foreach ($records as $r) {
            $uriSet[$r['uri_hash']] = true;
            if ($r['risk_score'] >= 40) { $riskHigh++; }
            if ($r['risk_score'] > 5) { $allClean = false; }
            if ($r['attack_phase'] === 'recon' || $r['attack_phase'] === 'probe') {
                $phaseRecon++;
            }
        }
        $uriCount = count($uriSet);
        $uriCoverage = $n > 0 ? $uriCount / $n : 0.0;

        // E1. 扫描器特征：极高频 或 高频+高 URI 覆盖
        if ($recent60 >= 20) {
            self::$actorProfiles[$ip] = 'scanner';
            return ['type' => 'scanner', 'bonus' => 12];
        }
        if ($recent60 >= 10 && $uriCoverage >= 0.5 && $uriCount >= 4) {
            self::$actorProfiles[$ip] = 'scanner';
            return ['type' => 'scanner', 'bonus' => 8];
        }
        // E2. 手动攻击者特征：有侦察阶段 + 风险高 + 低频
        if ($phaseRecon >= 2 && $riskHigh >= 1 && $recent60 <= 8) {
            self::$actorProfiles[$ip] = 'manual_attacker';
            return ['type' => 'manual_attacker', 'bonus' => 10];
        }
        if ($riskHigh >= 2 && $phaseRecon >= 1) {
            self::$actorProfiles[$ip] = 'manual_attacker';
            return ['type' => 'manual_attacker', 'bonus' => 8];
        }
        // E3. 爬虫特征：高频但风险全 clean + URI 多样
        if ($recent60 >= 8 && $allClean && $uriCount >= 4) {
            self::$actorProfiles[$ip] = 'crawler';
            return ['type' => 'crawler', 'bonus' => 0];
        }
        return ['type' => 'normal', 'bonus' => 0];
    }

    /** F. 群体行为对比：与同网段其他 IP 对比；同网段不足 3 个时跳过。 @return array{deviation:int} */
    private static function compareWithCohort(string $ip): array {
        $segment = self::extractSegment($ip);
        if ($segment === '') {
            return ['deviation' => 0];
        }
        $cohortScores = [];
        foreach (self::$histories as $otherIp => $h) {
            if ($otherIp === $ip || self::extractSegment($otherIp) !== $segment) {
                continue;
            }
            $recs = $h['records'];
            if (empty($recs)) {
                continue;
            }
            $sum = 0;
            foreach ($recs as $r) { $sum += $r['risk_score']; }
            $cohortScores[] = $sum / count($recs);
        }
        if (count($cohortScores) < 3) {
            return ['deviation' => 0];
        }
        $myRecs = self::$histories[$ip]['records'];
        $mySum = 0;
        foreach ($myRecs as $r) { $mySum += $r['risk_score']; }
        $myAvg = count($myRecs) > 0 ? $mySum / count($myRecs) : 0.0;
        $cohortAvg = array_sum($cohortScores) / count($cohortScores);
        $cohortStd = self::stdDev($cohortScores);
        // 当前 IP 显著高于群体（>1.5σ 且绝对差 >= 25）
        if ($cohortStd > 0 && ($myAvg - $cohortAvg) > 1.5 * $cohortStd
            && ($myAvg - $cohortAvg) >= 25) {
            return ['deviation' => 12];
        }
        return ['deviation' => 0];
    }

    /** 构建单条请求记录（含多维特征向量、UA、HTTP 方法，供 L9+ 深度分析使用） */
    private static function buildRecord(string $text, string $uri, array $params, array $features, $ts): array {
        $lScores = [
            'l1' => $features['l1_char_score'] ?? 0, 'l2' => $features['l2_word_score'] ?? 0,
            'l3' => $features['l3_structure_score'] ?? 0, 'l4' => $features['l4_param_score'] ?? 0,
            'l5' => $features['l5_business_score'] ?? 0, 'l6' => $features['l6_logic_score'] ?? 0,
            'l7' => $features['l7_intent_score'] ?? 0, 'l8' => $features['l8_chain_score'] ?? 0,
        ];
        $entropy = self::shannonEntropy($text);
        $special = self::specialRatio($text);
        return [
            'ts' => $ts, 'uri' => $uri, 'uri_hash' => md5($uri),
            'param_keys' => array_values(array_map('strval', array_keys($params))),
            'param_count' => count($params), 'text_length' => strlen($text),
            'char_entropy' => $entropy, 'special_ratio' => $special,
            'complexity' => self::complexity($text, $params, $lScores, $entropy, $special),
            'risk_level' => $features['risk_level'] ?? 'clean',
            'risk_score' => self::numericRiskScore($features),
            'attack_phase' => $features['attack_phase'] ?? 'none',
            'l_scores' => $lScores,
            'indicators_count' => count($features['indicators'] ?? []),
            'feature_vector' => self::extractFeatureVector($text, $uri, $params, $features),
            'ua' => (string) ($features['ua'] ?? $features['user_agent'] ?? ''),
            'method' => (string) ($features['method'] ?? 'GET'),
        ];
    }

    /** 综合复杂度评分（0-70）：文本长度 + 参数数 + L层分数 + 熵 + 特殊字符 */
    private static function complexity(string $text, array $params, array $lScores, $entropy, $special) {
        $lenScore = min(30, strlen($text) / 4);
        $paramScore = min(15, count($params) * 3);
        $lAvg = array_sum($lScores) / max(1, count($lScores));
        $entropyScore = min(15, $entropy * 3);
        $specialScore = min(10, $special / 5);
        return $lenScore + $paramScore + $lAvg * 0.3 + $entropyScore + $specialScore;
    }

    /** 将 risk_level + L 层分数汇总为数值风险分数（0-100） */
    private static function numericRiskScore(array $features) {
        $levelMap = ['clean' => 0, 'low' => 20, 'medium' => 45, 'high' => 70, 'critical' => 90];
        $levelScore = $levelMap[$features['risk_level'] ?? 'clean'] ?? 0;
        $lScores = [
            $features['l1_char_score'] ?? 0, $features['l2_word_score'] ?? 0,
            $features['l3_structure_score'] ?? 0, $features['l4_param_score'] ?? 0,
            $features['l5_business_score'] ?? 0, $features['l6_logic_score'] ?? 0,
            $features['l7_intent_score'] ?? 0, $features['l8_chain_score'] ?? 0,
        ];
        return max($levelScore, (float) max($lScores));
    }

    /** Shannon 熵（按字节） */
    private static function shannonEntropy(string $text) {
        $len = strlen($text);
        if ($len === 0) { return 0.0; }
        $freq = count_chars($text, 1);
        $entropy = 0.0;
        foreach ($freq as $cnt) {
            $p = $cnt / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    /** 由频次数组计算 Shannon 熵（用于行为多样性） */
    private static function shannonEntropyCounts(array $counts) {
        $total = array_sum($counts);
        if ($total <= 0) { return 0.0; }
        $entropy = 0.0;
        foreach ($counts as $c) {
            if ($c <= 0) { continue; }
            $p = $c / $total;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    /** 特殊字符占比（百分比） */
    private static function specialRatio(string $text) {
        $len = strlen($text);
        if ($len === 0) { return 0.0; }
        $special = '<>"\';%|&`$(){}\\/*#=?![]';
        $count = 0;
        for ($i = 0; $i < $len; $i++) {
            if (strpos($special, $text[$i]) !== false) { $count++; }
        }
        return round($count / $len * 100, 2);
    }

    /** 统计最近 N 秒内的请求数 */
    private static function countRecent(array $records, $windowSec) {
        $cutoff = microtime(true) - $windowSec;
        $count = 0;
        foreach ($records as $r) {
            if ($r['ts'] >= $cutoff) { $count++; }
        }
        return $count;
    }

    /** 简单线性回归斜率（用于趋势检测） */
    private static function linearTrend(array $values) {
        $n = count($values);
        if ($n < 2) { return 0.0; }
        $sumX = 0.0; $sumY = 0.0; $sumXY = 0.0; $sumXX = 0.0;
        for ($i = 0; $i < $n; $i++) {
            $x = $i; $y = $values[$i];
            $sumX += $x; $sumY += $y; $sumXY += $x * $y; $sumXX += $x * $x;
        }
        $denom = $n * $sumXX - $sumX * $sumX;
        if ($denom == 0) { return 0.0; }
        return ($n * $sumXY - $sumX * $sumY) / $denom;
    }

    /** 标准差 */
    private static function stdDev(array $values) {
        $n = count($values);
        if ($n < 2) { return 0.0; }
        $mean = array_sum($values) / $n;
        $sum = 0.0;
        foreach ($values as $v) {
            $diff = $v - $mean;
            $sum += $diff * $diff;
        }
        return sqrt($sum / $n);
    }

    /** 提取 IP 的网段（IPv4 取前三段，IPv6 取前两段） */
    private static function extractSegment(string $ip) {
        if (strpos($ip, ':') !== false) {
            $parts = explode(':', $ip);
            return implode(':', array_slice($parts, 0, 2));
        }
        $parts = explode('.', $ip);
        if (count($parts) === 4) {
            return implode('.', array_slice($parts, 0, 3));
        }
        return '';
    }

    /** 懒清理：清理超过 INACTIVE_TTL 未活跃的 IP */
    private static function cleanupIfStale($now) {
        $cutoff = $now - self::INACTIVE_TTL;
        foreach (self::$histories as $ip => $h) {
            if ($h['last_seen'] < $cutoff) {
                unset(
                    self::$histories[$ip], self::$baselines[$ip],
                    self::$anomalyAccumulator[$ip], self::$actorProfiles[$ip]
                );
            }
        }
    }

    /** 公共清理入口（可由外部调度） */
    public static function cleanup() {
        self::ensureLoaded();
        self::cleanupIfStale(microtime(true));
        self::persist();
    }

    /** 获取 IP 行为画像（调试 / 监控用） */
    public static function getProfile(string $ip): array {
        self::ensureLoaded();
        if (!isset(self::$histories[$ip])) {
            return ['exists' => false];
        }
        $h = self::$histories[$ip];
        return [
            'exists' => true,
            'total_requests' => $h['total_requests'],
            'first_seen' => $h['first_seen'],
            'last_seen' => $h['last_seen'],
            'recent_count' => count($h['records']),
            'baseline' => self::$baselines[$ip] ?? null,
            'actor_profile' => self::$actorProfiles[$ip] ?? 'unknown',
            'anomaly_history' => self::$anomalyAccumulator[$ip] ?? [],
        ];
    }

    /** 确保从持久化存储加载（仅一次） */
    private static function ensureLoaded() {
        if (self::$loaded) { return; }
        self::$loaded = true;
        $file = self::persistPath();
        if ($file === '') { return; }
        $content = @file_get_contents($file);
        if ($content === false) { return; }
        $data = json_decode($content, true);
        if (!is_array($data)) { return; }
        self::$histories = $data['histories'] ?? [];
        self::$baselines = $data['baselines'] ?? [];
        self::$anomalyAccumulator = $data['anomaly_accumulator'] ?? [];
        self::$actorProfiles = $data['actor_profiles'] ?? [];
        self::cleanupIfStale(microtime(true));
    }

    /** 持久化到 /tmp/shield_memory/（延迟批量写入，避免每次请求I/O） */
    private static function persist() {
        if (!self::$dirty) return;
        $now = time();
        if ($now - self::$lastPersistTime < self::PERSIST_INTERVAL) return;
        self::$lastPersistTime = $now;
        self::$dirty = false;

        $file = self::persistPath();
        if ($file === '') { return; }
        $data = [
            'histories' => self::$histories, 'baselines' => self::$baselines,
            'anomaly_accumulator' => self::$anomalyAccumulator,
            'actor_profiles' => self::$actorProfiles,
        ];
        @file_put_contents($file, json_encode($data), LOCK_EX);
    }

    /** 获取持久化文件路径（目录不可写时返回空串） */
    private static function persistPath() {
        $dir = self::PERSIST_DIR;
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0700, true)) { return ''; }
        }
        if (!is_writable($dir)) { return ''; }
        return $dir . '/' . self::PERSIST_FILE;
    }

    /**
     * G. 多维基线建模：构建精细化的多维基线模型
     * 包含 URI 频率集中度、参数数量统计、payload 大小、活跃小时、风险趋势、UA 多样性
     * @param string $ip 客户端 IP
     * @return array 多维基线模型
     */
    private static function buildMultiDimBaseline(string $ip): array {
        $records = self::$histories[$ip]['records'] ?? [];
        $n = count($records);
        if ($n === 0) {
            return ['sample_count' => 0];
        }

        // URI 频率与集中度
        $uriFreq = [];
        foreach ($records as $r) {
            $uriFreq[$r['uri_hash']] = ($uriFreq[$r['uri_hash']] ?? 0) + 1;
        }
        arsort($uriFreq);
        $mostCommonUri = (string) array_key_first($uriFreq);
        $mostCommonCount = (int) reset($uriFreq);
        $concentration = $n > 0 ? $mostCommonCount / $n : 0.0;

        // 参数数量统计
        $paramCounts = array_column($records, 'param_count');
        $paramMean = !empty($paramCounts) ? array_sum($paramCounts) / count($paramCounts) : 0.0;
        $paramStd = self::stdDev($paramCounts);

        // payload 大小统计
        $payloadSizes = array_column($records, 'text_length');
        $payloadMean = !empty($payloadSizes) ? array_sum($payloadSizes) / count($payloadSizes) : 0.0;
        $payloadStd = self::stdDev($payloadSizes);

        // 活跃小时统计
        $activeHours = [];
        foreach ($records as $r) {
            $hour = (int) gmdate('G', (int) $r['ts']);
            $activeHours[$hour] = ($activeHours[$hour] ?? 0) + 1;
        }
        arsort($activeHours);
        $topHours = array_keys($activeHours);

        // 风险趋势（线性回归斜率）
        $riskScores = array_column($records, 'risk_score');
        $slope = self::linearTrend($riskScores);
        $isIncreasing = $slope > 0.0;

        // UA 多样性
        $uas = [];
        foreach ($records as $r) {
            $ua = $r['ua'] ?? '';
            if ($ua !== '') {
                $uas[$ua] = true;
            }
        }
        $uaCount = count($uas);
        $uaChanging = $uaCount > 1;

        return [
            'sample_count' => $n,
            'uri_freq' => [
                'most_common' => $mostCommonUri,
                'concentration' => round($concentration, 4),
            ],
            'param_count' => [
                'mean' => round($paramMean, 2),
                'stddev' => round($paramStd, 2),
            ],
            'payload_size' => [
                'mean' => round($payloadMean, 2),
                'stddev' => round($payloadStd, 2),
            ],
            'active_hours' => $topHours,
            'risk_trend' => [
                'slope' => round($slope, 4),
                'is_increasing' => $isIncreasing,
            ],
            'ua_diversity' => [
                'count' => $uaCount,
                'is_changing' => $uaChanging,
            ],
        ];
    }

    /**
     * G. 基线漂移精细化检测：对比当前请求与多维基线
     * - URI 集中度突变（如 0.6→0.2）→ drift_score +15
     * - payload 大小偏离 2σ → drift_score +10
     * - 活跃小时突变（白天→凌晨） → drift_score +20
     * - UA 切换 → drift_score +15
     * - 风险趋势斜率突然上升 → drift_score +25
     * @param string $ip 客户端 IP
     * @param array $currentFeatures 当前请求特征
     * @return array{drift_score:int, drift_dimensions:array, is_abnormal:bool}
     */
    private static function detectBaselineDrift(string $ip, array $currentFeatures): array {
        $empty = ['drift_score' => 0, 'drift_dimensions' => [], 'is_abnormal' => false];
        if (!isset(self::$histories[$ip])) {
            return $empty;
        }
        $records = self::$histories[$ip]['records'];
        if (count($records) < self::BASELINE_MIN_SAMPLES) {
            return $empty;
        }

        $baseline = self::buildMultiDimBaseline($ip);
        if (($baseline['sample_count'] ?? 0) < self::BASELINE_MIN_SAMPLES) {
            return $empty;
        }

        $last = end($records);
        if ($last === false) {
            return $empty;
        }

        $driftScore = 0;
        $driftDimensions = [];

        // 1. URI 集中度突变：基线高集中度突然分散
        $uriFreq = $baseline['uri_freq'];
        $baseConcentration = $uriFreq['concentration'];
        $currentUriHash = $last['uri_hash'];
        $currentUriCount = 0;
        foreach ($records as $r) {
            if ($r['uri_hash'] === $currentUriHash) { $currentUriCount++; }
        }
        $currentConcentration = count($records) > 0 ? $currentUriCount / count($records) : 0.0;
        if ($baseConcentration >= 0.5 && $currentConcentration < $baseConcentration * 0.4) {
            $driftScore += 15;
            $driftDimensions[] = 'uri_concentration_drop';
        }

        // 2. payload 大小偏离 2σ
        $payloadStats = $baseline['payload_size'];
        if ($payloadStats['stddev'] > 0) {
            $zScore = abs($last['text_length'] - $payloadStats['mean']) / $payloadStats['stddev'];
            if ($zScore >= 2.0) {
                $driftScore += 10;
                $driftDimensions[] = 'payload_size_deviation';
            }
        }

        // 3. 活跃小时突变（白天突然凌晨活跃）
        $currentHour = (int) gmdate('G', (int) $last['ts']);
        $activeHours = $baseline['active_hours'];
        $isNightHour = ($currentHour < 6 || $currentHour >= 22);
        $baselineHasNight = false;
        foreach ($activeHours as $h) {
            if ($h < 6 || $h >= 22) {
                $baselineHasNight = true;
                break;
            }
        }
        if ($isNightHour && !$baselineHasNight) {
            $driftScore += 20;
            $driftDimensions[] = 'active_hours_shift';
        }

        // 4. UA 切换检测（当前 UA 不在历史中出现过）
        $currentUa = $last['ua'] ?? '';
        if ($currentUa !== '') {
            $uaSeen = false;
            foreach ($records as $r) {
                if (($r['ua'] ?? '') === $currentUa) {
                    $uaSeen = true;
                    break;
                }
            }
            if (!$uaSeen) {
                $driftScore += 15;
                $driftDimensions[] = 'ua_switch';
            }
        }

        // 5. 风险趋势斜率突然上升
        $riskTrend = $baseline['risk_trend'];
        if ($riskTrend['is_increasing'] && $riskTrend['slope'] > 1.0) {
            $driftScore += 25;
            $driftDimensions[] = 'risk_trend_spike';
        }

        $driftScore = min(100, $driftScore);
        return [
            'drift_score' => $driftScore,
            'drift_dimensions' => $driftDimensions,
            'is_abnormal' => $driftScore >= 20,
        ];
    }

    /**
     * H. 多维特征向量提取：提取 12 维归一化特征向量
     * 维度：payload_length / param_count / entropy / special_char_ratio
     *       numeric_ratio / uppercase_ratio / non_ascii_ratio
     *       url_depth / path_segment_count / query_param_count
     *       risk_score / encoding_depth
     * @param string $text 请求文本
     * @param string $uri 请求 URI
     * @param array $params 请求参数
     * @param array $features 特征数组
     * @return array 12 维归一化（0-1）特征向量
     */
    private static function extractFeatureVector(string $text, string $uri, array $params, array $features): array {
        $len = strlen($text);
        $paramCount = count($params);

        // payload_length 归一化（基准 4096 字节）
        $payloadLength = min(1.0, $len / 4096.0);

        // param_count 归一化（基准 20 个参数）
        $paramCountNorm = min(1.0, $paramCount / 20.0);

        // entropy 归一化（最大 8 bit）
        $entropy = self::shannonEntropy($text);
        $entropyNorm = min(1.0, $entropy / 8.0);

        // special_char_ratio 归一化
        $special = self::specialRatio($text) / 100.0;
        $specialNorm = min(1.0, max(0.0, $special));

        // numeric_ratio：数字字符占比
        $numericRatio = $len > 0 ? self::countNumeric($text) / $len : 0.0;

        // uppercase_ratio：大写字母占比
        $uppercaseRatio = $len > 0 ? self::countUppercase($text) / $len : 0.0;

        // non_ascii_ratio：非 ASCII 字节占比
        $nonAsciiRatio = $len > 0 ? self::countNonAscii($text) / $len : 0.0;

        // url_depth：URI 中斜杠深度（基准 10）
        $urlDepth = min(1.0, substr_count($uri, '/') / 10.0);

        // path_segment_count：路径段数（归一化）
        $parsedPath = parse_url($uri, PHP_URL_PATH);
        $path = ($parsedPath === false || $parsedPath === null) ? $uri : (string) $parsedPath;
        $pathSegments = $path !== '' ? explode('/', trim($path, '/')) : [];
        $pathSegments = array_filter($pathSegments, function ($s) { return $s !== ''; });
        $pathSegmentCount = min(1.0, count($pathSegments) / 10.0);

        // query_param_count：查询参数数量（归一化）
        $queryParamCount = min(1.0, $paramCount / 20.0);

        // risk_score 归一化
        $riskScore = min(1.0, self::numericRiskScore($features) / 100.0);

        // encoding_depth：URL 编码层数（基准 3 层）
        $encodingDepth = min(1.0, self::detectEncodingDepth($text) / 3.0);

        return [
            'payload_length' => $payloadLength,
            'param_count' => $paramCountNorm,
            'entropy' => $entropyNorm,
            'special_char_ratio' => $specialNorm,
            'numeric_ratio' => $numericRatio,
            'uppercase_ratio' => $uppercaseRatio,
            'non_ascii_ratio' => $nonAsciiRatio,
            'url_depth' => $urlDepth,
            'path_segment_count' => $pathSegmentCount,
            'query_param_count' => $queryParamCount,
            'risk_score' => $riskScore,
            'encoding_depth' => $encodingDepth,
        ];
    }

    /**
     * H. 特征向量欧氏距离计算
     * 距离 >0.5 → 异常分 +15
     * @param array $v1 特征向量 1
     * @param array $v2 特征向量 2
     * @return float 欧氏距离
     */
    private static function calcFeatureDistance(array $v1, array $v2): float {
        $sum = 0.0;
        foreach ($v1 as $key => $val) {
            $other = $v2[$key] ?? 0.0;
            $diff = (float) $val - (float) $other;
            $sum += $diff * $diff;
        }
        return sqrt($sum);
    }

    /**
     * K. 加权异常累积评分：不同维度异常差异化权重
     * - drift 0.5x / pattern 0.8x / velocity 0.6x
     * - 单次累积上限 30（防止短时间误判封死）
     * @param string $ip 客户端 IP
     * @param array $anomalies 异常标签数组
     * @return int 本次累积分数
     */
    private static function accumulateWithWeights(string $ip, array $anomalies): int {
        if (empty($anomalies)) {
            return 0;
        }

        $weights = [
            'drift' => 0.5,
            'pattern' => 0.8,
            'velocity' => 0.6,
        ];

        // 每个异常的基础分
        $baseScore = 10;
        $totalScore = 0;

        foreach ($anomalies as $anomaly) {
            $dim = self::classifyAnomalyDimension($anomaly);
            $weight = $weights[$dim] ?? 1.0;
            $totalScore += (int) round($baseScore * $weight);
        }

        // 单次累积上限 30
        return min(30, $totalScore);
    }

    /**
     * I. 群体对比增强：对比当前 IP 与全局群体基线（前 100 个 IP 聚合）
     * 检测离群点（如访问频率超过群体 95 分位）→ 异常分 +20
     * @param string $ip 客户端 IP
     * @return array{is_outlier:bool, deviation:float, outlier_dimensions:array}
     */
    private static function compareWithPopulation(string $ip): array {
        $empty = ['is_outlier' => false, 'deviation' => 0.0, 'outlier_dimensions' => []];
        if (!isset(self::$histories[$ip])) {
            return $empty;
        }

        // 聚合全局群体基线（最多 100 个 IP）
        $population = [];
        foreach (self::$histories as $otherIp => $h) {
            if (count($population) >= 100) { break; }
            $recs = $h['records'];
            if (empty($recs)) { continue; }

            $riskSum = 0;
            $paramSum = 0;
            $payloadSum = 0;
            foreach ($recs as $r) {
                $riskSum += $r['risk_score'];
                $paramSum += $r['param_count'];
                $payloadSum += $r['text_length'];
            }
            $n = count($recs);
            $population[] = [
                'ip' => $otherIp,
                'avg_risk' => $riskSum / $n,
                'avg_param' => $paramSum / $n,
                'avg_payload' => $payloadSum / $n,
                'request_count' => $n,
            ];
        }

        // 群体样本数不足 5 个时跳过
        if (count($population) < 5) {
            return $empty;
        }

        // 群体统计量
        $riskValues = array_column($population, 'avg_risk');
        $paramValues = array_column($population, 'avg_param');
        $payloadValues = array_column($population, 'avg_payload');
        $requestCounts = array_column($population, 'request_count');

        sort($riskValues);
        sort($requestCounts);

        $riskP95 = self::percentile($riskValues, 95.0);
        $requestP95 = self::percentile($requestCounts, 95.0);
        $paramMean = array_sum($paramValues) / count($paramValues);
        $paramStd = self::stdDev($paramValues);
        $payloadMean = array_sum($payloadValues) / count($payloadValues);
        $payloadStd = self::stdDev($payloadValues);

        // 当前 IP 统计
        $myRecs = self::$histories[$ip]['records'];
        $myRiskSum = 0; $myParamSum = 0; $myPayloadSum = 0;
        foreach ($myRecs as $r) {
            $myRiskSum += $r['risk_score'];
            $myParamSum += $r['param_count'];
            $myPayloadSum += $r['text_length'];
        }
        $myN = count($myRecs);
        $myAvgRisk = $myN > 0 ? $myRiskSum / $myN : 0.0;
        $myAvgParam = $myN > 0 ? $myParamSum / $myN : 0.0;
        $myAvgPayload = $myN > 0 ? $myPayloadSum / $myN : 0.0;

        $isOutlier = false;
        $deviation = 0.0;
        $outlierDims = [];

        // 风险分数超过群体 95 分位
        if ($riskP95 > 0 && $myAvgRisk > $riskP95) {
            $isOutlier = true;
            $deviation += $myAvgRisk - $riskP95;
            $outlierDims[] = 'risk_score';
        }

        // 访问频率超过群体 95 分位
        if ($requestP95 > 0 && $myN > $requestP95) {
            $isOutlier = true;
            $deviation += ($myN - $requestP95) * 5;
            $outlierDims[] = 'request_count';
        }

        // 参数数量离群（>2σ）
        if ($paramStd > 0 && abs($myAvgParam - $paramMean) > 2 * $paramStd) {
            $isOutlier = true;
            $deviation += abs($myAvgParam - $paramMean) * 10;
            $outlierDims[] = 'param_count';
        }

        // payload 大小离群（>2σ）
        if ($payloadStd > 0 && abs($myAvgPayload - $payloadMean) > 2 * $payloadStd) {
            $isOutlier = true;
            $deviation += abs($myAvgPayload - $payloadMean) / 100;
            $outlierDims[] = 'payload_size';
        }

        return [
            'is_outlier' => $isOutlier,
            'deviation' => round($deviation, 2),
            'outlier_dimensions' => $outlierDims,
        ];
    }

    /**
     * J. 行为序列提取：提取最近 N 个请求的行为序列
     * 每个行为 = ['uri_pattern' => '/api/*', 'method' => 'GET', 'phase' => 'recon', 'risk' => 'low']
     * @param string $ip 客户端 IP
     * @param int $windowSize 窗口大小（默认 10）
     * @return array 行为序列数组
     */
    private static function extractBehaviorSequence(string $ip, int $windowSize = 10): array {
        if (!isset(self::$histories[$ip])) {
            return [];
        }
        $records = self::$histories[$ip]['records'];
        if (empty($records)) {
            return [];
        }

        if ($windowSize < 1) {
            $windowSize = 10;
        }

        $recent = array_slice($records, -$windowSize);
        $sequence = [];
        foreach ($recent as $r) {
            $uriPattern = self::normalizeUriPattern($r['uri']);
            $risk = 'low';
            if ($r['risk_score'] >= 70) {
                $risk = 'critical';
            } elseif ($r['risk_score'] >= 50) {
                $risk = 'high';
            } elseif ($r['risk_score'] >= 25) {
                $risk = 'medium';
            }

            $sequence[] = [
                'uri_pattern' => $uriPattern,
                'method' => $r['method'] ?? 'GET',
                'phase' => $r['attack_phase'] ?? 'none',
                'risk' => $risk,
            ];
        }
        return $sequence;
    }

    /**
     * J. 行为序列异常检测：对比当前行为序列与历史模式
     * 检测行为模式突变（如 GET→POST / 查询→上传 / 风险等级跃迁）
     * @param string $ip 客户端 IP
     * @return array{pattern_changed:bool, change_score:int}
     */
    private static function detectBehaviorAnomaly(string $ip): array {
        $empty = ['pattern_changed' => false, 'change_score' => 0];
        $sequence = self::extractBehaviorSequence($ip, 10);
        if (count($sequence) < self::BASELINE_MIN_SAMPLES) {
            return $empty;
        }

        $half = (int) floor(count($sequence) / 2);
        if ($half < 2) {
            return $empty;
        }

        $firstHalf = array_slice($sequence, 0, $half);
        $secondHalf = array_slice($sequence, $half);

        $changeScore = 0;
        $changes = 0;

        // 1. URI 模式突变：后半段出现大量前半段未访问的 URI
        $firstUris = array_column($firstHalf, 'uri_pattern');
        $secondUris = array_column($secondHalf, 'uri_pattern');
        $firstUriSet = array_unique($firstUris);
        $secondUriSet = array_unique($secondUris);
        $newUris = array_diff($secondUriSet, $firstUriSet);
        if (count($newUris) > 0 && count($secondUriSet) > 0
            && count($newUris) / count($secondUriSet) > 0.5) {
            $changeScore += 10;
            $changes++;
        }

        // 2. 风险等级突变：后半段平均风险显著高于前半段
        $riskMap = ['low' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3];
        $firstRisks = array_column($firstHalf, 'risk');
        $secondRisks = array_column($secondHalf, 'risk');
        $firstRiskSum = 0;
        foreach ($firstRisks as $r) {
            $firstRiskSum += $riskMap[$r] ?? 0;
        }
        $secondRiskSum = 0;
        foreach ($secondRisks as $r) {
            $secondRiskSum += $riskMap[$r] ?? 0;
        }
        $firstRiskAvg = count($firstRisks) > 0 ? $firstRiskSum / count($firstRisks) : 0.0;
        $secondRiskAvg = count($secondRisks) > 0 ? $secondRiskSum / count($secondRisks) : 0.0;
        if ($secondRiskAvg > $firstRiskAvg + 1) {
            $changeScore += 10;
            $changes++;
        }

        // 3. 攻击阶段突变：后半段攻击阶段显著高于前半段
        $phaseMap = ['none' => 0, 'recon' => 1, 'probe' => 2, 'attempt' => 3, 'attack' => 4, 'exploit' => 5];
        $firstPhases = array_column($firstHalf, 'phase');
        $secondPhases = array_column($secondHalf, 'phase');
        $firstPhaseSum = 0;
        foreach ($firstPhases as $p) {
            $firstPhaseSum += $phaseMap[$p] ?? 0;
        }
        $secondPhaseSum = 0;
        foreach ($secondPhases as $p) {
            $secondPhaseSum += $phaseMap[$p] ?? 0;
        }
        $firstPhaseAvg = count($firstPhases) > 0 ? $firstPhaseSum / count($firstPhases) : 0.0;
        $secondPhaseAvg = count($secondPhases) > 0 ? $secondPhaseSum / count($secondPhases) : 0.0;
        if ($secondPhaseAvg > $firstPhaseAvg + 1) {
            $changeScore += 10;
            $changes++;
        }

        $changeScore = min(30, $changeScore);
        return [
            'pattern_changed' => $changes >= 2,
            'change_score' => $changeScore,
        ];
    }

    /**
     * 计算历史平均特征向量（不含当前最后一条记录）
     * @param string $ip 客户端 IP
     * @return array|null 平均特征向量，数据不足返回 null
     */
    private static function computeAvgFeatureVector(string $ip): ?array {
        if (!isset(self::$histories[$ip])) {
            return null;
        }
        $records = self::$histories[$ip]['records'];
        $n = count($records);
        if ($n < 2) {
            return null;
        }

        // 排除最后一条（当前请求），仅用历史
        $historyRecords = array_slice($records, 0, -1);
        $sum = [];
        $count = 0;
        foreach ($historyRecords as $r) {
            if (!isset($r['feature_vector']) || !is_array($r['feature_vector'])) {
                continue;
            }
            $count++;
            foreach ($r['feature_vector'] as $key => $val) {
                $sum[$key] = ($sum[$key] ?? 0.0) + (float) $val;
            }
        }

        if ($count === 0) {
            return null;
        }

        $avg = [];
        foreach ($sum as $key => $total) {
            $avg[$key] = $total / $count;
        }
        return $avg;
    }

    /**
     * 分类异常标签到维度（drift / pattern / velocity）
     * @param string $anomaly 异常标签
     * @return string 维度名称
     */
    private static function classifyAnomalyDimension(string $anomaly): string {
        if (strpos($anomaly, 'drift:') === 0 || strpos($anomaly, 'drift_dim:') === 0) {
            return 'drift';
        }
        if (strpos($anomaly, 'dev:freq') === 0) {
            return 'velocity';
        }
        if (strpos($anomaly, 'dev:off_hours') === 0) {
            return 'velocity';
        }
        return 'pattern';
    }

    /**
     * 统计文本中数字字符数量
     * @param string $text 文本
     * @return int 数字字符数
     */
    private static function countNumeric(string $text): int {
        $len = strlen($text);
        $count = 0;
        for ($i = 0; $i < $len; $i++) {
            if ($text[$i] >= '0' && $text[$i] <= '9') {
                $count++;
            }
        }
        return $count;
    }

    /**
     * 统计文本中大写字母数量
     * @param string $text 文本
     * @return int 大写字母数
     */
    private static function countUppercase(string $text): int {
        $len = strlen($text);
        $count = 0;
        for ($i = 0; $i < $len; $i++) {
            if ($text[$i] >= 'A' && $text[$i] <= 'Z') {
                $count++;
            }
        }
        return $count;
    }

    /**
     * 统计文本中非 ASCII 字节数量
     * @param string $text 文本
     * @return int 非 ASCII 字节数
     */
    private static function countNonAscii(string $text): int {
        $len = strlen($text);
        $count = 0;
        for ($i = 0; $i < $len; $i++) {
            if (ord($text[$i]) > 127) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * 检测 URL 编码层数（最多 3 层）
     * @param string $text 文本
     * @return int 编码层数
     */
    private static function detectEncodingDepth(string $text): int {
        $depth = 0;
        $current = $text;
        while ($depth < 3) {
            $decoded = @urldecode($current);
            if ($decoded === $current || $decoded === '') {
                break;
            }
            $depth++;
            $current = $decoded;
        }
        return $depth;
    }

    /**
     * 计算已排序数组的百分位数
     * @param array $sortedValues 已排序的值数组
     * @param float $p 百分位（0-100）
     * @return float 百分位值
     */
    private static function percentile(array $sortedValues, float $p): float {
        $n = count($sortedValues);
        if ($n === 0) {
            return 0.0;
        }
        if ($n === 1) {
            return (float) $sortedValues[0];
        }
        $rank = ($p / 100.0) * ($n - 1);
        $lower = (int) floor($rank);
        $upper = (int) ceil($rank);
        if ($lower === $upper) {
            return (float) $sortedValues[$lower];
        }
        $frac = $rank - $lower;
        return (float) $sortedValues[$lower] + $frac * ((float) $sortedValues[$upper] - (float) $sortedValues[$lower]);
    }

    /**
     * URI 模式归一化：将数字段替换为 {id}，长十六进制串替换为 {hash}
     * 例如 /api/users/123/posts/abc123def456 → /api/users/{id}/posts/{hash}
     * @param string $uri 原始 URI
     * @return string 归一化后的 URI 模式
     */
    private static function normalizeUriPattern(string $uri): string {
        $parsedPath = parse_url($uri, PHP_URL_PATH);
        $path = ($parsedPath === false || $parsedPath === null) ? $uri : (string) $parsedPath;
        $segments = $path !== '' ? explode('/', trim($path, '/')) : [];
        $pattern = [];
        foreach ($segments as $seg) {
            if ($seg === '') {
                continue;
            }
            if (preg_match('/^\d+$/', $seg)) {
                $pattern[] = '{id}';
            } elseif (preg_match('/^[0-9a-f]{8,}$/i', $seg)) {
                $pattern[] = '{hash}';
            } else {
                $pattern[] = $seg;
            }
        }
        return '/' . implode('/', $pattern);
    }
}
