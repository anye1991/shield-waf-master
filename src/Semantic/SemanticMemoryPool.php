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
    const MAX_HISTORY_PER_IP = 100;   // 每IP最多保留的最近记录数
    const BASELINE_MIN_SAMPLES = 5;   // 基线建立所需的最小样本数
    const BASELINE_WINDOW = 10;       // 基线计算的最近样本窗口
    const INACTIVE_TTL = 1800;        // 不活跃超时（秒）—— 30 分钟自动清理
    const FREQ_WINDOW = 60;           // 频率统计窗口（秒）
    const ACCUM_HALFLIFE = 600;       // 累积半衰期（秒）
    const PERSIST_DIR = '/tmp/shield_memory';
    const PERSIST_FILE = 'memory_pool.json';

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

    /** 记录一次请求到记忆池，并基于历史（不含当前）重建基线。 */
    public static function record(string $ip, string $text, string $uri, array $params, array $features): void {
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
        self::persist();
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

        $total = $devScore + $drift['score'] + $accumulated['score'] + $actor['bonus'] + $cohort['deviation'];
        $total = max(0, min(100, (int) round($total)));

        return [
            'score' => $total,
            'anomalies' => array_values(array_unique($anomalies)),
            'baseline_exists' => true,
        ];
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

    /** 构建单条请求记录 */
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

    /** 持久化到 /tmp/shield_memory/（best-effort） */
    private static function persist() {
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
}
