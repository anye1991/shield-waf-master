<?php
/**
 * 语义记忆池引擎
 * 职责：为每个IP建立深层语义特征记忆，跨请求对比分析语义演化。
 *       不仅记录攻击链，更记录语义指纹、请求模式、参数指纹、时序特征等。
 *       通过历史语义对比，检测异常演化（如突然变复杂、突然变长、突然切换字符集等）。
 */
defined('ABSPATH') || exit;

class SemanticMemoryPool {
    private static $memory_file = 'semantic_memory.json';
    private static $max_memory_per_ip = 50;
    private static $memory_expire_hours = 48;

    /**
     * 语义指纹数据结构
     */
    private static function buildFingerprint(string $text, string $uri, array $params, array $semanticResult): array {
        $fp = [
            'timestamp'       => time(),
            'uri_hash'        => md5($uri),
            'text_hash'       => md5($text),
            'text_length'     => strlen($text),
            'param_count'     => count($params),
            'param_keys'      => array_keys($params),
            'char_entropy'    => self::calcEntropy($text),
            'special_ratio'   => self::calcSpecialRatio($text),
            'encoding_depth'  => $semanticResult['encoding_depth'] ?? 0,
            'risk_level'      => $semanticResult['risk_level'] ?? 'clean',
            'l_scores'        => [
                'l1' => $semanticResult['l1_char_score'] ?? 0,
                'l2' => $semanticResult['l2_word_score'] ?? 0,
                'l3' => $semanticResult['l3_structure_score'] ?? 0,
                'l4' => $semanticResult['l4_param_score'] ?? 0,
                'l5' => $semanticResult['l5_business_score'] ?? 0,
                'l6' => $semanticResult['l6_logic_score'] ?? 0,
                'l7' => $semanticResult['l7_intent_score'] ?? 0,
                'l8' => $semanticResult['l8_chain_score'] ?? 0,
            ],
            'attack_phase'    => $semanticResult['attack_phase'] ?? 'none',
            'logic_type'      => $semanticResult['logic_type'] ?? 'none',
            'word_roles'      => $semanticResult['word_roles'] ?? [],
            'indicators_count' => count($semanticResult['indicators'] ?? []),
        ];
        return $fp;
    }

    /**
     * 记录语义指纹到记忆池
     */
    public static function record(string $ip, string $text, string $uri, array $params, array $semanticResult): void {
        $memories = self::loadMemories();
        $now = time();

        if (!isset($memories[$ip])) {
            $memories[$ip] = [
                'first_seen'     => $now,
                'last_seen'      => $now,
                'total_requests' => 0,
                'fingerprints'   => [],
                'semantic_evolution' => [],
                'baseline'       => null,
            ];
        }

        $fp = self::buildFingerprint($text, $uri, $params, $semanticResult);
        $memories[$ip]['fingerprints'][] = $fp;
        $memories[$ip]['last_seen'] = $now;
        $memories[$ip]['total_requests']++;

        // 限制数量
        if (count($memories[$ip]['fingerprints']) > self::$max_memory_per_ip) {
            $memories[$ip]['fingerprints'] = array_slice($memories[$ip]['fingerprints'], -self::$max_memory_per_ip);
        }

        // 更新基线（前5个正常请求的平均）
        if ($memories[$ip]['total_requests'] <= 5 && $semanticResult['risk_level'] === 'clean') {
            self::updateBaseline($memories[$ip]);
        }

        // 计算语义演化
        if ($memories[$ip]['total_requests'] > 1) {
            $evolution = self::calcEvolution($memories[$ip]);
            $memories[$ip]['semantic_evolution'][] = $evolution;
            if (count($memories[$ip]['semantic_evolution']) > self::$max_memory_per_ip) {
                $memories[$ip]['semantic_evolution'] = array_slice($memories[$ip]['semantic_evolution'], -self::$max_memory_per_ip);
            }
        }

        self::saveMemories($memories);
    }

    /**
     * 语义演化分析：对比当前请求与历史基线
     */
    public static function analyzeEvolution(string $ip, array $currentSemanticResult): array {
        $memories = self::loadMemories();
        if (!isset($memories[$ip]) || $memories[$ip]['total_requests'] < 2) {
            return ['score' => 0, 'anomalies' => [], 'baseline_exists' => false];
        }

        $baseline = $memories[$ip]['baseline'];
        $anomalies = [];
        $score = 0;

        if ($baseline) {
            // 字符熵突变
            $currentEntropy = $currentSemanticResult['l1_char_score'] ?? 0;
            if ($currentEntropy > ($baseline['char_entropy_avg'] ?? 0) * 3) {
                $anomalies[] = 'entropy_spike';
                $score += 15;
            }

            // 风险等级跃升
            $riskLevels = ['clean' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
            $currentRisk = $riskLevels[$currentSemanticResult['risk_level'] ?? 'clean'];
            $baselineRisk = $riskLevels[$baseline['risk_level_avg'] ?? 'clean'];
            if ($currentRisk >= 3 && $baselineRisk <= 1) {
                $anomalies[] = 'risk_level_jump';
                $score += 20;
            }

            // 攻击阶段突进
            $phaseProgress = ['none' => 0, 'recon' => 1, 'probe' => 2, 'attempt' => 3, 'attack' => 4, 'exploit' => 5];
            $currentPhase = $phaseProgress[$currentSemanticResult['attack_phase'] ?? 'none'];
            $prevPhase = $phaseProgress[$memories[$ip]['fingerprints'][count($memories[$ip]['fingerprints'])-2]['attack_phase'] ?? 'none'];
            if ($currentPhase > $prevPhase + 1) {
                $anomalies[] = 'phase_acceleration';
                $score += 18;
            }

            // 指标数量突增
            $currentIndicators = count($currentSemanticResult['indicators'] ?? []);
            if ($currentIndicators > ($baseline['indicators_avg'] ?? 0) * 4) {
                $anomalies[] = 'indicator_burst';
                $score += 12;
            }

            // L层分数突变
            $lKeys = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8'];
            foreach ($lKeys as $lk) {
                $currentL = $currentSemanticResult[$lk === 'l1' ? 'l1_char_score' : ($lk === 'l2' ? 'l2_word_score' : ($lk === 'l3' ? 'l3_structure_score' : ($lk === 'l4' ? 'l4_param_score' : ($lk === 'l5' ? 'l5_business_score' : ($lk === 'l6' ? 'l6_logic_score' : ($lk === 'l7' ? 'l7_intent_score' : 'l8_chain_score'))))))] ?? 0;
                $baselineL = $baseline['l_scores_avg'][$lk] ?? 0;
                if ($baselineL < 10 && $currentL > 50) {
                    $anomalies[] = $lk . '_mutation';
                    $score += 10;
                    break; // 只记第一个突变
                }
            }
        }

        // 请求频率异常
        $recent = array_slice($memories[$ip]['fingerprints'], -5);
        $timestamps = array_column($recent, 'timestamp');
        if (count($timestamps) >= 3) {
            $intervals = [];
            for ($i = 1; $i < count($timestamps); $i++) {
                $intervals[] = $timestamps[$i] - $timestamps[$i-1];
            }
            $avgInterval = array_sum($intervals) / count($intervals);
            if ($avgInterval < 2) {
                $anomalies[] = 'high_frequency_burst';
                $score += 8;
            }
        }

        return [
            'score'           => min(100, $score),
            'anomalies'       => $anomalies,
            'baseline_exists' => $baseline !== null,
            'total_requests'  => $memories[$ip]['total_requests'],
            'history_duration'=> $memories[$ip]['last_seen'] - $memories[$ip]['first_seen'],
        ];
    }

    /**
     * 获取IP语义画像
     */
    public static function getProfile(string $ip): array {
        $memories = self::loadMemories();
        if (!isset($memories[$ip])) {
            return ['exists' => false];
        }

        $m = $memories[$ip];
        $fps = $m['fingerprints'];
        $riskDistribution = ['clean' => 0, 'low' => 0, 'medium' => 0, 'high' => 0, 'critical' => 0];
        $phaseDistribution = ['none' => 0, 'recon' => 0, 'probe' => 0, 'attempt' => 0, 'attack' => 0, 'exploit' => 0];
        $totalScore = 0;

        foreach ($fps as $fp) {
            $riskDistribution[$fp['risk_level'] ?? 'clean']++;
            $phaseDistribution[$fp['attack_phase'] ?? 'none']++;
            $totalScore += array_sum($fp['l_scores'] ?? []);
        }

        $count = count($fps);
        $avgScore = $count > 0 ? round($totalScore / $count / 8, 1) : 0;

        return [
            'exists'             => true,
            'total_requests'     => $m['total_requests'],
            'first_seen'         => $m['first_seen'],
            'last_seen'          => $m['last_seen'],
            'risk_distribution'  => $riskDistribution,
            'phase_distribution' => $phaseDistribution,
            'avg_score'          => $avgScore,
            'baseline'           => $m['baseline'],
            'evolution_count'    => count($m['semantic_evolution'] ?? []),
        ];
    }

    /**
     * 更新基线
     */
    private static function updateBaseline(array &$ipMemory): void {
        $cleanFps = array_filter($ipMemory['fingerprints'], fn($fp) => ($fp['risk_level'] ?? '') === 'clean');
        if (count($cleanFps) < 2) return;

        $entropies = array_column($cleanFps, 'char_entropy');
        $indicators = array_column($cleanFps, 'indicators_count');
        $lScores = [];
        foreach (['l1','l2','l3','l4','l5','l6','l7','l8'] as $lk) {
            $vals = array_column(array_column($cleanFps, 'l_scores'), $lk);
            $lScores[$lk] = array_sum($vals) / count($vals);
        }

        $ipMemory['baseline'] = [
            'char_entropy_avg'  => array_sum($entropies) / count($entropies),
            'indicators_avg'    => array_sum($indicators) / count($indicators),
            'risk_level_avg'    => 'clean',
            'l_scores_avg'      => $lScores,
            'sample_count'      => count($cleanFps),
        ];
    }

    /**
     * 计算语义演化
     */
    private static function calcEvolution(array $ipMemory): array {
        $fps = $ipMemory['fingerprints'];
        if (count($fps) < 2) return [];
        $current = end($fps);
        $prev = $fps[count($fps) - 2];

        $evolution = [
            'timestamp'       => $current['timestamp'],
            'entropy_delta'   => round($current['char_entropy'] - $prev['char_entropy'], 3),
            'length_delta'    => $current['text_length'] - $prev['text_length'],
            'score_delta'     => array_sum($current['l_scores']) - array_sum($prev['l_scores']),
            'risk_changed'    => $current['risk_level'] !== $prev['risk_level'],
            'phase_changed'   => $current['attack_phase'] !== $prev['attack_phase'],
        ];
        return $evolution;
    }

    /**
     * 计算Shannon熵
     */
    private static function calcEntropy(string $text): float {
        $len = strlen($text);
        if ($len === 0) return 0.0;
        $freq = count_chars($text, 1);
        $entropy = 0.0;
        foreach ($freq as $cnt) {
            $p = $cnt / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    private static function calcSpecialRatio(string $text): float {
        $len = strlen($text);
        if ($len === 0) return 0.0;
        $special = '<>"\';%|&`$(){}\\/*#=*?![]';
        $count = 0;
        for ($i = 0; $i < $len; $i++) {
            if (strpos($special, $text[$i]) !== false) $count++;
        }
        return round($count / $len * 100, 2);
    }

    /**
     * 清理过期记忆
     */
    public static function cleanup(): void {
        $memories = self::loadMemories();
        $expireTime = time() - self::$memory_expire_hours * 3600;
        $changed = false;
        foreach ($memories as $ip => $mem) {
            if ($mem['last_seen'] < $expireTime) {
                unset($memories[$ip]);
                $changed = true;
            }
        }
        if ($changed) self::saveMemories($memories);
    }

    private static function getFilePath(): string {
        $dir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : __DIR__ . '/../waf_logs/';
        $dir = rtrim($dir, '/\\') . '/';
        // 验证目录路径安全
        $realDir = realpath($dir);
        if ($realDir === false) {
            // 目录不存在，尝试创建
            if (!mkdir($dir, 0700, true)) {
                error_log("SemanticMemoryPool: 无法创建日志目录: $dir");
                return '';
            }
            $realDir = realpath($dir);
        }
        if ($realDir === false || !is_writable($realDir)) {
            error_log("SemanticMemoryPool: 日志目录不可写: $dir");
            return '';
        }
        return $realDir . '/' . self::$memory_file;
    }

    private static function loadMemories(): array {
        $file = self::getFilePath();
        if ($file === '' || !is_file($file)) return [];
        $content = @file_get_contents($file);
        if ($content === false) {
            error_log("SemanticMemoryPool: 无法读取文件: $file");
            return [];
        }
        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("SemanticMemoryPool: JSON解析错误: " . json_last_error_msg());
            return [];
        }
        return is_array($data) ? $data : [];
    }

    private static function saveMemories(array $memories): void {
        $file = self::getFilePath();
        if ($file === '') return;
        $result = @file_put_contents($file, json_encode($memories), LOCK_EX);
        if ($result === false) {
            error_log("SemanticMemoryPool: 无法写入文件: $file");
        }
    }
}
