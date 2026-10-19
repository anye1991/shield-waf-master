<?php
/**
 * 语义权重桥接器 (SemanticWeightBridge) v5.4
 *
 * 职责：
 *   根据 AutoLearn 的学习数据（攻击趋势 + 误报反馈），动态调整语义引擎的 28 个维度权重。
 *   这是"反哺语义权重"的核心实现，补全四层闭环的最后一环。
 *
 * 设计原则：
 *   1. 只读 AutoLearn 数据，不修改 AutoLearn 状态
 *   2. 调整幅度受限（±0.05/次），防止评分剧烈波动
 *   3. 映射表明确（攻击类型 → 语义权重组），不盲目调整
 *   4. 带节流（1 小时最多 1 次），由调用方控制
 *   5. 所有异常兜底，不影响主流程
 *   6. 调整历史持久化，可追溯、可回滚
 *
 * 依赖：
 *   - Learning_Storage（文件读写）
 *   - SemanticEngine::setWeights()（写入接口，需在 SemanticEngine 中新增）
 *   - AutoLearn 的 attack_stats.json / feedback_log.json（学习数据）
 *
 * 安全边界：
 *   - 单次调整 ≤ ±0.05
 *   - 权重范围 [0.01, 0.30]
 *   - 未知攻击类型不调整
 *   - 无学习数据时不调整
 *   - 并发写由 SemanticEngine::setWeights() 的文件锁保证
 */
defined('ABSPATH') || exit;

class Learning_SemanticWeightBridge {

    /** 单次调整上限（绝对值） */
    const MAX_DELTA_PER_RUN = 0.05;

    /** 单个维度的权重上下限 */
    const WEIGHT_MIN = 0.01;
    const WEIGHT_MAX = 0.30;

    /** 攻击频率统计窗口（天） */
    const TREND_WINDOW_DAYS = 7;

    /** 最小触发调整的样本数（低于此数不调整，避免冷启动噪声） */
    const MIN_SAMPLES_FOR_ADJUST = 20;

    /** 调整历史保留条数 */
    const HISTORY_MAX = 200;

    /**
     * 攻击类型 → 语义权重组件的映射
     *
     * 设计依据：
     *   - 每种攻击类型主要依赖哪些解析器/分析器
     *   - 高频攻击类型 → 对应权重上调（提升检出率）
     *   - 高误报攻击类型 → 对应权重下调（降低误报）
     *
     * 注意：这里的 key 必须与 SemanticEngine::$weights 的 key 完全一致
     */
    private static $typeToWeightKeys = [
        'sqli'            => ['sql_parser', 'logic', 'param'],
        'sql_injection'   => ['sql_parser', 'logic', 'param'],
        'sqli_blind'      => ['sql_parser', 'logic'],
        'xss'             => ['html_parser', 'structure', 'char'],
        'xss_reflected'   => ['html_parser', 'structure'],
        'xss_stored'      => ['html_parser', 'structure', 'memory'],
        'rce'             => ['php_parser', 'command_parser', 'intent'],
        'command_exec'    => ['command_parser', 'php_parser', 'intent'],
        'command_injection' => ['command_parser', 'intent'],
        'path_traversal'  => ['path_parser', 'word'],
        'file_inclusion'  => ['path_parser', 'php_parser'],
        'webshell'        => ['php_parser', 'adversarial'],
        'xxe'             => ['xxe_parser'],
        'ssrf'            => ['ssrf_parser'],
        'ssti'            => ['ssti_parser', 'expr_parser'],
        'deserialization' => ['deser_parser'],
        'deser'           => ['deser_parser'],
        'crlf'            => ['crlf_parser'],
        'crlf_injection'  => ['crlf_parser'],
        'expr_injection'  => ['expr_parser'],
        'expression_injection' => ['expr_parser'],
        'graphql'         => ['graphql_parser'],
        'websocket'       => ['websocket_parser'],
        'csv_injection'   => ['csv_parser'],
        'csv'             => ['csv_parser'],
        'yaml'            => ['yaml_parser'],
        'yaml_injection'  => ['yaml_parser'],
        'redos'           => ['redos_parser'],
        'regex_dos'       => ['redos_parser'],
        'obfuscation'     => ['adversarial', 'char'],
        'file_read'       => ['path_parser', 'php_parser'],
        'file_upload'     => ['php_parser', 'adversarial'],
    ];

    /** 是否启用调试日志 */
    private static $debug = false;

    /**
     * 主入口：计算并应用语义权重调整
     *
     * @return array [
     *   'ok'        => bool 是否成功,
     *   'reason'    => string 结果说明,
     *   'adjustments' => array 计算出的调整建议（无论是否应用）,
     *   'applied'   => array 实际应用的变化,
     *   'samples'   => int 参与计算的样本数,
     * ]
     */
    public static function apply(): array {
        try {
            // 1. 前置检查
            if (!class_exists('SemanticEngine')) {
                return self::result(false, 'semantic_engine_missing');
            }
            if (!method_exists('SemanticEngine', 'setWeights')) {
                return self::result(false, 'set_weights_not_implemented');
            }
            if (!class_exists('Learning_Storage')) {
                return self::result(false, 'storage_missing');
            }

            // 2. 计算调整建议
            $adjustments = self::computeAdjustments();
            if (empty($adjustments['adjustments'])) {
                return self::result(true, $adjustments['reason'], $adjustments, [], $adjustments['samples'] ?? 0);
            }

            // 3. 应用到语义引擎
            $applied = SemanticEngine::setWeights($adjustments['adjustments']);

            // 4. 记录历史
            if (!empty($applied)) {
                self::logAdjustment($applied, $adjustments['samples'] ?? 0);
            }

            return [
                'ok'          => true,
                'reason'      => empty($applied) ? 'no_change_needed' : 'applied',
                'adjustments' => $adjustments['adjustments'],
                'applied'     => $applied,
                'samples'     => $adjustments['samples'] ?? 0,
            ];
        } catch (\Throwable $e) {
            if (self::$debug) {
                error_log('[SemanticWeightBridge] apply error: ' . $e->getMessage());
            }
            return self::result(false, 'exception: ' . $e->getMessage());
        }
    }

    /**
     * 计算权重调整建议（不应用，供预览/测试）
     *
     * @return array [
     *   'adjustments' => ['weight_key' => delta, ...],
     *   'reason'      => string,
     *   'samples'     => int,
     *   'details'     => array 各攻击类型的原始统计,
     * ]
     */
    public static function computeAdjustments(): array {
        // 1. 读最近 7 天攻击趋势
        $trend = self::readRecentTrend();
        if (empty($trend['counts'])) {
            return [
                'adjustments' => [],
                'reason'      => 'no_attack_trend',
                'samples'     => 0,
                'details'     => [],
            ];
        }

        // 2. 读误报反馈
        $fpCounts = self::readFeedbackFalsePositives();

        // 3. 样本数不足，不调整（防冷启动噪声）
        $totalSamples = array_sum($trend['counts']);
        if ($totalSamples < self::MIN_SAMPLES_FOR_ADJUST) {
            return [
                'adjustments' => [],
                'reason'      => 'insufficient_samples',
                'samples'     => $totalSamples,
                'details'     => ['trend' => $trend['counts'], 'fp' => $fpCounts],
            ];
        }

        // 4. 计算调整
        $maxCount = max($trend['counts']);
        $adjustments = [];
        $details = [];

        foreach ($trend['counts'] as $type => $count) {
            $weightKeys = self::$typeToWeightKeys[$type] ?? [];
            if (empty($weightKeys)) continue;

            // 4.1 频率加成（相对最高频类型的比例 × 0.03）
            $freqRatio = $count / max($maxCount, 1);
            $freqBoost = $freqRatio * 0.03;

            // 4.2 误报惩罚（误报越多，越降权）
            $fpCount = $fpCounts[$type] ?? 0;
            $fpPenalty = 0.0;
            if ($fpCount > 0) {
                $fpRatio = min($fpCount / max($count, 1), 1.0);
                $fpPenalty = $fpRatio * 0.04;
            }

            // 4.3 净调整
            $delta = $freqBoost - $fpPenalty;

            // 4.4 过小调整忽略（防噪声）
            if (abs($delta) < 0.005) continue;

            // 4.5 分散到该攻击类型的所有关联权重
            $perKey = $delta / count($weightKeys);
            foreach ($weightKeys as $key) {
                if (!isset($adjustments[$key])) $adjustments[$key] = 0.0;
                $adjustments[$key] += $perKey;
            }

            $details[$type] = [
                'count'      => $count,
                'fp_count'   => $fpCount,
                'freq_boost' => round($freqBoost, 4),
                'fp_penalty' => round($fpPenalty, 4),
                'delta'      => round($delta, 4),
            ];
        }

        // 5. 限制每个 key 的调整幅度在 ±MAX_DELTA_PER_RUN 内
        foreach ($adjustments as $key => $v) {
            $adjustments[$key] = round(
                max(-self::MAX_DELTA_PER_RUN, min(self::MAX_DELTA_PER_RUN, $v)),
                4
            );
            if (abs($adjustments[$key]) < 0.001) {
                unset($adjustments[$key]);
            }
        }

        return [
            'adjustments' => $adjustments,
            'reason'      => empty($adjustments) ? 'no_meaningful_adjustment' : 'computed',
            'samples'     => $totalSamples,
            'details'     => $details,
        ];
    }

    /**
     * 获取调整历史（供控制台展示）
     */
    public static function getHistory(int $limit = 20): array {
        if (!class_exists('Learning_Storage')) return [];
        $file = self::getHistoryFile();
        $data = Learning_Storage::read($file, ['records' => []]);
        $records = $data['records'] ?? [];
        if (count($records) > $limit) {
            $records = array_slice($records, -$limit);
        }
        return array_reverse($records); // 最新在前
    }

    /**
     * 回滚到指定历史记录的权重（按记录索引）
     *
     * @param int $index 历史记录索引（0 = 最新）
     * @return array
     */
    public static function rollback(int $index = 0): array {
        if (!class_exists('SemanticEngine') || !method_exists('SemanticEngine', 'setWeights')) {
            return self::result(false, 'semantic_engine_unavailable');
        }

        $file = self::getHistoryFile();
        if (!class_exists('Learning_Storage')) {
            return self::result(false, 'storage_missing');
        }

        $data = Learning_Storage::read($file, ['records' => []]);
        $records = $data['records'] ?? [];
        if (empty($records)) {
            return self::result(false, 'no_history');
        }

        // index 0 = 最新
        $target = $records[count($records) - 1 - $index] ?? null;
        if (!$target || empty($target['applied'])) {
            return self::result(false, 'record_not_found');
        }

        // 反向调整（把 old 值写回去）
        $revert = [];
        foreach ($target['applied'] as $key => $change) {
            if (!isset($change['old'])) continue;
            $current = SemanticEngine::getWeights()[$key] ?? null;
            if ($current === null) continue;
            // delta = 目标值 - 当前值，反向调整
            $revert[$key] = (float)$change['old'] - (float)$current;
        }

        if (empty($revert)) {
            return self::result(false, 'nothing_to_revert');
        }

        $applied = SemanticEngine::setWeights($revert);
        self::logAdjustment($applied, 0, 'rollback');

        return [
            'ok'      => true,
            'reason'  => 'rolled_back',
            'applied' => $applied,
        ];
    }

    /**
     * 获取当前映射表（供控制台展示/调试）
     */
    public static function getMappingTable(): array {
        return self::$typeToWeightKeys;
    }

    /**
     * 设置调试模式
     */
    public static function setDebug(bool $debug): void {
        self::$debug = $debug;
    }

    // ====================== 内部方法 ======================

    /**
     * 读最近 N 天攻击趋势
     *
     * @return array ['counts' => ['sqli' => 120, ...], 'days' => 7]
     */
    private static function readRecentTrend(): array {
        if (!class_exists('Learning_Storage')) {
            return ['counts' => [], 'days' => 0];
        }

        $statsFile = self::getStatsFile();
        $stats = Learning_Storage::read($statsFile, []);
        $trend = $stats['type_trend'] ?? [];
        if (empty($trend)) {
            return ['counts' => [], 'days' => 0];
        }

        $counts = [];
        $now = time();
        $validDays = 0;

        for ($i = 0; $i < self::TREND_WINDOW_DAYS; $i++) {
            $dayKey = date('Y-m-d', $now - $i * 86400);
            if (!isset($trend[$dayKey])) continue;
            $validDays++;
            foreach ($trend[$dayKey] as $type => $count) {
                $type = strtolower((string)$type);
                if ($type === '') continue;
                if (!isset($counts[$type])) $counts[$type] = 0;
                $counts[$type] += (int)$count;
            }
        }

        return ['counts' => $counts, 'days' => $validDays];
    }

    /**
     * 读反馈中的误报统计
     *
     * @return array ['sqli' => 5, 'xss' => 2, ...]
     */
    private static function readFeedbackFalsePositives(): array {
        if (!class_exists('Learning_Storage')) return [];

        $feedbackFile = self::getFeedbackFile();
        $feedback = Learning_Storage::read($feedbackFile, []);
        if (empty($feedback) || !is_array($feedback)) return [];

        // 只统计最近 7 天的误报反馈
        $cutoff = time() - self::TREND_WINDOW_DAYS * 86400;
        $fpCounts = [];

        foreach ($feedback as $fb) {
            if (empty($fb['is_false_positive'])) continue;
            $ts = (int)($fb['timestamp'] ?? 0);
            if ($ts < $cutoff) continue;
            $type = strtolower((string)($fb['attack_type'] ?? ''));
            if ($type === '') continue;
            if (!isset($fpCounts[$type])) $fpCounts[$type] = 0;
            $fpCounts[$type]++;
        }

        return $fpCounts;
    }

    /**
     * 记录调整历史
     */
    private static function logAdjustment(array $applied, int $samples, string $action = 'adjust'): void {
        if (empty($applied) || !class_exists('Learning_Storage')) return;

        $file = self::getHistoryFile();
        $data = Learning_Storage::read($file, ['records' => []]);
        if (!isset($data['records']) || !is_array($data['records'])) {
            $data['records'] = [];
        }

        $data['records'][] = [
            'time'    => time(),
            'action'  => $action,
            'samples' => $samples,
            'applied' => $applied,
        ];

        // 上限裁剪
        if (count($data['records']) > self::HISTORY_MAX) {
            $data['records'] = array_slice($data['records'], -self::HISTORY_MAX);
        }

        Learning_Storage::write($file, $data);
    }

    private static function result(bool $ok, string $reason, array $extra = [], array $applied = [], int $samples = 0): array {
        return array_merge([
            'ok'          => $ok,
            'reason'      => $reason,
            'adjustments' => $extra['adjustments'] ?? [],
            'applied'     => $applied,
            'samples'     => $samples,
        ], $extra);
    }

    // ====================== 路径 ======================

    private static function getLogPath(): string {
        return defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
    }

    private static function getStatsFile(): string {
        return self::getLogPath() . '/attack_stats.json';
    }

    private static function getFeedbackFile(): string {
        return self::getLogPath() . '/feedback_log.json';
    }

    private static function getHistoryFile(): string {
        return self::getLogPath() . '/learning/weight_history.json';
    }
}