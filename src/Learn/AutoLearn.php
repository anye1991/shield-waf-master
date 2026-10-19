<?php
/**
 * 盾甲 WAF 自适应学习系统 (src/Learn/AutoLearn.php)
 *
 * 功能：
 *  1. 记录所有被拦截的攻击载荷（归一化后），统计频率
 *  2. 从高频攻击载荷中自动提取特征模式，生成新的检测规则
 *  3. 动态调整攻击类型权重（根据近期攻击趋势）
 *  4. 支持误报/漏报反馈，自动修正评分
 *  5. 自动学习正常请求特征，建立白名单，降低误报率
 *  6. [v5.4] 智能学习闭环：样本采集 → 质量过滤 → 训练调度 / 审核队列 → 模型评估
 *
 * 存储文件（waf_logs/ 目录）：
 *  - learned_patterns.json  : 自动学习到的特征规则
 *  - attack_stats.json      : 攻击载荷频率统计
 *  - weight_adjustments.json: 权重修正数据
 *  - feedback_log.json      : 误报/漏报反馈记录
 *  - normal_patterns.json   : 正常请求模式白名单
 *  - learning/*.json        : [v5.4] 智能学习模块数据
 */
defined('ABSPATH') || exit;

if (!function_exists('waf_safe_read_json')) {
    require_once __DIR__ . '/../Support/Functions.php';
}
require_once __DIR__ . '/NaiveBayesClassifier.php';

// ====================== v5.4 智能学习模块加载 ======================
// 与 AutoLearn.php 同级目录，幂等加载，缺失时降级到老逻辑
foreach (['Storage', 'SampleCollector', 'SampleFilter', 'ReviewQueue', 'ModelEvaluator', 'TrainingScheduler'] as $__learningCls) {
    $__learningFile = __DIR__ . '/' . $__learningCls . '.php';
    if (is_file($__learningFile) && !class_exists('Learning_' . $__learningCls)) {
        require_once $__learningFile;
    }
}
unset($__learningCls, $__learningFile);

class AutoLearn {
    private static $patterns_file = null;
    private static $stats_file = null;
    private static $weights_file = null;
    private static $feedback_file = null;
    private static $normal_file = null;
    private static $cache = null;
    private static $cache_ttl = 60;

    private static $static_cache = [];
    private static $static_cache_ts = [];
    public const STATIC_CACHE_TTL = 30;

    public static function init() {
        if (self::$patterns_file !== null) return;
        self::$patterns_file = WAF_LOG_PATH . '/learned_patterns.json';
        self::$stats_file   = WAF_LOG_PATH . '/attack_stats.json';
        self::$weights_file = WAF_LOG_PATH . '/weight_adjustments.json';
        self::$feedback_file = WAF_LOG_PATH . '/feedback_log.json';
        self::$normal_file  = WAF_LOG_PATH . '/normal_patterns.json';
    }

    // ====================== 攻击载荷记录 ======================

    /**
     * 记录一次攻击事件，更新频率统计
     */
    public static function recordAttack($normalizedPayload, $attackResult) {
        self::init();
        if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);

        $stats = self::loadStats();
        $hash = md5($normalizedPayload);

        if (!isset($stats['payloads'][$hash])) {
            $stats['payloads'][$hash] = [
                'payload'   => mb_substr($normalizedPayload, 0, 500, 'UTF-8'),
                'count'     => 0,
                'first_seen' => time(),
                'last_seen'  => time(),
                'attack_type' => [],
                'risk_level'  => $attackResult['risk_level'] ?? 'unknown',
            ];
        }

        $stats['payloads'][$hash]['count']++;
        $stats['payloads'][$hash]['last_seen'] = time();

        if (!empty($attackResult['attack_type_scores'])) {
            $topType = array_keys($attackResult['attack_type_scores'], max($attackResult['attack_type_scores']))[0];
            if (!isset($stats['payloads'][$hash]['attack_type'][$topType])) {
                $stats['payloads'][$hash]['attack_type'][$topType] = 0;
            }
            $stats['payloads'][$hash]['attack_type'][$topType]++;
        }

        $stats['total_attacks'] = ($stats['total_attacks'] ?? 0) + 1;
        $stats['last_attack_time'] = time();

        if (!empty($attackResult['attack_type_scores'])) {
            $topType = array_keys($attackResult['attack_type_scores'], max($attackResult['attack_type_scores']))[0];
            $dayKey = date('Y-m-d');
            if (!isset($stats['type_trend'][$dayKey][$topType])) {
                $stats['type_trend'][$dayKey][$topType] = 0;
            }
            $stats['type_trend'][$dayKey][$topType]++;
        }

        $stats = self::pruneStats($stats);
        self::saveStats($stats);
        self::$cache = null;

        if ($stats['payloads'][$hash]['count'] >= 3) {
            self::tryLearnPattern($normalizedPayload, $stats['payloads'][$hash]);
        }

        // ========== v5.4 智能学习：采集 → 过滤 → 训练队列 / 审核队列 ==========
        self::feedBayesAttack($normalizedPayload, $attackResult);
    }

    /**
     * [v5.4] 攻击样本投喂贝叶斯
     * 高置信度 → 训练队列；中风险 → 审核队列；低置信度 → 丢弃
     */
    private static function feedBayesAttack($normalizedPayload, $attackResult) {
        $hasLearning = class_exists('Learning_SampleCollector')
                    && class_exists('Learning_SampleFilter')
                    && class_exists('Learning_TrainingScheduler');

        if (!$hasLearning) {
            // 降级：学习模块缺失时保持老行为
            if (!empty($normalizedPayload) && strlen($normalizedPayload) < 10000) {
                NaiveBayesClassifier::train($normalizedPayload, 'attack');
                NaiveBayesClassifier::save();
            }
            return;
        }

        if (empty($normalizedPayload) || strlen($normalizedPayload) >= 10000) return;

        $sample = Learning_SampleCollector::collectAttack($normalizedPayload, $attackResult);

        if (Learning_SampleFilter::isHighConfidenceAttack($sample)) {
            Learning_TrainingScheduler::enqueue($sample);
            Learning_TrainingScheduler::maybeFlush();
        } elseif (class_exists('Learning_ReviewQueue') && Learning_SampleFilter::isMediumRisk($sample)) {
            Learning_ReviewQueue::push($sample);
        }

        // 抽样加入评估池（不参与训练，仅用于评估模型质量）
        if (class_exists('Learning_ModelEvaluator') && mt_rand(1, 50) === 1) {
            Learning_ModelEvaluator::addEvalSample($normalizedPayload, 'attack');
        }
    }

    // ====================== 自动模式学习 ======================

    private static function tryLearnPattern($payload, $payloadStats) {
        $patterns = self::loadPatterns();
        $tokens = self::extractTokens($payload);
        if (empty($tokens)) return;

        $mainType = 'unknown';
        if (!empty($payloadStats['attack_type'])) {
            arsort($payloadStats['attack_type']);
            $mainType = array_key_first($payloadStats['attack_type']);
        }

        foreach ($tokens as $token) {
            $ruleKey = md5($token . $mainType);

            if (!isset($patterns['rules'][$ruleKey])) {
                $patterns['rules'][$ruleKey] = [
                    'pattern'   => $token,
                    'type'      => $mainType,
                    'severity'  => 60,
                    'name'      => '自动学习: ' . $token,
                    'learned_at'=> time(),
                    'hit_count' => 0,
                    'source_payloads' => [],
                ];
            }

            $patterns['rules'][$ruleKey]['hit_count']++;
            $patterns['rules'][$ruleKey]['last_seen'] = time();

            $hash = md5($payload);
            if (!in_array($hash, $patterns['rules'][$ruleKey]['source_payloads']) &&
                count($patterns['rules'][$ruleKey]['source_payloads']) < 5) {
                $patterns['rules'][$ruleKey]['source_payloads'][] = $hash;
            }

            if ($patterns['rules'][$ruleKey]['hit_count'] >= 10) {
                $patterns['rules'][$ruleKey]['severity'] = min(80, 60 + $patterns['rules'][$ruleKey]['hit_count']);
            }
        }

        $patterns['last_learn_time'] = time();
        $patterns['total_learned'] = count($patterns['rules']);
        self::savePatterns($patterns);
    }

    private static function extractTokens($payload) {
        $tokens = [];
        $seen = [];

        if (preg_match_all('/\b([a-z_]{3,20})\s*\(/i', $payload, $matches)) {
            foreach ($matches[1] as $func) {
                $func = strtolower($func);
                if (in_array($func, ['if', 'for', 'while', 'echo', 'print', 'array', 'strlen', 'count', 'isset', 'empty', 'date', 'time'])) continue;
                $key = $func . '(';
                if (!isset($seen[$key])) { $tokens[] = $key; $seen[$key] = true; }
            }
        }

        if (preg_match_all('/\b(union\s+\w+|select\s+\w+|insert\s+\w+|drop\s+\w+|delete\s+\w+|update\s+\w+|create\s+\w+)\b/i', $payload, $matches)) {
            foreach ($matches[1] as $kw) {
                $kw = strtolower($kw);
                if (!isset($seen[$kw])) { $tokens[] = $kw; $seen[$kw] = true; }
            }
        }

        if (preg_match_all('/(\.\.[\/\\\\]|\/etc\/\w+|\/var\/\w+|\/proc\/\w+|[a-z]:\\\\\w+)/i', $payload, $matches)) {
            foreach ($matches[1] as $path) {
                $path = strtolower($path);
                if (!isset($seen[$path])) { $tokens[] = $path; $seen[$path] = true; }
            }
        }

        if (preg_match_all('/<(script|iframe|img|svg|object|embed)[^>]/i', $payload, $matches)) {
            foreach ($matches[1] as $tag) {
                $tag = '<' . strtolower($tag);
                if (!isset($seen[$tag])) { $tokens[] = $tag; $seen[$tag] = true; }
            }
        }

        return $tokens;
    }

    // ====================== 正常请求白名单学习 ======================

    /**
     * 记录正常请求模式，用于建立白名单
     * @param string $uri 请求URI
     * @param array  $params 请求参数键名
     */
    public static function recordNormal($uri, $params = []) {
        self::init();
        if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);

        // 基线冻结期间不更新（防攻击者"教坏"基线）
        // 已有正常模式继续生效，但不学习新的
        if (self::isBaselineFrozen()) {
            return;
        }

        $normal = self::loadNormal();
        $path = parse_url($uri, PHP_URL_PATH) ?: $uri;
        $hash = md5($path);

        if (!isset($normal['patterns'][$hash])) {
            $normal['patterns'][$hash] = [
                'path'       => $path,
                'count'      => 0,
                'first_seen' => time(),
                'last_seen'  => time(),
                'param_keys' => [],
            ];
        }

        $normal['patterns'][$hash]['count']++;
        $normal['patterns'][$hash]['last_seen'] = time();

        foreach ($params as $key) {
            $key = strtolower($key);
            if (!in_array($key, $normal['patterns'][$hash]['param_keys'])) {
                $normal['patterns'][$hash]['param_keys'][] = $key;
            }
        }

        $normal['total_normal'] = ($normal['total_normal'] ?? 0) + 1;

        // 清理超过30天的旧数据
        $cutoff = time() - 30 * 86400;
        foreach ($normal['patterns'] as $h => $info) {
            if ($info['last_seen'] < $cutoff) unset($normal['patterns'][$h]);
        }

        self::saveNormal($normal);

        // ========== v5.4 智能学习：正常样本经均衡过滤后入训练队列 ==========
        self::feedBayesNormal($path, $params);
    }

    /**
     * [v5.4] 正常样本投喂贝叶斯
     * 经类别均衡过滤后入训练队列，避免正常样本淹没攻击样本
     */
    private static function feedBayesNormal($path, $params) {
        $normalText = $path . '?' . implode('&', array_map('strval', $params));
        if (strlen($normalText) >= 500) return;

        $hasLearning = class_exists('Learning_SampleCollector')
                    && class_exists('Learning_SampleFilter')
                    && class_exists('Learning_TrainingScheduler');

        if (!$hasLearning) {
            // 降级：保持老行为（10% 概率训练）
            if (mt_rand(1, 100) <= 10) {
                NaiveBayesClassifier::train($normalText, 'normal');
                NaiveBayesClassifier::save();
            }
            return;
        }

        $sample = Learning_SampleCollector::collectNormal($normalText, ['path' => $path, 'params' => $params]);

        if (Learning_SampleFilter::isTrainableNormal($sample)) {
            Learning_TrainingScheduler::enqueue($sample);
            Learning_TrainingScheduler::maybeFlush();
        }

        // 抽样加入评估池
        if (class_exists('Learning_ModelEvaluator') && mt_rand(1, 50) === 1) {
            Learning_ModelEvaluator::addEvalSample($normalText, 'normal');
        }
    }

    /**
     * 检查请求是否匹配已学习的正常模式
     * @param string $uri
     * @param array  $params 请求参数键名
     * @return float 偏差分数 (0=完全匹配, 1=完全未知)
     */
    public static function getDeviationScore($uri, $params = []) {
        self::init();
        $normal = self::loadNormal();

        // 集成点 1：沙箱高危 IP 加成（必须在早退前计算，确保未知 URI 也能叠加）
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $sandboxRisk = ($ip !== '') ? self::getSandboxIpRisk($ip) : 0.0;

        if (empty($normal['patterns'])) {
            // 没有正常模式基线时，仅沙箱风险生效
            return min($sandboxRisk * 0.3, 1.0);
        }

        $path = parse_url($uri, PHP_URL_PATH) ?: $uri;
        $hash = md5($path);

        if (!isset($normal['patterns'][$hash])) {
            // 未知 URI：基础 0.3 + 沙箱风险加成
            return min(0.3 + $sandboxRisk * 0.3, 1.0);
        }

        $pattern = $normal['patterns'][$hash];
        if ($pattern['count'] < 5) {
            // 已知但样本少：基础 0.2 + 沙箱风险加成
            return min(0.2 + $sandboxRisk * 0.3, 1.0);
        }

        // 检查参数键偏差
        $knownKeys = array_map('strtolower', $pattern['param_keys']);
        $unknownParams = 0;
        foreach ($params as $key) {
            if (!in_array(strtolower($key), $knownKeys)) $unknownParams++;
        }

        $totalParams = max(count($params), 1);
        $deviation = min($unknownParams / $totalParams, 1.0);

        // 沙箱风险叠加（上限 1.0）
        if ($sandboxRisk > 0) {
            $deviation = min($deviation + $sandboxRisk * 0.3, 1.0);
        }

        return $deviation;
    }

    // ====================== 获取学习规则 ======================

    public static function getLearnedPatterns() {
        self::init();
        return self::loadPatterns();
    }

    public static function getLearnedRules() {
        self::init();
        $patterns = self::loadPatterns();
        if (empty($patterns['rules'])) return [];

        $rules = [];
        foreach ($patterns['rules'] as $rule) {
            $rules[] = [
                'pattern'  => $rule['pattern'],
                'type'     => $rule['type'],
                'severity' => $rule['severity'],
                'name'     => $rule['name'],
                'learned'  => true,
            ];
        }
        return $rules;
    }

    // ====================== 权重自适应 ======================

    public static function getAdjustedWeights() {
        self::init();
        $stats = self::loadStats();
        $weights = self::loadWeights();

        $baseWeights = [
            'sqli' => 1.2, 'sqli_blind' => 1.3, 'xss' => 1.0, 'rce' => 1.4,
            'path_traversal' => 1.1, 'webshell' => 1.5, 'xxe' => 1.2,
            'file_read' => 0.9, 'file_inclusion' => 1.3, 'obfuscation' => 0.7,
        ];

        if (empty($stats['type_trend'])) return $baseWeights;

        $recentCounts = [];
        $now = time();
        for ($i = 0; $i < 7; $i++) {
            $dayKey = date('Y-m-d', $now - $i * 86400);
            if (isset($stats['type_trend'][$dayKey])) {
                foreach ($stats['type_trend'][$dayKey] as $type => $count) {
                    if (!isset($recentCounts[$type])) $recentCounts[$type] = 0;
                    $recentCounts[$type] += $count;
                }
            }
        }

        if (empty($recentCounts)) return $baseWeights;

        arsort($recentCounts);
        $maxCount = max($recentCounts);
        foreach ($recentCounts as $type => $count) {
            if (!isset($baseWeights[$type])) continue;
            $boost = ($count / $maxCount) * 0.3;
            $baseWeights[$type] += $boost;
        }

        if (!empty($weights['feedback_adjustments'])) {
            foreach ($weights['feedback_adjustments'] as $type => $adjustment) {
                if (isset($baseWeights[$type])) {
                    $baseWeights[$type] += $adjustment;
                    $baseWeights[$type] = max(0.5, min(2.0, $baseWeights[$type]));
                }
            }
        }

        return $baseWeights;
    }

    // ====================== 反馈机制 ======================

    public static function provideFeedback($payload, $isFalsePositive, $attackType = '') {
        self::init();
        if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);

        $feedback = self::loadFeedback();
        $feedback[] = [
            'payload'       => mb_substr($payload, 0, 500, 'UTF-8'),
            'is_false_positive' => $isFalsePositive,
            'attack_type'   => $attackType,
            'timestamp'     => time(),
        ];
        if (count($feedback) > 1000) $feedback = array_slice($feedback, -1000);
        self::saveFeedback($feedback);

        $weights = self::loadWeights();
        if (!isset($weights['feedback_adjustments'])) $weights['feedback_adjustments'] = [];
        if (!isset($weights['feedback_adjustments'][$attackType])) {
            $weights['feedback_adjustments'][$attackType] = 0;
        }

        if ($isFalsePositive) {
            $weights['feedback_adjustments'][$attackType] -= 0.1;
            $weights['feedback_adjustments'][$attackType] = max(-0.5, $weights['feedback_adjustments'][$attackType]);
        } else {
            $weights['feedback_adjustments'][$attackType] += 0.1;
            $weights['feedback_adjustments'][$attackType] = min(0.5, $weights['feedback_adjustments'][$attackType]);
        }

        $weights['last_feedback_time'] = time();
        self::saveWeights($weights);
    }

    // ====================== 沙箱联动接口 ======================

    /**
     * 集成点 1：沙箱 → AutoLearn 事件回流
     */
    public static function markIpFromSandbox(string $ip, string $reason, array $context = []) {
        if ($ip === '' || $ip === 'cli' || $ip === 'unknown') return;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return;

        self::init();
        if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0700, true);

        $file = WAF_LOG_PATH . '/sandbox_blacklist.json';
        $data = waf_safe_read_json($file, ['ips' => [], 'total_events' => 0]);

        if (!isset($data['ips'][$ip])) {
            $data['ips'][$ip] = [
                'first_seen'    => time(),
                'last_seen'     => time(),
                'event_count'   => 0,
                'events'         => [],
                'frozen'         => false,
            ];
        }

        $entry = &$data['ips'][$ip];
        $entry['last_seen'] = time();
        $entry['event_count']++;

        if (count($entry['events']) >= 100) {
            $entry['events'] = array_slice($entry['events'], -99);
        }
        $entry['events'][] = [
            'time'   => time(),
            'reason' => $reason,
            'path'   => mb_substr($context['path'] ?? '', 0, 200),
            'score'  => $context['score'] ?? 0,
        ];

        if ($entry['event_count'] >= 3 && !$entry['frozen']) {
            $entry['frozen'] = true;
            $entry['frozen_at'] = time();
        }

        $data['total_events']++;

        if (count($data['ips']) > 10000) {
            uasort($data['ips'], function($a, $b) {
                return $a['last_seen'] <=> $b['last_seen'];
            });
            $data['ips'] = array_slice($data['ips'], 1000, null, true);
        }

        waf_safe_write_json($file, $data);
    }

    /**
     * 查询某 IP 在沙箱事件中的高危分（用于 getDeviationScore 加成）
     */
    public static function getSandboxIpRisk(string $ip): float {
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) return 0.0;
        self::init();

        $file = WAF_LOG_PATH . '/sandbox_blacklist.json';
        $data = waf_safe_read_json($file, ['ips' => []]);
        if (!isset($data['ips'][$ip])) return 0.0;

        $entry = $data['ips'][$ip];

        $ageDays = (time() - $entry['last_seen']) / 86400;
        if ($ageDays > 30) return 0.0;

        $cnt = $entry['event_count'];
        $risk = $cnt >= 10 ? 1.0 : ($cnt >= 3 ? 0.6 : 0.3);

        if ($ageDays > 7) {
            $risk *= 0.5;
        }

        return $risk;
    }

    /**
     * 集成点 2：AutoLearn → Sandbox 特征反哺
     */
    public static function getHotSignatures(int $minHits = 10, int $limit = 50): array {
        self::init();
        $patterns = self::loadPatterns();
        if (empty($patterns['rules'])) return [];

        $result = [];
        foreach ($patterns['rules'] as $rule) {
            if (($rule['hit_count'] ?? 0) < $minHits) continue;

            $pattern = $rule['pattern'] ?? '';
            if ($pattern === '') continue;

            if (preg_match('/^(if|for|while|echo|print|array|count|strlen|isset|empty|date|time|substr|trim|explode|implode|sprintf|printf)\(/i', $pattern)) {
                continue;
            }

            $weight = min(($rule['severity'] ?? 60) / 4, 15);
            if ($weight < 5) continue;

            $result[$pattern] = (int)$weight;
            if (count($result) >= $limit) break;
        }

        return $result;
    }

    /**
     * 集成点 3：基线状态联动 — 冻结 AutoLearn 行为基线
     */
    public static function freezeBaseline(string $reason = 'sandbox_lock'): array {
        self::init();
        $file = WAF_LOG_PATH . '/baseline_freeze.json';
        $data = waf_safe_read_json($file, ['frozen' => false]);

        $data = [
            'frozen'     => true,
            'frozen_at'  => time(),
            'reason'     => $reason,
            'prev_state' => $data['frozen'] ?? false,
        ];
        waf_safe_write_json($file, $data);
        return $data;
    }

    /**
     * 解冻 AutoLearn 行为基线
     */
    public static function unfreezeBaseline(): array {
        self::init();
        $file = WAF_LOG_PATH . '/baseline_freeze.json';
        $data = ['frozen' => false, 'unfrozen_at' => time()];
        waf_safe_write_json($file, $data);
        return $data;
    }

    /**
     * AutoLearn 行为基线是否已冻结（供 recordNormal 检查）
     */
    public static function isBaselineFrozen(): bool {
        self::init();
        $file = WAF_LOG_PATH . '/baseline_freeze.json';
        $data = waf_safe_read_json($file, ['frozen' => false]);
        return !empty($data['frozen']);
    }

    // ====================== 学习报告 ======================

    public static function getReport() {
        self::init();
        $stats = self::loadStats();
        $patterns = self::loadPatterns();
        $weights = self::loadWeights();
        $feedback = self::loadFeedback();
        $normal = self::loadNormal();

        $recentTrend = [];
        $now = time();
        for ($i = 6; $i >= 0; $i--) {
            $dayKey = date('Y-m-d', $now - $i * 86400);
            $recentTrend[$dayKey] = $stats['type_trend'][$dayKey] ?? [];
        }

        $topPayloads = [];
        if (!empty($stats['payloads'])) {
            $sorted = $stats['payloads'];
            uasort($sorted, function($a, $b) { return $b['count'] - $a['count']; });
            $topPayloads = array_slice($sorted, 0, 10, true);
        }

        return [
            'total_attacks'      => $stats['total_attacks'] ?? 0,
            'total_learned_rules'=> $patterns['total_learned'] ?? 0,
            'last_learn_time'    => $patterns['last_learn_time'] ?? 0,
            'recent_trend'       => $recentTrend,
            'top_payloads'       => $topPayloads,
            'feedback_count'     => count($feedback),
            'weight_adjustments' => $weights['feedback_adjustments'] ?? [],
            'normal_patterns'    => count($normal['patterns'] ?? []),
            'total_normal'       => $normal['total_normal'] ?? 0,
        ];
    }

    // ====================== [v5.4] 学习系统扩展报告 ======================

    /**
     * [v5.4] 获取智能学习系统的完整状态（供控制台展示）
     * 包含：训练队列、审核队列、评估指标、模型快照
     */
    public static function getLearningStatus(): array {
        self::init();
        $status = [
            'enabled'    => class_exists('Learning_SampleFilter'),
            'scheduler'  => null,
            'review'     => null,
            'evaluation' => null,
            'snapshots'  => [],
            'cold_start' => true,
        ];

        if (class_exists('Learning_TrainingScheduler')) {
            $status['scheduler'] = Learning_TrainingScheduler::stats();
        }
        if (class_exists('Learning_ReviewQueue')) {
            $status['review'] = Learning_ReviewQueue::stats();
        }
        if (class_exists('Learning_ModelEvaluator')) {
            $history = Learning_ModelEvaluator::history(1);
            $status['evaluation'] = !empty($history) ? end($history) : null;
            $status['snapshots'] = Learning_ModelEvaluator::listSnapshots();
        }
        if (class_exists('Learning_SampleFilter')) {
            $status['cold_start'] = Learning_SampleFilter::isColdStart();
        }

        return $status;
    }

    /**
     * [v5.4] 手动触发评估（控制台/CLI 调用）
     */
    public static function evaluateModel(): array {
        if (!class_exists('Learning_ModelEvaluator')) {
            return ['ok' => false, 'reason' => 'evaluator_missing'];
        }
        return Learning_ModelEvaluator::evaluate();
    }

    /**
     * [v5.4] 手动保存模型快照（控制台/CLI 调用）
     */
    public static function snapshotModel(): bool {
        if (!class_exists('Learning_ModelEvaluator')) return false;
        return Learning_ModelEvaluator::snapshot();
    }

    /**
     * [v5.4] 强制 flush 训练队列（CLI/定时任务调用）
     */
    public static function flushTrainingQueue(): int {
        if (!class_exists('Learning_TrainingScheduler')) return 0;
        return Learning_TrainingScheduler::flushNow();
    }

    // ====================== 文件读写（带进程内静态缓存） ======================

    private static function loadStats() {
        return self::cachedLoad('stats', ['payloads' => [], 'total_attacks' => 0, 'type_trend' => []]);
    }
    private static function saveStats($data) { self::cachedSave('stats', $data); }
    private static function loadPatterns() {
        return self::cachedLoad('patterns', ['rules' => [], 'total_learned' => 0, 'last_learn_time' => 0]);
    }
    private static function savePatterns($data) { self::cachedSave('patterns', $data); }
    private static function loadWeights() {
        return self::cachedLoad('weights', ['feedback_adjustments' => [], 'last_feedback_time' => 0]);
    }
    private static function saveWeights($data) { self::cachedSave('weights', $data); }
    private static function loadFeedback() { return self::cachedLoad('feedback', []); }
    private static function saveFeedback($data) { self::cachedSave('feedback', $data); }
    private static function loadNormal() {
        return self::cachedLoad('normal', ['patterns' => [], 'total_normal' => 0]);
    }
    private static function saveNormal($data) { self::cachedSave('normal', $data); }

    private static function getFilePath($key) {
        $map = [
            'stats' => self::$stats_file,
            'patterns' => self::$patterns_file,
            'weights' => self::$weights_file,
            'feedback' => self::$feedback_file,
            'normal' => self::$normal_file,
        ];
        return $map[$key] ?? null;
    }

    private static function cachedLoad($key, $default) {
        $now = time();
        if (isset(self::$static_cache[$key])
            && isset(self::$static_cache_ts[$key])
            && ($now - self::$static_cache_ts[$key]) < self::STATIC_CACHE_TTL) {
            return self::$static_cache[$key];
        }
        $file = self::getFilePath($key);
        if ($file === null) return $default;
        $data = waf_safe_read_json($file, $default);
        self::$static_cache[$key] = $data;
        self::$static_cache_ts[$key] = $now;
        return $data;
    }

    private static function cachedSave($key, $data) {
        $file = self::getFilePath($key);
        if ($file === null) return;
        waf_safe_write_json($file, $data);
        self::$static_cache[$key] = $data;
        self::$static_cache_ts[$key] = time();
    }

    public static function invalidateCache($key = null) {
        if ($key === null) {
            self::$static_cache = [];
            self::$static_cache_ts = [];
        } else {
            unset(self::$static_cache[$key], self::$static_cache_ts[$key]);
        }
    }

    private static function pruneStats($stats) {
        if (empty($stats['payloads'])) return $stats;
        $cutoff = time() - 30 * 86400;
        foreach ($stats['payloads'] as $hash => $info) {
            if ($info['last_seen'] < $cutoff) unset($stats['payloads'][$hash]);
        }
        if (!empty($stats['type_trend'])) {
            $trendCutoff = date('Y-m-d', time() - 7 * 86400);
            foreach ($stats['type_trend'] as $day => $data) {
                if ($day < $trendCutoff) unset($stats['type_trend'][$day]);
            }
        }
        return $stats;
    }
}

// 向后兼容别名
class_alias('AutoLearn', 'WafAutoLearner');