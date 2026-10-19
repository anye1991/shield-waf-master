<?php
defined('ABSPATH') || exit;

/**
 * 纯 PHP 朴素贝叶斯文本分类器
 *
 * 原理：基于词袋模型 + 拉普拉斯平滑，计算 payload 属于"攻击"或"正常"的概率
 * 优势：零依赖、纯PHP、训练快、可解释性强、增量学习方便
 * 用途：辅助WAF评分，作为机器学习维度融入整体评分系统
 *
 * [v5.4] 新增：
 *  - getRawModel()            获取原始模型数据（供 RobinsonFisher 等外部引擎读取）
 *  - getScoreDimensions()     5 维评分（贝叶斯概率/置信度/词汇匹配/特殊特征/长度惩罚）
 *  - getScoreDimensionsSafe() 容错版 5 维评分（异常时返回零值，不抛错）
 *  - getModelStats()          模型健康度统计（样本均衡/词汇覆盖/训练新鲜度）
 *
 * 开源版轻量实现：不搞复杂算法，只求实用有效
 */
class NaiveBayesClassifier {

    private static $modelFile = null;
    private static $model = null;
    private static $loaded = false;

    /** 5 维评分权重（可通过 setScoreWeights 调整） */
    private static $scoreWeights = [
        'bayes_prob'     => 0.40,
        'confidence'     => 0.20,
        'vocab_match'    => 0.15,
        'special_token'  => 0.15,
        'length_penalty' => 0.10,
    ];

    /**
     * 获取模型存储文件路径
     */
    private static function getModelFile(): string {
        if (self::$modelFile !== null) {
            return self::$modelFile;
        }
        $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
        self::$modelFile = $logDir . '/bayes_model.json';
        return self::$modelFile;
    }

    /**
     * 加载模型
     */
    private static function loadModel(): void {
        if (self::$loaded) return;
        self::$loaded = true;

        $file = self::getModelFile();
        if (!is_file($file)) {
            self::$model = self::emptyModel();
            return;
        }

        $raw = @file_get_contents($file);
        if ($raw === false) {
            self::$model = self::emptyModel();
            return;
        }

        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['classes'])) {
            self::$model = self::emptyModel();
            return;
        }

        self::$model = $data;
    }

    /**
     * 保存模型
     */
    private static function saveModel(): void {
        $file = self::getModelFile();
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        @file_put_contents($file, json_encode(self::$model, JSON_UNESCAPED_SLASHES), LOCK_EX);
    }

    /**
     * 空模型初始化
     */
    private static function emptyModel(): array {
        return [
            'classes' => [
                'attack' => ['count' => 0, 'tokens' => []],
                'normal' => ['count' => 0, 'tokens' => []],
            ],
            'vocab' => [],
            'vocab_size' => 0,
            'trained_at' => 0,
        ];
    }

    /**
     * 文本分词（字符级 n-gram + 关键字提取）
     * WAF payload 用字符 2-gram + 3-gram 效果最好
     */
    public static function tokenize(string $text): array {
        $text = strtolower(trim($text));
        if ($text === '') return [];

        $tokens = [];
        $len = strlen($text);

        if ($len < 4) {
            $tokens[] = $text;
            return $tokens;
        }

        for ($i = 0; $i < $len - 1; $i++) {
            $tokens[] = substr($text, $i, 2);
        }

        for ($i = 0; $i < $len - 2; $i++) {
            $tokens[] = substr($text, $i, 3);
        }

        $specialTokens = self::extractSpecialTokens($text);
        $tokens = array_merge($tokens, $specialTokens);

        return $tokens;
    }

    /**
     * 提取 WAF 场景的特殊特征 token
     */
    private static function extractSpecialTokens(string $text): array {
        $tokens = [];

        if (preg_match('/\b(union|select|insert|delete|drop|update|alter|create)\b/i', $text)) {
            $tokens[] = '__sql_keyword__';
        }
        if (preg_match('/<script|javascript:|on\w+\s*=|eval\s*\(/i', $text)) {
            $tokens[] = '__xss_pattern__';
        }
        if (preg_match('/\.\.[\/\\\\]|\/etc\/|\/proc\/|php:\/\/|file:\/\//i', $text)) {
            $tokens[] = '__path_trav__';
        }
        if (preg_match('/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i', $text)) {
            $tokens[] = '__cmd_exec__';
        }
        if (preg_match('/\{\{.*\}\}|<%.*%>|\$\{.*\}/', $text)) {
            $tokens[] = '__ssti_pattern__';
        }
        if (preg_match('/169\.254\.|10\.0\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost/i', $text)) {
            $tokens[] = '__internal_ip__';
        }
        if (preg_match('/base64_decode|str_rot13|gzinflate|strrev/i', $text)) {
            $tokens[] = '__obfuscation__';
        }

        return $tokens;
    }

    /**
     * 训练单个样本
     */
    public static function train(string $text, string $class): void {
        self::loadModel();

        $tokens = self::tokenize($text);
        if (empty($tokens)) return;

        if (!isset(self::$model['classes'][$class])) {
            self::$model['classes'][$class] = ['count' => 0, 'tokens' => []];
        }

        self::$model['classes'][$class]['count']++;

        $tokenCounts = array_count_values($tokens);
        foreach ($tokenCounts as $token => $count) {
            if (!isset(self::$model['classes'][$class]['tokens'][$token])) {
                self::$model['classes'][$class]['tokens'][$token] = 0;
            }
            self::$model['classes'][$class]['tokens'][$token] += $count;

            if (!isset(self::$model['vocab'][$token])) {
                self::$model['vocab'][$token] = true;
                self::$model['vocab_size']++;
            }
        }

        self::$model['trained_at'] = time();
    }

    /**
     * 批量训练后保存
     */
    public static function save(): void {
        if (self::$model !== null) {
            self::$model['trained_at'] = time();
            self::saveModel();
        }
    }

    /**
     * 预测文本类别
     * 返回：['class' => 'attack'/'normal', 'confidence' => 0-1, 'attack_prob' => 0-1]
     */
    public static function predict(string $text): array {
        self::loadModel();

        $totalAttack = self::$model['classes']['attack']['count'] ?? 0;
        $totalNormal = self::$model['classes']['normal']['count'] ?? 0;
        $total = $totalAttack + $totalNormal;

        if ($total < 10) {
            return ['class' => 'unknown', 'confidence' => 0, 'attack_prob' => 0.5, 'reason' => 'insufficient_training'];
        }

        $tokens = self::tokenize($text);
        if (empty($tokens)) {
            return ['class' => 'normal', 'confidence' => 0.5, 'attack_prob' => 0.1, 'reason' => 'empty_text'];
        }

        $vocabSize = max(self::$model['vocab_size'], 1);

        $logProbAttack = log(($totalAttack + 1) / ($total + 2));
        $logProbNormal = log(($totalNormal + 1) / ($total + 2));

        $attackTokens = self::$model['classes']['attack']['tokens'] ?? [];
        $normalTokens = self::$model['classes']['normal']['tokens'] ?? [];
        $attackTotalCount = array_sum($attackTokens);
        $normalTotalCount = array_sum($normalTokens);

        $tokenCounts = array_count_values($tokens);
        $matchingTokens = 0;

        foreach ($tokenCounts as $token => $count) {
            $attackCount = $attackTokens[$token] ?? 0;
            $normalCount = $normalTokens[$token] ?? 0;

            if ($attackCount > 0 || $normalCount > 0) {
                $matchingTokens++;
            }

            $logProbAttack += $count * log(($attackCount + 1) / ($attackTotalCount + $vocabSize));
            $logProbNormal += $count * log(($normalCount + 1) / ($normalTotalCount + $vocabSize));
        }

        $maxLog = max($logProbAttack, $logProbNormal);
        $probAttack = exp($logProbAttack - $maxLog);
        $probNormal = exp($logProbNormal - $maxLog);
        $totalProb = $probAttack + $probNormal;

        $attackProb = $totalProb > 0 ? $probAttack / $totalProb : 0.5;
        $confidence = abs($attackProb - 0.5) * 2;

        $matchingRatio = count($tokens) > 0 ? $matchingTokens / count($tokens) : 0;
        if ($matchingRatio < 0.1) {
            $confidence *= 0.5;
        }

        return [
            'class' => $attackProb > 0.5 ? 'attack' : 'normal',
            'confidence' => round($confidence, 4),
            'attack_prob' => round($attackProb, 4),
            'matching_ratio' => round($matchingRatio, 4),
            'reason' => $matchingRatio < 0.1 ? 'low_vocab_match' : 'classified',
        ];
    }

    /**
     * 获取攻击概率分（0-100），方便直接融入评分系统
     */
    public static function getAttackScore(string $text): float {
        $result = self::predict($text);
        if ($result['reason'] === 'insufficient_training') {
            return 0;
        }
        $score = $result['attack_prob'] * 100 * $result['confidence'];
        return (float)round(min($score, 100), 1);
    }

    // ====================== [v5.4] 原始模型读取 ======================

    /**
     * [v5.4] 获取原始模型数据（供 RobinsonFisher / FingerprintMatcher 等外部引擎读取）
     *
     * 返回完整模型数组，调用方自行负责不修改。
     * 空模型时返回 emptyModel() 结构。
     */
    public static function getRawModel(): array {
        self::loadModel();
        return self::$model ?? self::emptyModel();
    }

    // ====================== [v5.4] 5 维评分 ======================

    /**
     * [v5.4] 5 维评分
     * 返回：总分 + 各维度分值 + 权重说明
     *
     * 维度：
     *  1. bayes_prob     贝叶斯攻击概率（0-100）
     *  2. confidence     模型置信度（0-100）
     *  3. vocab_match    词汇匹配率（0-100），模型对这段文本的"熟悉度"
     *  4. special_token  特殊特征命中（0-100），SQL/XSS/路径遍历等特征 token 数
     *  5. length_penalty 长度惩罚（0-100），超长 payload 更可疑
     *
     * 返回：
     *  [
     *    'total'   => 0-100 总分,
     *    'dims'    => ['bayes_prob'=>.., 'confidence'=>.., ...],
     *    'weights' => ['bayes_prob'=>0.4, ...],
     *    'reason'  => 'scored' / 'insufficient_training' / 'empty_text',
     *  ]
     */
    public static function getScoreDimensions(string $text): array {
        $result = self::predict($text);

        if (($result['reason'] ?? '') === 'insufficient_training') {
            return [
                'total'   => 0.0,
                'dims'    => [],
                'weights' => self::$scoreWeights,
                'reason'  => 'insufficient_training',
            ];
        }

        $tokens = self::tokenize($text);
        if (empty($tokens)) {
            return [
                'total'   => 0.0,
                'dims'    => [],
                'weights' => self::$scoreWeights,
                'reason'  => 'empty_text',
            ];
        }

        // 维度 1：贝叶斯攻击概率
        $d1 = ($result['attack_prob'] ?? 0.5) * 100;

        // 维度 2：置信度
        $d2 = ($result['confidence'] ?? 0) * 100;

        // 维度 3：词汇匹配率
        $d3 = ($result['matching_ratio'] ?? 0) * 100;

        // 维度 4：特殊特征命中（每个特殊 token 25 分，上限 100）
        $special = self::extractSpecialTokens(strtolower($text));
        $d4 = min(count($special) * 25, 100);

        // 维度 5：长度惩罚（>500 字节 80 分，>200 字节 60 分，其余 30 分）
        $len = strlen($text);
        if ($len > 500) {
            $d5 = 80.0;
        } elseif ($len > 200) {
            $d5 = 60.0;
        } else {
            $d5 = 30.0;
        }

        // 加权总分
        $w = self::$scoreWeights;
        $total = $d1 * $w['bayes_prob']
               + $d2 * $w['confidence']
               + $d3 * $w['vocab_match']
               + $d4 * $w['special_token']
               + $d5 * $w['length_penalty'];

        $total = max(0.0, min(100.0, $total));

        return [
            'total' => round($total, 1),
            'dims'  => [
                'bayes_prob'     => round($d1, 1),
                'confidence'     => round($d2, 1),
                'vocab_match'    => round($d3, 1),
                'special_token'  => round($d4, 1),
                'length_penalty' => round($d5, 1),
            ],
            'weights' => $w,
            'reason'  => 'scored',
        ];
    }

    /**
     * [v5.4] 容错版 5 维评分：任何异常都返回零值，不抛错
     * 供控制台/评分引擎等"不能因 ML 模块异常而崩溃"的场景调用
     */
    public static function getScoreDimensionsSafe(string $text): array {
        try {
            return self::getScoreDimensions($text);
        } catch (\Throwable $e) {
            return [
                'total'   => 0.0,
                'dims'    => [],
                'weights' => self::$scoreWeights,
                'reason'  => 'exception: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * [v5.4] 设置 5 维评分权重（权重和会自动归一化）
     * @param array $weights 形如 ['bayes_prob'=>0.4, 'confidence'=>0.2, ...]
     */
    public static function setScoreWeights(array $weights): void {
        $keys = ['bayes_prob', 'confidence', 'vocab_match', 'special_token', 'length_penalty'];
        $merged = [];
        $sum = 0.0;
        foreach ($keys as $k) {
            $v = max(0.0, (float)($weights[$k] ?? self::$scoreWeights[$k]));
            $merged[$k] = $v;
            $sum += $v;
        }
        if ($sum <= 0) return; // 全零则忽略
        // 归一化，保证权重和 = 1
        foreach ($merged as $k => $v) {
            $merged[$k] = round($v / $sum, 4);
        }
        self::$scoreWeights = $merged;
    }

    /**
     * [v5.4] 获取当前 5 维评分权重
     */
    public static function getScoreWeights(): array {
        return self::$scoreWeights;
    }

    // ====================== [v5.4] 模型健康度 ======================

    /**
     * [v5.4] 获取模型健康度统计
     * 供控制台展示：样本是否均衡、词汇覆盖、训练新鲜度、冷启动状态
     */
    public static function getModelStats(): array {
        self::loadModel();

        $attack = (int)(self::$model['classes']['attack']['count'] ?? 0);
        $normal = (int)(self::$model['classes']['normal']['count'] ?? 0);
        $total = $attack + $normal;
        $vocabSize = (int)(self::$model['vocab_size'] ?? 0);
        $trainedAt = (int)(self::$model['trained_at'] ?? 0);

        $attackTokens = self::$model['classes']['attack']['tokens'] ?? [];
        $normalTokens = self::$model['classes']['normal']['tokens'] ?? [];

        // 类别均衡度：0（严重偏斜）~ 1（完全均衡）
        $balance = 0.0;
        if ($total > 0) {
            $ratio = min($attack, $normal) / max($attack, $normal, 1);
            $balance = round($ratio, 4);
        }

        // 训练新鲜度：天数，0 = 今天训练过
        $daysSinceTrain = $trainedAt > 0 ? round((time() - $trainedAt) / 86400, 1) : -1;

        // 冷启动判断
        $coldStart = ($total < 30) || ($attack < 10) || ($normal < 10);

        return [
            'attack_count'    => $attack,
            'normal_count'    => $normal,
            'total_count'     => $total,
            'vocab_size'      => $vocabSize,
            'attack_token_kinds'  => count($attackTokens),
            'normal_token_kinds'  => count($normalTokens),
            'class_balance'   => $balance,
            'trained_at'      => $trainedAt,
            'trained_at_str'  => $trainedAt > 0 ? date('Y-m-d H:i:s', $trainedAt) : 'never',
            'days_since_train'=> $daysSinceTrain,
            'cold_start'      => $coldStart,
            'health'          => self::healthLabel($total, $balance, $coldStart),
        ];
    }

    /**
     * [v5.4] 模型健康度标签
     */
    private static function healthLabel(int $total, float $balance, bool $coldStart): string {
        if ($coldStart) return 'cold_start';
        if ($balance < 0.3) return 'imbalanced';
        if ($total < 100) return 'warming_up';
        if ($balance >= 0.6 && $total >= 500) return 'healthy';
        return 'fair';
    }

    /**
     * 获取模型状态信息
     */
    public static function getModelInfo(): array {
        self::loadModel();
        return [
            'attack_count' => self::$model['classes']['attack']['count'] ?? 0,
            'normal_count' => self::$model['classes']['normal']['count'] ?? 0,
            'vocab_size' => self::$model['vocab_size'] ?? 0,
            'trained_at' => self::$model['trained_at'] ?? 0,
            'trained_at_str' => self::$model['trained_at'] ? date('Y-m-d H:i:s', self::$model['trained_at']) : 'never',
        ];
    }

    /**
     * 重置模型
     */
    public static function reset(): void {
        self::$model = self::emptyModel();
        self::$loaded = true;
        self::saveModel();
    }
}