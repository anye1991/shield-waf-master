<?php
defined('ABSPATH') || exit;

/**
 * 纯 PHP 朴素贝叶斯文本分类器
 *
 * 原理：基于词袋模型 + 拉普拉斯平滑，计算 payload 属于"攻击"或"正常"的概率
 * 优势：零依赖、纯PHP、训练快、可解释性强、增量学习方便
 * 用途：辅助WAF评分，作为机器学习维度融入整体评分系统
 *
 * 开源版轻量实现：不搞复杂算法，只求实用有效
 */
class NaiveBayesClassifier {

    private static $modelFile = null;
    private static $model = null;
    private static $loaded = false;

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
