<?php
/**
 * Robinson-Fisher 二分类器 (v5.4)
 *
 * 原理：
 *   - 对每个 token 计算 P(attack|token)
 *   - 只保留"极端概率"的 token（<=0.1 或 >=0.9），这是 Fisher-Robinson 的核心
 *   - 用卡方检验组合极端 token 的判别力，得到 H（attack 假设）和 S（normal 假设）
 *   - 用 (1 + H - S) / 2 合并，防 cancellation disease
 *
 * 优势：
 *   - 比标准 NB 对"极端 token"更敏感，适合不均衡二分类
 *   - 复用 NaiveBayesClassifier 的模型数据，不重复训练
 *   - 纯 PHP，无外部依赖
 *
 * 用途：
 *   - 作为 WAF 多引擎融合的第二个 ML 信号源
 *   - 与朴素贝叶斯、规则引擎、指纹匹配共同投票
 */
defined('ABSPATH') || exit;

class Learning_RobinsonFisher {

    /** 极端概率阈值（<=0.1 或 >=0.9） */
    const EXTREME_LOW  = 0.10;
    const EXTREME_HIGH = 0.90;

    /** 最少极端 token 数（少于这个数，RF 结果不可信） */
    const MIN_EXTREME_COUNT = 2;

    /** 冷启动门槛（与 NaiveBayesClassifier 一致） */
    const MIN_TOTAL_SAMPLES = 10;

    /**
     * 分类入口
     * @param string $text
     * @return array [
     *   'score'         => 0-100 攻击概率（RF 视角）,
     *   'h'             => attack 假设的 Fisher 组合值,
     *   's'             => normal 假设的 Fisher 组合值,
     *   'extreme_count' => 极端 token 数,
     *   'reason'        => 'classified' / 'insufficient_training' / 'no_extreme_token',
     * ]
     */
    public static function classify(string $text): array {
        if (!class_exists('NaiveBayesClassifier')) {
            return self::emptyResult('classifier_missing');
        }

        // 复用贝叶斯的模型信息
        $info = NaiveBayesClassifier::getModelInfo();
        $total = (int)$info['attack_count'] + (int)$info['normal_count'];
        if ($total < self::MIN_TOTAL_SAMPLES) {
            return self::emptyResult('insufficient_training');
        }

        $tokens = NaiveBayesClassifier::tokenize($text);
        if (empty($tokens)) {
            return self::emptyResult('empty_text');
        }

        // 去重（同一 token 多次出现不重复计入 Fisher，避免长 payload 稀释）
        $uniqueTokens = array_unique($tokens);

        // 计算每个 token 的 P(attack|token)
        $probs = [];
        foreach ($uniqueTokens as $token) {
            $p = self::tokenProbability($token);
            if ($p !== null) $probs[] = $p;
        }

        // 只保留极端 token
        $extreme = [];
        foreach ($probs as $p) {
            if ($p <= self::EXTREME_LOW || $p >= self::EXTREME_HIGH) {
                $extreme[] = $p;
            }
        }

        if (count($extreme) < self::MIN_EXTREME_COUNT) {
            return self::emptyResult('no_extreme_token');
        }

        // Fisher 组合
        $h = self::fisherCombined($extreme, 'attack');
        $s = self::fisherCombined($extreme, 'normal');

        // Hooft 修正：防 cancellation disease（H 和 S 都极小时，简单 H/(H+S) 会误导）
        $indicator = (1 + $h - $s) / 2;
        $indicator = max(0.0, min(1.0, $indicator));

        return [
            'score'         => round($indicator * 100, 1),
            'h'             => round($h, 4),
            's'             => round($s, 4),
            'extreme_count' => count($extreme),
            'reason'        => 'classified',
        ];
    }

    /**
     * 计算 P(attack|token)
     * 用贝叶斯公式的简化版：P(A|t) = (P(t|A) * P(A)) / (P(t|A)*P(A) + P(t|N)*P(N))
     * 概率接近 1 表示"强攻击特征"，接近 0 表示"强正常特征"
     */
    private static function tokenProbability(string $token): ?float {
        // 通过 NaiveBayesClassifier 的模型数据读取 token 计数
        // 注意：这里需要访问模型的私有数据，用反射或新增公共方法
        $model = self::getModelData();
        if ($model === null) return null;

        $attackTokens = $model['classes']['attack']['tokens'] ?? [];
        $normalTokens = $model['classes']['normal']['tokens'] ?? [];
        $attackCount  = (int)($attackTokens[$token] ?? 0);
        $normalCount  = (int)($normalTokens[$token] ?? 0);

        // 两个类都没见过这个 token，不参与计算
        if ($attackCount === 0 && $normalCount === 0) return null;

        $attackTotal = max(array_sum($attackTokens), 1);
        $normalTotal = max(array_sum($normalTokens), 1);
        $vocabSize   = max((int)($model['vocab_size'] ?? 0), 1);

        // 拉普拉斯平滑
        $p_t_given_a = ($attackCount + 1) / ($attackTotal + $vocabSize);
        $p_t_given_n = ($normalCount + 1) / ($normalTotal + $vocabSize);

        // 先验
        $priorA = (int)($model['classes']['attack']['count'] ?? 0) / max(
            (int)($model['classes']['attack']['count'] ?? 0) + (int)($model['classes']['normal']['count'] ?? 0),
            1
        );
        $priorN = 1 - $priorA;

        $numerator = $p_t_given_a * $priorA;
        $denominator = $numerator + $p_t_given_n * $priorN;
        if ($denominator <= 0) return null;

        return $numerator / $denominator;
    }

    /**
     * Fisher 组合公式
     * p_combined = 1 - I_{x}(k/2, 1/2)，其中 x = -2 * ln(prod(p))
     * 用卡方分布近似：p ≈ 1 - chi2_cdf(x, 2k)
     * 为纯 PHP 高效，用不完全伽马函数的级数展开近似
     */
    private static function fisherCombined(array $probs, string $direction): float {
        if (empty($probs)) return 0.5;

        $logProduct = 0.0;
        foreach ($probs as $p) {
            // 对 attack 方向用 (1-p)，对 normal 方向用 p
            // 含义：如果 token 是"攻击特征"（p 接近 1），(1-p) 很小，prod 很小，x 很大
            //       → 卡方 p 值很小 → 1 - p 值接近 1 → H 高（强支持 attack）
            $v = ($direction === 'attack') ? (1 - $p) : $p;
            $v = max(min($v, 1.0), 1e-10); // 防 log(0)
            $logProduct += log($v);
        }

        $x = -2.0 * $logProduct;
        $k2 = 2 * count($probs); // 卡方自由度

        // p 值 = 1 - chi2_cdf(x, k2)
        // 用正则化不完全伽马函数近似
        $pValue = self::chi2Survival($x, $k2);

        return max(0.0, min(1.0, 1.0 - $pValue));
    }

    /**
     * 卡方分布生存函数（1 - CDF）近似
     * 用 Wilson-Hilferty 变换近似，精度足够 WAF 场景
     * chi2(k) 近似为 k * (1 - 2/(9k) + z * sqrt(2/(9k)))^3，其中 z 是标准正态分位数
     */
    private static function chi2Survival(float $x, int $k): float {
        if ($x <= 0) return 1.0;
        if ($k <= 0) return 1.0;

        $k = (float)$k;
        // Wilson-Hilferty: (x/k)^(1/3) 近似正态
        $cubeRoot = pow($x / $k, 1.0 / 3.0);
        $mean = 1.0 - 2.0 / (9.0 * $k);
        $std  = sqrt(2.0 / (9.0 * $k));
        if ($std <= 0) return 0.5;

        $z = ($cubeRoot - $mean) / $std;

        // 标准正态生存函数 1 - Φ(z)，用 erfc 近似
        return 0.5 * self::erfc($z / sqrt(2.0));
    }

    /** 互补误差函数 erfc 近似（数值稳定，精度 ~1e-7） */
    private static function erfc(float $x): float {
        // Abramowitz & Stegun 7.1.26
        $z = abs($x);
        $t = 1.0 / (1.0 + 0.5 * $z);
        $r = $t * exp(
            -$z * $z - 1.26551223
            + $t * (1.00002368
            + $t * (0.37409196
            + $t * (0.09678418
            + $t * (-0.18628806
            + $t * (0.27886807
            + $t * (-1.13520398
            + $t * (1.48851587
            + $t * (-0.82215223
            + $t * 0.17087277)))))))))
        );
        return $x >= 0 ? $r : 2.0 - $r;
    }

    /**
     * 读模型数据（通过 NaiveBayesClassifier 新增的 getRawModel 方法）
     * 如果该方法不存在，降级返回 null
     */
    private static function getModelData(): ?array {
        if (!method_exists('NaiveBayesClassifier', 'getRawModel')) {
            return null;
        }
        try {
            $m = NaiveBayesClassifier::getRawModel();
            return is_array($m) ? $m : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function emptyResult(string $reason): array {
        return [
            'score'         => 0.0,
            'h'             => 0.0,
            's'             => 0.0,
            'extreme_count' => 0,
            'reason'        => $reason,
        ];
    }
}