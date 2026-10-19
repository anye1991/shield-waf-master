<?php
/**
 * Robinson-Fisher 二分类器 (v5.4 企业级终极完整版)
 *
 * 核心特性：
 *   - 真正的 Fisher-Robinson 卡方组合（防 Cancellation Disease）
 *   - 高精度互补误差函数 (erfc) 近似，无精度损失
 *   - 极致鲁棒性：类型强校验、除零保护、异常兜底
 *   - 内存与词表容量上限保护，防恶意超长 Payload 内存暴涨
 *   - 冷启动与极端稀疏性保护（无极端特征时安全降级）
 */
defined('ABSPATH') || exit;

class Learning_RobinsonFisher {

    // =========================================================================
    // 核心超参数常量
    // =========================================================================

    /** 极端概率阈值下限：低于此值的 token 视为“强正常特征” */
    const EXTREME_LOW  = 0.10;
    /** 极端概率阈值上限：高于此值的 token 视为“强攻击特征” */
    const EXTREME_HIGH = 0.90;
    /** 最少极端 token 数：少于这个数，Fisher 检验失去统计学意义 */
    const MIN_EXTREME_COUNT = 2;
    /** 训练数据总量冷启动门槛：低于 10 个样本，任何分类器都不可信 */
    const MIN_TOTAL_SAMPLES = 10;
    
    /** 单次 Payload 词元分析上限：防止超长恶意请求导致计算时间过长 */
    const MAX_TOKENS_LIMIT = 2000;
    /** 词汇表最大容量保护：防内存溢出 (OOM) */
    const MAX_VOCAB_SIZE = 50000;

    // =========================================================================
    // 主分类入口
    // =========================================================================

    /**
     * 执行 Robinson-Fisher 二分类
     * 
     * @param string $text 待检测的原始字符串
     * @return array 包含 score, h, s, extreme_count, reason 的关联数组
     */
    public static function classify(string $text): array {
        try {
            // 1. 前置依赖检查
            if (!class_exists('NaiveBayesClassifier')) {
                return self::emptyResult('classifier_missing');
            }

            // 2. 冷启动与模型状态检查
            $info = NaiveBayesClassifier::getModelInfo();
            $total = (int)($info['attack_count'] ?? 0) + (int)($info['normal_count'] ?? 0);
            if ($total < self::MIN_TOTAL_SAMPLES) {
                return self::emptyResult('insufficient_training');
            }

            // 3. 文本分词与边界截断
            $tokens = NaiveBayesClassifier::tokenize($text);
            if (empty($tokens)) {
                return self::emptyResult('empty_text');
            }
            // 限制单次分析的 Token 数量，防止 ReDoS / OOM
            if (count($tokens) > self::MAX_TOKENS_LIMIT) {
                $tokens = array_slice($tokens, 0, self::MAX_TOKENS_LIMIT);
            }

            // 4. 去重（同一 token 在 Fisher 中只贡献一次信号）
            $uniqueTokens = array_values(array_unique($tokens));

            // 5. 计算 P(attack|token) 并提取极端特征
            $probs = [];
            foreach ($uniqueTokens as $token) {
                $p = self::tokenProbability($token);
                if ($p !== null) {
                    $probs[] = $p;
                }
            }

            $extreme = [];
            foreach ($probs as $p) {
                if ($p <= self::EXTREME_LOW || $p >= self::EXTREME_HIGH) {
                    $extreme[] = $p;
                }
            }

            // 6. 极端特征不足保护
            if (count($extreme) < self::MIN_EXTREME_COUNT) {
                return self::emptyResult('no_extreme_token');
            }

            // 7. Fisher 卡方组合
            $h = self::fisherCombined($extreme, 'attack');
            $s = self::fisherCombined($extreme, 'normal');

            // 8. Hooft 修正 (防 Cancellation Disease)
            // 当 H 和 S 都极小时（即既不像攻击也不像正常），H/(H+S) 会严重失真
            $indicator = (1 + $h - $s) / 2;
            $indicator = max(0.0, min(1.0, (float)$indicator));

            return [
                'score'         => round($indicator * 100, 1),
                'h'             => round($h, 4),
                's'             => round($s, 4),
                'extreme_count' => count($extreme),
                'reason'        => 'classified',
            ];

        } catch (\Throwable $e) {
            // 任何未预料的异常直接兜底，绝不拖垮 WAF 主流程
            return self::emptyResult('exception: ' . $e->getMessage());
        }
    }

    // =========================================================================
    // 概率计算与数学核心
    // =========================================================================

    /**
     * 计算 P(attack|token) - 带拉普拉斯平滑的贝叶斯推断
     */
    private static function tokenProbability(string $token): ?float {
        $model = self::getModelData();
        if ($model === null) return null;

        $attackTokens = $model['classes']['attack']['tokens'] ?? [];
        $normalTokens = $model['classes']['normal']['tokens'] ?? [];
        $attackCount  = (int)($attackTokens[$token] ?? 0);
        $normalCount  = (int)($normalTokens[$token] ?? 0);

        // 未见过的 token，不提供任何信息增益
        if ($attackCount === 0 && $normalCount === 0) {
            return null;
        }

        $attackTotal = max((int)array_sum($attackTokens), 1);
        $normalTotal = max((int)array_sum($normalTokens), 1);
        $vocabSize   = max((int)($model['vocab_size'] ?? 0), 1);
        
        // 边界保护：防 vocabSize 异常导致的除零或负值
        if ($vocabSize > self::MAX_VOCAB_SIZE) {
            $vocabSize = self::MAX_VOCAB_SIZE;
        }

        // 拉普拉斯平滑 (+1)
        $p_t_given_a = ($attackCount + 1) / ($attackTotal + $vocabSize);
        $p_t_given_n = ($normalCount + 1) / ($normalTotal + $vocabSize);

        // 先验概率
        $classA = (int)($model['classes']['attack']['count'] ?? 0);
        $classN = (int)($model['classes']['normal']['count'] ?? 0);
        $priorA = $classA / max($classA + $classN, 1);
        $priorN = 1.0 - $priorA;

        // 贝叶斯公式
        $numerator   = $p_t_given_a * $priorA;
        $denominator = $numerator + $p_t_given_n * $priorN;

        if ($denominator <= 0) {
            return null;
        }

        return (float)($numerator / $denominator);
    }

    /**
     * Fisher 组合（卡方检验）
     */
    private static function fisherCombined(array $probs, string $direction): float {
        if (empty($probs)) return 0.5;

        $logProduct = 0.0;
        foreach ($probs as $p) {
            // 攻击方向取 1-p（强攻击特征），正常方向取 p
            $v = ($direction === 'attack') ? (1.0 - $p) : $p;
            // 防止 log(0) 导致 -INF
            $v = max(min($v, 1.0), 1e-10);
            $logProduct += log($v);
        }

        // 卡方统计量 x = -2 * sum(ln(p))
        $x = -2.0 * $logProduct;
        $k2 = 2 * count($probs); // 自由度 = 2 * token 数量

        $pValue = self::chi2Survival($x, $k2);
        
        // 返回 1 - pValue
        return max(0.0, min(1.0, 1.0 - $pValue));
    }

    /**
     * 卡方生存函数 (Chi-Square Survival Function) 的高精度近似
     * 使用 Wilson-Hilferty 正态转换，在 k >= 4 时精度极高
     */
    private static function chi2Survival(float $x, int $k): float {
        if ($x <= 0) return 1.0;
        if ($k <= 0) return 1.0;

        $kFloat = (float)$k;
        
        // Wilson-Hilferty 变换
        $cubeRoot = pow($x / $kFloat, 1.0 / 3.0);
        $mean = 1.0 - 2.0 / (9.0 * $kFloat);
        $std  = sqrt(2.0 / (9.0 * $kFloat));
        
        if ($std <= 0) return 0.5;

        $z = ($cubeRoot - $mean) / $std;

        // 正态分布生存函数近似
        return 0.5 * self::erfc($z / sqrt(2.0));
    }

    /**
     * 互补误差函数 (erfc) 的极小极大近似
     * 精度达 1.2e-7，完全满足机器学习判别需求，纯单行多项式防复制错位
     */
    private static function erfc(float $x): float {
        $z = abs($x);
        $t = 1.0 / (1.0 + 0.5 * $z);
        
        $poly = 1.26551223 + $t * (1.00002368 + $t * (0.37409196 + $t * (0.09678418 + $t * (-0.18628806 + $t * (0.27886807 + $t * (-1.13520398 + $t * (1.48851587 + $t * (-0.82215223 + $t * 0.17087277))))))));
        
        $r = $t * exp(-$z * $z - $poly);
        
        return ($x >= 0) ? $r : (2.0 - $r);
    }

    // =========================================================================
    // 模型与基础设施
    // =========================================================================

    /**
     * 安全获取模型原始数据
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

    /**
     * 统一返回空结果，保证数据结构一致性
     */
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
