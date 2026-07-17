<?php
/**
 * 盾甲 WAF 机器人评分计算模块 (bot/BotScorer.php)
 *
 * 功能：
 *  1. 四维评分：指纹 30% / 语义 30% / 行为 25% / 攻击链 15%
 *  2. 输出总分与各维度子分
 */
defined('ABSPATH') || exit;

class BotScorer {
    // 维度权重
    const W_FINGERPRINT = 0.30;
    const W_SEMANTIC    = 0.30;
    const W_BEHAVIOR    = 0.25;
    const W_CHAIN       = 0.15;

    /**
     * 综合评分
     * @param array $fingerprint BotFingerprint::analyze 结果
     * @param array $behavior    行为数据（含 path_diversity, interval_uniformity, resource_bias, request_rate, attack_chain, probe_count, error_rate）
     * @param array $semantic    BotSemantic::analyze 结果
     * @return array
     */
    public static function score(array $fingerprint, array $behavior, array $semantic): array {
        // ---------- 指纹分 ----------
        $fingerprint_score = (int)($fingerprint['score'] ?? 0);

        // ---------- 语义分 ----------
        $semantic_score = (int)($semantic['score'] ?? 0);

        // ---------- 行为分 ----------
        $behavior_score = self::computeBehaviorScore($behavior);

        // ---------- 攻击链分 ----------
        $chain_score = self::computeChainScore($behavior, $fingerprint);

        // ---------- 加权总分 ----------
        $total = (int)round(
            $fingerprint_score * self::W_FINGERPRINT +
            $semantic_score    * self::W_SEMANTIC +
            $behavior_score    * self::W_BEHAVIOR +
            $chain_score       * self::W_CHAIN
        );
        $total = max(0, min(100, $total));

        return [
            'total_score'       => $total,
            'fingerprint_score' => $fingerprint_score,
            'behavior_score'    => $behavior_score,
            'semantic_score'    => $semantic_score,
            'chain_score'       => $chain_score,
        ];
    }

    /**
     * 行为分计算
     * 综合路径多样性、间隔均匀度、资源偏好与请求速率
     */
    private static function computeBehaviorScore(array $behavior): int {
        $score = 0;

        $path_diversity      = $behavior['path_diversity'] ?? 0; // 0-100
        $interval_uniformity = $behavior['interval_uniformity'] ?? 0; // 0-100
        $resource_bias       = $behavior['resource_bias'] ?? 0; // 0-100
        $request_rate        = $behavior['request_rate'] ?? 0; // 每分钟请求数

        // 路径多样性 0-100 → 贡献 0-30
        $score += (int)min(30, $path_diversity * 0.30);

        // 间隔均匀度 0-100 → 贡献 0-25
        $score += (int)min(25, $interval_uniformity * 0.25);

        // 资源偏好（仅 API 无静态）0-100 → 贡献 0-25
        $score += (int)min(25, $resource_bias * 0.25);

        // 请求速率：>120/min 视为高频
        if ($request_rate > 120) {
            $score += 20;
        } elseif ($request_rate > 60) {
            $score += 12;
        } elseif ($request_rate > 30) {
            $score += 6;
        }

        return (int)min(100, $score);
    }

    /**
     * 攻击链分计算
     * 检测行为序列中的攻击模式与探测行为
     */
    private static function computeChainScore(array $behavior, array $fingerprint): int {
        $score = 0;

        // 行为侧攻击链指标
        $attack_chain = $behavior['attack_chain'] ?? 0;
        $score += (int)min(60, $attack_chain * 0.6);

        // 探测行为：访问敏感路径次数
        $probe_count = $behavior['probe_count'] ?? 0;
        if ($probe_count > 0) {
            $score += (int)min(25, $probe_count * 5);
        }

        // 错误请求率（百分比）
        $error_rate = $behavior['error_rate'] ?? 0;
        if ($error_rate > 50) {
            $score += 15;
        } elseif ($error_rate > 20) {
            $score += 8;
        }

        // 指纹为恶意类型时加成
        $fp_type = $fingerprint['type'] ?? 'unknown';
        if ($fp_type === 'malicious') {
            $score += 10;
        }

        return (int)min(100, $score);
    }
}
