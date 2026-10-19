<?php
/**
 * 样本采集器
 * 职责：从 attackResult 中采集训练样本，字段缺失时兜底推算
 * 设计：不假设上游传了 score/confidence，尽量从现有字段推导
 */
defined('ABSPATH') || exit;

class Learning_SampleCollector {

    /** 采集攻击样本 */
    public static function collectAttack(string $payload, array $attackResult): array {
        $score      = $attackResult['score']      ?? null;
        $confidence = $attackResult['confidence'] ?? null;
        $riskLevel  = strtolower((string)($attackResult['risk_level'] ?? 'unknown'));
        $typeScores = $attackResult['attack_type_scores'] ?? [];

        // 兜底：从 attack_type_scores 推算 score
        if ($score === null) {
            if (!empty($typeScores) && is_array($typeScores)) {
                $score = (float)max($typeScores);
                // 量纲自适应：<=1 视为概率，放大到 0-100
                if ($score > 0 && $score <= 1) $score *= 100;
            } else {
                $score = 0.0;
            }
        }
        $score = max(0.0, min(100.0, (float)$score));

        // 兜底：从 risk_level 推算 confidence
        if ($confidence === null) {
            $confidence = self::riskToConfidence($riskLevel);
        }
        $confidence = max(0.0, min(1.0, (float)$confidence));

        return [
            'payload'      => $payload,
            'class'        => 'attack',
            'score'        => round($score, 2),
            'confidence'   => round($confidence, 4),
            'risk_level'   => $riskLevel,
            'type_scores'  => $typeScores,
            'source'       => 'attack',
            'collected_at' => time(),
            'payload_md5'  => md5($payload),
            'payload_len'  => strlen($payload),
        ];
    }

    /** 采集正常样本 */
    public static function collectNormal(string $text, array $context = []): array {
        return [
            'payload'      => $text,
            'class'        => 'normal',
            'score'        => 0.0,
            'confidence'   => 1.0,
            'risk_level'   => 'none',
            'type_scores'  => [],
            'source'       => 'normal',
            'collected_at' => time(),
            'payload_md5'  => md5($text),
            'payload_len'  => strlen($text),
            'context'      => $context,
        ];
    }

    private static function riskToConfidence(string $level): float {
        switch ($level) {
            case 'critical': return 0.95;
            case 'high':     return 0.85;
            case 'medium':   return 0.65;
            case 'low':      return 0.40;
            default:         return 0.50;
        }
    }
}