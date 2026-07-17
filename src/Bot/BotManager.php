<?php
/**
 * 盾甲 WAF 机器人检测统一入口 (bot/BotManager.php)
 *
 * 功能：
 *  1. 加载并协调 BotFingerprint / BotSemantic / BotScorer / BotClassifier / CaptchaHandler
 *  2. 统一入口 check(array $request) 返回动作建议
 *  3. 根据分类结果执行动作：allow, challenge, limit, block
 */
defined('ABSPATH') || exit;

// ====================== 加载同目录其他 bot 模块 ======================
require_once __DIR__ . '/BotFingerprint.php';
require_once __DIR__ . '/BotSemantic.php';
require_once __DIR__ . '/BotScorer.php';
require_once __DIR__ . '/BotClassifier.php';
require_once __DIR__ . '/CaptchaHandler.php';

class BotManager {
    // 动作阈值
    const ALLOW_THRESHOLD     = 25;
    const CHALLENGE_THRESHOLD = 45;
    const LIMIT_THRESHOLD     = 65;

    // 受信任分类（合法爬虫，默认放行）
    private static $trusted_categories = ['search_engine', 'social_media', 'ai'];

    /**
     * 统一入口检查
     * @param array $request 请求上下文：
     *   - headers:  array  请求头
     *   - uri:      string  请求 URI
     *   - ua:       string  User-Agent（若不传则从 headers 提取）
     *   - behavior: array   额外行为数据（可选，如 request_rate / attack_chain / probe_count / error_rate）
     * @return array ['action'=>'allow|challenge|limit|block', 'category'=>'...', 'score'=>0-100, 'reason'=>'...']
     */
    public static function check(array $request): array {
        $headers = $request['headers'] ?? [];
        $uri     = $request['uri']     ?? ($_SERVER['REQUEST_URI'] ?? '/');
        $ua      = $request['ua']      ?? self::extractUa($headers);
        $ip      = $request['ip']      ?? '';
        $extra   = $request['behavior'] ?? [];

        // ---------- 1. 指纹分析 ----------
        $fingerprint = BotFingerprint::analyze($headers, $ua, $ip);

        // ---------- 2. 语义 / 行为分析 ----------
        $semantic = BotSemantic::analyze($uri, $headers, $ua);

        // ---------- 3. 合并行为数据（语义结果 + UA + 外部行为指标） ----------
        $behavior = array_merge($semantic, ['ua' => $ua], $extra);

        // ---------- 4. 综合评分 ----------
        $scoring = BotScorer::score($fingerprint, $behavior, $semantic);

        // ---------- 5. 分类 ----------
        $classification = BotClassifier::classify($fingerprint, $behavior);

        $category = $classification['category'];
        $score    = $scoring['total_score'];

        // ---------- 6. 动作决策 ----------
        list($action, $reason) = self::decideAction($category, $score, $fingerprint, $classification);

        return [
            'action'     => $action,
            'category'   => $category,
            'score'      => $score,
            'reason'     => $reason,
            'confidence' => $classification['confidence'] ?? 0,
            'detail'     => [
                'fingerprint'    => $fingerprint,
                'semantic'       => $semantic,
                'scoring'        => $scoring,
                'classification' => $classification,
            ],
        ];
    }

    /**
     * 发起验证挑战（封装 CaptchaHandler，便于上层调用）
     */
    public static function challenge(string $type = 'slider'): array {
        return CaptchaHandler::challenge($type);
    }

    /**
     * 验证挑战结果
     */
    public static function verify(string $token, string $type): bool {
        return CaptchaHandler::verify($token, $type);
    }

    // ====================== 内部实现 ======================

    /**
     * 决策动作
     */
    private static function decideAction(string $category, int $score, array $fingerprint, array $classification): array {
        // 最高优先级：已验证的搜索引擎（DNS或头特征验证通过）→ 强制放行
        // 注意：这不会跳过后续的攻击检测（SQLi/XSS等），只跳过机器人拦截
        // 攻击载荷会被 detector.php 和 Scorer.php 独立检测
        if (!empty($fingerprint['verified_search_engine'])) {
            return ['allow', '已验证搜索引擎: ' . ($fingerprint['engine_name'] ?? 'unknown')];
        }

        // 受信任分类（合法搜索引擎 / AI / 社交）默认放行，但分数极高仍挑战
        if (in_array($category, self::$trusted_categories, true)) {
            if ($score >= 80) {
                return ['challenge', '受信任爬虫但风险评分过高，发起挑战'];
            }
            return ['allow', '受信任分类: ' . $category];
        }

        // 恶意机器人
        if ($category === 'malicious_bot') {
            if ($score >= self::LIMIT_THRESHOLD) {
                return ['block', '恶意机器人且风险评分超阈值'];
            }
            if ($score >= self::CHALLENGE_THRESHOLD) {
                return ['limit', '恶意机器人，限速访问'];
            }
            return ['challenge', '疑似恶意机器人，发起挑战'];
        }

        // 通用爬虫
        if ($category === 'crawler') {
            if ($score >= self::LIMIT_THRESHOLD) {
                return ['limit', '爬虫访问过频，限速'];
            }
            if ($score >= self::CHALLENGE_THRESHOLD) {
                return ['challenge', '爬虫特征明显，发起挑战'];
            }
            return ['allow', '爬虫但风险较低'];
        }

        // 人类
        if ($category === 'human') {
            if ($score >= self::LIMIT_THRESHOLD) {
                return ['limit', '行为异常，限速观察'];
            }
            if ($score >= self::CHALLENGE_THRESHOLD) {
                return ['challenge', '人类但风险偏高，发起挑战'];
            }
            return ['allow', '正常人类访问'];
        }

        // 默认兜底
        if ($score >= self::LIMIT_THRESHOLD) {
            return ['block', '风险评分过高'];
        }
        if ($score >= self::CHALLENGE_THRESHOLD) {
            return ['challenge', '风险评分偏高，发起挑战'];
        }
        return ['allow', '默认放行'];
    }

    /**
     * 从请求头提取 UA
     */
    private static function extractUa(array $headers): string {
        foreach ($headers as $k => $v) {
            if (strtolower((string)$k) === 'user-agent') return (string)$v;
        }
        return '';
    }
}
