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
require_once __DIR__ . '/HoneypotLinks.php';

class BotManager {
    private static $trusted_categories = ['search_engine', 'social_media', 'ai'];

    public static function check(array $request): array {
        $headers = $request['headers'] ?? [];
        $uri     = $request['uri']     ?? ($_SERVER['REQUEST_URI'] ?? '/');
        $ua      = $request['ua']      ?? self::extractUa($headers);
        $ip      = $request['ip']      ?? '';
        $extra   = $request['behavior'] ?? [];

        $fingerprint = BotFingerprint::analyze($headers, $ua, $ip);

        if (!empty($fingerprint['verified_search_engine'])) {
            return [
                'action'   => 'allow',
                'category' => 'search_engine',
                'score'    => 0,
                'reason'   => '已验证搜索引擎: ' . ($fingerprint['engine_name'] ?? 'unknown') . '（DNS/头特征验证通过）',
                'confidence' => 95,
                'detail'   => ['fingerprint' => $fingerprint],
            ];
        }

        if (HoneypotLinks::checkRequest()) {
            return [
                'action'   => 'block',
                'category' => 'malicious_bot',
                'score'    => 100,
                'reason'   => '命中蜜罐链接（爬虫/扫描器特征）',
                'confidence' => 99,
                'detail'   => ['honeypot' => true],
            ];
        }

        // ---------- 2. 语义 / 行为分析 ----------
        $semantic = BotSemantic::analyze($uri, $headers, $ua);

        // ---------- 3. 合并行为数据 ----------
        $honey_count = HoneypotLinks::getTriggerCount($ip);
        $behavior = array_merge($semantic, ['ua' => $ua, 'honeypot_triggered' => $honey_count], $extra);

        // 蜜罐历史触发 → 行为加成
        if ($honey_count > 0) {
            $behavior['attack_chain'] = ($behavior['attack_chain'] ?? 0) + 50;
        }

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
        // 注意：已验证的搜索引擎在 check() 开头就已提前返回，不会走到这里

        // 受信任分类（合法搜索引擎 / AI / 社交）默认放行，但分数极高仍挑战
        if (in_array($category, self::$trusted_categories, true)) {
            if ($score >= 85) {
                return ['challenge', '受信任爬虫但风险评分过高，发起挑战'];
            }
            return ['allow', '受信任分类: ' . $category];
        }

        // 恶意机器人
        if ($category === 'malicious_bot') {
            if ($score >= 75) {
                return ['block', '恶意机器人且风险评分超阈值'];
            }
            if ($score >= 50) {
                return ['limit', '恶意机器人，限速访问'];
            }
            return ['challenge', '疑似恶意机器人，发起挑战'];
        }

        // 通用爬虫
        if ($category === 'crawler') {
            if ($score >= 75) {
                return ['limit', '爬虫访问过频，限速'];
            }
            if ($score >= 50) {
                return ['challenge', '爬虫特征明显，发起挑战'];
            }
            return ['allow', '爬虫但风险较低'];
        }

        // 人类
        if ($category === 'human') {
            if ($score >= 75) {
                return ['limit', '行为异常，限速观察'];
            }
            if ($score >= 50) {
                return ['challenge', '人类但风险偏高，发起挑战'];
            }
            return ['allow', '正常人类访问'];
        }

        // 默认兜底
        if ($score >= 75) {
            return ['block', '风险评分过高'];
        }
        if ($score >= 50) {
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
