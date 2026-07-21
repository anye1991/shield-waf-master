<?php
/**
 * 盾甲 WAF 机器人多维度分类模块 (bot/BotClassifier.php)
 *
 * 功能：
 *  1. 基于指纹、行为、语义多维度综合分类
 *  2. 分类为：human, search_engine, social_media, ai, crawler, malicious_bot
 *  3. 输出分类结果、置信度与决策理由
 */
defined('ABSPATH') || exit;

class BotClassifier {
    private static $social_media_patterns = [
        '/facebookexternalhit/i' => 'Facebook',
        '/Facebot/i'             => 'Facebook',
        '/Twitterbot/i'          => 'Twitter',
        '/LinkedInBot/i'         => 'LinkedIn',
        '/WhatsApp/i'            => 'WhatsApp',
        '/TelegramBot/i'         => 'Telegram',
        '/Slackbot/i'            => 'Slack',
        '/Discordbot/i'          => 'Discord',
        '/Pinterest/i'           => 'Pinterest',
        '/SkypeUriPreview/i'     => 'Skype',
    ];

    private static $ai_patterns = [
        '/GPTBot/i'          => 'OpenAI',
        '/ChatGPT-User/i'    => 'OpenAI',
        '/OAI-SearchBot/i'   => 'OpenAI-Search',
        '/ClaudeBot/i'       => 'Anthropic',
        '/Claude-Web/i'      => 'Anthropic',
        '/anthropic-ai/i'    => 'Anthropic',
        '/CCBot/i'           => 'CommonCrawl',
        '/PerplexityBot/i'   => 'Perplexity',
        '/Diffbot/i'         => 'Diffbot',
        '/AI2Bot/i'          => 'AI2',
        '/cohere-ai/i'       => 'Cohere',
    ];

    public static function classify(array $fingerprint, array $behavior): array {
        $reasons = [];
        $scores  = [
            'human'         => 0,
            'search_engine' => 0,
            'social_media'  => 0,
            'ai'            => 0,
            'crawler'       => 0,
            'malicious_bot' => 0,
        ];

        $signals           = $fingerprint['signals'] ?? [];
        $fp_score          = $fingerprint['score'] ?? 0;
        $fp_type           = $fingerprint['type'] ?? 'unknown';
        $ua                = $behavior['ua'] ?? '';
        $is_verified_se    = $fingerprint['verified_search_engine'] ?? false;

        foreach ($signals as $s) {
            $code = $s['code'] ?? '';
            if ($code === 'search_engine_ua') {
                if ($is_verified_se) {
                    $scores['search_engine'] += 50;
                    $reasons[] = '已验证搜索引擎: ' . ($s['name'] ?? '');
                } else {
                    $scores['crawler'] += 20;
                    $reasons[] = '未验证搜索引擎 UA: ' . ($s['name'] ?? '');
                }
            }
            if ($code === 'fake_search_engine') {
                $scores['malicious_bot'] += 35;
                $reasons[] = '伪造搜索引擎 UA';
            }
            if ($code === 'fake_search_engine_headless') {
                $scores['malicious_bot'] += 45;
                $reasons[] = '伪造搜索引擎 + 无头浏览器';
            }
            if ($code === 'automation_tool') {
                $scores['malicious_bot'] += 40;
                $reasons[] = '检测到自动化工具特征';
            }
            if ($code === 'ai_bot_ua') {
                $scores['ai'] += 30;
                $reasons[] = 'AI 爬虫 UA';
            }
            if ($code === 'empty_ua') {
                $scores['crawler'] += 25;
                $reasons[] = 'UA 为空';
            }
            if (in_array($code, ['missing_browser_headers', 'wildcard_accept', 'missing_accept_language', 'missing_host', 'long_xff_chain'], true)) {
                $scores['crawler'] += min(15, $s['weight'] ?? 0);
                $reasons[] = '请求头异常: ' . ($s['desc'] ?? $code);
            }
        }

        // ---------- 社交媒体分类 ----------
        foreach (self::$social_media_patterns as $pattern => $name) {
            if (preg_match($pattern, $ua)) {
                $scores['social_media'] += 45;
                $reasons[] = '社交媒体爬虫: ' . $name;
                break;
            }
        }

        // ---------- AI 分类 ----------
        foreach (self::$ai_patterns as $pattern => $name) {
            if (preg_match($pattern, $ua)) {
                $scores['ai'] += 40;
                $reasons[] = 'AI 爬虫: ' . $name;
                break;
            }
        }

        // ---------- 行为 / 语义分析 ----------
        $sem_score          = $behavior['score'] ?? 0;
        $path_diversity     = $behavior['path_diversity'] ?? 0;
        $interval_uniformity= $behavior['interval_uniformity'] ?? 0;
        $resource_bias      = $behavior['resource_bias'] ?? 0;
        $attack_chain       = $behavior['attack_chain'] ?? 0;

        if ($path_diversity >= 60) {
            $scores['crawler'] += 20;
            $reasons[] = '路径多样性高(' . (int)$path_diversity . ')';
        }
        if ($interval_uniformity >= 70) {
            $scores['crawler'] += 20;
            $reasons[] = '访问间隔过于均匀(' . (int)$interval_uniformity . ')';
        }
        if ($resource_bias >= 70) {
            $scores['malicious_bot'] += 20;
            $reasons[] = '资源偏好异常(仅访问 API)';
        }
        if ($attack_chain >= 50) {
            $scores['malicious_bot'] += 30;
            $reasons[] = '检测到攻击链特征(' . (int)$attack_chain . ')';
        }

        // 语义分数高 → 倾向爬虫或恶意
        if ($sem_score >= 60) {
            if ($fp_type === 'malicious') {
                $scores['malicious_bot'] += 15;
            } else {
                $scores['crawler'] += 15;
            }
            $reasons[] = '语义评分较高(' . (int)$sem_score . ')';
        }

        // ---------- 人类判定 ----------
        if ($fp_score < 25 && $sem_score < 30 && $attack_chain < 20) {
            $scores['human'] += 40;
            $reasons[] = '指纹与行为均接近正常用户';
        }

        // ---------- 选择最高分类 ----------
        arsort($scores);
        $category     = array_key_first($scores);
        $top_score    = $scores[$category];
        $second       = array_slice($scores, 1, 1, true);
        $second_score = !empty($second) ? (int)reset($second) : 0;

        // 置信度：领先第二名越多，置信度越高
        $lead = $top_score - $second_score;
        $confidence = min(100, max(30, (int)round(40 + $top_score * 0.5 + $lead * 1.5)));

        // 若所有分类得分都很低，默认人类
        if ($top_score < 15) {
            $category   = 'human';
            $confidence = 50;
            $reasons[]  = '无明确机器人特征，默认判定为人类';
        }

        return [
            'category'   => $category,
            'confidence' => $confidence,
            'reasons'    => $reasons,
        ];
    }
}
