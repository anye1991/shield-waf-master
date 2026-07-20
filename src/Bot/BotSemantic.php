<?php
/**
 * 盾甲 WAF 机器人语义行为分析模块 (bot/BotSemantic.php)
 *
 * 功能：
 *  1. 路径多样性分析（访问大量不同路径 = 爬虫特征）
 *  2. 访问间隔分析（均匀间隔 = 机器人）
 *  3. 资源偏好分析（只访问 API 不访问静态资源 = 恶意）
 *  4. 基于 IP 的轻量级行为追踪（文件存储）
 */
defined('ABSPATH') || exit;

class BotSemantic {
    private static $tracker_dir   = null;
    private static $history_window = 300; // 5 分钟窗口
    private static $max_history    = 100; // 最多保留 100 条

    /**
     * 语义行为分析
     * @param string $uri     请求 URI
     * @param array  $headers 请求头
     * @param string $ua      User-Agent（用于识别搜索引擎蜘蛛，降权处理）
     * @return array ['score'=>0-100, 'indicators'=>[...], 'path_diversity'=>..., 'interval_uniformity'=>..., 'resource_bias'=>..., 'probe_score'=>..., 'ua_rotation_score'=>..., 'crawl_depth'=>...]
     */
    public static function analyze(string $uri, array $headers, string $ua = ''): array {
        self::initDir();

        $ip   = self::getClientIp();
        $now  = microtime(true);

        $history = self::recordAndGetHistory($ip, $uri, $now, $ua);

        $indicators = [];

        $is_search_spider = self::isSearchEngineUa($ua);

        // ---------- 1. 路径多样性 ----------
        $path_diversity = self::computePathDiversity($history);
        $indicators[] = [
            'code'  => 'path_diversity',
            'value' => round($path_diversity, 1),
            'desc'  => '路径多样性(' . self::uniquePathCount($history) . '/' . count($history) . ')',
        ];

        // ---------- 2. 访问间隔均匀度 ----------
        $interval_uniformity = self::computeIntervalUniformity($history);
        $indicators[] = [
            'code'  => 'interval_uniformity',
            'value' => round($interval_uniformity, 1),
            'desc'  => '访问间隔均匀度',
        ];

        // ---------- 3. 资源偏好 ----------
        $resource_bias = self::computeResourceBias($history);
        $indicators[] = [
            'code'  => 'resource_bias',
            'value' => round($resource_bias, 1),
            'desc'  => 'API/静态资源偏好偏差',
        ];

        // ---------- 4. 当前 URI 的探测特征 ----------
        $probe_score = self::computeProbeScore($uri);
        if ($probe_score > 0) {
            $indicators[] = [
                'code'  => 'probe_pattern',
                'value' => $probe_score,
                'desc'  => '敏感路径探测',
            ];
        }

        // ---------- 5. UA 随机化检测（代理池/爬虫集群特征） ----------
        $ua_rotation_score = self::computeUaRotationScore($history);
        if ($ua_rotation_score > 0) {
            $indicators[] = [
                'code'  => 'ua_rotation',
                'value' => $ua_rotation_score,
                'desc'  => 'UA随机化（疑似代理池）',
            ];
        }

        // ---------- 6. 爬取深度分析 ----------
        $crawl_depth = self::computeCrawlDepth($history);
        if ($crawl_depth > 0) {
            $indicators[] = [
                'code'  => 'crawl_depth',
                'value' => $crawl_depth,
                'desc'  => '爬取深度',
            ];
        }

        // ---------- 综合评分 ----------
        $score = self::computeScore($path_diversity, $interval_uniformity, $resource_bias, $probe_score, $ua_rotation_score, $crawl_depth, count($history));

        if ($is_search_spider) {
            $score = (int)round($score * 0.15);
            $indicators[] = [
                'code'  => 'search_spider_discount',
                'value' => 0.15,
                'desc'  => '搜索引擎蜘蛛行为分析降权(15%)',
            ];
        }

        return [
            'score'               => $score,
            'indicators'          => $indicators,
            'path_diversity'      => $path_diversity,
            'interval_uniformity' => $interval_uniformity,
            'resource_bias'       => $resource_bias,
            'probe_score'         => $probe_score,
            'ua_rotation_score'   => $ua_rotation_score,
            'crawl_depth'         => $crawl_depth,
            'sample_size'         => count($history),
            'is_search_spider'    => $is_search_spider,
        ];
    }

    /**
     * 检测 UA 是否为已知搜索引擎蜘蛛（与 BotFingerprint 保持一致的核心列表）
     */
    private static function isSearchEngineUa(string $ua): bool {
        if (empty($ua)) return false;
        $patterns = [
            // 全球主流
            '/Googlebot/i', '/Bingbot|msnbot/i', '/Baiduspider/i', '/YandexBot/i',
            '/DuckDuckBot/i', '/Exabot/i',
            // 中国搜索
            '/Sogou\s+web\s+spider|Sogou\s+spider/i', '/360Spider|360spider|HaoSouSpider/i',
            '/Sosospider/i', '/Bytespider/i', '/ShenmaBot/i', '/YisouSpider/i',
            '/YoudaoBot/i', '/JikeSpider/i',
            // 科技公司
            '/Applebot/i', '/facebookexternalhit|Facebot/i', '/Twitterbot/i',
            // SEO工具（合规爬虫）
            '/AhrefsBot/i', '/SemrushBot/i', '/MJ12bot/i', '/DotBot/i', '/rogerbot/i',
            // 其他
            '/NaverBot|Yeti/i', '/SeznamBot/i',
            // 社交平台（也算合规爬虫）
            '/LinkedInBot/i', '/Pinterest/i', '/Slackbot/i', '/Discordbot/i',
            '/TelegramBot/i', '/WhatsApp/i', '/SkypeUriPreview/i',
        ];
        foreach ($patterns as $p) {
            if (preg_match($p, $ua)) return true;
        }
        return false;
    }

    // ====================== 内部计算 ======================

    /**
     * 路径多样性：unique 路径占比 × 样本充足度
     */
    private static function computePathDiversity(array $history): float {
        if (count($history) < 3) return 0.0;
        $paths = [];
        foreach ($history as $item) {
            $paths[$item['path']] = true;
        }
        $ratio = count($paths) / count($history);
        $confidence = min(1.0, count($history) / 20); // 样本越多越可信
        return $ratio * 100 * $confidence;
    }

    private static function uniquePathCount(array $history): int {
        $paths = [];
        foreach ($history as $item) $paths[$item['path']] = true;
        return count($paths);
    }

    /**
     * 间隔均匀度：相邻请求间隔的变异系数，CV 越小越均匀
     */
    private static function computeIntervalUniformity(array $history): float {
        if (count($history) < 4) return 0.0;
        $intervals = [];
        for ($i = 1; $i < count($history); $i++) {
            $intervals[] = $history[$i]['ts'] - $history[$i - 1]['ts'];
        }
        $n = count($intervals);
        $mean = array_sum($intervals) / $n;
        if ($mean <= 0) return 0.0;
        $var = 0.0;
        foreach ($intervals as $d) $var += ($d - $mean) ** 2;
        $std = sqrt($var / $n);
        $cv = $std / $mean; // 变异系数
        $uniformity = max(0, 100 * (1 - $cv)); // CV=0 → 100，CV>=1 → 0
        return $uniformity;
    }

    /**
     * 资源偏好偏差：只访问 API/动态接口不访问静态资源
     */
    private static function computeResourceBias(array $history): float {
        if (count($history) < 3) return 0.0;
        $static = 0;
        $api    = 0;
        foreach ($history as $item) {
            $path = $item['path'];
            if (preg_match('/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)(\?|$)/i', $path)) {
                $static++;
            } elseif (preg_match('#/(api|json|xml|ajax|graphql)(/|\?|$)#i', $path) ||
                      preg_match('/\.(php|json|xml)(\?|$)/i', $path)) {
                $api++;
            }
        }
        $total = $static + $api;
        if ($total === 0) return 0.0;
        $api_ratio = $api / $total;
        // API 占比极高且几乎无静态 + 样本充足 → 偏差高
        if ($api_ratio >= 0.9 && count($history) >= 5) {
            return $api_ratio * 100;
        }
        return 0.0;
    }

    /**
     * 敏感路径探测评分
     */
    private static function computeProbeScore(string $uri): int {
        $score = 0;
        $patterns = [
            '#/wp-admin#i'        => 10,
            '#/wp-login#i'        => 15,
            '#/xmlrpc\.php#i'     => 20,
            '#/\.env#i'           => 25,
            '#/\.git#i'           => 25,
            '#/phpmyadmin#i'      => 20,
            '#/admin#i'           => 10,
            '#/config\.php#i'     => 20,
            '#/(etc|proc|var)/#i' => 25,
            '#/shell\.php#i'      => 30,
            '#\.\./#i'            => 25,
            '#/vendor/#i'         => 15,
            '#/backup#i'          => 15,
        ];
        foreach ($patterns as $p => $w) {
            if (preg_match($p, $uri)) $score += $w;
        }
        return min(100, $score);
    }

    /**
     * 综合评分
     */
    private static function computeScore(float $diversity, float $uniformity, float $bias, int $probe, float $ua_rotation, float $crawl_depth, int $sample): int {
        $score = 0;
        $score += (int)min(25, $diversity * 0.25);    // 路径多样性 0-25
        $score += (int)min(20, $uniformity * 0.20);   // 间隔均匀度 0-20
        $score += (int)min(15, $bias * 0.15);         // 资源偏好 0-15
        $score += (int)min(20, $probe * 0.20);        // 探测特征 0-20
        $score += (int)min(25, $ua_rotation * 0.25);  // UA随机化 0-25
        $score += (int)min(15, $crawl_depth * 0.15);  // 爬取深度 0-15
        if ($sample < 3) {
            $score = (int)($score * 0.3);
        }
        return (int)min(100, $score);
    }

    /**
     * UA随机化检测：同一IP短时间内出现多个不同UA → 代理池/爬虫集群
     */
    private static function computeUaRotationScore(array $history): float {
        if (count($history) < 5) return 0.0;
        $uas = [];
        foreach ($history as $item) {
            if (!empty($item['ua'])) {
                $uas[md5($item['ua'])] = true;
            }
        }
        $ua_count = count($uas);
        if ($ua_count <= 1) return 0.0;
        // 5分钟内出现3个以上不同UA → 高度可疑
        $ratio = $ua_count / count($history);
        $score = 0.0;
        if ($ua_count >= 5) {
            $score = 100;
        } elseif ($ua_count >= 3) {
            $score = 70;
        } elseif ($ua_count >= 2) {
            $score = 30;
        }
        return $score;
    }

    /**
     * 爬取深度分析：爬虫通常会爬很多层目录，人类通常在1-3层
     */
    private static function computeCrawlDepth(array $history): float {
        if (count($history) < 5) return 0.0;
        $total_depth = 0;
        $deep_pages = 0;
        foreach ($history as $item) {
            $path = $item['path'];
            $depth = substr_count(trim($path, '/'), '/');
            $total_depth += $depth;
            if ($depth >= 4) $deep_pages++;
        }
        $avg_depth = $total_depth / count($history);
        $deep_ratio = $deep_pages / count($history);
        // 平均深度超过4层 或 深度页占比超过40% → 爬虫特征
        $score = 0.0;
        if ($avg_depth >= 6) {
            $score = 100;
        } elseif ($avg_depth >= 4) {
            $score = 70;
        } elseif ($avg_depth >= 3) {
            $score = 40;
        }
        if ($deep_ratio >= 0.5) {
            $score = min(100, $score + 20);
        }
        return $score;
    }

    // ====================== 行为追踪存储 ======================

    private static function initDir() {
        if (self::$tracker_dir !== null) return;
        $base = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (sys_get_temp_dir() . '/shield_waf_');
        $dir  = $base . '/bot_tracker/';
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        self::$tracker_dir = $dir;
    }

    private static function getClientIp(): string {
        if (function_exists('waf_get_real_ip')) {
            return waf_get_real_ip();
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * 记录访问并返回该 IP 窗口内历史
     */
    private static function recordAndGetHistory(string $ip, string $uri, float $now, string $ua = ''): array {
        $file    = self::$tracker_dir . md5($ip) . '.json';
        $history = [];
        if (is_file($file)) {
            $raw = @file_get_contents($file);
            if ($raw) {
                $data = json_decode($raw, true);
                if (is_array($data)) $history = $data;
            }
        }

        $history[] = ['ts' => $now, 'path' => self::normalizePath($uri), 'ua' => $ua];

        $cutoff = $now - self::$history_window;
        $history = array_values(array_filter($history, function ($item) use ($cutoff) {
            return $item['ts'] >= $cutoff;
        }));

        if (count($history) > self::$max_history) {
            $history = array_slice($history, -self::$max_history);
        }

        @file_put_contents($file, json_encode($history), LOCK_EX);
        return $history;
    }

    /**
     * 归一化路径：去除数字 ID / 长哈希，提升路径多样性统计准确性
     */
    private static function normalizePath(string $uri): string {
        $path = parse_url($uri, PHP_URL_PATH) ?: $uri;
        $path = preg_replace('#/\d+#', '/{id}', $path);
        $path = preg_replace('#/[0-9a-f]{16,}#i', '/{hash}', $path);
        return $path;
    }
}
