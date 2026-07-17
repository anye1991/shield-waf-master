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
    private static $max_history    = 50;  // 最多保留 50 条

    /**
     * 语义行为分析
     * @param string $uri     请求 URI
     * @param array  $headers 请求头
     * @param string $ua      User-Agent（用于识别搜索引擎蜘蛛，降权处理）
     * @return array ['score'=>0-100, 'indicators'=>[...], 'path_diversity'=>..., 'interval_uniformity'=>..., 'resource_bias'=>..., 'probe_score'=>...]
     */
    public static function analyze(string $uri, array $headers, string $ua = ''): array {
        self::initDir();

        $ip   = self::getClientIp();
        $now  = microtime(true);

        // 记录本次访问并获取窗口内历史
        $history = self::recordAndGetHistory($ip, $uri, $now);

        $indicators = [];

        // 检测是否为已知搜索引擎蜘蛛
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

        // ---------- 综合评分 ----------
        $score = self::computeScore($path_diversity, $interval_uniformity, $resource_bias, $probe_score, count($history));

        // 搜索引擎蜘蛛降权：路径多样性和间隔均匀是蜘蛛的正常行为，不应计为风险
        if ($is_search_spider) {
            $score = (int)round($score * 0.2); // 降权 80%
            $indicators[] = [
                'code'  => 'search_spider_discount',
                'value' => 0.2,
                'desc'  => '搜索引擎蜘蛛行为分析降权',
            ];
        }

        return [
            'score'               => $score,
            'indicators'          => $indicators,
            'path_diversity'      => $path_diversity,
            'interval_uniformity' => $interval_uniformity,
            'resource_bias'       => $resource_bias,
            'probe_score'         => $probe_score,
            'sample_size'         => count($history),
            'is_search_spider'    => $is_search_spider,
        ];
    }

    /**
     * 检测 UA 是否为已知搜索引擎蜘蛛
     */
    private static function isSearchEngineUa(string $ua): bool {
        if (empty($ua)) return false;
        $patterns = [
            '/Googlebot/i', '/Bingbot/i', '/Baiduspider/i', '/YandexBot/i',
            '/DuckDuckBot/i', '/Sogou\s+web\s+spider/i', '/Sosospider/i',
            '/Exabot/i', '/facebot|facebookexternalhit/i', '/Twitterbot/i',
            '/Applebot/i', '/AhrefsBot/i', '/SemrushBot/i', '/MJ12bot/i',
            '/Bytespider/i', '/360Spider/i',
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
    private static function computeScore(float $diversity, float $uniformity, float $bias, int $probe, int $sample): int {
        $score = 0;
        $score += (int)min(35, $diversity * 0.35);  // 路径多样性 0-35
        $score += (int)min(25, $uniformity * 0.25); // 间隔均匀度 0-25
        $score += (int)min(20, $bias * 0.20);       // 资源偏好 0-20
        $score += (int)min(30, $probe * 0.30);      // 探测特征 0-30
        if ($sample < 3) {
            $score = (int)($score * 0.3); // 样本过少时降权
        }
        return (int)min(100, $score);
    }

    // ====================== 行为追踪存储 ======================

    private static function initDir(): void {
        if (self::$tracker_dir !== null) return;
        $base = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (sys_get_temp_dir() . '/shield_waf_');
        $dir  = $base . 'bot_tracker/';
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
    private static function recordAndGetHistory(string $ip, string $uri, float $now): array {
        $file    = self::$tracker_dir . md5($ip) . '.json';
        $history = [];
        if (is_file($file)) {
            $raw = @file_get_contents($file);
            if ($raw) {
                $data = json_decode($raw, true);
                if (is_array($data)) $history = $data;
            }
        }

        // 追加本次
        $history[] = ['ts' => $now, 'path' => self::normalizePath($uri)];

        // 清理过期
        $cutoff = $now - self::$history_window;
        $history = array_values(array_filter($history, function ($item) use ($cutoff) {
            return $item['ts'] >= $cutoff;
        }));

        // 限制条数
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
