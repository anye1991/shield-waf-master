<?php
/**
 * 盾甲 WAF 机器人指纹分析模块 (bot/BotFingerprint.php)
 *
 * 功能：
 *  1. 分析 User-Agent 字符串，识别搜索引擎爬虫与自动化工具
 *  2. 分析 TLS / 请求头指纹（Accept 头顺序、Connection 头、缺失头等异常模式）
 *  3. 检测自动化工具特征（缺少常见浏览器头、异常 Accept-Language 等）
 *  4. 内置主流搜索引擎指纹库（Google, Bing, Baidu, Yandex 等）
 *  5. 返回综合评分与机器人类型
 */
defined('ABSPATH') || exit;

class BotFingerprint {
    // ====================== 主流搜索引擎指纹库（32种） ======================
    private static $search_engines = [
        // ===== 全球主流搜索引擎 =====
        ['pattern' => '/Googlebot/i',            'name' => 'Google',     'hint' => 'googlebot',     'tier' => 'tier1'],
        ['pattern' => '/Bingbot|msnbot/i',       'name' => 'Bing',       'hint' => 'bingbot',       'tier' => 'tier1'],
        ['pattern' => '/DuckDuckBot/i',          'name' => 'DuckDuckGo', 'hint' => 'duckduck',      'tier' => 'tier2'],
        ['pattern' => '/YandexBot/i',            'name' => 'Yandex',     'hint' => 'yandex',        'tier' => 'tier1'],
        ['pattern' => '/Exabot/i',               'name' => 'Exalead',    'hint' => 'exabot',        'tier' => 'tier3'],
        // ===== 中国搜索引擎 =====
        ['pattern' => '/Baiduspider/i',          'name' => 'Baidu',      'hint' => 'baidu',         'tier' => 'tier1'],
        ['pattern' => '/Sogou\s+web\s+spider|Sogou\s+spider/i', 'name' => 'Sogou', 'hint' => 'sogou', 'tier' => 'tier2'],
        ['pattern' => '/360Spider|360spider|HaoSouSpider/i', 'name' => '360', 'hint' => '360', 'tier' => 'tier2'],
        ['pattern' => '/Sosospider/i',           'name' => 'Tencent_Soso', 'hint' => 'soso',        'tier' => 'tier3'],
        ['pattern' => '/Bytespider/i',           'name' => 'ByteDance_Toutiao', 'hint' => 'bytespider', 'tier' => 'tier2'],
        ['pattern' => '/ShenmaBot/i',            'name' => 'Shenma_UC',  'hint' => 'shenma',        'tier' => 'tier2'],
        ['pattern' => '/YisouSpider/i',          'name' => 'Yisou',      'hint' => 'yisou',         'tier' => 'tier3'],
        ['pattern' => '/YoudaoBot/i',            'name' => 'Youdao',     'hint' => 'youdao',        'tier' => 'tier3'],
        ['pattern' => '/JikeSpider/i',           'name' => 'Jike',       'hint' => 'jike',          'tier' => 'tier3'],
        // ===== 科技公司蜘蛛 =====
        ['pattern' => '/Applebot/i',             'name' => 'Apple_Siri', 'hint' => 'apple',         'tier' => 'tier2'],
        ['pattern' => '/facebookexternalhit|Facebot/i', 'name' => 'Facebook', 'hint' => 'facebook', 'tier' => 'tier2'],
        ['pattern' => '/Twitterbot/i',           'name' => 'Twitter_X',  'hint' => 'twitter',       'tier' => 'tier2'],
        // ===== SEO工具蜘蛛（合规，放行） =====
        ['pattern' => '/AhrefsBot/i',            'name' => 'Ahrefs',     'hint' => 'ahrefs',        'tier' => 'seo'],
        ['pattern' => '/SemrushBot/i',           'name' => 'Semrush',    'hint' => 'semrush',       'tier' => 'seo'],
        ['pattern' => '/MJ12bot/i',              'name' => 'Majestic',   'hint' => 'mj12',          'tier' => 'seo'],
        ['pattern' => '/DotBot/i',               'name' => 'Moz',        'hint' => 'dotbot',        'tier' => 'seo'],
        ['pattern' => '/rogerbot/i',             'name' => 'Moz_Roger',  'hint' => 'rogerbot',      'tier' => 'seo'],
        ['pattern' => '/SearchmetricsBot/i',     'name' => 'Searchmetrics', 'hint' => 'searchmetrics', 'tier' => 'seo'],
        ['pattern' => '/SEOkicks|Seobility/i',   'name' => 'SEO_Tools',  'hint' => 'seotools',      'tier' => 'seo'],
        // ===== 内容平台蜘蛛 =====
        ['pattern' => '/LinkedInBot/i',          'name' => 'LinkedIn',   'hint' => 'linkedin',      'tier' => 'social'],
        ['pattern' => '/Pinterest/i',            'name' => 'Pinterest',  'hint' => 'pinterest',     'tier' => 'social'],
        ['pattern' => '/Slackbot/i',             'name' => 'Slack',      'hint' => 'slack',         'tier' => 'social'],
        ['pattern' => '/Discordbot/i',           'name' => 'Discord',    'hint' => 'discord',       'tier' => 'social'],
        ['pattern' => '/TelegramBot/i',          'name' => 'Telegram',   'hint' => 'telegram',      'tier' => 'social'],
        ['pattern' => '/WhatsApp/i',             'name' => 'WhatsApp',   'hint' => 'whatsapp',      'tier' => 'social'],
        ['pattern' => '/SkypeUriPreview/i',      'name' => 'Skype',      'hint' => 'skype',         'tier' => 'social'],
        ['pattern' => '/NaverBot|Yeti/i',        'name' => 'Naver',      'hint' => 'naver',         'tier' => 'tier2'],
        ['pattern' => '/SeznamBot/i',            'name' => 'Seznam',     'hint' => 'seznam',        'tier' => 'tier3'],
    ];

    // ====================== 无头浏览器 / 自动化工具指纹 ======================
    private static $headless_patterns = [
        '/HeadlessChrome/i',
        '/Puppeteer/i',
        '/Playwright/i',
        '/PhantomJS/i',
        '/Selenium/i',
        '/WebDriver/i',
        '/\bphantom\b/i',
        '/\bchromedriver\b/i',
        '/\bgeckodriver\b/i',
        '/\bsafaridriver\b/i',
        '/\bedgedriver\b/i',
        '/\bwebdriver\b/i',
        '/Lighthouse/i',
        '/PageSpeed/i',
        '/Pingdom/i',
        '/GTmetrix/i',
        '/WebPageTest/i',
    ];

    // ====================== 自动化工具 / 恶意爬虫指纹 ======================
    private static $automation_tools = [
        '/\bscrapy\b/i', '/\bcurl\b/i', '/\bwget\b/i',
        '/\bpython-requests\b/i', '/\bpython-urllib\b/i', '/\baiohttp\b/i', '/\bhttpx\b/i',
        '/\bGo-http-client\b/i', '/\bokhttp\b/i', '/\bJava\//i',
        '/\bJakarta\s+Commons/i', '/\bHttpClient\b/i', '/\blibwww-perl\b/i',
        '/\bPerl\b/i', '/\bRuby\b/i', '/\bnode-superagent\b/i',
        '/\bnode-fetch\b/i', '/\baxios\b/i', '/\bGuzzleHttp\b/i',
        '/\bPHP\//i', '/\bZend_Http_Client\b/i', '/\bMechanize\b/i',
        '/\bNmap\b/i', '/\bnikto\b/i', '/\bsqlmap\b/i', '/\bmasscan\b/i',
        '/\bZGrab\b/i', '/\bHydra\b/i', '/\bNessus\b/i',
        '/\bAcunetix\b/i', '/\bAppScan\b/i', '/\bBurp\b/i', '/\bWebInspect\b/i',
    ];

    // AI 爬虫指纹
    private static $ai_bots = [
        '/\bGPTBot\b/i', '/\bClaudeBot\b/i', '/\bCCBot\b/i',
        '/\banthropic-ai\b/i', '/\bPerplexityBot\b/i', '/\bGoogle-Extended\b/i',
        '/\bDiffbot\b/i', '/\bOAI-SearchBot\b/i', '/\bAI2Bot\b/i',
        '/\bAmazonbot\b/i', '/\bApplebot\b/i',
    ];

    // DNS验证后缀映射（扩展版）
    private static $dns_suffix_map = [
        'Google'             => ['.googlebot.com', '.google.com'],
        'Bing'               => ['.search.msn.com', '.bing.com', '.microsoft.com'],
        'Baidu'              => ['.baidu.com', '.baidu.jp', '.baidu.cn'],
        'Yandex'             => ['.yandex.com', '.yandex.ru', '.yandex.net'],
        'DuckDuckGo'         => ['.duckduckgo.com'],
        'Sogou'              => ['.sogou.com'],
        '360'                => ['.360.cn', '.360.com', '.haosou.com'],
        'Shenma_UC'          => ['.sm.cn', '.uc.cn', '.alibaba.com'],
        'ByteDance_Toutiao'  => ['.bytedance.com', '.toutiao.com'],
        'Apple_Siri'         => ['.apple.com'],
        'Facebook'           => ['.facebook.com', '.fb.com'],
        'Twitter_X'          => ['.twitter.com', '.x.com'],
        'LinkedIn'           => ['.linkedin.com'],
        'Pinterest'          => ['.pinterest.com'],
        'Ahrefs'             => ['.ahrefs.com'],
        'Semrush'            => ['.semrush.com'],
        'Majestic'           => ['.majestic12.co.uk', '.majestic.com'],
        'Moz'                => ['.moz.com'],
        'Moz_Roger'          => ['.moz.com'],
        'Naver'              => ['.naver.com'],
        'Seznam'             => ['.seznam.cz'],
    ];

    // 正常浏览器必备的请求头
    private static $expected_browser_headers = ['accept', 'accept-language', 'accept-encoding', 'user-agent'];

    /**
     * 分析请求指纹
     * @param array  $headers 请求头（键名大小写均可）
     * @param string $ua      User-Agent 字符串
     * @param string $ip      客户端IP（用于DNS反查验证）
     * @return array ['score'=>0-100, 'is_bot'=>bool, 'type'=>'search|crawler|malicious|unknown', 'signals'=>[...]]
     */
    public static function analyze(array $headers, string $ua, string $ip = ''): array {
        $score   = 0;
        $signals = [];
        $type    = 'unknown';
        $is_bot  = false;

        // 归一化请求头键名为小写（保留插入顺序用于顺序指纹分析）
        $h = [];
        foreach ($headers as $k => $v) {
            $h[strtolower((string)$k)] = (string)$v;
        }

        $ua_lower = strtolower($ua);
        $ua_empty = ($ua === '' || trim($ua) === '');

        // ---------- 1. UA 为空 ----------
        if ($ua_empty) {
            $score += 35;
            $is_bot = true;
            $type   = 'malicious';
            $signals[] = ['code' => 'empty_ua', 'weight' => 35, 'desc' => 'User-Agent 为空'];
        }

        // ---------- 2. 匹配主流搜索引擎 ----------
        $matched_engine = null;
        foreach (self::$search_engines as $engine) {
            if (preg_match($engine['pattern'], $ua)) {
                $matched_engine = $engine;
                break;
            }
        }

        $is_verified_search_engine = false;

        if ($matched_engine !== null) {
            $is_bot = true;
            $type   = 'search';
            $signals[] = [
                'code'   => 'search_engine_ua',
                'weight' => 5,
                'desc'   => '匹配搜索引擎爬虫: ' . $matched_engine['name'],
                'name'   => $matched_engine['name'],
            ];

            // DNS 反向验证（最可靠的方法）
            $dnsVerified = false;
            if (!empty($ip) && (defined('WAF_BOT_VERIFY_DNS') && WAF_BOT_VERIFY_DNS)) {
                $dnsVerified = self::verifyByDns($ip, $matched_engine['name']);
                if ($dnsVerified) {
                    $is_verified_search_engine = true;
                    $signals[] = [
                        'code'   => 'dns_verified',
                        'weight' => 0,
                        'desc'   => 'DNS反查验证通过: ' . $ip . ' → ' . $matched_engine['name'],
                    ];
                }
            }

            // 如果 DNS 验证未启用或未通过，进行头特征验证
            if (!$dnsVerified) {
                $verify = self::verifySearchEngine($h, $ua, $matched_engine);
                if ($verify['valid']) {
                    // 头特征验证通过，信任为搜索引擎（降低风险但不能完全确定）
                    $is_verified_search_engine = true;
                    $score += 5;
                    $signals[] = [
                        'code'   => 'header_verified',
                        'weight' => 5,
                        'desc'   => '搜索引擎头特征验证通过',
                    ];
                } else {
                    // 头特征不符，可能是伪造，但不要立即标记为恶意
                    // 可能是真实的搜索引擎但不发送标准头
                    $score += 20;
                    $signals[] = [
                        'code'   => 'search_engine_unverified',
                        'weight' => 20,
                        'desc'   => '搜索引擎UA未通过验证: ' . $verify['reason'] . '（建议开启DNS验证）',
                    ];
                }
            }

            // 已验证的搜索引擎：分数极低，确保不会被误拦
            if ($is_verified_search_engine) {
                $score = min($score, 10);
            }
        }

        // ---------- 3. AI 爬虫 ----------
        foreach (self::$ai_bots as $pattern) {
            if (preg_match($pattern, $ua)) {
                $is_bot = true;
                if ($type === 'unknown') $type = 'crawler';
                $score += 25;
                $signals[] = ['code' => 'ai_bot_ua', 'weight' => 25, 'desc' => 'AI 爬虫 UA'];
                break;
            }
        }

        // ---------- 4. 自动化工具特征 ----------
        // 注意：如果 UA 同时包含搜索引擎和自动化工具名称，说明在伪造搜索引擎
        foreach (self::$automation_tools as $pattern) {
            if (preg_match($pattern, $ua)) {
                $is_bot = true;
                $type   = 'malicious';
                $score += 60;
                $signals[] = [
                    'code'   => 'automation_tool',
                    'weight' => 60,
                    'desc'   => '自动化工具 UA: ' . trim(preg_replace('/[^a-z0-9\-_\/\s]/i', '', $ua)),
                ];
                // 如果同时匹配了搜索引擎UA，说明在伪造搜索引擎，撤销验证状态
                if ($matched_engine !== null) {
                    $is_verified_search_engine = false;
                    $type = 'malicious';
                    $signals[] = [
                        'code'   => 'fake_search_engine',
                        'weight' => 50,
                        'desc'   => '伪造搜索引擎 UA（同时包含自动化工具特征）',
                    ];
                    $score += 50;
                }
                break;
            }
        }

        // ---------- 5. 无头浏览器检测 ----------
        $headless_detected = false;
        foreach (self::$headless_patterns as $pattern) {
            if (preg_match($pattern, $ua)) {
                $headless_detected = true;
                $is_bot = true;
                $type   = 'malicious';
                $score += 55;
                $signals[] = [
                    'code'   => 'headless_browser',
                    'weight' => 55,
                    'desc'   => '无头浏览器/自动化框架: ' . trim(preg_replace('/[^a-z0-9\-_\/\s]/i', '', $ua)),
                ];
                if ($matched_engine !== null) {
                    $is_verified_search_engine = false;
                    $signals[] = [
                        'code'   => 'fake_search_engine_headless',
                        'weight' => 60,
                        'desc'   => '伪造搜索引擎UA（含无头浏览器特征）',
                    ];
                    $score += 60;
                }
                break;
            }
        }

        // ---------- 6. 浏览器伪装检测 ----------
        if (!$ua_empty && !$headless_detected && stripos($ua, 'Mozilla') === false && $matched_engine === null) {
            $score += 20;
            $signals[] = ['code' => 'non_mozilla_ua', 'weight' => 20, 'desc' => 'UA 非 Mozilla 开头'];
        }
        if (strlen($ua) > 256) {
            $score += 15;
            $signals[] = ['code' => 'oversized_ua', 'weight' => 15, 'desc' => 'UA 长度异常'];
        }

        // ---------- 7. 请求头指纹分析 ----------
        // 已验证的搜索引擎跳过头异常检测（蜘蛛天然不发送某些浏览器头）
        if (!$is_verified_search_engine) {
            $header_signals = self::analyzeHeaders($h, $ua_empty, $matched_engine !== null);
            foreach ($header_signals as $s) {
                $signals[] = $s;
                $score += $s['weight'];
                if ($s['weight'] >= 20) $is_bot = true;
                if ($type === 'unknown' && $s['weight'] >= 30) $type = 'malicious';
            }
        }

        // ---------- 7. 最终类型判定 ----------
        if ($is_verified_search_engine) {
            $type = 'search';
        } elseif ($score >= 60 && $type === 'unknown') {
            $type = 'crawler';
        }
        if (!$is_bot && $score >= 50) {
            $is_bot = true;
        }

        $score = max(0, min(100, $score));

        return [
            'score'   => $score,
            'is_bot'  => $is_bot,
            'type'    => $type,
            'signals' => $signals,
            'verified_search_engine' => $is_verified_search_engine,
            'engine_name' => $matched_engine['name'] ?? '',
        ];
    }

    /**
     * 反向验证搜索引擎真实性（基于头特征）
     * 注意：头特征验证是辅助手段，DNS反查是最可靠的方法
     */
    private static function verifySearchEngine(array $h, string $ua, array $engine): array {
        // Googlebot 版本号格式校验
        if (stripos($ua, 'Googlebot') !== false && stripos($ua, 'Googlebot/') === false) {
            return ['valid' => false, 'reason' => 'Googlebot 版本号格式不符'];
        }
        // Bingbot 版本号格式校验
        if (stripos($ua, 'Bingbot') !== false && stripos($ua, 'Bingbot/') === false) {
            return ['valid' => false, 'reason' => 'Bingbot 版本号格式不符'];
        }
        // 有 Accept 头则通过（放宽：不要求 Accept 头，因为有些蜘蛛不发送）
        return ['valid' => true, 'reason' => ''];
    }

    /**
     * DNS 反向验证搜索引擎
     * 通过反向 DNS 解析验证 IP 是否属于搜索引擎官方域名
     * @param string $ip   客户端 IP
     * @param string $engine 搜索引擎名称
     * @return bool
     */
    private static function verifyByDns(string $ip, string $engine): bool {
        $suffixes = self::$dns_suffix_map[$engine] ?? [];
        if (empty($suffixes)) return false;

        $hostname = @gethostbyaddr($ip);
        if ($hostname === false || $hostname === $ip) return false;

        $forward_ip = @gethostbyname($hostname);
        if ($forward_ip !== $ip) return false;

        $host_lower = strtolower($hostname);
        foreach ($suffixes as $suffix) {
            if (str_ends_with($host_lower, $suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 分析请求头指纹（$h 已是小写键名）
     * @param bool $is_search_engine_ua 是否匹配了搜索引擎UA（降低头异常权重）
     */
    private static function analyzeHeaders(array $h, bool $ua_empty, bool $is_search_engine_ua = false): array {
        $signals = [];

        // 搜索引擎权重折扣系数（蜘蛛天然不发送某些浏览器头）
        $spider_discount = $is_search_engine_ua ? 0.3 : 1.0;

        // 1. 缺失常见浏览器头
        $missing = [];
        foreach (self::$expected_browser_headers as $name) {
            if (!isset($h[$name]) || trim($h[$name]) === '') {
                $missing[] = $name;
            }
        }
        $missing = array_values(array_diff($missing, ['user-agent'])); // UA 已单独处理
        if (count($missing) >= 2) {
            $weight = (int)round(count($missing) * 10 * $spider_discount);
            if ($weight > 0) {
                $signals[] = [
                    'code'   => 'missing_browser_headers',
                    'weight' => $weight,
                    'desc'   => '缺失浏览器常见头: ' . implode(',', $missing),
                ];
            }
        }

        // 2. Accept 头异常
        $accept = $h['accept'] ?? '';
        if ($accept === '' && !$ua_empty) {
            $weight = $is_search_engine_ua ? 0 : 12; // 蜘蛛通常不带Accept头
            if ($weight > 0) $signals[] = ['code' => 'missing_accept', 'weight' => $weight, 'desc' => '缺失 Accept 头'];
        } elseif ($accept === '*/*') {
            $weight = (int)round(18 * $spider_discount); // 蜘蛛常用 */*
            if ($weight > 0) $signals[] = ['code' => 'wildcard_accept', 'weight' => $weight, 'desc' => 'Accept: */*'];
        } elseif (stripos($accept, 'text/html') === false && stripos($accept, 'application/xhtml') === false) {
            if (!$ua_empty && stripos($h['user-agent'] ?? '', 'Mozilla') !== false && !$is_search_engine_ua) {
                $signals[] = ['code' => 'no_html_accept', 'weight' => 15, 'desc' => 'UA 像浏览器但不接受 text/html'];
            }
        }

        // 3. Accept-Language 异常（蜘蛛通常不发送 Accept-Language）
        $al = $h['accept-language'] ?? '';
        if ($al === '' && !$ua_empty) {
            $weight = $is_search_engine_ua ? 0 : 15;
            if ($weight > 0) $signals[] = ['code' => 'missing_accept_language', 'weight' => $weight, 'desc' => '缺失 Accept-Language'];
        } elseif ($al === '*') {
            $weight = (int)round(20 * $spider_discount);
            if ($weight > 0) $signals[] = ['code' => 'wildcard_accept_language', 'weight' => $weight, 'desc' => 'Accept-Language: *'];
        } elseif (preg_match('/^[a-z]{2}(,[a-z]{2})*$/i', $al) && stripos($al, ';q=') === false) {
            $weight = (int)round(8 * $spider_discount);
            if ($weight > 0) $signals[] = ['code' => 'simplified_accept_language', 'weight' => $weight, 'desc' => 'Accept-Language 简化无 q 值'];
        }

        // 4. Connection 头（蜘蛛常用 Connection: close）
        $conn = strtolower($h['connection'] ?? '');
        if ($conn === 'close' && stripos($h['user-agent'] ?? '', 'Mozilla') !== false && !$is_search_engine_ua) {
            $signals[] = ['code' => 'connection_close', 'weight' => 10, 'desc' => 'Connection: close 异常'];
        }

        // 5. 请求头顺序指纹（PHP 关联数组保留插入顺序）
        $order = array_keys($h);
        if (!empty($order)) {
            $ua_pos   = array_search('user-agent', $order, true);
            $host_pos = array_search('host', $order, true);
            if ($host_pos === false && !$ua_empty) {
                $signals[] = ['code' => 'missing_host', 'weight' => 25, 'desc' => '缺失 Host 头'];
            } elseif ($ua_pos !== false && $host_pos !== false && $ua_pos < $host_pos) {
                $weight = (int)round(12 * $spider_discount);
                if ($weight > 0) $signals[] = ['code' => 'abnormal_header_order', 'weight' => $weight, 'desc' => '请求头顺序异常'];
            }
        }

        // 6. Referer 缺失（蜘蛛天然不带 Referer，跳过）
        $referer = $h['referer'] ?? '';
        if ($referer === '' && !$ua_empty && stripos($h['user-agent'] ?? '', 'Mozilla') !== false && !$is_search_engine_ua) {
            $signals[] = ['code' => 'missing_referer', 'weight' => 6, 'desc' => '浏览器 UA 但缺失 Referer'];
        }

        // 7. X-Forwarded-For 链过长（可能使用代理池）
        $xff = $h['x-forwarded-for'] ?? '';
        if (substr_count($xff, ',') >= 4) {
            $signals[] = ['code' => 'long_xff_chain', 'weight' => 15, 'desc' => 'XFF 链过长，可能代理池'];
        }

        return $signals;
    }
}
