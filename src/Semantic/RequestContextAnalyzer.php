<?php
/**
 * 跨请求上下文分析器
 *
 * 职责：在单次请求检测之外，结合跨请求历史信息识别需要多次请求才能确认的攻击模式。
 *       包括 CSRF 风险、重放攻击、会话伪造/劫持、时序异常（自动化工具）、
 *       API 滥用（端点扫描/枚举）以及跨请求 payload 演进与参数枚举模式。
 *
 * 设计理念：
 *   - 单次请求只是事件点，跨请求上下文才能形成行为画像。
 *   - 评分采用加权最大值策略，避免单一维度噪声触发误判。
 *   - 历史数据按 IP 维度隔离，限制单 IP 记录数与活跃窗口，控制内存与磁盘占用。
 *
 * 核心能力：
 *   1. CSRF 风险评估     - Referer/Origin/Host/Token 多维一致性检查
 *   2. 重放攻击检测       - 请求签名（method+uri+sorted_params MD5）短窗口重复率
 *   3. 会话异常检测       - 同 session 的 UA/IP 切换、会话固定检测
 *   4. 时序异常检测       - 请求间隔标准差、规律性、突发性分析
 *   5. API 滥用检测       - 单 IP 短时间内端点覆盖、敏感端点扫描
 *   6. 跨请求模式识别     - 参数枚举、payload 变形演进、端点跳转横向移动
 *   7. 评分计算           - 多维加权最大值（上限 100）
 *   8. 持久化与清理       - WAF_STORAGE_DIR/request_context/ 持久化，30 分钟过期清理
 */
defined('ABSPATH') || exit;

class RequestContextAnalyzer {

    /** @var int 每IP最大请求记录数 */
    const MAX_RECORDS_PER_IP = 200;

    /** @var int 不活跃过期时间（秒）- 30分钟 */
    const INACTIVITY_TIMEOUT = 1800;

    /** @var int 重放检测短窗口（秒） */
    const REPLAY_SHORT_WINDOW = 60;

    /** @var int 重放检测长窗口（秒） */
    const REPLAY_LONG_WINDOW = 300;

    /** @var int API 滥用检测窗口（秒）- 5分钟 */
    const API_ABUSE_WINDOW = 300;

    /** @var int 时序异常最小样本数 */
    const TIMING_MIN_SAMPLES = 5;

    /** @var int 突发攻击连续请求数阈值 */
    const BURST_CONSECUTIVE = 5;

    /** @var int 突发攻击间隔阈值（毫秒） */
    const BURST_INTERVAL_MS = 100;

    /**
     * 已知端点集合（用于端点覆盖率计算）
     * 实际生产环境应从路由表动态加载，这里给一组常见端点用于启发式评估
     *
     * @var array<int,string>
     */
    private static $knownEndpoints = [
        '/', '/index.php', '/login', '/admin', '/wp-admin', '/phpmyadmin',
        '/api', '/api/users', '/api/login', '/api/v1', '/search', '/upload',
        '/config.php', '/info.php', '/robots.txt', '/sitemap.xml',
    ];

    /**
     * 敏感端点特征（用于后台扫描检测）
     *
     * @var array<int,string>
     */
    private static $sensitiveEndpoints = [
        '/admin', '/wp-admin', '/phpmyadmin', '/administrator',
        '/manager', '/console', '/dashboard', '/panel',
    ];

    /**
     * 敏感端点（用于会话固定检测：新 session 直接访问敏感端点）
     *
     * @var array<int,string>
     */
    private static $sessionFixationSensitivePaths = [
        '/admin', '/wp-admin', '/phpmyadmin', '/dashboard',
        '/api/admin', '/console', '/settings', '/account/delete',
    ];

    /**
     * 请求签名历史（按 IP 隔离）
     * 结构：['ip' => [['signature' => md5, 'timestamp' => ts, 'uri' => '...']]]
     *
     * @var array<string,array>
     */
    private static $requestSignatures = [];

    /**
     * 会话指纹历史（按 session_id 隔离）
     * 结构：['session_id' => ['ua_history' => [...], 'ip_history' => [...], 'first_seen' => ts, 'last_seen' => ts, 'first_uri' => '...']]
     *
     * @var array<string,array>
     */
    private static $sessionFingerprints = [];

    /**
     * 请求时间戳历史（按 IP 隔离）
     * 结构：['ip' => [ts1, ts2, ...]]
     *
     * @var array<string,array>
     */
    private static $requestTimestamps = [];

    /**
     * API 访问模式（按 IP 隔离）
     * 结构：['ip' => ['endpoints' => ['uri' => ts, ...], 'total' => int, 'unique' => int, 'first_seen' => ts]]
     *
     * @var array<string,array>
     */
    private static $apiAccessPatterns = [];

    /**
     * 跨请求参数样本（按 IP 隔离，用于参数枚举与 payload 演进检测）
     * 结构：['ip' => [['uri' => '...', 'params' => [...], 'timestamp' => ts]]]
     *
     * @var array<string,array>
     */
    private static $paramSamples = [];

    /** @var bool 是否已加载持久化数据 */
    private static $loaded = false;

    /** @var bool 当前请求是否已写入持久化（避免重复 IO） */
    private static $persisted = false;

    // ====================================================================
    // 公共 API
    // ====================================================================

    /**
     * 跨请求上下文威胁分析入口
     *
     * @param string $ip         客户端 IP
     * @param string $uri        请求 URI
     * @param string $method     请求方法
     * @param array  $headers    请求头（小写键名）
     * @param array  $params     请求参数
     * @param string $sessionId  会话 ID
     * @return array{
     *     score:int,
     *     csrf_risk:array,
     *     replay_risk:array,
     *     session_anomaly:array,
     *     timing_anomaly:array,
     *     api_abuse:array,
     *     context_indicators:array,
     *     cross_request_patterns:array
     * }
     */
    public static function analyze(
        string $ip = '',
        string $uri = '',
        string $method = 'GET',
        array $headers = [],
        array $params = [],
        string $sessionId = ''
    ): array {
        self::loadData();

        // IP 为空时无法做跨请求上下文，仅做无状态 CSRF 检查
        $safeIp = $ip !== '' ? $ip : '0.0.0.0';
        $method = strtoupper($method !== '' ? $method : 'GET');

        // 先记录本次请求到各历史结构，再触发检测，使得当前请求可被纳入统计
        self::recordRequestSignatures($safeIp, $uri, $params, $method);
        self::recordSessionFingerprint($sessionId, $safeIp, $headers, $uri);
        self::recordTimestamp($safeIp);
        self::recordApiAccess($safeIp, $uri);
        self::recordParamSample($safeIp, $uri, $params);

        $csrf     = self::assessCsrfRisk($uri, $method, $headers, $sessionId);
        $replay   = self::detectReplayAttack($safeIp, $uri, $params, $method);
        $session  = self::detectSessionAnomaly($sessionId, $safeIp, $headers);
        $timing   = self::detectTimingAnomaly($safeIp);
        $api      = self::detectApiAbuse($safeIp, $uri);
        $patterns = self::identifyCrossRequestPatterns($safeIp);

        $score = self::calcContextScore($csrf, $replay, $session, $timing, $api, $patterns);

        $indicators = self::buildContextIndicators($csrf, $replay, $session, $timing, $api, $patterns);

        self::cleanupStaleRecords();
        self::persistData();

        return [
            'score'                 => $score,
            'csrf_risk'             => $csrf,
            'replay_risk'           => $replay,
            'session_anomaly'       => $session,
            'timing_anomaly'        => $timing,
            'api_abuse'             => $api,
            'context_indicators'    => $indicators,
            'cross_request_patterns' => $patterns,
        ];
    }

    // ====================================================================
    // 1. CSRF 风险评估
    // ====================================================================

    /**
     * CSRF 风险评估
     *
     * 检查项：
     *   - Referer 与 Origin 是否匹配（不匹配 +30）
     *   - Origin 与 Host 是否一致（不一致 +25）
     *   - POST 请求是否携带 CSRF Token（缺失 +15）
     *   - POST 请求但 Referer 为空（可疑 +20）
     *
     * @param string $uri        请求 URI
     * @param string $method     请求方法
     * @param array  $headers    请求头
     * @param string $sessionId  会话 ID
     * @return array{
     *     is_csrf:bool,
     *     confidence:int,
     *     reasons:array,
     *     risk_score:int
     * }
     */
    private static function assessCsrfRisk(string $uri, string $method, array $headers, string $sessionId): array {
        $reasons = [];
        $score = 0;

        $referer = self::headerValue($headers, 'referer');
        $origin  = self::headerValue($headers, 'origin');
        $host    = self::headerValue($headers, 'host');

        $methodUpper = strtoupper($method);
        $isStateChanging = in_array($methodUpper, ['POST', 'PUT', 'DELETE', 'PATCH'], true);

        // 1. Referer 与 Origin 不匹配（同时存在但 host 不同）
        if ($referer !== '' && $origin !== '') {
            $refererHost = self::parseHost($referer);
            $originHost  = self::parseHost($origin);
            if ($refererHost !== '' && $originHost !== '' && strcasecmp($refererHost, $originHost) !== 0) {
                $score += 30;
                $reasons[] = sprintf('Referer(%s) 与 Origin(%s) 主机不匹配', $refererHost, $originHost);
            }
        }

        // 2. Origin 与 Host 不一致
        if ($origin !== '' && $host !== '') {
            $originHost = self::parseHost($origin);
            if ($originHost !== '' && strcasecmp($originHost, $host) !== 0) {
                $score += 25;
                $reasons[] = sprintf('Origin(%s) 与 Host(%s) 不一致', $originHost, $host);
            }
        }

        // 3. 状态变更请求缺少 CSRF Token
        if ($isStateChanging) {
            $hasToken = self::hasCsrfToken($headers);
            if (!$hasToken) {
                $score += 15;
                $reasons[] = $methodUpper . ' 请求未携带 CSRF Token';
            }
        }

        // 4. POST 请求但 Referer 为空
        if ($methodUpper === 'POST' && $referer === '') {
            $score += 20;
            $reasons[] = 'POST 请求缺少 Referer 头（可能跨站伪造）';
        }

        // 上限保护
        if ($score > 100) {
            $score = 100;
        }

        $isCsrf = $score >= 40;
        $confidence = $score; // 风险分即置信度（0-100）

        return [
            'is_csrf'    => $isCsrf,
            'confidence' => $confidence,
            'reasons'    => $reasons,
            'risk_score' => $score,
        ];
    }

    // ====================================================================
    // 2. 重放攻击检测
    // ====================================================================

    /**
     * 重放攻击检测
     *
     * 检查项：
     *   - 60 秒内相同请求签名出现 >3 次（+25）
     *   - 5 分钟内相同签名占比 >50%（自动化工具 +20）
     *
     * @param string $ip      客户端 IP
     * @param string $uri     请求 URI
     * @param array  $params  请求参数
     * @param string $method  请求方法
     * @return array{
     *     is_replay:bool,
     *     repeat_count:int,
     *     time_window:int,
     *     risk_score:int
     * }
     */
    private static function detectReplayAttack(string $ip, string $uri, array $params, string $method): array {
        $signature = self::computeSignature($method, $uri, $params);
        $now = time();
        $signatures = self::$requestSignatures[$ip] ?? [];

        // 短窗口内同签名计数
        $shortCount = 0;
        $longTotal = 0;
        $longSame = 0;
        foreach ($signatures as $entry) {
            $age = $now - $entry['timestamp'];
            if ($age <= self::REPLAY_LONG_WINDOW) {
                $longTotal++;
                if ($entry['signature'] === $signature) {
                    $longSame++;
                    if ($age <= self::REPLAY_SHORT_WINDOW) {
                        $shortCount++;
                    }
                }
            }
        }

        $score = 0;
        $timeWindow = 0;

        // 短窗口重放：>3 次（含当前请求已写入，故 >=3 即等同 >3 的累计）
        if ($shortCount >= 3) {
            $score += 25;
            $timeWindow = self::REPLAY_SHORT_WINDOW;
        }

        // 长窗口重复率：>50%
        if ($longTotal > 0) {
            $ratio = $longSame / $longTotal;
            if ($ratio > 0.5) {
                $score += 20;
                if ($timeWindow === 0) {
                    $timeWindow = self::REPLAY_LONG_WINDOW;
                }
            }
        }

        if ($score > 100) {
            $score = 100;
        }

        return [
            'is_replay'    => $score >= 25,
            'repeat_count' => $shortCount,
            'time_window'  => $timeWindow,
            'risk_score'   => $score,
        ];
    }

    // ====================================================================
    // 3. 会话异常检测
    // ====================================================================

    /**
     * 会话异常检测
     *
     * 检查项：
     *   - 同 session 的 UA 切换 >2 个（+20）
     *   - 同 session 的 IP 切换 >3 个（+25，疑似会话劫持）
     *   - 会话固定：新 session 直接访问敏感端点（+30）
     *
     * @param string $sessionId 会话 ID
     * @param string $ip        客户端 IP
     * @param array  $headers   请求头
     * @return array{
     *     is_anomaly:bool,
     *     ua_changes:int,
     *     ip_changes:int,
     *     risk_score:int
     * }
     */
    private static function detectSessionAnomaly(string $sessionId, string $ip, array $headers): array {
        if ($sessionId === '') {
            return [
                'is_anomaly' => false,
                'ua_changes' => 0,
                'ip_changes' => 0,
                'risk_score' => 0,
            ];
        }

        $fp = self::$sessionFingerprints[$sessionId] ?? null;
        if ($fp === null) {
            return [
                'is_anomaly' => false,
                'ua_changes' => 0,
                'ip_changes' => 0,
                'risk_score' => 0,
            ];
        }

        $uaHistory = $fp['ua_history'] ?? [];
        $ipHistory = $fp['ip_history'] ?? [];

        $uaUnique = count(array_unique($uaHistory));
        $ipUnique = count(array_unique($ipHistory));

        $score = 0;

        // UA 切换：>2 个不同 UA
        if ($uaUnique > 2) {
            $score += 20;
        }

        // IP 切换：>3 个不同 IP（会话劫持强信号）
        if ($ipUnique > 3) {
            $score += 25;
        }

        // 会话固定：first_seen 与 last_seen 接近（新 session）且首个 URI 命中敏感端点
        if (isset($fp['first_uri']) && self::isSessionFixationPath($fp['first_uri'])) {
            $age = (isset($fp['first_seen']) ? time() - $fp['first_seen'] : 0);
            // 新 session（首次出现 60 秒内）直接访问敏感端点
            if ($age <= 60) {
                $score += 30;
            }
        }

        if ($score > 100) {
            $score = 100;
        }

        return [
            'is_anomaly' => $score >= 25,
            'ua_changes' => $uaUnique,
            'ip_changes' => $ipUnique,
            'risk_score' => $score,
        ];
    }

    // ====================================================================
    // 4. 时序异常检测
    // ====================================================================

    /**
     * 时序异常检测
     *
     * 检查项：
     *   - 间隔标准差 σ < 0.5 秒（机器人 +25）
     *   - 间隔方差 < 5%（规律性自动化 +20）
     *   - 连续 5 个请求间隔 < 100ms（暴力突发 +30）
     *
     * @param string $ip 客户端 IP
     * @return array{
     *     is_anomaly:bool,
     *     avg_interval:float,
     *     stddev:float,
     *     pattern:string,
     *     risk_score:int
     * }
     */
    private static function detectTimingAnomaly(string $ip): array {
        $timestamps = self::$requestTimestamps[$ip] ?? [];
        $n = count($timestamps);

        $empty = [
            'is_anomaly'  => false,
            'avg_interval' => 0.0,
            'stddev'       => 0.0,
            'pattern'      => 'human',
            'risk_score'   => 0,
        ];

        if ($n < self::TIMING_MIN_SAMPLES) {
            return $empty;
        }

        // 计算间隔（秒，浮点）
        $intervals = [];
        for ($i = 1; $i < $n; $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i - 1];
        }
        $intervalCount = count($intervals);
        if ($intervalCount === 0) {
            return $empty;
        }

        $sum = array_sum($intervals);
        $avg = $sum / $intervalCount;

        // 标准差
        $variance = 0.0;
        foreach ($intervals as $v) {
            $variance += ($v - $avg) * ($v - $avg);
        }
        $variance /= $intervalCount;
        $stddev = sqrt($variance);

        $score = 0;
        $pattern = 'human';

        // σ < 0.5 秒 -> 机器人
        if ($stddev < 0.5) {
            $score += 25;
            $pattern = 'robot';
        }

        // 间隔方差 < 5% -> 规律性自动化
        if ($avg > 0) {
            $cv = $stddev / $avg; // 变异系数
            if ($cv < 0.05) {
                $score += 20;
                if ($pattern === 'human') {
                    $pattern = 'robot';
                }
            }
        }

        // 连续 5 个请求间隔 < 100ms -> 暴力突发
        $burst = self::detectBurstPattern($intervals);
        if ($burst) {
            $score += 30;
            $pattern = 'burst';
        }

        if ($score > 100) {
            $score = 100;
        }

        return [
            'is_anomaly'  => $score >= 25,
            'avg_interval' => round($avg, 4),
            'stddev'       => round($stddev, 4),
            'pattern'      => $pattern,
            'risk_score'   => $score,
        ];
    }

    // ====================================================================
    // 5. API 滥用检测
    // ====================================================================

    /**
     * API 滥用检测
     *
     * 检查项：
     *   - 5 分钟内访问 >20 个不同端点（扫描 +30）
     *   - 端点覆盖率 >50%（枚举 +25）
     *   - 连续访问敏感端点（/admin /wp-admin /phpmyadmin 等 -> 后台扫描 +20）
     *
     * @param string $ip  客户端 IP
     * @param string $uri 请求 URI
     * @return array{
     *     is_abuse:bool,
     *     unique_endpoints:int,
     *     coverage_ratio:float,
     *     risk_score:int
     * }
     */
    private static function detectApiAbuse(string $ip, string $uri): array {
        $pattern = self::$apiAccessPatterns[$ip] ?? null;
        if ($pattern === null) {
            return [
                'is_abuse'        => false,
                'unique_endpoints' => 0,
                'coverage_ratio'  => 0.0,
                'risk_score'      => 0,
            ];
        }

        $now = time();
        $endpoints = $pattern['endpoints'] ?? [];

        // 仅统计窗口内的端点
        $activeEndpoints = [];
        foreach ($endpoints as $ep => $ts) {
            if ($now - $ts <= self::API_ABUSE_WINDOW) {
                $activeEndpoints[] = $ep;
            }
        }
        $uniqueCount = count(array_unique($activeEndpoints));

        $score = 0;

        // >20 个不同端点 -> 扫描
        if ($uniqueCount > 20) {
            $score += 30;
        }

        // 端点覆盖率 >50%
        $knownCount = count(self::$knownEndpoints);
        $coverage = 0.0;
        if ($knownCount > 0) {
            $matched = 0;
            foreach ($activeEndpoints as $ep) {
                if (in_array($ep, self::$knownEndpoints, true)) {
                    $matched++;
                }
            }
            $coverage = $matched / $knownCount;
            if ($coverage > 0.5) {
                $score += 25;
            }
        }

        // 连续访问敏感端点 -> 后台扫描
        $sensitiveHits = 0;
        foreach ($activeEndpoints as $ep) {
            if (self::isSensitiveEndpoint($ep)) {
                $sensitiveHits++;
            }
        }
        if ($sensitiveHits >= 2) {
            $score += 20;
        }

        if ($score > 100) {
            $score = 100;
        }

        return [
            'is_abuse'        => $score >= 25,
            'unique_endpoints' => $uniqueCount,
            'coverage_ratio'  => round($coverage, 4),
            'risk_score'      => $score,
        ];
    }

    // ====================================================================
    // 6. 跨请求模式识别
    // ====================================================================

    /**
     * 跨请求模式识别
     *
     * 检查项：
     *   - 参数值变化模式（id=1, id=2, id=3 -> 枚举 +20）
     *   - payload 演进（union select -> union 内联注释绕过 -> 变形绕过 +25）
     *   - 端点跳转模式（/login -> /admin -> /api -> 横向移动 +20）
     *
     * @param string $ip 客户端 IP
     * @return array{
     *     patterns:array,
     *     pattern_count:int,
     *     risk_score:int
     * }
     */
    private static function identifyCrossRequestPatterns(string $ip): array {
        $samples = self::$paramSamples[$ip] ?? [];
        $patterns = [];
        $score = 0;

        if (count($samples) >= 3) {
            // 1. 参数枚举：同名参数值呈递增/枚举序列
            $enumHits = self::detectParamEnumeration($samples);
            if ($enumHits > 0) {
                $patterns[] = [
                    'type'        => 'param_enumeration',
                    'description' => '参数值呈现枚举序列（如 id=1,2,3...）',
                    'hits'        => $enumHits,
                ];
                $score += 20;
            }

            // 2. payload 演进：同端点参数值出现 obfuscation 变形
            $evolutionHits = self::detectPayloadEvolution($samples);
            if ($evolutionHits > 0) {
                $patterns[] = [
                    'type'        => 'payload_evolution',
                    'description' => '检测到 payload 变形演进（如 union select -> union/**/select）',
                    'hits'        => $evolutionHits,
                ];
                $score += 25;
            }

            // 3. 端点跳转：/login -> /admin -> /api 横向移动
            $lateral = self::detectLateralMovement($samples);
            if ($lateral) {
                $patterns[] = [
                    'type'        => 'lateral_movement',
                    'description' => '端点跳转模式：登录 -> 后台 -> API 横向移动',
                ];
                $score += 20;
            }
        }

        if ($score > 100) {
            $score = 100;
        }

        return [
            'patterns'      => $patterns,
            'pattern_count' => count($patterns),
            'risk_score'    => $score,
        ];
    }

    // ====================================================================
    // 7. 评分计算
    // ====================================================================

    /**
     * 跨请求上下文综合评分
     *
     * 加权策略：各维度归一化到 [0,1] 后取加权最大值，避免简单累加触发误判。
     * 权重总和：CSRF(0.30) + 重放(0.25) + 会话(0.30) + 时序(0.25) + API(0.30) + 模式(0.25)
     * 总分上限 100。
     *
     * @param array $csrf     CSRF 评估结果
     * @param array $replay   重放检测结果
     * @param array $session  会话异常结果
     * @param array $timing   时序异常结果
     * @param array $api      API 滥用结果
     * @param array $patterns 跨请求模式结果
     * @return int 0-100 综合分
     */
    private static function calcContextScore(
        array $csrf,
        array $replay,
        array $session,
        array $timing,
        array $api,
        array $patterns
    ): int {
        $csrfScore    = isset($csrf['risk_score'])     ? (int)$csrf['risk_score']     : 0;
        $replayScore  = isset($replay['risk_score'])   ? (int)$replay['risk_score']   : 0;
        $sessionScore = isset($session['risk_score'])  ? (int)$session['risk_score']  : 0;
        $timingScore  = isset($timing['risk_score'])   ? (int)$timing['risk_score']   : 0;
        $apiScore     = isset($api['risk_score'])      ? (int)$api['risk_score']      : 0;
        $patternScore = isset($patterns['risk_score']) ? (int)$patterns['risk_score'] : 0;

        // 归一化到 [0,1]
        $csrfNorm    = $csrfScore    / 100;
        $replayNorm  = $replayScore  / 100;
        $sessionNorm = $sessionScore / 100;
        $timingNorm  = $timingScore  / 100;
        $apiNorm     = $apiScore     / 100;
        $patternNorm = $patternScore / 100;

        // 权重
        $wCsrf    = 0.30;
        $wReplay  = 0.25;
        $wSession = 0.30;
        $wTiming  = 0.25;
        $wApi     = 0.30;
        $wPattern = 0.25;

        // 加权最大值
        $weighted = [
            $wCsrf    * $csrfNorm,
            $wReplay  * $replayNorm,
            $wSession * $sessionNorm,
            $wTiming  * $timingNorm,
            $wApi     * $apiNorm,
            $wPattern * $patternNorm,
        ];
        $maxWeighted = max($weighted);

        // 归一化系数：最大权重为 0.30，将加权最大值映射回 [0,100]
        $score = (int)round($maxWeighted / 0.30 * 100);

        if ($score < 0) {
            $score = 0;
        }
        if ($score > 100) {
            $score = 100;
        }

        return $score;
    }

    // ====================================================================
    // 8. 持久化与清理
    // ====================================================================

    /**
     * 清理过期或不活跃的记录
     *
     * @return void
     */
    private static function cleanupStaleRecords(): void {
        $now = time();
        $cutoff = $now - self::INACTIVITY_TIMEOUT;

        // 清理请求签名（按 IP）
        foreach (self::$requestSignatures as $ip => $entries) {
            $kept = [];
            foreach ($entries as $entry) {
                if (isset($entry['timestamp']) && $entry['timestamp'] >= $cutoff) {
                    $kept[] = $entry;
                }
            }
            if (empty($kept)) {
                unset(self::$requestSignatures[$ip]);
            } else {
                // 限制每 IP 最多 MAX_RECORDS_PER_IP 条
                if (count($kept) > self::MAX_RECORDS_PER_IP) {
                    $kept = array_slice($kept, -self::MAX_RECORDS_PER_IP);
                }
                self::$requestSignatures[$ip] = $kept;
            }
        }

        // 清理时间戳（按 IP，整体过期才删除）
        foreach (self::$requestTimestamps as $ip => $timestamps) {
            $kept = [];
            foreach ($timestamps as $ts) {
                if ($ts >= $cutoff) {
                    $kept[] = $ts;
                }
            }
            if (empty($kept)) {
                unset(self::$requestTimestamps[$ip]);
            } else {
                if (count($kept) > self::MAX_RECORDS_PER_IP) {
                    $kept = array_slice($kept, -self::MAX_RECORDS_PER_IP);
                }
                self::$requestTimestamps[$ip] = $kept;
            }
        }

        // 清理 API 访问模式（按 IP，按端点过期）
        foreach (self::$apiAccessPatterns as $ip => $pattern) {
            $endpoints = $pattern['endpoints'] ?? [];
            $keptEndpoints = [];
            foreach ($endpoints as $ep => $ts) {
                if ($ts >= $cutoff) {
                    $keptEndpoints[$ep] = $ts;
                }
            }
            if (empty($keptEndpoints)) {
                unset(self::$apiAccessPatterns[$ip]);
            } else {
                $pattern['endpoints'] = $keptEndpoints;
                $pattern['unique'] = count($keptEndpoints);
                self::$apiAccessPatterns[$ip] = $pattern;
            }
        }

        // 清理会话指纹（按 session，last_seen 超时删除）
        foreach (self::$sessionFingerprints as $sid => $fp) {
            $lastSeen = $fp['last_seen'] ?? 0;
            if ($lastSeen < $cutoff) {
                unset(self::$sessionFingerprints[$sid]);
            }
        }

        // 清理参数样本（按 IP）
        foreach (self::$paramSamples as $ip => $samples) {
            $kept = [];
            foreach ($samples as $s) {
                if (isset($s['timestamp']) && $s['timestamp'] >= $cutoff) {
                    $kept[] = $s;
                }
            }
            if (empty($kept)) {
                unset(self::$paramSamples[$ip]);
            } else {
                if (count($kept) > self::MAX_RECORDS_PER_IP) {
                    $kept = array_slice($kept, -self::MAX_RECORDS_PER_IP);
                }
                self::$paramSamples[$ip] = $kept;
            }
        }
    }

    /**
     * 持久化历史数据到 WAF_STORAGE_DIR/request_context/
     *
     * @return void
     */
    private static function persistData(): void {
        if (self::$persisted) {
            return;
        }
        self::$persisted = true;

        $file = self::getPersistFile();
        if ($file === '') {
            return;
        }

        $data = [
            'request_signatures'  => self::$requestSignatures,
            'session_fingerprints' => self::$sessionFingerprints,
            'request_timestamps'  => self::$requestTimestamps,
            'api_access_patterns' => self::$apiAccessPatterns,
            'param_samples'       => self::$paramSamples,
            'persisted_at'        => time(),
        ];

        @file_put_contents($file, json_encode($data), LOCK_EX);
    }

    /**
     * 从持久化存储加载历史数据
     *
     * @return void
     */
    private static function loadData(): void {
        if (self::$loaded) {
            return;
        }
        self::$loaded = true;

        $file = self::getPersistFile();
        if ($file === '') {
            return;
        }

        $content = @file_get_contents($file);
        if ($content === false || $content === '') {
            return;
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return;
        }

        self::$requestSignatures  = is_array($data['request_signatures']  ?? null) ? $data['request_signatures']  : [];
        self::$sessionFingerprints = is_array($data['session_fingerprints'] ?? null) ? $data['session_fingerprints'] : [];
        self::$requestTimestamps  = is_array($data['request_timestamps']  ?? null) ? $data['request_timestamps']  : [];
        self::$apiAccessPatterns  = is_array($data['api_access_patterns'] ?? null) ? $data['api_access_patterns'] : [];
        self::$paramSamples       = is_array($data['param_samples']       ?? null) ? $data['param_samples']       : [];
    }

    /**
     * 获取持久化文件路径（目录不可写时返回空串）
     *
     * @return string
     */
    private static function getPersistFile(): string {
        $baseDir = defined('WAF_STORAGE_DIR') ? WAF_STORAGE_DIR : (sys_get_temp_dir() . '/shield-waf');
        $dir = rtrim($baseDir, '/') . '/request_context';

        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0755, true)) {
                return '';
            }
        }
        if (!is_writable($dir)) {
            return '';
        }

        return $dir . '/context_data.json';
    }

    // ====================================================================
    // 辅助方法 - 历史记录写入
    // ====================================================================

    /**
     * 记录请求签名到历史
     *
     * @param string $ip     客户端 IP
     * @param string $uri    请求 URI
     * @param array  $params 请求参数
     * @param string $method 请求方法
     * @return void
     */
    private static function recordRequestSignatures(string $ip, string $uri, array $params, string $method): void {
        $signature = self::computeSignature($method, $uri, $params);
        if (!isset(self::$requestSignatures[$ip])) {
            self::$requestSignatures[$ip] = [];
        }
        self::$requestSignatures[$ip][] = [
            'signature' => $signature,
            'timestamp' => time(),
            'uri'       => $uri,
        ];
        // 长度保护（cleanupStaleRecords 也会做，这里防止内存爆涨）
        if (count(self::$requestSignatures[$ip]) > self::MAX_RECORDS_PER_IP) {
            self::$requestSignatures[$ip] = array_slice(
                self::$requestSignatures[$ip],
                -self::MAX_RECORDS_PER_IP
            );
        }
    }

    /**
     * 记录会话指纹到历史
     *
     * @param string $sessionId 会话 ID
     * @param string $ip        客户端 IP
     * @param array  $headers   请求头
     * @param string $uri       请求 URI
     * @return void
     */
    private static function recordSessionFingerprint(string $sessionId, string $ip, array $headers, string $uri): void {
        if ($sessionId === '') {
            return;
        }
        $ua = self::headerValue($headers, 'user-agent');

        if (!isset(self::$sessionFingerprints[$sessionId])) {
            self::$sessionFingerprints[$sessionId] = [
                'ua_history' => [],
                'ip_history' => [],
                'first_seen' => time(),
                'last_seen'  => time(),
                'first_uri'  => $uri,
            ];
        }

        $fp = &self::$sessionFingerprints[$sessionId];
        $fp['last_seen'] = time();

        // UA 历史（去重，最多保留 10 个）
        if ($ua !== '' && !in_array($ua, $fp['ua_history'], true)) {
            $fp['ua_history'][] = $ua;
            if (count($fp['ua_history']) > 10) {
                $fp['ua_history'] = array_slice($fp['ua_history'], -10);
            }
        }

        // IP 历史（去重，最多保留 10 个）
        if ($ip !== '' && !in_array($ip, $fp['ip_history'], true)) {
            $fp['ip_history'][] = $ip;
            if (count($fp['ip_history']) > 10) {
                $fp['ip_history'] = array_slice($fp['ip_history'], -10);
            }
        }
        unset($fp);
    }

    /**
     * 记录请求时间戳到历史
     *
     * @param string $ip 客户端 IP
     * @return void
     */
    private static function recordTimestamp(string $ip): void {
        if (!isset(self::$requestTimestamps[$ip])) {
            self::$requestTimestamps[$ip] = [];
        }
        self::$requestTimestamps[$ip][] = microtime(true);
        if (count(self::$requestTimestamps[$ip]) > self::MAX_RECORDS_PER_IP) {
            self::$requestTimestamps[$ip] = array_slice(
                self::$requestTimestamps[$ip],
                -self::MAX_RECORDS_PER_IP
            );
        }
    }

    /**
     * 记录 API 访问模式到历史
     *
     * @param string $ip  客户端 IP
     * @param string $uri 请求 URI
     * @return void
     */
    private static function recordApiAccess(string $ip, string $uri): void {
        $endpoint = self::normalizeEndpoint($uri);
        if (!isset(self::$apiAccessPatterns[$ip])) {
            self::$apiAccessPatterns[$ip] = [
                'endpoints'  => [],
                'total'      => 0,
                'unique'     => 0,
                'first_seen' => time(),
            ];
        }
        $pattern = &self::$apiAccessPatterns[$ip];
        $pattern['endpoints'][$endpoint] = time();
        $pattern['total']++;
        $pattern['unique'] = count($pattern['endpoints']);
        unset($pattern);
    }

    /**
     * 记录参数样本到历史
     *
     * @param string $ip     客户端 IP
     * @param string $uri    请求 URI
     * @param array  $params 请求参数
     * @return void
     */
    private static function recordParamSample(string $ip, string $uri, array $params): void {
        if (!isset(self::$paramSamples[$ip])) {
            self::$paramSamples[$ip] = [];
        }
        // 参数样本精简化，仅保留键与字符串化值（限制单条大小）
        $sampleParams = [];
        foreach ($params as $k => $v) {
            if (is_array($v)) {
                $v = json_encode($v);
            } else {
                $v = (string)$v;
            }
            // 单值截断，避免超长 payload 占用过大
            if (strlen($v) > 256) {
                $v = substr($v, 0, 256);
            }
            $sampleParams[$k] = $v;
        }
        self::$paramSamples[$ip][] = [
            'uri'       => $uri,
            'params'    => $sampleParams,
            'timestamp' => time(),
        ];
        if (count(self::$paramSamples[$ip]) > self::MAX_RECORDS_PER_IP) {
            self::$paramSamples[$ip] = array_slice(
                self::$paramSamples[$ip],
                -self::MAX_RECORDS_PER_IP
            );
        }
    }

    // ====================================================================
    // 辅助方法 - 通用工具
    // ====================================================================

    /**
     * 计算请求签名（method + uri + sorted_params 的 MD5）
     *
     * @param string $method 请求方法
     * @param string $uri    请求 URI
     * @param array  $params 请求参数
     * @return string 32 位 MD5 签名
     */
    private static function computeSignature(string $method, string $uri, array $params): string {
        ksort($params);
        $serialized = json_encode($params);
        return md5(strtoupper($method) . '|' . $uri . '|' . $serialized);
    }

    /**
     * 从请求头数组中取值（兼容大小写）
     *
     * @param array  $headers 请求头
     * @param string $name    头名（小写）
     * @return string
     */
    private static function headerValue(array $headers, string $name): string {
        if (isset($headers[$name])) {
            return self::normalizeHeader($headers[$name]);
        }
        // 大小写兼容
        $lower = strtolower($name);
        foreach ($headers as $k => $v) {
            if (strtolower($k) === $lower) {
                return self::normalizeHeader($v);
            }
        }
        return '';
    }

    /**
     * 头值归一化（数组取首项，去除前后空白）
     *
     * @param mixed $value 头值
     * @return string
     */
    private static function normalizeHeader($value): string {
        if (is_array($value)) {
            $value = isset($value[0]) ? $value[0] : '';
        }
        $value = (string)$value;
        return trim($value);
    }

    /**
     * 从 URL 中解析主机名
     *
     * @param string $url URL
     * @return string 主机名（不含端口），失败返回空串
     */
    private static function parseHost(string $url): string {
        if ($url === '') {
            return '';
        }
        // 不带 scheme 的 host 直接返回小写
        if (strpos($url, '://') === false) {
            // 可能是裸 host 或 host:port
            $parts = explode(':', $url, 2);
            return strtolower(trim($parts[0]));
        }
        $parsed = parse_url($url, PHP_URL_HOST);
        if ($parsed === false || $parsed === null) {
            return '';
        }
        return strtolower($parsed);
    }

    /**
     * 检查请求头/参数中是否携带 CSRF Token
     *
     * @param array $headers 请求头
     * @return bool
     */
    private static function hasCsrfToken(array $headers): bool {
        $tokenHeaders = [
            'x-csrf-token', 'x-xsrf-token', 'x-csrftoken', 'x-xsrftoken',
        ];
        foreach ($tokenHeaders as $h) {
            if (self::headerValue($headers, $h) !== '') {
                return true;
            }
        }
        return false;
    }

    /**
     * 检测连续突发模式（连续 N 个间隔均小于阈值）
     *
     * @param array $intervals 间隔数组（秒，浮点）
     * @return bool
     */
    private static function detectBurstPattern(array $intervals): bool {
        $threshold = self::BURST_INTERVAL_MS / 1000; // 0.1 秒
        $need = self::BURST_CONSECUTIVE;
        if (count($intervals) < $need) {
            return false;
        }
        $consecutive = 0;
        foreach ($intervals as $v) {
            if ($v < $threshold) {
                $consecutive++;
                if ($consecutive >= $need) {
                    return true;
                }
            } else {
                $consecutive = 0;
            }
        }
        return false;
    }

    /**
     * 端点归一化（剥离查询字符串，仅保留路径）
     *
     * @param string $uri 请求 URI
     * @return string
     */
    private static function normalizeEndpoint(string $uri): string {
        if ($uri === '') {
            return '/';
        }
        $path = parse_url($uri, PHP_URL_PATH);
        if ($path === false || $path === null || $path === '') {
            $path = '/';
        }
        return $path;
    }

    /**
     * 判断端点是否为敏感后台端点
     *
     * @param string $endpoint 端点路径
     * @return bool
     */
    private static function isSensitiveEndpoint(string $endpoint): bool {
        if ($endpoint === '') {
            return false;
        }
        $lower = strtolower($endpoint);
        foreach (self::$sensitiveEndpoints as $s) {
            if (strpos($lower, $s) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断路径是否会话固定敏感端点
     *
     * @param string $uri 请求 URI
     * @return bool
     */
    private static function isSessionFixationPath(string $uri): bool {
        if ($uri === '') {
            return false;
        }
        $path = self::normalizeEndpoint($uri);
        $lower = strtolower($path);
        foreach (self::$sessionFixationSensitivePaths as $s) {
            if (strpos($lower, $s) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检测参数枚举模式（同名参数值呈递增/枚举序列）
     *
     * @param array $samples 参数样本
     * @return int 命中数
     */
    private static function detectParamEnumeration(array $samples): int {
        // 收集每个参数名的历史值
        $paramValues = [];
        foreach ($samples as $s) {
            $params = $s['params'] ?? [];
            foreach ($params as $k => $v) {
                if (!isset($paramValues[$k])) {
                    $paramValues[$k] = [];
                }
                $paramValues[$k][] = $v;
            }
        }

        $hits = 0;
        foreach ($paramValues as $key => $values) {
            $unique = array_unique($values);
            if (count($unique) < 3) {
                continue;
            }
            // 检测是否为数字递增序列
            $numericValues = [];
            $allNumeric = true;
            foreach ($unique as $v) {
                if (is_numeric($v)) {
                    $numericValues[] = (float)$v;
                } else {
                    $allNumeric = false;
                    break;
                }
            }
            if ($allNumeric && count($numericValues) >= 3) {
                sort($numericValues);
                $isIncreasing = true;
                for ($i = 1; $i < count($numericValues); $i++) {
                    if ($numericValues[$i] <= $numericValues[$i - 1]) {
                        $isIncreasing = false;
                        break;
                    }
                }
                if ($isIncreasing) {
                    $hits++;
                    continue;
                }
            }
            // 检测值长度相近但内容不同（如用户名枚举）
            $lengths = array_map('strlen', $unique);
            $lenStats = self::basicStats($lengths);
            if ($lenStats['stddev'] < 2 && count($unique) >= 5) {
                $hits++;
            }
        }
        return $hits;
    }

    /**
     * 检测 payload 演进模式（同端点参数值出现 obfuscation 变形）
     *
     * @param array $samples 参数样本
     * @return int 命中数
     */
    private static function detectPayloadEvolution(array $samples): int {
        // 按端点聚合参数值
        $byEndpoint = [];
        foreach ($samples as $s) {
            $ep = self::normalizeEndpoint($s['uri'] ?? '');
            $params = $s['params'] ?? [];
            foreach ($params as $k => $v) {
                if (!isset($byEndpoint[$ep][$k])) {
                    $byEndpoint[$ep][$k] = [];
                }
                $byEndpoint[$ep][$k][] = $v;
            }
        }

        $hits = 0;
        $obfuscationMarkers = ['/**/', '/**', '**/', '/*', '*/', '%20', '%09', '\t', '\n', '+', '--'];
        $semanticKeywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'script', 'alert', 'onerror', 'onload', 'eval',
            'exec', 'system', 'passthru', 'shell',
        ];

        foreach ($byEndpoint as $ep => $paramValues) {
            foreach ($paramValues as $key => $values) {
                $unique = array_unique($values);
                if (count($unique) < 2) {
                    continue;
                }
                // 同参数名下，多个值都含语义关键字（不同变形）
                $keywordHits = 0;
                $obfuscationHits = 0;
                foreach ($unique as $v) {
                    $lower = strtolower($v);
                    $hasKeyword = false;
                    foreach ($semanticKeywords as $kw) {
                        if (strpos($lower, $kw) !== false) {
                            $hasKeyword = true;
                            break;
                        }
                    }
                    if ($hasKeyword) {
                        $keywordHits++;
                    }
                    foreach ($obfuscationMarkers as $marker) {
                        if (strpos($lower, $marker) !== false) {
                            $obfuscationHits++;
                            break;
                        }
                    }
                }
                // >=2 个不同值都含语义关键字，且至少 1 个含混淆标记
                if ($keywordHits >= 2 && $obfuscationHits >= 1) {
                    $hits++;
                }
            }
        }
        return $hits;
    }

    /**
     * 检测端点跳转横向移动模式（/login -> /admin -> /api）
     *
     * @param array $samples 参数样本
     * @return bool
     */
    private static function detectLateralMovement(array $samples): bool {
        if (count($samples) < 3) {
            return false;
        }
        // 抽取端点序列
        $seq = [];
        foreach ($samples as $s) {
            $seq[] = self::normalizeEndpoint($s['uri'] ?? '');
        }
        // 去重连续相同端点
        $deduped = [];
        $prev = '';
        foreach ($seq as $ep) {
            if ($ep !== $prev) {
                $deduped[] = $ep;
                $prev = $ep;
            }
        }
        if (count($deduped) < 3) {
            return false;
        }

        // 模式：登录类端点 -> 后台类端点 -> API 类端点
        $loginMarkers = ['/login', '/signin', '/auth', '/account/login'];
        $adminMarkers = ['/admin', '/wp-admin', '/phpmyadmin', '/dashboard', '/console', '/panel'];
        $apiMarkers = ['/api', '/api/v1', '/api/v2', '/api/admin', '/graphql'];

        $hasLogin = false;
        $hasAdmin = false;
        $hasApi = false;
        $loginIdx = -1;
        $adminIdx = -1;
        $apiIdx = -1;
        foreach ($deduped as $i => $ep) {
            $lower = strtolower($ep);
            if (!$hasLogin) {
                foreach ($loginMarkers as $m) {
                    if (strpos($lower, $m) !== false) {
                        $hasLogin = true;
                        $loginIdx = $i;
                        break;
                    }
                }
            }
            if (!$hasAdmin) {
                foreach ($adminMarkers as $m) {
                    if (strpos($lower, $m) !== false) {
                        $hasAdmin = true;
                        $adminIdx = $i;
                        break;
                    }
                }
            }
            if (!$hasApi) {
                foreach ($apiMarkers as $m) {
                    if (strpos($lower, $m) !== false) {
                        $hasApi = true;
                        $apiIdx = $i;
                        break;
                    }
                }
            }
        }

        // 顺序：login < admin < api
        return ($hasLogin && $hasAdmin && $hasApi
            && $loginIdx < $adminIdx && $adminIdx < $apiIdx);
    }

    /**
     * 基础统计（均值与标准差）
     *
     * @param array $values 数值数组
     * @return array{mean:float, stddev:float}
     */
    private static function basicStats(array $values): array {
        $n = count($values);
        if ($n === 0) {
            return ['mean' => 0.0, 'stddev' => 0.0];
        }
        $sum = array_sum($values);
        $mean = $sum / $n;
        $variance = 0.0;
        foreach ($values as $v) {
            $variance += ($v - $mean) * ($v - $mean);
        }
        $variance /= $n;
        return ['mean' => $mean, 'stddev' => sqrt($variance)];
    }

    /**
     * 构建上下文指标摘要
     *
     * @param array $csrf     CSRF 评估结果
     * @param array $replay   重放检测结果
     * @param array $session  会话异常结果
     * @param array $timing   时序异常结果
     * @param array $api      API 滥用结果
     * @param array $patterns 跨请求模式结果
     * @return array
     */
    private static function buildContextIndicators(
        array $csrf,
        array $replay,
        array $session,
        array $timing,
        array $api,
        array $patterns
    ): array {
        $indicators = [];

        if (!empty($csrf['is_csrf'])) {
            $indicators[] = 'csrf_suspected';
        }
        if (!empty($replay['is_replay'])) {
            $indicators[] = 'replay_detected';
        }
        if (!empty($session['is_anomaly'])) {
            $indicators[] = 'session_anomaly';
        }
        if (!empty($timing['is_anomaly'])) {
            $indicators[] = 'timing_' . ($timing['pattern'] ?? 'anomaly');
        }
        if (!empty($api['is_abuse'])) {
            $indicators[] = 'api_abuse';
        }
        if (!empty($patterns['pattern_count'])) {
            foreach ($patterns['patterns'] as $p) {
                if (isset($p['type'])) {
                    $indicators[] = 'pattern_' . $p['type'];
                }
            }
        }

        return [
            'indicators'  => $indicators,
            'indicator_count' => count($indicators),
            'csrf_risk_score'    => $csrf['risk_score']    ?? 0,
            'replay_risk_score'  => $replay['risk_score']  ?? 0,
            'session_risk_score' => $session['risk_score'] ?? 0,
            'timing_risk_score'  => $timing['risk_score']  ?? 0,
            'api_risk_score'     => $api['risk_score']     ?? 0,
            'pattern_risk_score' => $patterns['risk_score'] ?? 0,
            'timing_pattern'     => $timing['pattern']     ?? 'human',
            'unique_endpoints'   => $api['unique_endpoints'] ?? 0,
            'repeat_count'       => $replay['repeat_count'] ?? 0,
        ];
    }
}
