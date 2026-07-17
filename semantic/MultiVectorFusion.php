<?php
/**
 * 多向量语义融合引擎
 * 职责：将请求的多个向量（URL路径、Query参数、POST Body、Headers、Cookie、
 *       User-Agent、Referer）统一提取语义特征并融合分析。
 *       攻击者可能在不同向量中分散载荷，单一向量分析可能遗漏。
 */
defined('ABSPATH') || exit;

class MultiVectorFusion {
    /**
     * 多向量语义融合分析
     *
     * @param string $uri      完整URI（含query string）
     * @param array  $get      GET参数
     * @param array  $post     POST参数
     * @param array  $headers  HTTP Headers
     * @param string $ua       User-Agent
     * @param string $referer  Referer
     * @param string $cookie   Cookie字符串
     * @param string $rawBody  原始Body
     * @return array 各向量分析及融合结果
     */
    public static function analyze(
        string $uri = '',
        array $get = [],
        array $post = [],
        array $headers = [],
        string $ua = '',
        string $referer = '',
        string $cookie = '',
        string $rawBody = ''
    ): array {
        $vectors = [];
        $scores = [];

        // ---- Vector 1: URI路径 ----
        $pathOnly = parse_url($uri, PHP_URL_PATH) ?? $uri;
        $pathAnalysis = self::analyzePath($pathOnly);
        $vectors['path'] = $pathAnalysis;
        $scores['path'] = $pathAnalysis['score'];

        // ---- Vector 2: Query参数 ----
        $queryAnalysis = self::analyzeParams($get, 'query');
        $vectors['query'] = $queryAnalysis;
        $scores['query'] = $queryAnalysis['score'];

        // ---- Vector 3: POST参数 ----
        $postAnalysis = self::analyzeParams($post, 'post');
        $vectors['post'] = $postAnalysis;
        $scores['post'] = $postAnalysis['score'];

        // ---- Vector 4: Headers ----
        $headerAnalysis = self::analyzeHeaders($headers);
        $vectors['headers'] = $headerAnalysis;
        $scores['headers'] = $headerAnalysis['score'];

        // ---- Vector 5: User-Agent ----
        $uaAnalysis = self::analyzeUserAgent($ua);
        $vectors['user_agent'] = $uaAnalysis;
        $scores['user_agent'] = $uaAnalysis['score'];

        // ---- Vector 6: Referer ----
        $refererAnalysis = self::analyzeReferer($referer);
        $vectors['referer'] = $refererAnalysis;
        $scores['referer'] = $refererAnalysis['score'];

        // ---- Vector 7: Cookie ----
        $cookieAnalysis = self::analyzeCookie($cookie);
        $vectors['cookie'] = $cookieAnalysis;
        $scores['cookie'] = $cookieAnalysis['score'];

        // ---- Vector 8: Raw Body ----
        if ($rawBody !== '' && strlen($rawBody) < 10000) {
            $bodyAnalysis = self::analyzeRawBody($rawBody);
            $vectors['raw_body'] = $bodyAnalysis;
            $scores['raw_body'] = $bodyAnalysis['score'];
        }

        // ---- 融合分析 ----
        $fusionScore = self::fuseScores($scores);
        $crossVectorIndicators = self::detectCrossVectorAnomalies($vectors);

        return [
            'fusion_score'       => $fusionScore,
            'vector_scores'      => $scores,
            'vectors'            => $vectors,
            'max_single_score'   => !empty($scores) ? max($scores) : 0,
            'active_vectors'     => count(array_filter($scores, fn($s) => $s > 0)),
            'cross_indicators'   => $crossVectorIndicators,
            'primary_vector'     => !empty($scores) ? array_search(max($scores), $scores) : '',
        ];
    }

    /**
     * URI路径语义分析
     */
    private static function analyzePath(string $path): array {
        $score = 0;
        $indicators = [];

        // 路径遍历
        if (preg_match('/\.\.[\/\\\\]/', $path)) {
            $score += 30;
            $indicators[] = 'path_traversal';
        }
        // 敏感路径
        $sensitivePaths = ['admin', 'wp-admin', 'phpmyadmin', 'manage', 'config', '.env', '.git', '.svn'];
        foreach ($sensitivePaths as $sp) {
            if (stripos($path, $sp) !== false) {
                $score += 10;
                $indicators[] = 'sensitive_path:' . $sp;
            }
        }
        // 路径深度异常
        $depth = substr_count($path, '/');
        if ($depth > 8) {
            $score += 5;
            $indicators[] = 'deep_path:' . $depth;
        }
        // 过长路径
        if (strlen($path) > 200) {
            $score += 8;
            $indicators[] = 'long_path:' . strlen($path);
        }
        // 编码路径
        if (preg_match('/%[0-9a-fA-F]{2}/', $path)) {
            $encodedCount = preg_match_all('/%[0-9a-fA-F]{2}/', $path);
            if ($encodedCount > 5) {
                $score += 10;
                $indicators[] = 'encoded_path:' . $encodedCount;
            }
        }
        // 双扩展名
        if (preg_match('/\.\w+\.\w+\.php/i', $path)) {
            $score += 20;
            $indicators[] = 'double_extension';
        }
        // 空字节注入
        if (strpos($path, "\0") !== false) {
            $score += 25;
            $indicators[] = 'null_byte_injection';
        }

        return ['score' => min(100, $score), 'indicators' => $indicators];
    }

    /**
     * 参数语义分析
     */
    private static function analyzeParams(array $params, string $type): array {
        $score = 0;
        $indicators = [];
        $totalLen = 0;
        $dangerousKeys = [];

        foreach ($params as $k => $v) {
            $totalLen += strlen((string)$v);
            $lowerK = strtolower($k);

            // 危险参数名
            $dangerous = ['cmd', 'exec', 'command', 'shell', 'callback', 'function', 'eval', 'code', 'include', 'file', 'path', 'url', 'redirect', 'return', 'next', 'jump'];
            if (in_array($lowerK, $dangerous)) {
                $score += 15;
                $dangerousKeys[] = $k;
            }

            // 参数值异常
            $val = (string)$v;
            if (strlen($val) > 500) {
                $score += 5;
                $indicators[] = 'long_param:' . $k . ':' . strlen($val);
            }
            if (preg_match('#[<>\'";]#', $val)) {
                $score += 8;
                $indicators[] = 'special_chars:' . $k;
            }
        }

        if (!empty($dangerousKeys)) {
            $indicators[] = 'dangerous_keys:' . implode(',', $dangerousKeys);
        }

        // 参数数量异常
        if (count($params) > 30) {
            $score += 10;
            $indicators[] = 'too_many_params:' . count($params);
        }

        return ['score' => min(100, $score), 'indicators' => $indicators, 'param_count' => count($params), 'total_length' => $totalLen];
    }

    /**
     * Headers语义分析
     */
    private static function analyzeHeaders(array $headers): array {
        $score = 0;
        $indicators = [];

        $lowerHeaders = array_change_key_case($headers, CASE_LOWER);

        // X-Forwarded-For 伪造
        if (isset($lowerHeaders['x-forwarded-for']) || isset($lowerHeaders['x-real-ip'])) {
            $score += 5;
            $indicators[] = 'ip_spoofing_header';
        }
        // Content-Type 异常
        if (isset($lowerHeaders['content-type'])) {
            $ct = $lowerHeaders['content-type'];
            if (stripos($ct, 'xml') !== false && stripos($ct, 'external') !== false) {
                $score += 15;
                $indicators[] = 'xxe_content_type';
            }
        }
        // 缺失标准Header
        if (!isset($lowerHeaders['user-agent']) || empty($lowerHeaders['user-agent'])) {
            $score += 8;
            $indicators[] = 'missing_user_agent';
        }
        if (!isset($lowerHeaders['accept'])) {
            $score += 3;
            $indicators[] = 'missing_accept';
        }
        // 危险Header值
        foreach ($lowerHeaders as $hk => $hv) {
            if (preg_match('#[<>\'";]|javascript:|data:|file:#i', $hv)) {
                $score += 12;
                $indicators[] = 'dangerous_header_value:' . $hk;
            }
        }

        return ['score' => min(100, $score), 'indicators' => $indicators];
    }

    /**
     * User-Agent语义分析
     */
    private static function analyzeUserAgent(string $ua): array {
        $score = 0;
        $indicators = [];

        if ($ua === '') {
            $score += 20;
            $indicators[] = 'empty_ua';
            return ['score' => $score, 'indicators' => $indicators];
        }

        // 已知恶意UA
        $maliciousUAs = ['sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'gobuster', 'wpscan', 'burp', 'metasploit', 'sqlmap', 'arachni', 'skipfish'];
        foreach ($maliciousUAs as $mua) {
            if (stripos($ua, $mua) !== false) {
                $score += 40;
                $indicators[] = 'malicious_ua:' . $mua;
            }
        }
        // 自动化工具特征
        if (preg_match('/curl|wget|python-requests|libwww|httpclient|java\//i', $ua)) {
            $score += 15;
            $indicators[] = 'automation_ua';
        }
        // 伪造UA
        if (preg_match('/chrome|firefox|safari|edge/i', $ua) && preg_match('#[<>;"\']#i', $ua)) {
            $score += 20;
            $indicators[] = 'forged_ua_with_special';
        }
        // 超长UA
        if (strlen($ua) > 500) {
            $score += 10;
            $indicators[] = 'long_ua:' . strlen($ua);
        }

        return ['score' => min(100, $score), 'indicators' => $indicators];
    }

    /**
     * Referer语义分析
     */
    private static function analyzeReferer(string $referer): array {
        $score = 0;
        $indicators = [];

        if ($referer === '') {
            return ['score' => 0, 'indicators' => []];
        }

        // 包含攻击载荷
        if (preg_match('#[<>\'\";]|javascript:|data:|vbscript:#i', $referer)) {
            $score += 25;
            $indicators[] = 'referer_with_payload';
        }
        // SSRF特征
        if (preg_match('/(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::\]|file:\/\/)/i', $referer)) {
            $score += 20;
            $indicators[] = 'referer_ssrf';
        }
        // 外部域注入
        if (preg_match('/http:\/\/[^\/]+\.(?:exe|php|jsp|asp|sh)/i', $referer)) {
            $score += 15;
            $indicators[] = 'referer_suspicious_ext';
        }

        return ['score' => min(100, $score), 'indicators' => $indicators];
    }

    /**
     * Cookie语义分析
     */
    private static function analyzeCookie(string $cookie): array {
        $score = 0;
        $indicators = [];

        if ($cookie === '') {
            return ['score' => 0, 'indicators' => []];
        }

        // Cookie注入
        if (preg_match('#[<>\'\";]|union\s+select|or\s+\d+\s*=\s*\d+#i', $cookie)) {
            $score += 25;
            $indicators[] = 'cookie_injection';
        }
        // 超长Cookie
        if (strlen($cookie) > 2000) {
            $score += 10;
            $indicators[] = 'long_cookie:' . strlen($cookie);
        }
        // Base64编码异常
        if (preg_match('/^[A-Za-z0-9+\/]{50,}={0,2}$/', $cookie)) {
            $decoded = @base64_decode($cookie, true);
            if ($decoded !== false && preg_match('#[<>\'\";]|php|eval|system#i', $decoded)) {
                $score += 20;
                $indicators[] = 'cookie_base64_malicious';
            }
        }
        // 序列化数据
        if (preg_match('/O:\d+:"\w+":\d+:/', $cookie)) {
            $score += 15;
            $indicators[] = 'cookie_serialized_object';
        }
        // JWT篡改检测
        // 注意：故意不验证签名，因为WAF检测的是攻击者篡改payload的尝试
        // 即使签名验证失败，攻击者尝试设置admin=true也是攻击行为
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $cookie)) {
            $parts = explode('.', $cookie);
            if (count($parts) === 3) {
                $payload = @json_decode(@base64_decode(strtr($parts[1], '-_', '+/')), true);
                if (is_array($payload)) {
                    if (isset($payload['admin']) && $payload['admin'] === true) {
                        $score += 20;
                        $indicators[] = 'jwt_admin_claim';
                    }
                    if (isset($payload['role']) && in_array(strtolower($payload['role']), ['admin', 'root', 'superuser'])) {
                        $score += 20;
                        $indicators[] = 'jwt_role_claim';
                    }
                }
            }
        }

        return ['score' => min(100, $score), 'indicators' => $indicators];
    }

    /**
     * Raw Body语义分析
     */
    private static function analyzeRawBody(string $body): array {
        $score = 0;
        $indicators = [];

        // XML实体注入
        if (preg_match('/<!ENTITY\s+\w+\s+SYSTEM\s+["\']/i', $body)) {
            $score += 30;
            $indicators[] = 'xxe_in_body';
        }
        // JSON注入
        if (preg_match('/\{\s*["\']\w+["\']\s*:\s*["\'][^"\']*["\'][^}]*\}/', $body)) {
            if (preg_match('#[<>\'\";]|union|select|or\s+\d+\s*=\s*\d+#i', $body)) {
                $score += 20;
                $indicators[] = 'json_injection';
            }
        }
        // 文件上传内容
        if (preg_match('/Content-Disposition:\s*form-data/i', $body)) {
            if (preg_match('/filename\s*=\s*["\'][^"\']*\.(?:php|phtml|php5|pht|phar)/i', $body)) {
                $score += 25;
                $indicators[] = 'upload_php_in_body';
            }
        }

        return ['score' => min(100, $score), 'indicators' => $indicators];
    }

    /**
     * 融合各向量分数
     */
    private static function fuseScores(array $scores): int {
        if (empty($scores)) return 0;

        $maxScore = max($scores);
        $highCount = count(array_filter($scores, fn($s) => $s >= 30));
        $mediumCount = count(array_filter($scores, fn($s) => $s >= 15 && $s < 30));

        $fusion = $maxScore;

        // 多向量同时中高风险 => 协同攻击
        if ($highCount >= 2) {
            $fusion += 15;
        } elseif ($highCount >= 1 && $mediumCount >= 1) {
            $fusion += 8;
        }

        // 活跃向量越多风险越高
        $activeCount = count(array_filter($scores, fn($s) => $s > 0));
        if ($activeCount >= 5) {
            $fusion += 10;
        }

        return min(100, $fusion);
    }

    /**
     * 检测跨向量异常（载荷分散在多个向量中）
     */
    private static function detectCrossVectorAnomalies(array $vectors): array {
        $indicators = [];

        // 路径有遍历 + Query有注入 = 组合攻击
        if (in_array('path_traversal', $vectors['path']['indicators'] ?? []) &&
            (in_array('special_chars:query', $vectors['query']['indicators'] ?? []) ||
             in_array('special_chars:post', $vectors['post']['indicators'] ?? []))) {
            $indicators[] = 'path_traversal_plus_injection';
        }

        // UA是自动化工具 + 参数有危险键 = 自动化攻击
        if (($vectors['user_agent']['score'] ?? 0) >= 15 && !empty($vectors['query']['indicators'] ?? [])) {
            $indicators[] = 'automated_attack';
        }

        // Cookie有注入 + 参数正常 = Cookie注入绕过
        if (($vectors['cookie']['score'] ?? 0) >= 20 && ($vectors['query']['score'] ?? 0) < 20 && ($vectors['post']['score'] ?? 0) < 20) {
            $indicators[] = 'cookie_injection_bypass';
        }

        // Header有IP伪造 + 参数有SSRF = 多层SSRF
        if (in_array('ip_spoofing_header', $vectors['headers']['indicators'] ?? []) &&
            in_array('referer_ssrf', $vectors['referer']['indicators'] ?? [])) {
            $indicators[] = 'multi_vector_ssrf';
        }

        // JWT篡改 + 参数有权限相关 = 权限提升组合
        if (in_array('jwt_admin_claim', $vectors['cookie']['indicators'] ?? []) ||
            in_array('jwt_role_claim', $vectors['cookie']['indicators'] ?? [])) {
            if (($vectors['query']['score'] ?? 0) > 10 || ($vectors['post']['score'] ?? 0) > 10) {
                $indicators[] = 'jwt_plus_param_attack';
            }
        }

        return $indicators;
    }
}
