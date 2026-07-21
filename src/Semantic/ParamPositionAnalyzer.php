<?php
/**
 * L4 参数位置上下文分析器
 *
 * 职责：识别 HTTP 请求参数所在位置（Query/POST/Cookie/Header/JSON），
 *   并根据位置上下文调整威胁评分。同一 payload 在不同位置威胁等级完全不同：
 *   - id 参数在 URL Query 是 IDOR 风险
 *   - id 参数在 HTTP Header 是注入风险
 *   - id 参数在 Cookie 是会话篡改风险
 *   - redirect 参数在 Query 是开放重定向
 *   - redirect 参数在 JSON Body 是 SSRF
 *
 * 核心能力：
 *   A. 参数位置分类（query/post/cookie/header/json 5 类）
 *   B. 位置威胁权重（query=1.0 / post=1.1 / cookie=1.3 / header=1.4 / json=1.2）
 *   C. 参数名-位置关联规则（13 个常见参数 × 位置 → 威胁类型）
 *   D. 跨位置模式检测（同名参数多处出现、跨位置值不一致）
 *   E. 位置异常检测（Cookie 含查询串、Header 注入特征、JSON 深度嵌套、参数数量异常）
 *   F. 高风险参数识别（规则匹配、超长值、特殊字符）
 *   G. 综合评分计算（基础分 + 异常分 + 高风险分 + 跨位置分，上限 100）
 *
 * 公共 API：
 *   analyze($queryParams, $postParams, $cookieParams, $headers, $jsonBody, $uri): array
 */
defined('ABSPATH') || exit;

class ParamPositionAnalyzer {

    /**
     * 位置威胁权重（基于历史攻击统计）
     * @var array<string,float>
     */
    private static $positionWeights = [
        'query'  => 1.0,  // 基准，最常见的注入入口
        'post'   => 1.1,  // POST 更易携带大 payload
        'cookie' => 1.3,  // Cookie 注入常被忽视，但危害大
        'header' => 1.4,  // Header 注入如 UA/Referer/XFF
        'json'   => 1.2,  // REST API 时代常见，且易被 WAF 忽略
    ];

    /**
     * 参数名-位置关联规则：参数名 → 位置 → [威胁类型/权重/描述]
     * @var array<string,array<string,array>>
     */
    private static $paramPositionRules = [
        'id' => [
            'query'  => ['threat' => 'idor', 'weight' => 1.2, 'desc' => 'URL ID 参数 - IDOR 风险'],
            'cookie' => ['threat' => 'session_manipulation', 'weight' => 1.5, 'desc' => 'Cookie ID - 会话篡改'],
            'header' => ['threat' => 'injection', 'weight' => 1.3, 'desc' => 'Header ID - 注入风险'],
        ],
        'redirect' => [
            'query' => ['threat' => 'open_redirect', 'weight' => 1.4, 'desc' => 'URL 重定向参数'],
            'post'  => ['threat' => 'open_redirect', 'weight' => 1.3, 'desc' => 'POST 重定向参数'],
        ],
        'url' => [
            'query' => ['threat' => 'ssrf', 'weight' => 1.5, 'desc' => 'URL 参数 - SSRF 风险'],
            'json'  => ['threat' => 'ssrf', 'weight' => 1.4, 'desc' => 'JSON URL - SSRF'],
        ],
        'file' => [
            'query' => ['threat' => 'path_traversal', 'weight' => 1.4, 'desc' => 'URL file 参数 - 路径遍历'],
            'post'  => ['threat' => 'file_upload', 'weight' => 1.5, 'desc' => 'POST file - 文件上传'],
        ],
        'cmd' => [
            'query' => ['threat' => 'command_injection', 'weight' => 1.5, 'desc' => 'cmd 参数 - 命令注入'],
            'post'  => ['threat' => 'command_injection', 'weight' => 1.4, 'desc' => 'POST cmd - 命令注入'],
        ],
        'template' => [
            'query' => ['threat' => 'ssti', 'weight' => 1.5, 'desc' => 'template 参数 - SSTI'],
            'json'  => ['threat' => 'ssti', 'weight' => 1.4, 'desc' => 'JSON template - SSTI'],
        ],
        'user-agent' => [
            'header' => ['threat' => 'xss_header_injection', 'weight' => 1.3, 'desc' => 'UA - 头部 XSS'],
        ],
        'referer' => [
            'header' => ['threat' => 'xss_header_injection', 'weight' => 1.3, 'desc' => 'Referer - 头部 XSS'],
        ],
        'x-forwarded-for' => [
            'header' => ['threat' => 'ip_spoofing', 'weight' => 1.4, 'desc' => 'XFF - IP 伪造'],
        ],
        'token' => [
            'cookie' => ['threat' => 'session_hijacking', 'weight' => 1.5, 'desc' => 'Cookie token - 会话劫持'],
            'header' => ['threat' => 'auth_bypass', 'weight' => 1.4, 'desc' => 'Header token - 认证绕过'],
        ],
        'session' => [
            'cookie' => ['threat' => 'session_fixation', 'weight' => 1.5, 'desc' => 'Cookie session - 会话固定'],
        ],
        'q' => [
            'query' => ['threat' => 'sqli_xss', 'weight' => 1.2, 'desc' => '搜索参数 - SQLi/XSS'],
        ],
        'search' => [
            'query' => ['threat' => 'sqli_xss', 'weight' => 1.2, 'desc' => '搜索参数 - SQLi/XSS'],
        ],
    ];

    /**
     * 常规请求头白名单（这些头不视为业务参数）
     * @var array<int,string>
     */
    private static $commonHeaders = [
        'host', 'accept', 'accept-encoding', 'accept-language', 'connection',
        'content-length', 'content-type', 'cache-control', 'pragma',
        'upgrade-insecure-requests', 'dnt', 'origin', 'range',
        'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'sec-fetch-dest',
        'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    ];

    /** SQL 注入特征正则 */
    private static $sqlPattern = '#(union\\s+select|or\\s+1=1|and\\s+1=1|\\bunion\\b|\\bselect\\b|information_schema|load_file|sleep\\s*\\(|benchmark\\s*\\(|extractvalue|updatexml|xp_cmdshell)#i';

    /** XSS 特征正则 */
    private static $xssPattern = '#(<script|onerror=|onload=|javascript:|<img|<svg|alert\\s*\\(|document\\.cookie|<iframe|<body|<object|<embed)#i';

    /* ======================================================================
     * 公共 API：参数位置上下文分析主入口
     * ====================================================================== */

    /**
     * 参数位置上下文分析
     * @param array  $queryParams  URL 查询参数（$_GET）
     * @param array  $postParams   表单 POST 参数（$_POST）
     * @param array  $cookieParams Cookie 参数（$_COOKIE）
     * @param array  $headers      HTTP 请求头（自定义头，自动排除常规头）
     * @param array  $jsonBody     JSON Body 参数（解析后的 JSON 数组）
     * @param string $uri          请求 URI
     * @return array{
     *     score:int,
     *     positions:array,
     *     position_anomalies:array,
     *     cross_position_patterns:array,
     *     high_risk_params:array,
     *     position_weights:array
     * }
     */
    public static function analyze(
        array $queryParams = [],
        array $postParams = [],
        array $cookieParams = [],
        array $headers = [],
        array $jsonBody = [],
        string $uri = ''
    ): array {
        // A. 参数位置分类（5 类）
        $positions = [
            'query'  => self::normalizePosition($queryParams),
            'post'   => self::normalizePosition($postParams),
            'cookie' => self::normalizePosition($cookieParams),
            'header' => self::filterCustomHeaders($headers),
            'json'   => self::flattenJsonBody($jsonBody),
        ];

        // D. 跨位置模式检测
        $crossPatterns = self::detectCrossPositionPatterns($positions);

        // E. 位置异常检测
        $anomalyResult = self::detectPositionAnomalies($positions, $uri);

        // F. 高风险参数识别
        $highRisk = self::identifyHighRiskParams($positions);

        // 将跨位置异常计数并入 $anomalies 参数供评分使用
        $anomalyResult['cross_anomaly_count'] = $crossPatterns['anomaly_count'];

        // G. 综合评分
        $score = self::calcPositionScore($positions, $anomalyResult, $highRisk);

        return [
            'score'                   => $score,
            'positions'               => self::buildPositionsSummary($positions),
            'position_anomalies'      => $anomalyResult['anomalies'],
            'cross_position_patterns' => $crossPatterns['patterns'],
            'high_risk_params'        => $highRisk,
            'position_weights'        => self::$positionWeights,
        ];
    }

    /* ======================================================================
     * A. 位置归一化 / 过滤
     * ====================================================================== */

    /**
     * 将参数键值归一化为 [name => value] 字符串映射
     * @param array $params 原始参数集
     * @return array<string,string>
     */
    private static function normalizePosition(array $params): array {
        $out = [];
        foreach ($params as $k => $v) {
            if (is_int($k)) continue;
            $key = (string) $k;
            if ($key === '') continue;
            $out[$key] = is_array($v) ? self::recursiveJoin($v) : (string) $v;
        }
        return $out;
    }

    /**
     * 递归拼接数组值为字符串（用于嵌套参数）
     * @param array $arr 多维数组
     * @return string
     */
    private static function recursiveJoin(array $arr): string {
        $parts = [];
        foreach ($arr as $k => $v) {
            if (is_array($v)) {
                $parts[] = $k . '=' . self::recursiveJoin($v);
            } else {
                $parts[] = $k . '=' . (string) $v;
            }
        }
        return implode('&', $parts);
    }

    /**
     * 过滤常规请求头，仅保留自定义头作为分析参数
     * 同时处理 $_SERVER 中 HTTP_ 前缀格式（HTTP_USER_AGENT → user-agent）
     * @param array $headers 原始请求头
     * @return array<string,string>
     */
    private static function filterCustomHeaders(array $headers): array {
        $out = [];
        foreach ($headers as $k => $v) {
            $key = is_int($k) ? (string) $k : (string) $k;
            if ($key === '') continue;
            $lk = strtolower($key);
            // 处理 $_SERVER 中的 HTTP_ 前缀
            if (strpos($lk, 'http_') === 0) {
                $lk = substr($lk, 5);
            }
            // 下划线 → 横杠（user_agent → user-agent）
            $cleanKey = str_replace('_', '-', $lk);
            if ($cleanKey === '') continue;
            // 排除常规头
            if (in_array($cleanKey, self::$commonHeaders, true)) continue;
            $out[$cleanKey] = is_array($v) ? self::recursiveJoin($v) : (string) $v;
        }
        return $out;
    }

    /**
     * 拍平 JSON Body 为 [name => value] 映射
     * 嵌套对象使用点路径表示（a.b.c）
     * @param array  $json    解码后的 JSON 数组
     * @param string $prefix  当前路径前缀
     * @return array<string,string>
     */
    private static function flattenJsonBody(array $json, string $prefix = ''): array {
        $out = [];
        foreach ($json as $k => $v) {
            $key = $prefix === '' ? (string) $k : $prefix . '.' . (string) $k;
            if (is_array($v)) {
                if (self::isAssocArray($v)) {
                    // 关联数组 → 递归拍平
                    $nested = self::flattenJsonBody($v, $key);
                    foreach ($nested as $nk => $nv) {
                        $out[$nk] = $nv;
                    }
                    // 同时保留整体值（便于行为分析）
                    $out[$key] = self::recursiveJoin($v);
                } else {
                    // 索引数组 → 拼接
                    $out[$key] = self::recursiveJoin($v);
                }
            } else {
                $out[$key] = (string) $v;
            }
        }
        return $out;
    }

    /**
     * 判断数组是否为关联数组（键非 0..n-1 序列）
     * @param array $arr 待判定数组
     * @return bool
     */
    private static function isAssocArray(array $arr): bool {
        if (empty($arr)) return false;
        return array_keys($arr) !== range(0, count($arr) - 1);
    }

    /**
     * 构建 positions 摘要（每位置参数数/风险分/参数列表）
     * @param array $positions 五个位置的参数集
     * @return array<string,array{param_count:int,risk_score:int,params:array}>
     */
    private static function buildPositionsSummary(array $positions): array {
        $summary = [];
        foreach (['query', 'post', 'cookie', 'header', 'json'] as $pos) {
            $params = $positions[$pos] ?? [];
            $risk = 0;
            foreach ($params as $name => $value) {
                $rule = self::lookupParamRule($name, $pos);
                if ($rule !== null) {
                    $risk += (int) round($rule['weight'] * 10);
                } else {
                    $risk += 5;
                }
            }
            $summary[$pos] = [
                'param_count' => count($params),
                'risk_score'  => $risk,
                'params'      => $params,
            ];
        }
        return $summary;
    }

    /**
     * 查询参数名在某位置的规则
     * 支持精确匹配 + 后缀 token 匹配（user_id → id）
     * @param string $name     参数名
     * @param string $position 位置
     * @return array|null 命中规则或 null
     */
    private static function lookupParamRule(string $name, string $position): ?array {
        if ($name === '') return null;
        $lk = strtolower($name);
        // 精确匹配
        if (isset(self::$paramPositionRules[$lk][$position])) {
            return self::$paramPositionRules[$lk][$position];
        }
        // token 后缀匹配（后 token 优先）
        $tokens = self::tokenize($lk);
        for ($i = count($tokens) - 1; $i >= 0; $i--) {
            $tok = $tokens[$i];
            if (isset(self::$paramPositionRules[$tok][$position])) {
                return self::$paramPositionRules[$tok][$position];
            }
        }
        return null;
    }

    /**
     * 简单 token 化：下划线/横杠/点分隔 + 驼峰边界切分
     * @param string $key 参数名
     * @return array<int,string>
     */
    private static function tokenize(string $key): array {
        if ($key === '') return [];
        $tokens = [];
        $current = '';
        $len = strlen($key);
        $prevUpper = false;
        for ($i = 0; $i < $len; $i++) {
            $ch = $key[$i];
            $o = ord($ch);
            $isUpper = ($o >= 0x41 && $o <= 0x5A);
            if ($ch === '_' || $ch === '-' || $ch === '.') {
                if ($current !== '') {
                    $tokens[] = strtolower($current);
                    $current = '';
                }
                $prevUpper = false;
                continue;
            }
            // 驼峰边界：lower→Upper 转换处切分
            if ($isUpper && !$prevUpper && $current !== '') {
                $tokens[] = strtolower($current);
                $current = $ch;
            } else {
                $current .= $ch;
            }
            $prevUpper = $isUpper;
        }
        if ($current !== '') $tokens[] = strtolower($current);
        return $tokens;
    }

    /* ======================================================================
     * D. 跨位置模式检测
     * ====================================================================== */

    /**
     * 跨位置模式检测
     *  - 同一参数名在多处出现（如 id 同时在 query 和 cookie）→ 异常 +10
     *  - 跨位置参数值不一致（如 user_id 在 query=1 但 cookie=2）→ 异常 +15
     * @param array $allPositions 五个位置的参数集合
     * @return array{patterns:array<int,array>,anomaly_count:int,score:int}
     */
    private static function detectCrossPositionPatterns(array $allPositions): array {
        $patterns = [];
        $anomalyCount = 0;
        $score = 0;

        // 1. 收集参数名 → 位置 → 值
        $nameMap = [];
        foreach ($allPositions as $pos => $params) {
            foreach ($params as $name => $value) {
                if (!isset($nameMap[$name])) {
                    $nameMap[$name] = [];
                }
                $nameMap[$name][$pos] = $value;
            }
        }

        // 2. 同一参数名在多处出现
        foreach ($nameMap as $name => $occurrences) {
            if (count($occurrences) < 2) continue;
            $positionsList = array_keys($occurrences);
            sort($positionsList);
            $anomalyCount++;
            $score += 10;
            $patterns[] = [
                'type'      => 'cross_position_duplicate',
                'name'      => $name,
                'positions' => $positionsList,
                'values'    => $occurrences,
                'severity'  => 'mid',
                'score'     => 10,
                'desc'      => sprintf('参数 "%s" 同时出现在 %d 个位置：%s', $name, count($occurrences), implode('/', $positionsList)),
            ];

            // 3. 跨位置值不一致
            $values = array_values($occurrences);
            $uniqueValues = array_unique($values);
            if (count($uniqueValues) > 1) {
                $anomalyCount++;
                $score += 15;
                $patterns[] = [
                    'type'      => 'cross_position_value_inconsistency',
                    'name'      => $name,
                    'positions' => $positionsList,
                    'values'    => $occurrences,
                    'severity'  => 'high',
                    'score'     => 15,
                    'desc'      => sprintf('参数 "%s" 在不同位置值不一致', $name),
                ];
            }
        }

        return [
            'patterns'      => $patterns,
            'anomaly_count' => $anomalyCount,
            'score'         => $score,
        ];
    }

    /* ======================================================================
     * E. 位置异常检测
     * ====================================================================== */

    /**
     * 位置异常检测
     *  - Cookie 中出现查询参数（如 ?id=1）→ 异常
     *  - Header 中出现 SQL/XSS 特征 → 异常
     *  - JSON Body 深度嵌套（depth > 5）→ 异常 +10
     *  - 单位置参数数量异常（> 20 个）→ 异常 +10
     * @param array  $positions 五个位置参数集
     * @param string $uri       请求 URI（保留参数兼容未来扩展）
     * @return array{anomalies:array<int,array>,total_anomaly_score:int}
     */
    private static function detectPositionAnomalies(array $positions, string $uri): array {
        $anomalies = [];
        $total = 0;

        // 1. Cookie 中出现查询参数（如 ?id=1）
        if (!empty($positions['cookie'])) {
            foreach ($positions['cookie'] as $name => $value) {
                if (strpos($value, '?') !== false && preg_match('#\?[a-zA-Z0-9_\-]+=#', $value)) {
                    $anomalies[] = [
                        'type'     => 'cookie_contains_query_string',
                        'name'     => $name,
                        'value'    => self::preview($value),
                        'score'    => 10,
                        'severity' => 'mid',
                        'desc'     => 'Cookie 参数中包含查询字符串',
                    ];
                    $total += 10;
                }
            }
        }

        // 2. Header 中出现 SQL/XSS 特征
        if (!empty($positions['header'])) {
            foreach ($positions['header'] as $name => $value) {
                $hit = false;
                if (preg_match(self::$sqlPattern, $value)) {
                    $anomalies[] = [
                        'type'     => 'header_sql_signature',
                        'name'     => $name,
                        'value'    => self::preview($value),
                        'score'    => 12,
                        'severity' => 'high',
                        'desc'     => 'Header 参数含 SQL 注入特征',
                    ];
                    $total += 12;
                    $hit = true;
                }
                if (preg_match(self::$xssPattern, $value)) {
                    $anomalies[] = [
                        'type'     => 'header_xss_signature',
                        'name'     => $name,
                        'value'    => self::preview($value),
                        'score'    => 12,
                        'severity' => 'high',
                        'desc'     => 'Header 参数含 XSS 特征',
                    ];
                    $total += 12;
                    $hit = true;
                }
                if (!$hit && strlen($value) > 16 && preg_match('#[<>\'"]#', $value)) {
                    $anomalies[] = [
                        'type'     => 'header_special_chars',
                        'name'     => $name,
                        'value'    => self::preview($value),
                        'score'    => 6,
                        'severity' => 'low',
                        'desc'     => 'Header 参数含特殊字符',
                    ];
                    $total += 6;
                }
            }
        }

        // 3. JSON Body 深度嵌套（depth > 5）
        if (!empty($positions['json'])) {
            $maxDepth = 0;
            foreach ($positions['json'] as $name => $value) {
                $depth = substr_count($name, '.');
                if ($depth > $maxDepth) {
                    $maxDepth = $depth;
                }
            }
            if ($maxDepth > 5) {
                $anomalies[] = [
                    'type'     => 'json_deeply_nested',
                    'depth'    => $maxDepth + 1,
                    'score'    => 10,
                    'severity' => 'mid',
                    'desc'     => 'JSON Body 深度嵌套（深度 > 5）',
                ];
                $total += 10;
            }
        }

        // 4. 单位置参数数量异常（> 20 个）
        foreach ($positions as $pos => $params) {
            $cnt = count($params);
            if ($cnt > 20) {
                $anomalies[] = [
                    'type'     => 'position_param_count_anomaly',
                    'position' => $pos,
                    'count'    => $cnt,
                    'score'    => 10,
                    'severity' => 'mid',
                    'desc'     => sprintf('位置 "%s" 参数数量异常（%d 个）', $pos, $cnt),
                ];
                $total += 10;
            }
        }

        return [
            'anomalies'           => $anomalies,
            'total_anomaly_score' => $total,
        ];
    }

    /* ======================================================================
     * F. 高风险参数识别
     * ====================================================================== */

    /**
     * 高风险参数识别
     *  - 匹配 $paramPositionRules 中规则的参数
     *  - 超长参数值（length > 200）→ 高风险
     *  - 含特殊字符的参数（<>"' 在 Cookie/Header）→ 高风险
     * @param array $positions 五个位置参数集
     * @return array<int,array{name:string,position:string,value_preview:string,threat:string,risk_score:int,desc:string}>
     */
    private static function identifyHighRiskParams(array $positions): array {
        $highRisk = [];
        $seen = [];

        foreach ($positions as $pos => $params) {
            foreach ($params as $name => $value) {
                $valueLen = strlen($value);

                // 1. 匹配位置规则
                $rule = self::lookupParamRule($name, $pos);
                if ($rule !== null) {
                    $key = $name . '|' . $pos . '|rule';
                    if (!isset($seen[$key])) {
                        $seen[$key] = true;
                        $riskScore = (int) round(($rule['weight'] ?? 1.0) * 20);
                        $highRisk[] = [
                            'name'          => $name,
                            'position'      => $pos,
                            'value_preview' => self::preview($value),
                            'threat'        => $rule['threat'],
                            'risk_score'    => $riskScore,
                            'desc'          => $rule['desc'],
                        ];
                    }
                }

                // 2. 超长参数值
                if ($valueLen > 200) {
                    $key = $name . '|' . $pos . '|long';
                    if (!isset($seen[$key])) {
                        $seen[$key] = true;
                        $highRisk[] = [
                            'name'          => $name,
                            'position'      => $pos,
                            'value_preview' => self::preview($value),
                            'threat'        => 'oversized_value',
                            'risk_score'    => 15,
                            'desc'          => sprintf('参数值超长（%d 字节）', $valueLen),
                        ];
                    }
                }

                // 3. Cookie/Header 含 <>"' 特殊字符
                if (($pos === 'cookie' || $pos === 'header') && preg_match('#[<>"\']#', $value)) {
                    $key = $name . '|' . $pos . '|special';
                    if (!isset($seen[$key])) {
                        $seen[$key] = true;
                        $highRisk[] = [
                            'name'          => $name,
                            'position'      => $pos,
                            'value_preview' => self::preview($value),
                            'threat'        => 'special_chars_in_' . $pos,
                            'risk_score'    => 12,
                            'desc'          => $pos . ' 参数含 <>"\' 特殊字符',
                        ];
                    }
                }
            }
        }

        return $highRisk;
    }

    /* ======================================================================
     * G. 评分计算
     * ====================================================================== */

    /**
     * 计算位置加权威胁评分
     *  - 基础分：每位置参数数 × 位置权重（上限 30）
     *  - 异常分：位置异常总分（上限 30）
     *  - 高风险参数分：每个高风险参数 +5（上限 40）
     *  - 跨位置模式分：每个跨位置异常 +10（上限 20）
     *  - 总分上限 100
     * @param array $positions 五个位置参数集
     * @param array $anomalies 位置异常结果（含 total_anomaly_score 和 cross_anomaly_count）
     * @param array $highRisk  高风险参数列表
     * @return int 0-100
     */
    private static function calcPositionScore(array $positions, array $anomalies, array $highRisk): int {
        // 1. 基础分：每位置参数数 × 位置权重（上限 30）
        $baseScore = 0.0;
        foreach ($positions as $pos => $params) {
            $weight = self::$positionWeights[$pos] ?? 1.0;
            $baseScore += count($params) * $weight;
        }
        $baseScore = min(30, (int) round($baseScore));

        // 2. 异常分：位置异常总分（上限 30）
        $anomalyScore = min(30, (int) ($anomalies['total_anomaly_score'] ?? 0));

        // 3. 高风险参数分：每个 +5（上限 40）
        $highRiskScore = min(40, count($highRisk) * 5);

        // 4. 跨位置模式分：每个异常 +10（上限 20）
        $crossCount = (int) ($anomalies['cross_anomaly_count'] ?? 0);
        $crossScore = min(20, $crossCount * 10);

        $total = $baseScore + $anomalyScore + $highRiskScore + $crossScore;
        return max(0, min(100, (int) round($total)));
    }

    /* ======================================================================
     * 工具方法
     * ====================================================================== */

    /**
     * 截取参数值预览（保留前 60 字符，超出以 ...(长度) 表示）
     * @param string $value 原始值
     * @return string
     */
    private static function preview(string $value): string {
        $max = 60;
        $len = strlen($value);
        if ($len <= $max) return $value;
        return substr($value, 0, $max) . '...(' . $len . ')';
    }
}
