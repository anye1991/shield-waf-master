<?php
/**
 * 业务逻辑异常检测引擎 (L5)
 *
 * 职责：从"业务语义"层面推理请求是否符合业务逻辑预期，
 *       而非 URI 正则 / 关键词匹配。
 *
 * 七大业务语义能力：
 *   A. 端点语义解析 —— 状态机解析 URI，识别资源类型 / 动作意图 / 资源 ID / API 版本
 *   B. 业务流程状态推理 —— 认证前 / 认证后 / 高权限 / 资源访问 / 静态
 *   C. 参数-端点一致性推理 —— 端点期望参数集 vs 实际参数集
 *   D. 资源访问越权推理 —— ID 格式异常 / 敏感 ID / 路径遍历 / admin 端点
 *   E. 业务上下文异常检测 —— 重定向 / 文件 / 代码 payload 误置
 *   F. API 版本与格式语义 —— 版本异常 / 路径深度 / 控制字符 / 多版本段
 *   G. 业务逻辑攻击模式 —— WebShell 上传 / 伪协议重定向 / 敏感文件目标 / 批量操作
 *
 * 评分规范：每维贡献分值，多维交叉加成，总分上限 100，正常请求得 0 分。
 *
 * 返回：score(int) / scene(string) / valid(bool) / violations(array)
 *       / endpoint(array) / flow_state(string)
 */
defined('ABSPATH') || exit;

class BusinessSemantics {
    /* ===== 业务上下文知识库 ===== */

    /** 资源类型词典：URI 段小写 => 资源类型 */
    private static $resource_types = [
        'users'=>'user','user'=>'user','profile'=>'user','account'=>'user','accounts'=>'user','member'=>'user',
        'members'=>'user','u'=>'user','orders'=>'order','order'=>'order','invoice'=>'order','invoices'=>'order',
        'products'=>'product','product'=>'product','goods'=>'product','items'=>'product','files'=>'file','file'=>'file',
        'upload'=>'file','uploads'=>'file','attachments'=>'file','attachment'=>'file','documents'=>'file','docs'=>'file',
        'articles'=>'article','article'=>'article','posts'=>'article','post'=>'article','comments'=>'article','comment'=>'article',
        'auth'=>'auth','login'=>'auth','signin'=>'auth','logout'=>'auth','register'=>'auth','signup'=>'auth',
        'token'=>'auth','session'=>'auth','reset'=>'auth','forgot'=>'auth','recover'=>'auth','admin'=>'admin',
        'manage'=>'admin','management'=>'admin','dashboard'=>'admin','settings'=>'admin','config'=>'admin','system'=>'admin',
        'search'=>'search','query'=>'search','find'=>'search','cart'=>'payment','checkout'=>'payment','pay'=>'payment','payment'=>'payment',
    ];

    /** 动作意图词典：URI 段小写 => 动作 */
    private static $action_intents = [
        'list'=>'list','search'=>'search','find'=>'search','get'=>'read','view'=>'read','show'=>'read','read'=>'read',
        'detail'=>'read','create'=>'create','new'=>'create','add'=>'create','store'=>'create','update'=>'update','edit'=>'update',
        'modify'=>'update','patch'=>'update','delete'=>'delete','remove'=>'delete','destroy'=>'delete','drop'=>'delete',
        'admin'=>'admin','manage'=>'admin','login'=>'login','logout'=>'logout','signin'=>'login','register'=>'register',
        'signup'=>'register','upload'=>'upload','import'=>'upload','export'=>'export','download'=>'read',
    ];

    /** 端点类型 => [期望参数名, 禁止参数名] */
    private static $param_specs = [
        'login' => [
            'expect' => ['username','user','email','account','password','passwd','pwd','captcha','code','token','remember','otp','mfa','returnurl','return_url','redirect','redirect_url','next','back'],
            'reject' => ['file','upload','attachment','image','cmd','exec','command','shell','path','system','query','sql'],
        ],
        'register' => [
            'expect' => ['username','user','email','password','passwd','pwd','confirm','code','invite','captcha','nickname'],
            'reject' => ['file','upload','cmd','exec','shell','role','is_admin','admin','privilege','grant'],
        ],
        'password_reset' => [
            'expect' => ['email','token','password','new_password','code','otp'],
            'reject' => ['file','upload','cmd','exec','shell','id','role','is_admin'],
        ],
        'search' => [
            'expect' => ['q','query','keyword','keywords','kw','search','term','page','sort','order','filter','type','category','limit'],
            'reject' => ['file','upload','cmd','exec','shell','returnurl','redirect','next','url'],
        ],
        'upload' => [
            'expect' => ['file','upload','attachment','image','avatar','name','type','size','mime','chunk','folder'],
            'reject' => ['cmd','exec','shell','command','system','query','sql'],
        ],
        'admin' => [
            'expect' => ['id','action','page','sort','filter','status','type','limit','offset','q'],
            'reject' => ['file','upload','cmd','exec','shell','password','passwd','token','secret'],
        ],
        'payment' => [
            'expect' => ['amount','currency','order','order_id','card','cvv','exp','token','method','product_id'],
            'reject' => ['file','upload','cmd','exec','shell'],
        ],
    ];

    /** 敏感资源 ID（越权高价值目标） */
    private static $sensitive_ids = ['admin','root','administrator','0','super','system','sa','master'];

    /** 可执行文件后缀（上传威胁） */
    private static $exec_extensions = ['php','phtml','php5','pht','phar','phps','asp','aspx','jsp','jspx','exe','sh','cgi','pl','py','rb','war','bat','cmd','vbs'];

    /** 危险伪协议（重定向 / 文件包含攻击） */
    private static $pseudo_protocols = ['javascript:','vbscript:','data:','file:','expect:','php:','phar:','gopher:','dict:','jar:'];

    /** WebShell 文件名特征模式 */
    public const WEBSHELL_NAME_PATTERN = '/\b(shell|c99|r57|b374k|wso|eval|backdoor|webshell|cmdshell|hacktool|injector)\b/i';

    /** 敏感系统文件路径模式（路径遍历目标） */
    public const SENSITIVE_FILE_PATTERN = '#/(etc/(passwd|shadow|hosts)|proc/self|var/log|root/\.ssh|windows/system32|boot\.ini|win\.ini|\.env)#i';

    /** SQL 注入特征（用于 ID 参数检测） */
    public const SQL_INJECTION_PATTERN = "/'\\s*(or|and|union)\\b|\\bunion\\s+select\\b|\\bor\\s+1\\s*=\\s*1|\\bunion\\s+all\\b|--\\s*$|--\\s*\\w/i";

    /** 重定向参数名模式 */
    public const REDIRECT_KEY_PATTERN = '/^(returnurl|return_url|redirect|redirect_url|next|url|goto|target|back|callback|redir|continue|dest|destination)$/i';

    /** 业务逻辑分析入口
     * @param string $uri    请求 URI
     * @param array  $params 参数数组 (key => value)
     * @return array{score:int, scene:string, valid:bool, violations:array, endpoint:array, flow_state:string}
     */
    public static function analyze(string $uri, array $params = []): array {
        if ($uri === '' && empty($params)) {
            return ['score' => 0, 'scene' => 'unknown', 'valid' => true, 'violations' => [], 'endpoint' => [], 'flow_state' => 'unknown'];
        }

        // ===== A. 端点语义解析（状态机解析 URI） =====
        $endpoint = self::parseEndpoint($uri);
        self::enrichActionFromParams($endpoint, $params);

        // ===== B. 业务流程状态推理 =====
        $flowState = self::inferFlowState($endpoint);
        $endpoint['flow_state'] = $flowState;

        $violations = [];
        $hits = []; // 维度 => 分值

        // ===== C-G. 五维业务异常检测 =====
        $dims = [
            'consistency' => self::checkParamConsistency($endpoint, $params),
            'privilege'   => self::checkResourceAccess($endpoint, $params),
            'context'     => self::checkContextAnomaly($endpoint, $params),
            'format'      => self::checkApiFormat($endpoint),
            'attack'      => self::checkAttackPatterns($endpoint, $params, $uri),
        ];
        foreach ($dims as $name => $res) {
            if ($res['score'] > 0) {
                $hits[$name] = $res['score'];
                foreach ($res['violations'] as $v) $violations[] = $v;
            }
        }

        // ===== 评分汇总 + 多维交叉加成 =====
        $score = array_sum($hits);
        $dimCount = count($hits);
        if ($dimCount >= 4) { $score += 15; $violations[] = 'cross:4dims+'; }
        elseif ($dimCount === 3) { $score += 8; $violations[] = 'cross:3dims'; }
        elseif ($dimCount === 2) { $score += 3; }

        $score = max(0, min(100, (int) round($score)));
        return [
            'score' => $score, 'scene' => $endpoint['kind'], 'valid' => $score === 0,
            'violations' => array_values(array_unique($violations)),
            'endpoint' => $endpoint, 'flow_state' => $flowState,
        ];
    }

    /* ===== A. 端点语义解析（状态机） =====
     * 解析 PROTOCOL://HOST/SEGMENT/SEGMENT?QUERY
     * 状态流转：scheme/host 剥离 -> query 剥离 -> 分段 -> api -> 版本 -> 资源 -> ID -> 子资源/动作
     */
    private static function parseEndpoint(string $uri): array {
        $endpoint = [
            'raw' => $uri, 'path' => '', 'segments' => [], 'version' => null,
            'is_api' => false, 'resource_type' => 'unknown', 'resource_segment' => -1,
            'action' => 'read', 'resource_id' => null, 'sub_resource' => null,
            'has_path_traversal' => false, 'depth' => 0, 'kind' => 'unknown',
        ];
        if ($uri === '') return $endpoint;

        // 1. 剥离 query 与 fragment
        $path = $uri;
        $qPos = strpos($path, '?');
        if ($qPos !== false) $path = substr($path, 0, $qPos);
        $hPos = strpos($path, '#');
        if ($hPos !== false) $path = substr($path, 0, $hPos);

        // 2. 剥离 scheme://host
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $path)) {
            $path = preg_replace('#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', '', $path, 1);
            $slashPos = strpos($path, '/');
            $path = ($slashPos !== false) ? substr($path, $slashPos) : '/';
        }
        $endpoint['path'] = $path;

        // 3. 分段（保留原始段，含编码/遍历片段以便后续检测）
        $segments = [];
        if ($path !== '') {
            foreach (explode('/', $path) as $seg) {
                if ($seg !== '') $segments[] = $seg;
            }
        }
        $endpoint['segments'] = $segments;
        $endpoint['depth'] = count($segments);

        // 4. 检测路径遍历（原始与编码）
        foreach ($segments as $seg) {
            if ($seg === '..' || strpos($seg, '../') !== false || strpos($seg, '..\\') !== false) {
                $endpoint['has_path_traversal'] = true; break;
            }
        }
        if (!$endpoint['has_path_traversal']) {
            $lower = strtolower($path);
            if (strpos($lower, '..%2f') !== false || strpos($lower, '..%5c') !== false || strpos($lower, '%2e%2e') !== false) {
                $endpoint['has_path_traversal'] = true;
            }
        }

        // 5. 状态机扫描段：api -> version -> resource -> id -> sub-resource / action
        $idx = 0;
        $n = count($segments);
        if ($idx < $n && strtolower($segments[$idx]) === 'api') {
            $endpoint['is_api'] = true;
            $idx++;
        }
        if ($idx < $n && preg_match('/^v(\d+)$/i', $segments[$idx])) {
            $endpoint['version'] = strtolower($segments[$idx]);
            $idx++;
        }

        $resolvedResource = false;
        for ($i = $idx; $i < $n; $i++) {
            $segLower = strtolower($segments[$i]);

            // 资源类型识别（首个匹配段）
            if (!$resolvedResource && isset(self::$resource_types[$segLower])) {
                $endpoint['resource_type'] = self::$resource_types[$segLower];
                $endpoint['resource_segment'] = $i;
                $resolvedResource = true;

                // 后续段若像 ID（且本身不是资源类型/动作），则记录为资源 ID
                if ($i + 1 < $n
                    && !isset(self::$resource_types[strtolower($segments[$i + 1])])
                    && !isset(self::$action_intents[strtolower($segments[$i + 1])])
                    && self::looksLikeResourceId($segments[$i + 1])) {
                    $endpoint['resource_id'] = $segments[$i + 1];
                    $i++;
                    // 再后续若为另一资源 -> 子资源（/users/123/orders）
                    if ($i + 1 < $n && isset(self::$resource_types[strtolower($segments[$i + 1])])) {
                        $endpoint['sub_resource'] = self::$resource_types[strtolower($segments[$i + 1])];
                        $i++;
                        if ($i + 1 < $n && self::looksLikeResourceId($segments[$i + 1])) {
                            $i++;
                        }
                    }
                }
                continue;
            }

            // 动作意图识别（不覆盖已识别的更具体动作）
            if (isset(self::$action_intents[$segLower]) && $endpoint['action'] === 'read') {
                $endpoint['action'] = self::$action_intents[$segLower];
            }
        }

        // 6. 端点类型分类
        $endpoint['kind'] = self::classifyEndpoint($endpoint, $segments);
        return $endpoint;
    }

    /** 判断段是否像资源 ID（数字 / UUID / hash / 常规 ID / 异常 ID） */
    private static function looksLikeResourceId(string $seg): bool {
        if ($seg === '') return false;
        if (ctype_digit($seg)) return true;
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $seg)) return true;
        if (preg_match('/^[0-9a-f]{12,}$/i', $seg)) return true;
        if (preg_match('/^[a-zA-Z0-9_\-]{3,64}$/', $seg)) return true;
        // 路径遍历 / 异常 ID（含 ../ 或路径分隔符）
        if (strpos($seg, '..') !== false || strpos($seg, '/') !== false || strpos($seg, '\\') !== false) return true;
        return false;
    }

    /** 从参数丰富动作意图（action=delete / op=update 等） */
    private static function enrichActionFromParams(array &$endpoint, array $params) {
        $actionKeys = ['action','op','operation','method','do','task','act'];
        foreach ($params as $k => $v) {
            if (in_array(strtolower((string) $k), $actionKeys, true)) {
                $vLower = strtolower((string) $v);
                if (isset(self::$action_intents[$vLower]) && $endpoint['action'] === 'read') {
                    $endpoint['action'] = self::$action_intents[$vLower];
                }
            }
        }
    }

    /** 端点类型分类（用于参数一致性 / 上下文检测） */
    private static function classifyEndpoint(array $endpoint, array $segments): string {
        $segs = array_map('strtolower', $segments);
        $groups = [
            'login'          => ['login','signin','wp-login'],
            'register'       => ['register','signup','sign-up','create-account'],
            'password_reset' => ['reset','forgot','recover'],
            'logout'         => ['logout','signout'],
            'search'         => ['search','query','find'],
            'upload'         => ['upload','uploads','import'],
            'admin'          => ['admin','manage','management','dashboard','wp-admin','administrator'],
            'payment'        => ['pay','payment','checkout','cart'],
        ];
        foreach ($groups as $kind => $aliases) {
            foreach ($segs as $s) {
                if (in_array($s, $aliases, true)) return $kind;
            }
        }
        if ($endpoint['resource_type'] !== 'unknown') {
            return $endpoint['is_api'] ? 'api_resource' : 'resource';
        }
        return 'unknown';
    }

    /* ===== B. 业务流程状态推理 ===== */
    private static function inferFlowState(array $endpoint): string {
        $kind = $endpoint['kind'];
        $rt = $endpoint['resource_type'];

        if (in_array($kind, ['login','register','password_reset','logout'], true)) {
            return 'pre_auth';
        }
        if ($kind === 'admin' || $rt === 'admin') {
            return 'high_privilege';
        }
        if ($rt !== 'unknown' && $endpoint['resource_id'] !== null) {
            return 'resource_access';
        }
        if ($rt !== 'unknown') {
            return 'post_auth';
        }
        if (preg_match('/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|xml|txt)$/i', $endpoint['raw'])) {
            return 'static';
        }
        return 'unknown';
    }

    /* ===== C. 参数-端点一致性推理 ===== */
    private static function checkParamConsistency(array $endpoint, array $params): array {
        $violations = [];
        $score = 0;
        $kind = $endpoint['kind'];

        $spec = self::$param_specs[$kind] ?? null;
        if ($spec === null) {
            return ['score' => 0, 'violations' => []];
        }
        $expect = $spec['expect'];
        $reject = $spec['reject'];
        $paramKeys = array_map('strtolower', array_keys($params));

        // 1. 禁止参数出现（强违反）
        $rejectHits = [];
        foreach ($paramKeys as $k) {
            if (in_array($k, $reject, true)) {
                $rejectHits[] = $k;
            }
        }
        if (!empty($rejectHits)) {
            $score += min(25, count($rejectHits) * 18);
            $violations[] = 'param:reject_param_on_' . $kind . ':' . implode(',', $rejectHits);
        }

        // 2. 必需参数缺失（有参数但核心期望参数缺失）
        if (!empty($paramKeys) && !empty($expect)) {
            $hasCore = false;
            foreach ($paramKeys as $k) {
                if (in_array($k, $expect, true)) {
                    $hasCore = true;
                    break;
                }
            }
            if (!$hasCore) {
                $score += 8;
                $violations[] = 'param:no_expected_param_on_' . $kind;
            }
        }

        // 3. 重定向参数出现在非认证端点（开放重定向探测）
        foreach ($paramKeys as $k) {
            if (preg_match(self::REDIRECT_KEY_PATTERN, $k)) {
                if (!in_array($kind, ['login','register','password_reset','logout'], true)) {
                    $score += 12;
                    $violations[] = 'param:redirect_param_on_' . $kind . ':' . $k;
                }
                break;
            }
        }

        return ['score' => min(40, $score), 'violations' => $violations];
    }

    /* ===== D. 资源访问越权推理 ===== */
    private static function checkResourceAccess(array $endpoint, array $params): array {
        $violations = [];
        $score = 0;

        // 1. URI 中路径遍历
        if ($endpoint['has_path_traversal']) {
            $score += 20; $violations[] = 'priv:path_traversal_in_uri';
        }

        // 2. 资源 ID 格式异常（含路径遍历 / 路径分隔符）
        $rid = $endpoint['resource_id'];
        if ($rid !== null && $rid !== '') {
            if (strpos($rid, '..') !== false || strpos($rid, '/') !== false || strpos($rid, '\\') !== false) {
                $score += 15; $violations[] = 'priv:malformed_resource_id';
            }
        }

        // 3. 敏感 ID 越权（admin / root / 0）
        if ($rid !== null && in_array(strtolower((string) $rid), self::$sensitive_ids, true)) {
            $score += 12; $violations[] = 'priv:sensitive_id_access:' . $rid;
        }

        // 4. 管理端点访问（无认证上下文 -> 越权探测）
        if ($endpoint['kind'] === 'admin') {
            $score += 15; $violations[] = 'priv:admin_endpoint_access';
            if (in_array($endpoint['action'], ['delete','drop','destroy'], true)) {
                $score += 15; $violations[] = 'priv:admin_destructive_action:' . $endpoint['action'];
            }
        }

        // 5. ID 参数中含 SQL 注入特征
        $idParamKeys = ['id','uid','user_id','order_id','pid','item_id','object_id','ref_id'];
        foreach ($params as $k => $v) {
            if (in_array(strtolower($k), $idParamKeys, true)
                && preg_match(self::SQL_INJECTION_PATTERN, (string) $v)) {
                $score += 15; $violations[] = 'priv:sql_in_id_param:' . $k;
            }
        }

        return ['score' => min(50, $score), 'violations' => $violations];
    }

    /* ===== E. 业务上下文异常检测 ===== */
    private static function checkContextAnomaly(array $endpoint, array $params): array {
        $violations = [];
        $score = 0;
        $kind = $endpoint['kind'];
        $flow = $endpoint['flow_state'];

        $paramKeys = array_map('strtolower', array_keys($params));
        $valuesStr = '';
        foreach ($params as $v) $valuesStr .= ' ' . (string) $v;
        $valuesLower = strtolower($valuesStr);

        // 1. 认证端点出现文件操作参数 / 代码 payload
        if (in_array($kind, ['login','register','password_reset'], true)) {
            $fileParams = ['file','upload','attachment','path','filename','filepath'];
            foreach ($paramKeys as $k) {
                if (in_array($k, $fileParams, true)) { $score += 20; $violations[] = 'ctx:file_op_on_auth:' . $k; break; }
            }
            if (preg_match('/\b(alert|eval|system|exec|shell_exec|document\.|window\.|<script)\b/i', $valuesLower)) { $score += 18; $violations[] = 'ctx:code_payload_on_auth'; }
        }

        // 2. 静态 / 未知端点出现 SQL/代码 payload
        if ($flow === 'static' || $kind === 'unknown') {
            if (preg_match('/\b(union\s+select|select\s+from|insert\s+into|drop\s+table|<script|eval\s*\()/i', $valuesLower)) { $score += 20; $violations[] = 'ctx:attack_payload_on_static'; }
        }

        // 3. 管理端点出现普通用户参数（越权探测）
        if ($kind === 'admin') {
            $userParams = ['username','user','email','profile','avatar','nickname'];
            foreach ($paramKeys as $k) {
                if (in_array($k, $userParams, true)) { $score += 12; $violations[] = 'ctx:user_param_on_admin:' . $k; break; }
            }
        }

        // 4. 搜索端点出现文件 / 命令参数
        if ($kind === 'search') {
            foreach ($paramKeys as $k) {
                if (in_array($k, ['file','cmd','exec','shell','command','system'], true)) { $score += 18; $violations[] = 'ctx:cmd_param_on_search:' . $k; break; }
            }
        }

        // 5. API 资源端点出现路径遍历
        if ($endpoint['has_path_traversal'] && $endpoint['is_api']) { $score += 15; $violations[] = 'ctx:traversal_in_api'; }

        return ['score' => min(45, $score), 'violations' => $violations];
    }

    /* ===== F. API 版本与格式语义 ===== */
    private static function checkApiFormat(array $endpoint): array {
        $violations = [];
        $score = 0;

        // 1. 路径深度异常（正常 API <=5 段；过深可能为探测）
        if ($endpoint['depth'] > 8) {
            $score += 10;
            $violations[] = 'fmt:depth_anomaly:' . $endpoint['depth'];
        }

        // 2. 版本段异常（v0 / v999）
        if ($endpoint['version'] !== null && preg_match('/^v(\d+)$/i', $endpoint['version'], $vm)) {
            $verNum = (int) $vm[1];
            if ($verNum === 0 || $verNum > 20) {
                $score += 8;
                $violations[] = 'fmt:abnormal_version:' . $endpoint['version'];
            }
        }

        // 3. 段中含控制字符 / NUL
        foreach ($endpoint['segments'] as $seg) {
            if (preg_match('/[\x00-\x1f\x7f]/', $seg) || strpos($seg, '%00') !== false) {
                $score += 12;
                $violations[] = 'fmt:control_char_in_segment';
                break;
            }
        }

        // 4. 同时出现多版本段（/api/v1/.../v2/...）
        $versionCount = 0;
        foreach ($endpoint['segments'] as $seg) {
            if (preg_match('/^v\d+$/i', $seg)) $versionCount++;
        }
        if ($versionCount >= 2) {
            $score += 12;
            $violations[] = 'fmt:multi_version_segments';
        }

        return ['score' => min(20, $score), 'violations' => $violations];
    }

    /* ===== G. 业务逻辑攻击模式 ===== */
    private static function checkAttackPatterns(array $endpoint, array $params, string $uri): array {
        $violations = [];
        $score = 0;
        $kind = $endpoint['kind'];
        $uriLower = strtolower($uri);

        // G1. WebShell 文件上传（上传端点 + 可执行后缀 / WebShell 名）
        if ($kind === 'upload' || $endpoint['resource_type'] === 'file') {
            $fileParamKeys = ['file','filename','name','upload','attachment','image','avatar'];
            foreach ($params as $k => $v) {
                if (!in_array(strtolower($k), $fileParamKeys, true)) continue;
                $vStr = (string) $v;
                $ext = strtolower(pathinfo($vStr, PATHINFO_EXTENSION));
                if ($ext !== '' && in_array($ext, self::$exec_extensions, true)) {
                    $score += 18;
                    $violations[] = 'attack:exec_extension_upload:' . $ext;
                } elseif (preg_match('/\.(php|asp|jsp|exe|sh)\b/i', $vStr)) {
                    // 双重后缀绕过（shell.php.jpg）
                    $score += 12;
                    $violations[] = 'attack:double_extension_bypass';
                }
                if (preg_match(self::WEBSHELL_NAME_PATTERN, $vStr)) {
                    $score += 12;
                    $violations[] = 'attack:webshell_filename';
                }
            }
        }

        // G2. 伪协议重定向（开放重定向 / XSS via redirect）
        foreach ($params as $k => $v) {
            if (!preg_match(self::REDIRECT_KEY_PATTERN, (string) $k)) continue;
            $vStr = (string) $v;
            $vLower = strtolower($vStr);
            $protoHit = false;
            foreach (self::$pseudo_protocols as $proto) {
                if (strpos($vLower, $proto) !== false) {
                    $protoHit = true;
                    break;
                }
            }
            if ($protoHit) {
                $score += 30;
                $violations[] = 'attack:pseudo_protocol_redirect:' . $k;
                if (preg_match('/\b(alert|prompt|confirm|eval|document\.|window\.|location\.|cookie|fromcharcode)\b/i', $vStr)) {
                    $score += 15;
                    $violations[] = 'attack:xss_in_redirect';
                }
            } elseif (preg_match('#^https?://#i', $vStr) && !in_array($kind, ['login','register','password_reset','logout'], true)) {
                // 绝对外链重定向（非认证端点的开放重定向）
                $score += 10;
                $violations[] = 'attack:absolute_redirect:' . $k;
            }
        }

        // G3. 敏感系统文件路径（路径遍历目标）
        $sensitiveHit = preg_match(self::SENSITIVE_FILE_PATTERN, $uriLower);
        if (!$sensitiveHit) {
            foreach ($params as $v) {
                if (preg_match(self::SENSITIVE_FILE_PATTERN, strtolower((string) $v))) {
                    $sensitiveHit = true;
                    break;
                }
            }
        }
        if ($sensitiveHit) {
            $score += 20;
            $violations[] = 'attack:sensitive_file_target';
        }

        // G4. 批量操作参数（管理端点的批量删除/更新探测）
        $batchKeys = ['ids','items','bulk','batch','mass','all','selected'];
        foreach ($params as $k => $v) {
            if (in_array(strtolower($k), $batchKeys, true) && $kind === 'admin') {
                $score += 10;
                $violations[] = 'attack:bulk_admin_op';
                break;
            }
        }

        return ['score' => min(60, $score), 'violations' => $violations];
    }
}
