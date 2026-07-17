<?php
/**
 * 业务语义分析引擎
 * 职责：基于请求 URI 与参数识别业务场景（登录、搜索、提交、上传、API调用等），
 *       验证请求是否符合该业务逻辑预期（如登录页不应出现 SQL UNION）。
 */
defined('ABSPATH') || exit;

class BusinessSemantics {
    /**
     * 场景识别规则
     * 每项：scene => [uri正则, 关键参数名正则, 描述]
     */
    private static $scene_rules = [
        'login'    => ['/login|signin|wp-login|auth|session/i', '/^(username|user|password|passwd|pwd|email|token|captcha|remember)$/i', '登录认证'],
        'register' => ['/register|signup|sign-up|create-account/i', '/^(username|email|password|confirm|code|invite)$/i', '注册'],
        'search'   => ['/search|query|find|list|filter/i', '/^(q|query|keyword|keywords|search|kw|term|page|sort|order)$/i', '搜索/列表'],
        'submit'   => ['/submit|post|comment|reply|feedback|contact/i', '/^(title|content|body|message|name|email|subject)$/i', '内容提交'],
        'upload'   => ['/upload|file|attachment|avatar|import/i', '/^(file|upload|attachment|image|type|name|size)$/i', '文件上传'],
        'api'      => ['/\/api\/|\/v\d+\//i', '//', 'API调用'],
        'admin'    => ['/\/admin\/|\/manage\/|\/dashboard\/|wp-admin/i', '//', '后台管理'],
        'payment'  => ['/pay|payment|order|checkout|cart/i', '/^(amount|currency|order|card|cvv|exp|token)$/i', '支付'],
        'reset'    => ['/reset|forgot|recover/i', '/^(email|token|password|new_password)$/i', '密码重置'],
    ];

    /**
     * 各场景禁止出现的攻击特征
     * 每项：scene => [危险特征正则 => 描述]
     */
    private static $scene_violations = [
        'login' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '登录中出现UNION注入',
            '/\bdrop\b|\bdelete\b|\binsert\b/iu'          => '登录中出现DML关键字',
            '/<script\b/iu'                                => '登录中出现脚本标签',
            '/\.\.[\/\\\\]/u'                              => '登录中出现路径遍历',
        ],
        'register' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '注册中出现UNION注入',
            '/<script\b/iu'                                => '注册中出现脚本标签',
        ],
        'search' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '搜索中出现UNION注入',
            '/\b(?:or|and)\b\s+\d+\s*=\s*\d+/iu'          => '搜索中出现逻辑永真',
            '/<script\b/iu'                                => '搜索中出现脚本标签',
            '/\b(?:eval|system|exec|shell_exec)\s*\(/iu'  => '搜索中出现命令执行函数',
        ],
        'submit' => [
            '/\b(?:eval|system|exec|shell_exec|passthru)\s*\(/iu' => '提交中出现命令执行函数',
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '提交中出现UNION注入',
        ],
        'upload' => [
            '/\.(?:php|phtml|php5|pht|phar|asp|aspx|jsp|exe|sh|cgi)\b/iu' => '上传可疑可执行后缀',
            '/<\?php|<\?=/iu'                              => '上传内容含PHP标签',
            '/\b(?:eval|system|exec)\s*\(/iu'             => '上传内容含命令执行函数',
        ],
        'api' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => 'API中出现UNION注入',
            '/\.\.[\/\\\\]/u'                              => 'API中出现路径遍历',
        ],
        'admin' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '后台请求中出现UNION注入',
        ],
        'payment' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '支付中出现UNION注入',
            '/\b(?:eval|system|exec)\s*\(/iu'             => '支付中出现命令执行函数',
        ],
        'reset' => [
            '/\bunion\b[\s\S]{0,40}?\bselect\b/iu'        => '密码重置中出现UNION注入',
            '/\.\.[\/\\\\]/u'                              => '密码重置中出现路径遍历',
        ],
    ];

    /**
     * 业务语义分析
     *
     * @param string $uri 请求URI
     * @param array $params 参数数组（key=>value）
     * @return array{score:int, scene:string, valid:bool}
     */
    public static function analyze(string $uri, array $params): array {
        $scene = 'unknown';
        $score = 0;
        $valid = true;
        $violations = [];

        if ($uri === '' && empty($params)) {
            return ['score' => 0, 'scene' => $scene, 'valid' => $valid, 'violations' => []];
        }

        // ---- 1. 识别业务场景（按 URI + 参数名匹配得分取最高） ----
        $bestScene = 'unknown';
        $bestScore = 0;
        foreach (self::$scene_rules as $name => $rule) {
            $uriPat = $rule[0];
            $keyPat = $rule[1];
            $s = 0;
            if (@preg_match($uriPat, $uri)) {
                $s += 2;
            }
            if ($keyPat !== '//') {
                foreach (array_keys($params) as $k) {
                    if (@preg_match($keyPat, (string) $k)) {
                        $s += 1;
                        break;
                    }
                }
            }
            if ($s > $bestScore) {
                $bestScore = $s;
                $bestScene = $name;
            }
        }
        $scene = $bestScene;

        // ---- 2. 校验场景合法性 ----
        $violationsRules = self::$scene_violations[$scene] ?? [];
        if (!empty($violationsRules)) {
            // 拼接 URI 与所有参数值用于检测
            $combined = $uri;
            foreach ($params as $k => $v) {
                $combined .= ' ' . (string) $k . '=' . (string) $v;
            }
            foreach ($violationsRules as $pat => $desc) {
                if (@preg_match($pat, $combined)) {
                    $violations[] = $desc;
                    $score += 30;
                    $valid = false;
                }
            }
        }

        // ---- 3. 通用异常：未知场景下出现高危结构 ----
        $genericHigh = 0;
        foreach ($params as $v) {
            $v = (string) $v;
            if (preg_match('/\bunion\b[\s\S]{0,40}?\bselect\b/iu', $v)) {
                $genericHigh++;
            }
            if (preg_match('/<script\b/iu', $v)) {
                $genericHigh++;
            }
            if (preg_match('/\b(?:eval|system|exec)\s*\(/iu', $v)) {
                $genericHigh++;
            }
        }
        if ($genericHigh > 0 && $scene === 'unknown') {
            // 未知场景下出现高危结构
            $score += min(30, $genericHigh * 15);
            $valid = false;
            $violations[] = 'unknown_scene_with_attack_payload';
        }

        // ---- 4. 后台场景直接访问敏感配置接口加可疑 ----
        if ($scene === 'admin' && preg_match('/\/admin\/(?:config|settings|database)\b/i', $uri)) {
            $score += 10;
        }

        // 场景识别置信度低 + 出现攻击特征，加重
        if ($scene === 'unknown' && $score > 0) {
            $score = min(100, $score + 5);
        }

        $score = max(0, min(100, (int) round($score)));
        return [
            'score'      => $score,
            'scene'      => $scene,
            'valid'      => $valid,
            'violations' => $violations,
        ];
    }
}
