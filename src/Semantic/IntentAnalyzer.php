<?php
/**
 * 攻击意图识别引擎
 * 职责：基于多维特征识别攻击者的具体意图，
 *       包括数据窃取、权限提升、命令执行、文件操控、身份绕过等类别。
 *       意图识别比单纯的攻击类型分类更深入，能揭示攻击的最终目的。
 */
defined('ABSPATH') || exit;

class IntentAnalyzer {
    /**
     * 攻击意图分类及特征模式
     * 每项：intent => [name, description, patterns, weight]
     */
    private static $intent_patterns = [
        'data_exfiltration' => [
            'name' => '数据窃取',
            'desc' => '试图窃取数据库、配置文件或敏感信息',
            'weight' => 95,
            'indicators' => [
                'union_select'       => '/\bunion\b[\s\S]{0,100}?\bselect\b/iu',
                'information_schema' => '/information_schema\.\w+/iu',
                'load_file'          => '/\bload_file\s*\(/iu',
                'into_outfile'       => '/\binto\s+outfile\b/iu',
                'select_star'        => '/select\s+\*\s+from/iu',
                'etc_passwd'         => '/\/etc\/passwd|\/etc\/shadow/iu',
                'config_file'        => '/config\.php|wp-config|database\.yml|\.env\b/iu',
                'credit_card'        => '/credit_card|ssn|password|passwd|secret/iu',
                'group_concat'       => '/group_concat\s*\(/iu',
                'table_schema'       => '/table_schema|column_name|tables\b/iu',
            ],
        ],
        'privilege_escalation' => [
            'name' => '权限提升',
            'desc' => '试图提升权限或获取管理员权限',
            'weight' => 90,
            'indicators' => [
                'admin_user'      => '/\badmin\b.*\bpassword\b|\bpassword\b.*\badmin\b/iu',
                'root_access'     => '/\broot\b|\bsuperuser\b|\bsudo\b/iu',
                'xp_cmdshell'     => '/xp_cmdshell/iu',
                'grant_priv'      => '/\bgrant\b.*\bprivilege\b|\bgrant\b.*\ball\b/iu',
                'create_user'     => '/\bcreate\s+user\b|\binsert\s+into\s+.*users?\b/iu',
                'update_admin'    => '/\bupdate\s+.*admin.*\bset\b.*password/iu',
                'wp_admin'        => '/wp-admin|wp_user_level|administrator/iu',
            ],
        ],
        'command_execution' => [
            'name' => '命令执行',
            'desc' => '试图在服务器上执行系统命令或代码',
            'weight' => 95,
            'indicators' => [
                'eval_assert'    => '/\b(?:eval|assert)\s*\(/iu',
                'system_exec'    => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(/iu',
                'cmd_chain'      => '/[;|&`]\s*\w+\s*[=|\/]/u',
                'backtick'       => '/`[^`]+`/u',
                'dollar_paren'   => '/\$\([^)]+\)/u',
                'base64_decode'  => '/\bbase64_decode\s*\(/iu',
                'gzinflate'      => '/\bgzinflate\s*\(/iu',
                'php_code'       => '/<\?php|<\?=/iu',
                'preg_replace'   => '/preg_replace\s*\(\s*[\'"]/iu',
                'python_perl'    => '/\b(?:python|perl|ruby|bash|sh)\s+-[a-z]/iu',
            ],
        ],
        'file_manipulation' => [
            'name' => '文件操控',
            'desc' => '试图读取、写入、修改或删除服务器文件',
            'weight' => 85,
            'indicators' => [
                'path_traversal'  => '/\.\.[\/\\\\]/u',
                'file_read'       => '/\b(?:file_get_contents|readfile|fopen|file)\s*\(/iu',
                'file_write'      => '/\b(?:file_put_contents|fwrite|fputs|move_uploaded_file)\s*\(/iu',
                'delete_file'     => '/\b(?:unlink|delete|rm\s+-rf|rmdir)\s*\(/iu',
                'include_file'    => '/\b(?:include|require)(?:_once)?\s*\(/iu',
                'php_wrapper'     => '/php:\/\/(?:input|filter|data)/iu',
                'upload_shell'    => '/\.(?:php|phtml|php5|pht|phar)\b/iu',
                'zip_slip'        => '/\.\.\/.*\.zip|zip.*\.\.\//iu',
            ],
        ],
        'identity_bypass' => [
            'name' => '身份绕过',
            'desc' => '试图绕过认证、登录或验证码等身份验证机制',
            'weight' => 80,
            'indicators' => [
                'sql_injection_auth' => '/\b(?:or|and)\b\s+[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+/iu',
                'token_manipulation' => '/\b(?:token|session|cookie|jwt)\b.*=.*(?:or|union|select)/iu',
                'captcha_bypass'     => '/captcha.*=.*(?:0|1|true|false)/iu',
                'password_spray'     => '/\bpassword\b.*=.*(?:admin|123456|password)/iu',
                'privilege_id'       => '/user_id\s*=\s*[01]|uid\s*=\s*[01]/iu',
                'cookie_tamper'      => '/\b(?:admin|is_admin|superuser)\s*=\s*(?:1|true|yes)/iu',
            ],
        ],
        'defacement' => [
            'name' => '页面篡改',
            'desc' => '试图修改页面内容或注入恶意脚本',
            'weight' => 75,
            'indicators' => [
                'xss_script'     => '/<script\b[\s\S]*?<\/script>/iu',
                'xss_event'      => '/<\w+[^>]*\bon\w+\s*=/iu',
                'iframe_inject'  => '/<iframe\b/iu',
                'svg_xxe'        => '/<svg\b.*<!ENTITY/iu',
                'meta_redirect'  => '/<meta[^>]+http-equiv[^>]+url/iu',
                'base_hijack'    => '/<base\s+href/iu',
                'form_hijack'    => '/<form[^>]+action\s*=/iu',
            ],
        ],
        'dos' => [
            'name' => '拒绝服务',
            'desc' => '试图耗尽服务器资源或导致服务不可用',
            'weight' => 70,
            'indicators' => [
                'sleep_injection' => '/\b(?:sleep|benchmark|waitfor\s+delay)\s*\(/iu',
                'heavy_query'     => '/select\s+.*\s+from\s+.*\s+cross\s+join/iu',
                'recursive'       => '/\brecursive\b|\bwith\s+recursive\b/iu',
                'regex_dos'       => '/\((?:.+\+|.+\*){3,}\)/u',
                'large_payload'   => '/(?:.{200,}){5,}/u',
            ],
        ],
        'information_gathering' => [
            'name' => '信息收集',
            'desc' => '试图探测系统信息、目录结构或漏洞',
            'weight' => 60,
            'indicators' => [
                'dir_traversal'   => '/\/\.\.|\/etc\/|\/proc\//u',
                'phpinfo'         => '/phpinfo|php_info/iu',
                'error_msg'       => '/mysql_error|warning|fatal\s+error|stack\s+trace/iu',
                'version_probe'   => '/\bversion\b|\bbanner\b|\bserver\s*:/iu',
                'backup_file'     => '/\.(?:bak|backup|old|orig|swp|~)\b/iu',
                'dot_file'        => '/\/\.(?:git|svn|env|htaccess|htpasswd)\b/iu',
            ],
        ],
    ];

    /**
     * 攻击意图综合分析
     *
     * @param string $text 归一化后的文本
     * @param string $uri  请求URI
     * @param array  $params 参数数组
     * @return array{score:int, primary_intent:string, intents:array, confidence:int}
     */
    public static function analyze(string $text, string $uri = '', array $params = []): array {
        if ($text === '' && empty($params)) {
            return [
                'score' => 0,
                'primary_intent' => 'unknown',
                'intents' => [],
                'confidence' => 0,
                'intent_names' => [],
            ];
        }

        $combined = $text . ' ' . $uri;
        foreach ($params as $k => $v) {
            $combined .= ' ' . $k . '=' . (string)$v;
        }

        $intentScores = [];
        $matchedIndicators = [];

        foreach (self::$intent_patterns as $intentKey => $intent) {
            $score = 0;
            $hits = 0;
            $matched = [];
            $totalIndicators = count($intent['indicators']);

            foreach ($intent['indicators'] as $indName => $pattern) {
                if (@preg_match($pattern, $combined)) {
                    $hits++;
                    $matched[] = $indName;
                    $score += 100 / $totalIndicators;
                }
            }

            if ($hits > 0) {
                $bonus = $hits >= 3 ? 1.3 : ($hits >= 2 ? 1.15 : 1.0);
                $finalScore = min(100, (int)round($score * $bonus * ($intent['weight'] / 100)));
                $intentScores[$intentKey] = $finalScore;
                $matchedIndicators[$intentKey] = $matched;
            }
        }

        arsort($intentScores);
        $topScore = !empty($intentScores) ? max($intentScores) : 0;
        $primaryIntent = !empty($intentScores) ? key($intentScores) : 'unknown';

        $topIntentInfo = self::$intent_patterns[$primaryIntent] ?? null;
        $confidence = 0;
        if ($topScore > 0) {
            $confidence = min(100, (int)round($topScore * 0.7 + count($matchedIndicators[$primaryIntent] ?? []) * 8));
        }

        $intentNames = [];
        foreach (array_keys($intentScores) as $key) {
            if ($intentScores[$key] >= 20) {
                $intentNames[] = self::$intent_patterns[$key]['name'] ?? $key;
            }
        }

        return [
            'score'           => $topScore,
            'primary_intent'  => $primaryIntent,
            'primary_name'    => $topIntentInfo ? $topIntentInfo['name'] : '未知',
            'primary_desc'    => $topIntentInfo ? $topIntentInfo['desc'] : '',
            'intents'         => $intentScores,
            'intent_names'    => $intentNames,
            'matched'         => $matchedIndicators,
            'confidence'      => $confidence,
        ];
    }

    /**
     * 获取所有意图类别
     */
    public static function getAllIntents(): array {
        $result = [];
        foreach (self::$intent_patterns as $key => $val) {
            $result[$key] = ['name' => $val['name'], 'desc' => $val['desc']];
        }
        return $result;
    }
}
