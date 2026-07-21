<?php
/**
 * L7 攻击意图链推理引擎
 *
 * 职责：从"标签匹配"升级为"攻击意图链推理"。基于单次请求特征推断攻击者意图：
 *   1. 攻击意图分类推理（A）—— 基于证据组合推断意图类别，而非"匹配到 union 就标 SQL"
 *   2. 攻击阶段推理（B）—— Lockheed Martin Cyber Kill Chain 七阶段模型
 *   3. 意图置信度推理（C）—— 伪贝叶斯式累积置信度（单证据低/多证据中/跨层印证高）
 *   4. 意图链节点定位（D）—— 推断当前请求处于意图链的哪个节点
 *   5. 攻击者画像推理（E）—— 脚本小子/渗透测试者/高级攻击者/自动化扫描器
 *   6. 上下文意图强化（F）—— payload 与 URI / 参数位置的关联强化
 *
 * 推理模型：每条检测规则产出一条证据 [意图类别, 权重, Kill Chain 阶段, 链节点]，
 *   聚合后产出主意图 / 主阶段 / 置信度 / 链节点 / 攻击者画像。
 * 评分（上限 100）：意图分类 0-30 + 阶段推理 0-20 + 置信度加成 0-20
 *   + 意图链深度 0-15 + 攻击者画像 0-15；正常文本（零证据）得 0 分。
 * 公共 API：analyze() / getAttackProgress()（兼容旧+新阶段名）/ getAllPhases()
 */
defined('ABSPATH') || exit;

class IntentInference {

    /* =====================================================================
     * 证据规则库（A 意图分类 + B Kill Chain 阶段 + D 链节点 联合标注）
     * 每条规则 = [type, pattern, label, weight, kill_chain_phase, chain_node]
     *   type : 're' 正则 ｜ 'substr' 大小写不敏感子串
     *   weight: 单条证据权重（聚合时累加，受置信度调节）
     * ===================================================================== */
    private static $intent_evidence = [
        'sql_injection' => [
            ['re', '/\bunion\b[\s\S]{0,40}?\bselect\b/iu', 'sql:union_select_extract', 26, 'exploitation', 'data_extraction'],
            ['re', '/\bor\b\s+\d+\s*=\s*\d+/iu', 'sql:auth_bypass_tautology', 24, 'exploitation', 'auth_bypass'],
            ['re', "/['\"`][\s]*(?:or|and)[\s]+[`'\" ]?\d+/i", 'sql:quote_logic_injection', 20, 'delivery', 'payload_delivery'],
            ['re', '/\bselect\b[\s\S]{0,80}?\bfrom\b/iu', 'sql:select_from_query', 18, 'exploitation', 'data_query'],
            ['re', '/information_schema\s*\./i', 'sql:metadata_recon', 24, 'recon', 'schema_recon'],
            ['re', '/\bsleep\s*\(\s*\d+/i', 'sql:time_blind_probe', 22, 'recon', 'time_blind_recon'],
            ['re', '/\bbenchmark\s*\(\s*\d+/i', 'sql:time_blind_benchmark', 22, 'recon', 'time_blind_recon'],
            ['re', "/['\"`]\s*(?:--|#)\s*[\r\n]*$/u", 'sql:comment_truncation', 18, 'delivery', 'closure'],
            ['re', '/;\s*(?:drop|insert|update|delete|truncate)\b/iu', 'sql:stacked_query', 22, 'actions', 'data_manipulation'],
            ['re', '/\bload_file\s*\(/i', 'sql:file_read', 24, 'actions', 'file_read'],
            ['re', '/into\s+(?:outfile|dumpfile)/i', 'sql:file_write', 24, 'actions', 'file_write'],
            ['re', '/extractvalue\s*\(/i', 'sql:error_based_extractvalue', 22, 'exploitation', 'error_based'],
            ['re', '/updatexml\s*\(/i', 'sql:error_based_updatexml', 22, 'exploitation', 'error_based'],
            ['re', '/@@(?:version|datadir|hostname|basedir)/i', 'sql:version_fingerprint', 18, 'recon', 'fingerprint'],
            ['re', '/\bgroup_concat\s*\(/i', 'sql:group_concat_dump', 20, 'actions', 'data_extraction'],
        ],
        'xss' => [
            ['re', '/<script\b/iu', 'xss:script_tag', 22, 'delivery', 'payload_delivery'],
            ['re', '/\bonerror\s*=/i', 'xss:onerror_handler', 24, 'delivery', 'payload_delivery'],
            ['re', '/\bonload\s*=/i', 'xss:onload_handler', 20, 'delivery', 'payload_delivery'],
            ['re', '/\bonclick\s*=/i', 'xss:onclick_handler', 16, 'delivery', 'payload_delivery'],
            ['re', '/javascript:/i', 'xss:js_uri_scheme', 22, 'delivery', 'payload_delivery'],
            ['substr', 'document.cookie', 'xss:cookie_steal_intent', 26, 'actions', 'session_steal'],
            ['re', '/\balert\s*\(/i', 'xss:alert_proof', 18, 'delivery', 'payload_delivery'],
            ['re', '/<svg\b/iu', 'xss:svg_payload', 22, 'delivery', 'payload_delivery'],
            ['re', '/<img\b[^>]*onerror/iu', 'xss:img_onerror', 22, 'delivery', 'payload_delivery'],
            ['re', '/\bfromcharcode\s*\(/i', 'xss:obfuscated_payload', 22, 'weaponization', 'payload_construction'],
            ['re', '/<iframe\b/iu', 'xss:iframe_injection', 20, 'delivery', 'payload_delivery'],
        ],
        'command_injection' => [
            ['re', '/[;|&`]\s*(?:cat|ls|id|whoami|uname|ifconfig|netstat|wget|curl|nc|bash|sh|python|perl|rm|chmod|chown)\b/iu', 'cmd:shell_command_chain', 26, 'exploitation', 'command_exec'],
            ['re', '/\b(?:cat|head|tail|more|less)\s+\/etc\//i', 'cmd:read_etc_file', 26, 'actions', 'sensitive_read'],
            ['re', '/\b(?:uname|whoami|id|hostname)\s+[-a]/i', 'cmd:sysinfo_gather', 22, 'recon', 'sysinfo_probe'],
            ['substr', '$(', 'cmd:command_substitution', 20, 'delivery', 'payload_delivery'],
            ['re', '/\|\|/u', 'cmd:logical_or_chain', 14, 'delivery', 'payload_delivery'],
            ['re', '/&&\s*\w+/u', 'cmd:and_chain', 14, 'delivery', 'payload_delivery'],
            ['re', '/\b(?:reverse|bind)[\s_-]?shell/i', 'cmd:reverse_shell_intent', 28, 'c2', 'shell_establish'],
            ['re', '/\/bin\/(?:sh|bash|zsh)/i', 'cmd:shell_path_invoke', 22, 'exploitation', 'shell_invoke'],
            ['re', '/\bbash\s+-[iec]\b/i', 'cmd:bash_exec_flag', 24, 'c2', 'shell_establish'],
            ['re', '/\bnc\s+-[elp]\b/i', 'cmd:netcat_listener', 24, 'c2', 'shell_establish'],
            ['re', '/\/etc\/(?:cron\.d|crontab|rc\.local)/i', 'cmd:cron_persistence', 26, 'installation', 'persistence'],
            ['re', '/\b(?:wget|curl)\s+["\']?https?:\/\//i', 'cmd:remote_fetch_tool', 20, 'weaponization', 'payload_fetch'],
        ],
        'path_traversal' => [
            ['re', '/\.\.[\/\\\\]/u', 'path:traversal_sequence', 22, 'exploitation', 'file_explore'],
            ['substr', '/etc/passwd', 'path:etc_passwd_read', 26, 'actions', 'credential_read'],
            ['substr', '/etc/shadow', 'path:etc_shadow_read', 28, 'actions', 'credential_read'],
            ['substr', '/proc/self', 'path:proc_self_probe', 22, 'recon', 'process_recon'],
            ['substr', 'php://input', 'path:php_input_wrapper', 26, 'delivery', 'code_inject_delivery'],
            ['substr', 'php://filter', 'path:php_filter_wrapper', 24, 'exploitation', 'code_read'],
            ['re', '/\b(?:boot|win)\.ini\b/i', 'path:windows_config_read', 22, 'actions', 'config_read'],
            ['substr', '/.ssh/id_rsa', 'path:ssh_key_read', 28, 'actions', 'credential_read'],
            ['re', '/\.\.%2[fF]/', 'path:encoded_traversal_bypass', 22, 'weaponization', 'bypass_construction'],
            ['re', '/\b(?:file|data|zip|phar|expect):\/\//i', 'path:stream_wrapper_abuse', 22, 'delivery', 'code_inject_delivery'],
        ],
        'code_execution' => [
            ['re', '/<\?php\b/i', 'code:php_open_tag', 22, 'installation', 'webshell_install'],
            ['re', '/<\?=/', 'code:php_short_echo', 16, 'delivery', 'code_inject_delivery'],
            ['re', '/\beval\s*\(\s*\$_(?:post|get|request|cookie)/i', 'code:eval_superglobal_webshell', 30, 'installation', 'webshell_install'],
            ['re', '/\bassert\s*\(\s*\$_/i', 'code:assert_superglobal_webshell', 28, 'installation', 'webshell_install'],
            ['re', '/\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(\s*\$_/i', 'code:cmd_func_superglobal', 28, 'exploitation', 'command_exec'],
            ['re', '/\b(?:system|exec|shell_exec|passthru)\s*\(\s*[\'"`]/i', 'code:cmd_func_call', 22, 'exploitation', 'command_exec'],
            ['substr', 'base64_decode(', 'code:b64_decode_chain', 22, 'weaponization', 'payload_construction'],
            ['re', '/\bcreate_function\s*\(/i', 'code:obsolete_create_function', 26, 'exploitation', 'rce_invoke'],
            ['re', '/\bpreg_replace\s*\([^,]*\/[a-z]*e[a-z]*[\'"`]/i', 'code:preg_replace_e_modifier', 26, 'exploitation', 'rce_invoke'],
            ['substr', '$_POST[', 'code:post_superglobal_input', 18, 'delivery', 'payload_delivery'],
            ['substr', '$_GET[', 'code:get_superglobal_input', 16, 'delivery', 'payload_delivery'],
            ['re', '/<\?php[\s\S]{0,80}?\b(?:eval|assert|system|exec)\b/i', 'code:webshell_template', 24, 'installation', 'webshell_install'],
        ],
        'ssti' => [
            ['substr', '{{', 'ssti:template_expr_open', 18, 'delivery', 'template_probe'],
            ['substr', '${', 'ssti:el_expression', 18, 'delivery', 'template_probe'],
            ['substr', '__class__', 'ssti:python_class_attr', 26, 'exploitation', 'sandbox_escape'],
            ['substr', '__subclasses__', 'ssti:mro_subclasses', 26, 'exploitation', 'sandbox_escape'],
            ['substr', '__globals__', 'ssti:globals_access', 24, 'actions', 'data_extract'],
            ['re', '/\{\{\s*[^}]*config\b/i', 'ssti:flask_config_leak', 24, 'actions', 'data_extract'],
        ],
    ];

    /* =====================================================================
     * Kill Chain 阶段定义（Lockheed Martin 模型）
     * order：阶段顺序深度；weight：阶段得分权重（越深权重越高）
     * ===================================================================== */
    private static $kill_chain = [
        'recon'         => ['name' => '侦察阶段',     'desc' => '探测端点、参数枚举、版本指纹收集',     'order' => 1, 'weight' => 6],
        'weaponization' => ['name' => '武器化阶段',   'desc' => '构造 payload、生成绕过、编码混淆',     'order' => 2, 'weight' => 10],
        'delivery'      => ['name' => '投递阶段',     'desc' => '发送 payload 到目标输入点',           'order' => 3, 'weight' => 14],
        'exploitation'  => ['name' => '利用阶段',     'desc' => '触发漏洞、获取非授权执行',           'order' => 4, 'weight' => 18],
        'installation'  => ['name' => '安装阶段',     'desc' => '植入 webshell、建立持久化',         'order' => 5, 'weight' => 22],
        'c2'            => ['name' => '命令控制阶段', 'desc' => '建立反向连接、持久命令通道',         'order' => 6, 'weight' => 26],
        'actions'       => ['name' => '目标达成阶段', 'desc' => '数据外传、凭据窃取、横向移动',       'order' => 7, 'weight' => 30],
    ];

    /* =====================================================================
     * Kill Chain 阶段转移概率矩阵（G 阶段转移异常推理）
     * 定义阶段间的转移概率（0.0-1.0），用于推断阶段转移的异常程度。
     *   正向推进（+1 阶段）= 0.70   同阶段停留 = 0.30
     *   跳跃推进（+2 阶段）= 0.15   反向回退（-1 阶段）= 0.10
     *   大跳跃（≥+3 阶段或回退至起点）= 0.05
     * 概率越低代表该转移路径越罕见，越可能是异常行为（如已知漏洞直接利用、
     * 重放攻击、目标切换、误报等）。
     * ===================================================================== */
    private static $phaseTransitionMatrix = [
        'recon' => [
            'recon' => 0.30, 'weaponization' => 0.70, 'delivery' => 0.15,
            'exploitation' => 0.15, 'installation' => 0.05, 'c2' => 0.05, 'actions' => 0.05,
        ],
        'weaponization' => [
            'recon' => 0.10, 'weaponization' => 0.30, 'delivery' => 0.70,
            'exploitation' => 0.15, 'installation' => 0.15, 'c2' => 0.05, 'actions' => 0.05,
        ],
        'delivery' => [
            'recon' => 0.05, 'weaponization' => 0.10, 'delivery' => 0.30,
            'exploitation' => 0.70, 'installation' => 0.15, 'c2' => 0.15, 'actions' => 0.05,
        ],
        'exploitation' => [
            'recon' => 0.10, 'weaponization' => 0.05, 'delivery' => 0.10,
            'exploitation' => 0.30, 'installation' => 0.70, 'c2' => 0.15, 'actions' => 0.15,
        ],
        'installation' => [
            'recon' => 0.05, 'weaponization' => 0.05, 'delivery' => 0.05,
            'exploitation' => 0.10, 'installation' => 0.30, 'c2' => 0.70, 'actions' => 0.15,
        ],
        'c2' => [
            'recon' => 0.05, 'weaponization' => 0.05, 'delivery' => 0.05,
            'exploitation' => 0.05, 'installation' => 0.10, 'c2' => 0.30, 'actions' => 0.70,
        ],
        'actions' => [
            'recon' => 0.10, 'weaponization' => 0.05, 'delivery' => 0.05,
            'exploitation' => 0.05, 'installation' => 0.05, 'c2' => 0.10, 'actions' => 0.30,
        ],
    ];

    /** 意图类别 -> 人类可读标签 */
    private static $intent_labels = [
        'sql_injection'      => 'SQL 注入',
        'xss'                => '跨站脚本攻击',
        'command_injection' => '命令注入',
        'path_traversal'     => '路径遍历 / 文件包含',
        'code_execution'     => '代码执行',
        'ssti'               => '服务端模板注入',
    ];

    /* =====================================================================
     * 意图链定义（D）：每条意图的典型攻击链节点序列（按推进顺序）
     * 节点越靠后，链深度越深。locateChainNode 据此推断当前节点。
     * ===================================================================== */
    private static $intent_chains = [
        'sql_injection'      => ['schema_recon', 'fingerprint', 'time_blind_recon', 'payload_delivery', 'closure', 'auth_bypass', 'data_query', 'error_based', 'data_extraction', 'file_read', 'file_write', 'data_manipulation'],
        'xss'                => ['recon', 'payload_construction', 'payload_delivery', 'session_steal'],
        'command_injection'  => ['sysinfo_probe', 'payload_fetch', 'payload_delivery', 'command_exec', 'shell_invoke', 'shell_establish', 'persistence', 'sensitive_read'],
        'path_traversal'     => ['process_recon', 'file_explore', 'code_inject_delivery', 'code_read', 'bypass_construction', 'config_read', 'credential_read', 'lateral_movement'],
        'code_execution'     => ['payload_delivery', 'code_inject_delivery', 'payload_construction', 'webshell_install', 'rce_invoke', 'command_exec', 'persistence'],
        'ssti'               => ['template_probe', 'sandbox_escape', 'data_extract'],
    ];

    /* =====================================================================
     * 意图转移图（G 意图转移异常推理）
     * 定义意图类别间的转移关系概率。用于检测攻击者切换攻击向量的行为。
     * 典型提权链：sql_injection -> code_execution -> command_injection
     * 未列出的意图对视为未知转移（概率 0.0），异常评分最高。
     * ===================================================================== */
    private static $intentTransitions = [
        'sql_injection' => [
            'path_traversal'    => 0.4,  // 数据获取转向文件读取
            'code_execution'    => 0.3,  // SQL 注入转向 RCE，典型提权链
        ],
        'xss' => [
            'command_injection' => 0.2,  // XSS 转向命令注入
        ],
        'path_traversal' => [
            'code_execution'    => 0.5,  // 文件读取转向代码执行
        ],
        'code_execution' => [
            'command_injection' => 0.6,  // RCE 转向命令执行
        ],
    ];

    /* =====================================================================
     * 攻击者画像特征库（E）
     * 每条 = [type, pattern, label, weight]；label 前缀决定画像归属。
     * ===================================================================== */
    private static $attacker_profiles = [
        // 脚本小子：现成工具 payload、陈词滥调
        ['re', '/<script>alert\s*\(\s*1\s*\)\s*<\/script>/i', 'skid:cliche_alert1', 8],
        ['re', "/['\"]?or['\"]?\s+1\s*=\s*1\s*--/i", 'skid:classic_or_1_1', 8],
        ['re', '/<\?php\s+eval\s*\(\s*\$_(?:post|get|request)\s*\[/i', 'skid:cliche_webshell', 8],
        ['substr', 'phpinfo()', 'skid:phpinfo_probe', 6],
        ['substr', '/etc/passwd', 'skid:classic_passwd_read', 6],
        ['re', '/<script>alert\s*\(\s*document\.cookie\s*\)/i', 'skid:alert_cookie_cliche', 6],

        // 渗透测试者：工具特征明显
        ['substr', 'burp', 'pentest:burp_signature', 12],
        ['re', '/\bsqlmap\b/i', 'pentest:sqlmark_tool', 14],
        ['re', '/\bnikto\b/i', 'pentest:nikto_tool', 14],
        ['substr', 'acunetix', 'pentest:acunetix_tool', 14],
        ['re', '/\bnuclei\b/i', 'pentest:nuclei_tool', 14],
        ['re', '/User-Agent[:\s].*(?:burp|sqlmap|nikto|nmap|masscan)/i', 'pentest:tool_useragent', 12],
        ['re', '/X-Scan-Info|X-Scanner/i', 'pentest:scanner_header', 10],

        // 高级攻击者：定制 payload、多重编码、绕过技巧
        ['re', '/0x[0-9a-f]{16,}/i', 'advanced:long_hex_payload', 12],
        ['re', '/\bchar\s*\(\s*\d+\s*\)/i', 'advanced:char_encode_obfuscation', 10],
        ['re', '/concat\s*\(\s*0x/i', 'advanced:concat_obfuscation', 10],
        ['re', '/\/\*[\s\S]*?\*\//u', 'advanced:inline_comment_bypass', 8],
        ['re', '/%25[0-9a-f]{2}/i', 'advanced:double_url_encode', 12],
        ['re', '/\bfromcharcode\s*\(/i', 'advanced:js_fromcharcode_obfuscation', 10],
        ['re', '/\\\\u[0-9a-f]{4}/i', 'advanced:unicode_escape_obfuscation', 10],
        ['re', '/\\\\x[0-9a-f]{2}/i', 'advanced:hex_escape_obfuscation', 8],

        // 自动化扫描器：模板化、批量路径扫描
        ['re', '/\/\.(?:git|svn|env|aws|hg)/i', 'scanner:config_file_scan', 8],
        ['re', '/\/(?:phpinfo|test|admin|backup|old|debug)\.(?:php|html|txt|bak)/i', 'scanner:common_path_scan', 6],
        ['re', '/\.(?:bak|old|swp|orig|~)$/i', 'scanner:backup_ext_scan', 6],
        ['re', '/\/(?:wp-admin|wp-login|administrator|phpmyadmin|manager)\b/i', 'scanner:admin_panel_scan', 6],
    ];

    /* =====================================================================
     * 上下文敏感区域（F）：URI / 参数键 -> 倾向意图与上下文标签
     * 命中时对该意图证据权重加权（强化意图推理的方向）。
     * ===================================================================== */
    private static $context_zones = [
        'login'      => ['intent' => 'sql_injection',     'zone' => 'auth',        'hint' => '认证绕过意图'],
        'signin'     => ['intent' => 'sql_injection',     'zone' => 'auth',        'hint' => '认证绕过意图'],
        'logout'     => ['intent' => 'sql_injection',     'zone' => 'auth',        'hint' => '认证会话意图'],
        'admin'      => ['intent' => 'sql_injection',     'zone' => 'auth',        'hint' => '后台认证意图'],
        'search'     => ['intent' => 'sql_injection',     'zone' => 'query',       'hint' => '查询注入意图'],
        'q'          => ['intent' => 'sql_injection',     'zone' => 'query',       'hint' => '查询注入意图'],
        'keyword'    => ['intent' => 'sql_injection',     'zone' => 'query',       'hint' => '查询注入意图'],
        'comment'    => ['intent' => 'xss',               'zone' => 'storage',    'hint' => '存储型 XSS 投递'],
        'message'    => ['intent' => 'xss',               'zone' => 'storage',    'hint' => '存储型 XSS 投递'],
        'feedback'   => ['intent' => 'xss',               'zone' => 'storage',    'hint' => '存储型 XSS 投递'],
        'name'       => ['intent' => 'xss',               'zone' => 'storage',    'hint' => '存储型 XSS 投递'],
        'upload'     => ['intent' => 'code_execution',   'zone' => 'upload',     'hint' => 'webshell 上传投递'],
        'file'       => ['intent' => 'path_traversal',   'zone' => 'file_access', 'hint' => '文件读取意图'],
        'path'       => ['intent' => 'path_traversal',   'zone' => 'file_access', 'hint' => '路径遍历意图'],
        'page'       => ['intent' => 'path_traversal',   'zone' => 'include',     'hint' => '文件包含意图'],
        'include'    => ['intent' => 'path_traversal',   'zone' => 'include',     'hint' => '文件包含意图'],
        'template'   => ['intent' => 'ssti',              'zone' => 'render',      'hint' => '模板注入意图'],
        'cmd'        => ['intent' => 'command_injection', 'zone' => 'exec',       'hint' => '命令执行意图'],
        'exec'       => ['intent' => 'command_injection', 'zone' => 'exec',       'hint' => '命令执行意图'],
        'user-agent' => ['intent' => 'xss',               'zone' => 'header',      'hint' => '头部注入侦察'],
        'referer'    => ['intent' => 'xss',               'zone' => 'header',      'hint' => '头部注入侦察'],
        'api'        => ['intent' => 'sql_injection',     'zone' => 'api',        'hint' => 'API 参数注入意图'],
    ];

    /** 画像类别 -> 人类可读标签 */
    private static $profile_labels = [
        'skid'     => '脚本小子',
        'pentest'  => '渗透测试者',
        'advanced' => '高级攻击者',
        'scanner'  => '自动化扫描器',
    ];

    /**
     * L7 攻击意图链推理入口
     *
     * @param string $text    归一化后的请求体文本
     * @param string $uri     请求 URI
     * @param array  $params  请求参数
     * @param array  $history 历史请求记录（支持 previous_phase/previous_intent/request_count/time_elapsed；
     *                        为空数组或 null 时按无历史处理，完全向后兼容）
     * @return array score, phase, phase_name, phase_desc, phase_confidence,
     *               phase_confidence_detail, primary_intent(_name), intents, kill_chain_phase,
     *               legacy_phase, chain_node, chain_depth(_score), attacker_profile(_name),
     *               context_zone, context_hint, indicators, next_actions,
     *               evidence_count, confidence, phase_hits,
     *               phase_transition, intent_transition
     */
    public static function analyze(string $text, string $uri = '', array $params = [], array $history = []): array {
        $paramText = self::collectParamText($params);
        $evidenceText = $text . "\n" . $uri . "\n" . $paramText;

        // ============== 0. 证据收集（A+B+D 联合标注） ==============
        $evidence = self::collectEvidence($evidenceText);

        if (empty($evidence)) {
            return self::emptyResult();
        }

        // ============== A. 攻击意图分类推理（聚合 + 多证据加成） ==============
        $intents = self::aggregateIntents($evidence);

        // ============== F. 上下文意图强化（提前于阶段/链推理，影响主意图选择） ==============
        $context = self::detectContextZone($uri, $params);
        $intents = self::reinforceContext($intents, $context);

        $primary = $intents[0];

        // ============== B. Kill Chain 阶段推理（到达的最深阶段） ==============
        $phase = self::inferKillChainPhase($evidence);

        // ============== B+. 阶段置信度精细化（独立于总置信度，按阶段证据独立计算） ==============
        $phaseConfidenceDetail = self::calcPhaseConfidence($evidence, $phase['phase']);

        // ============== C. 意图置信度推理（伪贝叶斯累积） ==============
        $confidence = self::inferConfidence($evidence, $intents);

        // ============== D. 意图链节点定位（主意图链上到达的最深节点） ==============
        $chain = self::locateChainNode($evidence, $primary['class']);

        // ============== E. 攻击者画像推理 ==============
        $profile = self::profileAttacker($evidenceText);

        // ============== 评分汇总（五维加权，上限 100） ==============
        $intentScore  = min(30, $primary['weight']);                                  // A 0-30
        $phaseScore   = min(20, $phase['weight']);                                    // B 0-20
        $confScore    = (int) round($confidence / 100 * 20);                          // C 0-20
        $chainScore   = min(15, $chain['depth_score']);                              // D 0-15
        $profileScore = min(15, $profile['score']);                                   // E 0-15
        $total = max(0, min(100, $intentScore + $phaseScore + $confScore + $chainScore + $profileScore));

        // ============== G. 阶段/意图转移异常推理（基于历史请求，向后兼容：history 为空时不触发） ==============
        $phaseTransition  = null;
        $intentTransition = null;
        if (!empty($history)) {
            // G1. 阶段转移异常：对比上一请求阶段与当前阶段
            $previousPhase = isset($history['previous_phase']) ? (string) $history['previous_phase'] : '';
            if ($previousPhase !== '' && $previousPhase !== $phase['phase']) {
                $phaseTransition = self::inferPhaseTransition($previousPhase, $phase['phase']);
                // 阶段转移异常分：anomaly_score * 0.15（最多贡献 0-10 分）
                $total += (int) round($phaseTransition['anomaly_score'] * 0.15);
            }
            // G2. 意图转移异常：对比上一请求主意图与当前主意图
            $previousIntent = isset($history['previous_intent']) ? (string) $history['previous_intent'] : '';
            if ($previousIntent !== '') {
                $intentTransition = self::inferIntentTransition(
                    $intents,
                    [['class' => $previousIntent]]
                );
                // 意图转移异常分：anomaly_score * 0.10（最多贡献 0-7 分）
                $total += (int) round($intentTransition['anomaly_score'] * 0.10);
            }
        }
        $total = max(0, min(100, $total));

        $indicators = [];
        foreach ($evidence as $e) {
            $indicators[] = $e['label'];
        }
        foreach ($profile['indicators'] as $p) {
            $indicators[] = $p;
        }
        if ($context['intent'] !== '' && isset(self::$intent_labels[$context['intent']])) {
            $indicators[] = 'ctx:' . $context['zone'] . ':' . $context['intent'];
        }

        return [
            'score'                   => $total,
            'phase'                   => $phase['phase'],
            'phase_name'              => $phase['name'],
            'phase_desc'              => $phase['desc'],
            'phase_confidence'        => (int) round($confidence),
            'phase_confidence_detail' => $phaseConfidenceDetail,
            'primary_intent'          => $primary['class'],
            'primary_intent_name'     => $primary['label'],
            'intents'                 => $intents,
            'kill_chain_phase'        => $phase['phase'],
            'legacy_phase'            => $phase['legacy_phase'],
            'chain_node'              => $chain['node'],
            'chain_depth'             => $chain['depth'],
            'chain_depth_score'       => $chainScore,
            'attacker_profile'        => $profile['profile'],
            'attacker_profile_name'   => $profile['profile_name'],
            'profile_score'           => $profileScore,
            'context_zone'            => $context['zone'],
            'context_hint'            => $context['hint'],
            'indicators'              => $indicators,
            'next_actions'            => $chain['next_nodes'],
            'evidence_count'          => count($evidence),
            'confidence'              => round($confidence, 2),
            'phase_hits'              => $phase['phase_hits'],
            'phase_transition'        => $phaseTransition,
            'intent_transition'       => $intentTransition,
        ];
    }

    /**
     * 攻击阶段进度（0-100）。兼容旧阶段名 (recon/probe/attempt/attack/exploit)
     * 与新 Kill Chain 阶段名 (weaponization/delivery/exploitation/installation/c2/actions)。
     */
    public static function getAttackProgress(string $phase): int {
        $progress = [
            'none'          => 0,
            'recon'         => 10,
            'probe'         => 30,
            'attempt'       => 50,
            'attack'        => 75,
            'exploit'       => 100,
            'weaponization' => 25,
            'delivery'      => 40,
            'exploitation'  => 60,
            'installation'  => 80,
            'c2'            => 92,
            'actions'       => 100,
        ];
        return $progress[$phase] ?? 0;
    }

    /** 返回 Kill Chain 全部阶段定义 */
    public static function getAllPhases(): array {
        $result = [];
        foreach (self::$kill_chain as $key => $val) {
            $result[$key] = [
                'name'     => $val['name'],
                'desc'     => $val['desc'],
                'weight'   => $val['weight'],
                'progress' => self::getAttackProgress($key),
            ];
        }
        return $result;
    }

    /* =====================================================================
     * 0. 证据收集：遍历证据规则库，产出带意图/阶段/链节点标注的证据
     * ===================================================================== */
    private static function collectEvidence(string $text): array {
        $evidence = [];
        foreach (self::$intent_evidence as $class => $rules) {
            foreach ($rules as $rule) {
                list($type, $pattern, $label, $weight, $phase, $node) = $rule;
                $hit = false;
                if ($type === 're') {
                    $hit = (bool) @preg_match($pattern, $text);
                } elseif ($type === 'substr') {
                    $hit = stripos($text, $pattern) !== false;
                }
                if ($hit) {
                    $evidence[] = [
                        'class'  => $class,
                        'label'  => $label,
                        'weight' => $weight,
                        'phase'  => $phase,
                        'node'   => $node,
                    ];
                }
            }
        }
        return $evidence;
    }

    /* =====================================================================
     * A. 意图分类推理：按意图类别聚合证据，多证据指向同一意图给予加成
     * （贝叶斯式累积：证据越多越确信，而非 0/1 判定）
     * ===================================================================== */
    private static function aggregateIntents(array $evidence): array {
        $byClass = [];
        foreach ($evidence as $e) {
            $c = $e['class'];
            if (!isset($byClass[$c])) {
                $byClass[$c] = ['class' => $c, 'weight' => 0, 'count' => 0, 'nodes' => [], 'evidence' => []];
            }
            $byClass[$c]['weight'] += $e['weight'];
            $byClass[$c]['count']++;
            $byClass[$c]['evidence'][] = $e['label'];
            $byClass[$c]['nodes'][$e['node']] = true;
        }
        foreach ($byClass as $c => &$info) {
            // 同意图多证据 -> 累积加成（最多 +12）
            if ($info['count'] >= 4) {
                $info['weight'] += 12;
            } elseif ($info['count'] >= 3) {
                $info['weight'] += 10;
            } elseif ($info['count'] === 2) {
                $info['weight'] += 5;
            }
            // 同意图跨链节点 -> 多节点推进加成（最多 +8）
            $nodeSpan = count($info['nodes']);
            if ($nodeSpan >= 3) {
                $info['weight'] += 8;
            } elseif ($nodeSpan === 2) {
                $info['weight'] += 4;
            }
            $info['label']    = self::$intent_labels[$c] ?? $c;
            $info['node_span'] = $nodeSpan;
            unset($info['nodes']);
        }
        unset($info);

        usort($byClass, function ($a, $b) {
            if ($a['weight'] !== $b['weight']) {
                return $b['weight'] <=> $a['weight'];
            }
            return $b['count'] <=> $a['count'];
        });
        return $byClass;
    }

    /* =====================================================================
     * B. Kill Chain 阶段推理：选取证据到达的"最深"阶段（杀伤链推进度）
     * 同时累计每阶段证据权重用于置信度判定。
     * ===================================================================== */
    private static function inferKillChainPhase(array $evidence): array {
        $phaseHits = [];
        $maxOrder  = 0;
        $maxPhase  = 'none';
        foreach ($evidence as $e) {
            $p = $e['phase'];
            $order = self::$kill_chain[$p]['order'] ?? 0;
            if ($order > $maxOrder) {
                $maxOrder = $order;
                $maxPhase = $p;
            }
            if (!isset($phaseHits[$p])) {
                $phaseHits[$p] = 0;
            }
            $phaseHits[$p] += $e['weight'];
        }
        arsort($phaseHits);

        if ($maxOrder === 0) {
            return [
                'phase'        => 'none',
                'name'         => '无攻击意图',
                'desc'         => '',
                'weight'       => 0,
                'legacy_phase' => 'none',
                'phase_hits'   => $phaseHits,
            ];
        }

        $info = self::$kill_chain[$maxPhase];
        return [
            'phase'        => $maxPhase,
            'name'         => $info['name'],
            'desc'         => $info['desc'],
            'weight'       => $info['weight'],
            'legacy_phase' => self::mapLegacyPhase($maxPhase),
            'phase_hits'   => $phaseHits,
        ];
    }

    /**
     * Kill Chain 阶段 -> 旧阶段名映射（向后兼容 L8 AttackChainAnalyzer）
     */
    private static function mapLegacyPhase(string $phase): string {
        static $map = [
            'recon'         => 'recon',
            'weaponization' => 'probe',
            'delivery'      => 'attempt',
            'exploitation'  => 'attack',
            'installation'  => 'attack',
            'c2'            => 'exploit',
            'actions'       => 'exploit',
        ];
        return $map[$phase] ?? 'none';
    }

    /* =====================================================================
     * C. 意图置信度推理（伪贝叶斯累积）
     *   单条证据               -> 低置信度（~30）
     *   多条证据指向同一意图     -> 中置信度（~60-75）
     *   多条证据 + 跨意图印证   -> 高置信度（~85-95）
     * 返回 0-100。
     * ===================================================================== */
    private static function inferConfidence(array $evidence, array $intents): float {
        $n = count($evidence);
        if ($n === 0) {
            return 0.0;
        }

        // 先验：基础置信度由证据数线性增长
        $base = min(40.0, $n * 12.0);

        // 主意图证据占比（主意图证据越多，越确信其意图）
        $primaryCount = $intents[0]['count'] ?? 0;
        $primaryBonus = min(25.0, $primaryCount * 8.0);

        // 跨意图印证：多个意图类别同时被激活 -> 攻击存在性更确信
        $distinctClasses = count($intents);
        $crossBonus = 0.0;
        if ($distinctClasses >= 3) {
            $crossBonus = 20.0;
        } elseif ($distinctClasses === 2) {
            $crossBonus = 12.0;
        }

        // 阶段推进深度加成：到达越深的 Kill Chain 阶段 -> 攻击成熟度越高
        $maxOrder = 0;
        foreach ($evidence as $e) {
            $order = self::$kill_chain[$e['phase']]['order'] ?? 0;
            if ($order > $maxOrder) {
                $maxOrder = $order;
            }
        }
        $depthBonus = ($maxOrder / 7.0) * 15.0;

        $total = $base + $primaryBonus + $crossBonus + $depthBonus;
        return max(0.0, min(100.0, $total));
    }

    /* =====================================================================
     * D. 意图链节点定位：在主意图的链上找到证据到达的最深节点
     *   返回节点名、链深度（1-based）、深度得分（0-15）、剩余链节点（下一步预判）
     * ===================================================================== */
    private static function locateChainNode(array $evidence, string $primaryClass): array {
        $chainDef = self::$intent_chains[$primaryClass] ?? [];
        if (empty($chainDef)) {
            return ['node' => 'unknown', 'depth' => 0, 'depth_score' => 0, 'next_nodes' => [], 'chain_total' => 0];
        }

        $maxIdx = -1;
        $matchedNode = 'unknown';
        foreach ($evidence as $e) {
            if ($e['class'] !== $primaryClass) {
                continue;
            }
            $idx = array_search($e['node'], $chainDef, true);
            if ($idx !== false && $idx > $maxIdx) {
                $maxIdx = $idx;
                $matchedNode = $e['node'];
            }
        }

        if ($maxIdx < 0) {
            // 主意图无链内节点命中（如证据落在通用节点）-> 取链起点
            return [
                'node'        => $chainDef[0],
                'depth'       => 1,
                'depth_score' => 2,
                'next_nodes'  => array_slice($chainDef, 1),
                'chain_total' => count($chainDef),
            ];
        }

        $depth      = $maxIdx + 1;
        $chainTotal = count($chainDef);
        $depthScore = (int) round(($depth / $chainTotal) * 15);
        return [
            'node'        => $matchedNode,
            'depth'       => $depth,
            'depth_score' => $depthScore,
            'next_nodes'  => array_slice($chainDef, $maxIdx + 1),
            'chain_total' => $chainTotal,
        ];
    }

    /* =====================================================================
     * E. 攻击者画像推理：画像特征库投票，最高票画像胜出
     * ===================================================================== */
    private static function profileAttacker(string $text): array {
        $scores = ['skid' => 0, 'pentest' => 0, 'advanced' => 0, 'scanner' => 0];
        $indicators = [];
        foreach (self::$attacker_profiles as $rule) {
            list($type, $pattern, $label, $weight) = $rule;
            $hit = false;
            if ($type === 're') {
                $hit = (bool) @preg_match($pattern, $text);
            } elseif ($type === 'substr') {
                $hit = stripos($text, $pattern) !== false;
            }
            if (!$hit) {
                continue;
            }
            $cat = strstr($label, ':', true) ?: $label;
            if (!isset($scores[$cat])) {
                $scores[$cat] = 0;
            }
            $scores[$cat] += $weight;
            $indicators[] = $label;
        }

        arsort($scores);
        $topCat   = key($scores);
        $topScore = current($scores) ?: 0;

        return [
            'profile'        => $topScore > 0 ? $topCat : 'unknown',
            'profile_name'   => $topScore > 0 ? (self::$profile_labels[$topCat] ?? '未知') : '未知',
            'score'           => $topScore,
            'indicators'      => $indicators,
            'scores'          => $scores,
        ];
    }

    /* =====================================================================
     * F. 上下文意图强化：基于 URI / 参数键推断上下文区域，
     *   对与上下文匹配的意图证据权重加成（改变主意图选择的方向）
     * ===================================================================== */
    private static function detectContextZone(string $uri, array $params): array {
        $keys = array_keys($params);
        $haystack = strtolower($uri . ' ' . implode(' ', $keys));
        foreach (self::$context_zones as $needle => $info) {
            if (strpos($haystack, $needle) !== false) {
                return [
                    'zone'   => $info['zone'],
                    'hint'   => $info['hint'],
                    'intent' => $info['intent'],
                    'key'    => $needle,
                ];
            }
        }
        return ['zone' => 'unknown', 'hint' => '', 'intent' => '', 'key' => ''];
    }

    private static function reinforceContext(array $intents, array $context): array {
        if (empty($context['intent'])) {
            return $intents;
        }
        foreach ($intents as &$info) {
            if ($info['class'] === $context['intent']) {
                $info['weight'] += 8;
                $info['context_boost'] = true;
            }
        }
        unset($info);
        usort($intents, function ($a, $b) {
            if ($a['weight'] !== $b['weight']) {
                return $b['weight'] <=> $a['weight'];
            }
            return $b['count'] <=> $a['count'];
        });
        return $intents;
    }

    /* =====================================================================
     * 辅助：拼接参数文本（key=value 形式，供证据扫描）
     * ===================================================================== */
    private static function collectParamText(array $params): string {
        $parts = [];
        foreach ($params as $k => $v) {
            if (is_array($v)) {
                $v = json_encode($v, JSON_UNESCAPED_UNICODE) ?: '';
            } else {
                $v = (string) $v;
            }
            $parts[] = $k . '=' . $v;
        }
        return implode(' ', $parts);
    }

    /* =====================================================================
     * G1. Kill Chain 阶段转移异常推理
     * 基于阶段转移概率矩阵计算从 $fromPhase 到 $toPhase 的转移异常程度。
     * 异常评分规则（按规范）：
     *   概率 < 0.05 -> 高度异常（取 60，对应规范 50-70 区间）
     *   概率 < 0.10 -> 异常转移（取 40，对应规范 30-50 区间）
     *   概率 >= 0.10 -> 正常转移（0）
     *
     * @param string $fromPhase 起始阶段（上一请求阶段）
     * @param string $toPhase   目标阶段（当前请求阶段）
     * @return array {probability, is_normal, transition_label, anomaly_score}
     * ===================================================================== */
    private static function inferPhaseTransition(string $fromPhase, string $toPhase): array {
        // 未知阶段兜底：视为极低概率转移（高度异常）
        if (!isset(self::$phaseTransitionMatrix[$fromPhase][$toPhase])) {
            return [
                'probability'      => 0.0,
                'is_normal'        => false,
                'transition_label' => '未知阶段转移',
                'anomaly_score'    => 70,
            ];
        }

        $probability = (float) self::$phaseTransitionMatrix[$fromPhase][$toPhase];

        // 异常评分（按规范区间取代表值）
        if ($probability < 0.05) {
            $anomalyScore = 60;  // 高度异常（50-70 区间）
        } elseif ($probability < 0.10) {
            $anomalyScore = 40;  // 异常转移（30-50 区间）
        } else {
            $anomalyScore = 0;   // 正常转移
        }

        // 推断转移类型标签：依据阶段深度差（order 之差）
        $fromOrder = isset(self::$kill_chain[$fromPhase]['order']) ? (int) self::$kill_chain[$fromPhase]['order'] : 0;
        $toOrder   = isset(self::$kill_chain[$toPhase]['order'])   ? (int) self::$kill_chain[$toPhase]['order']   : 0;
        $delta     = $toOrder - $fromOrder;

        if ($delta === 0) {
            $label = '同阶段停留';
        } elseif ($delta === 1) {
            $label = '正向推进';
        } elseif ($delta === 2) {
            $label = '跳跃推进';
        } elseif ($delta > 2) {
            $label = '大跳跃推进';
        } else {
            $label = '反向回退';
        }

        return [
            'probability'      => $probability,
            'is_normal'        => $anomalyScore === 0,
            'transition_label' => $label,
            'anomaly_score'    => $anomalyScore,
        ];
    }

    /* =====================================================================
     * B+. 阶段置信度精细化（独立于 inferConfidence 的总置信度）
     * 基于该阶段的证据数量、阶段深度权重、证据强度独立计算阶段置信度。
     *   证据数量：1 条 -> 40，2 条 -> 60，3+ 条 -> 80
     *   阶段权重：浅阶段（recon/weaponization）0.8，深阶段（c2/actions）1.2，其余 1.0
     *   证据强度：每条 weight>=24 的证据 +15
     *
     * @param array  $evidence 全量证据列表
     * @param string $phase    目标阶段
     * @return array {confidence, basis, stage_weight}
     * ===================================================================== */
    private static function calcPhaseConfidence(array $evidence, string $phase): array {
        // 筛选属于该阶段的证据
        $phaseEvidence = [];
        foreach ($evidence as $e) {
            if (isset($e['phase']) && $e['phase'] === $phase) {
                $phaseEvidence[] = $e;
            }
        }
        $count = count($phaseEvidence);

        // 基础置信度：由该阶段证据数量决定
        if ($count >= 3) {
            $base = 80;
        } elseif ($count === 2) {
            $base = 60;
        } elseif ($count === 1) {
            $base = 40;
        } else {
            $base = 0;
        }

        // 阶段深度权重
        $stageWeight = 1.0;
        if ($phase === 'recon' || $phase === 'weaponization') {
            $stageWeight = 0.8;
        } elseif ($phase === 'c2' || $phase === 'actions') {
            $stageWeight = 1.2;
        }

        // 证据强度加成：每条 weight>=24 的证据贡献 +15
        $weightBonus = 0;
        foreach ($phaseEvidence as $e) {
            if (isset($e['weight']) && $e['weight'] >= 24) {
                $weightBonus += 15;
            }
        }

        $confidence = (int) round(min(100.0, $base * $stageWeight + $weightBonus));

        $basis = sprintf(
            '阶段=%s 证据数=%d 基础分=%d 阶段权重=%.1f 强证据加成=+%d',
            $phase,
            $count,
            $base,
            $stageWeight,
            $weightBonus
        );

        return [
            'confidence'   => $confidence,
            'basis'        => $basis,
            'stage_weight' => $stageWeight,
        ];
    }

    /* =====================================================================
     * G2. 意图转移异常推理
     * 对比当前主意图与历史主意图，输出转移概率与异常评分。
     *   历史为 null/空 -> 零异常结果（向后兼容）
     *   同意图 -> 无转移，零异常
     *   转移概率 < 0.2 -> anomaly_score 取 15-30
     *
     * @param array      $currentIntents  当前请求的意图列表（取 [0] 为主意图）
     * @param array|null $previousIntents 历史请求的意图列表（取 [0] 为主意图）
     * @return array {transition, probability, anomaly_score, is_lateral_movement}
     * ===================================================================== */
    private static function inferIntentTransition(array $currentIntents, ?array $previousIntents = null): array {
        // 历史为空 -> 零异常结果
        if (empty($previousIntents)) {
            return [
                'transition'          => 'none',
                'probability'         => 1.0,
                'anomaly_score'       => 0,
                'is_lateral_movement' => false,
            ];
        }

        $current  = isset($currentIntents[0]['class'])  ? $currentIntents[0]['class']  : 'unknown';
        $previous = isset($previousIntents[0]['class']) ? $previousIntents[0]['class'] : 'unknown';

        // 同意图 -> 无转移
        if ($current === $previous) {
            return [
                'transition'          => $previous . '→' . $current,
                'probability'         => 1.0,
                'anomaly_score'       => 0,
                'is_lateral_movement' => false,
            ];
        }

        // 查询意图转移概率
        $probability = isset(self::$intentTransitions[$previous][$current])
            ? (float) self::$intentTransitions[$previous][$current]
            : 0.0;

        // 异常评分：转移概率 < 0.2 时取 15-30
        if ($probability < 0.05) {
            $anomalyScore = 30;  // 未知转移（概率为 0），最高异常
        } elseif ($probability < 0.20) {
            $anomalyScore = 20;  // 低概率已知转移
        } else {
            $anomalyScore = 0;   // 高概率已知转移（横向移动/提权链）
        }

        // 横向移动判定：转移发生在已定义的意图转移图中（攻击向量切换）
        $isLateral = $probability > 0.0;

        return [
            'transition'          => $previous . '→' . $current,
            'probability'         => $probability,
            'anomaly_score'       => $anomalyScore,
            'is_lateral_movement' => $isLateral,
        ];
    }

    /**
     * 空结果（无任何攻击证据时的统一返回）
     */
    private static function emptyResult(): array {
        return [
            'score'                   => 0,
            'phase'                   => 'none',
            'phase_name'              => '无攻击意图',
            'phase_desc'              => '',
            'phase_confidence'        => 0,
            'phase_confidence_detail' => [
                'confidence'   => 0,
                'basis'        => '',
                'stage_weight' => 1.0,
            ],
            'primary_intent'          => 'unknown',
            'primary_intent_name'     => '未知',
            'intents'                 => [],
            'kill_chain_phase'        => 'none',
            'legacy_phase'            => 'none',
            'chain_node'              => 'unknown',
            'chain_depth'             => 0,
            'chain_depth_score'       => 0,
            'attacker_profile'        => 'unknown',
            'attacker_profile_name'   => '未知',
            'profile_score'           => 0,
            'context_zone'            => 'unknown',
            'context_hint'            => '',
            'indicators'              => [],
            'next_actions'            => [],
            'evidence_count'          => 0,
            'confidence'              => 0.0,
            'phase_hits'              => [],
            'phase_transition'        => null,
            'intent_transition'       => null,
        ];
    }
}
