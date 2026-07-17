<?php
/**
 * L7 意图推理引擎
 * 职责：识别攻击者所处的攻击阶段，包括侦察、探测、尝试、攻击、利用五个阶段。
 *       通过分析当前请求特征和历史行为模式，推断攻击者的意图和下一步行动。
 *       意图推理为防御策略提供前瞻性决策依据。
 */
defined('ABSPATH') || exit;

class IntentInference {
    /**
     * 攻击阶段定义
     * 每个阶段包含：名称、描述、特征模式、权重、下一步预判
     */
    private static $attack_phases = [
        'recon' => [
            'name'       => '侦察阶段',
            'desc'       => '攻击者正在收集目标信息，探测系统架构和漏洞',
            'weight'     => 20,
            'indicators' => [
                'phpinfo'       => '/phpinfo|php_info|info\.php/i',
                'version_probe' => '/\bversion\b|\bbanner\b|\bserver\s*:/iu',
                'dir_scan'      => '/\/\.\.|\/etc\/|\/proc\/|\/robots\.txt|\.git|\.svn|backup|old|bak/i',
                'error_msg'     => '/mysql_error|warning|fatal\s+error|stack\s+trace/i',
                'status_code'   => '/404|403|500|status\s*code/i',
                'dns_lookup'    => '/dns_get_record|gethostbyname|gethostbyaddr/i',
                'port_scan'     => '/\b(?:port|scan|nmap|nc|netcat)\b/i',
                'whois'         => '/\bwhois\b/i',
                'ping_test'     => '/\bping\b|\btraceroute\b|\bnslookup\b/i',
            ],
            'next_action' => ['probe', 'attempt'],
        ],
        'probe' => [
            'name'       => '探测阶段',
            'desc'       => '攻击者正在探测具体漏洞点，测试输入点和响应模式',
            'weight'     => 35,
            'indicators' => [
                'sql_test'      => '/\b(?:or|and)\b\s+\d+\s*=\s*\d+/iu',
                'xss_test'      => '/<script|javascript:|onerror=|onload=/i',
                'path_test'     => '/\.\.[\/\\\\]/u',
                'file_incl_test'=> '/\b(?:include|require)\s*\(\s*[\$_\'"]/i',
                'blind_test'    => '/\bsleep\s*\(\s*1\s*\)/i',
                'union_test'    => '/\bunion\b[\s\S]{0,30}?\bselect\b/iu',
                'order_by_test' => '/\border\s+by\s+\d+/iu',
                'offset_test'   => '/limit\s+\d+\s*,\s*1/i',
                'test_payload'  => '/\'\s*--|\';|"\s*--|";/i',
                'id_fuzz'       => '/id\s*=\s*[\'"][^\'"]*[\'"]/i',
            ],
            'next_action' => ['attempt', 'attack'],
        ],
        'attempt' => [
            'name'       => '尝试阶段',
            'desc'       => '攻击者正在尝试利用漏洞，进行实际攻击尝试',
            'weight'     => 50,
            'indicators' => [
                'union_attack'   => '/\bunion\b[\s\S]{0,50}?\bselect\b[\s\S]{0,100}?\bfrom\b/iu',
                'sql_data_extract'=> '/information_schema\.\w+|table_schema|column_name/i',
                'xss_payload'    => '/<script\b[\s\S]*?<\/script>/iu',
                'cmd_exec_attempt'=> '/\b(?:eval|system|exec)\s*\(\s*[\$_\'"]/iu',
                'file_read_attempt'=> '/\b(?:file_get_contents|readfile)\s*\(\s*[\'"]/iu',
                'file_write_attempt'=> '/\b(?:file_put_contents|fwrite)\s*\(\s*[\'"]/iu',
                'upload_attempt' => '/\.(?:php|phtml|php5|pht|phar)\b/i',
                'auth_bypass'    => '/\b(?:admin|is_admin|user_id)\s*=\s*(?:1|true)/iu',
                'session_hijack' => '/session_id|session_regenerate_id|cookie\s*=/i',
            ],
            'next_action' => ['attack', 'exploit'],
        ],
        'attack' => [
            'name'       => '攻击阶段',
            'desc'       => '攻击者正在进行有效攻击，获取非授权访问或数据',
            'weight'     => 75,
            'indicators' => [
                'union_full'     => '/\bunion\b[\s\S]{0,50}?\bselect\b[\s\S]{0,200}?\bfrom\b[\s\S]{0,200}?\bwhere\b/iu',
                'data_dump'      => '/group_concat\s*\([^)]+\)|concat\s*\([^)]+\)/iu',
                'cmd_exec'       => '/\b(?:eval|system|exec|shell_exec)\s*\(\s*[^)]+\s*\)/iu',
                'file_read'      => '/\b(?:file_get_contents|readfile)\s*\(\s*(?:\'|")\/etc\/passwd/i',
                'file_write'     => '/\b(?:file_put_contents|fwrite)\s*\(\s*(?:\'|")[^\'"]+\.php/i',
                'backdoor_upload'=> '/<\?php.*\b(?:eval|system|exec)\b/i',
                'database_dump'  => '/into\s+outfile|into\s+dumpfile|load_file/i',
                'privilege_escal'=> '/\b(?:grant|create\s+user|alter\s+user|root)\b/iu',
                'cron_inject'    => '/\/etc\/cron\.d|\/etc\/crontab|cron\.job/i',
                'ssh_key'        => '/\/\.ssh\/id_rsa|\/\.ssh\/authorized_keys/i',
            ],
            'next_action' => ['exploit'],
        ],
        'exploit' => [
            'name'       => '利用阶段',
            'desc'       => '攻击者已经成功利用漏洞，建立持久化访问或横向移动',
            'weight'     => 95,
            'indicators' => [
                'reverse_shell'  => '/\b(?:bash|python|perl|ruby|php)\s+-e/i',
                'bind_shell'     => '/listen\s*\(\s*\d+\s*\)|socket\s*\(\)|connect\s*\(/i',
                'webshell'       => '/<\?php.*\becho.*\$_POST|<\?php.*\beval.*\$_REQUEST/i',
                'backdoor'       => '/\b(?:system|exec|eval)\s*\(\s*\$_POST|\$_GET|\$_REQUEST/i',
                'persistence'    => '/crontab|at\s+job|systemd\s+service|rc\.local/i',
                'lateral_movement' => '/\b(?:ssh|scp|rsync|wget|curl)\s*\(/i',
                'data_exfiltration'=> '/\b(?:ftp|sftp|smb|http|post)\s*\(.*\b(?:upload|send|put)\b/i',
                'crypto_mining'  => '/miner|hashrate|blockchain|cryptocurrency/i',
                'ransomware'     => '/encrypt|decrypt|ransom|bitcoin|wallet/i',
                'botnet'         => '/irc|bot|c2|command\s+and\s+control/i',
            ],
            'next_action' => [],
        ],
    ];

    /**
     * 意图推理分析
     *
     * @param string $text 归一化后的文本
     * @param string $uri 请求URI
     * @param array  $params 参数数组
     * @param array  $history 历史请求记录（可选）
     * @return array{score:int, phase:string, phase_name:string, indicators:array, next_actions:array}
     */
    public static function analyze(string $text, string $uri = '', array $params = [], array $history = []): array {
        if ($text === '' && empty($params)) {
            return [
                'score'           => 0,
                'phase'           => 'none',
                'phase_name'      => '无攻击意图',
                'phase_desc'      => '',
                'indicators'      => [],
                'next_actions'    => [],
                'phase_confidence'=> 0,
                'phase_scores'    => [],
            ];
        }

        $combined = $text . ' ' . $uri;
        foreach ($params as $k => $v) {
            $combined .= ' ' . $k . '=' . (string)$v;
        }

        $phaseScores = [];
        $phaseIndicators = [];

        foreach (self::$attack_phases as $phaseKey => $phase) {
            $score = 0;
            $hits = 0;
            $matched = [];
            $totalIndicators = count($phase['indicators']);

            foreach ($phase['indicators'] as $indName => $pattern) {
                if (@preg_match($pattern, $combined)) {
                    $hits++;
                    $matched[] = $indName;
                    $score += 100 / $totalIndicators;
                }
            }

            if ($hits > 0) {
                $bonus = $hits >= 3 ? 1.4 : ($hits >= 2 ? 1.2 : 1.0);
                $finalScore = min(100, (int)round($score * $bonus * ($phase['weight'] / 100)));
                $phaseScores[$phaseKey] = $finalScore;
                $phaseIndicators[$phaseKey] = $matched;
            }
        }

        arsort($phaseScores);
        $topScore = !empty($phaseScores) ? max($phaseScores) : 0;
        $primaryPhase = !empty($phaseScores) ? key($phaseScores) : 'none';

        $phaseInfo = self::$attack_phases[$primaryPhase] ?? null;
        $confidence = 0;
        if ($topScore > 0) {
            $confidence = min(100, (int)round($topScore * 0.6 + count($phaseIndicators[$primaryPhase] ?? []) * 10));
        }

        $nextActions = [];
        if ($phaseInfo) {
            foreach ($phaseInfo['next_action'] as $action) {
                $nextActions[] = self::$attack_phases[$action]['name'] ?? $action;
            }
        }

        $indicatorNames = [];
        foreach ($phaseIndicators[$primaryPhase] ?? [] as $ind) {
            $indicatorNames[] = $ind;
        }

        return [
            'score'           => $topScore,
            'phase'           => $primaryPhase,
            'phase_name'      => $phaseInfo ? $phaseInfo['name'] : '无攻击意图',
            'phase_desc'      => $phaseInfo ? $phaseInfo['desc'] : '',
            'indicators'      => $indicatorNames,
            'next_actions'    => $nextActions,
            'phase_confidence'=> $confidence,
            'phase_scores'    => $phaseScores,
            'all_phases'      => array_map(function($k) {
                return self::$attack_phases[$k]['name'] ?? $k;
            }, array_keys($phaseScores)),
        ];
    }

    /**
     * 获取攻击阶段进度条（0-100%）
     */
    public static function getAttackProgress(string $phase): int {
        $progress = [
            'none'   => 0,
            'recon'  => 10,
            'probe'  => 30,
            'attempt'=> 50,
            'attack' => 75,
            'exploit'=> 100,
        ];
        return $progress[$phase] ?? 0;
    }

    /**
     * 获取所有攻击阶段定义
     */
    public static function getAllPhases(): array {
        $result = [];
        foreach (self::$attack_phases as $key => $val) {
            $result[$key] = [
                'name'       => $val['name'],
                'desc'       => $val['desc'],
                'weight'     => $val['weight'],
                'next_action'=> $val['next_action'],
            ];
        }
        return $result;
    }
}
