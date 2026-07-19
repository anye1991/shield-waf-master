<?php
/**
 * 攻击路径预判引擎
 * 职责：建立攻击者心理模型，预判其下一步行动路径。
 *       通过分析当前攻击阶段、已使用的攻击方法、目标系统特征，
 *       预测攻击者接下来最可能访问的路径和使用的技术。
 *       核心理念：不追着攻击者跑，而是在必经之路设防。
 */
defined('ABSPATH') || exit;

class AttackPathPredictor {
    /**
     * 攻击路径图定义
     * 每个阶段 => 可能的下一步路径列表（按概率排序）
     */
    private static $attack_graph = [
        'recon' => [
            'next_paths' => [
                ['path' => '/robots.txt', 'prob' => 85, 'desc' => '获取站点地图'],
                ['path' => '/sitemap.xml', 'prob' => 70, 'desc' => '获取站点结构'],
                ['path' => '/.git/', 'prob' => 65, 'desc' => 'Git泄露'],
                ['path' => '/.svn/', 'prob' => 50, 'desc' => 'SVN泄露'],
                ['path' => '/phpinfo.php', 'prob' => 60, 'desc' => '环境探测'],
                ['path' => '/admin/', 'prob' => 55, 'desc' => '管理后台探测'],
                ['path' => '/wp-admin/', 'prob' => 50, 'desc' => 'WordPress后台'],
                ['path' => '/pma/', 'prob' => 45, 'desc' => 'phpMyAdmin'],
                ['path' => '/info.php', 'prob' => 40, 'desc' => '信息页'],
                ['path' => '/config.php', 'prob' => 35, 'desc' => '配置文件'],
            ],
            'next_params' => [
                ['key' => 'id', 'prob' => 80, 'desc' => 'ID参数注入'],
                ['key' => 'page', 'prob' => 70, 'desc' => '页面参数'],
                ['key' => 'file', 'prob' => 60, 'desc' => '文件参数'],
                ['key' => 'url', 'prob' => 55, 'desc' => 'URL参数'],
                ['key' => 'action', 'prob' => 50, 'desc' => '动作参数'],
            ],
        ],
        'probe' => [
            'next_paths' => [
                ['path' => '?id=1', 'prob' => 90, 'desc' => 'SQL注入测试'],
                ['path' => '?id=1%27', 'prob' => 85, 'desc' => '单引号测试'],
                ['path' => '?id=1%20or%201=1', 'prob' => 80, 'desc' => '恒真式测试'],
                ['path' => '?id=1%20union%20select', 'prob' => 75, 'desc' => 'UNION测试'],
                ['path' => '../etc/passwd', 'prob' => 65, 'desc' => '路径遍历'],
                ['path' => '?cmd=whoami', 'prob' => 60, 'desc' => '命令执行'],
                ['path' => '<script>alert(1)</script>', 'prob' => 70, 'desc' => 'XSS测试'],
                ['path' => '?file=index.php', 'prob' => 55, 'desc' => '文件包含'],
            ],
            'next_params' => [
                ['key' => 'id', 'prob' => 95, 'desc' => 'ID注入'],
                ['key' => 'search', 'prob' => 75, 'desc' => '搜索注入'],
                ['key' => 'q', 'prob' => 70, 'desc' => '查询注入'],
                ['key' => 'username', 'prob' => 65, 'desc' => '用户名注入'],
                ['key' => 'email', 'prob' => 60, 'desc' => '邮箱注入'],
            ],
        ],
        'attempt' => [
            'next_paths' => [
                ['path' => '?id=1 union select 1,2,3', 'prob' => 85, 'desc' => '完整UNION注入'],
                ['path' => '?id=1 union select 1,version(),3', 'prob' => 80, 'desc' => '版本获取'],
                ['path' => '?id=1 union select 1,group_concat(table_name),3', 'prob' => 75, 'desc' => '表名获取'],
                ['path' => '?id=1 union select 1,group_concat(column_name),3', 'prob' => 70, 'desc' => '列名获取'],
                ['path' => '?id=1 sleep(5)', 'prob' => 65, 'desc' => '时间盲注'],
                ['path' => '?id=1 updatexml(1,concat(0x7e,version()),1)', 'prob' => 60, 'desc' => '报错注入'],
                ['path' => '?file=../../etc/passwd', 'prob' => 70, 'desc' => '路径遍历攻击'],
                ['path' => '?cmd=ls%20-la', 'prob' => 60, 'desc' => '命令执行'],
            ],
            'next_params' => [
                ['key' => 'id', 'prob' => 95, 'desc' => 'ID注入'],
                ['key' => 'username', 'prob' => 80, 'desc' => '认证绕过'],
                ['key' => 'password', 'prob' => 75, 'desc' => '密码爆破'],
                ['key' => 'file', 'prob' => 70, 'desc' => '文件包含'],
                ['key' => 'url', 'prob' => 65, 'desc' => 'SSRF'],
            ],
        ],
        'attack' => [
            'next_paths' => [
                ['path' => '/admin/login.php', 'prob' => 85, 'desc' => '后台登录'],
                ['path' => '/wp-admin/admin-ajax.php', 'prob' => 70, 'desc' => 'WP AJAX'],
                ['path' => '/phpmyadmin/', 'prob' => 65, 'desc' => '数据库管理'],
                ['path' => '/uploads/', 'prob' => 60, 'desc' => '上传目录'],
                ['path' => '/shell.php', 'prob' => 80, 'desc' => 'Webshell'],
                ['path' => '/backdoor.php', 'prob' => 75, 'desc' => '后门'],
            ],
            'next_params' => [
                ['key' => 'admin', 'prob' => 85, 'desc' => '管理员参数'],
                ['key' => 'token', 'prob' => 80, 'desc' => 'Token窃取'],
                ['key' => 'session', 'prob' => 75, 'desc' => '会话劫持'],
                ['key' => 'user_id', 'prob' => 70, 'desc' => '用户ID篡改'],
            ],
        ],
        'exploit' => [
            'next_paths' => [
                ['path' => '/etc/passwd', 'prob' => 90, 'desc' => '获取密码文件'],
                ['path' => '/root/.ssh/id_rsa', 'prob' => 80, 'desc' => 'SSH密钥'],
                ['path' => '/var/www/html/config.php', 'prob' => 75, 'desc' => '数据库配置'],
                ['path' => '/etc/cron.d/', 'prob' => 70, 'desc' => '定时任务'],
                ['path' => '/proc/self/environ', 'prob' => 65, 'desc' => '环境变量'],
                ['path' => '/dev/tcp/', 'prob' => 60, 'desc' => '反向Shell'],
            ],
            'next_params' => [
                ['key' => 'cmd', 'prob' => 95, 'desc' => '命令执行'],
                ['key' => 'exec', 'prob' => 90, 'desc' => '执行函数'],
                ['key' => 'eval', 'prob' => 85, 'desc' => '代码执行'],
            ],
        ],
    ];

    /**
     * 攻击者心理模型
     */
    private static $attacker_profiles = [
        'script_kiddie' => [
            'name' => '脚本小子',
            'probability' => 40,
            'behavior' => ['uses_common_payloads', 'no_customization', 'quick_give_up'],
            'prediction_strategy' => 'follow_standard_paths',
            'confidence_modifier' => 0.7,
        ],
        'automated_scanner' => [
            'name' => '自动化扫描器',
            'probability' => 35,
            'behavior' => ['high_frequency', 'systematic', 'pattern_repeat'],
            'prediction_strategy' => 'follow_pattern',
            'confidence_modifier' => 0.9,
        ],
        'advanced_attacker' => [
            'name' => '高级攻击者',
            'probability' => 15,
            'behavior' => ['custom_payloads', 'slow_attack', 'context_aware'],
            'prediction_strategy' => 'diversify_paths',
            'confidence_modifier' => 0.6,
        ],
        'APT' => [
            'name' => 'APT组织',
            'probability' => 5,
            'behavior' => ['very_slow', 'stealthy', 'long_term'],
            'prediction_strategy' => 'unpredictable',
            'confidence_modifier' => 0.3,
        ],
        'penetration_tester' => [
            'name' => '渗透测试员',
            'probability' => 5,
            'behavior' => ['methodical', 'ethical', 'documented'],
            'prediction_strategy' => 'follow_standard_paths',
            'confidence_modifier' => 0.8,
        ],
    ];

    /**
     * 攻击类型与路径映射
     */
    private static $attack_type_paths = [
        'sql_injection' => [
            ['path' => '?id=', 'prob' => 90],
            ['path' => '?search=', 'prob' => 80],
            ['path' => '?q=', 'prob' => 75],
            ['path' => '?username=', 'prob' => 70],
            ['path' => '?email=', 'prob' => 65],
            ['path' => '?page=', 'prob' => 60],
        ],
        'xss' => [
            ['path' => '?name=', 'prob' => 85],
            ['path' => '?title=', 'prob' => 80],
            ['path' => '?message=', 'prob' => 75],
            ['path' => '?content=', 'prob' => 70],
            ['path' => '?comment=', 'prob' => 65],
        ],
        'path_traversal' => [
            ['path' => '?file=', 'prob' => 90],
            ['path' => '?path=', 'prob' => 85],
            ['path' => '?dir=', 'prob' => 80],
            ['path' => '?include=', 'prob' => 75],
            ['path' => '?view=', 'prob' => 70],
        ],
        'command_execution' => [
            ['path' => '?cmd=', 'prob' => 95],
            ['path' => '?exec=', 'prob' => 90],
            ['path' => '?command=', 'prob' => 85],
            ['path' => '?shell=', 'prob' => 80],
        ],
        'file_upload' => [
            ['path' => '/upload', 'prob' => 90],
            ['path' => '/file/upload', 'prob' => 85],
            ['path' => '/api/upload', 'prob' => 80],
        ],
        'ssrf' => [
            ['path' => '?url=', 'prob' => 95],
            ['path' => '?link=', 'prob' => 85],
            ['path' => '?proxy=', 'prob' => 80],
            ['path' => '?redirect=', 'prob' => 75],
        ],
        'brute_force' => [
            ['path' => '/login', 'prob' => 95],
            ['path' => '/signin', 'prob' => 90],
            ['path' => '/auth', 'prob' => 85],
            ['path' => '/wp-login.php', 'prob' => 80],
        ],
    ];

    /**
     * 预测攻击路径
     *
     * @param string $attack_phase 当前攻击阶段
     * @param string $attack_type 当前攻击类型
     * @param string $uri 当前URI
     * @param array $history 历史请求记录
     * @param string $ip 请求IP
     * @return array{predicted_paths:array, predicted_params:array, attacker_profile:string, confidence:int, recommendations:array}
     */
    public static function predict(
        string $attack_phase = 'none',
        string $attack_type = '',
        string $uri = '',
        array $history = [],
        string $ip = ''
    ): array {
        $predictedPaths = [];
        $predictedParams = [];
        $attackerProfile = 'unknown';
        $confidence = 0;
        $recommendations = [];

        // ---- 1. 基于攻击阶段预测 ----
        if ($attack_phase !== 'none' && isset(self::$attack_graph[$attack_phase])) {
            $graph = self::$attack_graph[$attack_phase];
            $predictedPaths = array_merge($predictedPaths, $graph['next_paths'] ?? []);
            $predictedParams = array_merge($predictedParams, $graph['next_params'] ?? []);
            $confidence += 30;
        }

        // ---- 2. 基于攻击类型预测 ----
        if (!empty($attack_type) && isset(self::$attack_type_paths[$attack_type])) {
            $typePaths = self::$attack_type_paths[$attack_type];
            foreach ($typePaths as $tp) {
                $exists = false;
                foreach ($predictedPaths as &$pp) {
                    if ($pp['path'] === $tp['path']) {
                        $exists = true;
                        $pp['prob'] = min(100, $pp['prob'] + $tp['prob'] / 2);
                        break;
                    }
                }
                unset($pp); // 解除引用
                if (!$exists) {
                    $predictedPaths[] = ['path' => $tp['path'], 'prob' => $tp['prob'], 'desc' => $attack_type . '路径'];
                }
            }
            $confidence += 25;
        }

        // ---- 3. 基于历史行为预测 ----
        if (!empty($history)) {
            $historyBased = self::predictFromHistory($history);
            foreach ($historyBased as $hb) {
                $exists = false;
                foreach ($predictedPaths as &$pp) {
                    if ($pp['path'] === $hb['path']) {
                        $exists = true;
                        $pp['prob'] = min(100, $pp['prob'] + 15);
                        break;
                    }
                }
                unset($pp); // 解除引用
                if (!$exists) {
                    $predictedPaths[] = ['path' => $hb['path'], 'prob' => $hb['prob'], 'desc' => '历史推断'];
                }
            }
            $confidence += 15;
        }

        // ---- 4. 识别攻击者画像 ----
        $profile = self::identifyAttackerProfile($history, $ip);
        $attackerProfile = $profile['profile'];
        $profileName = self::$attacker_profiles[$attackerProfile]['name'] ?? '未知';
        $confidence = (int)round($confidence * (self::$attacker_profiles[$attackerProfile]['confidence_modifier'] ?? 0.5));

        // ---- 5. 排序并筛选高概率路径 ----
        usort($predictedPaths, function($a, $b) {
            return $b['prob'] - $a['prob'];
        });

        usort($predictedParams, function($a, $b) {
            return $b['prob'] - $a['prob'];
        });

        $predictedPaths = array_slice($predictedPaths, 0, 10);
        $predictedParams = array_slice($predictedParams, 0, 8);

        // ---- 6. 生成防御建议 ----
        $recommendations = self::generateRecommendations($predictedPaths, $predictedParams, $attack_phase, $attackerProfile);

        return [
            'predicted_paths' => $predictedPaths,
            'predicted_params' => $predictedParams,
            'attacker_profile' => $attackerProfile,
            'attacker_profile_name' => $profileName,
            'confidence' => $confidence,
            'recommendations' => $recommendations,
            'total_predictions' => count($predictedPaths) + count($predictedParams),
        ];
    }

    /**
     * 从历史行为预测
     */
    private static function predictFromHistory(array $history): array {
        $paths = [];
        $seenPaths = [];
        $seenParams = [];

        foreach ($history as $req) {
            $uri = $req['uri'] ?? '';
            $params = $req['params'] ?? [];

            $seenPaths[] = $uri;
            foreach ($params as $k => $v) {
                $seenParams[$k] = ($seenParams[$k] ?? 0) + 1;
            }
        }

        $predictions = [];

        // 如果访问了 /admin/ 则可能访问 /admin/login/
        if (in_array('/admin/', $seenPaths) || in_array('/admin', $seenPaths)) {
            $predictions[] = ['path' => '/admin/login', 'prob' => 80];
            $predictions[] = ['path' => '/admin/dashboard', 'prob' => 70];
        }

        // 如果访问了 /wp-admin/ 则可能访问 wp-login.php
        if (strpos(implode(',', $seenPaths), '/wp-admin/') !== false) {
            $predictions[] = ['path' => '/wp-login.php', 'prob' => 85];
            $predictions[] = ['path' => '/wp-admin/admin-ajax.php', 'prob' => 70];
        }

        // 如果测试了 id 参数，则可能测试其他参数
        if (isset($seenParams['id'])) {
            foreach (['page', 'file', 'url', 'action'] as $p) {
                if (!isset($seenParams[$p])) {
                    $predictions[] = ['path' => "?$p=", 'prob' => 60];
                }
            }
        }

        return $predictions;
    }

    /**
     * 识别攻击者画像
     */
    private static function identifyAttackerProfile(array $history, string $ip): array {
        $totalRequests = count($history);
        $requestInterval = 0;
        $payloadDiversity = [];
        $attackPatterns = [];

        if ($totalRequests >= 2) {
            $timestamps = array_column($history, 'timestamp');
            $intervals = [];
            for ($i = 1; $i < $totalRequests; $i++) {
                $intervals[] = $timestamps[$i] - $timestamps[$i-1];
            }
            $requestInterval = array_sum($intervals) / count($intervals);
        }

        foreach ($history as $req) {
            $payload = ($req['params'] ?? []) + ['uri' => $req['uri'] ?? ''];
            foreach ($payload as $k => $v) {
                $hash = md5((string)$v);
                $payloadDiversity[$hash] = true;
            }
            $attackPatterns[$req['attack_type'] ?? 'unknown'] = true;
        }

        $diversity = count($payloadDiversity);
        $patterns = count($attackPatterns);

        // 自动化扫描器：高频、低多样性、固定模式
        if ($requestInterval < 2 && $totalRequests >= 10 && $diversity < 5) {
            return ['profile' => 'automated_scanner', 'reason' => '高频低多样性'];
        }

        // 脚本小子：中等频率、标准payload、快速放弃
        if ($requestInterval >= 2 && $requestInterval <= 30 && $diversity < 10 && $patterns <= 2) {
            return ['profile' => 'script_kiddie', 'reason' => '标准payload模式'];
        }

        // 高级攻击者：低频、高多样性、多种攻击模式
        if ($requestInterval > 30 && $totalRequests >= 5 && $diversity >= 10 && $patterns >= 3) {
            return ['profile' => 'advanced_attacker', 'reason' => '高多样性多模式'];
        }

        // APT：极低频率、极长时间跨度、隐身
        if ($totalRequests > 0 && $requestInterval > 300) {
            return ['profile' => 'APT', 'reason' => '极低频长时间'];
        }

        return ['profile' => 'script_kiddie', 'reason' => '默认推断'];
    }

    /**
     * 生成防御建议
     */
    private static function generateRecommendations(array $paths, array $params, string $phase, string $profile): array {
        $recommendations = [];

        // 针对预测路径建立防护
        if (!empty($paths)) {
            $recommendations[] = "在以下路径加强防护: " . implode(', ', array_map(function($p) { return $p['path']; }, array_slice($paths, 0, 5)));
        }

        // 针对预测参数建立防护
        if (!empty($params)) {
            $recommendations[] = "重点监控以下参数: " . implode(', ', array_map(function($p) { return $p['key']; }, array_slice($params, 0, 5)));
        }

        // 根据攻击者画像调整策略
        if ($profile === 'automated_scanner') {
            $recommendations[] = '检测到自动化扫描器，建议启用速率限制和验证码';
        } elseif ($profile === 'advanced_attacker') {
            $recommendations[] = '检测到高级攻击者，建议加强日志监控和实时告警';
        } elseif ($profile === 'APT') {
            $recommendations[] = '检测到疑似APT，建议立即通知安全团队';
        }

        // 根据攻击阶段调整策略
        if ($phase === 'recon') {
            $recommendations[] = '侦察阶段，建议隐藏敏感信息，禁用信息泄露';
        } elseif ($phase === 'probe') {
            $recommendations[] = '探测阶段，建议启用输入验证和异常检测';
        } elseif ($phase === 'attempt') {
            $recommendations[] = '尝试阶段，建议加强语义分析和编码归一化';
        } elseif ($phase === 'attack') {
            $recommendations[] = '攻击阶段，建议立即拦截并记录详细日志';
        } elseif ($phase === 'exploit') {
            $recommendations[] = '利用阶段，建议立即封禁IP并启动应急响应';
        }

        return $recommendations;
    }

    /**
     * 获取所有攻击路径图
     */
    public static function getAttackGraph(): array {
        return self::$attack_graph;
    }

    /**
     * 获取所有攻击者画像
     */
    public static function getAttackerProfiles(): array {
        return self::$attacker_profiles;
    }
}
