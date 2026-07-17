<?php
/**
 * L8 攻击链关联引擎
 * 职责：关联同一IP的多步攻击行为，构建攻击链，预判攻击路径，提前拦截。
 *       通过分析攻击者的行为序列，识别攻击模式和意图，实现前瞻性防御。
 *       攻击链关联是最高级别的语义分析，需要结合历史数据和实时行为。
 */
defined('ABSPATH') || exit;

class AttackChainAnalyzer {
    private static $chain_file = 'attack_chains.json';
    private static $max_chain_length = 20;
    private static $chain_expire_hours = 24;

    /**
     * 攻击链模式定义
     * 每项：chain_name => [描述, 阶段序列, 触发条件, 风险等级, 预判下一步]
     */
    private static $chain_patterns = [
        'sql_injection_chain' => [
            'name'        => 'SQL注入攻击链',
            'desc'        => '从探测到数据提取的完整SQL注入流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'attack', 'exploit'],
            'min_steps'   => 3,
            'risk_level'  => 'critical',
            'next_prediction' => ['union_attack', 'data_extraction', 'database_dump'],
        ],
        'xss_chain' => [
            'name'        => 'XSS攻击链',
            'desc'        => '从探测到脚本注入的XSS攻击流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'exploit'],
            'min_steps'   => 2,
            'risk_level'  => 'high',
            'next_prediction' => ['cookie_steal', 'session_hijack', 'defacement'],
        ],
        'rce_chain' => [
            'name'        => '远程命令执行攻击链',
            'desc'        => '从文件包含到命令执行的完整RCE流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'attack', 'exploit'],
            'min_steps'   => 3,
            'risk_level'  => 'critical',
            'next_prediction' => ['reverse_shell', 'data_exfiltration', 'persistence'],
        ],
        'path_traversal_chain' => [
            'name'        => '路径遍历攻击链',
            'desc'        => '从目录探测到敏感文件读取的流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'attack'],
            'min_steps'   => 2,
            'risk_level'  => 'high',
            'next_prediction' => ['etc_passwd', 'config_file_read', 'ssh_key'],
        ],
        'brute_force_chain' => [
            'name'        => '暴力破解攻击链',
            'desc'        => '从探测到认证绕过的暴力破解流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'attack'],
            'min_steps'   => 3,
            'risk_level'  => 'high',
            'next_prediction' => ['session_hijack', 'privilege_escalation'],
        ],
        'webshell_upload_chain' => [
            'name'        => 'Webshell上传攻击链',
            'desc'        => '从上传测试到后门部署的流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'attack', 'exploit'],
            'min_steps'   => 2,
            'risk_level'  => 'critical',
            'next_prediction' => ['reverse_shell', 'persistence', 'data_exfiltration'],
        ],
        'ddos_chain' => [
            'name'        => 'DDoS攻击链',
            'desc'        => '从探测到资源耗尽的攻击流程',
            'sequence'    => ['recon', 'probe', 'attack', 'exploit'],
            'min_steps'   => 2,
            'risk_level'  => 'medium',
            'next_prediction' => ['resource_exhaustion', 'service_disruption'],
        ],
        'privilege_escalation_chain' => [
            'name'        => '权限提升攻击链',
            'desc'        => '从普通用户到管理员权限的提升流程',
            'sequence'    => ['recon', 'probe', 'attempt', 'attack', 'exploit'],
            'min_steps'   => 3,
            'risk_level'  => 'critical',
            'next_prediction' => ['root_access', 'system_control', 'lateral_movement'],
        ],
    ];

    /**
     * 记录请求到攻击链
     *
     * @param string $ip 攻击者IP
     * @param string $uri 请求URI
     * @param array  $params 参数数组
     * @param string $attack_type 检测到的攻击类型
     * @param string $phase 攻击阶段
     * @param int    $score 风险分数
     */
    public static function recordRequest(string $ip, string $uri, array $params = [], string $attack_type = '', string $phase = '', int $score = 0): void {
        $chains = self::loadChains();
        $now = time();

        if (!isset($chains[$ip])) {
            $chains[$ip] = [
                'start_time' => $now,
                'last_activity' => $now,
                'requests' => [],
                'attack_types' => [],
                'phases' => [],
                'chain_detected' => null,
                'chain_progress' => 0,
                'predicted_next' => [],
            ];
        }

        $entry = [
            'time' => $now,
            'uri' => $uri,
            'params' => self::sanitizeParams($params),
            'attack_type' => $attack_type,
            'phase' => $phase,
            'score' => $score,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        ];

        $chains[$ip]['requests'][] = $entry;
        $chains[$ip]['last_activity'] = $now;

        if (!empty($attack_type)) {
            $chains[$ip]['attack_types'][$attack_type] = ($chains[$ip]['attack_types'][$attack_type] ?? 0) + 1;
        }
        if (!empty($phase)) {
            $chains[$ip]['phases'][$phase] = ($chains[$ip]['phases'][$phase] ?? 0) + 1;
        }

        // 限制请求数量
        if (count($chains[$ip]['requests']) > self::$max_chain_length) {
            $chains[$ip]['requests'] = array_slice($chains[$ip]['requests'], -self::$max_chain_length);
        }

        // 分析攻击链
        self::analyzeChain($chains[$ip]);

        self::saveChains($chains);
    }

    /**
     * 分析攻击链
     */
    private static function analyzeChain(array &$chain): void {
        $requests = $chain['requests'];
        $chain['chain_detected'] = null;
        $chain['chain_progress'] = 0;
        $chain['predicted_next'] = [];

        $phaseOrder = ['recon', 'probe', 'attempt', 'attack', 'exploit'];
        $currentPhaseIndex = -1;
        $phaseSequence = [];

        foreach ($requests as $req) {
            $phase = $req['phase'] ?? '';
            if (!empty($phase)) {
                $phaseSequence[] = $phase;
                $idx = array_search($phase, $phaseOrder);
                if ($idx !== false && $idx > $currentPhaseIndex) {
                    $currentPhaseIndex = $idx;
                }
            }
        }

        $chain['phase_sequence'] = $phaseSequence;
        $chain['current_phase_index'] = $currentPhaseIndex;

        $chain['chain_progress'] = min(100, (int)round(($currentPhaseIndex + 1) / count($phaseOrder) * 100));

        foreach (self::$chain_patterns as $chainKey => $pattern) {
            $matchedSteps = 0;
            $seq = $pattern['sequence'];
            $currentSeqIdx = 0;

            foreach ($phaseSequence as $phase) {
                if ($currentSeqIdx < count($seq) && $phase === $seq[$currentSeqIdx]) {
                    $matchedSteps++;
                    $currentSeqIdx++;
                }
            }

            if ($matchedSteps >= $pattern['min_steps']) {
                $chain['chain_detected'] = $chainKey;
                $chain['chain_name'] = $pattern['name'];
                $chain['chain_desc'] = $pattern['desc'];
                $chain['chain_risk'] = $pattern['risk_level'];
                $chain['predicted_next'] = $pattern['next_prediction'];
                break;
            }
        }
    }

    /**
     * 获取IP的攻击链信息
     */
    public static function getChain(string $ip): array {
        $chains = self::loadChains();
        return $chains[$ip] ?? [
            'start_time' => 0,
            'last_activity' => 0,
            'requests' => [],
            'attack_types' => [],
            'phases' => [],
            'chain_detected' => null,
            'chain_progress' => 0,
            'predicted_next' => [],
            'phase_sequence' => [],
            'current_phase_index' => -1,
        ];
    }

    /**
     * 判断是否应该提前拦截
     */
    public static function shouldBlockEarly(string $ip): bool {
        $chain = self::getChain($ip);
        if (!$chain['chain_detected']) return false;

        $riskMap = ['critical' => 80, 'high' => 70, 'medium' => 60];
        $threshold = $riskMap[$chain['chain_risk']] ?? 60;

        return $chain['chain_progress'] >= 40 && $chain['chain_risk'] !== 'medium';
    }

    /**
     * 获取攻击链预测
     */
    public static function getPrediction(string $ip): array {
        $chain = self::getChain($ip);
        return [
            'chain_detected' => $chain['chain_detected'],
            'chain_name' => $chain['chain_name'] ?? '',
            'chain_risk' => $chain['chain_risk'] ?? 'none',
            'chain_progress' => $chain['chain_progress'],
            'predicted_next' => $chain['predicted_next'],
            'current_phase_index' => $chain['current_phase_index'],
            'phase_sequence' => $chain['phase_sequence'],
            'total_requests' => count($chain['requests']),
            'attack_types' => $chain['attack_types'],
            'start_time' => $chain['start_time'],
            'last_activity' => $chain['last_activity'],
        ];
    }

    /**
     * 清理过期攻击链
     */
    public static function cleanupExpired(): void {
        $chains = self::loadChains();
        $expireTime = time() - self::$chain_expire_hours * 3600;
        $changed = false;

        foreach ($chains as $ip => $chain) {
            if ($chain['last_activity'] < $expireTime) {
                unset($chains[$ip]);
                $changed = true;
            }
        }

        if ($changed) {
            self::saveChains($chains);
        }
    }

    /**
     * 清除IP的攻击链记录
     */
    public static function clearChain(string $ip): void {
        $chains = self::loadChains();
        if (isset($chains[$ip])) {
            unset($chains[$ip]);
            self::saveChains($chains);
        }
    }

    /**
     * 获取所有活跃攻击链
     */
    public static function getAllChains(): array {
        $chains = self::loadChains();
        self::cleanupExpired();
        return $chains;
    }

    /**
     * 获取链文件路径
     */
    private static function getChainFilePath(): string {
        $dir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : __DIR__ . '/../waf_logs/';
        $dir = rtrim($dir, '/\\') . '/';
        $realDir = realpath($dir);
        if ($realDir === false) {
            if (!mkdir($dir, 0700, true)) {
                error_log("AttackChainAnalyzer: 无法创建日志目录: $dir");
                return '';
            }
            $realDir = realpath($dir);
        }
        if ($realDir === false || !is_writable($realDir)) {
            error_log("AttackChainAnalyzer: 日志目录不可写: $dir");
            return '';
        }
        return $realDir . '/' . self::$chain_file;
    }

    /**
     * 加载攻击链数据
     */
    private static function loadChains(): array {
        $file = self::getChainFilePath();
        if ($file === '' || !is_file($file)) return [];
        $content = @file_get_contents($file);
        if ($content === false) {
            error_log("AttackChainAnalyzer: 无法读取攻击链文件: $file");
            return [];
        }
        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("AttackChainAnalyzer: 攻击链文件JSON解析错误: " . json_last_error_msg());
            return [];
        }
        return is_array($data) ? $data : [];
    }

    /**
     * 保存攻击链数据
     */
    private static function saveChains(array $chains): void {
        $file = self::getChainFilePath();
        if ($file === '') return;
        $result = @file_put_contents($file, json_encode($chains), LOCK_EX);
        if ($result === false) {
            error_log("AttackChainAnalyzer: 无法写入攻击链文件: $file");
        }
    }

    /**
     * 清理参数（避免存储敏感信息）
     */
    private static function sanitizeParams(array $params): array {
        $sanitized = [];
        $sensitiveKeys = ['password', 'passwd', 'pwd', 'token', 'secret', 'api_key', 'credit_card'];
        foreach ($params as $k => $v) {
            $lowerK = strtolower($k);
            if (in_array($lowerK, $sensitiveKeys)) {
                $sanitized[$k] = '***REDACTED***';
            } else {
                $sanitized[$k] = strlen($v) > 100 ? substr($v, 0, 100) . '...' : $v;
            }
        }
        return $sanitized;
    }

    /**
     * 获取所有攻击链模式定义
     */
    public static function getAllChainPatterns(): array {
        return self::$chain_patterns;
    }
}
