<?php
/**
 * 主动防御引擎
 * 职责：在预判路径上提前布防，围追堵截攻击者。
 *       核心理念：不追着攻击者跑，而是在必经之路设防。
 *       实现：预判路径拦截 + 蜜罐部署 + 自动封禁 + 动态调整。
 */
defined('ABSPATH') || exit;

class ActiveDefense {
    private static $honey_file = 'honeytraps.json';
    private static $block_file = 'active_blocks.json';
    private static $honey_expire_hours = 24;
    private static $block_expire_hours = 72;

    /**
     * 蜜罐模板
     */
    private static $honey_templates = [
        'fake_admin' => [
            'name' => '虚假管理后台',
            'paths' => ['/admin/', '/admin/login', '/admin/index.php', '/manage/', '/dashboard/'],
            'response' => '<html><body><h1>管理后台登录</h1><form><input name="username"><input name="password" type="password"><button>登录</button></form></body></html>',
            'response_code' => 200,
            'log_message' => '访问虚假管理后台',
        ],
        'fake_pma' => [
            'name' => '虚假phpMyAdmin',
            'paths' => ['/pma/', '/phpmyadmin/', '/phpMyAdmin/', '/mysql/'],
            'response' => '<html><body><h1>phpMyAdmin</h1><form><input name="pma_username"><input name="pma_password" type="password"><button>登录</button></form></body></html>',
            'response_code' => 200,
            'log_message' => '访问虚假phpMyAdmin',
        ],
        'fake_git' => [
            'name' => '虚假Git仓库',
            'paths' => ['/.git/', '/.git/HEAD', '/.git/config'],
            'response' => 'ref: refs/heads/master',
            'response_code' => 200,
            'log_message' => '访问虚假Git仓库',
        ],
        'fake_svn' => [
            'name' => '虚假SVN仓库',
            'paths' => ['/.svn/', '/.svn/entries'],
            'response' => '<?xml version="1.0"?>',
            'response_code' => 200,
            'log_message' => '访问虚假SVN仓库',
        ],
        'fake_config' => [
            'name' => '虚假配置文件',
            'paths' => ['/config.php', '/wp-config.php', '/database.yml', '/.env'],
            'response' => "<?php\n\$db_host = 'localhost';\n\$db_user = 'root';\n\$db_pass = 'password';\n?>",
            'response_code' => 200,
            'log_message' => '访问虚假配置文件',
        ],
        'fake_phpinfo' => [
            'name' => '虚假phpinfo',
            'paths' => ['/phpinfo.php', '/info.php', '/info'],
            'response' => '<html><body><h1>PHP Version 8.0.0</h1></body></html>',
            'response_code' => 200,
            'log_message' => '访问虚假phpinfo',
        ],
        'fake_upload' => [
            'name' => '虚假上传接口',
            'paths' => ['/upload', '/api/upload', '/file/upload', '/upload.php'],
            'response' => '{"status":"success","message":"文件上传成功"}',
            'response_code' => 200,
            'log_message' => '访问虚假上传接口',
        ],
        'fake_ssh_key' => [
            'name' => '虚假SSH密钥',
            'paths' => ['/ssh/id_rsa', '/.ssh/id_rsa', '/root/.ssh/id_rsa'],
            'response' => '-----BEGIN RSA PRIVATE KEY-----',
            'response_code' => 200,
            'log_message' => '尝试获取SSH密钥',
        ],
    ];

    /**
     * 主动防御主入口
     *
     * @param string $uri 请求URI
     * @param string $ip 请求IP
     * @param array $prediction 路径预测结果
     * @param array $semanticResult 语义分析结果
     * @param array $attackChain 攻击链信息
     * @return array{action:string, reason:string, blocked:bool, honeytrap:bool, recommendation:string}
     */
    public static function defend(
        string $uri,
        string $ip,
        array $prediction = [],
        array $semanticResult = [],
        array $attackChain = []
    ): array {
        $action = 'allow';
        $reason = '';
        $blocked = false;
        $honeytrap = false;
        $recommendation = '';

        // ---- 1. 蜜罐检测 ----
        $honeyResult = self::checkHoneytrap($uri, $ip);
        if ($honeyResult['triggered']) {
            $action = 'block';
            $reason = $honeyResult['reason'];
            $blocked = true;
            $honeytrap = true;
            $recommendation = '蜜罐触发，立即封禁';
            self::autoBlock($ip, 'honeytrap', $honeyResult['honey_name'], 3600 * 24 * 7);
            return compact('action', 'reason', 'blocked', 'honeytrap', 'recommendation');
        }

        // ---- 2. 预判路径拦截 ----
        $predictResult = self::checkPredictedPaths($uri, $ip, $prediction);
        if ($predictResult['block']) {
            $action = 'block';
            $reason = $predictResult['reason'];
            $blocked = true;
            $recommendation = '预判路径拦截';
            self::autoBlock($ip, 'predicted_path', $predictResult['path'], 3600 * 24);
            return compact('action', 'reason', 'blocked', 'honeytrap', 'recommendation');
        }

        // ---- 3. 攻击链提前拦截 ----
        $chainResult = self::checkAttackChain($ip, $attackChain);
        if ($chainResult['block']) {
            $action = 'block';
            $reason = $chainResult['reason'];
            $blocked = true;
            $recommendation = '攻击链提前拦截';
            self::autoBlock($ip, 'attack_chain', $chainResult['chain_name'], 3600 * 24 * 3);
            return compact('action', 'reason', 'blocked', 'honeytrap', 'recommendation');
        }

        // ---- 4. 阶段进阶拦截 ----
        $phaseResult = self::checkPhaseAdvance($ip, $semanticResult);
        if ($phaseResult['block']) {
            $action = 'block';
            $reason = $phaseResult['reason'];
            $blocked = true;
            $recommendation = '阶段进阶拦截';
            self::autoBlock($ip, 'phase_advance', $phaseResult['phase'], 3600 * 24);
            return compact('action', 'reason', 'blocked', 'honeytrap', 'recommendation');
        }

        // ---- 5. 可疑行为监控 ----
        $monitorResult = self::checkSuspiciousBehavior($ip, $semanticResult);
        if ($monitorResult['monitor']) {
            $action = 'monitor';
            $reason = $monitorResult['reason'];
            $recommendation = '加强监控';
        }

        return compact('action', 'reason', 'blocked', 'honeytrap', 'recommendation');
    }

    /**
     * 检查蜜罐触发
     */
    private static function checkHoneytrap(string $uri, string $ip): array {
        foreach (self::$honey_templates as $key => $template) {
            foreach ($template['paths'] as $path) {
                if (stripos($uri, $path) === 0 || $uri === $path) {
                    self::logHoneytrap($ip, $uri, $template['name']);
                    return [
                        'triggered' => true,
                        'reason' => "触发蜜罐: {$template['name']} (路径: {$path})",
                        'honey_name' => $template['name'],
                        'honey_key' => $key,
                    ];
                }
            }
        }
        return ['triggered' => false];
    }

    /**
     * 检查预判路径
     */
    private static function checkPredictedPaths(string $uri, string $ip, array $prediction): array {
        $predictedPaths = $prediction['predicted_paths'] ?? [];
        if (empty($predictedPaths)) return ['block' => false];

        foreach ($predictedPaths as $pp) {
            if ($pp['prob'] >= 60) {
                if (stripos($uri, $pp['path']) !== false) {
                    return [
                        'block' => true,
                        'reason' => "命中高概率预判路径: {$pp['path']} (概率: {$pp['prob']}%)",
                        'path' => $pp['path'],
                        'probability' => $pp['prob'],
                    ];
                }
            }
        }

        return ['block' => false];
    }

    /**
     * 检查攻击链
     */
    private static function checkAttackChain(string $ip, array $attackChain): array {
        if (empty($attackChain['chain_detected'])) return ['block' => false];

        $chainProgress = $attackChain['chain_progress'] ?? 0;
        $chainRisk = $attackChain['chain_risk'] ?? '';

        // 攻击链进度超过40%且风险为critical或high => 提前拦截
        if ($chainProgress >= 40 && in_array($chainRisk, ['critical', 'high'])) {
            return [
                'block' => true,
                'reason' => "攻击链检测: {$attackChain['chain_name']} (进度: {$chainProgress}%, 风险: {$chainRisk})",
                'chain_name' => $attackChain['chain_name'],
                'chain_progress' => $chainProgress,
            ];
        }

        return ['block' => false];
    }

    /**
     * 检查阶段进阶
     */
    private static function checkPhaseAdvance(string $ip, array $semanticResult): array {
        $attackPhase = $semanticResult['attack_phase'] ?? 'none';
        $phaseOrder = ['none', 'recon', 'probe', 'attempt', 'attack', 'exploit'];
        $currentIndex = array_search($attackPhase, $phaseOrder);

        if ($currentIndex === false) return ['block' => false];

        // 如果直接跳到攻击或利用阶段 => 可能是高级攻击，立即拦截
        if ($currentIndex >= 4) {
            return [
                'block' => true,
                'reason' => "直接进入攻击阶段: {$attackPhase}",
                'phase' => $attackPhase,
            ];
        }

        // 阶段跳变（跳过中间阶段）
        $recentPhase = self::getRecentPhase($ip);
        if ($recentPhase !== null) {
            $recentIndex = array_search($recentPhase, $phaseOrder);
            if ($recentIndex !== false && $currentIndex > $recentIndex + 1) {
                return [
                    'block' => true,
                    'reason' => "阶段跳变: {$recentPhase} -> {$attackPhase} (跳过中间阶段)",
                    'phase' => $attackPhase,
                    'previous_phase' => $recentPhase,
                ];
            }
        }

        return ['block' => false];
    }

    /**
     * 检查可疑行为
     */
    private static function checkSuspiciousBehavior(string $ip, array $semanticResult): array {
        $adversarialScore = $semanticResult['l10_adversarial_score'] ?? 0;
        $memoryScore = $semanticResult['l9_memory_score'] ?? 0;

        if ($adversarialScore >= 40 || $memoryScore >= 40) {
            return [
                'monitor' => true,
                'reason' => "可疑行为检测 (对抗分数: {$adversarialScore}, 记忆异常: {$memoryScore})",
            ];
        }

        return ['monitor' => false];
    }

    /**
     * 自动封禁IP
     */
    public static function autoBlock(string $ip, string $reason, string $detail = '', int $seconds = 86400) {
        $blocks = self::loadBlocks();
        $now = time();

        if (!isset($blocks[$ip])) {
            $blocks[$ip] = [
                'first_block' => $now,
                'block_count' => 0,
                'reasons' => [],
            ];
        }

        $blocks[$ip]['last_block'] = $now;
        $blocks[$ip]['block_count']++;
        $blocks[$ip]['reasons'][] = [
            'time' => $now,
            'reason' => $reason,
            'detail' => $detail,
            'duration' => $seconds,
        ];

        // 累进惩罚：封禁次数越多，封禁时间越长
        $multiplier = min(10, $blocks[$ip]['block_count']);
        $actualSeconds = $seconds * $multiplier;
        $blocks[$ip]['expire_time'] = $now + $actualSeconds;

        self::saveBlocks($blocks);

        // 同时添加到IP管理器的封禁列表
        if (function_exists('waf_ban')) {
            waf_ban($ip, $actualSeconds);
        }
    }

    /**
     * 检查IP是否被主动封禁
     */
    public static function isBlocked(string $ip): bool {
        $blocks = self::loadBlocks();
        if (!isset($blocks[$ip])) return false;

        if ($blocks[$ip]['expire_time'] > time()) {
            return true;
        }

        // 清理过期记录
        unset($blocks[$ip]);
        self::saveBlocks($blocks);
        return false;
    }

    /**
     * 获取主动封禁列表
     */
    public static function getBlocks(): array {
        $blocks = self::loadBlocks();
        $now = time();
        $active = [];

        foreach ($blocks as $ip => $info) {
            if ($info['expire_time'] > $now) {
                $active[$ip] = $info;
            }
        }

        return $active;
    }

    /**
     * 解封IP
     */
    public static function unblock(string $ip) {
        $blocks = self::loadBlocks();
        if (isset($blocks[$ip])) {
            unset($blocks[$ip]);
            self::saveBlocks($blocks);
        }
    }

    /**
     * 清理过期封禁记录
     */
    public static function cleanup() {
        $blocks = self::loadBlocks();
        $now = time();
        $changed = false;

        foreach ($blocks as $ip => $info) {
            if ($info['expire_time'] < $now - self::$block_expire_hours * 3600) {
                unset($blocks[$ip]);
                $changed = true;
            }
        }

        if ($changed) {
            self::saveBlocks($blocks);
        }
    }

    /**
     * 获取最近攻击阶段
     */
    private static function getRecentPhase(string $ip): ?string {
        if (!class_exists('SemanticMemoryPool')) return null;

        $profile = SemanticMemoryPool::getProfile($ip);
        if (!$profile['exists']) return null;

        $fps = $profile['phase_distribution'] ?? [];
        arsort($fps);
        $topPhase = !empty($fps) ? key($fps) : null;

        return $topPhase === 'none' ? null : $topPhase;
    }

    /**
     * 记录蜜罐触发
     */
    private static function logHoneytrap(string $ip, string $uri, string $honeyName) {
        $honeyData = self::loadHoneytraps();
        if (!isset($honeyData[$ip])) {
            $honeyData[$ip] = [];
        }

        $honeyData[$ip][] = [
            'time' => time(),
            'uri' => $uri,
            'honey_name' => $honeyName,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ];

        self::saveHoneytraps($honeyData);
    }

    /**
     * 获取蜜罐触发记录
     */
    public static function getHoneytraps(): array {
        return self::loadHoneytraps();
    }

    private static function getFilePath(string $filename): string {
        $dir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : __DIR__ . '/../waf_logs/';
        $dir = rtrim($dir, '/\\') . '/';
        // 验证目录路径安全
        $realDir = realpath($dir);
        if ($realDir === false) {
            if (!mkdir($dir, 0700, true)) {
                error_log("ActiveDefense: 无法创建日志目录: $dir");
                return '';
            }
            $realDir = realpath($dir);
        }
        if ($realDir === false || !is_writable($realDir)) {
            error_log("ActiveDefense: 日志目录不可写: $dir");
            return '';
        }
        // 验证文件名安全（防止路径遍历）
        $safeName = basename($filename);
        if ($safeName !== $filename) {
            error_log("ActiveDefense: 非法文件名: $filename");
            return '';
        }
        return $realDir . '/' . $safeName;
    }

    private static function loadHoneytraps(): array {
        $file = self::getFilePath(self::$honey_file);
        if ($file === '' || !is_file($file)) return [];
        $content = @file_get_contents($file);
        if ($content === false) {
            error_log("ActiveDefense: 无法读取蜜罐文件: $file");
            return [];
        }
        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("ActiveDefense: 蜜罐文件JSON解析错误: " . json_last_error_msg());
            return [];
        }
        return is_array($data) ? $data : [];
    }

    private static function saveHoneytraps(array $data) {
        $file = self::getFilePath(self::$honey_file);
        if ($file === '') return;
        $result = @file_put_contents($file, json_encode($data), LOCK_EX);
        if ($result === false) {
            error_log("ActiveDefense: 无法写入蜜罐文件: $file");
        }
    }

    private static function loadBlocks(): array {
        $file = self::getFilePath(self::$block_file);
        if ($file === '' || !is_file($file)) return [];
        $content = @file_get_contents($file);
        if ($content === false) {
            error_log("ActiveDefense: 无法读取封禁文件: $file");
            return [];
        }
        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("ActiveDefense: 封禁文件JSON解析错误: " . json_last_error_msg());
            return [];
        }
        return is_array($data) ? $data : [];
    }

    private static function saveBlocks(array $data) {
        $file = self::getFilePath(self::$block_file);
        if ($file === '') return;
        $result = @file_put_contents($file, json_encode($data), LOCK_EX);
        if ($result === false) {
            error_log("ActiveDefense: 无法写入封禁文件: $file");
        }
    }

    /**
     * 获取所有蜜罐模板
     */
    public static function getHoneyTemplates(): array {
        return self::$honey_templates;
    }
}
