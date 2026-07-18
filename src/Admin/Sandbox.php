<?php
/**
 * 盾甲 WAF 虚拟沙箱 (sandbox.php)
 *
 * 顶级兜底防御，集成 14 层编码归一化 + 5 维语义分析 + 8 层编译引擎 + 4 维智能评分
 *
 * 核心能力：
 *  1. 实时文件监控（register_shutdown_function）— 请求结束时对比 MD5 快照
 *  2. 自动定时扫描（默认 5 分钟，可配置 WAF_SANDBOX_SCAN_INTERVAL）
 *  3. 手动扫描（API/CLI 触发）
 *  4. 精确恶意代码定位 — 锁定到 第N行 第X字符 到 第Y字符
 *  5. 文件隔离 — 原路恢复，保留原始路径和权限
 *  6. 新落地恶意文件秒删除 — register_shutdown_function 即时检测
 *  7. 人工审核 — 隔离后标记 pending_review，等待管理员确认
 *
 * 存储结构：
 *  waf_logs/sandbox/
 *    ├── snapshot.json           # 文件 MD5 快照（path => {md5, mtime, size}）
 *    ├── scan_result.json        # 最近一次扫描结果
 *    ├── scan_history.json       # 扫描历史（最近 20 次）
 *    ├── malicious_locations.json # 恶意代码精确定位
 *    └── sandbox.log             # 沙箱日志
 *  waf_logs/quarantine/
 *    ├── manifest.json           # 隔离清单（id => {original_path, quarantined_at, reason, analysis, status}）
 *    └── <id>.bak                # 隔离的文件备份
 */
defined('ABSPATH') || exit;

if (!function_exists('waf_safe_read_json')) {
    require_once __DIR__ . '/../Support/Functions.php';
}

class WafSandbox {
    // WAF 自身根目录（基于 __DIR__ 动态计算，不可被篡改）
    private static $waf_root_dir;

    // 可执行脚本扩展名
    private static $protected_ext = [
        'php', 'phtml', 'php5', 'php7', 'phps', 'inc', 'shtml',
        'cgi', 'pl', 'py', 'asp', 'aspx', 'jsp', 'js', 'htaccess',
    ];

    // 永不删除/隔离的文件名（WAF 自身核心文件）
    private static $protected_filenames = [
        'shield-waf.php', 'config.php', '.env', '.env.example',
        'Dockerfile', 'docker-compose.yml',
        'test_e2e.php', 'test_full_decode.php', 'test_fp_stress.php',
        'test_learning.php',
    ];

    // 永不删除/隔离的目录名（WAF 自身代码目录）
    private static $protected_dirnames = [
        'shield-waf-master', 'src', 'Semantic', 'Core', 'Defense',
        'Support', 'Admin', 'Learn', 'Bot', 'logs',
    ];

    // 恶意特征库（用于快速预筛）
    private static $malware_signatures = [
        'eval(base64_decode(' => 30,
        'eval(gzinflate(' => 30,
        'eval(gzuncompress(' => 30,
        'eval(str_rot13(' => 30,
        'eval($_' => 35,
        'assert($_' => 35,
        'system($_' => 30,
        'exec($_' => 30,
        'shell_exec($_' => 30,
        'passthru($_' => 30,
        'proc_open($_' => 30,
        'popen($_' => 25,
        '`$_' => 25,
        'base64_decode($_' => 20,
        'str_rot13($_' => 20,
        'gzinflate(base64_decode(' => 30,
        'preg_replace("/.*/e"' => 30,
        'create_function($_' => 25,
        'call_user_func($_' => 20,
        'file_put_contents($_' => 15,
        'fwrite(fopen(' => 15,
        'move_uploaded_file($_FILES' => 15,
        'include($_GET' => 30,
        'require($_POST' => 30,
        'include_once($_REQUEST' => 25,
        '@ini_set("display_errors","0")' => 15,
        '$GLOBALS[\'\\x' => 25,
        'goto ' => 5,  // goto 混淆
        'chr(' => 3,
    ];

    private static $log_file = null;
    private static $snapshot_file = null;
    private static $scan_result_file = null;
    private static $scan_history_file = null;
    private static $locations_file = null;
    private static $quarantine_dir = null;
    private static $manifest_file = null;
    private static $initialized = false;

    // ====================== 初始化 ======================

    public static function init() {
        if (self::$initialized) return;
        self::$initialized = true;

        // 计算 WAF 自身根目录（src/Admin/ 往上两级）
        self::$waf_root_dir = realpath(dirname(__DIR__, 2));

        $sandboxDir = WAF_LOG_PATH . 'sandbox/';
        waf_ensure_dir($sandboxDir);

        self::$log_file          = $sandboxDir . 'sandbox.log';
        self::$snapshot_file      = $sandboxDir . 'snapshot.json';
        self::$scan_result_file   = $sandboxDir . 'scan_result.json';
        self::$scan_history_file  = $sandboxDir . 'scan_history.json';
        self::$locations_file     = $sandboxDir . 'malicious_locations.json';
        self::$quarantine_dir    = defined('WAF_SANDBOX_QUARANTINE_DIR')
            ? WAF_SANDBOX_QUARANTINE_DIR : WAF_LOG_PATH . 'quarantine/';
        self::$manifest_file      = self::$quarantine_dir . 'manifest.json';

        waf_ensure_dir(self::$quarantine_dir);

        // 注册请求结束时的实时文件监控
        if (php_sapi_name() !== 'cli' && !waf_is_admin_ip()) {
            register_shutdown_function(['WafSandbox', 'realtimeMonitor']);
        }

        // 自动定时扫描（基于文件时间戳的轻量定时器）
        self::autoScanIfNeeded();
    }

    // ====================== 实时监控（请求结束时触发） ======================

    /**
     * 判断文件是否受保护（WAF 自身文件、入口文件、配置文件）
     * 受保护文件永不删除、永不隔离
     */
    private static function isProtectedFile(string $path): bool {
        $realPath = realpath($path);
        if ($realPath === false) {
            $realPath = $path;
        }
        $realPath = str_replace('\\', '/', $realPath);

        // 1. WAF 自身根目录下的所有文件都保护
        if (self::$waf_root_dir) {
            $wafRoot = str_replace('\\', '/', self::$waf_root_dir);
            if (strpos($realPath, $wafRoot) === 0) {
                return true;
            }
        }

        // 2. 文件名在保护列表中（即使在其他目录也保护）
        $basename = basename($realPath);
        if (in_array($basename, self::$protected_filenames)) {
            return true;
        }

        // 3. 路径中包含 WAF 核心目录名
        foreach (self::$protected_dirnames as $dir) {
            if (preg_match('#/' . preg_quote($dir, '#') . '/#', $realPath)) {
                return true;
            }
        }

        // 4. 用户自定义白名单路径
        $customWhitelist = defined('WAF_SANDBOX_WHITELIST_PATHS')
            ? unserialize(WAF_SANDBOX_WHITELIST_PATHS) : [];
        if (is_array($customWhitelist)) {
            foreach ($customWhitelist as $wPath) {
                if (strpos($realPath, $wPath) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    // ====================== 实时监控（请求结束时触发） ======================

    /**
     * 实时文件监控 — 对比请求开始和结束时的文件快照
     * 新落地的恶意文件秒删除，修改的现有文件触发分析
     */
    public static function realtimeMonitor() {
        $before = self::loadSnapshot();
        if (empty($before)) return; // 首次运行无快照，跳过

        $after = self::takeSnapshot();
        $newFiles = array_diff_key($after, $before);
        $modifiedFiles = [];

        foreach ($after as $path => $info) {
            if (isset($before[$path]) && $before[$path]['md5'] !== $info['md5']) {
                $modifiedFiles[] = $path;
            }
        }

        // 处理新文件 — 秒删除恶意文件
        foreach ($newFiles as $path => $info) {
            // ⚠️ 保护检查：WAF 自身文件永不删除
            if (self::isProtectedFile($path)) {
                self::log("SKIP_PROTECTED 跳过受保护文件: $path");
                continue;
            }
            $analysis = self::analyzeFile($path);
            if ($analysis['is_malicious']) {
                if (defined('WAF_SANDBOX_INSTANT_DELETE_NEW') && WAF_SANDBOX_INSTANT_DELETE_NEW) {
                    // 秒删除新落地的恶意文件
                    @unlink($path);
                    self::log("SECS_DELETE 新落地恶意文件已秒删: $path (score={$analysis['score']})");
                    self::alertWebhook("秒删恶意文件", $path, $analysis);
                } else {
                    // 移入隔离区
                    self::quarantineFile($path, "新落地恶意文件 (score={$analysis['score']})", $analysis);
                }
            }
        }

        // 处理修改的文件 — 分析是否被注入恶意代码
        foreach ($modifiedFiles as $path) {
            // ⚠️ 保护检查：WAF 自身文件永不隔离
            if (self::isProtectedFile($path)) {
                self::log("SKIP_PROTECTED 跳过受保护文件(已修改): $path");
                continue;
            }
            $analysis = self::analyzeFile($path);
            if ($analysis['is_malicious']) {
                $locations = self::locateMaliciousCode($path);
                self::saveMaliciousLocations($path, $locations);

                if (defined('WAF_SANDBOX_AUTO_QUARANTINE') && WAF_SANDBOX_AUTO_QUARANTINE) {
                    self::quarantineFile($path, "文件被注入恶意代码 (score={$analysis['score']})", $analysis);
                    self::log("AUTO_QUARANTINE 文件已隔离: $path (score={$analysis['score']}, locations=" . count($locations) . ")");
                    self::alertWebhook("文件隔离", $path, $analysis);
                } else {
                    self::log("ALERT 文件含恶意代码但未自动隔离: $path (score={$analysis['score']})");
                    self::alertWebhook("恶意代码告警", $path, $analysis);
                }
            }
        }

        // 更新快照
        self::saveSnapshot($after);
    }

    // ====================== 自动定时扫描 ======================

    /**
     * 检查是否需要自动扫描（基于上次扫描时间）
     */
    private static function autoScanIfNeeded() {
        $interval = defined('WAF_SANDBOX_SCAN_INTERVAL') ? WAF_SANDBOX_SCAN_INTERVAL : 300;
        $lastScan = self::loadScanResult();
        $lastScanTime = $lastScan['scan_time'] ?? 0;

        if (time() - $lastScanTime < $interval) return; // 未到间隔

        // 异步触发扫描（非阻塞）
        $result = self::scanAll();
        self::log("AUTO_SCAN 自动扫描完成: scanned={$result['scanned']}, malicious={$result['malicious_count']}, quarantined={$result['quarantined_count']}");
    }

    // ====================== 文件快照管理 ======================

    private static function loadSnapshot() {
        return waf_safe_read_json(self::$snapshot_file, []);
    }

    private static function saveSnapshot($snapshot) {
        waf_safe_write_json(self::$snapshot_file, $snapshot);
    }

    /**
     * 生成当前文件快照
     */
    public static function takeSnapshot() {
        $cache = self::$snapshot_file;
        // 快照缓存 10 秒内不重复扫描文件系统
        if (is_file($cache) && time() - filemtime($cache) < 10) {
            $cached = json_decode(file_get_contents($cache), true);
            if (is_array($cached)) return $cached;
        }

        $snapshot = [];
        $dirs = self::getMonitorDirs();
        $excludeDirs = self::getExcludeDirs();

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) continue;
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
            } catch (Exception $e) {
                continue;
            }

            foreach ($iterator as $file) {
                if (!$file->isFile()) continue;
                $path = $file->getPathname();

                // 排除目录
                $skip = false;
                foreach ($excludeDirs as $excl) {
                    if (strpos($path, $excl) !== false) { $skip = true; break; }
                }
                if ($skip) continue;

                // ⚠️ 排除 WAF 自身文件（不在快照中记录，永不扫描）
                if (self::isProtectedFile($path)) continue;

                $ext = strtolower($file->getExtension());
                if (!in_array($ext, self::$protected_ext)) continue;

                $snapshot[$path] = [
                    'md5'   => md5_file($path),
                    'mtime' => $file->getMTime(),
                    'size'  => $file->getSize(),
                ];
            }
        }

        self::saveSnapshot($snapshot);
        return $snapshot;
    }

    private static function getMonitorDirs() {
        $dirs = defined('WAF_SANDBOX_MONITOR_DIRS') ? unserialize(WAF_SANDBOX_MONITOR_DIRS) : [ABSPATH];
        return is_array($dirs) ? $dirs : [ABSPATH];
    }

    private static function getExcludeDirs() {
        $dirs = defined('WAF_SANDBOX_EXCLUDE_DIRS') ? unserialize(WAF_SANDBOX_EXCLUDE_DIRS) : [WAF_LOG_PATH];
        $dirs = is_array($dirs) ? $dirs : [WAF_LOG_PATH];

        // 自动加入 WAF 自身根目录
        if (self::$waf_root_dir) {
            $dirs[] = self::$waf_root_dir;
        }

        return $dirs;
    }

    // ====================== 单文件深度分析（核心） ======================

    /**
     * 对单个文件进行多引擎深度分析
     * 集成：14层归一化 + 规则检测 + 语义分析 + 编译引擎 + 智能评分
     *
     * @param string $path 文件路径
     * @return array 分析结果
     */
    public static function analyzeFile($path) {
        if (!is_file($path)) {
            return ['is_malicious' => false, 'score' => 0, 'error' => 'file not found'];
        }

        // ⚠️ WAF 自身文件永不分析（防止自我误杀）
        if (self::isProtectedFile($path)) {
            return ['is_malicious' => false, 'score' => 0, 'error' => 'protected file', 'protected' => true];
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return ['is_malicious' => false, 'score' => 0, 'error' => 'read failed'];
        }

        $threshold = defined('WAF_SANDBOX_MALWARE_THRESHOLD') ? WAF_SANDBOX_MALWARE_THRESHOLD : 50;
        $score = 0;
        $indicators = [];
        $malwareType = 'unknown';
        $engineHitCount = 0;

        // ---------- 1. 特征码快速预筛 ----------
        $sigScore = self::signatureScan($content);
        if ($sigScore > 0) {
            $engineHitCount++;
            $adjSigScore = min($sigScore * 0.6, 40);
            $score += $adjSigScore;
            $indicators[] = ['engine' => 'signature', 'score' => $adjSigScore, 'desc' => "命中恶意特征码 (raw=$sigScore)"];
        }

        // ---------- 2. 14 层编码归一化（AdversarialDefense）+ 规则检测 ----------
        if (class_exists('AdversarialDefense')) {
            $normResult = AdversarialDefense::normalizeWithContext($content);
            $normalized = $normResult['output'] ?? $content;
            $normEngineHit = false;

            // 编码复杂度加成（权重降低，避免误报）
            $encodingComplexity = $normResult['encoding_complexity'] ?? 0;
            if ($encodingComplexity > 50) {
                $score += 10;
                $normEngineHit = true;
                $indicators[] = ['engine' => 'normalizer', 'score' => 10, 'desc' => "编码复杂度极高 ($encodingComplexity)"];
            } elseif ($encodingComplexity > 30) {
                $score += 5;
                $normEngineHit = true;
                $indicators[] = ['engine' => 'normalizer', 'score' => 5, 'desc' => "编码复杂度偏高 ($encodingComplexity)"];
            }

            // 编码深度加成
            $encodingDepth = $normResult['encoding_depth'] ?? 0;
            if ($encodingDepth >= 4) {
                $score += 10;
                $normEngineHit = true;
                $indicators[] = ['engine' => 'normalizer', 'score' => 10, 'desc' => "编码深度 $encodingDepth 层（多重编码绕过）"];
            }

            // 归一化后内容与原始内容差异大 — 可能是混淆
            if (strlen($normalized) !== strlen($content) && strlen($content) > 0) {
                $diffRatio = abs(strlen($normalized) - strlen($content)) / strlen($content);
                if ($diffRatio > 0.3) {
                    $score += 5;
                    $normEngineHit = true;
                    $indicators[] = ['engine' => 'normalizer', 'score' => 5, 'desc' => "归一化后长度变化 " . round($diffRatio * 100) . "%"];
                }
            }

            if ($normEngineHit) $engineHitCount++;

            // 规则检测（归一化后的内容）
            if (function_exists('waf_analyze_attack')) {
                $attackResult = waf_analyze_attack($normalized, $normResult);
                if ($attackResult['is_attack']) {
                    $attackScore = min($attackResult['total_score'] * 0.35, 35);
                    $score += $attackScore;
                    $engineHitCount++;
                    $indicators[] = [
                        'engine' => 'detector',
                        'score' => round($attackScore, 1),
                        'desc' => "规则检测: {$attackResult['risk_level']} ({$attackResult['total_score']}%) hits={$attackResult['hit_count']}",
                    ];
                    // 提取攻击类型
                    if (!empty($attackResult['attack_type_scores'])) {
                        arsort($attackResult['attack_type_scores']);
                        $malwareType = array_key_first($attackResult['attack_type_scores']);
                    }
                }
            }
        }

        // ---------- 3. 语义分析引擎（核心权重） ----------
        if (class_exists('SemanticEngine')) {
            $semResult = SemanticEngine::analyze($content);
            $semScore = $semResult['total_score'] ?? 0;
            if ($semScore > 30) {
                $adjScore = min($semScore * 0.4, 30);
                $score += $adjScore;
                $engineHitCount++;
                $indicators[] = [
                    'engine' => 'semantic',
                    'score' => round($adjScore, 1),
                    'desc' => "语义分析: " . ($semResult['risk_level'] ?? 'unknown') . " ($semScore)",
                ];
            }
        }

        // ---------- 4. 结构分析（辅助，权重低） ----------
        $structScore = self::structuralAnalysis($content);
        if ($structScore > 40) {
            $adjScore = min($structScore * 0.15, 15);
            $score += $adjScore;
            $engineHitCount++;
            $indicators[] = [
                'engine' => 'structure',
                'score'  => round($adjScore, 1),
                'desc'   => "结构分析: score=$structScore",
            ];
        }

        // ---------- 5. 启发式特征（辅助，权重最低） ----------
        $heuristicScore = self::heuristicScan($content);
        if ($heuristicScore > 0) {
            $adjHeurScore = min($heuristicScore * 0.4, 15);
            $score += $adjHeurScore;
            $engineHitCount++;
            $indicators[] = ['engine' => 'heuristic', 'score' => $adjHeurScore, 'desc' => "启发式分析命中 (raw=$heuristicScore)"];
        }

        $score = min(round($score, 1), 100);

        // ---------- 多引擎交叉验证：命中引擎越多，阈值越低 ----------
        $effectiveThreshold = $threshold;
        if ($engineHitCount >= 4) {
            $effectiveThreshold = max(35, $threshold - 15); // 4个以上引擎命中，阈值降15
        } elseif ($engineHitCount >= 3) {
            $effectiveThreshold = max(40, $threshold - 10); // 3个引擎命中，阈值降10
        } elseif ($engineHitCount >= 2) {
            $effectiveThreshold = max(45, $threshold - 5);  // 2个引擎命中，阈值降5
        }
        // 只有1个引擎命中 → 阈值不变，保持高标准避免误报

        $is_malicious = $score >= $effectiveThreshold;

        // 命中恶意时自动投喂给 AutoLearn 学习（形成闭环）
        if ($is_malicious && $engineHitCount >= 2 && class_exists('AutoLearn')) {
            self::feedToAutoLearn($content, $score, $malwareType, $engineHitCount);
        }

        return [
            'is_malicious' => $is_malicious,
            'score'        => $score,
            'threshold'    => $threshold,
            'effective_threshold' => $effectiveThreshold,
            'engine_hit_count' => $engineHitCount,
            'type'         => $malwareType,
            'engines'      => $indicators,
            'file_size'    => strlen($content),
            'file_md5'     => md5($content),
            'analyzed_at'  => time(),
        ];
    }

    // ====================== AutoLearn 联动：恶意样本投喂 ======================

    /**
     * 将沙箱发现的恶意样本投喂给自动学习系统
     * 形成 WAF → 沙箱 → 学习 → WAF 规则更新 的闭环
     */
    private static function feedToAutoLearn($content, $score, $attackType, $engineHitCount) {
        try {
            if (!class_exists('AutoLearn')) return;

            // 归一化后提取特征
            $normalized = $content;
            if (class_exists('AdversarialDefense')) {
                $normResult = AdversarialDefense::normalize($content);
                if (!empty($normResult)) $normalized = $normResult;
            }

            // 高置信度才记录，避免误报污染学习数据
            if ($score >= 60 && $engineHitCount >= 3) {
                $attackResult = [
                    'risk_level' => $score >= 80 ? 'high' : 'medium',
                    'attack_type_scores' => [
                        $attackType => $score,
                    ],
                    'source' => 'sandbox',
                ];
                AutoLearn::recordAttack($normalized, $attackResult);
            }
        } catch (Exception $e) {
            // 静默失败，不影响沙箱主流程
            self::log("FEED_AUTOLEARN_ERR: " . $e->getMessage());
        }
    }

    // ====================== 结构分析（v3.0 整合自原 CompilerEngine） ======================

    /**
     * 文件内容的结构特征评分（沙箱专用：仅分析文件内容本身）
     */
    private static function structuralAnalysis($text) {
        $score = 0;
        $len = strlen($text);
        if ($len === 0) return 0;

        // 文本结构
        $upperRatio = strlen(preg_replace('/[^A-Z]/', '', $text)) / $len;
        $digitRatio = strlen(preg_replace('/[^0-9]/', '', $text)) / $len;
        $symRatio   = strlen(preg_replace('/[a-zA-Z0-9\s]/', '', $text)) / $len;
        if ($upperRatio > 0.5 && $digitRatio > 0.3) $score += 15;
        if ($symRatio > 0.4)                          $score += 15;

        // 可疑变量命名模式
        if (preg_match_all('/\$[a-z]{1,2}[0-9a-z]{0,3}\s*=/i', $text) > 10) $score += 10;

        // 超长单行（混淆代码通常不换行）
        $lines = explode("\n", $text);
        foreach ($lines as $line) {
            if (strlen($line) > 2000) { $score += 10; break; }
        }

        return min(round($score, 1), 100);
    }

    // ====================== 精确恶意代码定位 ======================

    /**
     * 精确锁定恶意代码位置 — 定位到 第N行 第X字符 到 第Y字符
     *
     * @param string $path 文件路径
     * @return array 定位结果
     */
    public static function locateMaliciousCode($path) {
        if (!is_file($path)) return [];

        $content = @file_get_contents($path);
        if ($content === false) return [];

        $lines = explode("\n", $content);
        $locations = [];

        // 逐行扫描
        foreach ($lines as $lineIdx => $line) {
            $lineNum = $lineIdx + 1;

            // 对每行进行归一化+检测（AdversarialDefense 14层解码）
            if (class_exists('AdversarialDefense')) {
                $normResult = AdversarialDefense::normalizeWithContext($line);
                $normalized = $normResult['output'] ?? $line;

                if (function_exists('waf_analyze_attack')) {
                    $attackResult = waf_analyze_attack($normalized, $normResult);
                    if ($attackResult['is_attack'] && $attackResult['total_score'] >= 50) {
                        // 在该行中精确定位匹配的模式
                        $patterns = self::locatePatternInLine($line, $normalized, $attackResult);
                        foreach ($patterns as $pat) {
                            $locations[] = [
                                'line'       => $lineNum,
                                'start_char' => $pat['start'],
                                'end_char'   => $pat['end'],
                                'snippet'    => $pat['snippet'],
                                'rule'       => $pat['rule'],
                                'score'      => $attackResult['total_score'],
                                'attack_type'=> $pat['attack_type'] ?? 'unknown',
                            ];
                        }
                    }
                }
            }

            // 特征码精确定位
            foreach (self::$malware_signatures as $sig => $sigScore) {
                $pos = mb_stripos($line, $sig);
                if ($pos !== false) {
                    $locations[] = [
                        'line'       => $lineNum,
                        'start_char' => $pos + 1,         // 1-based
                        'end_char'   => $pos + mb_strlen($sig),
                        'snippet'    => self::extractSnippet($line, $pos, mb_strlen($sig)),
                        'rule'       => 'signature: ' . $sig,
                        'score'      => $sigScore,
                        'attack_type'=> 'webshell',
                    ];
                }
            }

            // eval/base64_decode 组合定位
            if (preg_match_all('/(eval\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\()[^;]*\)/i', $line, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $fullMatch = $match[0];
                    $offset = $match[1];
                    $locations[] = [
                        'line'       => $lineNum,
                        'start_char' => $offset + 1,
                        'end_char'   => $offset + strlen($fullMatch),
                        'snippet'    => $fullMatch,
                        'rule'       => 'dangerous_function_call',
                        'score'      => 25,
                        'attack_type'=> 'rce',
                    ];
                }
            }

            // base64 编码的长字符串定位
            if (preg_match_all('/[A-Za-z0-9+\/]{60,}={0,2}/', $line, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $fullMatch = $match[0];
                    $offset = $match[1];
                    // 尝试解码验证是否为恶意内容
                    $decoded = @base64_decode($fullMatch);
                    if ($decoded !== false && self::isDecodedMalicious($decoded)) {
                        $locations[] = [
                            'line'       => $lineNum,
                            'start_char' => $offset + 1,
                            'end_char'   => $offset + strlen($fullMatch),
                            'snippet'    => mb_substr($fullMatch, 0, 40) . '...' . (strlen($fullMatch) > 40 ? mb_substr($fullMatch, -10) : ''),
                            'rule'       => 'base64_encoded_payload',
                            'score'      => 30,
                            'attack_type'=> 'obfuscation',
                            'decoded'    => mb_substr($decoded, 0, 100),
                        ];
                    }
                }
            }

            // $_GET/$_POST/$_REQUEST/$_COOKIE 直接传入危险函数
            if (preg_match_all('/\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]*\]/i', $line, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $fullMatch = $match[0];
                    $offset = $match[1];
                    // 检查这行是否有危险函数调用
                    if (preg_match('/(eval|assert|system|exec|shell_exec|passthru|include|require|file_put_contents|fwrite|move_uploaded_file)\s*\(/i', $line)) {
                        $locations[] = [
                            'line'       => $lineNum,
                            'start_char' => $offset + 1,
                            'end_char'   => $offset + strlen($fullMatch),
                            'snippet'    => $fullMatch,
                            'rule'       => 'user_input_to_sink',
                            'score'      => 30,
                            'attack_type'=> 'rce',
                        ];
                    }
                }
            }
        }

        // 去重（同一行同一位置可能被多个引擎命中）
        $seen = [];
        $unique = [];
        foreach ($locations as $loc) {
            $key = $loc['line'] . ':' . $loc['start_char'] . ':' . $loc['end_char'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $loc;
            }
        }

        // 自动持久化定位结果
        if (!empty($unique)) {
            self::saveMaliciousLocations($path, $unique);
        }

        return $unique;
    }

    /**
     * 在行中定位匹配的模式
     */
    private static function locatePatternInLine($line, $normalized, $attackResult) {
        $patterns = [];

        // 从 matched_rules 中提取模式并在原行中定位
        if (!empty($attackResult['matched_rules'])) {
            foreach ($attackResult['matched_rules'] as $rule) {
                $pattern = $rule['pattern'] ?? '';
                if (empty($pattern)) continue;

                // 尝试在归一化后的行中定位
                $pos = mb_stripos($normalized, $pattern);
                if ($pos !== false) {
                    $patterns[] = [
                        'start'       => $pos + 1,
                        'end'         => $pos + mb_strlen($pattern),
                        'snippet'     => mb_substr($normalized, $pos, min(mb_strlen($pattern) + 20, mb_strlen($normalized) - $pos)),
                        'rule'        => $rule['name'] ?? $rule['pattern'],
                        'attack_type' => $rule['type'] ?? 'unknown',
                    ];
                }
            }
        }

        return $patterns;
    }

    /**
     * 提取匹配点周围的代码片段
     */
    private static function extractSnippet($line, $pos, $length) {
        $start = max(0, $pos - 10);
        $end = min(strlen($line), $pos + $length + 10);
        $snippet = substr($line, $start, $end - $start);
        return trim($snippet);
    }

    /**
     * 检查 base64 解码后的内容是否恶意
     */
    private static function isDecodedMalicious($decoded) {
        $decoded_lower = strtolower($decoded);
        foreach (self::$malware_signatures as $sig => $_) {
            if (strpos($decoded_lower, strtolower($sig)) !== false) return true;
        }
        return false;
    }

    // ====================== 特征码扫描 ======================

    private static function signatureScan($content) {
        $content_lower = strtolower($content);
        $score = 0;
        foreach (self::$malware_signatures as $sig => $weight) {
            if (strpos($content_lower, strtolower($sig)) !== false) {
                $score += $weight;
            }
        }
        return min($score, 80);
    }

    // ====================== 启发式扫描 ======================

    private static function heuristicScan($content) {
        $score = 0;
        $content_lower = strtolower($content);

        // 1. base64_decode 出现次数过多
        $b64count = preg_match_all('/base64_decode\s*\(/', $content_lower);
        if ($b64count > 2) {
            $score += min($b64count * 5, 20);
        }

        // 2. 全 base64 内容（文件内容几乎全是 base64）
        if (strlen($content) > 500 && preg_match('/^[a-zA-Z0-9+\/=\s]+$/', trim($content))) {
            $score += 25;
        }

        // 3. 大量 chr() 调用（字符级混淆）
        $chrCount = preg_match_all('/chr\s*\(\s*\d+\s*\)/', $content);
        if ($chrCount > 5) {
            $score += min($chrCount * 2, 15);
        }

        // 4. 混淆变量名（$a0x1, $OOO 等）
        if (preg_match_all('/\$[O0lI]{4,}/', $content)) {
            $score += 10;
        }

        // 5. goto 混淆（大量 goto 跳转）
        $gotoCount = preg_match_all('/goto\s+\w+\s*;/', $content);
        if ($gotoCount > 3) {
            $score += 10;
        }

        // 6. 超长单行（混淆代码通常不换行）
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            if (strlen($line) > 2000) {
                $score += 10;
                break;
            }
        }

        return min($score, 50);
    }

    // ====================== 全量扫描 ======================

    /**
     * 扫描所有监控目录
     * @return array 扫描结果
     */
    public static function scanAll() {
        $startTime = microtime(true);
        $snapshot = self::takeSnapshot();
        $beforeSnapshot = self::loadSnapshot();

        $scanned = 0;
        $maliciousFiles = [];
        $quarantinedCount = 0;
        $locationCount = 0;

        foreach ($snapshot as $path => $info) {
            $scanned++;

            // ⚠️ 保护检查：WAF 自身文件永不删除/隔离
            if (self::isProtectedFile($path)) {
                continue;
            }

            $analysis = self::analyzeFile($path);

            if ($analysis['is_malicious']) {
                $maliciousFiles[] = [
                    'path'  => $path,
                    'score' => $analysis['score'],
                    'type'  => $analysis['type'],
                    'engines' => $analysis['engines'],
                ];

                // 精确定位恶意代码
                $locations = self::locateMaliciousCode($path);
                $locationCount += count($locations);
                self::saveMaliciousLocations($path, $locations);

                // 新文件（不在之前的快照中）→ 秒删除或隔离
                $isNew = !isset($beforeSnapshot[$path]);
                if ($isNew && defined('WAF_SANDBOX_INSTANT_DELETE_NEW') && WAF_SANDBOX_INSTANT_DELETE_NEW) {
                    // ⚠️ 二次保护检查
                    if (!self::isProtectedFile($path)) {
                        @unlink($path);
                        self::log("SECS_DELETE 新落地恶意文件秒删: $path (score={$analysis['score']})");
                        self::alertWebhook("秒删恶意文件", $path, $analysis);
                    }
                } elseif (defined('WAF_SANDBOX_AUTO_QUARANTINE') && WAF_SANDBOX_AUTO_QUARANTINE) {
                    // ⚠️ 二次保护检查
                    if (!self::isProtectedFile($path)) {
                        self::quarantineFile($path, "全量扫描发现恶意代码 (score={$analysis['score']})", $analysis);
                        $quarantinedCount++;
                        self::log("AUTO_QUARANTINE 文件已隔离: $path (score={$analysis['score']})");
                        self::alertWebhook("文件隔离", $path, $analysis);
                    }
                } else {
                    self::log("ALERT 恶意文件: $path (score={$analysis['score']})");
                    self::alertWebhook("恶意代码告警", $path, $analysis);
                }
            }
        }

        $elapsed = round(microtime(true) - $startTime, 2);

        $result = [
            'scan_time'        => time(),
            'scan_duration'    => $elapsed,
            'scanned'          => $scanned,
            'malicious_count'  => count($maliciousFiles),
            'quarantined_count'=> $quarantinedCount,
            'location_count'   => $locationCount,
            'malicious_files'  => $maliciousFiles,
            'snapshot_updated' => true,
        ];

        // 保存扫描结果
        self::saveScanResult($result);
        self::saveScanHistory($result);

        return $result;
    }

    // ====================== 文件隔离与恢复 ======================

    /**
     * 隔离文件 — 移入隔离区，保留原始路径信息
     */
    public static function quarantineFile($path, $reason, $analysis = []) {
        if (!is_file($path)) return false;

        // ⚠️ 最终保护屏障：WAF 自身文件永不被隔离
        if (self::isProtectedFile($path)) {
            self::log("BLOCK_QUARANTINE 拦截隔离受保护文件: $path");
            return false;
        }

        $manifest = self::loadManifest();
        $id = 'Q' . date('YmdHis') . '_' . substr(md5($path . time()), 0, 8);
        $backupFile = self::$quarantine_dir . $id . '.bak';

        // 复制到隔离区
        if (!@copy($path, $backupFile)) return false;

        // 记录文件权限
        $perms = fileperms($path);

        // 从原路径删除
        @unlink($path);

        // 记录到清单
        $manifest[$id] = [
            'id'             => $id,
            'original_path'  => $path,
            'backup_file'    => $backupFile,
            'quarantined_at' => time(),
            'reason'         => $reason,
            'analysis'       => $analysis,
            'original_perms' => $perms,
            'status'         => 'pending_review', // pending_review / approved / restored / deleted
            'reviewed_by'    => null,
            'reviewed_at'    => null,
        ];

        self::saveManifest($manifest);
        self::log("QUARANTINE 文件已隔离: $path → $backupFile (id=$id, reason=$reason)");
        return $id;
    }

    /**
     * 恢复隔离文件 — 原路返回
     */
    public static function restoreFile($id) {
        $manifest = self::loadManifest();
        if (!isset($manifest[$id])) return false;

        $entry = $manifest[$id];
        $backupFile = $entry['backup_file'];
        $originalPath = $entry['original_path'];

        if (!is_file($backupFile)) return false;

        // 确保目标目录存在
        $dir = dirname($originalPath);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);

        // 恢复文件
        if (!@copy($backupFile, $originalPath)) return false;

        // 恢复权限
        if (!empty($entry['original_perms'])) {
            @chmod($originalPath, $entry['original_perms']);
        }

        // 更新清单状态
        $manifest[$id]['status'] = 'restored';
        $manifest[$id]['restored_at'] = time();
        self::saveManifest($manifest);

        // 删除备份
        @unlink($backupFile);

        self::log("RESTORE 文件已恢复: $originalPath (id=$id)");
        return true;
    }

    /**
     * 恢复所有隔离文件
     */
    public static function restoreAllFiles() {
        $manifest = self::loadManifest();
        $count = 0;
        foreach ($manifest as $id => $entry) {
            if ($entry['status'] === 'pending_review' || $entry['status'] === 'approved') {
                if (self::restoreFile($id)) $count++;
            }
        }
        return $count;
    }

    /**
     * 审核隔离文件（管理员确认是否为恶意）
     */
    public static function reviewFile($id, $action, $reviewer = 'admin') {
        $manifest = self::loadManifest();
        if (!isset($manifest[$id])) return false;

        $manifest[$id]['reviewed_by'] = $reviewer;
        $manifest[$id]['reviewed_at'] = time();

        switch ($action) {
            case 'approve': // 确认恶意，永久删除
                $manifest[$id]['status'] = 'approved';
                @unlink($manifest[$id]['backup_file']);
                self::log("REVIEW_APPROVE 确认恶意，永久删除: {$manifest[$id]['original_path']} (id=$id)");
                break;
            case 'false_positive': // 误报，恢复文件
                self::restoreFile($id);
                $manifest[$id]['status'] = 'false_positive';
                self::log("REVIEW_FP 误报，已恢复: {$manifest[$id]['original_path']} (id=$id)");
                break;
            case 'delete': // 永久删除备份
                $manifest[$id]['status'] = 'deleted';
                @unlink($manifest[$id]['backup_file']);
                self::log("REVIEW_DELETE 永久删除: {$manifest[$id]['original_path']} (id=$id)");
                break;
            case 'keep': // 保留隔离
                $manifest[$id]['status'] = 'pending_review';
                break;
        }

        self::saveManifest($manifest);
        return true;
    }

    /**
     * 获取隔离文件列表
     */
    public static function getQuarantineList() {
        $manifest = self::loadManifest();
        $list = [];
        foreach ($manifest as $id => $entry) {
            $list[] = [
                'id'             => $id,
                'original_path'  => $entry['original_path'],
                'quarantined_at' => $entry['quarantined_at'],
                'reason'         => $entry['reason'],
                'score'          => $entry['analysis']['score'] ?? 0,
                'type'           => $entry['analysis']['type'] ?? 'unknown',
                'status'         => $entry['status'],
                'file_size'      => $entry['analysis']['file_size'] ?? 0,
                'engines'        => $entry['analysis']['engines'] ?? [],
            ];
        }
        return $list;
    }

    /**
     * 获取隔离统计
     */
    public static function getStats() {
        $manifest = self::loadManifest();
        $scanResult = self::loadScanResult();
        $locations = self::loadMaliciousLocationsAll();

        $stats = [
            'total_quarantined'    => count($manifest),
            'pending_review'       => 0,
            'approved'             => 0,
            'restored'             => 0,
            'false_positive'       => 0,
            'deleted'              => 0,
            'last_scan'            => $scanResult,
            'total_locations'      => count($locations),
            'auto_scan_interval'   => defined('WAF_SANDBOX_SCAN_INTERVAL') ? WAF_SANDBOX_SCAN_INTERVAL : 300,
            'instant_delete_new'   => defined('WAF_SANDBOX_INSTANT_DELETE_NEW') ? WAF_SANDBOX_INSTANT_DELETE_NEW : true,
            'auto_quarantine'      => defined('WAF_SANDBOX_AUTO_QUARANTINE') ? WAF_SANDBOX_AUTO_QUARANTINE : true,
            'monitor_dirs'         => self::getMonitorDirs(),
            'exclude_dirs'         => self::getExcludeDirs(),
        ];

        foreach ($manifest as $entry) {
            $status = $entry['status'];
            if (isset($stats[$status])) $stats[$status]++;
        }

        return $stats;
    }

    // ====================== 恶意代码定位存储 ======================

    private static function saveMaliciousLocations($path, $locations) {
        $all = self::loadMaliciousLocationsAll();
        $all[$path] = [
            'path'       => $path,
            'locations'  => $locations,
            'updated_at' => time(),
        ];
        waf_safe_write_json(self::$locations_file, $all);
    }

    private static function loadMaliciousLocationsAll() {
        return waf_safe_read_json(self::$locations_file, []);
    }

    /**
     * 获取指定文件的恶意代码定位
     */
    public static function getMaliciousLocations($path = '') {
        $all = self::loadMaliciousLocationsAll();
        if (empty($path)) return $all;
        return $all[$path] ?? ['path' => $path, 'locations' => []];
    }

    // ====================== 扫描结果存储 ======================

    private static function loadScanResult() {
        return waf_safe_read_json(self::$scan_result_file, []);
    }

    private static function saveScanResult($result) {
        waf_safe_write_json(self::$scan_result_file, $result);
    }

    private static function saveScanHistory($result) {
        $history = waf_safe_read_json(self::$scan_history_file, []);
        // 只保留摘要，不保留完整文件列表
        $summary = [
            'scan_time'       => $result['scan_time'],
            'scan_duration'   => $result['scan_duration'],
            'scanned'         => $result['scanned'],
            'malicious_count' => $result['malicious_count'],
            'quarantined'     => $result['quarantined_count'],
        ];
        $history[] = $summary;
        $history = array_slice($history, -20); // 保留最近 20 次
        waf_safe_write_json(self::$scan_history_file, $history);
    }

    // ====================== 隔离清单管理 ======================

    private static function loadManifest() {
        return waf_safe_read_json(self::$manifest_file, []);
    }

    private static function saveManifest($manifest) {
        waf_ensure_dir(self::$quarantine_dir);
        waf_safe_write_json(self::$manifest_file, $manifest);
    }

    // ====================== 日志与告警 ======================

    private static function log($message) {
        $line = date('Y-m-d H:i:s') . ' | ' . $message . "\n";
        @file_put_contents(self::$log_file, $line, FILE_APPEND | LOCK_EX);
    }

    private static function alertWebhook($title, $path, $analysis) {
        if (!defined('WAF_WEBHOOK_URL') || empty(WAF_WEBHOOK_URL)) return;
        if (!function_exists('waf_webhook_notify')) return;

        $message = "盾甲WAF沙箱告警: $title\n";
        $message .= "文件: $path\n";
        $message .= "评分: {$analysis['score']}\n";
        $message .= "类型: {$analysis['type']}\n";
        $message .= "时间: " . date('Y-m-d H:i:s');

        waf_webhook_notify($message);
    }

    // ====================== 兼容旧接口 ======================

    public static function checkFileChanges() {
        return self::realtimeMonitor();
    }

    public static function checkFileWrite($filename) {
        if (waf_is_admin_ip()) return true;
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (in_array($ext, self::$protected_ext)) {
            self::log("BLOCK_WRITE 拦截写入: $filename");
            return false;
        }
        return true;
    }
}
