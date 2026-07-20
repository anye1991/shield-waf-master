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
    private static $baseline_file = null;      // 基线文件哈希
    private static $baseline_meta_file = null;  // 基线元数据（锁定时间等）
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
        self::$baseline_file      = $sandboxDir . 'baseline.json';
        self::$baseline_meta_file = $sandboxDir . 'baseline_meta.json';
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
        // PHP 7.0+ 数组常量直接使用，无需 json_decode
        $customWhitelist = defined('WAF_SANDBOX_WHITELIST_PATHS') ? WAF_SANDBOX_WHITELIST_PATHS : [];
        if (!is_array($customWhitelist)) {
            $customWhitelist = [];
        }
        foreach ($customWhitelist as $wPath) {
            if (strpos($realPath, $wPath) !== false) {
                return true;
            }
        }

        return false;
    }

    // ====================== 沙箱工作模式 ======================

    /**
     * 获取当前工作模式
     * learning: 学习模式（只扫描告警，不删除）
     * baseline: 基线模式（建立干净文件哈希）
     * protecting: 保护模式（秒删除+精准切割）
     */
    public static function getMode(): string {
        return defined('WAF_SANDBOX_MODE') ? WAF_SANDBOX_MODE : 'learning';
    }

    /**
     * 基线是否已锁定
     */
    public static function isBaselineLocked(): bool {
        $meta = waf_safe_read_json(self::$baseline_meta_file, []);
        return !empty($meta['locked']) && $meta['locked'] === true;
    }

    /**
     * 建立并锁定基线 — 将当前所有干净文件作为"原始基线"
     * 调用前提：用户已手动排查并清理完所有后门
     */
    public static function lockBaseline(): array {
        $snapshot = self::takeSnapshot();
        $baseline = [];
        $protected = 0;
        $totalFiles = 0;

        foreach ($snapshot as $path => $info) {
            // WAF 自身文件不纳入基线（已受保护）
            if (self::isProtectedFile($path)) {
                $protected++;
                continue;
            }
            $totalFiles++;
            $baseline[$path] = [
                'md5'   => $info['md5'],
                'size'  => $info['size'],
                'mtime' => $info['mtime'],
            ];
        }

        // 保存基线
        waf_safe_write_json(self::$baseline_file, $baseline);

        // 备份所有原始文件（用于精准切割时恢复）
        $backedUp = self::backupBaselineFiles($baseline);

        $meta = [
            'locked'        => true,
            'locked_at'     => time(),
            'locked_by'     => $_SERVER['REMOTE_ADDR'] ?? 'cli',
            'total_files'   => $totalFiles,
            'protected_files' => $protected,
            'backed_up_files' => $backedUp,
            'mode_at_lock'  => self::getMode(),
        ];
        waf_safe_write_json(self::$baseline_meta_file, $meta);

        self::log("BASELINE_LOCKED 基线已锁定: files={$totalFiles}, protected={$protected}, backed_up={$backedUp}, by=" . ($meta['locked_by']));

        // 集成点 3：联动 AutoLearn 冻结行为基线
        // 防止攻击者在保护模式下慢慢"教坏" AutoLearn
        self::notifyAutoLearnFreeze(true);

        return [
            'success'        => true,
            'total_files'    => $totalFiles,
            'protected_files' => $protected,
            'backed_up_files' => $backedUp,
            'locked_at'      => $meta['locked_at'],
            'message'        => "基线已锁定，共 {$totalFiles} 个文件受保护，{$backedUp} 个已备份",
        ];
    }

    /**
     * 解锁基线（回到学习模式）
     */
    public static function unlockBaseline(): array {
        waf_safe_write_json(self::$baseline_meta_file, ['locked' => false, 'unlocked_at' => time()]);
        self::log("BASELINE_UNLOCKED 基线已解锁，回到学习模式");

        // 集成点 3：联动 AutoLearn 解冻行为基线
        self::notifyAutoLearnFreeze(false);

        return ['success' => true, 'message' => '基线已解锁，回到学习模式'];
    }

    /**
     * 获取基线统计信息
     */
    public static function getBaselineInfo(): array {
        $meta = waf_safe_read_json(self::$baseline_meta_file, []);
        $baseline = waf_safe_read_json(self::$baseline_file, []);
        return [
            'locked'        => !empty($meta['locked']) && $meta['locked'] === true,
            'locked_at'      => $meta['locked_at'] ?? null,
            'total_files'   => $meta['total_files'] ?? 0,
            'protected_files' => $meta['protected_files'] ?? 0,
            'baseline_count' => count($baseline),
            'current_mode'  => self::getMode(),
        ];
    }

    /**
     * 检查文件是否在基线中（已知干净文件）
     */
    private static function isInBaseline(string $path): bool {
        $baseline = waf_safe_read_json(self::$baseline_file, []);
        return isset($baseline[$path]);
    }

    /**
     * 获取基线中文件的原始哈希
     */
    private static function getBaselineHash(string $path): ?string {
        $baseline = waf_safe_read_json(self::$baseline_file, []);
        return $baseline[$path]['md5'] ?? null;
    }

    // ====================== 精准切割（核心） ======================

    /**
     * 精准切割 — 原始文件被插入后门时，只移除恶意部分，保留原始内容
     *
     * 算法：
     * 1. 从基线读取原始文件内容
     * 2. 与当前文件做行级 diff
     * 3. 找出新增的行（攻击者插入的代码）
     * 4. 对新增行做恶意检测
     * 5. 如果是恶意，只移除恶意行，保留原始内容
     * 6. 写回文件，恢复原始内容
     */
    public static function surgicalCut(string $path): array {
        if (!is_file($path)) {
            return ['success' => false, 'error' => 'file not found'];
        }

        // WAF 自身文件不切割
        if (self::isProtectedFile($path)) {
            return ['success' => false, 'error' => 'protected file'];
        }

        $baselineHash = self::getBaselineHash($path);
        if ($baselineHash === null) {
            return ['success' => false, 'error' => 'not in baseline'];
        }

        $currentContent = @file_get_contents($path);
        if ($currentContent === false) {
            return ['success' => false, 'error' => 'read failed'];
        }

        // 如果当前文件哈希与基线一致，说明没被修改
        if (md5($currentContent) === $baselineHash) {
            return ['success' => true, 'action' => 'no_change', 'message' => '文件未被修改'];
        }

        // 没有原始文件备份无法做精准切割 → 只能整体隔离
        // 基线只存了哈希，没有原始内容 → 需要从备份恢复
        $backupContent = self::getBaselineBackup($path);
        if ($backupContent === null) {
            // 没有备份 → 隔离当前文件并告警
            self::quarantineFile($path, "基线无备份，无法精准切割，已隔离", ['score' => 0, 'type' => 'modified']);
            return ['success' => false, 'error' => 'no backup available', 'action' => 'quarantined'];
        }

        // 行级 diff：找出新增的行
        $originalLines = explode("\n", $backupContent);
        $currentLines  = explode("\n", $currentContent);
        $diff = self::lineDiff($originalLines, $currentLines);

        if (empty($diff['added'])) {
            // 没有新增行，可能是删除或修改 → 直接恢复原始内容
            file_put_contents($path, $backupContent);
            self::log("SURGICAL_CUT 恢复原始文件(无新增): $path");
            return [
                'success'     => true,
                'action'      => 'restored',
                'added_lines' => 0,
                'removed_lines' => count($diff['removed']),
                'message'     => '文件已恢复为原始内容',
            ];
        }

        // 对新增行做恶意检测
        // 构建上下文（所有新增行拼接），用于跨行变量函数检测
        // 攻击者常把 $a='sys'.'tem'; 和 $a($_GET['cmd']); 分两行写
        $context = '';
        foreach ($diff['added'] as $lineInfo) {
            $context .= $lineInfo['content'] . "\n";
        }

        $maliciousLines = [];
        foreach ($diff['added'] as $lineInfo) {
            $lineNum = $lineInfo['line'];
            $lineContent = $lineInfo['content'];
            $analysis = self::analyzeLineForMalware($lineContent, $context);
            if ($analysis['is_malicious']) {
                $maliciousLines[] = [
                    'line'    => $lineNum,
                    'content' => $lineContent,
                    'score'   => $analysis['score'],
                    'reason'  => $analysis['reason'],
                ];
            }
        }

        if (empty($maliciousLines)) {
            // 新增行不是恶意 → 可能是正常更新，不处理
            return [
                'success'       => true,
                'action'        => 'skip',
                'added_lines'   => count($diff['added']),
                'malicious_lines' => 0,
                'message'       => '新增内容非恶意，跳过',
            ];
        }

        // 精准切割：移除恶意行，保留其余内容
        $cleanLines = $currentLines;
        foreach (array_reverse($maliciousLines) as $ml) {
            // 按行号删除（从后往前删，避免行号偏移）
            $lineIdx = $ml['line'] - 1;
            if (isset($cleanLines[$lineIdx])) {
                unset($cleanLines[$lineIdx]);
            }
        }
        $cleanContent = implode("\n", $cleanLines);

        // 写回清理后的内容
        file_put_contents($path, $cleanContent);

        $cutCount = count($maliciousLines);
        self::log("SURGICAL_CUT 精准切割完成: $path, 移除 {$cutCount} 行恶意代码");
        // 集成点 1：事件回流到 AutoLearn
        self::notifyAutoLearn('surgical_cut', $path, ['score' => 80]);

        return [
            'success'         => true,
            'action'          => 'cut',
            'added_lines'     => count($diff['added']),
            'malicious_lines' => $cutCount,
            'removed_lines'   => count($diff['removed']),
            'malicious_details' => $maliciousLines,
            'message'         => "精准切割完成，移除 {$cutCount} 行恶意代码",
        ];
    }

    /**
     * 获取基线备份的原始文件内容
     * 基线锁定时，将原始文件备份到 quarantine/baseline_backup/
     */
    private static function getBaselineBackup(string $path): ?string {
        $backupDir = self::$quarantine_dir . 'baseline_backup/';
        $backupFile = $backupDir . md5($path) . '.bak';
        if (!is_file($backupFile)) return null;
        $content = @file_get_contents($backupFile);
        return $content !== false ? $content : null;
    }

    /**
     * 建立基线时备份所有原始文件
     */
    private static function backupBaselineFiles(array $baseline): int {
        $backupDir = self::$quarantine_dir . 'baseline_backup/';
        waf_ensure_dir($backupDir);

        $count = 0;
        foreach ($baseline as $path => $info) {
            if (!is_file($path)) continue;
            $backupFile = $backupDir . md5($path) . '.bak';
            if (@copy($path, $backupFile)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * 行级 diff — 找出新增和删除的行
     */
    private static function lineDiff(array $original, array $current): array {
        $added = [];
        $removed = [];

        $origSet = [];
        foreach ($original as $idx => $line) {
            $key = md5(trim($line));
            $origSet[$key][] = $idx + 1;
        }

        $curSet = [];
        foreach ($current as $idx => $line) {
            $key = md5(trim($line));
            $curSet[$key][] = $idx + 1;
        }

        // 找新增行（当前有，原始没有）
        foreach ($current as $idx => $line) {
            $key = md5(trim($line));
            if (!isset($origSet[$key])) {
                $added[] = ['line' => $idx + 1, 'content' => $line];
            }
        }

        // 找删除行（原始有，当前没有）
        foreach ($original as $idx => $line) {
            $key = md5(trim($line));
            if (!isset($curSet[$key])) {
                $removed[] = ['line' => $idx + 1, 'content' => $line];
            }
        }

        return ['added' => $added, 'removed' => $removed];
    }

    /**
     * 对单行做恶意检测（用于精准切割）
     *
     * 抗混淆设计：攻击者常用以下手法绕过简单正则
     *   1. 变量函数：$a='sys'.'tem'; $a($_GET['cmd']);
     *   2. 字符串拼接：'ev'.'al'(...)
     *   3. 注释插入：ev[xx]al(...)（注释符被插入函数名中间）
     *   4. 可变变量：$$func(...)
     *   5. 嵌套编码：base64_decode(base64_decode(...))
     *   6. chr() 拼装：chr(101).chr(118).chr(97).chr(108)
     *   7. Hex/Octal 转义："\x65\x76\x61\x6c"
     *   8. URL/HTML 编码：%65%76%61%6c
     *
     * 应对策略：先脱壳归一化，再对原始行+归一化行做双层特征检测；
     * 混淆行为本身也是可疑信号（正常代码极少混淆）。
     *
     * @param string $line    待检测的行
     * @param string $context 上下文（同一文件的其他新增行拼接），用于跨行变量函数检测
     */
    private static function analyzeLineForMalware(string $line, string $context = ''): array {
        $score = 0;
        $reason = '';
        $indicators = [];

        // === 1. 静态脱壳（注释剥离 + chr/hex/octal 拼装 + 字符串拼接） ===
        $normalized = self::deobfuscateLine($line, $indicators);

        // 混淆行为本身加分（合法代码极少混淆）
        if (!empty($indicators)) {
            $obfWeight = min(count($indicators) * 8, 25);
            $score += $obfWeight;
            $reason .= '混淆特征(' . implode(',', $indicators) . '); ';
        }

        // === 2. 双层特征码扫描（原始行 + 归一化行都查） ===
        $checkedTexts = [$line];
        if ($normalized !== $line) {
            $checkedTexts[] = $normalized;
        }
        foreach ($checkedTexts as $idx => $text) {
            $suffix = $idx === 0 ? '' : '(归一化)';
            $textLower = strtolower($text);
            foreach (self::$malware_signatures as $sig => $weight) {
                if (strpos($textLower, strtolower($sig)) !== false) {
                    $score += $weight;
                    $reason .= "特征码{$suffix}:{$sig}; ";
                }
            }
        }

        // === 2.5 集成点 2：AutoLearn 高频攻击特征反哺（单向只读建议） ===
        // 安全设计：
        //   - 仅作"加分"建议，权重上限 10
        //   - 必须配合沙箱原有特征码命中才能加分（防反向污染误杀）
        //   - 即使匹配也只加 5-10 分，不能单独触发判定（阈值 20）
        $hotSigs = self::getHotSignaturesFromAutoLearn();
        if (!empty($hotSigs) && $score > 0) {
            foreach ($checkedTexts as $text) {
                $textLower = strtolower($text);
                foreach ($hotSigs as $sig => $weight) {
                    if (strpos($textLower, strtolower($sig)) !== false) {
                        $addScore = min($weight, 10);
                        $score += $addScore;
                        $reason .= "AutoLearn热点({$sig},+{$addScore}); ";
                    }
                }
            }
        }

        // === 3. 危险函数调用（边界匹配，防 'eval_xxx(' 误报） ===
        if (preg_match('/\b(eval|assert|system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i', $normalized)) {
            $score += 25;
            $reason .= '危险函数; ';
        }

        // === 4. 变量函数调用：$f='sys'.'tem'; $f($_GET['cmd']); ===
        if (preg_match('/\$[a-z_]\w*\s*=\s*[\'"].*?[\'"]\s*(\.\s*[\'"].*?[\'"])*\s*;/i', $normalized)
            && preg_match('/\$[a-z_]\w*\s*\(/i', $normalized)) {
            $score += 25;
            $reason .= '变量函数调用; ';
        }

        // === 5. 可变变量 $$func(...) ===
        if (preg_match('/\$\$[a-z_]\w*\s*\(/i', $normalized)) {
            $score += 25;
            $reason .= '可变变量调用; ';
        }

        // === 6. $_GET/$_POST/$_REQUEST 直接传入 ===
        if (preg_match('/\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i', $normalized)) {
            $score += 20;
            $reason .= '用户输入直接传入; ';
        }

        // === 7. 长 Base64 字符串（疑似编码载荷） ===
        if (preg_match('/[A-Za-z0-9+\/]{60,}={0,2}/', $normalized)) {
            $score += 15;
            $reason .= '长Base64; ';
        }

        // === 8. 嵌套编码 ===
        if (preg_match('/(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(/i', $normalized)) {
            $score += 20;
            $reason .= '嵌套编码; ';
        }

        // === 9. chr() 拼装（≥3 个 chr 连用，行内组装字符串） ===
        if (preg_match_all('/chr\s*\(\s*\d+\s*\)/i', $normalized, $m) >= 1
            && count($m[0]) >= 3) {
            $score += 20;
            $reason .= 'chr()拼装; ';
        }

        // === 10. Hex/Octal 转义序列（≥2 个连用视为可疑） ===
        $hexCount = preg_match_all('/\\\\x[0-9a-f]{2}/i', $normalized);
        $octCount = preg_match_all('/\\\\[0-7]{3}/', $normalized);
        if ($hexCount >= 2 || $octCount >= 2) {
            $score += 12;
            $reason .= "Hex/Octal转义(hex={$hexCount},oct={$octCount}); ";
        }

        // === 11. create_function / preg_replace /e 修饰符（旧版 PHP RCE 入口） ===
        if (preg_match('/create_function\s*\(/i', $normalized)) {
            $score += 25;
            $reason .= 'create_function; ';
        }
        if (preg_match('#preg_replace\s*\(.+?/[imsxADSUXJu]*e[imsxADSUXJu]*["\']#i', $normalized)) {
            $score += 30;
            $reason .= 'preg_replace /e修饰符; ';
        }

        // === 12. 反引号执行注入 ===
        if (preg_match('/`.*\$_(GET|POST|REQUEST)/i', $normalized)) {
            $score += 25;
            $reason .= '反引号执行; ';
        }

        // === 13. 文件写入 + 用户输入 ===
        if (preg_match('/(file_put_contents|fwrite|fputs)\s*\(/i', $normalized)
            && preg_match('/\$_(GET|POST|REQUEST)/i', $normalized)) {
            $score += 25;
            $reason .= '写入用户输入到文件; ';
        }

        // === 14. include/require 来自用户输入 ===
        if (preg_match('/(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)/i', $normalized)) {
            $score += 30;
            $reason .= '包含用户输入文件; ';
        }

        // === 15. 调用 AdversarialDefense 14 层解码（针对 URL/HTML/base64 编码混淆） ===
        if (class_exists('AdversarialDefense', false)) {
            $advResult = AdversarialDefense::normalizeWithContext($line);
            $advDepth = $advResult['encoding_depth'] ?? 0;
            if ($advDepth >= 1) {
                $score += min($advDepth * 5, 15);
                $reason .= "AdversarialDefense解码(depth={$advDepth}); ";
            }
            $decoded = $advResult['output'] ?? '';
            if ($decoded && $decoded !== $line) {
                $decodedLower = strtolower($decoded);
                foreach (self::$malware_signatures as $sig => $weight) {
                    if (strpos($decodedLower, strtolower($sig)) !== false) {
                        $score += $weight;
                        $reason .= "解码后特征码:{$sig}; ";
                    }
                }
                // 解码后出现的危险函数
                if (preg_match('/\b(eval|assert|system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i', $decoded)) {
                    $score += 25;
                    $reason .= '解码后危险函数; ';
                }
            }
        }

        // === 16. 跨行变量函数检测 ===
        // 当前行形如 $func(...) 调用，看上下文里是否有 $func = '...' 赋值
        if ($context !== '' && preg_match('/^\s*\$([a-z_]\w*)\s*\(/i', $line, $m)) {
            $varName = preg_quote('$' . $m[1], '/');
            if (preg_match('/' . $varName . '\s*=\s*[\'"].*?[\'"]/i', $context)) {
                $score += 20;
                $reason .= '跨行变量函数; ';
            }
        }

        return [
            'is_malicious' => $score >= 20,
            'score'        => min($score, 100),
            'reason'       => $reason ?: 'clean',
            'obfuscation'  => $indicators,
        ];
    }

    /**
     * PHP 代码静态脱壳 — 针对常见混淆手法做字符串归一化
     *
     * 安全原则：纯字符串变换，绝不执行任何代码（不用 eval/assert/create_function）。
     * 只做：注释剥离、chr()→字符串、hex/octal→字符串、字符串字面量拼接、URL/HTML 解码。
     *
     * @param string $line       原始行
     * @param array  $indicators [out] 记录命中的脱壳类型
     */
    private static function deobfuscateLine(string $line, array &$indicators = []): string {
        $text = $line;

        // 1. PHP-aware 注释剥离（不破坏字符串内部）
        $stripped = self::stripPhpComments($text);
        if ($stripped !== $text) {
            $indicators[] = '注释插入';
            $text = $stripped;
        }

        // 2. chr() 拼装还原：chr(101).chr(118).chr(97).chr(108) => "eval"
        if (preg_match_all('/chr\s*\(\s*(\d+)\s*\)/i', $text, $chrMatches)) {
            if (count($chrMatches[0]) >= 2) {
                $assembled = '';
                foreach ($chrMatches[1] as $code) {
                    $c = (int)$code & 0xFF;
                    $assembled .= chr($c);
                }
                $text = str_replace($chrMatches[0], '"' . $assembled . '"', $text);
                $indicators[] = 'chr拼装';
            }
        }

        // 3. Hex 转义还原："\x65\x76\x61\x6c" => "eval"
        if (preg_match('/\\\\x[0-9a-f]{2}/i', $text)) {
            $newText = preg_replace_callback('/"(?:\\\\x[0-9a-f]{2})+"/i', function($m) {
                $decoded = '';
                if (preg_match_all('/\\\\x([0-9a-f]{2})/i', $m[0], $hex)) {
                    foreach ($hex[1] as $h) $decoded .= chr(hexdec($h));
                    return '"' . $decoded . '"';
                }
                return $m[0];
            }, $text);
            if ($newText !== $text) {
                $text = $newText;
                $indicators[] = 'Hex转义';
            }
        }

        // 4. Octal 转义还原："\101\102\103" => "ABC"
        if (preg_match('/\\\\[0-7]{3}/', $text)) {
            $newText = preg_replace_callback('/"(?:\\\\[0-7]{3})+"/', function($m) {
                $decoded = '';
                if (preg_match_all('/\\\\([0-7]{3})/', $m[0], $oct)) {
                    foreach ($oct[1] as $o) $decoded .= chr(octdec($o));
                    return '"' . $decoded . '"';
                }
                return $m[0];
            }, $text);
            if ($newText !== $text) {
                $text = $newText;
                $indicators[] = 'Octal转义';
            }
        }

        // 5. 字符串字面量拼接还原：'ev'.'al' => "eval"
        //    匹配形如 'ev'.'al' 或 "ev"."al" 的连用（≥2 段拼接）
        if (preg_match('/([\'"][a-z0-9_]+[\'"]\s*\.\s*){1,}[\'"][a-z0-9_]+[\'\"]/i', $text)) {
            $newText = preg_replace_callback(
                '/(?:[\'"]([a-z0-9_]+)[\'"]\s*\.\s*){1,}[\'"]([a-z0-9_]+)[\'\"]/i',
                function($m) {
                    $full = $m[0];
                    if (preg_match_all('/[\'"]([a-z0-9_]+)[\'"]/i', $full, $parts)) {
                        return '"' . implode('', $parts[1]) . '"';
                    }
                    return $full;
                },
                $text
            );
            if ($newText !== $text) {
                $text = $newText;
                $indicators[] = '字符串拼接';
            }
        }

        // 6. URL/HTML 解码（依赖 AdversarialDefense 14 层解码引擎）
        if (class_exists('AdversarialDefense', false)) {
            $decoded = AdversarialDefense::normalize($text);
            if ($decoded !== $text && $decoded !== '') {
                $indicators[] = '编码解码';
                $text = $decoded;
            }
        }

        return $text;
    }

    /**
     * PHP-aware 注释剥离
     * 安全移除 // 和 /* *\/ 注释，但不破坏字符串字面量内部的伪注释
     * 状态机：单引号串 / 双引号串 / 行注释 / 块注释 四种状态互斥切换
     */
    private static function stripPhpComments(string $code): string {
        $result = '';
        $len = strlen($code);
        $inSingleStr = false;
        $inDoubleStr = false;
        $inLineComment = false;
        $inBlockComment = false;
        $escaped = false;

        for ($i = 0; $i < $len; $i++) {
            $char = $code[$i];
            $next = ($i + 1 < $len) ? $code[$i + 1] : '';

            if ($inLineComment) {
                if ($char === "\n") {
                    $inLineComment = false;
                    $result .= $char; // 保留换行，避免行号偏移
                }
                continue;
            }
            if ($inBlockComment) {
                if ($char === '*' && $next === '/') {
                    $inBlockComment = false;
                    $i++; // 跳过 /
                }
                continue;
            }
            if ($inSingleStr) {
                $result .= $char;
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === "'") {
                    $inSingleStr = false;
                }
                continue;
            }
            if ($inDoubleStr) {
                $result .= $char;
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inDoubleStr = false;
                }
                continue;
            }

            // 不在字符串或注释内
            if ($char === '/' && $next === '/') {
                $inLineComment = true;
                $i++;
                continue;
            }
            if ($char === '/' && $next === '*') {
                $inBlockComment = true;
                $i++;
                continue;
            }
            if ($char === '#') {
                $inLineComment = true;
                continue;
            }
            if ($char === "'") {
                $inSingleStr = true;
            } elseif ($char === '"') {
                $inDoubleStr = true;
            }
            $result .= $char;
        }

        return $result;
    }

    // ====================== 实时监控（请求结束时触发） ======================

    /**
     * 实时文件监控 — 对比请求开始和结束时的文件快照
     * 新落地的恶意文件秒删除，修改的现有文件触发分析
     */
    public static function realtimeMonitor() {
        $before = self::loadSnapshot();
        if (empty($before)) return; // 首次运行无快照，跳过

        $mode = self::getMode();
        $baselineLocked = self::isBaselineLocked();

        $after = self::takeSnapshot();
        $newFiles = array_diff_key($after, $before);
        $modifiedFiles = [];

        foreach ($after as $path => $info) {
            if (isset($before[$path]) && $before[$path]['md5'] !== $info['md5']) {
                $modifiedFiles[] = $path;
            }
        }

        // 处理新文件
        foreach ($newFiles as $path => $info) {
            // ⚠️ 保护检查：WAF 自身文件永不删除
            if (self::isProtectedFile($path)) {
                self::log("SKIP_PROTECTED 跳过受保护文件: $path");
                continue;
            }

            // 学习模式：只记录告警，不删除
            if ($mode === 'learning') {
                $analysis = self::analyzeFile($path);
                if ($analysis['is_malicious']) {
                    self::log("LEARNING_ALERT 新文件疑似恶意(学习模式不删除): $path (score={$analysis['score']})");
                    self::alertWebhook("学习模式告警-新文件", $path, $analysis);
                }
                continue;
            }

            // 保护模式：基线锁定后，不在基线中的新文件直接秒删除
            if ($mode === 'protecting' && $baselineLocked) {
                if (!self::isInBaseline($path)) {
                    // 不在基线中的新文件 → 秒删除
                    @unlink($path);
                    self::log("SECS_DELETE 新文件不在基线中，已秒删: $path");
                    self::alertWebhook("秒删-未授权新文件", $path, ['score' => 100, 'type' => 'unauthorized_new']);
                    // 集成点 1：事件回流到 AutoLearn
                    self::notifyAutoLearn('instant_delete_unauthorized', $path, ['score' => 100]);
                    continue;
                }
            }

            // 保护模式但在基线中的新文件，或基线模式 → 分析
            $analysis = self::analyzeFile($path);
            if ($analysis['is_malicious']) {
                if (defined('WAF_SANDBOX_INSTANT_DELETE_NEW') && WAF_SANDBOX_INSTANT_DELETE_NEW) {
                    @unlink($path);
                    self::log("SECS_DELETE 新落地恶意文件已秒删: $path (score={$analysis['score']})");
                    self::alertWebhook("秒删恶意文件", $path, $analysis);
                    // 集成点 1：事件回流到 AutoLearn
                    self::notifyAutoLearn('instant_delete', $path, $analysis);
                } else {
                    self::quarantineFile($path, "新落地恶意文件 (score={$analysis['score']})", $analysis);
                }
            }
        }

        // 处理修改的文件
        foreach ($modifiedFiles as $path) {
            // ⚠️ 保护检查：WAF 自身文件永不隔离
            if (self::isProtectedFile($path)) {
                self::log("SKIP_PROTECTED 跳过受保护文件(已修改): $path");
                continue;
            }

            // 学习模式：只记录告警
            if ($mode === 'learning') {
                $analysis = self::analyzeFile($path);
                if ($analysis['is_malicious']) {
                    self::log("LEARNING_ALERT 文件被修改且疑似恶意(学习模式不处理): $path (score={$analysis['score']})");
                    self::alertWebhook("学习模式告警-文件被修改", $path, $analysis);
                }
                continue;
            }

            // 保护模式且基线已锁定 → 精准切割
            if ($mode === 'protecting' && $baselineLocked && self::isInBaseline($path)) {
                $cutResult = self::surgicalCut($path);
                if ($cutResult['action'] === 'cut') {
                    self::log("SURGICAL_CUT 精准切割: $path, 移除 {$cutResult['malicious_lines']} 行恶意代码");
                    self::alertWebhook("精准切割", $path, ['score' => 100, 'type' => 'surgical_cut', 'details' => $cutResult]);
                } elseif ($cutResult['action'] === 'restored') {
                    self::log("SURGICAL_CUT 恢复原始文件: $path");
                    self::alertWebhook("恢复原始文件", $path, ['score' => 80, 'type' => 'restored']);
                }
                continue;
            }

            // 保护模式但不在基线中，或基线模式 → 原有逻辑
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
        // 学习模式不自动扫描（让用户手动排查）
        if (self::getMode() === 'learning') return;

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
        // PHP 7.0+ 数组常量直接使用，无需 json_decode
        $dirs = defined('WAF_SANDBOX_MONITOR_DIRS') ? WAF_SANDBOX_MONITOR_DIRS : [ABSPATH];
        return is_array($dirs) ? $dirs : [ABSPATH];
    }

    private static function getExcludeDirs() {
        // PHP 7.0+ 数组常量直接使用，无需 json_decode
        $dirs = defined('WAF_SANDBOX_EXCLUDE_DIRS') ? WAF_SANDBOX_EXCLUDE_DIRS : [WAF_LOG_PATH];
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
                        // 集成点 1：事件回流到 AutoLearn
                        self::notifyAutoLearn('instant_delete', $path, $analysis);
                    }
                } elseif (defined('WAF_SANDBOX_AUTO_QUARANTINE') && WAF_SANDBOX_AUTO_QUARANTINE) {
                    // ⚠️ 二次保护检查
                    if (!self::isProtectedFile($path)) {
                        self::quarantineFile($path, "全量扫描发现恶意代码 (score={$analysis['score']})", $analysis);
                        $quarantinedCount++;
                        self::log("AUTO_QUARANTINE 文件已隔离: $path (score={$analysis['score']})");
                        self::alertWebhook("文件隔离", $path, $analysis);
                        // 集成点 1：事件回流到 AutoLearn（quarantineFile 内部已通知，这里跳过避免重复）
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
        // 集成点 1：事件回流到 AutoLearn
        self::notifyAutoLearn('quarantine', $path, $analysis);
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
     * 获取基线文件路径（供外部调用）
     */
    public static function getBaselineFile(): string {
        return self::$baseline_file;
    }

    /**
     * 获取隔离区目录（供外部调用）
     */
    public static function getQuarantineDir(): string {
        return self::$quarantine_dir;
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
            'mode'                 => self::getMode(),
            'baseline'             => self::getBaselineInfo(),
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

    /**
     * 集成点 1：事件回流到 AutoLearn
     *
     * 把沙箱事件（秒删/精准切割/隔离）的来源 IP 标记为高危。
     * AutoLearn 在 getDeviationScore 时对该 IP 加成，下次请求即可被拦截。
     *
     * 安全设计：
     *   - 必须开启 WAF_SANDBOX_LEARN_COUPLING 开关（默认 true）
     *   - CLI 扫描（无 REMOTE_ADDR）自动跳过
     *   - Admin IP 跳过（管理员手动操作不应污染行为基线）
     *   - 失败静默，绝不影响沙箱主流程
     */
    private static function notifyAutoLearn(string $reason, string $path, array $context = []) {
        if (!defined('WAF_SANDBOX_LEARN_COUPLING') || !WAF_SANDBOX_LEARN_COUPLING) return;
        if (!class_exists('AutoLearn', false)) return;

        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            if ($ip === '' || (function_exists('waf_is_admin_ip') && waf_is_admin_ip())) {
                return;
            }
            AutoLearn::markIpFromSandbox($ip, $reason, [
                'path'  => $path,
                'score' => $context['score'] ?? 0,
            ]);
        } catch (\Throwable $e) {
            // 集成失败绝不影响沙箱主流程
            self::log("AUTOLEARN_NOTIFY_FAILED: " . $e->getMessage());
        }
    }

    /**
     * 集成点 2：查询 AutoLearn 高频攻击特征（单向只读）
     *
     * 用于 analyzeLineForMalware 合并查询。
     * 安全设计：返回的特征权重上限 15，沙箱侧最多加 10 分，
     * 必须配合原有特征才能加分，不能单独触发判定。
     */
    private static function getHotSignaturesFromAutoLearn(): array {
        if (!defined('WAF_SANDBOX_LEARN_COUPLING') || !WAF_SANDBOX_LEARN_COUPLING) return [];
        if (!class_exists('AutoLearn', false)) return [];

        try {
            return AutoLearn::getHotSignatures(10, 50);
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * 集成点 3：基线联动 — 通知 AutoLearn 冻结/解冻行为基线
     */
    private static function notifyAutoLearnFreeze(bool $freeze) {
        if (!defined('WAF_SANDBOX_LEARN_COUPLING') || !WAF_SANDBOX_LEARN_COUPLING) return;
        if (!class_exists('AutoLearn', false)) return;

        try {
            if ($freeze) {
                AutoLearn::freezeBaseline('sandbox_lock');
            } else {
                AutoLearn::unfreezeBaseline();
            }
        } catch (\Throwable $e) {
            self::log("AUTOLEARN_FREEZE_FAILED: " . $e->getMessage());
        }
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
