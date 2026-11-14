<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
 * 许可  : MIT -- SPDX-License-Identifier: MIT
 */

/**
 * YSL语枢-盾甲WAF · 安装 / 自检 / 卸载（CLI）
 *
 *   php install.php --check
 *   php install.php --site=/path/to/site
 *   php install.php --site=/path/to/site --uninstall
 *
 * 默认源码模式：只往站点目录的 .user.ini 写入 auto_prepend_file，指向本包的
 * shield-waf.php（core/、ai/ 随包发布，由 php-beast 扩展在加载时透明解密）；
 * 不碰任何业务代码。
 *
 * 前提：目标 PHP 必须已安装 php-beast 扩展（详见 README「核心加密与 php-beast 扩展」）。
 * 可选 --phar=/path/shield-waf.phar 走单文件模式（需自行构建；phar 内加密文件与 beast
 * 的兼容性未经验证，不推荐用于生产）。
 */
declare(strict_types=1);

$root = __DIR__;
$args = [];
foreach (array_slice($argv, 1) as $a) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $a, $m)) {
        $args[$m[1]] = $m[2] ?? true;
    }
}

function out(string $s): void { echo $s . PHP_EOL; }
function fail(string $s): void { out('  [FAIL] ' . $s); exit(1); }
function ok(string $s): void  { out('  [ OK ] ' . $s); }

out('YSL语枢-盾甲WAF v6.5.1 · ' . (isset($args['uninstall']) ? '卸载' : (isset($args['check']) ? '环境自检' : '安装')));
out(str_repeat('-', 60));

// ---------- 环境自检 ----------
if (PHP_VERSION_ID < 80100) {
    fail('需要 PHP >= 8.1，当前 ' . PHP_VERSION);
}
ok('PHP ' . PHP_VERSION);

$kernelFiles = glob($root . '/core/Ysl*.php') ?: [];
if (count($kernelFiles) !== 19) {
    fail('内核文件应为 19 个，实际 ' . count($kernelFiles) . ' 个（core/ 缺失或被改动）');
}
ok('内核 19 个文件齐全（母本完整保留，YslEngine.php 经授权改动）');

foreach (['shield-waf.php', 'config.php', 'core/YslWaf.php', 'core/YslEngine.php'] as $f) {
    if (!is_file($root . '/' . $f)) { fail('缺少 ' . $f); }
}
ok('入口与配置齐全');

// ---------- 运行时依赖函数（disable_functions 加固环境）----------
// 宝塔等面板默认会禁用 putenv / exec 等函数。过去自检完全不看这些，导致
// "自检全绿、上线整站 500"。入口已对这些函数做了 function_exists 兜底，
// 不会致命，但能力会降级；自检必须如实报告，绝不静默放过。
$disabledHint = '';
foreach ([
    'putenv' => '运行时开关注入（大屏控制台的模式/守卫/蜜罐开关）',
    'exec'   => 'DNA 守护进程启停、控制台部分运维动作',
] as $fn => $what) {
    if (!function_exists($fn)) {
        out('  [WARN] ' . $fn . '() 被禁用（disable_functions），影响：' . $what);
        out('         入口已做兜底，站点不会 500，但该能力降级；');
        out('         需要完整能力请从 disable_functions 移除 ' . $fn . '()，');
        out('         或在 PHP-FPM 池配置里用 env[WAF_*] 预置默认值。');
        $disabledHint .= ' ' . $fn . '()';
    } else {
        ok($fn . '() 可用（' . $what . '）');
    }
}
if ($disabledHint !== '') {
    out('  [INFO] 降级提示：运行时开关将回落到启动环境变量 / WAF_ENV_DEFAULTS，');
    out('         默认 mode=enforce、各守卫全开、蜜罐停用，均为 fail-closed，不会静默放行。');
}

if (!extension_loaded('pdo_sqlite')) {
    out('  [WARN] 未装 pdo_sqlite：C2 监控模块会降级，主检测流程不受影响');
} else {
    ok('pdo_sqlite 可用');
}

// core/、ai/ 为 php-beast 加密文件，必须由 beast 扩展解密后才能被 PHP 编译执行。
// 这不是"可选组件"：缺它整站会 503（fail-closed），因此默认硬性拦截，不给静默放行的机会。
if (!extension_loaded('beast')) {
    out('');
    out('  ==================== 缺少解密扩展，无法上线 ====================');
    out('  [FAIL] 未检测到 php-beast 扩展。');
    out('         core/、ai/ 是加密文件，缺该扩展时内核无法解密——');
    out('         站点会在**每一个请求**上返回 503，不是"少个功能"，是整体不可用。');
    out('');
    out('  安装步骤（Linux / PHP 8.1）：');
    out('    1) 找到扩展目录：php -i | grep "^extension_dir"');
    out('    2) 复制扩展：    cp ext/beast-8.1.so <extension_dir>/beast.so');
    out('    3) 启用配置：    cp ext/beast.ini /etc/php/8.1/mods-available/beast.ini');
    out('                     （或直接写入对应 SAPI 的 conf.d 目录）');
    out('    4) 重启 PHP-FPM：systemctl restart php8.1-fpm');
    out('    5) 验证：        php -m | grep beast   → 应输出 beast');
    out('');
    out('  三个高频坑：');
    out('    · .so 按 PHP ABI 编译，必须与目标 PHP **主版本一致**（本包为 8.1）；8.2/8.3 加载会失败。');
    out('    · 装了但没重启 PHP-FPM —— 扩展不会自动生效。');
    out('    · CLI 与 FPM 可能是两个 PHP：命令行有 beast 不代表网站进程有，请用 FPM 同版本的 php 复验。');
    out('');
    out('  若确认 FPM 侧已装好、只是 CLI 版本不同，可加 --force 跳过本检查后继续。');
    out('  ================================================================');
    out('');
    if (!isset($args['force'])) {
        fail('已中止，未写入任何配置（加 --force 可跳过，但请自行确认 FPM 侧真的加载了 beast）');
    }
    out('  [WARN] 已按 --force 继续。上线前请务必确认 FPM 侧 php -m 里有 beast，否则全站 503。');
} else {
    ok('php-beast 扩展已加载（可解密 core/、ai/）');
}

$probeDir = (string)($args['site'] ?? $root);
if (!is_dir($probeDir) && !@mkdir($probeDir, 0755, true) && !is_dir($probeDir)) {
    fail('目录不可写：' . $probeDir);
}
$testFile = $probeDir . '/.waf-write-probe';
if (@file_put_contents($testFile, 'x') === false) {
    fail('目录不可写：' . $probeDir);
}
@unlink($testFile);
ok('目录可写：' . $probeDir);

if (isset($args['check'])) {
    out(str_repeat('-', 60));
    out('自检通过。安装命令：php install.php --site=/你的站点目录');
    exit(0);
}

$site = (string)($args['site'] ?? '');
if ($site === '') {
    fail('请用 --site=/绝对路径 指定站点目录');
}
$site = rtrim(str_replace('\\', '/', $site), '/');
if (!is_dir($site)) { fail('站点目录不存在：' . $site); }

$ini = $site . '/.user.ini';
$backup = $site . '/.user.ini.waf-backup';

// ---------- 卸载 ----------
if (isset($args['uninstall'])) {
    if (is_file($backup)) {
        $cur = @file_get_contents($ini) ?: '';
        if (strpos($cur, 'shield-waf') === false) {
            out('  [INFO] .user.ini 已不含 YSL语枢-盾甲WAF 配置，跳过恢复');
        } elseif (@rename($backup, $ini)) {
            ok('已恢复原 .user.ini，备份文件已消费');
        } else {
            fail('恢复 .user.ini 失败，请手动处理 ' . $backup);
        }
    } elseif (is_file($ini)) {
        $lines = file($ini, FILE_IGNORE_NEW_LINES);
        $kept = array_values(array_filter($lines, static fn($l) => stripos($l, 'shield-waf') === false));
        @file_put_contents($ini, $kept ? implode("\n", $kept) . "\n" : '');
        ok('已移除 auto_prepend_file 配置行');
    }
    foreach (['shield-waf.phar'] as $f) {
        if (is_file($site . '/' . $f) && @unlink($site . '/' . $f)) { ok('已删除 ' . $f); }
    }
    out(str_repeat('-', 60));
    out('卸载完成。请重启 PHP-FPM 使 .user.ini 生效（默认有 300 秒缓存）。');
    exit(0);
}

// ---------- 安装 ----------
// 默认源码模式：auto_prepend 指向本包的 shield-waf.php（core/、ai/ 随包走，beast 解密）。
// 可选 --phar：指向自行构建的 shield-waf.phar（单文件模式，beast 兼容性未验证，不推荐）。
$mode = 'source';
if (isset($args['phar'])) {
    $phar = str_replace('\\', '/', (string)$args['phar']);
    if (!is_file($phar)) { fail('找不到 phar：' . $phar); }
    $target = $phar;
    $mode = 'phar';
} else {
    $target = $root . '/shield-waf.php';
    if (!is_file($target)) { fail('找不到入口：' . $target); }
}
ok('部署模式：' . $mode . '（' . $target . '）');

$logDir  = rtrim(str_replace('\\', '/', (string)(getenv('WAF_LOG_DIR') ?: ($root . '/var/logs'))), '/');
$dataDir = rtrim(str_replace('\\', '/', (string)(getenv('WAF_DATA_DIR') ?: ($root . '/var/data'))), '/');
foreach ([$logDir, $dataDir] as $p) {
    if (!is_dir($p) && !@mkdir($p, 0750, true) && !is_dir($p)) { fail('无法创建 ' . $p); }
    ok('运行目录：' . $p);
}

// 只读控制台密钥：每次安装重新生成，避免沿用默认值
$keyFile = $dataDir . '/console.key';
$consoleKey = bin2hex(random_bytes(16));
@file_put_contents($keyFile, $consoleKey . "\n", LOCK_EX);
@chmod($keyFile, 0600);
// 运行目录指向 tmpfs 时，额外在本包持久目录留一份；控制台与大屏会优先读运行目录，
// 读不到时回退到这份，避免容器重启 / tmpfs 清空后两个页面同时 403。
$persistKeyFile = $root . '/var/data/console.key';
if (rtrim(str_replace('\\', '/', $persistKeyFile), '/') !== rtrim(str_replace('\\', '/', $keyFile), '/')) {
    if (!is_dir(dirname($persistKeyFile))) { @mkdir(dirname($persistKeyFile), 0750, true); }
    @file_put_contents($persistKeyFile, $consoleKey . "\n", LOCK_EX);
    @chmod($persistKeyFile, 0600);
}
ok('已生成控制台密钥');

if (is_file($ini) && !is_file($backup)) {
    @copy($ini, $backup);
    ok('已备份原 .user.ini → .user.ini.waf-backup');
}
$existing = is_file($ini) ? (string)@file_get_contents($ini) : '';
$lines = $existing === '' ? [] : explode("\n", rtrim($existing, "\r\n"));
// 清除旧的 WAF 配置行（去重 / 升级兼容）
$lines = array_values(array_filter($lines, static fn($l) =>
    stripos($l, 'shield-waf') === false && stripos($l, 'auto_prepend_file') === false));
$lines[] = '; YSL语枢-盾甲WAF · 嵌入式前置（由 install.php 写入）';
$lines[] = 'auto_prepend_file=' . $target;
@file_put_contents($ini, implode("\n", $lines) . "\n");
ok('已写入 auto_prepend_file（重复安装自动去重）');

out(str_repeat('-', 60));
out('安装完成。本包建议放在站点之外的安全路径（如 /opt/ysl-waf），仅站点目录的 .user.ini 引用它。');
out('重启 PHP-FPM 后生效；.user.ini 默认 300 秒缓存，可用 WAF_MODE=observe 先观察误报。');
out('性能：状态与审计写在 ' . $logDir . '；高并发场景可把 WAF_LOG_DIR 指向 tmpfs（如 /dev/shm/waf-logs）进一步降低落盘开销。');
if (getenv('WAF_LOG_DIR') || getenv('WAF_DATA_DIR')) {
    out('注意：已用自定义运行目录，PHP-FPM 环境需设置相同的 WAF_LOG_DIR / WAF_DATA_DIR。');
}
out('零 JS 控制台：http://你的域名/waf-console?key=' . $consoleKey . '（底部表单可直接操作）');
out('态势大屏：  http://你的域名/waf-screen?key=' . $consoleKey . '（全功能控制矩阵逐项可控 + 右上角控制台抽屉；底栏状态灯可点击直达）');
out('蜜罐诱捕：  默认停用（高危）· 启用需输入确认短语「启用蜜罐」+ 用途 + 有效期并二次确认，到期自动停用；一键停用无需确认');
out('QPS 限流：  默认全局 300/600 QPS、单 IP 80/160；429 限流页 / 502 熔断页已内置，阈值可在控制台实时调整');
out('文件 DNA：  先 php dna.php baseline 建档，再 php dna.php watch --interval=30 --apply 守护');
