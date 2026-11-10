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
 * YSL语枢-盾甲WAF · 单文件发行（Phar）
 *
 *   php -d phar.readonly=0 build.php
 *
 * 产物：dist/shield-waf.phar —— 用户部署只需这 1 个文件。
 * 内核 core/ 原样打包，不修改一行；日志/数据目录由 stub 指向 phar 外部。
 */
declare(strict_types=1);

$root = __DIR__;
$dist = $root . '/dist';
$out = $dist . '/shield-waf.phar';

if (!is_dir($dist) && !mkdir($dist, 0755, true) && !is_dir($dist)) {
    fwrite(STDERR, "无法创建 dist/\n");
    exit(1);
}
if (is_file($out)) { @unlink($out); }

$stub = <<<'STUB'
<?php
/**
 * YSL语枢-盾甲WAF 单文件发行 · stub
 * 所有路径常量指向 phar 外部真实目录，日志与状态可写。
 */
Phar::mapPhar('shield-waf.phar');

$wafHome = getenv('WAF_HOME');
if (!$wafHome || !is_dir($wafHome)) {
    $wafHome = dirname(Phar::running(false));
}
$wafHome = rtrim(str_replace('\\', '/', $wafHome), '/');
if (!defined('WAF_HOME'))    define('WAF_HOME', $wafHome);
if (!defined('ABSPATH'))     define('ABSPATH', $wafHome . '/');
$wafLogDir  = rtrim(str_replace('\\', '/', getenv('WAF_LOG_DIR') ?: ($wafHome . '/var/logs')), '/');
$wafDataDir = rtrim(str_replace('\\', '/', getenv('WAF_DATA_DIR') ?: ($wafHome . '/var/data')), '/');
if (!defined('WAF_LOG_PATH')) define('WAF_LOG_PATH', $wafLogDir);
if (!defined('WAF_DATA_PATH')) define('WAF_DATA_PATH', $wafDataDir);
foreach ([$wafLogDir, $wafDataDir] as $p) {
    if (!is_dir($p)) { @mkdir($p, 0750, true); }
}

require 'phar://shield-waf.phar/shield-waf.php';
__HALT_COMPILER();
STUB;

try {
    $phar = new Phar($out, 0, 'shield-waf.phar');
    $phar->startBuffering();

    $phar->addFile($root . '/shield-waf.php', 'shield-waf.php');
    $phar->addFile($root . '/config.php', 'config.php');
    $phar->addFile($root . '/console.php', 'console.php');
    $phar->addFile($root . '/screen.php', 'screen.php');
    $phar->addFile($root . '/runtime.php', 'runtime.php');
    $phar->addFile($root . '/i18n.php', 'i18n.php');
    $phar->addFile($root . '/features.php', 'features.php');
    $phar->addFile($root . '/control.php', 'control.php');
    $phar->addFile($root . '/qps.php', 'qps.php');
    $phar->addFile($root . '/pages.php', 'pages.php');
    $phar->addFile($root . '/dna.php', 'dna.php');
    foreach (glob($root . '/core/Ysl*.php') ?: [] as $f) {
        $phar->addFile($f, 'core/' . basename($f));
    }
    // AI 自学习层与通用函数：全部打进同一个 phar，用户仍只部署 1 个文件。
    // 注意：自 v6.1.0 起语义解析层（semantic/）默认不打包、不加载（核心+AI 精简模式）。
    foreach (['ai', 'Support'] as $wafSub) {
        foreach (glob($root . '/' . $wafSub . '/*.php') ?: [] as $f) {
            $phar->addFile($f, $wafSub . '/' . basename($f));
        }
    }

    $phar->setStub($stub);
    $phar->stopBuffering();
} catch (Throwable $e) {
    fwrite(STDERR, '构建失败：' . $e->getMessage() . "\n");
    fwrite(STDERR, "提示：无 phar/zip 扩展时请用「源码目录集成」方式部署。\n");
    @unlink($out);
    exit(1);
}

$count = count($phar);
printf("已生成 %s（%.2f MiB，%d 个文件）\n", $out, filesize($out) / 1048576, $count);
