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
 * YSL语枢-盾甲WAF · 唯一入口（auto_prepend_file 指向本文件）
 *
 * 设计原则：外壳零检测逻辑。定位内核 → 交给内核 → 异常时 fail-closed。
 * core/ 为封存原版，禁止在此目录内修改任何 Ysl*.php。
 *
 * v6.3.0：入口每请求读取 var/data/runtime.json，把大屏控制台写入的运行时配置
 * 真正应用到 config / putenv / 常量，控制按钮不是摆设。文件不存在时与旧版完全等价。
 * v6.5.0：蜜罐改为默认停用且受控启用（确认短语 / 有效期 / 审批留痕 / 到期自动回退），
 *          大屏新增全功能控制矩阵，每一项功能都有真实状态灯与真实操作入口。
 * v6.4.1：展示层统一中文化（i18n.php），内部状态枚举与 JSON 契约不变
 * v6.4.0：前置接入层 QPS 限流 / 熔断，并统一由 pages.php 输出美化的
 * 403 / 429 / 502 / 503 响应页；外壳仍只做分发与呈现，不含检测逻辑。
 */
declare(strict_types=1);

// ---------------------------------------------------------------- 定位站点根（必须早于任何配置读取）
$wafRoot    = __DIR__;
$wafEnvHome = getenv('WAF_HOME');
$wafHome    = defined('WAF_HOME') ? WAF_HOME : ($wafEnvHome ?: $wafRoot);
$wafHome    = rtrim(str_replace('\\', '/', $wafHome), '/');

// ---------------------------------------------------------------- 运行时配置覆盖
require_once $wafRoot . '/runtime.php';   // 内含 require_once qps.php
require_once $wafRoot . '/pages.php';
// 冻结「启动时的环境变量」：下面每请求 putenv 会覆盖运行时值，
// 控制端点的「恢复出厂」必须回到这份启动快照，而不是当前值。
if (!defined('WAF_ENV_DEFAULTS')) {
    define('WAF_ENV_DEFAULTS', [
        'mode'      => getenv('WAF_MODE') ?: 'enforce',
        'ai'        => getenv('WAF_AI_ENABLED') !== '0',
        'fp'        => getenv('WAF_FP_GUARD') !== '0',
        'tautology' => getenv('WAF_TAUTOLOGY_GUARD') !== '0',
        'bypass'    => getenv('WAF_BYPASS_GUARD') !== '0',
        'errors'    => getenv('WAF_KEEP_DISPLAY_ERRORS') === '1',
        'honeypot'  => getenv('WAF_HONEYPOT_ENABLED') === '1',
    ]);
}
$wafRuntime = wafRtRead($wafHome);

// 安全底线：任何模块的 Warning/Notice 一旦输出到响应体，headers 会提前发出，
// 内核 reject() 里的 403 会静默退化成 200。排查时可在控制台打开「错误输出」。
if (!$wafRuntime['guards']['errors']) {
    @ini_set('display_errors', '0');
    @ini_set('display_startup_errors', '0');
    @ini_set('log_errors', '1');
}

if (defined('SHIELD_WAF_BOOTED')) {
    return;
}
define('SHIELD_WAF_BOOTED', true);
define('SHIELD_WAF_VERSION', '6.5.0');

if (!defined('WAF_HOME')) {
    define('WAF_HOME', $wafHome);
}
if (!defined('ABSPATH')) {
    define('ABSPATH', $wafHome . '/');
}
// 日志/状态目录与控制台密钥目录均可由环境变量覆盖，便于把高频状态写放到 tmpfs。
$wafLogDir  = defined('WAF_LOG_PATH')  ? rtrim(str_replace('\\', '/', WAF_LOG_PATH), '/')
                                      : rtrim(str_replace('\\', '/', getenv('WAF_LOG_DIR') ?: ($wafHome . '/var/logs')), '/');
$wafDataDir = defined('WAF_DATA_PATH') ? rtrim(str_replace('\\', '/', WAF_DATA_PATH), '/')
                                      : rtrim(str_replace('\\', '/', getenv('WAF_DATA_DIR') ?: ($wafHome . '/var/data')), '/');
if (!defined('WAF_LOG_PATH')) {
    define('WAF_LOG_PATH', $wafLogDir);
}
if (!defined('WAF_DATA_PATH')) {
    define('WAF_DATA_PATH', $wafDataDir);
}

// 内核里以 getenv() 读取的开关：每请求重置进程环境，保证控制台改动立即生效。
// 仅覆盖白名单变量，绝不触碰 WAF_HOME / WAF_LOG_DIR 等路径常量。
foreach ([
    'WAF_MODE'                  => $wafRuntime['mode'],
    'WAF_AI_ENABLED'            => $wafRuntime['guards']['ai']        ? '1' : '0',
    'WAF_FP_GUARD'              => $wafRuntime['guards']['fp']        ? '1' : '0',
    'WAF_TAUTOLOGY_GUARD'       => $wafRuntime['guards']['tautology'] ? '1' : '0',
    'WAF_BYPASS_GUARD'          => $wafRuntime['guards']['bypass']    ? '1' : '0',
    'WAF_KEEP_DISPLAY_ERRORS'   => $wafRuntime['guards']['errors']    ? '1' : '0',
    // v6.5.0：蜜罐默认停用，只有控制端点显式启用且未过有效期才会传给内核
    'WAF_HONEYPOT_ENABLED'      => !empty($wafRuntime['honeypot']['enabled']) ? '1' : '0',
] as $wafEnvKey => $wafEnvVal) {
    putenv($wafEnvKey . '=' . $wafEnvVal);
}

// 蜜罐有效期届满：只在文件里仍标「启用」时原子写回一次并留审计，
// 之后所有请求立即回到「不诱捕」状态，不会因忘记关闭而长期影响生产流量。
$hpFile = wafRtPath($wafHome);
$hpRaw  = is_file($hpFile) ? json_decode((string)@file_get_contents($hpFile), true) : null;
if (is_array($hpRaw) && !empty($hpRaw['honeypot']['enabled'])
    && (int)($hpRaw['honeypot']['until'] ?? 0) > 0
    && time() >= (int)$hpRaw['honeypot']['until']) {
    $hpRt = wafRtRead($wafHome);
    $hpRt['honeypot'] = ['enabled' => false, 'until' => 0, 'enabled_at' => 0, 'by' => '', 'reason' => ''];
    if (wafRtWrite($wafHome, $hpRt)) {
        wafCtlLog($wafHome, 'honeypot.disable', true, '有效期届满，蜜罐已自动停用（安全侧自动回退）');
    }
}
// 叙述性误报复核是常量型开关，必须在内核加载前定义
if (!defined('WAF_FP_NARRATIVE_GUARD')) {
    define('WAF_FP_NARRATIVE_GUARD', $wafRuntime['guards']['fp']);
}
foreach ([$wafLogDir, $wafDataDir] as $wafDirPath) {
    if (!is_dir($wafDirPath)) { @mkdir($wafDirPath, 0750, true); }
}

// ---------------------------------------------------------------- 管理路由（在检测之前分发，避免自身请求计入攻击日志）
$wafPath = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
if (in_array($wafPath, ['/waf-control', '/waf-control.php', '/control.php'], true)) {
    require $wafRoot . '/control.php';
    exit;
}
// 只读控制台（零 JS / CSP 兜底视图）
if (in_array($wafPath, ['/waf-console', '/waf-console.php', '/console.php'], true)) {
    require $wafRoot . '/console.php';
    exit;
}
// 实时威胁态势大屏 + 控制台面板
if (in_array($wafPath, ['/waf-screen', '/waf-screen.php', '/screen.php'], true)) {
    require $wafRoot . '/screen.php';
    exit;
}

// ---------------------------------------------------------------- 接入层 QPS 限流 / 熔断
// 放在管理路由之后：/waf-screen、/waf-console、/waf-control 已 exit，天然豁免，
// 大屏轮询与控制台操作既不计入 QPS，也不会把自己熔断。
// 内核 core/YslCircuitBreaker.php 的窗口是请求内对象属性，跨请求累加不起来，
// 真正的限流判定由这一层承担；内核 breaker 仍保留为内核内部降级信号。
$qpsCfg = wafQpsConfig($wafRuntime);
$qpsHit = wafQpsGuard($wafLogDir, $qpsCfg, $wafHome);
if (!empty($qpsHit['block'])) {
    wafPage((int)$qpsHit['code'], $qpsHit + ['version' => SHIELD_WAF_VERSION]);
}

$kernel = $wafRoot . '/core/YslWaf.php';
if (!is_file($kernel)) {
    error_log('[ShieldWAF] kernel missing: ' . $kernel);
    wafPage(503, ['version' => SHIELD_WAF_VERSION, 'reason' => 'kernel_missing']);
}

// AI / 语义层引导：必须在内核之前；WAF_AI_ENABLED 已由上面的运行时配置设置。
$wafAiBootstrap = $wafRoot . '/ai/bootstrap.php';
if (getenv('WAF_AI_ENABLED') !== '0' && is_file($wafAiBootstrap)) {
    try {
        require_once $wafAiBootstrap;
    } catch (Throwable $e) {
        error_log('[ShieldWAF] AI layer unavailable: ' . $e->getMessage());
    }
}

require_once $kernel;

$wafConfig = require $wafRoot . '/config.php';
// 运行时覆盖：模式 / 单请求 body 上限 / 硬旁路白名单，均由控制台真实写入并回读
$wafConfig['mode']              = $wafRuntime['mode'];
$wafConfig['max_payload_bytes'] = $wafRuntime['body_max'];
$wafConfig['whitelist_cidrs']   = $wafRuntime['whitelist'];

// 训练队列攒批落盘：注册在 shutdown，保证拦截 exit 之后仍会执行。
if (class_exists('Learning_TrainingScheduler')) {
    register_shutdown_function(static function (): void {
        try {
            Learning_TrainingScheduler::maybeFlush();
        } catch (Throwable $e) {
            error_log('[ShieldWAF] training flush failed: ' . $e->getMessage());
        }
    });
}

try {
    // v6.4.0：外壳调用 inspect 拿真实决策，自己负责响应呈现。
    // 与 YslWaf::enforce() 判定完全等价，但输出的是美化页而不是纯文本。
    $wafResult = YslWaf::inspectCurrentRequest($wafConfig);
    $wafAction = (string)($wafResult['action'] ?? '');
    if (($wafConfig['mode'] ?? 'enforce') !== 'observe'
        && !in_array($wafAction, ['allow', 'monitor', 'pass'], true)) {
        $wafStatus = (int)($wafResult['code'] ?? 403);
        if ($wafStatus < 400 || $wafStatus > 599) { $wafStatus = 403; }
        wafPage($wafStatus, [
            'version'    => SHIELD_WAF_VERSION,
            'reason'     => (string)($wafResult['reason'] ?? ''),
            'score'      => (string)($wafResult['score'] ?? 0),
            'risk'       => (string)($wafResult['risk'] ?? ''),
            'elapsed_ms' => (string)($wafResult['elapsed_ms'] ?? 0),
        ]);
    }
} catch (Throwable $e) {
    // 内核设计铁律：任何模块异常 → 降级不中断；但外壳必须 fail-closed
    error_log('[ShieldWAF] request inspection failed (' . get_class($e) . '): ' . $e->getMessage());
    wafPage(503, [
        'version' => SHIELD_WAF_VERSION,
        'reason'  => 'kernel_exception',
        'detail'  => get_class($e),
    ]);
}
