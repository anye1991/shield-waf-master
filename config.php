<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少. 保留所有权利.
 */

/**
 * YSL语枢-盾甲WAF · 唯一配置文件
 *
 * 外壳只负责「把请求交给内核」，所有检测规则都在 core/ 里，一行不改。
 * WAF_HOME 由启动器定义（phar stub / install / 演示站）；源码模式退化为 __DIR__。
 * 用 / 作为分隔符：Windows 与 Linux 均可，且与内核 samePath() 校验一致。
 */
declare(strict_types=1);

$wafEnvHome = getenv('WAF_HOME');
$home = defined('WAF_HOME') ? WAF_HOME : ($wafEnvHome ?: __DIR__);
$home = rtrim(str_replace('\\', '/', $home), '/');

// 状态/日志目录可由 WAF_LOG_DIR 覆盖。内核每请求会写攻击链、时间窗、熔断状态与审计，
// 磁盘 IO 是主要开销；生产建议指向 tmpfs（如 /dev/shm/waf-logs）可显著降低延迟。
// 未设置时保持默认 var/logs，行为与旧版完全一致。
$wafLogDir = getenv('WAF_LOG_DIR') ?: ($home . '/var/logs');
$wafLogDir = rtrim(str_replace('\\', '/', $wafLogDir), '/');

return [
    // 必须是绝对、可写目录；内核会在此创建 ysl/ 子目录写审计链/窗口/熔断状态
    'log_path' => $wafLogDir,

    // 单请求最大读取 body（字节），内核允许 1 ~ 67108864
    'max_payload_bytes' => 8388608,

    // 硬旁路白名单，IP 或 CIDR；例：['127.0.0.1/8', '10.0.0.0/8']
    'whitelist_cidrs' => [],

    // enforce = 真拦；observe = 只写审计日志、一律放行（上线前先观察误报）
    'mode' => getenv('WAF_MODE') ?: 'enforce',

    // AI / 语义层由 ai/bootstrap.php 自动接线，不需要在这里配路径。
    // 注意：phar 模式下 semantic/ 在归档内部，若在此写外部绝对路径会与
    // bootstrap 定义的 WAF_SEMANTIC_PATH 冲突，内核会抛异常，所以保持注释。
    // 想退回纯内核（更快）：设置环境变量 WAF_AI_ENABLED=0
    // 'semantic_path' => $home . '/plugins/semantic',   // 需含 SemanticEngine.php
    // 'security_path' => $home . '/plugins/security',   // 需含 UploadSecurity.php 等 6 个
];
