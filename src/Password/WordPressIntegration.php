<?php
/**
 * 盾甲 WAF — WordPress 密码双重加密集成
 *
 * 功能：自动接管 WordPress 的密码哈希和验证函数，
 *       使 WordPress 用户密码存储为双重哈希 (Argon2id + bcrypt)。
 *
 * 特性：
 *   1. 零配置：引入即生效
 *   2. 平滑升级：旧 WordPress 用户密码（phpass $P$）登录时自动升级为双重哈希
 *   3. 完全兼容：所有 WP 函数（wp_hash_password / wp_check_password / wp_set_password）无缝工作
 *   4. 可关闭：WAF_PASSWORD_WP_INTEGRATION=false 时不接管
 *
 * 用法：
 *   在 wp-config.php 或主题 functions.php 顶部加入：
 *   require_once '/path/to/shield-waf/src/Password/WordPressIntegration.php';
 *
 * 或者通过 WAF 主入口自动加载（如果是 WAF WordPress 插件模式）。
 */

// 兼容非 WordPress 环境：未定义 ABSPATH 时自动定义为项目根目录
// 注意：本文件位于 src/Password/，需向上回溯 2 级到项目根
if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__DIR__, 2) . '/');
}

// 加载核心类
if (!class_exists('DualPassword', false)) {
    require_once __DIR__ . '/DualPassword.php';
}

// 检查是否启用 WordPress 集成
$wpIntegration = getenv('WAF_PASSWORD_WP_INTEGRATION');
if ($wpIntegration === false || $wpIntegration !== 'false') {
    // 默认启用

    // 注册 wp_hash_password 过滤器
    if (function_exists('add_filter')) {
        add_filter('wp_hash_password', 'shield_wp_hash_password', 10, 2);
        add_filter('wp_check_password', 'shield_wp_check_password', 10, 4);
    }

    // 备用：如果 WP 还没加载，用 function_exists 检查避免冲突
    if (!function_exists('wp_hash_password') && !function_exists('wp_check_password')) {
        // WP 未加载，定义包装函数，等 WP 加载后由 filter 接管
    }
}

/**
 * 替换 wp_hash_password：生成双重哈希
 *
 * @param string $password 明文密码
 * @return string 双重哈希
 */
function shield_wp_hash_password($password)
{
    try {
        return DualPassword::hash($password);
    } catch (Exception $e) {
        if (function_exists('wp_hash_password')) {
            return wp_hash_password($password);
        }
        return password_hash($password, PASSWORD_BCRYPT);
    }
}

/**
 * 替换 wp_check_password：验证 + 自动升级旧密码
 *
 * @param bool    $check   默认校验结果
 * @param string  $password 明文密码
 * @param string  $hash     存储的哈希
 * @param int     $userId   用户ID
 * @return bool
 */
function shield_wp_check_password($check, $password, $hash, $userId = 0)
{
    $ok = DualPassword::verify($password, $hash);
    if (!$ok) return false;

    if ($userId && DualPassword::needsRehash($hash)) {
        $newHash = DualPassword::hash($password);
        global $wpdb;
        if (isset($wpdb) && is_object($wpdb) && method_exists($wpdb, 'update')) {
            $wpdb->update($wpdb->users, ['user_pass' => $newHash], ['ID' => $userId]);
        }
    }

    return true;
}
