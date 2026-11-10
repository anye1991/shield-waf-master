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
 * 内置服务器路由（仅用于 e2e 验收，不属于发行文件）。
 *
 * 两个作用：
 *  1. 让 /waf-console、/waf-screen 这类「没有实体文件」的虚拟路由也能进到 WAF；
 *  2. 显式 require 入口——PHP 内置服务器**不会**对 router 脚本执行 auto_prepend_file，
 *     因此这里手动前置加载。语义与生产环境 .user.ini 的 auto_prepend_file 完全等价
 *     （shield-waf.php 有 SHIELD_WAF_BOOTED 常量，重复加载会直接返回）。
 */
declare(strict_types=1);

$root = dirname(__DIR__, 2);

require $root . '/shield-waf.php';   // 命中拦截会输出拦截页并 exit

require $root . '/demo/index.php';   // 未被拦截 → 交给业务页
