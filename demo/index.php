<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少. 保留所有权利.
 */

/**
 * 演示业务页：不含任何 WAF 代码，防护靠 auto_prepend_file 注入。
 * 仅用于本地验证「内核真的在每个 PHP 请求前生效」，不属于发行文件。
 */
header('Content-Type: text/html; charset=utf-8');
$loaded = defined('SHIELD_WAF_BOOTED');
?><!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>YSL语枢-盾甲WAF · 演示站点</title>
<style>body{background:#0b1220;color:#e2e8f0;font:15px/1.8 system-ui;padding:36px;max-width:760px;margin:auto}
h1{color:#22d3ee;font-size:22px}code{background:#1e293b;padding:2px 6px;border-radius:4px}
li{margin:6px 0}.ok{color:#4ade80}.bad{color:#f87171}</style></head><body>
<h1>YSL语枢-盾甲WAF · 演示站点</h1>
<p>本页是普通 PHP 业务代码，没有任何 <code>require</code> WAF 的语句。</p>
<p>WAF 加载状态：
<?php if ($loaded): ?>
  <span class="ok">已加载 v<?= htmlspecialchars(SHIELD_WAF_VERSION) ?></span>
<?php else: ?>
  <span class="bad">未加载（auto_prepend_file 未生效）</span>
<?php endif; ?>
</p>
<h3>验证链接</h3>
<ul>
  <li><a href="/?id=1%27%20OR%201%3D1--">SQL 注入</a> —— 应返回 403</li>
  <li><a href="/?x=%3Cscript%3Ealert(1)%3C/script%3E">XSS</a> —— 应返回 403</li>
  <li><a href="/?id=12">正常请求</a> —— 应返回 200</li>
  <li><a href="/waf-console">只读控制台</a> —— 需带 <code>?key=</code>（安装时打印）</li>
</ul>
<p style="color:#94a3b8;font-size:13px">观察模式：<code>WAF_MODE=observe</code> 时攻击只记日志不拦截。</p>
</body></html>
