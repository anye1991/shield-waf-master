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
 * YSL语枢-盾甲WAF · 统一安全响应页（v6.4.0）
 *
 * 替换内核 YslWaf::reject() 那句纯文本 "Request rejected."，以及
 * 内核里那套从未被调用的 429 老页面。外壳只做「响应呈现」，不含任何检测逻辑。
 *
 * 设计约束：
 *   - 零外部资源：内联 CSS / 内联 SVG / 系统字体，断网、CSP 严格环境照样完整显示
 *   - 零 JavaScript：倒计时用 CSS 动画 + meta refresh，绝不会重演「整页 JS 被挡」
 *   - 严格 CSP / no-store / nosniff / DENY / no-referrer，页面本身不回显未转义输入
 *   - 所有展示值都来自调用方传入的真实上下文，没有演示占位数字
 *   - 视觉与 /waf-screen 态势大屏同套深蓝科技语言
 *
 * 状态码语义：403 安全拦截 / 429 QPS 限流 / 502 保护性熔断 / 503 Fail-Closed
 */
declare(strict_types=1);

// 统一的中文展示映射；require_once 保证 phar / 源码 / 独立引入都不会重复定义
require_once __DIR__ . '/i18n.php';

function wafPageE($v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** 内核 reason → 中文可读名；与控制台 / 大屏共用 i18n.php 的同一张表 */
function wafPageReason(string $r): string {
    return wafCnReason($r);
}

function wafPage(int $status, array $ctx = []): void
{
    $skin = [
        403 => ['title' => '访问已被拦截', 'badge' => '安全拦截', 'c' => '#fb7185', 'c2' => '#f43f5e',
                'rgb' => '244,63,94',
                'sub'  => '该请求命中了安全防护规则，已在到达业务代码之前被YSL语枢-盾甲WAF 阻断。'],
        429 => ['title' => '请求频率超限', 'badge' => '访问限流', 'c' => '#fbbf24', 'c2' => '#f59e0b',
                'rgb' => '251,191,36',
                'sub'  => '当前访问速率超过节点限流阈值，请求已被暂时拒绝，请稍后重试。'],
        502 => ['title' => '服务已熔断降级', 'badge' => '服务熔断', 'c' => '#f87171', 'c2' => '#ef4444',
                'rgb' => '248,113,113',
                'sub'  => '节点负载触发保护性熔断，正在冷却。冷却结束后会自动半开试探并恢复服务。'],
        503 => ['title' => '安全模块暂时不可用', 'badge' => '故障关闭', 'c' => '#a78bfa', 'c2' => '#8b5cf6',
                'rgb' => '167,139,250',
                'sub'  => '检测链路异常，已按「故障关闭」策略拒绝放行，避免站点在失去防护的状态下对外服务。'],
        413 => ['title' => '请求体超过上限', 'badge' => '请求体超限', 'c' => '#fbbf24', 'c2' => '#f59e0b',
                'rgb' => '251,191,36',
                'sub'  => '本次请求携带的数据量超过 WAF 允许的检测上限，已拒绝读取。'],
    ];
    $s = $skin[$status] ?? $skin[403];

    // ---------------------------------------------------------------- 真实上下文
    $rid = (string)($ctx['request_id'] ?? '');
    if ($rid === '' || !preg_match('/\A[A-Za-z0-9._:-]{1,64}\z/', $rid)) {
        try { $rid = bin2hex(random_bytes(8)); } catch (Throwable $e) { $rid = uniqid('ysl_', true); }
    }
    $uriRaw = (string)($_SERVER['REQUEST_URI'] ?? '/');
    $uri    = preg_replace('/[\x00-\x1F\x7F]/u', '', $uriRaw) ?? '/';
    if (function_exists('mb_substr')) { $uri = mb_substr($uri, 0, 180, 'UTF-8'); }
    else { $uri = substr($uri, 0, 180); }
    $ip   = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) { $ip = '—'; }
    $node = (string)($ctx['node'] ?? (function_exists('gethostname') ? gethostname() : 'unknown'));
    $ver  = (string)($ctx['version'] ?? (defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : '6.5.1'));
    $time = date('Y-m-d H:i:s', time() + 8 * 3600) . ' UTC+8';
    $reasonRaw = (string)($ctx['reason'] ?? '');
    $reasonTxt = wafPageReason($reasonRaw);
    $retry = max(0, (int)($ctx['retry_after'] ?? 0));
    $isRate = ($status === 429 || $status === 502);
    $refresh = ($status === 502 && $retry > 0 && $retry <= 60) ? $retry : 0;

    // 信息网格：只展示本次真实存在的字段
    $info = [
        ['请求编号', 'REQ-' . $rid],
        ['发生时间', $time],
        ['客户端地址', $ip],
        ['请求路径', $uri],
    ];
    if ($status === 403) {
        $riskMap = ['critical' => '危急', 'high' => '高危', 'medium' => '中危',
                    'low' => '低危', 'clean' => '正常'];
        $riskRaw = (string)($ctx['risk'] ?? '');
        $info[] = ['拦截原因', $reasonTxt];
        if ($reasonRaw !== '' && $reasonRaw !== $reasonTxt) { $info[] = ['规则标识', $reasonRaw]; }
        if (isset($ctx['score']))    { $info[] = ['威胁评分', (string)$ctx['score'] . ' / 100']; }
        if ($riskRaw !== '')         { $info[] = ['风险等级', $riskMap[$riskRaw] ?? $riskRaw]; }
        if (isset($ctx['elapsed_ms'])) { $info[] = ['检测耗时', number_format((float)$ctx['elapsed_ms'], 2) . ' ms']; }
    } elseif ($isRate) {
        $info[] = ['触发原因', $reasonTxt];
        $info[] = ['当前 QPS', (string)(int)($ctx['qps'] ?? 0)];
        $info[] = ['窗口峰值', (string)(int)($ctx['peak'] ?? 0) . ' QPS'];
        $info[] = ['限流阈值', '全局 ' . (int)($ctx['soft'] ?? 0) . ' / 单 IP ' . (int)($ctx['ip_soft'] ?? 0) . ' QPS'];
        $info[] = ['熔断阈值', '全局 ' . (int)($ctx['hard'] ?? 0) . ' / 单 IP ' . (int)($ctx['ip_hard'] ?? 0) . ' QPS'];
        $info[] = ['触发维度', ($ctx['scope'] ?? '') === 'ip' ? '单 IP' : '全局'];
        $stateRaw = (string)($ctx['state'] ?? 'closed');
        $info[] = ['熔断状态', wafCnState($stateRaw)];
        $info[] = ['累计拒绝', (string)(int)($ctx['rejects'] ?? 0) . ' 次'];
    } else {
        $info[] = ['异常类别', $reasonTxt];
        if (isset($ctx['detail'])) { $info[] = ['诊断信息', (string)$ctx['detail']]; }
    }

    $tips = [
        403 => '若您认为这是误判，请把上方请求编号提供给站点管理员，可在控制台审计日志中按编号检索。请勿重复提交相同载荷。',
        429 => '请降低访问频率后重试。持续的自动化高频请求会进一步触发保护性熔断（502）。',
        502 => '节点正在保护性降级，冷却结束后自动半开试探恢复；期间管理后台与态势大屏仍可访问，用于复位或调整阈值。',
        503 => '请检查 PHP 错误日志、目录权限与内核文件完整性。故障未排除前站点将持续拒绝请求，这是刻意的安全设计。',
        413 => '请缩减上传内容后重试；如业务确需更大体积，可在控制台调整「请求体上限」并确认磁盘与内存预算。',
    ];

    // ---------------------------------------------------------------- 响应头
    while (ob_get_level() > 0) { @ob_end_clean(); }
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
        if ($status === 429 || $status === 502) {
            header('Retry-After: ' . max(1, $retry ?: 2));
        }
        if ($status === 502) {
            header('X-WAF-Circuit: open');
        }
        header('X-WAF-Request-Id: ' . $rid);
    }

    $code  = wafPageE((string)$status);
    $title = wafPageE($s['title']);
    $badge = wafPageE($s['badge']);
    $sub   = wafPageE($s['sub']);
    $tip   = wafPageE($tips[$status] ?? $tips[403]);
    $c     = wafPageE($s['c']);
    $c2    = wafPageE($s['c2']);
    $rgb   = wafPageE($s['rgb']);
    $verE  = wafPageE($ver);
    $nodeE = wafPageE(substr($node, 0, 40));
    $ridE  = wafPageE($rid);

    $infoHtml = '';
    foreach ($info as $it) {
        $infoHtml .= '<div class="it"><div class="k">' . wafPageE($it[0]) . '</div>'
                   . '<div class="v">' . wafPageE($it[1]) . '</div></div>';
    }

    $cdHtml = '';
    if ($isRate && $retry > 0) {
        $cdHtml = '<div class="cd">'
                . '<svg viewBox="0 0 100 100" width="88" height="88" aria-hidden="true">'
                . '<circle class="cd-bg" cx="50" cy="50" r="42"></circle>'
                . '<circle class="cd-bar" cx="50" cy="50" r="42" style="animation-duration:' . max(1, min($retry, 60)) . 's"></circle>'
                . '</svg><div class="cd-t"><b>' . (int)$retry . '</b><span>秒后可重试</span></div></div>';
    }

    $wave = '';
    if ($status === 502) {
        $wave = '<svg class="wave" viewBox="0 0 680 56" preserveAspectRatio="none" aria-hidden="true">'
              . '<path d="M0 28 H150 L162 28 L170 12 L178 44 L186 28 H330 L342 28 L350 16 L358 40 L366 28 H500 L512 28 L520 10 L528 46 L536 28 H680" '
              . 'fill="none" stroke="' . $c . '" stroke-width="1.6" stroke-linejoin="round" opacity=".75"/>'
              . '<path d="M0 28 H150 L162 28 L170 12 L178 44 L186 28 H330 L342 28 L350 16 L358 40 L366 28 H500 L512 28 L520 10 L528 46 L536 28 H680" '
              . 'fill="none" stroke="' . $c2 . '" stroke-width="6" stroke-linejoin="round" opacity=".12"/>'
              . '</svg>';
    }

    echo <<<HTML
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{$code} · {$title} | YSL语枢-盾甲WAF</title>
HTML;
    if ($refresh > 0) {
        echo "\n<meta http-equiv=\"refresh\" content=\"" . (int)$refresh . "\">";
    }
    echo <<<HTML
<style>
*{box-sizing:border-box}
html,body{margin:0;padding:0;min-height:100%}
body{
  background:#050a16;color:#e8f2ff;
  font:14px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  display:flex;align-items:center;justify-content:center;padding:34px 20px;min-height:100vh;overflow-x:hidden;
}
.grid-bg{position:fixed;inset:0;pointer-events:none;
  background-image:linear-gradient(rgba(34,211,238,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,.045) 1px,transparent 1px);
  background-size:44px 44px;mask-image:radial-gradient(ellipse at 50% 35%,#000 20%,transparent 78%)}
.glow{position:fixed;inset:0;pointer-events:none;
  background:radial-gradient(ellipse 620px 380px at 50% 0%,rgba({$rgb},.13),transparent 70%),
             radial-gradient(ellipse 500px 400px at 85% 90%,rgba(34,211,238,.07),transparent 72%)}
.scan{position:fixed;left:0;right:0;top:-10%;height:1px;pointer-events:none;
  background:linear-gradient(90deg,transparent,rgba({$rgb},.55),transparent);
  box-shadow:0 0 22px rgba({$rgb},.5);animation:scan 7s linear infinite}
@keyframes scan{0%{top:-10%}100%{top:110%}}
.wrap{position:relative;width:100%;max-width:860px;z-index:1}
.brand{display:flex;align-items:center;gap:12px;margin:0 2px 18px}
.brand .logo{width:34px;height:34px;flex:none;display:flex;align-items:center;justify-content:center;
  border:1px solid rgba(34,211,238,.35);border-radius:9px;background:rgba(34,211,238,.07)}
.brand .bn b{display:block;font-size:14px;letter-spacing:2px;color:#eaf6ff;font-weight:650}
.brand .bn span{display:block;font-size:9.5px;letter-spacing:2.2px;color:#6f8fb4;margin-top:1px}
.brand .ver{margin-left:auto;font-size:11px;color:#7f9dc2;letter-spacing:1px;
  border:1px solid rgba(148,163,184,.22);border-radius:20px;padding:3px 11px;white-space:nowrap}
.card{position:relative;overflow:hidden;border-radius:20px;
  border:1px solid rgba({$rgb},.22);
  background:linear-gradient(158deg,rgba(18,29,49,.97),rgba(8,15,30,.985));
  box-shadow:0 30px 90px rgba(0,0,0,.6),0 0 70px rgba({$rgb},.09),inset 0 1px 0 rgba(255,255,255,.045)}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,{$c},rgba({$rgb},.28) 45%,transparent)}
.card::after{content:"";position:absolute;right:-90px;top:-90px;width:300px;height:300px;border-radius:50%;
  background:radial-gradient(circle,rgba({$rgb},.13),transparent 68%);pointer-events:none}
.hero{position:relative;display:flex;align-items:center;gap:34px;padding:40px 42px 30px}
.num{flex:none;font-size:clamp(82px,13vw,148px);font-weight:800;line-height:.9;letter-spacing:-7px;
  background:linear-gradient(175deg,#fff 8%,{$c} 92%);-webkit-background-clip:text;background-clip:text;
  color:transparent;filter:drop-shadow(0 0 26px rgba({$rgb},.42))}
.hero-r{min-width:0}
.badge{display:inline-flex;align-items:center;gap:8px;padding:5px 13px;border-radius:20px;
  font-size:10.5px;letter-spacing:1.6px;font-weight:600;color:{$c};
  border:1px solid rgba({$rgb},.38);background:rgba({$rgb},.1)}
.badge i{width:7px;height:7px;border-radius:50%;background:{$c};box-shadow:0 0 10px {$c};animation:pulse 1.7s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.42;transform:scale(.7)}}
h1{margin:14px 0 8px;font-size:clamp(22px,3.4vw,30px);font-weight:650;letter-spacing:1px;color:#f2f8ff}
.sub{margin:0;color:#9db6d6;font-size:13.5px;line-height:1.85;max-width:430px}
.wave{display:block;width:100%;height:56px;margin:2px 0 0;opacity:.85}
.info{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:0 42px 8px;
  background:rgba(148,163,184,.12);border:1px solid rgba(148,163,184,.12);border-radius:12px;overflow:hidden}
.it{background:rgba(9,17,32,.92);padding:12px 15px;min-width:0}
.it .k{font-size:10px;letter-spacing:1.4px;color:#7390b4;text-transform:uppercase;margin-bottom:3px}
.it .v{font-size:13px;color:#dbeaff;word-break:break-all;
  font-family:"SF Mono","Cascadia Code",Consolas,"PingFang SC",monospace}
/* 奇数个字段时最后一项横跨整行，避免网格右下留一块空洞 */
.it:last-child:nth-child(odd){grid-column:span 2}
.bottom{display:flex;align-items:center;gap:20px;padding:20px 42px 26px;flex-wrap:wrap}
.cd{position:relative;flex:none;width:88px;height:88px}
.cd svg{transform:rotate(-90deg)}
.cd-bg{fill:none;stroke:rgba(148,163,184,.16);stroke-width:7}
.cd-bar{fill:none;stroke:{$c};stroke-width:7;stroke-linecap:round;
  stroke-dasharray:263.9;stroke-dashoffset:0;animation:drain linear forwards;filter:drop-shadow(0 0 6px rgba({$rgb},.6))}
@keyframes drain{to{stroke-dashoffset:263.9}}
.cd-t{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:1.1}
.cd-t b{font-size:24px;color:#fff;font-weight:650}
.cd-t span{font-size:9px;color:#8aa6c8;letter-spacing:.5px;margin-top:3px}
.tip{flex:1;min-width:220px;font-size:11.5px;color:#87a3c6;line-height:1.8;
  border-left:2px solid rgba({$rgb},.5);padding-left:14px}
.retry{display:inline-block;margin-top:9px;padding:5px 14px;border-radius:8px;text-decoration:none;
  font-size:11.5px;color:{$c};border:1px solid rgba({$rgb},.4);background:rgba({$rgb},.08);
  transition:background .2s,border-color .2s}
.retry:hover{background:rgba({$rgb},.2);border-color:{$c}}
.foot{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  margin:16px 4px 0;font-size:10.5px;color:#5f7b9d;letter-spacing:.4px}
.foot b{color:#8fb6dc;font-weight:500}
@media(max-width:680px){
  body{padding:20px 14px;align-items:flex-start}
  .hero{flex-direction:column;align-items:flex-start;gap:8px;padding:28px 24px 20px}
  .num{letter-spacing:-4px}
  .info{grid-template-columns:1fr;margin:0 24px 6px}
  .bottom{padding:16px 24px 24px}
  .brand .ver{font-size:10px}
}
</style>
</head>
<body>
<div class="grid-bg"></div><div class="glow"></div><div class="scan"></div>
<div class="wrap">
  <header class="brand">
    <div class="logo">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 2 20 5v6c0 5-3.4 8.7-8 11-4.6-2.3-8-6-8-11V5l8-3Z" stroke="#22d3ee" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="m8.5 12 2.4 2.4 4.6-4.8" stroke="#34d399" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </div>
    <div class="bn"><b>YSL语枢-盾甲WAF</b><span>安全防护网关</span></div>
    <div class="ver">内核 v{$verE}</div>
  </header>

  <main class="card">
    <div class="hero">
      <div class="num">{$code}</div>
      <div class="hero-r">
        <span class="badge"><i></i>{$badge}</span>
        <h1>{$title}</h1>
        <p class="sub">{$sub}</p>
      </div>
    </div>
    {$wave}
    <div class="info">{$infoHtml}</div>
    <div class="bottom">
      {$cdHtml}
      <div class="tip">{$tip}<br><a class="retry" href="">重新发起请求</a></div>
    </div>
  </main>

  <footer class="foot">
    <span>YSL语枢-盾甲WAF · 请求已终止于业务之前 · 本页不加载任何外部资源</span>
    <span>节点 <b>{$nodeE}</b> · 请求编号 <b>{$ridE}</b></span>
  </footer>
</div>
</body>
</html>
HTML;
    exit;
}
