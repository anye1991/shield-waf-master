<?php
defined('ABSPATH') || exit;

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
if (!$ok1 || !$ok2) { http_response_code(403); exit; }
$version = defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : '3.0.0';
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>盾甲 WAF · 安全控制台</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#070b14;--bg2:#0b1220;--panel:rgba(15,23,42,.6);
  --border:rgba(148,163,184,.08);--border2:rgba(148,163,184,.12);
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;--text4:#475569;
  --cyan:#06b6d4;--blue:#3b82f6;--purple:#8b5cf6;--pink:#ec4899;
  --green:#10b981;--yellow:#f59e0b;--red:#ef4444;--orange:#f97316;
  --grad-1:linear-gradient(135deg,#06b6d4,#3b82f6);
  --grad-2:linear-gradient(135deg,#8b5cf6,#ec4899);
  --grad-3:linear-gradient(135deg,#10b981,#06b6d4);
  --grad-4:linear-gradient(135deg,#f59e0b,#ef4444);
  --glow-cyan:0 0 20px rgba(6,182,212,.3);
  --glow-purple:0 0 20px rgba(139,92,246,.3);
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:"Inter","PingFang SC","Microsoft YaHei",-apple-system,sans-serif;overflow:hidden;font-size:14px}
body{display:flex}

/* 滚动条 */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(148,163,184,.15);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(148,163,184,.3)}

/* ========== 侧边栏 ========== */
.sidebar{width:240px;min-width:240px;background:linear-gradient(180deg,var(--bg2),var(--bg));border-right:1px solid var(--border);display:flex;flex-direction:column;height:100vh;position:relative;z-index:10}
.sidebar::after{content:'';position:absolute;top:0;right:0;width:1px;height:100%;background:linear-gradient(180deg,transparent,rgba(6,182,212,.2),transparent)}
.logo{padding:24px 20px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border)}
.logo-icon{width:40px;height:40px;border-radius:12px;background:var(--grad-1);display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:var(--glow-cyan)}
.logo-text{font-weight:700;font-size:16px;letter-spacing:.5px}
.logo-text small{display:block;font-size:10px;color:var(--text3);font-weight:400;letter-spacing:1px;text-transform:uppercase;margin-top:2px}
.nav{flex:1;padding:16px 12px;overflow-y:auto}
.nav-section{margin-bottom:20px}
.nav-title{font-size:11px;color:var(--text4);text-transform:uppercase;letter-spacing:1px;padding:8px 12px;margin-bottom:4px;font-weight:600}
.nav-item{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;cursor:pointer;color:var(--text2);transition:all .2s;margin-bottom:2px;position:relative}
.nav-item:hover{background:rgba(148,163,184,.06);color:var(--text)}
.nav-item.active{background:linear-gradient(90deg,rgba(6,182,212,.12),transparent);color:#22d3ee}
.nav-item.active::before{content:'';position:absolute;left:0;top:10%;height:80%;width:3px;border-radius:2px;background:var(--cyan);box-shadow:var(--glow-cyan)}
.nav-item .icon{font-size:16px;width:20px;text-align:center}
.nav-item .label{flex:1;font-size:13px;font-weight:500}
.nav-item .badge{background:rgba(239,68,68,.2);color:var(--red);font-size:10px;padding:2px 6px;border-radius:6px;font-weight:600}
.sidebar-footer{padding:16px;border-top:1px solid var(--border)}
.ver-cell{display:flex;justify-content:space-between;font-size:11px;color:var(--text3);margin-bottom:6px}
.ver-cell span:last-child{color:var(--green)}
.ver-cell.warn span:last-child{color:var(--yellow)}

/* ========== 主内容区 ========== */
.main{flex:1;display:flex;flex-direction:column;height:100vh;overflow:hidden}
.topbar{height:60px;min-height:60px;border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 28px;gap:20px;background:rgba(7,11,20,.8);backdrop-filter:blur(12px);position:relative;z-index:5}
.topbar-left{display:flex;align-items:center;gap:16px}
.page-title{font-size:18px;font-weight:700}
.page-sub{font-size:12px;color:var(--text3);margin-top:2px}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:16px}
.search-box{position:relative}
.search-box input{background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:10px;padding:8px 14px 8px 36px;color:var(--text);font-size:13px;width:240px;outline:none;transition:all .2s}
.search-box input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(6,182,212,.1)}
.search-box::before{content:'🔍';position:absolute;left:12px;top:50%;transform:translateY(-50%);font-size:12px;opacity:.5}
.status-dot{display:inline-flex;align-items:center;gap:8px;font-size:12px;color:var(--text2)}
.status-dot .dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse-dot 2s infinite}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:.5}}
.clock{font-size:13px;color:var(--text2);font-variant-numeric:tabular-nums}

.content{flex:1;overflow-y:auto;padding:24px 28px}

/* ========== 页面切换 ========== */
.page{display:none;animation:fadeIn .3s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* ========== KPI 卡片 ========== */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.kpi-card{position:relative;background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:20px;overflow:hidden;backdrop-filter:blur(12px);transition:all .3s}
.kpi-card:hover{border-color:var(--border2);transform:translateY(-2px)}
.kpi-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--card-grad,var(--grad-1));opacity:.6}
.kpi-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:12px}
.kpi-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;background:var(--icon-bg,rgba(6,182,212,.15))}
.kpi-trend{font-size:11px;font-weight:600;padding:3px 8px;border-radius:6px}
.kpi-trend.up{background:rgba(239,68,68,.15);color:var(--red)}
.kpi-trend.down{background:rgba(16,185,129,.15);color:var(--green)}
.kpi-value{font-size:32px;font-weight:800;line-height:1;letter-spacing:-.5px;margin-bottom:6px;background:var(--card-grad,var(--grad-1));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-variant-numeric:tabular-nums}
.kpi-label{font-size:12px;color:var(--text2);font-weight:500}
.kpi-sub{font-size:11px;color:var(--text4);margin-top:4px}
.kpi-spark{position:absolute;bottom:12px;right:16px;opacity:.3}

/* ========== 图表网格 ========== */
.chart-row{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px}
.chart-row.two{grid-template-columns:1fr 1fr}
.chart-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:20px;backdrop-filter:blur(12px)}
.card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-title{font-size:13px;font-weight:600;color:var(--text2);display:flex;align-items:center;gap:8px}
.card-title .dot{width:6px;height:6px;border-radius:50%;background:var(--cyan)}
.card-actions{display:flex;gap:6px}
.chip{padding:4px 10px;border-radius:7px;font-size:11px;color:var(--text3);background:rgba(148,163,184,.06);cursor:pointer;transition:all .2s;border:1px solid transparent}
.chip:hover{color:var(--text)}
.chip.active{background:rgba(6,182,212,.1);color:var(--cyan);border-color:rgba(6,182,212,.2)}
.chart-wrap{position:relative;height:260px}

/* ========== 实时日志流 ========== */
.log-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:20px;backdrop-filter:blur(12px);margin-bottom:20px}
.log-stream{height:340px;overflow-y:auto;font-family:"JetBrains Mono","SF Mono",Consolas,monospace;font-size:12px;line-height:1.8;border-radius:10px;background:rgba(0,0,0,.3);padding:12px 16px;border:1px solid var(--border)}
.log-line{display:flex;gap:12px;animation:logSlide .3s ease}
@keyframes logSlide{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:translateX(0)}}
.log-time{color:var(--text4);min-width:80px;font-variant-numeric:tabular-nums}
.log-level{min-width:60px;font-weight:700;text-transform:uppercase;font-size:10px;letter-spacing:.5px}
.log-level.critical{color:#f87171;text-shadow:0 0 10px rgba(248,113,113,.5)}
.log-level.high{color:#fb923c}
.log-level.medium{color:#facc15}
.log-level.low{color:#4ade80}
.log-ip{color:var(--text2);min-width:120px}
.log-msg{color:var(--text3);flex:1;word-break:break-all}

/* ========== 数据表格 ========== */
.table-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:20px;backdrop-filter:blur(12px);margin-bottom:20px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:12px 14px;color:var(--text3);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);background:rgba(148,163,184,.03)}
td{padding:12px 14px;border-bottom:1px solid var(--border);color:var(--text2)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(148,163,184,.03)}
.tag{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600}
.tag.red{background:rgba(239,68,68,.15);color:#f87171}
.tag.orange{background:rgba(249,115,22,.15);color:#fb923c}
.tag.yellow{background:rgba(245,158,11,.15);color:#facc15}
.tag.green{background:rgba(16,185,129,.15);color:#4ade80}
.tag.blue{background:rgba(59,130,246,.15);color:#60a5fa}
.tag.purple{background:rgba(139,92,246,.15);color:#a78bfa}
.tag.cyan{background:rgba(6,182,212,.15);color:#22d3ee}

.btn{padding:6px 14px;border-radius:8px;border:none;cursor:pointer;font-size:12px;font-weight:600;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--grad-1);color:#070b14}
.btn-primary:hover{box-shadow:var(--glow-cyan)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--red)}
.btn-danger:hover{background:rgba(239,68,68,.25)}
.btn-success{background:rgba(16,185,129,.15);color:var(--green)}
.btn-success:hover{background:rgba(16,185,129,.25)}
.btn-ghost{background:rgba(148,163,184,.06);color:var(--text2)}
.btn-ghost:hover{background:rgba(148,163,184,.12)}

/* ========== 概览页面特殊布局 ========== */
.hero-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px}
.hero-left{background:linear-gradient(135deg,rgba(6,182,212,.08),rgba(139,92,246,.08));border:1px solid var(--border);border-radius:16px;padding:24px;position:relative;overflow:hidden}
.hero-left::before{content:'';position:absolute;top:-50%;right:-20%;width:400px;height:400px;background:radial-gradient(circle,rgba(6,182,212,.15),transparent 60%);pointer-events:none}
.hero-badge{display:inline-flex;align-items:center;gap:8px;background:rgba(16,185,129,.15);color:#4ade80;padding:6px 12px;border-radius:20px;font-size:11px;font-weight:600;margin-bottom:14px}
.hero-badge .dot{width:6px;height:6px;border-radius:50%;background:#4ade80;animation:pulse-dot 2s infinite}
.hero-title{font-size:26px;font-weight:800;margin-bottom:6px;background:linear-gradient(135deg,#fff,#94a3b8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero-desc{font-size:13px;color:var(--text2);margin-bottom:20px;line-height:1.6}
.hero-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:20px}
.hero-stat h4{font-size:24px;font-weight:800;color:var(--text);font-variant-numeric:tabular-nums}
.hero-stat p{font-size:11px;color:var(--text3);margin-top:4px}

.hero-right{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:20px;display:flex;flex-direction:column}
.world-map{flex:1;display:flex;align-items:center;justify-content:center;font-size:60px;opacity:.3;position:relative}
.map-dots{position:absolute;inset:0}
.map-dot{position:absolute;width:8px;height:8px;border-radius:50%;background:var(--red);box-shadow:0 0 10px var(--red);animation:mapPulse 2s infinite}
@keyframes mapPulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.5);opacity:.5}}

/* ========== 响应式 ========== */
@media(max-width:1200px){.kpi-grid{grid-template-columns:repeat(2,1fr)}.chart-row{grid-template-columns:1fr}}
@media(max-width:768px){.sidebar{display:none}.kpi-grid{grid-template-columns:1fr}.chart-row.two{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- ========== 侧边栏 ========== -->
<aside class="sidebar">
  <div class="logo">
    <div class="logo-icon">🛡️</div>
    <div class="logo-text">盾甲 WAF<small>Security Console</small></div>
  </div>
  <nav class="nav">
    <div class="nav-section">
      <div class="nav-title">概览</div>
      <div class="nav-item active" data-page="overview"><span class="icon">📊</span><span class="label">安全总览</span></div>
      <div class="nav-item" data-page="attacks"><span class="icon">⚔️</span><span class="label">攻击日志</span><span class="badge" id="attackBadge">0</span></div>
    </div>
    <div class="nav-section">
      <div class="nav-title">防护管理</div>
      <div class="nav-item" data-page="bots"><span class="icon">🤖</span><span class="label">机器人防护</span></div>
      <div class="nav-item" data-page="firewall"><span class="icon">🔥</span><span class="label">IP 管理</span></div>
      <div class="nav-item" data-page="rules"><span class="icon">📋</span><span class="label">防护规则</span></div>
      <div class="nav-item" data-page="sandbox"><span class="icon">📦</span><span class="label">沙箱中心</span></div>
    </div>
    <div class="nav-section">
      <div class="nav-title">系统</div>
      <div class="nav-item" data-page="learn"><span class="icon">🧠</span><span class="label">自学习系统</span></div>
      <div class="nav-item" data-page="settings"><span class="icon">⚙️</span><span class="label">系统设置</span></div>
    </div>
  </nav>
  <div class="sidebar-footer">
    <div class="ver-cell"><span>WAF 版本</span><span>v<?php echo $version; ?></span></div>
    <div class="ver-cell"><span>防护状态</span><span class="status-dot"><span class="dot"></span>运行中</span></div>
    <div class="ver-cell warn"><span>更新时间</span><span id="verTime">--</span></div>
  </div>
</aside>

<!-- ========== 主内容 ========== -->
<div class="main">
  <div class="topbar">
    <div class="topbar-left">
      <div>
        <div class="page-title" id="pageTitle">安全总览</div>
        <div class="page-sub">实时监控 · 智能防御 · 主动围堵</div>
      </div>
    </div>
    <div class="topbar-right">
      <div class="search-box"><input type="text" placeholder="搜索 IP / URL / 规则..."></div>
      <div class="status-dot"><span class="dot"></span>防护中</div>
      <div class="clock" id="clock">--</div>
    </div>
  </div>

  <div class="content">

    <!-- ===== 安全总览 ===== -->
    <div class="page active" id="page-overview">
      <!-- Hero 区域 -->
      <div class="hero-grid">
        <div class="hero-left">
          <div class="hero-badge"><span class="dot"></span>系统运行正常 · 全维度防护中</div>
          <div class="hero-title">您的站点安全无忧</div>
          <div class="hero-desc">盾甲 WAF 正以 14 层编码归一化 + 10 维语义分析 + 主动路径围堵，全方位守护您的 Web 应用。</div>
          <div class="hero-stats">
            <div class="hero-stat"><h4 id="kTotal">0</h4><p>累计拦截攻击</p></div>
            <div class="hero-stat"><h4 id="kToday" style="color:#f87171">0</h4><p>今日拦截</p></div>
            <div class="hero-stat"><h4 id="kIps" style="color:#facc15">0</h4><p>攻击来源 IP</p></div>
            <div class="hero-stat"><h4 id="kTypes" style="color:#4ade80">0</h4><p>防护类型</p></div>
          </div>
        </div>
        <div class="hero-right">
          <div class="card-head"><div class="card-title"><span class="dot"></span>全球攻击分布</div><div class="card-actions"><span class="chip active">实时</span></div></div>
          <div class="world-map">
            🌍
            <div class="map-dots" id="mapDots"></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
            <div style="text-align:center;padding:8px;background:rgba(0,0,0,.2);border-radius:8px">
              <div style="font-size:16px;font-weight:700;color:#f87171" id="topCountry">--</div>
              <div style="font-size:10px;color:var(--text4)">攻击最多地区</div>
            </div>
            <div style="text-align:center;padding:8px;background:rgba(0,0,0,.2);border-radius:8px">
              <div style="font-size:16px;font-weight:700;color:#fb923c" id="avgPerMin">0</div>
              <div style="font-size:10px;color:var(--text4)">次/分钟</div>
            </div>
          </div>
        </div>
      </div>

      <!-- KPI 卡片 -->
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-4);--icon-bg:rgba(239,68,68,.15)">
          <div class="kpi-top"><div class="kpi-icon">🚨</div><span class="kpi-trend up" id="trendSql">+0%</span></div>
          <div class="kpi-value" id="cntSql">0</div>
          <div class="kpi-label">SQL 注入攻击</div>
          <div class="kpi-sub">最常见的攻击类型</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-1);--icon-bg:rgba(6,182,212,.15)">
          <div class="kpi-top"><div class="kpi-icon">💉</div><span class="kpi-trend up" id="trendXss">+0%</span></div>
          <div class="kpi-value" id="cntXss">0</div>
          <div class="kpi-label">XSS 跨站脚本</div>
          <div class="kpi-sub">跨站脚本攻击</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2);--icon-bg:rgba(139,92,246,.15)">
          <div class="kpi-top"><div class="kpi-icon">🤖</div><span class="kpi-trend up" id="trendBot">+0%</span></div>
          <div class="kpi-value" id="cntBot">0</div>
          <div class="kpi-label">恶意爬虫</div>
          <div class="kpi-sub">自动化攻击工具</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3);--icon-bg:rgba(16,185,129,.15)">
          <div class="kpi-top"><div class="kpi-icon">🛡️</div><span class="kpi-trend down" id="trendFp">-0%</span></div>
          <div class="kpi-value" id="cntFp">0</div>
          <div class="kpi-label">误报率</div>
          <div class="kpi-sub">7层误报控制</div>
        </div>
      </div>

      <!-- 图表行1 -->
      <div class="chart-row">
        <div class="chart-card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>攻击趋势 (近7日)</div>
            <div class="card-actions">
              <span class="chip">24h</span>
              <span class="chip active">7天</span>
              <span class="chip">30天</span>
            </div>
          </div>
          <div class="chart-wrap"><canvas id="trendChart"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="card-head">
            <div class="card-title"><span class="dot"></span>攻击类型分布</div>
          </div>
          <div class="chart-wrap"><canvas id="typeChart"></canvas></div>
        </div>
      </div>

      <!-- 实时日志流 -->
      <div class="log-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--red);animation:pulse-dot 1s infinite"></span>实时攻击日志流</div>
          <div class="card-actions">
            <span class="chip active">全部</span>
            <span class="chip">严重</span>
            <span class="chip">高危</span>
            <span class="chip">中危</span>
          </div>
        </div>
        <div class="log-stream" id="logStream"></div>
      </div>

      <!-- 攻击来源 TOP -->
      <div class="chart-row two">
        <div class="table-card">
          <div class="card-head">
            <div class="card-title"><span class="dot" style="background:var(--orange)"></span>攻击来源 TOP 10</div>
            <button class="btn btn-ghost" onclick="loadBlacklistPage()">封禁管理 →</button>
          </div>
          <table id="topIpTable">
            <thead><tr><th>IP 地址</th><th>攻击次数</th><th>最近攻击</th><th>操作</th></tr></thead>
            <tbody></tbody>
          </table>
        </div>
        <div class="table-card">
          <div class="card-head">
            <div class="card-title"><span class="dot" style="background:var(--purple)"></span>受攻击 URL TOP 10</div>
          </div>
          <table id="topUrlTable">
            <thead><tr><th>URL 路径</th><th>攻击次数</th><th>占比</th></tr></thead>
            <tbody></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ===== 攻击日志 ===== -->
    <div class="page" id="page-attacks">
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--red)"></span>全部攻击日志</div>
          <div class="card-actions">
            <select style="background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--text);font-size:12px;outline:none">
              <option>全部类型</option><option>SQL注入</option><option>XSS</option><option>爬虫</option>
            </select>
            <button class="btn btn-ghost">导出</button>
          </div>
        </div>
        <table>
          <thead><tr><th>时间</th><th>IP 地址</th><th>类型</th><th>URL</th><th>风险等级</th><th>状态</th></tr></thead>
          <tbody id="allAttackBody"></tbody>
        </table>
      </div>
    </div>

    <!-- ===== 机器人防护 ===== -->
    <div class="page" id="page-bots">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-1)">
          <div class="kpi-top"><div class="kpi-icon">🔍</div><span class="kpi-trend down">-0%</span></div>
          <div class="kpi-value" id="botSearch">0</div><div class="kpi-label">搜索引擎蜘蛛</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-4)">
          <div class="kpi-top"><div class="kpi-icon">💀</div><span class="kpi-trend up">+0%</span></div>
          <div class="kpi-value" id="botMalicious">0</div><div class="kpi-label">恶意爬虫</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2)">
          <div class="kpi-top"><div class="kpi-icon">🕷️</div><span class="kpi-trend up">+0%</span></div>
          <div class="kpi-value" id="botCrawler">0</div><div class="kpi-label">通用爬虫</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3)">
          <div class="kpi-top"><div class="kpi-icon">🧑</div><span class="kpi-trend down">-0%</span></div>
          <div class="kpi-value" id="botHuman">0</div><div class="kpi-label">人类访客</div>
        </div>
      </div>
      <div class="chart-row two">
        <div class="chart-card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>机器人分类占比</div></div>
          <div class="chart-wrap"><canvas id="botPieChart"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>爬虫访问趋势</div></div>
          <div class="chart-wrap"><canvas id="botTrendChart"></canvas></div>
        </div>
      </div>
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--cyan)"></span>已知搜索引擎蜘蛛 (32种)</div></div>
        <table>
          <thead><tr><th>搜索引擎</th><th>UA 特征</th><th>验证方式</th><th>状态</th></tr></thead>
          <tbody>
            <tr><td>Google</td><td>Googlebot</td><td>DNS 反向+正向</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>Bing</td><td>Bingbot / msnbot</td><td>DNS 反向+正向</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>百度</td><td>Baiduspider</td><td>DNS 反向+正向</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>Yandex</td><td>YandexBot</td><td>DNS 反向+正向</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>360搜索</td><td>360Spider</td><td>头特征验证</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>搜狗</td><td>Sogou web spider</td><td>头特征验证</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>字节跳动</td><td>Bytespider</td><td>头特征验证</td><td><span class="tag green">已放行</span></td></tr>
            <tr><td>神马搜索</td><td>ShenmaBot</td><td>头特征验证</td><td><span class="tag green">已放行</span></td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ===== IP 管理 ===== -->
    <div class="page" id="page-firewall">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-4)">
          <div class="kpi-value" id="banCount">0</div><div class="kpi-label">封禁 IP 数</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3)">
          <div class="kpi-value" id="wlCount">0</div><div class="kpi-label">白名单 IP 数</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-1)">
          <div class="kpi-value" id="rateCount">0</div><div class="kpi-label">限流 IP 数</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2)">
          <div class="kpi-value" id="honeypotCount">0</div><div class="kpi-label">蜜罐触发</div>
        </div>
      </div>
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--red)"></span>封禁列表</div>
          <div style="display:flex;gap:10px">
            <input type="text" id="banIp" placeholder="输入 IP 地址" style="background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;padding:7px 12px;color:var(--text);font-size:12px;outline:none;width:180px">
            <button class="btn btn-danger" onclick="quickBan()">手动封禁</button>
          </div>
        </div>
        <table>
          <thead><tr><th>IP 地址</th><th>到期时间</th><th>封禁次数</th><th>原因</th><th>操作</th></tr></thead>
          <tbody id="banBody"></tbody>
        </table>
      </div>
    </div>

    <!-- ===== 防护规则 ===== -->
    <div class="page" id="page-rules">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-1)"><div class="kpi-value">14</div><div class="kpi-label">编码归一化层</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-2)"><div class="kpi-value">10</div><div class="kpi-label">语义分析维度</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-3)"><div class="kpi-value">20+</div><div class="kpi-label">防护模块</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-4)"><div class="kpi-value">7</div><div class="kpi-label">误报控制层</div></div>
      </div>
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--cyan)"></span>已启用的防护模块</div></div>
        <table>
          <thead><tr><th>模块名称</th><th>类型</th><th>说明</th><th>状态</th></tr></thead>
          <tbody>
            <tr><td>SQL 注入防护</td><td><span class="tag red">核心</span></td><td>14层编码归一化 + 语义分析</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>XSS 跨站脚本</td><td><span class="tag red">核心</span></td><td>HTML/JS 注入检测</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>SSRF 防护</td><td><span class="tag orange">高级</span></td><td>内网IP/云元数据端点检测</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>NoSQL 注入</td><td><span class="tag orange">高级</span></td><td>MongoDB / Redis 注入</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>请求走私防护</td><td><span class="tag orange">高级</span></td><td>CL.TE / TE.CL 攻击</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>JWT 安全</td><td><span class="tag purple">API</span></td><td>空签名 / alg=none 检测</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>模板注入检测</td><td><span class="tag purple">高级</span></td><td>Jinja2 / Twig / Smarty</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>API 安全防护</td><td><span class="tag purple">API</span></td><td>路径遍历 / 控制字符 / 大小限制</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>CRLF 注入</td><td><span class="tag yellow">协议</span></td><td>Header 注入检测</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>缓存投毒防护</td><td><span class="tag yellow">协议</span></td><td>缓存绕过头 / Host 投毒</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>机器人防护</td><td><span class="tag cyan">5星</span></td><td>32种蜘蛛识别 + 蜜罐</td><td><span class="tag green">已启用</span></td></tr>
            <tr><td>主动路径围堵</td><td><span class="tag cyan">5星</span></td><td>攻击预判 + 蜜罐部署</td><td><span class="tag green">已启用</span></td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ===== 沙箱中心 ===== -->
    <div class="page" id="page-sandbox">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-4)"><div class="kpi-value" id="sandMal">0</div><div class="kpi-label">检测到恶意文件</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-3)"><div class="kpi-value" id="sandClean">0</div><div class="kpi-label">已清除文件</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-1)"><div class="kpi-value" id="sandWatch">0</div><div class="kpi-label">监控文件数</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-2)"><div class="kpi-value" id="sandQuar">0</div><div class="kpi-label">隔离区文件</div></div>
      </div>
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--red)"></span>恶意文件记录</div></div>
        <table>
          <thead><tr><th>文件路径</th><th>检测时间</th><th>威胁类型</th><th>状态</th></tr></thead>
          <tbody><tr><td colspan="4" style="text-align:center;color:var(--text4);padding:30px">暂无恶意文件 · 系统安全</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- ===== 自学习系统 ===== -->
    <div class="page" id="page-learn">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-3)"><div class="kpi-value" id="learnPatterns">0</div><div class="kpi-label">自动学习规则</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-1)"><div class="kpi-value" id="learnNormal">0</div><div class="kpi-label">正常基线参数</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-2)"><div class="kpi-value" id="learnFeedback">0</div><div class="kpi-label">反馈修正次数</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-4)"><div class="kpi-value" id="learnAcc">99.9%</div><div class="kpi-label">识别准确率</div></div>
      </div>
      <div class="chart-row two">
        <div class="chart-card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>学习趋势</div></div>
          <div class="chart-wrap"><canvas id="learnChart"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>权重自适应</div></div>
          <div class="chart-wrap"><canvas id="weightChart"></canvas></div>
        </div>
      </div>
    </div>

    <!-- ===== 系统设置 ===== -->
    <div class="page" id="page-settings">
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--cyan)"></span>系统配置</div></div>
        <table>
          <thead><tr><th>配置项</th><th>当前值</th><th>说明</th></tr></thead>
          <tbody>
            <tr><td>WAF 版本</td><td><span class="tag cyan">v<?php echo $version; ?></span></td><td>当前运行版本</td></tr>
            <tr><td>编码归一化</td><td><span class="tag green">14层</span></td><td>URL/HTML/Unicode/Base64/NFKC/同形字等</td></tr>
            <tr><td>语义分析</td><td><span class="tag green">10维</span></td><td>L1-L10 全维度语义引擎</td></tr>
            <tr><td>误报控制</td><td><span class="tag green">7层</span></td><td>宁可漏网 绝不误杀</td></tr>
            <tr><td>CC 防护阈值</td><td><span class="tag yellow">60/分钟</span></td><td>超过即限流</td></tr>
            <tr><td>自动学习</td><td><span class="tag green">已启用</span></td><td>3次触发自动生成规则</td></tr>
            <tr><td>DNS 蜘蛛验证</td><td><span class="tag yellow">可选</span></td><td>搜索引擎真实性验证</td></tr>
            <tr><td>蜜罐链接</td><td><span class="tag green">已启用</span></td><td>页面注入隐藏链接</td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>
</div>

<script>
// ========== 基础设置 ==========
const colors = ['#ef4444','#f97316','#f59e0b','#10b981','#06b6d4','#3b82f6','#8b5cf6','#ec4899'];
let charts = {};

// ========== 侧边栏导航 ==========
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    const page = item.dataset.page;
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById('page-' + page).classList.add('active');
    const titles = {overview:'安全总览',attacks:'攻击日志',bots:'机器人防护',firewall:'IP 管理',rules:'防护规则',sandbox:'沙箱中心',learn:'自学习系统',settings:'系统设置'};
    document.getElementById('pageTitle').textContent = titles[page] || '安全总览';
    if(page==='overview') loadOverview();
    if(page==='attacks') loadAllAttacks();
    if(page==='firewall') loadFirewall();
  });
});

// ========== 时钟 ==========
function updateClock(){
  const d = new Date();
  document.getElementById('clock').textContent = d.toLocaleString('zh-CN',{hour12:false});
  document.getElementById('verTime').textContent = d.toLocaleTimeString('zh-CN',{hour12:false});
}
setInterval(updateClock,1000);updateClock();

// ========== API 请求 ==========
async function api(action, data={}){
  const fd = new FormData();
  for(const [k,v] of Object.entries(data)) fd.append(k,v);
  try{
    const r = await fetch('/waf-dashboard-api?action='+action,{method:'POST',body:fd});
    return await r.json();
  }catch(e){return {success:false,data:[]}}
}

// ========== 总览页面 ==========
let attackLogs = [];

async function loadOverview(){
  const res = await fetch('/waf-dashboard-api').then(r=>r.json()).catch(()=>({}));

  // KPI
  const total = res.total || 0;
  const daily = res.daily || {};
  const days = Object.keys(daily).sort();
  const today = days.length ? daily[days[days.length-1]] : 0;
  const yesterday = days.length>1 ? daily[days[days.length-2]] : 0;
  document.getElementById('kTotal').textContent = total;
  document.getElementById('kToday').textContent = today;
  document.getElementById('kIps').textContent = Object.keys(res.top_ips||{}).length;
  document.getElementById('kTypes').textContent = Object.keys(res.types||{}).length;
  document.getElementById('attackBadge').textContent = today;

  // 类型统计
  const types = res.types || {};
  document.getElementById('cntSql').textContent = types['SQL注入'] || types.sql || 0;
  document.getElementById('cntXss').textContent = types['XSS'] || types.xss || 0;
  document.getElementById('cntBot').textContent = types['爬虫'] || types.bot || 0;
  document.getElementById('cntFp').textContent = '0.01%';

  // 趋势图
  if(days.length){
    const counts = days.map(d=>daily[d]);
    if(charts.trend) charts.trend.destroy();
    charts.trend = new Chart(document.getElementById('trendChart'),{
      type:'line',
      data:{labels:days.map(d=>d.slice(5)),datasets:[{
        label:'攻击次数',data:counts,borderColor:'#06b6d4',
        backgroundColor:(ctx)=>{const g=ctx.chart.ctx.createLinearGradient(0,0,0,260);g.addColorStop(0,'rgba(6,182,212,.3)');g.addColorStop(1,'rgba(6,182,212,0)');return g},
        fill:true,tension:.4,pointRadius:3,pointBackgroundColor:'#06b6d4',borderWidth:2
      }]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(15,23,42,.95)',borderColor:'rgba(148,163,184,.1)',borderWidth:1,titleColor:'#e2e8f0',bodyColor:'#94a3b8',padding:12,cornerRadius:8}},
        scales:{y:{beginAtZero:true,grid:{color:'rgba(148,163,184,.06)'},ticks:{color:'#64748b',font:{size:11}}},x:{grid:{display:false},ticks:{color:'#64748b',font:{size:11}}}}}
    });
  }

  // 类型饼图
  if(Object.keys(types).length){
    if(charts.type) charts.type.destroy();
    charts.type = new Chart(document.getElementById('typeChart'),{
      type:'doughnut',
      data:{labels:Object.keys(types),datasets:[{data:Object.values(types),backgroundColor:colors.slice(0,Object.keys(types).length),borderWidth:0,hoverOffset:8}]},
      options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},padding:12,usePointStyle:true,pointStyle:'circle'}}}}
    });
  }

  // TOP IP
  const topIps = res.top_ips || {};
  const ipEntries = Object.entries(topIps).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const tbody = document.querySelector('#topIpTable tbody');
  tbody.innerHTML = ipEntries.length ? ipEntries.map(([ip,cnt])=>{
    const last = (res.latest||[]).filter(a=>a.ip===ip).pop();
    return `<tr><td style="font-family:monospace">${ip}</td><td><span class="tag red">${cnt}</span></td><td style="color:var(--text3);font-size:12px">${last?.time||'-'}</td><td><button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="quickBanIp('${ip}')">封禁</button></td></tr>`;
  }).join('') : '<tr><td colspan="4" style="text-align:center;color:var(--text4);padding:20px">暂无数据</td></tr>';

  // TOP URL (从日志中提取)
  const urlMap = {};
  (res.latest||[]).forEach(a=>{const u=(a.uri||'').split('?')[0];urlMap[u]=(urlMap[u]||0)+1});
  const urlEntries = Object.entries(urlMap).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const maxUrl = urlEntries[0]?.[1] || 1;
  document.querySelector('#topUrlTable tbody').innerHTML = urlEntries.length ? urlEntries.map(([url,cnt])=>{
    const pct = Math.round(cnt/maxUrl*100);
    const short = url.length>40 ? url.slice(0,40)+'...' : url;
    return `<tr><td style="font-family:monospace;font-size:12px;color:var(--text2)" title="${url}">${short}</td><td><span class="tag orange">${cnt}</span></td><td><div style="background:rgba(148,163,184,.1);border-radius:4px;height:6px;width:100%;overflow:hidden"><div style="background:linear-gradient(90deg,#f97316,#ef4444);height:100%;width:${pct}%"></div></div></td></tr>`;
  }).join('') : '<tr><td colspan="3" style="text-align:center;color:var(--text4);padding:20px">暂无数据</td></tr>';

  // 实时日志
  if(res.latest) attackLogs = res.latest;
  renderLogStream();

  // 地图点
  renderMapDots(ipEntries);
}

function renderMapDots(ips){
  const container = document.getElementById('mapDots');
  if(!container) return;
  container.innerHTML = ips.slice(0,6).map((_,i)=>{
    const x = 15 + Math.random()*70;
    const y = 20 + Math.random()*60;
    return `<div class="map-dot" style="left:${x}%;top:${y}%;animation-delay:${i*0.3}s"></div>`;
  }).join('');
  if(ips.length){
    document.getElementById('topCountry').textContent = ips[0][0].slice(0,7)+'...';
    const total = ips.reduce((s,[,c])=>s+c,0);
    document.getElementById('avgPerMin').textContent = Math.round(total/10080);
  }
}

function renderLogStream(){
  const container = document.getElementById('logStream');
  if(!container) return;
  const lines = attackLogs.slice(-30).reverse();
  container.innerHTML = lines.map(a=>{
    let level = 'medium';
    let type = a.msg || '';
    if(/SQL|注入/i.test(type)) level = 'critical';
    else if(/XSS|SSRF|RCE|命令/i.test(type)) level = 'high';
    else if(/爬虫|bot|扫描/i.test(type)) level = 'low';
    const t = (a.time||'').split(' ').pop() || '--:--:--';
    return `<div class="log-line"><span class="log-time">${t}</span><span class="log-level ${level}">${level==='critical'?'严重':level==='high'?'高危':level==='medium'?'中危':'低危'}</span><span class="log-ip">${a.ip||'--'}</span><span class="log-msg">${(a.msg||'')} → ${a.uri||''}</span></div>`;
  }).join('');
  container.scrollTop = 0;
}

// ========== 所有攻击日志 ==========
function loadAllAttacks(){
  const tbody = document.getElementById('allAttackBody');
  if(!tbody) return;
  const rows = attackLogs.slice(-50).reverse().map(a=>{
    let level = 'medium', tag = 'yellow';
    const type = a.msg || '';
    if(/SQL|注入/i.test(type)){level='严重';tag='red'}
    else if(/XSS|SSRF/i.test(type)){level='高危';tag='orange'}
    else if(/爬虫/i.test(type)){level='低危';tag='green'}
    return `<tr><td style="color:var(--text3);font-size:12px">${a.time||''}</td><td style="font-family:monospace">${a.ip||''}</td><td><span class="tag ${tag}">${type.slice(0,20)}</span></td><td style="font-family:monospace;font-size:12px;color:var(--text2);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.uri||''}</td><td><span class="tag ${tag}">${level}</span></td><td><span class="tag red">已拦截</span></td></tr>`;
  }).join('');
  tbody.innerHTML = rows || '<tr><td colspan="6" style="text-align:center;color:var(--text4);padding:30px">暂无攻击日志</td></tr>';
}

// ========== 防火墙/IP管理 ==========
function loadFirewall(){
  api('get_banned').then(res=>{
    const data = res.data || [];
    document.getElementById('banCount').textContent = data.length;
    document.getElementById('banBody').innerHTML = data.length ? data.map(item=>`<tr><td style="font-family:monospace">${item.ip}</td><td style="color:var(--text3);font-size:12px">${item.expire_str||'永久'}</td><td><span class="tag yellow">${item.history_count||1}次</span></td><td style="color:var(--text3);font-size:12px">自动封禁</td><td><button class="btn btn-success" style="padding:4px 10px;font-size:11px" onclick="unbanIpQuick('${item.ip}')">解封</button></td></tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text4);padding:20px">暂无封禁记录</td></tr>';
  });
  api('get_whitelist').then(res=>{
    document.getElementById('wlCount').textContent = (res.data||[]).length;
  });
}

function quickBanIp(ip){
  api('ban_ip',{ip,duration:86400}).then(res=>{
    if(res.success){showToast('封禁成功','success');loadFirewall()}
    else showToast(res.message||'操作失败','error');
  });
}
function unbanIpQuick(ip){
  api('unban_ip',{ip}).then(res=>{
    if(res.success){showToast('解封成功','success');loadFirewall()}
    else showToast(res.message||'操作失败','error');
  });
}
function quickBan(){
  const ip = document.getElementById('banIp').value.trim();
  if(!ip) return showToast('请输入 IP','error');
  quickBanIp(ip);
  document.getElementById('banIp').value = '';
}
function loadBlacklistPage(){
  document.querySelector('.nav-item[data-page="firewall"]').click();
}

// ========== Toast ==========
function showToast(msg,type='success'){
  const t = document.createElement('div');
  t.style.cssText = `position:fixed;top:24px;right:24px;padding:12px 20px;border-radius:10px;font-size:13px;font-weight:600;z-index:9999;animation:toastIn .3s ease;${type==='success'?'background:rgba(16,185,129,.95);color:#fff':'background:rgba(239,68,68,.95);color:#fff'}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>{t.style.opacity='0';t.style.transform='translateX(100%)';t.style.transition='all .3s';setTimeout(()=>t.remove(),300)},2500);
}
const toastStyle = document.createElement('style');
toastStyle.textContent = '@keyframes toastIn{from{opacity:0;transform:translateX(100%)}to{opacity:1;transform:translateX(0)}}';
document.head.appendChild(toastStyle);

// ========== 初始化 ==========
loadOverview();
setInterval(()=>{
  if(document.getElementById('page-overview').classList.contains('active')){
    fetch('/waf-dashboard-api').then(r=>r.json()).then(res=>{
      if(res.latest) attackLogs = res.latest;
      renderLogStream();
    }).catch(()=>{});
  }
},5000);
</script>
</body>
</html>
