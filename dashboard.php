<?php
defined('ABSPATH') || exit;

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']);
if (!$ok1 || !$ok2) { http_response_code(403); exit; }
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>盾甲 WAF · 攻击态势</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #06090f;
            --card: rgba(255,255,255,0.03);
            --border: rgba(255,255,255,0.06);
            --text: #e2e8f0;
            --text2: #94a3b8;
            --accent: #00d4ff;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: var(--bg);
            font-family: system-ui, -apple-system, sans-serif;
            color: var(--text);
            padding: 40px 30px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            background-image:
                radial-gradient(circle at 20% 20%, rgba(0,212,255,0.03) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(124,58,237,0.03) 0%, transparent 50%);
        }
        .container { max-width: 1400px; width: 100%; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .header h1 {
            font-size: 2.2rem; font-weight: 800;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        .header .time { color: var(--text2); font-size: 0.95rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 24px; margin-bottom: 40px; }
        .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 30px; backdrop-filter: blur(12px); }
        .stat-card .label { font-size: 0.9rem; color: var(--text2); margin-bottom: 12px; }
        .stat-card .value { font-size: 2.8rem; font-weight: 800; line-height: 1; }
        .chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 40px; }
        .chart-card { background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 30px; backdrop-filter: blur(12px); }
        .chart-card h3 { font-size: 1.1rem; margin-bottom: 20px; color: var(--text2); }
        .top-ips { background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 30px; backdrop-filter: blur(12px); }
        .top-ips table { width: 100%; border-collapse: collapse; }
        .top-ips th, .top-ips td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        .top-ips th { color: var(--text2); font-weight: 500; font-size: 0.9rem; }
        .recent-logs { background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 30px; backdrop-filter: blur(12px); margin-top: 40px; max-height: 400px; overflow-y: auto; }
        .recent-logs h3 { margin-bottom: 20px; color: var(--text2); }
        .log-entry { font-size: 0.85rem; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.03); color: var(--text2); }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; background: rgba(255,255,255,0.05); }
        .badge.danger { background: rgba(239,68,68,0.2); color: var(--danger); }
        .badge.warning { background: rgba(245,158,11,0.2); color: var(--warning); }
        @media (max-width: 768px) { .chart-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ 盾甲 WAF · 攻击态势</h1>
        <div class="time" id="clock"></div>
    </div>
    <div class="stats-grid" id="statsCards"></div>
    <div class="chart-grid">
        <div class="chart-card"><h3>📊 攻击趋势 (近7日)</h3><canvas id="trendChart"></canvas></div>
        <div class="chart-card"><h3>🎯 攻击类型分布</h3><canvas id="typeChart"></canvas></div>
    </div>
    <div class="top-ips"><h3>🌐 攻击来源 TOP 10</h3><table id="topIpTable"></table></div>
    <div class="recent-logs"><h3>📋 最近拦截记录</h3><div id="logList"></div></div>
</div>

<script>
let trendChart, typeChart;
const colors = ['#ef4444','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ec4899','#06b6d4'];

async function loadData() {
    const res = await fetch('/waf-dashboard-api');
    return await res.json();
}

function render(data) {
    document.getElementById('statsCards').innerHTML = `
        <div class="stat-card"><div class="label">7日攻击总数</div><div class="value" style="color:var(--danger)">${data.total||0}</div></div>
        <div class="stat-card"><div class="label">今日攻击</div><div class="value" style="color:var(--warning)">${Object.values(data.daily||{}).pop()||0}</div></div>
        <div class="stat-card"><div class="label">攻击来源IP</div><div class="value" style="color:var(--accent)">${Object.keys(data.top_ips||{}).length}</div></div>
        <div class="stat-card"><div class="label">攻击类型</div><div class="value" style="color:var(--success)">${Object.keys(data.types||{}).length}</div></div>`;

    if (data.daily) {
        const days = Object.keys(data.daily).sort();
        const counts = days.map(d => data.daily[d]);
        if (trendChart) trendChart.destroy();
        trendChart = new Chart(document.getElementById('trendChart'), {
            type: 'line',
            data: { labels: days, datasets: [{ label: '攻击次数', data: counts, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.1)', fill: true, tension: 0.4, pointRadius: 4 }] },
            options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false } } } }
        });
    }

    if (data.types) {
        const types = Object.keys(data.types);
        const counts = Object.values(data.types);
        if (typeChart) typeChart.destroy();
        typeChart = new Chart(document.getElementById('typeChart'), {
            type: 'doughnut',
            data: { labels: types, datasets: [{ data: counts, backgroundColor: colors.slice(0, types.length) }] },
            options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } } }
        });
    }

    if (data.top_ips) {
        let html = '<tr><th>IP 地址</th><th>攻击次数</th><th>最近攻击</th></tr>';
        for (const [ip, cnt] of Object.entries(data.top_ips)) {
            const last = (data.latest||[]).filter(a => a.ip === ip).pop();
            html += `<tr><td>${ip}</td><td><span class="badge danger">${cnt}</span></td><td>${last?.time||'-'}</td></tr>`;
        }
        document.getElementById('topIpTable').innerHTML = html;
    }

    if (data.latest) {
        let logHtml = '';
        data.latest.slice(-15).reverse().forEach(a => {
            logHtml += `<div class="log-entry">[${a.time}] <strong>${a.ip}</strong> → ${a.uri} <span class="badge warning">${a.msg}</span></div>`;
        });
        document.getElementById('logList').innerHTML = logHtml;
    }
}

function updateClock() {
    document.getElementById('clock').textContent = new Date().toLocaleString('zh-CN', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

loadData().then(render).catch(console.error);
setInterval(() => loadData().then(render).catch(console.error), 5000);
</script>
</body>
</html>