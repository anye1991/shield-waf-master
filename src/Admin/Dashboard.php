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
        .badge.success { background: rgba(16,185,129,0.2); color: var(--success); }
        .badge.active { background: rgba(16,185,129,0.2); color: var(--success); }
        .badge.expired { background: rgba(148,163,184,0.2); color: var(--text2); }

        .nav-tabs { display: flex; gap: 8px; margin-bottom: 24px; }
        .nav-tab { padding: 10px 24px; border-radius: 12px; background: var(--card); border: 1px solid var(--border); color: var(--text2); cursor: pointer; transition: all 0.2s; }
        .nav-tab:hover { border-color: var(--accent); color: var(--accent); }
        .nav-tab.active { background: rgba(0,212,255,0.1); border-color: var(--accent); color: var(--accent); }

        .ip-panel { background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 30px; backdrop-filter: blur(12px); margin-bottom: 40px; }
        .ip-panel h3 { font-size: 1.2rem; margin-bottom: 24px; color: var(--text); }

        .form-group { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; align-items: center; }
        .form-group input, .form-group select {
            padding: 12px 16px; border-radius: 12px; border: 1px solid var(--border);
            background: rgba(255,255,255,0.03); color: var(--text); font-size: 0.9rem;
            min-width: 200px;
        }
        .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--accent); }
        .btn {
            padding: 12px 24px; border-radius: 12px; border: none; cursor: pointer; font-size: 0.9rem; font-weight: 600;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--accent); color: #06090f; }
        .btn-primary:hover { opacity: 0.9; }
        .btn-danger { background: var(--danger); color: white; }
        .btn-danger:hover { opacity: 0.9; }
        .btn-success { background: var(--success); color: white; }
        .btn-success:hover { opacity: 0.9; }

        .ip-table { width: 100%; border-collapse: collapse; }
        .ip-table th, .ip-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        .ip-table th { color: var(--text2); font-weight: 500; font-size: 0.9rem; }
        .ip-table tr:hover { background: rgba(255,255,255,0.02); }

        .toast {
            position: fixed; top: 20px; right: 20px; padding: 16px 24px; border-radius: 12px;
            font-size: 0.9rem; font-weight: 500; z-index: 1000; animation: slideIn 0.3s;
        }
        .toast.success { background: var(--success); color: white; }
        .toast.error { background: var(--danger); color: white; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

        .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 1001; justify-content: center; align-items: center; }
        .modal.show { display: flex; }
        .modal-content { background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 30px; width: 400px; max-width: 90%; }
        .modal-content h4 { margin-bottom: 20px; color: var(--text); }
        .modal-content .form-group { margin-bottom: 20px; }
        .modal-content .btn { width: 100%; margin-top: 10px; }

        @media (max-width: 768px) {
            .chart-grid { grid-template-columns: 1fr; }
            .form-group { flex-direction: column; }
            .form-group input, .form-group select { width: 100%; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ 盾甲 WAF · 攻击态势 <small style="font-size:0.4em;opacity:0.6;">v<?php echo defined('SHIELD_WAF_VERSION') ? SHIELD_WAF_VERSION : '3.0.0'; ?></small></h1>
        <div class="time" id="clock"></div>
    </div>

    <div class="nav-tabs">
        <div class="nav-tab active" data-tab="dashboard">📊 仪表盘</div>
        <div class="nav-tab" data-tab="whitelist">✅ IP 白名单</div>
        <div class="nav-tab" data-tab="blacklist">❌ 封禁管理</div>
    </div>

    <div id="dashboard-tab" class="tab-content">
        <div class="stats-grid" id="statsCards"></div>
        <div class="chart-grid">
            <div class="chart-card"><h3>📊 攻击趋势 (近7日)</h3><canvas id="trendChart"></canvas></div>
            <div class="chart-card"><h3>🎯 攻击类型分布</h3><canvas id="typeChart"></canvas></div>
        </div>
        <div class="top-ips"><h3>🌐 攻击来源 TOP 10</h3><table id="topIpTable"></table></div>
        <div class="recent-logs"><h3>📋 最近拦截记录</h3><div id="logList"></div></div>
    </div>

    <div id="whitelist-tab" class="tab-content" style="display:none;">
        <div class="ip-panel">
            <h3>✅ IP 白名单管理</h3>
            <div class="form-group">
                <input type="text" id="wl-ip" placeholder="输入 IP 地址或 CIDR（如 192.168.1.0/24）">
                <select id="wl-ttl">
                    <option value="3600">1 小时</option>
                    <option value="86400">1 天</option>
                    <option value="604800">7 天</option>
                    <option value="2592000">30 天</option>
                    <option value="0">永久</option>
                </select>
                <button class="btn btn-primary" onclick="addWhitelist()">添加白名单</button>
            </div>
            <table class="ip-table">
                <thead><tr><th>IP 地址</th><th>有效期</th><th>状态</th><th>操作</th></tr></thead>
                <tbody id="whitelist-body"></tbody>
            </table>
        </div>
    </div>

    <div id="blacklist-tab" class="tab-content" style="display:none;">
        <div class="ip-panel">
            <h3>❌ IP 封禁管理</h3>
            <div class="form-group">
                <input type="text" id="bl-ip" placeholder="输入 IP 地址">
                <select id="bl-duration">
                    <option value="3600">1 小时</option>
                    <option value="86400">1 天</option>
                    <option value="604800">7 天</option>
                    <option value="2592000">30 天</option>
                    <option value="-1">永久</option>
                </select>
                <button class="btn btn-danger" onclick="banIp()">封禁 IP</button>
            </div>
            <table class="ip-table">
                <thead><tr><th>IP 地址</th><th>到期时间</th><th>状态</th><th>封禁次数</th><th>操作</th></tr></thead>
                <tbody id="blacklist-body"></tbody>
            </table>
        </div>
    </div>
</div>

<div class="modal" id="confirmModal">
    <div class="modal-content">
        <h4 id="modal-title">确认操作</h4>
        <p id="modal-msg">确定要执行此操作吗？</p>
        <div style="display:flex;gap:12px;">
            <button class="btn btn-primary" onclick="closeModal()">取消</button>
            <button class="btn btn-danger" onclick="confirmAction()">确认</button>
        </div>
    </div>
</div>

<script>
let trendChart, typeChart;
const colors = ['#ef4444','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ec4899','#06b6d4'];
let pendingAction = null;

document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
        document.getElementById(tab.dataset.tab + '-tab').style.display = 'block';
        if (tab.dataset.tab === 'whitelist') loadWhitelist();
        if (tab.dataset.tab === 'blacklist') loadBlacklist();
    });
});

async function apiRequest(action, data = {}) {
    const formData = new FormData();
    for (const [k, v] of Object.entries(data)) formData.append(k, v);
    const res = await fetch('/waf-dashboard-api?action=' + action, { method: 'POST', body: formData });
    return await res.json();
}

async function loadWhitelist() {
    const res = await apiRequest('get_whitelist');
    const tbody = document.getElementById('whitelist-body');
    tbody.innerHTML = res.data.length ? res.data.map(item => `
        <tr>
            <td>${item.ip}</td>
            <td>${item.expire_str}</td>
            <td><span class="badge ${item.status === 'active' ? 'active' : 'expired'}">${item.status === 'active' ? '生效中' : '已过期'}</span></td>
            <td><button class="btn btn-danger" style="padding:6px 12px;font-size:0.8rem;" onclick="removeWhitelist('${item.ip}')">移除</button></td>
        </tr>
    `).join('') : '<tr><td colspan="4" style="text-align:center;color:var(--text2);">暂无白名单记录</td></tr>';
}

async function addWhitelist() {
    const ip = document.getElementById('wl-ip').value.trim();
    const ttl = document.getElementById('wl-ttl').value;
    if (!ip) { showToast('请输入 IP 地址', 'error'); return; }
    const res = await apiRequest('add_whitelist', { ip, ttl });
    showToast(res.message, res.success ? 'success' : 'error');
    if (res.success) { document.getElementById('wl-ip').value = ''; loadWhitelist(); }
}

function removeWhitelist(ip) {
    pendingAction = { type: 'remove_whitelist', ip };
    document.getElementById('modal-title').textContent = '移除白名单';
    document.getElementById('modal-msg').textContent = `确定要移除 IP ${ip} 吗？`;
    document.getElementById('confirmModal').classList.add('show');
}

async function loadBlacklist() {
    const res = await apiRequest('get_banned');
    const tbody = document.getElementById('blacklist-body');
    tbody.innerHTML = res.data.length ? res.data.map(item => `
        <tr>
            <td>${item.ip}</td>
            <td>${item.expire_str}</td>
            <td><span class="badge ${item.status === 'active' ? 'danger' : 'expired'}">${item.status === 'active' ? '封禁中' : '已过期'}</span></td>
            <td><span class="badge warning">${item.history_count}</span></td>
            <td><button class="btn btn-success" style="padding:6px 12px;font-size:0.8rem;" onclick="unbanIp('${item.ip}')">解封</button></td>
        </tr>
    `).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text2);">暂无封禁记录</td></tr>';
}

async function banIp() {
    const ip = document.getElementById('bl-ip').value.trim();
    let duration = document.getElementById('bl-duration').value;
    if (!ip) { showToast('请输入 IP 地址', 'error'); return; }
    if (duration === '-1') duration = 2147483647;
    const res = await apiRequest('ban_ip', { ip, duration });
    showToast(res.message, res.success ? 'success' : 'error');
    if (res.success) { document.getElementById('bl-ip').value = ''; loadBlacklist(); }
}

function unbanIp(ip) {
    pendingAction = { type: 'unban_ip', ip };
    document.getElementById('modal-title').textContent = '解封 IP';
    document.getElementById('modal-msg').textContent = `确定要解封 IP ${ip} 吗？`;
    document.getElementById('confirmModal').classList.add('show');
}

async function confirmAction() {
    if (!pendingAction) return;
    const res = await apiRequest(pendingAction.type, { ip: pendingAction.ip });
    showToast(res.message, res.success ? 'success' : 'error');
    closeModal();
    pendingAction = null;
    loadWhitelist();
    loadBlacklist();
}

function closeModal() {
    document.getElementById('confirmModal').classList.remove('show');
    pendingAction = null;
}

function showToast(msg, type) {
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

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
        let html = '<tr><th>IP 地址</th><th>攻击次数</th><th>最近攻击</th><th>操作</th></tr>';
        for (const [ip, cnt] of Object.entries(data.top_ips)) {
            const last = (data.latest||[]).filter(a => a.ip === ip).pop();
            html += `<tr><td>${ip}</td><td><span class="badge danger">${cnt}</span></td><td>${last?.time||'-'}</td><td><button class="btn btn-danger" style="padding:4px 10px;font-size:0.75rem;" onclick="banIpQuick('${ip}')">封禁</button></td></tr>`;
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

function banIpQuick(ip) {
    pendingAction = { type: 'ban_ip', ip, duration: 86400 };
    document.getElementById('modal-title').textContent = '快速封禁';
    document.getElementById('modal-msg').textContent = `确定要封禁 IP ${ip} 吗？默认封禁 1 天。`;
    document.getElementById('confirmModal').classList.add('show');
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
