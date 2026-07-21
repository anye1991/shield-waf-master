<?php
/**
 * 盾甲 WAF 机器人检测仪表盘 (dashboard_bot.php)
 * 展示机器人检测结果、分类统计、验证码挑战记录
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/../Support/Functions.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$ok1 = isset($_SESSION['waf_ok1']) && $_SESSION['waf_ok1'] > time();
$ok2 = isset($_SESSION['waf_ok2']) && $_SESSION['waf_ok2'] > time();
$ipOk = isset($_SESSION['waf_ip']) && $_SESSION['waf_ip'] === waf_get_real_ip();
if (!$ok1 || !$ok2 || !$ipOk) {
    http_response_code(403);
    exit('Forbidden');
}

require_once __DIR__ . '/../Bot/BotManager.php';

// 获取机器人统计数据
$reportFile = WAF_LOG_PATH . '/bot_stats.json';
$botStats = [];
if (is_file($reportFile)) {
    $botStats = json_decode(file_get_contents($reportFile), true) ?: [];
}

$totalBots      = $botStats['total_detected'] ?? 0;
$humanCount     = $botStats['categories']['human'] ?? 0;
$searchCount    = $botStats['categories']['search_engine'] ?? 0;
$crawlerCount   = $botStats['categories']['crawler'] ?? 0;
$maliciousCount = $botStats['categories']['malicious_bot'] ?? 0;
$aiCount        = $botStats['categories']['ai'] ?? 0;
$socialCount    = $botStats['categories']['social_media'] ?? 0;
$blockedCount   = $botStats['actions']['block'] ?? 0;
$challengedCount= $botStats['actions']['challenge'] ?? 0;
$limitedCount   = $botStats['actions']['limit'] ?? 0;
$recentEvents    = $botStats['recent_events'] ?? [];
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>盾甲 WAF - 机器人检测仪表盘</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;padding:20px}
.header{display:flex;align-items:center;gap:15px;margin-bottom:25px;padding-bottom:15px;border-bottom:1px solid #1e2a3a}
.header h1{font-size:1.6rem;background:linear-gradient(90deg,#00d2ff,#3a7bd5);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .badge{background:#1e2a3a;padding:4px 12px;border-radius:12px;font-size:.75rem;color:#00d2ff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:25px}
.card{background:#111827;border:1px solid #1e2a3a;border-radius:10px;padding:18px;transition:border-color .3s}
.card:hover{border-color:#3a7bd5}
.card .label{font-size:.75rem;color:#667880;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.card .value{font-size:2rem;font-weight:700}
.card.human .value{color:#2ed573}
.card.search .value{color:#00d2ff}
.card.crawler .value{color:#ffa502}
.card.malicious .value{color:#ff4757}
.card.ai .value{color:#a55eea}
.card.blocked .value{color:#ff4757}
.card.challenged .value{color:#ffa502}
.card.limited .value{color:#feca57}
.section-title{font-size:1.1rem;color:#00d2ff;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1e2a3a}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:10px;color:#667880;border-bottom:1px solid #1e2a3a;font-weight:600}
td{padding:10px;border-bottom:1px solid #111827}
.tag{display:inline-block;padding:2px 10px;border-radius:10px;font-size:.7rem}
.tag-human{background:#1a3a2a;color:#2ed573}
.tag-search{background:#1a2a3a;color:#00d2ff}
.tag-crawler{background:#3a2a1a;color:#ffa502}
.tag-malicious{background:#3a1a1a;color:#ff4757}
.tag-ai{background:#2a1a3a;color:#a55eea}
.tag-block{background:#3a1a1a;color:#ff4757}
.tag-challenge{background:#3a2a1a;color:#ffa502}
.tag-allow{background:#1a3a2a;color:#2ed573}
.empty{text-align:center;padding:40px;color:#445}
</style>
</head>
<body>
<div class="header">
    <h1>机器人检测</h1>
    <span class="badge">盾甲 WAF</span>
    <span style="margin-left:auto;font-size:.8rem;color:#445">每5秒自动刷新</span>
</div>

<div class="grid">
    <div class="card human"><div class="label">人类访客</div><div class="value"><?= $humanCount ?></div></div>
    <div class="card search"><div class="label">搜索引擎</div><div class="value"><?= $searchCount ?></div></div>
    <div class="card crawler"><div class="label">爬虫</div><div class="value"><?= $crawlerCount ?></div></div>
    <div class="card malicious"><div class="label">恶意机器人</div><div class="value"><?= $maliciousCount ?></div></div>
    <div class="card ai"><div class="label">AI 爬虫</div><div class="value"><?= $aiCount ?></div></div>
    <div class="card social"><div class="label">社交媒体</div><div class="value"><?= $socialCount ?></div></div>
    <div class="card blocked"><div class="label">已拦截</div><div class="value"><?= $blockedCount ?></div></div>
    <div class="card challenged"><div class="label">验证码挑战</div><div class="value"><?= $challengedCount ?></div></div>
    <div class="card limited"><div class="label">已限流</div><div class="value"><?= $limitedCount ?></div></div>
</div>

<div class="section-title">最近事件</div>
<?php if (!empty($recentEvents)): ?>
<table>
    <thead><tr><th>时间</th><th>IP</th><th>分类</th><th>评分</th><th>动作</th><th>原因</th></tr></thead>
    <tbody>
    <?php foreach (array_slice(array_reverse($recentEvents), 0, 50) as $event): ?>
    <tr>
        <td><?= date('H:i:s', $event['time'] ?? 0) ?></td>
        <td><?= htmlspecialchars($event['ip'] ?? '-') ?></td>
        <td><span class="tag tag-<?= htmlspecialchars($event['category'] ?? 'unknown', ENT_QUOTES) ?>"><?= htmlspecialchars($event['category'] ?? '-', ENT_QUOTES) ?></span></td>
        <td><?= htmlspecialchars((string)($event['score'] ?? '-'), ENT_QUOTES) ?></td>
        <td><span class="tag tag-<?= htmlspecialchars($event['action'] ?? 'allow', ENT_QUOTES) ?>"><?= htmlspecialchars($event['action'] ?? '-', ENT_QUOTES) ?></span></td>
        <td><?= htmlspecialchars($event['reason'] ?? '-') ?></td>
    </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php else: ?>
<div class="empty">暂无机器人检测数据</div>
<?php endif; ?>

<script>setTimeout(()=>location.reload(),5000);</script>
</body>
</html>
