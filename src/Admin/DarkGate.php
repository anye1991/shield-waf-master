<?php
/**
 * 暗门二次验证页面（美化版）
 */
defined('ABSPATH') || exit;

function waf_2fa() {
    // 生成 CSRF token
    if (empty($_SESSION['waf_csrf'])) {
        $_SESSION['waf_csrf'] = bin2hex(random_bytes(32));
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // CSRF 验证
        $token = $_POST['csrf_token'] ?? '';
        if (!hash_equals($_SESSION['waf_csrf'], $token)) {
            waf_block('CSRF token invalid');
        }
        // 简单密码验证（WordPress 简化模式）
        $input = trim($_POST['w2f'] ?? '');
        $stored = defined('WAF_PASSWORD') ? WAF_PASSWORD : '';
        if ($stored && hash_equals($stored, $input)) {
            $_SESSION['waf_ok2'] = time() + WAF_MAGIC_EXPIRE;
            // 同时刷新 waf_ok1，避免用户在 magic 验证后等待过久导致 ok1 过期
            $_SESSION['waf_ok1'] = time() + WAF_MAGIC_EXPIRE;
            // 成功后重置错误计数器
            waf_attempt_reset('2fa');
            // 刷新 CSRF token
            $_SESSION['waf_csrf'] = bin2hex(random_bytes(32));
            // 安全重定向：用 SERVER_NAME 而非 HTTP_HOST 防止开放重定向
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https://' : 'http://';
            $host = $_SERVER['SERVER_NAME'] ?? $_SERVER['HTTP_HOST'];
            // 验证 host 合法性（只允许字母数字点减号）
            if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $host)) {
                $host = 'localhost';
            }
            header('Location: ' . $scheme . $host . '/wp-admin/');
            exit;
        } else {
            waf_attempt_inc('2fa');
            if (waf_attempt_get('2fa') >= WAF_MAGIC_MAX_RETRY) {
                waf_smart_ban(waf_get_real_ip());
                waf_block('Too many 2FA attempts');
            }
            $error = '密码错误，请重试';
        }
    }

    $error_html = isset($error) ? '<div class="error-msg">' . htmlspecialchars($error) . '</div>' : '';

    echo '<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>暗门验证 · Shield WAF</title>
    <style>
        :root {
            --bg: #06090f;
            --surface: rgba(255,255,255,0.04);
            --border: rgba(255,255,255,0.08);
            --accent: #00d4ff;
            --accent2: #7c3aed;
            --text: #e2e8f0;
            --text2: #94a3b8;
            --danger: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: var(--bg);
            font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text);
            overflow: hidden;
        }
        .bg-particles {
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 0;
        }
        .particle {
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--accent);
            border-radius: 50%;
            opacity: 0.2;
            animation: float 15s infinite ease-in-out;
        }
        @keyframes float {
            0%, 100% { transform: translate(0, 0); opacity: 0; }
            25% { opacity: 0.5; }
            50% { transform: translate(100px, -100px); opacity: 0.2; }
            75% { opacity: 0.6; }
        }
        .card {
            position: relative;
            z-index: 1;
            background: rgba(15, 23, 42, 0.7);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--border);
            border-radius: 32px;
            padding: 48px 40px;
            max-width: 420px;
            width: 92%;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.6),
                        0 0 0 1px rgba(255,255,255,0.05) inset;
            animation: cardIn 0.5s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes cardIn {
            from { opacity: 0; transform: scale(0.95) translateY(10px); }
            to   { opacity: 1; transform: scale(1) translateY(0); }
        }
        .icon {
            font-size: 48px;
            margin-bottom: 24px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        h2 {
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .sub {
            font-size: 0.9rem;
            color: var(--text2);
            margin-bottom: 28px;
        }
        .form-group {
            margin-bottom: 16px;
            text-align: left;
        }
        .form-group label {
            display: block;
            font-size: 0.85rem;
            color: var(--text2);
            margin-bottom: 6px;
        }
        .input-wrapper {
            position: relative;
        }
        .input-wrapper input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: #fff;
            font-size: 1rem;
            outline: none;
            transition: all 0.2s;
        }
        .input-wrapper input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(0,212,255,0.15);
        }
        .input-wrapper .icon-lock {
            position: absolute;
            right: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text2);
            font-size: 1.1rem;
        }
        .btn {
            width: 100%;
            padding: 14px;
            margin-top: 8px;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            border: none;
            border-radius: 12px;
            color: #fff;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 4px 20px rgba(0,212,255,0.2);
        }
        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 8px 25px rgba(0,212,255,0.3);
        }
        .btn:active {
            transform: scale(0.98);
        }
        .error-msg {
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: 10px;
            padding: 10px 16px;
            margin-bottom: 16px;
            color: var(--danger);
            font-size: 0.9rem;
            text-align: center;
        }
        .footer-note {
            margin-top: 24px;
            font-size: 0.75rem;
            color: #475569;
        }
    </style>
</head>
<body>
    <div class="bg-particles">';

    for ($i = 0; $i < 20; $i++) {
        $x = mt_rand(0, 100);
        $y = mt_rand(0, 100);
        $delay = mt_rand(0, 5) . 's';
        $size = mt_rand(1, 3) . 'px';
        echo "<div class='particle' style='left:{$x}%;top:{$y}%;animation-delay:{$delay};width:{$size};height:{$size};'></div>";
    }

    echo '</div>
    <div class="card">
        <div class="icon">🚪</div>
        <h2>暗门验证</h2>
        <p class="sub">请输入二次验证密码以继续</p>
        ' . $error_html . '
        <form method="post">
            <input type="hidden" name="csrf_token" value="' . htmlspecialchars($_SESSION['waf_csrf']) . '">
            <div class="form-group">
                <label>验证密码</label>
                <div class="input-wrapper">
                    <input type="password" name="w2f" placeholder="输入密码" required autofocus autocomplete="off">
                    <span class="icon-lock">🔒</span>
                </div>
            </div>
            <button type="submit" class="btn">验证并访问</button>
        </form>
        <div class="footer-note">🛡️ Shield WAF · 访问受保护区域需要额外验证</div>
    </div>
</body>
</html>';
    exit;
}