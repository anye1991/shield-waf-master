<?php
/**
 * 盾甲 WAF · 403 拦截页面
 * 可用变量：
 *   $waf_msg  - 拦截原因（可选）
 *   $waf_ip   - 客户端 IP
 *   $waf_uri  - 请求 URI
 */
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden</title>
    <style>
        :root {
            --bg: #0a0e17;
            --surface: rgba(255,255,255,0.03);
            --border: rgba(255,255,255,0.06);
            --accent: #ff4757;
            --accent2: #ff6b81;
            --text: #e2e8f0;
            --text2: #94a3b8;
            --text3: #64748b;
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

        /* 背景动态网格 */
        .bg-grid {
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }

        /* 主卡片 */
        .card {
            position: relative;
            z-index: 1;
            background: rgba(15, 23, 42, 0.7);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 32px;
            padding: 60px 48px;
            max-width: 560px;
            width: 92%;
            text-align: center;
            box-shadow:
                0 25px 50px -12px rgba(0,0,0,0.6),
                0 0 0 1px rgba(255,255,255,0.05) inset;
            animation: cardIn 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes cardIn {
            from { opacity: 0; transform: scale(0.96) translateY(10px); }
            to   { opacity: 1; transform: scale(1) translateY(0); }
        }

        /* 光晕装饰 */
        .card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle at 30% 20%, rgba(255,71,87,0.08) 0%, transparent 50%),
                        radial-gradient(circle at 70% 80%, rgba(255,107,129,0.06) 0%, transparent 50%);
            pointer-events: none;
            z-index: -1;
        }

        /* 图标 */
        .icon-shield {
            width: 90px;
            height: 90px;
            margin: 0 auto 32px;
            background: rgba(255,71,87,0.1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 54px;
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(255,71,87,0.3); }
            50%      { box-shadow: 0 0 0 20px rgba(255,71,87,0); }
        }

        h1 {
            font-size: 2.8rem;
            font-weight: 800;
            letter-spacing: -1px;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
            line-height: 1.1;
        }
        .subtitle {
            font-size: 1.05rem;
            color: var(--text2);
            margin-bottom: 10px;
            font-weight: 450;
        }
        .en {
            font-size: 0.95rem;
            color: var(--text3);
            font-style: italic;
            margin-bottom: 28px;
        }
        .divider {
            width: 50px;
            height: 3px;
            background: linear-gradient(90deg, var(--accent), transparent);
            margin: 24px auto;
            border-radius: 2px;
        }
        .info {
            font-size: 0.85rem;
            color: var(--text3);
            margin-top: 24px;
            line-height: 1.6;
        }
        .info strong {
            color: var(--text2);
            font-weight: 500;
        }
        .footer-brand {
            margin-top: 32px;
            font-size: 0.75rem;
            color: var(--text3);
            letter-spacing: 1px;
            text-transform: uppercase;
            opacity: 0.7;
        }

        /* 调试信息（生产环境可移除或通过条件控制） */
        .debug {
            margin-top: 20px;
            font-size: 0.7rem;
            color: #4b5563;
            word-break: break-all;
            border-top: 1px solid rgba(255,255,255,0.05);
            padding-top: 16px;
            display: none; /* 默认隐藏 */
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    <div class="card">
        <div class="icon-shield">🛡️</div>
        <h1>403</h1>
        <p class="subtitle">访问被拒绝</p>
        <div class="divider"></div>
        <p class="en">Access Denied – Request Blocked by Security Policy.</p>
        <p class="info">
            您的请求已被<strong>盾甲 WAF</strong>拦截。<br>如确有必要访问，请联系网站管理员。
        </p>
        <?php
        // 测试模式或调试模式：显示拦截原因（方便测试）
        $show_debug = (defined('WAF_TEST_MODE') && WAF_TEST_MODE) ||
                      (defined('WAF_DEBUG_MODE') && WAF_DEBUG_MODE);
        if (!empty($waf_msg) && $show_debug):
        ?>
        <div class="debug" style="display:block;">
            <strong style="color:#fbbf24;">[测试模式]</strong> 拦截原因：<?php echo htmlspecialchars($waf_msg); ?><br>
            您的 IP：<?php echo htmlspecialchars($waf_ip ?? ''); ?><br>
            请求路径：<?php echo htmlspecialchars($waf_uri ?? ''); ?>
            <br><br>
            <span style="color:#10b981;">测试模式下 IP 不会被实际封禁，可继续访问。</span>
        </div>
        <?php endif; ?>
        <div class="footer-brand">🛡️ Shield WAF</div>
    </div>
</body>
</html>