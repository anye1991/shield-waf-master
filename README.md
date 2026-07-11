# 盾甲 WAF (Shield WAF)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13568/badge)](https://www.bestpractices.dev/projects/13568)
**全球顶级编码归一化 · 模块化 PHP Web 应用防火墙**

盾甲 WAF 是一款专为 WordPress（或任意 PHP 站点）设计的 Web 应用防火墙，以**12 层递归编码归一化**和**500+ 全球同形字符映射**为核心，能够防御各类高级编码绕过攻击（多重 URL 编码、HTML 实体、Unicode 转义、UTF‑7、Base64、零宽字符、SQL 注释混淆等），同时提供注入检测、文件上传扫描、虚拟沙箱、后门猎杀、CC 防护、暗门保护、可视化仪表盘等 20+ 安全模块。

---

## 功能清单

| 分类 | 模块 | 说明 |
|------|------|------|
| **编码归一化** | `normalizer.php` | 递归 URL 解码、HTML 实体、Unicode 转义、UTF‑7、Base64 智能解码、NFKC 规范化、全角→半角、同形字符映射、零宽/控制字符清除、SQL 注释移除、空格压缩 |
| **上下文感知** | `normalizer.php` | 对 JSON/XML 载荷进行结构保留式归一化（只清洗值，不破坏键和标签） |
| **攻击检测** | `detector.php` | 静态关键词 + 正则双引擎，覆盖 SQLi、XSS、命令注入、路径遍历、Webshell、XXE 等 |
| **协议层防御** | `shield-waf.php` + `chunked.php` | 请求方法白名单、Content‑Type 校验、HTTP 参数污染检测、分块传输自动重组 |
| **速率限制** | `rate_limit.php` + `api_rate_limit.php` | 单 IP 窗口计数器；对 `/wp-login.php`、`/wp-json/` 等敏感路径独立限流 |
| **登录保护** | `shield-waf.php` 内建 | `wp-login.php` POST 频率限制（5 分钟 10 次），防止暴力破解 |
| **CSRF 防护** | `csrf_protect.php` | 检查 Origin/Referer 头，状态改变请求必须与本站同源 |
| **CORS 策略** | `cors_policy.php` | 仅允许本站域名跨域，自动处理 OPTIONS 预检 |
| **安全响应头** | `security_headers.php` | 注入 HSTS、CSP、X‑Frame‑Options、X‑Content‑Type‑Options 等 |
| **会话加固** | `session_security.php` | 强制 Cookie 属性 `HttpOnly`、`Secure`、`SameSite=Lax` |
| **WebSocket 阻断** | `websocket_block.php` | 直接拒绝 WebSocket 升级请求 |
| **GraphQL 注入检测** | `graphql_injection.php` | 检测 `$where`、`$regex`、`__schema` 等内省攻击 |
| **文件上传检测** | `upload.php` | 扩展名白名单、真实 MIME 校验、文件内容归一化后特征扫描 |
| **虚拟沙箱** | `sandbox.php` | 监控 PHP 文件新增/修改（MD5 快照），发现异常写入即告警 |
| **后门扫描** | `malware_scanner.php` | 特征码 + 启发式扫描全站 PHP 文件，定位 webshell 和可疑代码 |
| **IP 管理** | `ip_manager.php` | 封禁/解封、管理员白名单、暴力尝试计数器、**4 阶段累进惩罚**（1天 → 7天 → 30天 → 永久） |
| **暗门保护** | `darkgate.php` | 魔法密钥 + 二次密码双重验证，保护后台入口；验证通过后仅依赖会话，不自动加白 |
| **可视化仪表盘** | `dashboard.php` + `dashboard_api.php` + `stats.php` | 7日攻击趋势、攻击类型分布、攻击来源 TOP10、实时拦截记录、沙箱告警、后门扫描结果，科技感暗色 UI |
| **日志与告警** | `functions.php` | 本地日志 + 可选 Webhook 推送（企业微信/钉钉/Slack 等） |
| **输出过滤** | `output_filter.php` | 捕获含敏感错误的响应，替换为通用 500 页面，防止信息泄露 |

---

## 目录结构

```
shield-waf/
├── shield-waf.php              # 主入口（加载器 + 核心流程）
├── config.php                  # 配置常量（密钥、阈值、路径等）
├── functions.php               # 通用函数（IP获取、403页面、webhook）
├── normalizer.php              # 编码归一化引擎（WafNormalizer 类）
├── detector.php                # 攻击检测（双引擎）
├── upload.php                  # 文件上传防护（含 MIME 校验）
├── rate_limit.php              # CC 攻击防护（速率限制）
├── api_rate_limit.php          # API 独立速率限制
├── ip_manager.php              # IP 封禁/白名单/暴力计数/累进惩罚
├── darkgate.php                # 暗门二次验证页面（美化版）
├── output_filter.php           # 输出过滤（防敏感信息泄露）
├── chunked.php                 # 分块传输解码
├── sandbox.php                 # 虚拟沙箱（文件完整性监控）
├── malware_scanner.php         # 后门/木马扫描引擎
├── scanner_api.php             # 扫描结果 JSON API
├── dashboard.php               # 仪表盘 HTML 页面
├── dashboard_api.php           # 仪表盘数据接口
├── stats.php                   # 攻击日志统计聚合
├── security_headers.php        # 安全响应头注入
├── cors_policy.php             # 跨域请求控制
├── csrf_protect.php            # CSRF 防护
├── graphql_injection.php       # GraphQL 注入检测
├── session_security.php        # 会话 Cookie 安全属性
├── websocket_block.php         # WebSocket 连接阻断
├── waf_403_template.php        # 403 拦截页面模板（可自定义）
├── homoglyph_map.json          # 同形字符扩展文件（空 JSON）
└── waf_logs/                   # 日志目录（程序自动创建）
```

---

## 安装部署

### 环境要求

- PHP 7.4 或更高版本
- 推荐启用扩展：`mbstring`、`json`、`fileinfo`、`intl`、`dom`
- 目录 `waf_logs/` 需要 PHP 进程可写

### 步骤（适用于 WordPress）

1. 将整个 `shield-waf` 文件夹上传至 `/wp-content/plugins/`。
2. 确保 `waf_logs/` 目录存在并可写（若不存在程序会自动创建，但需确保父目录有写入权限）。
3. 在 WordPress 主题的 `functions.php` 末尾添加：

```php
require_once WP_CONTENT_DIR . '/plugins/shield-waf/shield-waf.php';
```

4. 立即修改 `config.php` 中的 `WAF_MAGIC_KEY` 和 `WAF_2FA_PASS`（支持从环境变量读取）。
5. 访问网站首页，确认无异常；若被拦截，请检查 IP 是否已封禁或通过暗门验证。

### 非 WordPress 站点

将文件夹放在任意位置，在入口文件（如 `index.php`）最顶部添加：

```php
require_once '/path/to/shield-waf/shield-waf.php';
```

> 注意：需要自行定义 `ABSPATH` 常量，或修改所有文件中 `defined('ABSPATH') || exit;` 为合适的验证。

---

## 配置说明

编辑 `config.php` 可调整以下核心参数：

| 常量 | 说明 | 默认值 |
|------|------|--------|
| `WAF_MAGIC_KEY` | 暗门魔法密钥（第一因子） | 从环境变量 `WAF_MAGIC_KEY` 读取，否则使用示例值 |
| `WAF_2FA_PASS` | 二次验证密码 | 从环境变量 `WAF_2FA_PASS` 读取，否则使用示例值 |
| `WAF_MAGIC_EXPIRE` | 第一因子有效期（秒） | 3600（1 小时） |
| `WAF_MAGIC_MAX_RETRY` | 魔法密钥 / 二次密码最大重试次数 | 3 |
| `WAF_ADMIN_IP_TTL` | 管理员 IP 白名单有效期（秒），0 表示永久 | 86400（24 小时） |
| `WAF_CC_LIMIT` | CC 攻击阈值（窗口内最大请求数） | 60 |
| `WAF_CC_WINDOW` | CC 攻击时间窗口（秒） | 60 |
| `WAF_NORMALIZE_SQL_COMMENTS` | 是否移除 SQL 注释 (true/false) | true |
| `WAF_WEBHOOK_URL` | 告警 Webhook 地址（企业微信/钉钉/Slack 等） | 空（不启用） |
| `WAF_TRUST_CF_IP` | 若使用 Cloudflare，是否信任 CF-Connecting-IP 头 | false |

---

## 使用指南

### 管理员如何免拦截？

1. 访问 `https://你的域名/wp-admin?magic=你的WAF_MAGIC_KEY`（或直接访问 `/wp-admin` 会触发暗门，再附加 magic 参数）。
2. 若魔法密钥正确，页面会跳转并显示二次验证框，输入 `WAF_2FA_PASS` 中的密码。
3. 验证通过后，当前会话（浏览器）即可正常访问后台，直到会话过期或关闭浏览器。

> 如果需要长期免验证，可手动在 `waf_logs/admin_ips.txt` 中添加 IP 和过期时间戳。

### 查看攻击仪表盘

通过暗门验证后，访问 `https://你的域名/waf-dashboard`。

页面每 5 秒自动刷新，显示 7 日攻击总数、趋势图、攻击类型分布、TOP10 攻击 IP、最新拦截记录，以及沙箱告警和后门扫描结果。

### 添加自定义同形字符

编辑 `homoglyph_map.json`，按 `"混淆字符": "映射后的ASCII"` 格式添加条目。

例如 `{"㋛": "s", "㋡": "o"}`，保存后立即生效，无需重启。

### 测试防护效果

使用浏览器无痕窗口或 curl 发送以下请求（请确保当前 IP 不在白名单中）：

```bash
# 基本 SQL 注入
curl "https://your-domain.com/?id=1' OR '1'='1"

# XSS
curl "https://your-domain.com/?q=<script>alert(1)</script>"

# 双重 URL 编码绕过
curl "https://your-domain.com/?id=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

# 全球同形字符（高棉文 s）
curl "https://your-domain.com/?q=%E1%9E%9Flect"
```

预期均返回 403 拦截页面。

---

## 高级特性说明

### 4 阶段累进惩罚

同一 IP 触发的每次拦截都会记录在 `ban.txt` 中（永久保留，过期 30 天后清理）。封禁时长随历史次数自动升级：

- 第 1 次：1 天
- 第 2 次：7 天
- 第 3 次：30 天
- 第 4 次及以上：永久封禁

> 管理员 IP（白名单）不受累进惩罚影响。

### 白名单与暗门的关系

- 暗门验证通过后不再自动写入 IP 白名单，仅依赖 PHP 会话。
- 如果管理员需要长期免验证，可手动编辑 `waf_logs/admin_ips.txt` 添加 IP，或通过 `waf_add_admin_ip()` 函数调用。
- 白名单 IP 仍会经过注入检测、文件扫描等核心防御，只跳过速率限制。

### 性能考虑

- 所有正则均为预编译，归一化有深度/长度限制，文件计数器带有缓存。
- 个人博客、中小站点无需额外配置即可流畅运行。
- 若日请求量超过百万，建议将计数器和封禁列表迁移至 Redis（已预留接口）。

---

## 文件清单与依赖关系

- **主入口**：`shield-waf.php` → 负责加载顺序和流程控制。
- 所有模块均通过 `require_once` 引入，依赖关系清晰，可单独禁用。
- **核心依赖**：`config.php`、`functions.php`、`normalizer.php`、`detector.php`、`ip_manager.php`。
- **可视化依赖**：`dashboard.php`、`dashboard_api.php`、`stats.php`、`scanner_api.php`、`malware_scanner.php`。
- **模板文件**：`waf_403_template.php`、`darkgate.php` 中的 HTML/CSS。

---

## 常见问题

**Q：为什么我清空白名单文件后仍然能直接访问后台？**

> A：您的浏览器可能仍持有之前暗门验证的 PHP 会话 Cookie。请使用无痕窗口测试，或清除 PHPSESSID Cookie。

**Q：仪表盘无数据？**

> A：检查 `waf_logs/` 目录下是否存在 `block_*.log` 文件，以及 PHP 进程是否可写入。

**Q：上传合法图片被拦截？**

> A：检查 `upload.php` 中的 MIME 白名单和扩展名白名单，或临时注释掉 fileinfo 检测部分测试。

**Q：如何临时关闭 WAF？**

> A：在 `wp-config.php` 中将引入行注释掉即可完全跳过所有防护（仅限紧急情况）。

---

## 版权

© 2026 暗夜铭少 (DarkNightMing)  
官网网站：https://waf.duduziy.com

---

## License

This project is licensed under the **Business Source License 1.1**.

- ✅ Free for non-production use (learning, testing, personal projects)
- 🔒 Commercial production use requires a commercial license
- 📅 Changes to Apache 2.0 on 2029-07-01

For commercial licensing: https://shieldwaf.com/license

See the [LICENSE](./LICENSE) file for full details.

守护每一行代码，从盾甲开始。 🛡️
