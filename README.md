# 🛡️ 盾甲 WAF (Shield WAF) v5.0.0

[![Version](https://img.shields.io/badge/version-5.0.0-blue)](https://github.com/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple)](https://php.net/)
[![Database](https://img.shields.io/badge/database-MySQL%20%7C%20PostgreSQL%20%7C%20SQLite%20%7C%20MSSQL-orange)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Security](https://img.shields.io/badge/security-audited-red)]()
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13568/badge)](https://www.bestpractices.dev/zh-CN/projects/13568/passing)
> **下一代 PHP Web 应用防火墙 · 14 层编码归一化 · 11 解析器语义引擎 · 双证据融合 · 双重密码加密**
> **署名：暗夜铭少**

---

## ✨ 为什么选择盾甲 WAF？

| 核心能力 | 说明 |
|---------|------|
| 🔐 **双重密码加密** | 业界首创「主层 + 副层」双重哈希，数据库永不明文，旧密码自动迁移 |
| 🧬 **14 层编码归一化** | 覆盖 Base64/URL/Unicode/同形字/HTML实体等 699 种混淆绕过 |
| 🧠 **语义分析引擎** | 11 个深度语义解析器，内容类型路由 + 双证据增强 + 签名保底 |
| 🔗 **双证据融合架构** | 规则引擎 + 语义引擎双路评分，互相印证，杜绝绕过 |
| 🎛️ **可视化控制台** | 12 个功能页面，33 个防御模块，大厂级交互体验 |
| 📦 **沙箱兜底防御** | 5 引擎交叉验证，智能切割，基线对比，主动围堵 |
| 🌍 **3D 全球攻击地图** | 真实 IP 地理定位，3D 旋转地球，实时攻击可视化 |
| 🤖 **机器人防护** | 12 维评分模型，94 种指纹识别，蜜罐系统，验证码体系，DNS 反向验证 |
| 📡 **全数据库兼容** | MySQL / PostgreSQL / SQLite / MSSQL，原生扩展 + PDO 双模式 |
| ⚡ **零依赖部署** | 单文件引入，即插即用，兼容 WordPress / ThinkPHP / Laravel 等任意框架 |
| 🧪 **测试模式** | 一键开启「只拦截不封IP」，方便部署期间调试规则不影响线上访问 |
| 🛡️ **管理员白名单** | 配置文件直配 IP/CIDR 网段，跳过速率限制与封禁检查 |

---

## 🏗️ 防御架构（七层纵深防御）

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 7  输出过滤 · 错误掩码 · 敏感信息脱敏                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 6  沙箱兜底 · 恶意文件扫描 · 精准切割 · 基线对比       │
├─────────────────────────────────────────────────────────────┤
│  Layer 5  高级防护 · SSRF/XXE/反序列化/SSTI/NoSQL 等 9 项    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4  核心防御 · SQL 注入/XSS/文件包含/命令注入           │
├─────────────────────────────────────────────────────────────┤
│  Layer 3  语义分析 · 11 解析器 · 内容路由 · 双证据融合         │
├─────────────────────────────────────────────────────────────┤
│  Layer 2  编码归一化 · 14 层递归解码 · 699 同形字符映射       │
├─────────────────────────────────────────────────────────────┤
│  Layer 1  接入层 · 速率限制 · IP 封禁 · 白名单 · 机器人识别   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎛️ 控制台（12 大功能中心）

现代化暗色科技风控制台，丝滑动效，完整掌控所有功能。

| # | 页面 | 核心功能 |
|---|------|---------|
| 1 | 📊 **安全总览** | KPI 大盘、攻击趋势、实时日志流、3D 旋转全球攻击地图、TOP 10 来源/URL、5 秒自动刷新 |
| 2 | ⚔️ **攻击日志** | 全量攻击日志、多维度筛选、详情展开、攻击载荷分析 |
| 3 | 🛡️ **防护中心** | 5 大分类、33 个模块独立开关、一键操作、防护模式切换、模块配置面板 |
| 4 | 🧬 **语义引擎** | 全局控制、灵敏度调节、11 个解析器管理、内容路由、双证据融合、误报控制 |
| 5 | 🤖 **机器人防护** | 12 维评分规则、蜜罐管理、验证码配置、指纹白名单、爬虫趋势 |
| 6 | 🔥 **IP 管理** | 封禁列表、白名单、手动封禁/解封、批量操作、IP 详情 |
| 7 | ✅ **误报中心** | URL 白名单、参数白名单、规则豁免、误报工单、批量导入导出 |
| 8 | 📦 **沙箱中心** | 基线管理、隔离区、文件分析、精准切割、基线对比、扫描任务 |
| 9 | 🔌 **API 安全** | JWT 安全、API 速率限制、GraphQL 防护、WebSocket、竞态条件 |
| 10 | 🧠 **自学习系统** | 学习趋势、权重自适应、沙箱联动、三层学习闭环 |
| 11 | 🔐 **网站密码** | 双重哈希配置、数据库连接、密码格式统计、集成代码、一键迁移 |
| 12 | ⚙️ **系统设置** | 全局配置、密钥管理、日志配置、版本信息 |

> 💡 所有配置实时生效，支持 localStorage 前端持久化 + JSON 文件后端持久化

---

## 🔐 双重密码加密（业界首创）

### 核心机制

```
用户明文密码
    │
    ├─→  主层哈希 (Argon2id / bcrypt / phpass)
    │
    └─→  副层哈希 (bcrypt / SHA-512)
              │
              ▼
       双重验证：两层都通过才算登录成功
```

### 技术特性

| 特性 | 说明 |
|------|------|
| **双层哈希** | 主层（强算法）+ 副层（独立算法），即使一层被破仍有保障 |
| **算法自动降级** | Argon2id → bcrypt-12 → bcrypt-10 → phpass，自动适配环境 |
| **旧密码兼容** | 支持 bcrypt / phpass(WordPress) / MD5 / SHA1 / SHA256 等所有旧格式 |
| **自动迁移** | 用户登录时自动检测并升级为双重哈希，无缝切换 |
| **防时序攻击** | 两层验证始终执行，`hash_equals` 常量时间比较 |
| **长密码安全** | bcrypt 72 字节截断前预哈希，长密码安全 |
| **零依赖** | 单文件引入，兼容 PHP 5.6+ |

### 支持的数据库

| 数据库 | 驱动 | 版本 |
|--------|------|------|
| MySQL / MariaDB | mysqli / pdo_mysql | 5.5+ |
| PostgreSQL | pgsql / pdo_pgsql | 9.5+ |
| SQLite | sqlite3 / pdo_sqlite | 3+ |
| SQL Server | pdo_sqlsrv | 2012+ |

### 快速集成

```php
// 1. 引入库
require_once 'shield-waf-master/src/Password/DualPassword.php';

// 2. 注册时加密
$hash = ShieldWAF\Password\DualPassword::hash($password);

// 3. 登录时验证
if (ShieldWAF\Password\DualPassword::verify($password, $storedHash)) {
    // 登录成功
    // 4. 自动升级旧密码格式
    if (ShieldWAF\Password\DualPassword::needsRehash($storedHash)) {
        $newHash = ShieldWAF\Password\DualPassword::hash($password);
        // 更新数据库...
    }
}
```

### WordPress 集成

```php
// 只需在主题 functions.php 中引入一行
require_once 'shield-waf-master/src/Password/WordPressIntegration.php';
// 自动接管 wp_hash_password / wp_check_password，零配置
```

---

## 🛡️ 33 个防御模块全覆盖

### 🔥 核心防护（6 个）

| 模块 | 防御目标 | 检测维度 |
|------|---------|---------|
| SQL 注入防护 | 联合注入/盲注/报错注入/堆叠查询 | 语义解析 + 规则 + 启发式 |
| XSS 跨站脚本 | 反射型/存储型/DOM 型 | HTML 解析 + JS 语义 + 编码绕过 |
| 文件包含检测 | LFI/RFI/PHP 封装协议 | 路径规范化 + 协议检测 |
| 命令注入 | 系统命令/Shell 元字符 | 命令解析 + 危险函数 |
| 代码执行检测 | 一句话木马/回调执行/可变函数 | PHP 语义 + 特征码 |
| 木马后门检测 | WebShell/后门/一句话 | 多引擎交叉验证 |

### ⚡ 高级防护（9 个）

SSRF 防护 · XXE 外部实体 · 反序列化 · 模板注入(SSTI) · LDAP 注入 · XPath 注入 · NoSQL 注入 · 文件上传检测 · 恶意扫描

### 🔗 协议防护（7 个）

CRLF 注入 · 缓存投毒 · HTTP 请求走私 · 分块传输 · 开放重定向 · 安全响应头 · CORS 策略

### 🔐 会话安全（5 个）

会话固定 · 会话劫持 · 会话安全加固 · CSRF 防护 · Cookie 安全

### 📡 API 防护（6 个）

JWT 安全 · API 速率限制 · GraphQL 防护 · WebSocket 防护 · 竞态条件防护 · API 安全基线

---

## 🧬 语义分析引擎

不依赖正则表达式，真正理解攻击意图。

### 11 个语义解析器

| 分类 | 解析器 | 深度级别 |
|------|--------|---------|
| **注入类** | SQL 语义解析器 (AST) | Level 5 - 语法树构建 |
| **代码类** | PHP 代码语义解析器 (Tokenizer) | Level 4 - Token 分析 |
| **代码类** | 命令注入解析器 | Level 2 - 模式匹配 |
| **包含类** | 路径遍历解析器 | Level 2 - 模式匹配 |
| **包含类** | SSRF 语义解析器 | Level 3 - 协议解析 |
| **XSS 类** | HTML/XSS 语义解析器 (DOM) | Level 4 - DOM 构建 |
| **XSS 类** | CRLF 注入解析器 | Level 2 - 模式匹配 |
| **代码类** | 反序列化解析器 | Level 2 - 模式匹配 |
| **代码类** | SSTI 模板注入解析器 | Level 3 - 多引擎识别 |
| **代码类** | XXE 实体解析器 | Level 3 - DTD 解析 |
| **业务类** | 表达式注入解析器 | Level 2 - 模板检测 |

### 6 个语义上下文分析器（L7-L12）

| 级别 | 分析器 | 核心能力 |
|------|--------|---------|
| **L7** | IntentInference（攻击意图推理） | Kill Chain 七阶段 + 转移概率矩阵 + 意图转移图 + 攻击者画像 |
| **L8** | AttackChainAnalyzer（攻击链时序关联） | 多链并行检测 + 三窗口时序 + 横向移动 + 8 个攻击链模板 |
| **L9** | SemanticMemoryPool（行为基线偏差） | 6 维基线建模 + 12 维特征向量 + 漂移检测 + 群体对比 |
| **L10** | FalsePositiveGuard（误报控制） | 23 个业务模式 + 自学习 + 动态参数白名单 + 智能降分 |
| **L11** | ParamPositionAnalyzer（参数位置语义） | 同 payload 在 query/post/cookie/header/json 不同位置威胁不同 |
| **L12** | RequestContextAnalyzer（跨请求上下文） | CSRF / 重放 / 会话异常 / 时序异常 / API 滥用 / 横向移动 |

### 混淆解码能力

- 支持 **14 层**递归编码归一化
- 覆盖 **699 个**同形/混淆字符
- 解码类型：URL / Double URL / Base64 / Unicode / HTML 实体 / 十六进制 / 八进制 / 注释剥离 / 空格归一化 / 大小写混淆 / 字符串拼接 / 反引号 / 可变变量 / 回调执行

---

## 🤖 机器人防护（12 维评分模型）

### 12 维评分因子

| 评分因子 | 默认权重 | 说明 |
|---------|---------|------|
| User-Agent 异常 | 15 | 缺失/伪造/罕见 UA |
| 请求频率异常 | 15 | 单位时间请求过多 |
| 无头浏览器特征 | 12 | webdriver/selenium 检测 |
| JavaScript 禁用 | 10 | 不执行 JS 的可疑爬虫 |
| IP 信誉 | 10 | 数据中心/代理/IDC IP |
| 蜜罐触发 | 15 | 访问蜜罐链接/资源 |
| 点击行为异常 | 10 | 无鼠标移动/点击轨迹 |
| 资源加载异常 | 8 | 只加载 HTML 不加载资源 |
| Cookie 支持缺失 | 8 | 不接受 Cookie |
| 指纹一致性 | 8 | 各指纹字段矛盾 |
| 页面停留时间 | 7 | 过短或过长 |
| Referer 缺失 | 5 | 直接访问占比过高 |

### 4 大指纹识别库（94 种识别规则）

| 指纹库 | 数量 | 说明 |
|--------|------|------|
| 🕷️ 搜索引擎蜘蛛 | 33 种 | Google/Bing/Baidu/Sogou/360/神马/头条/有道等，3 级信任分层 |
| 🤖 AI 爬虫 | 11 种 | GPTBot/ClaudeBot/CCBot/PerplexityBot/Google-Extended 等 |
| 🎭 无头浏览器 | 17 种 | Puppeteer/Playwright/PhantomJS/Selenium/WebDriver/Lighthouse 等 |
| 🔧 自动化工具 | 33 种 | curl/wget/python-requests/scrapy/sqlmap/nikto/Nmap/Burp 等 |

### 3 级蜘蛛信任分层

| 层级 | 蜘蛛 | 处置 |
|------|------|------|
| **tier1**（顶级信任） | Google/Bing/Baidu/Yandex | DNS 验证后直接放行 |
| **tier2**（标准信任） | DuckDuckGo/Sogou/360/神马/头条/Apple/Facebook/Twitter | 头特征验证后放行 |
| **tier3**（观察信任） | Exalead/搜搜/宜搜/即刻/Seznam | 头特征验证 + 限速 |

### 2 重验证机制

| 验证方式 | 说明 | 配置 |
|---------|------|------|
| 🔍 **DNS 反向验证**（最可靠） | 反向 DNS 解析 → 正向验证 → 后缀匹配，三步确保蜘蛛真实性 | `WAF_BOT_VERIFY_DNS=true` |
| 📋 **头特征验证**（辅助） | Googlebot/Bingbot 版本号格式校验 + Accept 头检测 | 默认开启 |

### 6 种分类与 4 级处置

| 分类 | 说明 | 处置策略 |
|------|------|---------|
| 🟢 search_engine | 已验证搜索引擎 | 直接放行 |
| 🟢 social_media | 社交媒体蜘蛛 | 直接放行 |
| 🟢 ai | AI 爬虫 | 直接放行 |
| 🟡 crawler | 通用爬虫 | allow → challenge → limit |
| 🟠 malicious_bot | 恶意机器人 | challenge → limit → block |
| 🔵 human | 正常人类 | allow → challenge → limit |

### 防护能力

- 🕸️ **蜜罐系统**：自定义蜜罐链接/资源，精准识别爬虫，触发即标记恶意
- 🔐 **验证码体系**：图形/滑块/算术/无感验证，4 种类型可选
- 🛡️ **伪造检测**：同时包含搜索引擎 UA + 自动化工具特征 → 判定伪造，撤销信任
- 📊 **自定义白名单**：UA 关键字 / IP 段 / 域名反向验证

---

## 📦 沙箱系统（第 6 层兜底防御）

### 5 引擎交叉验证

| 引擎 | 权重范围 | 说明 |
|------|---------|------|
| 特征码检测 | 0-40 | 已知 WebShell 特征库 |
| 规则检测 | 0-35 | 危险函数/语法模式 |
| 语义分析 | 0-30 | PHP 代码语义理解 |
| 结构分析 | 0-15 | 文件结构异常检测 |
| 启发式检测 | 0-15 | 行为模式分析 |

### 核心功能

- ✂️ **精准切割**：智能识别恶意代码块，安全清除保留业务代码，切割前自动备份
- 📊 **基线对比**：新增/修改/删除文件检测，可视化差异对比，基线锁定时自动备份
- 🔄 **扫描任务**：立即扫描 + 定时扫描 + 历史任务管理，异步执行不阻塞请求
- 🗑️ **隔离区**：可疑文件隔离，支持恢复/白名单/批量操作
- 🔗 **学习联动**：高置信度样本自动投喂自学习系统
- 💓 **运行心跳**：启动自动记录心跳日志，运行状态可查可见
- 👁️ **实时监控**：文件变更实时检测，秒级响应恶意写入

---

## 📤 文件上传检测（第 4 层核心防御）

在文件上传瞬间拦截恶意文件，防止 WebShell 落地。与沙箱系统互补：上传检测是第一道防线，沙箱是兜底防线。

### 7 层检测流水线

| 层级 | 检测内容 | 说明 |
|------|---------|------|
| 第 1 层 | 扩展名白名单 | 拦截 `.php/.asp/.jsp` 等危险扩展名 |
| 第 1 层+ | 双扩展名检测 | 拦截 `.php.jpg` 等绕过技巧 |
| 第 2 层 | MIME 类型检测 | 校验实际 MIME 与声明是否一致 |
| 第 3 层 | GD 库图像验证 | `getimagesize()` 验证图像真实性，识别图像马/图种 |
| 第 4 层 | 文件内容读取 | 大文件分块读取（默认 5MB），只扫描头部+尾部 |
| 第 5 层 | SVG 专用检测 | 检测 SVG 中的脚本注入和 XXE 攻击 |
| 第 6 层 | 多引擎深度分析 | 14 层编码归一化 + 11 解析器语义 + 双证据融合 |
| 第 7 层 | 分阶段处置 | 低风险放行 / 中风险记录 / 高风险拦截 |

### 8 维深度分析引擎

| 引擎 | 说明 |
|------|------|
| 🔄 14 层编码归一化 | 解码 Base64/URL/Unicode 等混淆 |
| 🧠 11 解析器语义分析 | SQL AST / HTML DOM / PHP Tokenizer 等深度解析 |
| 📊 双路评分融合 | 规则引擎 + 语义引擎双路评分取较高值 |
| 🎯 精确定位 | 行号 + 字符位置定位恶意代码 |
| 🖼️ 图像马检测 | 在二进制中搜索嵌入的 PHP 代码 |
| 📐 SVG 检测 | 脚本注入 / XXE 检测 |
| 🧪 启发式扫描 | 行为模式分析 |
| 🔖 特征码扫描 | 27+ WebShell 特征码 |

### 3 级处置机制

| 等级 | 评分范围 | 动作 |
|------|---------|------|
| 🟢 低风险 | < 30 | 放行 |
| 🟡 中风险 | 30-59 | 记录日志 |
| 🔴 高风险 | ≥ 60 | 拦截 + 可选封禁 IP |

### 配置项（9 个）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `WAF_UPLOAD_DETECTION` | `true` | 总开关 |
| `WAF_UPLOAD_ALLOWED_EXT` | 8 种图片 | 允许的扩展名白名单 |
| `WAF_UPLOAD_ALLOWED_MIME` | 7 种类型 | 允许的 MIME 类型 |
| `WAF_UPLOAD_GD_VERIFY` | `true` | GD 库图像验证 |
| `WAF_UPLOAD_ALLOW_SVG` | `false` | 是否允许 SVG（默认禁止，风险高） |
| `WAF_UPLOAD_BLOCK_THRESHOLD` | `60` | 拦截阈值 |
| `WAF_UPLOAD_LOG_THRESHOLD` | `30` | 记录阈值 |
| `WAF_UPLOAD_SCAN_MAX_SIZE` | `5MB` | 扫描最大大小 |
| `WAF_UPLOAD_BAN_ON_BLOCK` | `true` | 拦截时是否触发封禁 |

---

## 🧠 自学习系统（三层闭环）

```
WAF 主入口拦截
       ↓
上传检测 / 核心防护 → 高置信度样本
       ↓
沙箱兜底验证 → 多引擎确认
       ↓
AutoLearn 模型训练
       ↓
反哺 WAF 规则 + 语义权重
```

- **进程内静态缓存**：30 秒 TTL，减少磁盘 IO
- **权重自适应**：根据攻击数据自动调整各模块权重
- **沙箱联动**：高置信度恶意样本自动投喂
- **人工审核**：中风险样本标记待审核，避免误报污染

---

## 🚀 快速开始

### 方式一：WordPress 插件模式（推荐）

```bash
# 1. 下载解压到 wp-content/plugins/ 目录
# 2. 后台插件页面启用「盾甲 WAF」
# 3. 访问 工具 → 盾甲 WAF 控制台
```

### 方式二：任意 PHP 站点集成

```php
// 在项目入口文件最顶部加入（必须是第一行）
require_once '/path/to/shield-waf-master/shield-waf.php';
// 完成！WAF 自动开始防护
```

### 方式三：双重密码加密单独使用

```php
require_once '/path/to/shield-waf-master/src/Password/DualPassword.php';
use ShieldWAF\Password\DualPassword;

$hash = DualPassword::hash('user_password');
$valid = DualPassword::verify('user_password', $hash);
```

### 控制台访问

- **WordPress 模式**: `后台 → 工具 → 盾甲 WAF`
- **独立模式**: 访问 `https://你的域名/waf-dashboard`（需在入口文件引入 shield-waf.php）
- **暗门入口**: 访问任意页面携带暗门 Cookie（首次安装自动生成，见 `logs/auto_key.php`）

> 💡 独立模式下，确保 `shield-waf.php` 在项目入口文件最顶部引入，然后直接访问 `/waf-dashboard` 路径即可进入控制台。

---

## ⚠️ 部署必读：常见陷阱与解决方案

### 1. 首页打开直接 403

**根因**：logs 目录不可写，导致 ban 记录无法持久化，但 403 仍输出
**解决**：

```bash
# 授予 logs 目录写入权限（最常见解决方案）
chmod -R 0775 logs/
chown -R www-data:www-data logs/   # nginx/php-fpm 用户

# 验证
ls -la logs/block_$(date +%Y-%m-%d).log
```

如果 logs 不可写，WAF 会自动降级到：
1. PHP `error_log()` → 写入 nginx/php-fpm error log
2. `/tmp/shield_waf_block.log` → 系统临时目录（最后兜底）

### 2. 测试期间不想封禁自己 IP

**方案一**：开启测试模式（推荐）

```php
// config.php 顶部加入
define('WAF_TEST_MODE', true);
```

或 `.env`：
```bash
WAF_TEST_MODE=true
```

效果：
- ✅ 仍会拦截攻击（输出 403 页面）
- ✅ 不实际封禁 IP（不写 ban.txt）
- ✅ 记录到 `logs/test_mode_ban.log` 方便复盘
- ✅ 403 页面显示拦截原因
- ✅ 响应头 `X-ShieldWAF-TestMode: 1`

**方案二**：配置管理员白名单

```php
// config.php 加入
define('WAF_ADMIN_IPS', ['127.0.0.1', '192.168.1.100', '10.0.0.0/8']);
```

或 `.env`：
```bash
WAF_ADMIN_IPS=127.0.0.1,192.168.1.100,10.0.0.0/8
```

效果：
- ✅ 跳过速率限制（CC）
- ✅ 跳过封禁检查（waf_is_banned）
- ✅ waf_smart_ban 不累进封禁
- ✅ 支持 CIDR 网段（如 `10.0.0.0/8` 命中 `10.1.2.3`）
- ⚠️ 仍会 waf_block 触发 403（拦截规则照常工作）

### 3. PHP 版本兼容性

**最低支持 PHP 7.4**（推荐 7.4 或 8.x）。v4.1.1 已通过 105 个 PHP 文件全量审计：

| 问题 | 影响版本 | 已修复 |
|------|---------|--------|
| 类常量 `??` 表达式 | PHP 8.3+ 致命错误 | ✅ 改为静态属性 + getter |
| `str_contains`/`starts_with`/`ends_with` | PHP 8.0+ 专有 | ✅ Functions.php polyfill |
| `array_key_first`/`last` | PHP 7.3+ 引入 | ✅ Functions.php polyfill |
| 箭头函数 `fn()` | PHP 7.4+ 专有 | ✅ 全部改为传统 closure |
| `void` 返回类型 | PHP 7.1+ | ✅ 全部移除 |
| `private/protected const` | PHP 7.1+ | ✅ 5 处改为 public const |
| `getallheaders()` | nginx/php-fpm 不存在 | ✅ `$_SERVER` 回退 |
| match/nullsafe/联合类型/mixed | PHP 8.0+ 专有 | ✅ 全部未使用 |
| enum/readonly/never | PHP 8.1+ 专有 | ✅ 全部未使用 |

完整审计报告：[SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)

### 4. 日志目录文件说明

**正常情况下 logs 目录有多少个文件？**

刚安装时（零攻击）约 **11 个文件 + 1 个子目录**：

| 文件/目录 | 必选 | 说明 |
|----------|------|------|
| `block_YYYY-MM-DD.log` | ✅ | 每日拦截日志，每天生成一个新文件 |
| `ban.txt` | ✅ | 封禁 IP 列表，初始为空 |
| `cc_counter.txt` | ✅ | 速率限制计数器 |
| `active_blocks.json` | ✅ | 活跃拦截记录缓存 |
| `attack_stats.json` | ✅ | 攻击统计数据（控制台大盘） |
| `security.log` | ✅ | 安全事件日志 |
| `auto_key.php` | ✅ | 控制台暗门密钥（首次访问自动生成） |
| `learned_patterns.json` | ✅ | 自学习攻击规则（初始为空） |
| `normal_patterns.json` | ✅ | 正常请求基线（初始为空） |
| `admin_ips.txt` | ✅ | 管理员白名单（初始为空） |
| `test_mode_ban.log` | ⭕ | 测试模式下才生成 |
| `bot_tracker/` | ✅ | 机器人跟踪数据目录 |

> 💡 验证命令：`ls -la logs/ | wc -l`（含 `.` 和 `..` 会多 2 行，实际文件数减 2）

### 5. 部署检查清单

部署后请逐项确认：

- [ ] `php -v` 显示 PHP 7.4+（推荐 7.4 或 8.x）
- [ ] `logs/` 目录可写（`is_writable('logs/')` 返回 true）
- [ ] `data/` 目录可写
- [ ] 访问首页返回 200，不是 403
- [ ] `tail -f logs/block_*.log` 能看到拦截记录
- [ ] 模拟攻击 `/?id=1' OR 1=1--` 能触发 403
- [ ] `logs/ban.txt` 能记录封禁 IP（默认模式）
- [ ] 配置 `WAF_ADMIN_IPS` 加入办公网段
- [ ] 测试模式 `WAF_TEST_MODE=true` 仅在测试期间开启

---

## ❓ 常见问题 FAQ

### 1. 图片不显示 / 部分页面 500 错误

**现象**：安装 WAF 后，网站图片加载不出来，或者部分页面返回 500 错误。

**根因**：旧版本 OutputFilter 会对所有输出（包括图片、CSS、JS 等静态资源）做 PHP 错误信息匹配，二进制数据中碰巧命中模式就被替换成 500 页面。

**解决**：v4.1.0+ 已修复，OutputFilter 会自动跳过静态资源（图片/CSS/JS/字体等），只对 HTML 页面生效。

- 如仍有问题，可临时关闭错误掩码功能：
```php
// config.php 加入
define('WAF_ERROR_MASKING', false);
```

### 2. 如何确认 WAF 正在正常工作？

**方法一：模拟攻击测试**
```bash
# 访问带有 SQL 注入特征的 URL
curl -I "https://你的域名/?id=1' OR 1=1--"
# 正常应该返回 403 Forbidden
```

**方法二：查看拦截日志**
```bash
# 查看今日拦截日志
tail -f logs/block_$(date +%Y-%m-%d).log

# 查看封禁 IP 列表
cat logs/ban.txt
```

**方法三：查看响应头**
```bash
curl -I "https://你的域名/"
# 正常响应中会包含 X-ShieldWAF 相关响应头
```

**方法四：登录控制台**
访问 `/waf-dashboard` 进入控制台，在「安全总览」页面可以看到实时攻击数据和日志流。

### 3. 自学习系统怎么用？机器人怎么学习？

盾甲 WAF 的自学习系统是**全自动运行**的，无需手动配置即可开始学习。

**学习原理（三层闭环）**：
```
攻击拦截 → 高置信度样本 → 沙箱验证 → AutoLearn 训练 → 反哺规则
```

**学习什么？**
- 📊 **攻击频率统计**：自动记录攻击载荷、攻击类型、来源 IP
- 🎯 **特征提取**：同一攻击载荷命中 ≥3 次自动提取特征生成规则
- ⚖️ **权重自适应**：根据攻击数据自动调整各防御模块权重
- 🔬 **沙箱联动**：高置信度恶意样本自动投喂学习系统
- ✅ **正常基线**：自动学习正常请求模式，降低误报率

**如何查看学习效果？**
1. 进入控制台 → 「🧠 自学习系统」页面
2. 查看「学习趋势图」「已学习规则」「权重自适应详情」
3. 可以提交误报/漏报反馈，系统会自动调整权重

**手动干预方式**：
- **冻结基线**：学习到一定程度后可冻结，防止新异常影响现有规则
- **重置学习**：清空所有学习数据，从头开始
- **删除规则**：手动删除误学习的规则
- **反馈调整**：标记误报/漏报，系统自动调整对应类型权重

### 4. 封禁 IP 没有记录 / 看不到 ban.txt？

**常见原因**：
1. `logs/` 目录不可写 → 参考「部署必读 → 首页打开直接 403」章节
2. 开启了测试模式 `WAF_TEST_MODE=true` → 只拦截不封禁，记录在 `test_mode_ban.log`
3. 管理员白名单中的 IP → 不会被封禁
4. 还没有触发封禁阈值（默认 60 秒内 60 次请求才触发 CC 封禁）

**验证方法**：
```bash
# 检查 logs 目录权限
ls -la logs/

# 检查测试模式是否开启
grep WAF_TEST_MODE config.php

# 检查管理员白名单
grep WAF_ADMIN_IPS config.php
```

### 5. 首页打开直接 403？

参考上方「部署必读 → 首页打开直接 403」章节。

---

## ⚙️ 配置

### 环境变量 / .env 配置

```env
# 基础配置
WAF_ENABLED=true
WAF_LOG_PATH=/var/log/shield-waf/

# 管理员 IP 白名单（逗号分隔，支持 CIDR 网段）
WAF_ADMIN_IPS=127.0.0.1,192.168.1.100,10.0.0.0/8

# 测试模式（只拦截不封IP，生产环境务必 false）
WAF_TEST_MODE=false

# 速率限制
WAF_CC_ENABLED=true
WAF_CC_LIMIT=60
WAF_CC_WINDOW=60

# 沙箱配置
WAF_SANDBOX_ENABLED=true
WAF_SANDBOX_MALWARE_THRESHOLD=50
WAF_SANDBOX_AUTO_QUARANTINE=true

# 上传防护
WAF_UPLOAD_DETECTION=true
WAF_UPLOAD_BLOCK_THRESHOLD=60

# 双重密码
WAF_DUAL_PASSWORD_ENABLED=true
WAF_DUAL_PASSWORD_PRIMARY=argon2id
WAF_DUAL_PASSWORD_SECONDARY=bcrypt

# 调试模式（生产环境务必关闭）
WAF_DEBUG=false
WAF_DB_DEBUG=false
```

> 完整配置项见 [config.php](config.php)

---

## 📊 性能与效果

### 检测能力

| 指标 | 盾甲 WAF | 传统 WAF |
|------|---------|----------|
| 混淆攻击检测率 | **100%**（极限测试 71/71） | ~20% |
| 正常请求误报率 | **0%**（误报测试 10/10 通过） | ~2-5% |
| 编码绕过覆盖 | 14 层 / 699 字 | 3-5 层 |
| 语义分析能力 | 11 个深度解析器 + 内容路由 | 无 / 极弱 |
| 评分架构 | 规则 + 语义双路融合 | 单一规则匹配 |
| SQL 注入检测 | SQL AST + 规则 + 双证据 | 正则匹配 |

### 性能开销

| 场景 | 单请求开销 |
|------|-----------|
| 正常请求 | **< 5ms** |
| 含编码混淆 | **< 15ms** |
| 上传文件扫描 | 取决于文件大小 |
| 内存占用 | **< 4MB** |

---

## 🔒 安全审计

代码已通过 **97 项**全面安全审计：

| 等级 | 数量 | 状态 |
|------|------|------|
| 🔴 Critical | 12 | ✅ 全部修复 |
| 🟠 High | 27 | ✅ 已修复 24+（v4.1 新增 9 项修复） |
| 🟡 Medium | 35 | 🔄 进行中 |
| 🟢 Low | 23 | 📋 计划中 |

**v4.1 新增修复**（深度代码审计）：
- 首页403误拦截根因（CachePoisoning 字符类正则误匹配 localhost）
- `getallheaders()` 无限递归 bug
- 10处箭头函数 `fn()` (PHP 7.4+) 兼容性
- `CrlfInjection` PCRE2 非法转义编译失败
- `BotFingerprint` 数组值强转警告
- `Scorer.observe` 阈值失效（与block相等被短路）
- `FalsePositiveGuard` 短载荷攻击漏检
- `WordPressIntegration.ABSPATH` 路径错误
- `HoneypotLinks` 误判（要求值长度≥8且含2+敏感词）
- 日志目录不可写时403页面输出但日志丢失

审计报告：[SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)

### 关键安全特性

- ✅ 所有数据库操作使用参数化查询
- ✅ 动态表名/列名严格标识符校验
- ✅ 双重哈希防时序攻击
- ✅ 管理后台三重认证（时间戳×2 + IP绑定）
- ✅ CSRF token 全 API 覆盖
- ✅ 错误信息脱敏（生产环境返回通用错误）
- ✅ .env 加载白名单机制
- ✅ 配置持久化使用 JSON（无 unserialize）
- ✅ XML 解析禁用外部实体（防 XXE）
- ✅ 速率限制原子操作（防竞态绕过）
- ✅ 日志三级兜底（WAF_LOG_PATH → error_log → /tmp）
- ✅ 测试模式只拦截不封IP（不影响业务）
- ✅ 管理员白名单支持 CIDR 网段

---

## 📁 项目结构

```
shield-waf-master/
├── shield-waf.php              # 主入口文件
├── config.php                  # 配置文件（含 WAF_ADMIN_IPS / WAF_TEST_MODE）
├── README.md                   # 项目文档
├── CHANGELOG.md                # 变更记录
├── SECURITY.md                 # 安全策略
├── SECURITY_AUDIT_REPORT.md    # 安全审计报告
├── TEST_REPORT.md              # 测试报告
├── CONTRIBUTING.md             # 贡献指南
├── data/                       # 运行时数据（自动创建）
│   ├── modules_config.json     # 模块开关配置
│   ├── settings.json           # 系统设置
│   ├── whitelist_url.json      # URL 白名单
│   └── sandbox_tasks.json      # 扫描任务
├── logs/                       # 日志目录（自动创建，需可写）
│   ├── block_YYYY-MM-DD.log    # 每日拦截日志（每天一个文件）
│   ├── ban.txt                 # 封禁 IP 列表（持久化）
│   ├── cc_counter.txt          # 速率限制计数器
│   ├── active_blocks.json      # 当前活跃拦截记录
│   ├── attack_stats.json       # 攻击统计数据（控制台大盘用）
│   ├── security.log            # 安全事件日志（登录、配置变更等）
│   ├── auto_key.php            # 控制台暗门密钥（首次安装自动生成）
│   ├── learned_patterns.json   # 自学习系统提取的攻击规则
│   ├── normal_patterns.json    # 自学习系统的正常请求基线
│   ├── test_mode_ban.log       # 测试模式下的封禁记录（不实际封禁）
│   ├── admin_ips.txt           # 控制台动态添加的管理员白名单
│   └── bot_tracker/            # 机器人跟踪数据目录
├── src/
│   ├── Admin/                  # 管理后台
│   │   ├── Dashboard.php       # 控制台主页面
│   │   ├── DashboardApi.php    # 控制台 API
│   │   ├── SandboxApi.php      # 沙箱 API
│   │   ├── PasswordApi.php     # 密码服务 API
│   │   ├── ScannerApi.php      # 扫描器 API
│   │   ├── DashboardBot.php    # 机器人管理
│   │   ├── IpManager.php       # IP 管理（封禁/白名单）
│   │   ├── Waf403Template.php  # 403 拦截页面模板
│   │   ├── DarkGate.php        # 暗门认证
│   │   └── Sandbox.php         # 沙箱核心
│   ├── Core/                   # 核心模块
│   │   ├── Normalizer.php      # 请求归一化
│   │   ├── Scorer.php          # 评分引擎
│   │   ├── Detector.php        # 检测引擎
│   │   └── Request.php         # 请求封装
│   ├── Defense/                # 防御模块（33 个）
│   │   ├── SqlInjection.php
│   │   ├── XssFilter.php
│   │   ├── RateLimit.php
│   │   ├── Upload.php
│   │   ├── CachePoisoning.php  # 缓存投毒防护
│   │   ├── CrlfInjection.php   # CRLF 注入防护
│   │   ├── CorsPolicy.php      # CORS 策略
│   │   └── ... (26+ 模块)
│   ├── Semantic/               # 语义分析（11 大解析器）
│   ├── Bot/                    # 机器人防护
│   ├── Password/               # 密码加密
│   │   ├── DualPassword.php    # 双重加密核心
│   │   ├── DbAdapter.php       # 数据库适配器
│   │   ├── PasswordService.php # 密码服务
│   │   └── WordPressIntegration.php
│   ├── Support/                # 工具函数
│   │   ├── Functions.php       # 通用工具函数 + PHP 版本兼容 polyfill
│   │   └── IpGeo.php           # IP 地理定位（50+ 国家 CIDR + 经纬度）
│   └── Learning/               # 自学习
├── test_*.php                  # 测试用例（首页403/FP压力/白名单等）
```

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！详见 [CONTRIBUTING.md](CONTRIBUTING.md)

### 开发环境

```bash
# 克隆项目
git clone https://github.com/anye1991/shield-waf-master.git
cd shield-waf-master

# 运行核心测试套件
php test_password.php            # 密码模块基础测试
php test_password_full.php       # 双重密码加密全量测试（68用例）
php test_homepage_compat.php     # 首页403回归测试（17用例）
php test_fp_stress.php           # 误报压力测试（37用例）
php test_admin_whitelist.php     # 管理员白名单+测试模式（11用例）
php test_parser_scores.php       # 攻击载荷评分详情
php test_full_decode.php         # 14层解码测试
php test_obfuscation.php         # 混淆检测测试（34用例）
php test_learning.php            # 自学习系统测试
php test_sandbox_learn_coupling.php  # 沙箱学习联动测试（23用例）
php test_e2e.php                 # 端到端 E2E 测试
php test_extreme.php             # 极限测试

# 代码语法检查
find src -name "*.php" -exec php -l {} \; | grep -v "No syntax errors"
```

---

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

---

## 💪 版本历程

| 版本 | 核心特性 |
|------|---------|
| **v5.0.0** 🧠 | 11 解析器语义引擎 · 内容类型路由 · 双证据融合架构 · 签名保底机制 · 14层归一化全局统一接入 · 9项安全审计修复 · 71/71 极限测试通过 · 0% 误报率 |
| **v4.2.0** 🌍 | 3D 旋转全球攻击地图 · 真实 IP 地理定位 · 沙箱异步扫描 · 切割备份 · 运行心跳 · 控制台全量按钮修复 · 5 秒实时数据刷新 |
| **v4.1.1** 🔧 | 深度PHP 7.4兼容性审计 · 105文件全扫描 · 17处兼容性修复 · 0处PHP 8.0+专有语法 |
| **v4.1.0** 🔥 | 深度代码审计修复 · 首页403根因解决 · PHP 7.0 兼容性 · 管理员IP白名单 · 测试模式 · 日志三级兜底 |
| v4.0.0 | 可视化控制台 12 页面 · 双重密码加密 · 多数据库适配 · 全量视觉动效升级 |
| v3.1.0 | 统一归一化引擎 · 沙箱/上传双引擎重优化 · 学习闭环 · 全配置 .env 化 |
| v3.0.0 | 8 个高级防护模块 · 语义分析引擎 · 机器人防护 · 沙箱系统 |
| v2.0.0 | 10 层编码归一化 · 评分系统 · 自学习 · WordPress 深度集成 |
| v1.0.0 | 基础 SQL/XSS 防护 · IP 封禁 · 速率限制 |

> 完整变更记录见 [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**如果觉得不错，给个 ⭐ Star 支持一下**

Made with ❤️ by 暗夜铭少

</div>
