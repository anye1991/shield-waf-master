# 变更记录

所有重要变更将记录在此文件中。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> 署名：暗夜铭少

---

## [v4.1.0] - 2026-07-19

### 🆕 新增功能

- **管理员 IP 白名单（`WAF_ADMIN_IPS`）**：在 `config.php` 直接配置 IP 或 CIDR 网段，无需登录控制台
  - 支持 CIDR 网段：`10.0.0.0/8` 命中 `10.1.2.3`
  - 可通过 `.env` 配置：`WAF_ADMIN_IPS=127.0.0.1,192.168.1.100,10.0.0.0/8`
  - 白名单 IP 跳过速率限制、封禁检查、累进封禁

- **测试模式（`WAF_TEST_MODE`）**：一键开启「只拦截不封IP」
  - `waf_smart_ban` / `waf_ban` 不执行实际封禁，只记录到 `logs/test_mode_ban.log`
  - `waf_is_banned` 跳过封禁检查（避免历史 ban 影响测试）
  - 403 页面显示拦截原因（方便调试）
  - 响应头 `X-ShieldWAF-TestMode: 1` 标识

- **日志三级兜底机制**：解决 logs 目录不可写时日志丢失问题
  - 主路径：`WAF_LOG_PATH/block_*.log`（自动 mkdir 0775）
  - 兜底1：PHP `error_log()`（写入 nginx/php-fpm error log）
  - 兜底2：`/tmp/shield_waf_block.log`（Web 用户一般可写）

- **部署诊断**：`shield-waf.php` 启动时检测 logs 目录可写性，不可写时通过 `error_log` 输出修复命令提示

### 🐛 修复（首页403 + PHP兼容性深度审计）

#### 首页403误拦截根因链

- **CachePoisoning Host 字符类正则误匹配 localhost**：`/[\r\n%0d%0a]/i` 是字符类，会把 `%`、`0`、`d`、`a` 当单独字符匹配，导致 "localhost" 含 0/d/a 被命中 → 改为字面量匹配 `/(?:\r\n|\n|\r|%0d%0a|%0a%0d|%0d|%0a)/i`
- **`getAllHeadersCompat()` 无限递归**：`self::getAllHeadersCompat()` 自调用 → 改为 `getallheaders()`
- **`$_SERVER` 当 headers 传给 BotManager**：环境变量(PATH/HTTP_PROXY等)被当成 header 参与 Bot 指纹分析 → 只提取 `HTTP_` 开头的请求头
- **CRLF `\u000d\u000a` PCRE2 非法转义**：每次请求编译失败 → 改为字面量 `\\u000d\\u000a`
- **`BotFingerprint` 数组值强转(string)警告**：`$_SERVER['argv']` 是数组 → 跳过非标量值

#### PHP 兼容性修复

- **10 处箭头函数 `fn()`**（PHP 7.4+ 专有）全部改为传统 closure
- **`str_ends_with`**（PHP 8.0+ 专有）添加 `function_exists` 守护
- **`getallheaders()`**（nginx/php-fpm/CLI 不存在）添加 `$_SERVER` 回退
- **`ABSPATH` 未定义**致命错误：自动定义指向正确目录

#### 评分与拦截逻辑修复

- **`Scorer.observe` 阈值失效**：observe=70 与 block=70 相等被短路 → 改为 50（严格递增）
- **`FalsePositiveGuard` 短载荷漏检**：`system(ls)` 误判为正常请求 → 添加 `containsAttackKeyword` 检查解析器布尔标志位
- **短载荷攻击得分偏低**：69.6分差0.4到block → 新增 `calcClearAttackEvidenceBonus` 保底（在FP调整后应用）
- **`HoneypotLinks` 误判**：短值含敏感词即触发 → 要求值长度≥8且含2+敏感词
- **`Detector` 阈值不一致**：60 与 Scorer 70 不一致 → 统一为 70
- **`WordPressIntegration.ABSPATH` 路径错误**：`dirname(__FILE__)` → `dirname(__DIR__, 2)`

#### 阈值统一

- `Scorer` block = 70
- `Detector` isAttack = 70
- `shield-waf.php` $blockThreshold = 70
- `config.php` `WAF_SCORE_BLOCK` = 70

### 📚 文档

- **README.md**：v4.0.0 → v4.1.0，新增「部署必读：常见陷阱与解决方案」章节
  - 首页403排查方法
  - 测试模式使用指南
  - 管理员白名单配置
  - PHP 版本兼容性表
  - 部署检查清单
- **SECURITY.md**：新增 v4.1 深度代码审计修复章节
- **TEST_REPORT.md**：新增 v4.1 增量测试结果（35/35 通过）
- **CHANGELOG.md**：本次新增

### 🧪 测试

新增 3 个测试套件：

- `test_homepage_compat.php`：首页403回归测试（17 用例）
- `test_admin_whitelist.php`：管理员白名单+测试模式（11 用例）
- `test_parser_scores.php`：攻击载荷评分详情（7 用例）

---

## [v4.0.0] - 2026-07-18

### 🆕 新增功能

- **可视化控制台**：12 个功能页面，33 个防御模块，大厂级交互体验
- **双重密码加密**：业界首创「主层 + 副层」双重哈希
- **多数据库适配**：MySQL / PostgreSQL / SQLite / MSSQL
- **全量视觉动效升级**

### 🐛 修复

- HTML 实体 SQL 检测偏弱
- 明文攻击得分偏低
- 全量解码测试通过率 94.1% → 100%
- E2E 测试通过率 83.3% → 88.9%

---

## [v3.1.0] - 2026-07-15

### 🆕 新增功能

- 统一归一化引擎
- 沙箱/上传双引擎重优化
- 学习闭环
- 全配置 .env 化

---

## [v3.0.0] - 2026-07-10

### 🆕 新增功能

- 8 个高级防护模块
- 语义分析引擎
- 机器人防护
- 沙箱系统

---

## [v2.0.0] - 2026-07-05

### 🆕 新增功能

- 10 层编码归一化
- 评分系统
- 自学习
- WordPress 深度集成

---

## [v1.0.0] - 2026-07-01

### 🆕 初始版本

- 基础 SQL/XSS 防护
- IP 封禁
- 速率限制
