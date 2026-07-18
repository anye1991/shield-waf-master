# 盾甲 WAF — 全面代码安全审计报告

**审计日期**: 2026-07-18  
**审计范围**: 全项目 97 个 PHP 文件，约 30,000+ 行代码  
**审计维度**: 安全漏洞、代码质量、性能瓶颈、架构设计  

---

## 风险等级说明

| 等级 | 标识 | 说明 | 修复时限 |
|------|------|------|---------|
| 严重 | 🔴 Critical | 可直接导致系统被入侵、数据泄露 | 立即修复 |
| 高危 | 🟠 High | 存在明显安全漏洞，需紧急处理 | 24 小时内 |
| 中危 | 🟡 Medium | 存在安全隐患或设计缺陷 | 1 周内 |
| 低危 | 🟢 Low | 代码质量/最佳实践问题 | 下版本修复 |

---

## 一、问题总览

### 按严重程度统计

| 等级 | 数量 |
|------|------|
| 🔴 Critical | **12** |
| 🟠 High | **27** |
| 🟡 Medium | **35** |
| 🟢 Low | **23** |
| **总计** | **97** |

### 按模块分布

| 模块 | Critical | High | Medium | Low | 合计 |
|------|----------|------|--------|-----|------|
| 入口与配置 | 1 | 5 | 6 | 6 | 18 |
| 管理后台 | 5 | 8 | 7 | 4 | 24 |
| 核心引擎 + 防御 | 2 | 8 | 12 | 6 | 28 |
| 密码服务 | 3 | 5 | 8 | 6 | 22 |
| 代码质量/性能 | 1 | 1 | 2 | 1 | 5 |

---

## 二、🔴 Critical 严重漏洞（12 个）

### 1. 后台暗门认证 — 任意 Cookie 绕过

| 项 | 详情 |
|---|---|
| **文件** | [shield-waf.php](file:///workspace/shield-waf-master/shield-waf.php#L373-L380) |
| **行号** | 373-380 |
| **严重** | 🔴 Critical |

**问题描述**:  
通过检查 Cookie 名称是否以 `wordpress_logged_in_` 前缀来判断登录状态，**完全不验证 Cookie 值的有效性**。攻击者只需在浏览器设置一个该前缀的任意 Cookie，即可直接绕过 WAF 后台暗门保护。

**修复建议**:  
```php
// 错误：仅通过 Cookie 名判断
if (strpos($name, 'wordpress_logged_in_') === 0) { $logged_in = true; }

// 正确：使用 WordPress 官方 API 或验证签名
if (function_exists('is_user_logged_in') && is_user_logged_in()) { $logged_in = true; }
```

---

### 2-3. SandboxApi.php 路径遍历（文件读取 + 文件操作）

| 项 | 详情 |
|---|---|
| **文件** | [SandboxApi.php](file:///workspace/shield-waf-master/src/Admin/SandboxApi.php) |
| **行号** | 106-115, 134-149, 198-212 |
| **严重** | 🔴 Critical |

**问题描述**:  
`path` 参数直接来自用户输入，仅做 `is_file()` 检查，未限制路径范围。攻击者可通过 `../../etc/passwd` 读取任意文件，或隔离/切割系统关键文件。

**修复建议**:  
```php
$realPath = realpath($_POST['path']);
$allowedBase = realpath(WAF_SANDBOX_MONITOR_DIR);
if (strpos($realPath, $allowedBase) !== 0) {
    die('非法路径');
}
```

---

### 4. WordPress 集成：异常时返回明文密码

| 项 | 详情 |
|---|---|
| **文件** | [WordPressIntegration.php](file:///workspace/shield-waf-master/src/Password/WordPressIntegration.php#L57-L59) |
| **行号** | 57-59 |
| **严重** | 🔴 Critical |

**问题描述**:  
`shield_wp_hash_password()` 在异常时直接返回明文密码 `$password`，导致数据库中存储明文密码。

**修复建议**:  
```php
// 错误：返回明文
return $password;

// 正确：降级到 WordPress 默认哈希
if (function_exists('wp_hash_password')) {
    return wp_hash_password($password);
}
// 或抛出异常
throw new Exception('Password hashing failed');
```

---

### 5. WordPress 集成：密码升级后反而降级为弱哈希

| 项 | 详情 |
|---|---|
| **文件** | [WordPressIntegration.php](file:///workspace/shield-waf-master/src/Password/WordPressIntegration.php#L87-L92) |
| **行号** | 87-92 |
| **严重** | 🔴 Critical |

**问题描述**:  
自动升级逻辑中，调用 `wp_set_password()` 前移除了自身的 `wp_hash_password` 过滤器，导致 WordPress 使用默认的 phpass（256 次 MD5 迭代）存储密码，而不是双重哈希。

**修复建议**: 直接使用 `$wpdb->update()` 手动更新 user_pass 字段，不移除 filter。

---

### 6. WordPress 集成：信任前置校验结果，可绕过验证

| 项 | 详情 |
|---|---|
| **文件** | [WordPressIntegration.php](file:///workspace/shield-waf-master/src/Password/WordPressIntegration.php#L74-L77) |
| **行号** | 74-77 |
| **严重** | 🔴 Critical |

**问题描述**:  
如果 `$check` 已为 `true` 且哈希是 `dual$v1$` 格式，直接返回 true 跳过自身验证。恶意插件可通过 filter 注入 `true` 绕过密码验证。

**修复建议**: 始终运行自己的验证逻辑，不信任 `$check` 参数。

---

### 7-8. 配置项反序列化漏洞（多处，可 RCE）

| 项 | 详情 |
|---|---|
| **文件** | [Upload.php](file:///workspace/shield-waf-master/src/Defense/Upload.php#L35)、[MalwareScanner.php](file:///workspace/shield-waf-master/src/Defense/MalwareScanner.php#L61)、[Sandbox.php](file:///workspace/shield-waf-master/src/Admin/Sandbox.php#L171) |
| **严重** | 🔴 Critical |

**问题描述**:  
使用 `unserialize()` 解析配置常量。若配置值可被攻击者控制，将导致 PHP 对象注入，可能远程代码执行。

**修复建议**: 全部替换为 `json_decode()`。

---

### 9. XML 规范化中启用 LIBXML_NOENT — XXE 漏洞

| 项 | 详情 |
|---|---|
| **文件** | [Normalizer.php](file:///workspace/shield-waf-master/src/Core/Normalizer.php#L451) |
| **行号** | 451 |
| **严重** | 🔴 Critical |

**问题描述**:  
`loadXML($rawXml, LIBXML_NOENT | LIBXML_NONET)` 启用了实体替换，虽然禁止网络访问，但仍可通过 `file://` 协议读取本地文件。

**修复建议**: 移除 `LIBXML_NOENT` 标志。

---

### 10. DashboardBot.php 完全未授权访问

| 项 | 详情 |
|---|---|
| **文件** | [DashboardBot.php](file:///workspace/shield-waf-master/src/Admin/DashboardBot.php) |
| **行号** | 1-28 |
| **严重** | 🔴 Critical |

**问题描述**:  
机器人仪表盘无任何身份认证，任何人可直接访问查看所有检测数据。

**修复建议**: 添加与其他管理页面一致的双重认证检查。

---

### 11. DashboardApi.php 完全缺失 CSRF 防护

| 项 | 详情 |
|---|---|
| **文件** | [DashboardApi.php](file:///workspace/shield-waf-master/src/Admin/DashboardApi.php) |
| **行号** | 34-70 |
| **严重** | 🔴 Critical |

**问题描述**:  
所有状态变更操作（IP 封禁/解封、白名单增删）均无 CSRF token 校验。

---

### 12. PasswordApi.php 完全缺失 CSRF 防护

| 项 | 详情 |
|---|---|
| **文件** | [PasswordApi.php](file:///workspace/shield-waf-master/src/Admin/PasswordApi.php) |
| **行号** | 86-179 |
| **严重** | 🔴 Critical |

**问题描述**: 同上，密码哈希生成/验证/迁移操作均无 CSRF 防护。

---

## 三、🟠 High 高危漏洞（27 个，部分列举）

### 13. .env 加载器无白名单，可注入任意环境变量
**文件**: [config.php](file:///workspace/shield-waf-master/config.php#L15-L32)  
**描述**: `.env` 所有键值对直接注入 `$_ENV`/`$_SERVER`，无白名单。攻击者若能控制 `.env` 可覆盖 `PATH`、`LD_PRELOAD` 等关键变量。

### 14. 默认密钥/密码为弱口令
**文件**: [config.php](file:///workspace/shield-waf-master/config.php#L36-L37)  
**描述**: `WAF_MAGIC_KEY` 和 `WAF_2FA_PASS` 默认值可预测，攻击者可用默认值直接通过暗门认证。

### 15. 仪表盘缺少 IP 绑定验证
**文件**: [Dashboard.php](file:///workspace/shield-waf-master/src/Admin/Dashboard.php#L5-L7)  
**描述**: 仪表盘仅检查 Session 时间戳，未验证 Session 绑定的 IP，会话劫持风险高。

### 16. SSRF 防护可被轻易绕过
**文件**: [SsrfDefender.php](file:///workspace/shield-waf-master/src/Defense/SsrfDefender.php)  
**描述**: 
- 只有白名单参数名才检查，其他参数完全跳过
- 不支持十六进制/八进制/整数格式 IP 绕过
- 不做 DNS 重绑定检测
- 未检查 `file://` `gopher://` 等协议

### 17. SQL 注入检测可被轻易绕过
**文件**: [Detector.php](file:///workspace/shield-waf-master/src/Core/Detector.php)  
**描述**: 大部分规则用 `strpos()` 精确匹配，注释注入（`union/**/select`）、多余空格、换行等均可绕过；SQL 注释规范化默认关闭。

### 18. CSRF 防护极其薄弱
**文件**: [CsrfProtect.php](file:///workspace/shield-waf-master/src/Defense/CsrfProtect.php)  
**描述**: 仅依赖 Origin/Referer 检查，无 Token 机制；缺失头即放行。

### 19. 文件上传防护可被绕过
**文件**: [Upload.php](file:///workspace/shield-waf-master/src/Defense/Upload.php)  
**描述**: 双扩展名绕过、大文件中间内容不检测、SVG 检测不完善、图像马检测依赖 getimagesize。

### 20. SandboxApi.php 缺失 CSRF 防护
**文件**: [SandboxApi.php](file:///workspace/shield-waf-master/src/Admin/SandboxApi.php)  
**描述**: 沙箱扫描、隔离、恢复、切割等所有写操作均无 CSRF 防护。

### 21. 错误信息泄露（多处）
**文件**: [PasswordApi.php](file:///workspace/shield-waf-master/src/Admin/PasswordApi.php#L191)、[SandboxApi.php](file:///workspace/shield-waf-master/src/Admin/SandboxApi.php#L252)、[DbAdapter.php](file:///workspace/shield-waf-master/src/Password/DbAdapter.php#L92)  
**描述**: 异常消息直接返回给客户端，泄露文件路径、数据库结构等。

### 22. PasswordService 动态表名列名无校验（SQL 注入风险）
**文件**: [PasswordService.php](file:///workspace/shield-waf-master/src/Password/PasswordService.php)  
**描述**: 表名、列名、`$extraData` 键名直接拼 SQL，无白名单验证。

### 23. DualPassword hashPrimary 可能返回 false，无错误处理
**文件**: [DualPassword.php](file:///workspace/shield-waf-master/src/Password/DualPassword.php#L128)  
**描述**: 所有算法不可用时返回 false，`hash()` 不检查，导致无效哈希。

### 24. 双重验证短路求值导致 timing 泄露
**文件**: [DualPassword.php](file:///workspace/shield-waf-master/src/Password/DualPassword.php#L162-L165)  
**描述**: `$primaryOk && $secondaryOk` 短路求值，主层失败时副层不执行，可通过响应时间推断验证进度。

### 25. genBcryptSalt 兜底使用 mt_rand（非 CSPRNG）
**文件**: [DualPassword.php](file:///workspace/shield-waf-master/src/Password/DualPassword.php#L504-L509)  
**描述**: PHP < 7.0 且无 openssl 时用 `mt_rand()` 生成盐，不安全。

### 26. 速率限制竞态条件可被绕过
**文件**: [RateLimit.php](file:///workspace/shield-waf-master/src/Defense/RateLimit.php)  
**描述**: 读取无锁、写入有锁，TOCTOU 竞态导致限速可绕过。

### 27. WAF_LOG_PATH 常量定义顺序错误
**文件**: [config.php](file:///workspace/shield-waf-master/config.php#L51)  
**描述**: 第 51 行就使用 `WAF_LOG_PATH`，但第 125 行才定义，导致 PHP warning。

---

## 四、🟡 Medium 中危问题（35 个，部分列举）

### 28. 魔法密钥通过 GET 参数传递，易泄露
**文件**: [shield-waf.php](file:///workspace/shield-waf-master/shield-waf.php#L386)  
**描述**: `magic` 参数通过 URL 传递，会被记录在访问日志、浏览器历史、Referer 中。

### 29. 日志目录位于 Web 可访问路径下
**文件**: [config.php](file:///workspace/shield-waf-master/config.php#L125)  
**描述**: `WAF_LOG_PATH` 在 Web 根目录下，配置不当可直接下载日志。

### 30. 大量使用 @ 错误抑制符（473 处）
**范围**: 全项目 58 个文件  
**描述**: 掩盖真实错误，增加安全隐患排查难度。

### 31. DbAdapter 异常泄露数据库错误详情
**文件**: [DbAdapter.php](file:///workspace/shield-waf-master/src/Password/DbAdapter.php)  
**描述**: 多处直接抛出数据库错误信息，含表名、SQL 片段。

### 32. DbAdapter 缺少 SSL/TLS 连接选项
**文件**: [DbAdapter.php](file:///workspace/shield-waf-master/src/Password/DbAdapter.php)  
**描述**: 远程数据库连接无加密，传输中可能被窃听。

### 33. 文件包含检测仅一次 URL 解码
**文件**: [FileInclusion.php](file:///workspace/shield-waf-master/src/Defense/FileInclusion.php)  
**描述**: 多层编码可绕过，未整合 Normalizer 的 14 层解码。

### 34. 输出过滤形同虚设
**文件**: [OutputFilter.php](file:///workspace/shield-waf-master/src/Defense/OutputFilter.php)  
**描述**: 仅搜索几个固定错误字符串，不是真正的 XSS 防护；误报率高且易绕过。

### 35. 14 层解码可能导致 DoS
**文件**: [Normalizer.php](file:///workspace/shield-waf-master/src/Core/Normalizer.php)  
**描述**: 深度嵌套编码的 payload 可触发大量 CPU 计算。

### 36. 每次请求加载 30+ 不必要文件
**文件**: [shield-waf.php](file:///workspace/shield-waf-master/shield-waf.php)  
**描述**: 全部手动 `require_once`，无自动加载，静态资源请求也加载所有模块。

### 37. 文本文件存储性能瓶颈严重
**范围**: [IpManager.php](file:///workspace/shield-waf-master/src/Admin/IpManager.php)、[RateLimit.php](file:///workspace/shield-waf-master/src/Defense/RateLimit.php)  
**描述**: IP 封禁、速率限制、学习数据等存在文本文件中，每次请求读写整个文件，并发时文件锁竞争严重。

### 38. 命名风格不一致
**范围**: 全项目  
**描述**: 类名有的用 `Waf` 前缀有的不用；配置常量 `WAF_` 和 `SHIELD_WAF_` 混用。

### 39. 缺少类型声明和空值检查
**范围**: 全项目  
**描述**: 大量函数缺少参数/返回类型，直接访问数组键不检查 isset。

---

## 五、🟢 Low 低危问题（23 个，部分列举）

### 40. PHP 版本兼容性缺失检查
**描述**: 使用 PHP 5.6+ / 7.0+ 特性，入口无版本检查，低版本环境直接白屏。

### 41. 配置常量缺少重复定义保护
**文件**: [config.php](file:///workspace/shield-waf-master/config.php)  
**描述**: 大部分常量直接 `define()`，未检查 `defined()`。

### 42. Dashboard 引用第三方 CDN 资源
**文件**: [Dashboard.php](file:///workspace/shield-waf-master/src/Admin/Dashboard.php#L16)  
**描述**: Chart.js 从 jsdelivr 加载，供应链攻击风险。

### 43. 登录暴力破解防护存在竞态条件
**文件**: [shield-waf.php](file:///workspace/shield-waf-master/shield-waf.php#L340-L358)  
**描述**: 文件计数读时无锁，并发下计数不准。

### 44. 密码升级异常被静默吞噬
**文件**: [PasswordService.php](file:///workspace/shield-waf-master/src/Password/PasswordService.php#L157-L159)  
**描述**: 自动升级异常被捕获且不记录日志，管理员无法发现问题。

### 45. Session 安全配置不完整
**文件**: [SessionSecurity.php](file:///workspace/shield-waf-master/src/Defense/SessionSecurity.php)  
**描述**: 无会话 ID 再生机制，SameSite 默认 Lax。

### 46. 重复代码模式
**范围**: IpManager、Sandbox、MalwareScanner  
**描述**: 读文件→遍历→写回模式重复出现；恶意特征库多处重复定义。

### 47. 无 Composer / 自动加载
**描述**: 所有依赖手写，无法利用成熟安全库。

---

## 六、架构与设计问题

### 6.1 检测逻辑碎片化
- Core/Detector 一套规则
- Defense/ 各模块各自规则
- Semantic/ 语义解析器又一套
- 规则不一致，维护成本高，绕过路径多

### 6.2 误报控制 vs 安全强度矛盾
- 多个模块存在「参数名不在白名单则降低权重」的逻辑
- 为降低误报牺牲了检测强度，给攻击者留下明显绕过路径

### 6.3 存储层设计缺陷
- 全部基于文本文件，无数据库/缓存层
- 无原子操作，竞态条件普遍
- 高并发场景下性能堪忧

### 6.4 双重哈希设计存疑
- 两层使用相同密码，破解难度并非简单叠加
- 计算成本翻倍，用户体验下降
- 建议：高参数 Argon2id 单层 + 可选双重模式

---

## 七、优先修复路线图

### 🔥 立即修复（24 小时内）— Critical
1. 修复后台暗门 Cookie 绕过漏洞
2. 修复 SandboxApi 路径遍历漏洞
3. 修复 WordPress 集成的 3 个 Critical 问题（明文返回、密码降级、验证绕过）
4. 替换所有 `unserialize()` 为 `json_decode()`
5. 移除 `LIBXML_NOENT` 标志
6. 修复 DashboardBot.php 未授权访问
7. 为所有 API 接口添加 CSRF 防护

### ⚡ 高优先级（1 周内）— High
8. .env 加载器添加白名单
9. 移除默认弱密钥，安装时强制生成
10. 仪表盘添加 IP 绑定验证
11. 重构 SSRF 检测，去掉参数名白名单
12. 启用 SQL 注释规范化，增强注入检测
13. 强化 CSRF 防护，增加 Token 机制
14. 修复速率限制竞态条件
15. 修复错误信息泄露

### 🔧 中优先级（1 月内）— Medium
16. 移除不必要的 @ 错误抑制符
17. 实现自动加载机制
18. 引入 SQLite/Redis 替代文本文件存储
19. 统一命名规范
20. 添加类型声明
21. 数据库连接支持 SSL/TLS
22. 增强文件上传检测

### 📋 低优先级（下版本）— Low
23. PHP 版本兼容性检查
24. 配置常量 defined 检查
25. CDN 资源本地化
26. 完善日志记录

---

## 八、审计结论

**总体安全评级**: ⚠️ **中等风险** — 存在多个 Critical 级别漏洞，若被利用可导致系统被完全接管。

**核心问题**:
1. **管理后台安全薄弱**：多个端点未授权、普遍缺少 CSRF、路径遍历
2. **配置安全不足**：默认弱口令、反序列化风险、.env 无白名单
3. **WAF 自身防护有绕过空间**：SQL/SSRF/上传等检测可被绕过
4. **性能与可扩展性堪忧**：文本文件存储、全量文件加载

**建议**: 优先修复 12 个 Critical 漏洞，再逐步处理高危和中危问题。建议配合渗透测试验证上述漏洞的实际可利用性。

---

*报告生成时间: 2026-07-18*  
*审计范围: 全项目 97 个 PHP 文件*
