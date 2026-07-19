# 安全漏洞报告

盾甲 WAF 高度重视安全问题。作为一款 Web 应用防火墙产品，我们对自身代码安全的要求甚至高于对客户的防护标准。

> **署名：暗夜铭少**

---

## 🔐 安全审计状态

代码已通过 **114 项**全面安全审计 + v4.1.1 深度代码审计：

| 等级 | 数量 | 状态 |
|------|------|------|
| 🔴 Critical | 12 | ✅ 全部修复 |
| 🟠 High | 27 | ✅ 已修复 24（89%） |
| 🟡 Medium | 35 | 🔄 已修复 18（51%） |
| 🟢 Low | 23 | 📋 已修复 8（35%） |
| 🔵 Compat | 17 | ✅ 全部修复（v4.1.1 新增） |

完整审计报告：[SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)

---

## 🆕 v4.1.1 深度 PHP 7.4 兼容性审计（2026-07-19）

针对用户反馈"7.4 就报错"的问题，对全项目 105 个 PHP 文件进行了系统性扫描，全面修复 PHP 版本兼容性问题。

### 扫描覆盖项

| 检查项 | PHP 版本要求 | 发现 | 修复 |
|--------|-------------|------|------|
| match 表达式 | PHP 8.0+ | 0 | ✅ 未使用 |
| nullsafe 运算符 `?->` | PHP 8.0+ | 0 | ✅ 未使用 |
| 联合类型 `A\|B` | PHP 8.0+ | 0 | ✅ 未使用 |
| 构造器属性提升 | PHP 8.0+ | 0 | ✅ 未使用 |
| mixed 类型 | PHP 8.0+ | 0 | ✅ 未使用 |
| static 返回类型 | PHP 8.0+ | 0 | ✅ 未使用 |
| throw 表达式 | PHP 8.0+ | 0 | ✅ 未使用 |
| Attributes 注解 | PHP 8.0+ | 0 | ✅ 未使用 |
| enum 枚举 | PHP 8.1+ | 0 | ✅ 未使用 |
| readonly 属性 | PHP 8.1+ | 0 | ✅ 未使用 |
| never 返回类型 | PHP 8.1+ | 0 | ✅ 未使用 |
| First class callable | PHP 8.1+ | 0 | ✅ 未使用 |

### 修复的兼容性问题

| 问题 | 影响版本 | 修复方案 |
|------|---------|---------|
| 类常量 `??` 表达式 | PHP 8.3+ 致命错误 | 改为静态属性 + getter 方法 |
| `array_key_first/last` | PHP 7.3- 不存在 | Functions.php polyfill |
| `str_contains/starts_with/ends_with` | PHP 8.0- 不存在 | Functions.php polyfill |
| 箭头函数 `fn()` | PHP 7.3- 不支持 | 全部改为传统 closure |
| void 返回类型 | PHP 7.0- 不支持 | 全部移除 void 声明 |
| private/protected const | PHP 7.0- 不支持 | 5 处改为 public const |
| `getallheaders()` 不存在 | nginx/php-fpm/CLI | function_exists + $_SERVER 回退 |

### 验证测试

- **105 个 PHP 文件语法检查**：全部通过
- **密码模块测试**：41/41 通过
- **密码模块完整测试**：68/68 通过
- **首页兼容性测试**：17/17 通过
- **FP 压力测试**：37/37 通过，0 误报
- **管理员白名单+测试模式**：11/11 通过

---

## 🆕 v4.1 深度代码审计修复（2026-07-19）

本次深度审计针对用户反馈"首页403 + PHP兼容性问题"展开，定位并修复以下关键问题：

### 首页403误拦截根因链
| 问题 | 文件 | 影响 |
|------|------|------|
| CachePoisoning Host 字符类正则误匹配 localhost | [CachePoisoning.php](src/Defense/CachePoisoning.php) | 首页直接403 |
| `getAllHeadersCompat()` 无限递归 | [CachePoisoning.php](src/Defense/CachePoisoning.php) | Apache环境stack overflow |
| `$_SERVER` 当 headers 传给 BotManager | [shield-waf.php](shield-waf.php) | 环境变量污染Bot指纹 |
| CRLF `\u000d\u000a` PCRE2 非法转义 | [CrlfInjection.php](src/Defense/CrlfInjection.php) | 每次请求编译失败 |
| `BotFingerprint` 数组值强转警告 | [BotFingerprint.php](src/Bot/BotFingerprint.php) | 每次请求触发warning |

### PHP 兼容性修复
| 问题 | 修复前 | 修复后 |
|------|--------|--------|
| 箭头函数 `fn()` | PHP 7.4+ 专有 | 全部改为传统 closure |
| `str_ends_with` | PHP 8.0+ 专有 | 添加 `function_exists` 守护 |
| `getallheaders()` | nginx/php-fpm 不存在 | 添加 `$_SERVER` 回退 |
| `ABSPATH` 未定义 | 致命错误 | 自动定义指向正确目录 |

### 评分与拦截逻辑修复
| 问题 | 修复前 | 修复后 |
|------|--------|--------|
| `Scorer.observe` 阈值失效 | observe=70 与 block=70 相等 | observe=50（严格递增） |
| `FalsePositiveGuard` 短载荷漏检 | `system(ls)` 误判为正常 | 添加 `containsAttackKeyword` 检查 |
| 短载荷攻击得分偏低 | 69.6分差0.4到block | 新增 `calcClearAttackEvidenceBonus` 保底 |
| `HoneypotLinks` 误判 | 短值含敏感词即触发 | 要求值长度≥8且含2+敏感词 |
| `Detector` 阈值不一致 | 60 与 Scorer 70 不一致 | 统一为 70 |

### 日志与运维修复
| 问题 | 修复前 | 修复后 |
|------|--------|--------|
| logs 目录不可写时日志丢失 | `@file_put_contents` 静默失败 | 三级兜底：WAF_LOG_PATH → error_log → /tmp |
| `waf_smart_ban` 累进封禁影响测试 | 测试时IP被封无法继续 | 测试模式跳过实际封禁 |
| 管理员白名单仅支持文件 | 必须登录控制台添加 | config.php 直配 + CIDR 网段支持 |

---

## 🛡️ 已验证的关键安全特性

- ✅ **SQL 注入防护**：全参数化查询 + 动态标识符校验
- ✅ **XSS 防护**：输出过滤 + 错误掩码 + 敏感信息脱敏
- ✅ **CSRF 防护**：全 API 接口 CSRF Token 验证
- ✅ **路径遍历防护**：沙箱文件操作路径白名单 + realpath 验证
- ✅ **反序列化漏洞**：配置持久化全面使用 JSON，无 `unserialize()`
- ✅ **XXE 防护**：XML 解析禁用外部实体
- ✅ **认证安全**：管理后台三重认证（时间戳×2 + IP 绑定）
- ✅ **密码安全**：双重哈希 + 防时序攻击 + 长密码安全
- ✅ **错误信息泄露**：生产环境返回通用错误，详细信息写入日志
- ✅ **速率限制**：原子操作防竞态条件绕过
- ✅ **.env 安全**：白名单机制，禁止覆盖敏感环境变量
- ✅ **文件权限**：配置文件 0600，数据目录 0700
- ✅ **日志兜底**：三级降级（WAF_LOG_PATH → error_log → /tmp）
- ✅ **测试模式**：只拦截不封IP，方便部署期间调试
- ✅ **管理员白名单**：config.php 直配 IP/CIDR，跳过速率限制与封禁

---

## 📮 报告渠道

如果你发现了安全漏洞，请通过以下方式报告：

- **邮箱**：`634769642@qq.com`
- **标题格式**：`[Security] + 漏洞简述`
- **建议提供**：
  - 漏洞描述和影响范围
  - 复现步骤（POC 更佳）
  - 受影响的版本
  - 可能的修复建议

---

## ⏱️ 响应承诺

| 阶段 | 时间承诺 |
|------|---------|
| 确认收到 | **48 小时**内 |
| 漏洞评估 | **7 个工作日**内 |
| 修复开发 | 根据严重程度而定 |
| 公开披露 | 修复发布后 7 天 |

---

## 🙏 致谢

我们会在安全公告中公开致谢报告者（如本人同意）。

---

## ⚠️ 不适用范围

- ❌ 请勿通过公开 Issues 报告安全漏洞
- ❌ 社会工程学攻击不在范围内
- ❌ 理论上存在但实际无法利用的问题

---

> **暗夜铭少** — 以做安全产品的态度做安全产品
