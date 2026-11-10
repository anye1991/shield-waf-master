# 编码规范（Coding Standards）

> 对应 OpenSSF 准则 `coding_standards` / `coding_standards_enforced`。本项目主语言为 **PHP（≥8.1）**，无外部 PHP 依赖（零 Composer 包），因此规范聚焦语言核心与安全约定。

## 1. 基础规范

以 **PSR-12**（扩展编码风格）为基础，叠加本项目约定：

- 4 空格缩进，不用 Tab；UTF-8（无 BOM）。
- 文件以 `<?php` 开头，随后紧跟文件级 DocBlock（项目名/作者/版权/许可说明，见 §4）。
- 类名 `StudlyCaps`；方法 `camelCase`；常量 `UPPER_SNAKE_CASE`（如 `SHIELD_WAF_VERSION`）。
- 控制结构关键字后留一个空格；`{` 与语句同行（K&R 风格）。

## 2. 项目安全约定（硬性）

1. **禁止**使用：`eval()`、`create_function()`、`preg_replace('/…/e')`、`assert()`（生产路径）、反引号执行符。
2. shell 调用一律走 `escapeshellarg()` / `escapeshellcmd()`；禁止字符串拼接命令。
3. 文件路径拼接必须先 `basename()` / 白名单校验，防目录穿越。
4. 输出转义：HTML 上下文一律 `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`；JSON 上下文走 `json_encode(..., JSON_UNESCAPED_UNICODE|JSON_HEX_TAG|JSON_HEX_AMP)`。
5. 输入校验一律**白名单**优先（枚举/正则全匹配），黑名单仅作补充。
6. 请求路径**禁止**：网络调用（`curl_*`、`file_get_contents(http…)`）、数据库长事务、无界循环/递归——时延必须有静态上界。
7. 错误与日志不得回显敏感值（密钥、路径细节、用户数据）到响应页。
8. 随机性一律 `random_bytes()` / `random_int()`，禁止 `rand()` / `mt_rand()` / `uniqid()`。

## 3. 强制执行（coding_standards_enforced）

- **语法检查**：CI 对所有入库 `*.php` 执行 `php -l`（任何 warning/error 即失败）。
- **静态安全检查**：CI 执行 `php tools/static_check.php`——基于规则匹配的静态分析，覆盖 §2 中的禁用项与危险模式（`eval`、`exec`、拼接命令、`rand()` 等），命中即失败。
- **风格例外**：确需偏离处必须在代码现场以注释说明理由（`// CS-EXCEPTION: …`），保持稀有且可复核。

## 4. 文件头声明（SPDX）

每个**明文**源文件顶部统一加入：

```php
/**
 * YSL语枢-盾甲WAF
 * Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
 * SPDX-License-Identifier: MIT
 */
```

> 加密分发的 `core/`、`ai/` 文件无法携带明文头，其版权与许可由根 `LICENSE` 与 `NOTICE` 统一声明（详见 `NOTICE`）。

## 5. 文档同步

改代码契约（配置键、JSON 字段、状态码）时**必须**同步：`README.md`、`CHANGELOG.md`、`ARCHITECTURE.md` 相关段落。已知文档不一致按缺陷跟踪修复（`documentation_current`）。
