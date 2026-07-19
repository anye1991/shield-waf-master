# 贡献指南

感谢你关注盾甲 WAF！我们欢迎各种形式的贡献 —— 无论是提交 Bug、建议新功能、完善文档，还是直接贡献代码。

> **署名：暗夜铭少**

---

## 📋 目录

- [如何贡献](#如何贡献)
- [编码标准](#编码标准)
- [开发环境](#开发环境)
- [测试规范](#测试规范)
- [提交 PR 指南](#提交-pr-指南)
- [代码审查](#代码审查)
- [社区行为准则](#社区行为准则)

---

## 如何贡献

### 1. 报告 Bug 🐛

请通过 Issues 提交 Bug 报告，包含以下信息：

- **环境信息**：PHP 版本、数据库类型、Web 服务器、操作系统
- **WAF 版本**：具体版本号或 commit hash
- **复现步骤**：清晰的复现路径
- **预期行为 vs 实际行为**
- **日志/截图**：如有

### 2. 建议新功能 💡

欢迎提交功能建议，请说明：

- 使用场景和解决的问题
- 期望的行为
- 类似产品的参考（如有）

### 3. 贡献代码 🔧

1. Fork 本仓库
2. 创建功能分支：`git checkout -b feature/amazing-feature`
3. 提交更改：`git commit -m 'Add amazing feature'`
4. 推送到分支：`git push origin feature/amazing-feature`
5. 发起 Pull Request

---

## 编码标准

本项目遵循 **PSR-12** 编码风格，并在此基础上有以下约定：

### 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 类名 | PascalCase | `DualPassword` |
| 接口名 | PascalCase + 形容词 | `LoggerInterface` |
| 方法名 | camelCase | `verifyPassword` |
| 属性名 | camelCase | `$hashAlgorithm` |
| 常量 | UPPER_SNAKE_CASE | `WAF_CC_LIMIT` |
| 函数 | snake_case + waf_ 前缀 | `waf_get_real_ip` |
| 配置常量 | UPPER_SNAKE_CASE + WAF_ 前缀 | `WAF_SANDBOX_ENABLED` |

### 文件结构

- 每个文件一个类（除了函数文件）
- 命名空间遵循目录结构：`ShieldWAF\Defense\SqlInjection`
- 类文件名与类名一致

### 安全优先

提交的代码**必须**满足以下安全要求：

- ✅ 所有数据库查询使用参数化绑定
- ✅ 动态表名/列名必须经过标识符校验
- ✅ 用户输入输出必须经过过滤/转义
- ✅ 不使用 `unserialize()` 处理不可信数据
- ✅ 文件操作必须验证路径（防路径遍历）
- ✅ 错误信息不泄露敏感细节
- ✅ 不硬编码密钥、密码等敏感信息
- ✅ 加密/哈希使用标准库函数，不自行实现

### 性能意识

- 避免在循环中执行磁盘 IO
- 大数据处理使用流式读取
- 合理使用静态缓存，注意内存泄漏
- 关键路径避免不必要的对象创建

---

## 开发环境

### 环境要求

- PHP 7.4+（推荐 PHP 8.1+）
- 至少一种数据库：MySQL / PostgreSQL / SQLite
- Composer（可选，用于开发工具）

### 本地开发

```bash
# 克隆项目
git clone https://github.com/yourname/shield-waf.git
cd shield-waf

# 语法检查
find src -name "*.php" -exec php -l {} \;

# 运行密码模块测试
php test_password.php
php test_dual_password.php
php test_db_adapter.php
```

### 目录结构速览

```
src/
├── Admin/          # 管理后台（Dashboard/API）
├── Core/           # 核心（归一化/评分/请求）
├── Defense/        # 防御模块（33 个）
├── Semantic/       # 语义分析引擎
├── Bot/            # 机器人防护
├── Password/       # 双重密码加密
├── Learning/       # 自学习系统
└── Support/        # 工具函数
```

---

## 测试规范

### 测试原则

- 新增功能必须附带测试用例
- 修复 Bug 必须添加回归测试
- 测试用例应覆盖：正常路径、边界条件、异常情况

### 运行测试

```bash
# 密码模块全量测试
php test_password.php

# 双重加密专项测试
php test_dual_password.php

# 数据库适配器测试（需要对应数据库）
php test_db_adapter.php

# 首页403回归测试（v4.1 新增）
php test_homepage_compat.php

# 误报压力测试（37 用例）
php test_fp_stress.php

# 管理员白名单 + 测试模式（v4.1 新增，11 用例）
php test_admin_whitelist.php

# 攻击载荷评分详情
php test_parser_scores.php

# 14 层解码测试
php test_full_decode.php

# 极限测试
php test_extreme.php
```

### 测试数据要求

- 不包含真实用户数据
- 不包含真实攻击 payload（使用脱敏/替换版本）
- 测试文件不提交敏感信息

---

## 提交 PR 指南

### PR 模板

提交 PR 时请包含以下内容：

```
## 变更类型
- [ ] Bug 修复
- [ ] 新功能
- [ ] 性能优化
- [ ] 代码重构
- [ ] 文档更新

## 描述
简要描述变更内容和目的。

## 关联 Issue
Closes #123

## 测试
- [ ] 已通过现有测试
- [ ] 已添加新测试
- [ ] 已进行安全自检

## 影响范围
- 受影响的模块
- 是否有破坏性变更
- 配置项变更

## 截图（如适用）
```

### 提交前检查清单

- [ ] 代码通过 PHP 语法检查（`php -l`）
- [ ] 现有测试全部通过
- [ ] 新增/修改的功能有对应测试
- [ ] 文档已同步更新
- [ ] 没有遗留的调试代码（`var_dump`, `die`, `exit` 等）
- [ ] 没有硬编码的敏感信息
- [ ] 遵循项目编码风格

---

## 代码审查

所有 PR 至少需要 1 名维护者审查通过才能合并。审查关注点：

1. **安全性**：是否引入新的安全漏洞
2. **正确性**：逻辑是否正确，边界是否处理
3. **可维护性**：代码是否清晰，命名是否合理
4. **性能**：是否有明显的性能问题
5. **兼容性**：是否破坏现有 API

---

## 社区行为准则

我们致力于营造一个开放、友好、包容的社区环境。参与本项目即表示你同意：

- 🤝 尊重不同观点和经验
- 💬 友善且建设性的沟通
- 📩 接受建设性批评
- ✊ 对社区整体利益负责
- ❌ 不使用羞辱性语言、不进行人身攻击、不发布骚扰内容

---

## 🏅 贡献者

感谢所有为盾甲 WAF 做出贡献的人！

---

有任何问题，欢迎通过 Issue 或邮件联系我们。

---

> **暗夜铭少** — 欢迎一起打造更安全的 Web 世界
