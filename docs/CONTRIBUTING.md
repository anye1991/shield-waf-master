# 贡献指南（Contributing）

> 对应 OpenSSF 准则 `contribution` / `contribution_requirements` / `dco` / `test_policy_mandated` / `tests_documented_added` / `regression_tests_added50` / `coding_standards` / `code_review_standards` / `small_tasks` / `require_2FA`。

## 1. 快速上手（开发环境）

```bash
# 1) 克隆仓库
git clone https://github.com/anye1991/shield-waf-master.git
cd shield-waf-master

# 2) 本地跑测试套件（PHP 8.1+）
php tests/feature_matrix_check.php
php tests/control_check.php
php tests/ai_check.php
php tests/adversarial.php

# 3) 语法自检（提交前）
for f in $(git ls-files '*.php'); do php -l "$f" || exit 1; done

# 4) 跑自定义静态安全检查
php tools/static_check.php
```

无需安装 Composer 依赖——本项目除 PHP 8.1+ 与随附 `ext/` 扩展外**零外部依赖**。

## 2. 提交流程

1. Fork / 建分支（命名 `feat/xxx`、`fix/xxx`、`docs/xxx`）。
2. 改动后**必须**跑 §1 的测试与静态检查，全绿再提交。
3. 提交 PR 到 `main`，描述：改了什么、为什么、如何验证、影响面。
4. 由维护者复核（见 §5 代码复核标准）后合入。

### 2.1 DCO（Developer Certificate of Origin）

所有提交必须含 `Signed-off-by` 行（DCO）：

```bash
git commit -s -m "fix: 修复 QPS 统计窗口漂移"
# 生成：
# Signed-off-by: 你的名字 <你的邮箱>
```

这表示你确认自己有权以本项目许可证（MIT）提交该改动。

## 3. 新功能必须带测试（书面政策）

> **政策（MANDATORY）**：新增**主要功能**（new major functionality）必须在自动化测试套件中加入对应测试；修复 bug 时**必须**添加能复现该 bug 的回归测试。PR 中未附测试的主要功能改动将被要求补测试后再复核。

- 测试入口：`tests/` 下 `*_check.php` 与 `fp_regression.sh`。
- 新功能对应关系：内核语义 → `adversarial.php` 加用例；控制台/接口 → `control_check.php`；AI 学习 → `ai_check.php`；QPS/限流 → `qps_check.php`。
- 近 6 个月修复的 bug，至少 **50%** 需附回归测试（`regression_tests_added50`）。

## 4. 编码规范

遵循 [`CODING_STANDARDS.md`](CODING_STANDARDS.md)（PHP PSR-12 基础 + 本项目安全约定）。CI 会在每次提交时自动执行语法检查与静态安全检查，不通过即失败。

## 5. 代码复核标准（code_review_standards）

> 本项目要求 **≥50% 的修改经作者以外的第二人复核**后方可发布（`two_person_review`）。

复核人按以下清单逐项确认：

| 检查项 | 合入门槛 |
|---|---|
| ① 功能正确性 | 与 PR 描述一致，测试覆盖到位 |
| ② 安全面 | 无新增不可信输入未校验路径；无弱密码学；无危险函数（`eval`/`exec` 等） |
| ③ 兼容性 | 不破坏既有 JSON 契约 / `.user.ini` 部署方式 / 旧版本升级路径 |
| ④ 性能 | 请求路径不引入模型调用、不引入无界循环 |
| ⑤ 文档 | `README.md` / `CHANGELOG.md` / 相关 doc 与代码同步 |
| ⑥ 风格 | 符合 `CODING_STANDARDS.md` |

**可接受标准**：①②③全部通过且无未决疑问，④⑤⑥无阻塞项。任何一项不达标，复核人须给出具体修改意见（而非笼统"不行"）。

**复核执行**：PR 必须由作者以外的人 Approve（bot 复核不计入）。单人维护期由 Lead 交叉复核历史提交补足比例；长期目标见 `ROADMAP.md` 贡献者梯队。

## 6. 小任务（good-first-issue）

适合新人 / 临时贡献者的任务在 Issue 中打以下标签：

| 标签 | 含义 |
|---|---|
| `good-first-issue` | 新人友好，改动小、有明确验收标准 |
| `documentation` | 文档 / 控制台文案改进 |
| `test` | 补测试用例（非常受欢迎） |
| `i18n` | 中英文案/国际化 |

这些任务**不要求**新增功能，改文档、补用例同样有效。动手前请在对应 Issue 下评论认领，避免重复劳动。

## 7. 账号安全（require_2FA）

所有拥有**推送权限**的贡献者**必须**开启 GitHub 双因素认证（2FA）；建议使用 TOTP 应用或硬件密钥（满足 `secure_2FA`），**SMS 不算安全 2FA**。仓库将逐步强制组织级 2FA。

## 8. 行为准则

参与即同意 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。

---
*感谢每一位贡献者——包括改文档、补测试的同学。*
