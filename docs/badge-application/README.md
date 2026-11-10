# OpenSSF 最佳实践徽章 · 申请材料汇总

> 目标：从 **passing（已达成）** → **silver** → **gold（目标）** 逐级申报。
> 本文档是**唯一的材料总表**：每一级准则一行，申请时只需把「证据链接」列填上对应 URL 即可提交。
> 数据来源：官方 `docs/other.md` 全量 + https://www.bestpractices.dev/criteria （2026-11 核对）。

## 0. 基本信息（申请时直接复用）

| 项目 | 内容 |
|---|---|
| 项目名 | YSL语枢 · 盾甲WAF（Shield WAF） |
| 仓库 | https://github.com/anye1991/shield-waf-master |
| Best Practices 项目页 | https://www.bestpractices.dev/zh-CN/projects/13568 |
| 当前状态 | ✅ **passing 已获**（项目 ID 13568） |
| 官方标准（全量） | https://www.bestpractices.dev/criteria |
| 申报目标 | 🥇 **gold** |

> 填写规范：每条准则在申报系统里都有「Met URL / 证据链接」或「N/A 理由 / Met 理由」输入框。本表「证据链接（申请时填）」列即对应它。

---

## 1. 一级 · Passing（已达成，回顾 + 补证据链接）

> 已过 passing，下列为必达项（MUST）回顾。升级时系统会一并校验，建议把每条证据链接补齐。

### Basics
| 准则 | 级别 | 要求 | 建议证据 | 证据链接 |
|---|---|---|---|---|
| description_good | MUST | 站点简明描述软件用途 | README 简介 | 🔗 |
| interact | MUST | 提供获取/反馈/贡献方式 | README 快速开始 + Issues | 🔗 |
| contribution | MUST | 说明贡献流程（PR？） | CONTRIBUTING / README | 🔗 |
| floss_license | MUST | 以 FLOSS 许可发布 | LICENSE | 🔗 |
| license_location | MUST | 许可证置于仓库标准位置 | 仓库根 LICENSE | 🔗 |
| documentation_basics | MUST | 提供基础文档 | README | 🔗 |
| documentation_interface | MUST | 描述对外接口（输入/输出） | 部署/配置文档 | 🔗 |
| sites_https | MUST | 站点/仓库/下载支持 HTTPS/TLS | 均为 HTTPS | 🔗 |
| discussion | MUST | 可检索、可按 URL 定位的讨论机制 | GitHub Issues | 🔗 |
| maintained | MUST | 项目处于维护状态 | 近期提交记录 | 🔗 |

### Change Control
| 准则 | 级别 | 要求 | 建议证据 | 证据链接 |
|---|---|---|---|---|
| repo_public | MUST | 公开可读的版本控制仓库 | 仓库 URL | 🔗 |
| repo_track | MUST | 记录改动/作者/时间 | git 历史 | 🔗 |
| repo_interim | MUST | 含发布间的中间版本 | 分支/提交 | 🔗 |
| version_unique | MUST | 每次发布有唯一版本号 | 版本号规范 | 🔗 |
| release_notes | MUST | 每次发布有人类可读发布说明 | CHANGELOG / Release Notes | 🔗 |
| release_notes_vulns | MUST | 发布说明列出已修复公开漏洞 | Release Notes | 🔗 |

### Reporting
| 准则 | 级别 | 要求 | 建议证据 | 证据链接 |
|---|---|---|---|---|
| report_process | MUST | 提供用户提交 bug 的流程 | Issue 模板 / SECURITY | 🔗 |
| report_responses | MUST | 近 2–12 月内 majority bug 有回应 | Issue 活动记录 | 🔗 |

### Quality / Security / Analysis（摘要）
| 准则 | 级别 | 要求 | 建议证据 | 证据链接 |
|---|---|---|---|---|
| working build / build_repeatable | MUST | 能用常见工具构建/可重复 | install.php / 部署文档 | 🔗 |
| tests | MUST | 有自动化测试套件 | tests/ 目录 | 🔗 |
| vulnerabilities_fixed / critical_fixed | SHOULD | 及时修复已报告漏洞 | 安全更新记录 | 🔗 |
| crypto_weaknesses / static_analysis / dependency_monitoring（基础） | MUST/SHOULD | 无已知未处理高危漏洞；静态分析；监控依赖 | 扫描报告 | 🔗 |

> 全量 passing 条目以官方页面为准：https://www.bestpractices.dev/criteria

---

## 2. 二级 · Silver（完整清单，重点补齐）

> Silver = 全部 passing MUST + 以下「passing 升级为 MUST」+「silver 新增」。带 ★ 者为 silver 新增。

### 由 passing 升级为 MUST 的条目
| 准则 | 级别 | 要求 | N/A? | 证据链接 |
|---|---|---|---|---|
| contribution_requirements | MUST | 贡献信息含可接受贡献的要求 | — | 🔗 |
| report_tracker | MUST | 使用 issue 跟踪器 | — | 🔗 |
| tests_documented_added | MUST | 变更指引中写明"加新功能须加测试"策略 | — | 🔗 |
| warnings_strict | MUST | 尽量严格开启告警 | — | 🔗 |
| crypto_weaknesses | MUST | 默认安全机制不依赖已知弱算法 | — | 🔗 |
| static_analysis_common_vulnerabilities | MUST | 用静态分析工具查常见漏洞 | — | 🔗 |
| dynamic_analysis_unsafe | MUST | 若用内存不安全语言须用动态分析工具 | ✅ N/A（PHP 内存安全） | 🔗 |
| automated_integration_testing | MUST | 每次合入至少一分支跑自动化测试并出报告 | — | 🔗 |
| test_policy_mandated | MUST | 书面政策：加主要功能须加测试 | — | 🔗 |
| regression_tests_added50 | MUST | 近 6 月修复的 bug 至少 50% 加回归测试 | — | 🔗 |
| test_statement_coverage80 | MUST | 语句覆盖率 ≥ 80% | — | 🔗 |
| coding_standards | MUST | 指明主要语言编码规范并大致遵守 | — | 🔗 |
| coding_standards_enforced | MUST | 若有 FLOSS 工具则自动强制规范 | — | 🔗 |
| external_dependencies | MUST | 以机器可处理方式列出外部依赖 | — | 🔗 |
| updateable_reused_components | MUST | 易识别/更新复用的外部组件 | — | 🔗 |
| build_standard_variables | MUST | 构建系统尊重 CC/CFLAGS 等环境变量 | ✅ N/A（无原生二进制） | 🔗 |
| build_non_recursive | MUST | 构建系统不递归构建有交叉依赖的子目录 | ✅ N/A（无编译） | 🔗 |
| build_repeatable | MUST | 从源码重复生成结果 bit-for-bit 一致 | ✅ N/A（PHP 解释执行） | 🔗 |
| installation_common | MUST | 提供常见方式安装/卸载 | — | 🔗 |
| installation_standard_variables | MUST | 安装系统尊重 DESTDIR 等约定 | ✅ N/A（无安装系统） | 🔗 |
| installation_development_quick | MUST | 潜在开发者可快速装好开发与测试环境 | — | 🔗 |
| implement_secure_design | MUST | 落实安全设计原则 | — | 🔗 |
| input_validation | MUST | 校验所有不可信输入（白名单） | — | 🔗 |
| crypto_certificate_verification | MUST | 若用 TLS 默认校验证书 | ✅ N/A（库本身不用 TLS） | 🔗 |
| crypto_verification_private | MUST | 发隐私信息前校验证书 | ✅ N/A（库本身不用 TLS） | 🔗 |
| signed_releases | MUST | 广泛使用的发布须加密签名 + 说明验签 | — | 🔗 |
| dependency_monitoring | MUST | 监控外部依赖发现/修复已知漏洞 | — | 🔗 |

### Silver 新增条目（★）
| # | 准则 | 级别 | 要求 | N/A? | 证据链接 |
|---|---|---|---|---|---|
| S1★ | dco | SHOULD | 使用 DCO 或等效法律机制（如 CLA） | — | 🔗 |
| S2★ | code_of_conduct | MUST | 采用行为准则并置于标准位置 | — | 🔗 |
| S3★ | governance | MUST | 明确并记录治理模型 | — | 🔗 |
| S4★ | roles_responsibilities | MUST | 明确并记录关键角色与职责 | — | 🔗 |
| S5★ | documentation_roadmap | MUST | 有至少未来一年的路线图 | — | 🔗 |
| S6★ | documentation_architecture | MUST | 含软件架构（高层设计）文档 | ✅ N/A（不产生软件则 N/A） | 🔗 |
| S7★ | documentation_security | MUST | 文档化安全需求 + 保证论证（威胁模型/信任边界/已知弱点已应对） | — | 🔗 |
| S8★ | documentation_quick_start | MUST | 提供快速上手指南 | — | 🔗 |
| S9★ | documentation_current | MUST | 文档与当前版本保持一致，已知缺陷须修 | — | 🔗 |
| S10★ | documentation_achievements | MUST | 获成就 48h 内于首页/站点标明并链接 | — | 🔗 |
| S11★ | crypto_password_storage | MUST | 若存认证密码须用带盐迭代哈希 | ✅ N/A（软件不存密码） | 🔗 |
| S12★ | accessibility_best_practices | SHOULD | 遵循无障碍最佳实践 | ⚠️ 常 N/A（库） | 🔗 |
| S13★ | internationalization | SHOULD | 软件国际化便于本地化 | ⚠️ 可 N/A | 🔗 |
| S14★ | access_continuity | MUST | 任一核心成员失联仍能持续（密钥/权限托管） | — | 🔗 |
| S15★ | bus_factor | SHOULD | 总线因子 ≥ 2 | — | 🔗 |
| S16★ | maintenance_or_update | MUST | 维护旧版本或提供升级路径 | — | 🔗 |
| S17★ | vulnerability_report_credit | MUST | 对近 12 月修复漏洞的报告者致谢（可匿名除外） | ✅ N/A（近 12 月无漏洞修复） | 🔗 |
| S18★ | vulnerability_response_process | MUST | 有书面的漏洞响应流程 | — | 🔗 |
| S19★ | hardening | SHOULD | 使用加固机制 | — | 🔗 |
| S20★ | crypto_used_network | SHOULD | 支持安全协议、默认禁用不安全协议 | ✅ N/A（库本身不发网络） | 🔗 |
| S21★ | crypto_tls12 | SHOULD | 若用 TLS 至少支持 1.2 | ✅ N/A（库本身不用 TLS） | 🔗 |
| S22★ | crypto_algorithm_agility | SHOULD | 支持多种加密算法便于切换 | — | 🔗 |
| S23★ | crypto_credential_agility | SHOULD | 凭证/私钥与配置分离可更新 | ✅ N/A（不处理凭证） | 🔗 |

---

## 3. 三级 · Gold（完整清单，逐条攻坚）

> Gold = 全部 silver + 以下「升级为 MUST」+「gold 新增」。带 ★ 者为 gold 新增。

### 由 lower 升级为 MUST 的条目
| 准则 | 级别 | 要求 | N/A? | 证据链接 |
|---|---|---|---|---|
| bus_factor | MUST（原 SHOULD） | 总线因子 ≥ 2 | — | 🔗 |
| hardening | MUST（原 SHOULD） | 使用加固机制 | ✅ N/A（不产生软件） | 🔗 |
| dynamic_analysis | MUST（原 SUGGESTED） | 主要生产发布前至少用一种动态分析工具 | — | 🔗 |
| repo_distributed | MUST（原 SUGGESTED） | 使用常见分布式版本控制（git） | — | 🔗 |
| test_invocation | MUST（原 SHOULD） | 测试套件可用该语言标准方式调用 | — | 🔗 |
| test_continuous_integration | MUST（原 SUGGESTED） | 实施持续集成 | — | 🔗 |
| crypto_used_network | MUST NOT（原 SHOULD） | 有加密等价时不得用明文网络协议 | ✅ N/A（库本身不发网络） | 🔗 |
| crypto_tls12 | MUST（原 SHOULD） | 若用 TLS 至少支持 1.2 | ✅ N/A（库本身不用 TLS） | 🔗 |
| dynamic_analysis_enable_assertions | MUST（原 SUGGESTED） | 软件含大量运行时断言并在动态分析中检查 | — | 🔗 |

### Gold 新增条目（★）
| # | 准则 | 级别 | 要求 | N/A / 补救 | 证据链接 |
|---|---|---|---|---|---|
| G1★ | copyright_per_file | MUST | 每源文件含版权声明 | **Met+理由**（核心加密，版权统一在 LICENSE/core-src 声明） | 🔗 |
| G2★ | license_per_file | MUST | 每源文件含许可声明（SPDX） | **Met+理由**（同上） | 🔗 |
| G3★ | contributors_unassociated | MUST | ≥2 名无关联的重要贡献者 | — | 🔗 |
| G4★ | small_tasks | MUST | 明确标识新人/临时贡献者可做的小任务 | — | 🔗 |
| G5★ | require_2FA | MUST | 开发者改中央仓库/访问敏感数据须 2FA | — | 🔗 |
| G6★ | secure_2FA | SHOULD | 2FA 应使用加密机制防仿冒（SMS 不算） | — | 🔗 |
| G7★ | two_person_review | MUST | ≥50% 修改经第二人复核 | — | 🔗 |
| G8★ | code_review_standards | MUST | 书面记录代码复核要求（怎么做/查什么/何可接受） | — | 🔗 |
| G9★ | build_reproducible | MUST | 可复现构建 | ✅ **N/A**（PHP 解释执行，无编译产物；扩展为预编译标准组件） | 🔗 |
| G10★ | test_statement_coverage90 | MUST | 语句覆盖率 ≥ 90% | — | 🔗 |
| G11★ | test_branch_coverage80 | MUST | 分支覆盖率 ≥ 80% | — | 🔗 |
| G12★ | security_review | MUST | 近 5 年内做过安全评审 | — | 🔗 |
| G13★ | hardened_site | MUST | 站点/仓库/下载站含关键加固响应头（非宽松值） | — | 🔗 |

---

## 4. 官方「补救 / 例外」机制（申请核心依据）

官方**没有独立申诉窗口**，但提供以下合规弹性，本项目应充分利用：

1. **逐条 N/A + 理由**：凡标注 `N/A allowed` 的准则，可填「不适用理由」免测。本项目可 N/A 的：
   - `build_reproducible` / `build_repeatable` / `build_standard_variables` / `build_non_recursive`（PHP 解释执行，无编译产物）
   - `crypto_used_network` / `crypto_tls12` / `crypto_certificate_verification` / `crypto_verification_private`（WAF 为库，TLS 由宿主负责）
   - `dynamic_analysis_unsafe`（PHP 内存安全）
   - `crypto_password_storage` / `crypto_credential_agility`（软件不处理凭证/密码）
   - `vulnerability_report_credit`（近 12 月无漏洞修复）
   - `accessibility_best_practices` / `internationalization`（库常 N/A）
2. **Met + 理由**：部分准则（如 `copyright_per_file` / `license_per_file`）接受「未逐字合规但可论证达标」——核心已加密时，在理由中说明版权/许可统一在 `LICENSE` 与 `core-src/` 声明即可。
3. **用户配置例外**：`crypto_used_network` 允许「用户显式配置才启用明文协议」。
4. **准则反馈渠道**：对准则本身有疑问可到 `ossf/best-practices-badge` 提 issue（非项目申诉，但是官方答疑入口）。

---

## 5. ⚠️ Gold 当前难点提示（申请前待办）

以下 gold 准则对本项目（单人主导 + 核心已加密 + PHP 解释型）是**主要缺口**，需提前处理：

1. **G3 无关联贡献者 / G7 双人复核**：当前以单人（暗夜铭少）为主，需再引入 ≥1 名独立贡献者，并让其参与 ≥50% 修改的 review（bot 复核不算，须人类第二人）。
2. **G1/G2 每文件版权/许可**：核心已加密，明文版权头不可见 → 用 **Met + 理由** 说明（版权/许可统一在 LICENSE 与 core-src）。
3. **G4 small_tasks / G8 code_review_standards**：需在 Issue 打 `good-first-issue` 等标签标识小任务；并写一份代码复核标准文档（CONTRIBUTING 增补）。
4. **G9 可复现构建**：PHP 解释执行 → 标 **N/A + 理由**（扩展为预编译标准组件）。
5. **G10/G11 覆盖率 90%/80%、CI、依赖监控、签名发布**：需补自动化测试 + 跑覆盖率 + 搭 GitHub Actions + 开 Dependabot + 发布做 GPG 签名。
6. **G12 安全评审**：安排一次内部或外部安全评审并产出报告。
7. **G5 2FA**：个人 GitHub 账户开启 2FA 即可（最简单）；G6 建议用 TOTP/硬件密钥而非 SMS。
8. **Silver 侧文档类 MUST**：需补 `GOVERNANCE.md`、`CODE_OF_CONDUCT.md`、安全文档（威胁模型/保证论证）、架构文档、`SECURITY.md`、路线图、快速上手（已有）、行为准则致谢等。

---

## 6. 申请流程（逐步）

1. 在 https://www.bestpractices.dev/zh-CN/projects/13568 进入「升级 / Upgrade」。
2. 逐级确认：先 silver 全部 Met/N/A → 再 gold 全部 Met/N/A。
3. 每条在系统粘贴本表对应「证据链接（申请时填）」列的 URL；可 N/A 的填理由；可用 Met+理由 的填论证。
4. 本文件夹作为证据统一出处（截图/报告直接存入 `badge-application/` 并引 raw 链接）。

---

*本文档随申报进度持续更新；准则原文与最新要求以官方页面 https://www.bestpractices.dev/criteria 为准。*
