# OpenSSF 最佳实践徽章 · 申请材料汇总

> 目标：从 **passing（已达成）** → **silver** → **gold（目标）** 逐级申报。
> 本文档是**唯一的材料总表**：每一级准则一行，申请时只需把「证据链接」列填上对应 URL 即可提交。

## 0. 基本信息（申请时直接复用）

| 项目 | 内容 |
|---|---|
| 项目名 | YSL语枢 · 盾甲WAF（Shield WAF） |
| 仓库 | https://github.com/anye1991/shield-waf-master |
| Best Practices 项目页 | https://www.bestpractices.dev/zh-CN/projects/13568 |
| 当前状态 | ✅ **passing 已获**（项目 ID 13568） |
| 官方标准（全量） | https://www.bestpractices.dev/criteria |
| 申报目标 | 🥇 **gold** |

> 填写规范：每条准则在申报系统里都有一个「Met URL / 证据链接」输入框。本表「证据链接（申请时填）」列即对应它——粘贴能证明该条达标的公开链接（文档章节、截图页、CI 报告、测试覆盖率报告等）。

---

## 1. 一级 · Passing（已达成，回顾 + 补证据链接）

> 已过 passing，下列为必达项（MUST）回顾。申请 higher level 时系统会一并校验，建议把每条证据链接补齐以防复查。

### Basics
| 准则 | 级别 | 要求 | 建议证据 | 证据链接（申请时填） |
|---|---|---|---|---|
| description_good | MUST | 站点简明描述软件用途 | README 简介章节 | 🔗 |
| interact | MUST | 提供获取/反馈/贡献方式 | README 快速开始 + Issues | 🔗 |
| contribution | MUST | 说明贡献流程（PR？） | CONTRIBUTING 或 README | 🔗 |
| floss_license | MUST | 以 FLOSS 许可发布 | LICENSE 文件 | 🔗 |
| license_location | MUST | 许可证置于仓库标准位置 | 仓库根 LICENSE | 🔗 |
| documentation_basics | MUST | 提供基础文档 | README | 🔗 |
| documentation_interface | MUST | 描述对外接口（输入/输出） | 部署/配置文档 | 🔗 |
| sites_https | MUST | 站点/仓库/下载支持 HTTPS/TLS | 仓库与主页均为 HTTPS | 🔗 |
| discussion | MUST | 可检索、可按 URL 定位的讨论机制 | GitHub Issues | 🔗 |
| maintained | MUST | 项目处于维护状态 | 近期提交记录 | 🔗 |

### Change Control
| 准则 | 级别 | 要求 | 建议证据 | 证据链接（申请时填） |
|---|---|---|---|---|
| repo_public | MUST | 公开可读的版本控制仓库 | 仓库 URL | 🔗 |
| repo_track | MUST | 记录改动/作者/时间 | git 历史 | 🔗 |
| repo_interim | MUST | 含发布间的中间版本 | 分支/提交 | 🔗 |
| version_unique | MUST | 每次发布有唯一版本号 | 版本号规范 | 🔗 |
| release_notes | MUST | 每次发布有人类可读的发布说明 | CHANGELOG / Release Notes | 🔗 |
| release_notes_vulns | MUST | 发布说明列出已修复的公开漏洞 | Release Notes | 🔗 |

### Reporting
| 准则 | 级别 | 要求 | 建议证据 | 证据链接（申请时填） |
|---|---|---|---|---|
| report_process | MUST | 提供用户提交 bug 的流程 | Issue 模板 / SECURITY | 🔗 |
| report_responses | MUST | 近 2–12 月内 majority bug 有回应 | Issue 活动记录 | 🔗 |

### Quality / Security / Analysis（摘要）
| 准则 | 级别 | 要求 | 建议证据 | 证据链接（申请时填） |
|---|---|---|---|---|
| build_common_tools / working_build | MUST | 能用常见工具构建 | install.php / 部署文档 | 🔗 |
| tests | MUST | 有自动化测试套件 | tests/ 目录 | 🔗 |
| vulnerabilities_fixed_20 / vulnerabilities_critical_fixed | SHOULD | 及时修复已报告漏洞 | 安全更新记录 | 🔗 |
| crypto_weaknesses / static_analysis / dependency_monitoring（基础） | MUST/SHOULD | 无已知未处理高危漏洞；做静态分析；监控依赖 | 扫描报告 | 🔗 |

> 全量 passing 条目以官方页面为准：https://www.bestpractices.dev/criteria

---

## 2. 二级 · Silver（重点补齐）

| # | 准则 | 级别 | 要求 | 建议证据 | 证据链接（申请时填） |
|---|---|---|---|---|---|
| S1 | dco | MUST | 使用 DCO 或等效机制（如 CLA / PR 签署） | DCO 说明 + 签署记录 | 🔗 |
| S2 | governance | MUST | 明确并记录治理模型（决策方式/关键角色） | GOVERNANCE.md | 🔗 |
| S3 | access_continuity | MUST | 若核心成员失联，他人仍有必要访问权 | 多维护者/密钥托管说明 | 🔗 |
| S4 | bus_factor | SHOULD | 总线因子 ≥ 2 | 维护者名单 ≥2 | 🔗 |
| S5 | documentation_security | MUST | 文档化安全需求 | SECURITY.md / 安全章节 | 🔗 |
| S6 | assurance_case | MUST | 有保证论证说明为何满足安全需求 | 安全论证文档 | 🔗 |
| S7 | documentation_quick_start | MUST | 提供快速上手指南 | README 快速开始 | 🔗 |
| S8 | accessibility_best_practices | SHOULD | 遵循无障碍最佳实践 | 控制台无障碍说明 | 🔗 |
| S9 | coding_standards | MUST | 选用并遵循编码规范 | CODING_STANDARD.md | 🔗 |
| S10 | dependency_monitoring | MUST | 监控外部依赖以发现/修复已知漏洞 | Dependabot/Renovate 配置 | 🔗 |
| S11 | test_statement_coverage80 | MUST | 语句覆盖率 ≥ 80% | 覆盖率报告（≥80%） | 🔗 |
| S12 | signed_releases | MUST | 广泛使用的发布须加密签名 | GPG 签名 tag / 发布签名 | 🔗 |
| S13 | input_validation | MUST | 校验所有不可信输入（用白名单） | 输入校验代码/文档 | 🔗 |
| S14 | hardening | SHOULD | 使用加固机制 | 安全配置说明 | 🔗 |

---

## 3. 三级 · Gold（最终目标，逐条攻坚）

| # | 准则 | 级别 | 要求 | 建议证据 | 证据链接（申请时填） |
|---|---|---|---|---|---|
| G1 | contributors_unassociated | MUST | ≥2 名无关联的重要贡献者 | 两位独立贡献者记录 | 🔗 |
| G2 | copyright_per_file | MUST | 每文件含版权与许可证声明 | 文件头声明规范 | 🔗 |
| G3 | require_2FA | MUST | 使用双因素认证（2FA） | 账户 2FA 开启说明/截图 | 🔗 |
| G4 | two_person_review | MUST | ≥50% 的修改经第二人复核 | PR review 记录（≥50%） | 🔗 |
| G5 | reproducible_build | MUST | 可复现构建 | 构建脚本 + 复现验证报告 | 🔗 |
| G6 | test_continuous_integration | MUST | 使用持续集成 | GitHub Actions 工作流 | 🔗 |
| G7 | test_statement_coverage90 | MUST | 语句覆盖率 ≥ 90% | 覆盖率报告（≥90%） | 🔗 |
| G8 | test_branch_coverage80 | MUST | 分支覆盖率 ≥ 80% | 覆盖率报告（≥80%） | 🔗 |
| G9 | crypto_used_network | MUST | 支持安全协议，默认禁用不安全协议 | TLS/安全配置说明 | 🔗 |
| G10 | crypto_tls12 | MUST | 使用 TLS 1.2 及以上 | 站点/接口 TLS 配置 | 🔗 |
| G11 | hardened_site | MUST | 加固的项目站点/仓库/下载站 | HTTPS+HSTS+CSP 等配置 | 🔗 |
| G12 | security_review | MUST | 完成一次安全评审（内部或外部） | 安全评审报告 | 🔗 |

---

## 4. ⚠️ Gold 当前难点提示（申请前待办）

以下 gold 准则对本项目（单人主导 + 核心已加密）是**主要缺口**，需提前处理：

1. **G1 无关联贡献者 / G4 双人复核**：当前以单人（暗夜铭少）为主，需再引入 ≥1 名独立贡献者，并让其参与 ≥50% 修改的 review。
2. **G2 每文件版权**：核心代码已用 php-beast 加密（`.so` + 加密文件），明文版权头在加密后不可见。方案：在明文源 `core-src/` 与文档中说明版权策略，并向申报系统就加密文件申请 N/A / 例外说明。
3. **G5 可复现构建**：加密核心 + 二进制扩展使可复现构建复杂。需提供确定性构建脚本并附复现验证报告（建议把构建过程写进文档/CI）。
4. **G7/G8 覆盖率 90%/80%**：需补足自动化测试并跑覆盖率（当前 `tests/` 存在但覆盖不足）。
5. **G6 CI / S10 依赖监控 / S12 签名发布**：需搭建 GitHub Actions（CI + 覆盖率 + 依赖扫描）、开启 Dependabot、发布做 GPG 签名。
6. **G12 安全评审**：需安排一次内部或外部安全评审并产出报告。
7. **G3 2FA**：个人 GitHub 账户开启 2FA 即可（最简单）。

---

## 5. 申请流程（逐步）

1. 在 https://www.bestpractices.dev/zh-CN/projects/13568 进入「升级 / Upgrade to gold」。
2. 逐级确认：先 silver 全部 Met → 再 gold 全部 Met。
3. 每条准则在系统里粘贴本表对应「证据链接（申请时填）」列的 URL。
4. 提交后等待系统/人工复核；本文件夹可作为证据材料的统一出处（如需放截图/报告，直接存入本 `badge-application/` 目录并引用相对路径或 raw 链接）。

---

*本文档随申报进度持续更新；准则原文与最新要求以官方页面 https://www.bestpractices.dev/criteria 为准。*
