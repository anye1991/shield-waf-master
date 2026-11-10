# OpenSSF 最佳实践徽章 · 申请材料汇总

> 结果：**🥇 Gold 已获**（2026-11-10 由 OpenSSF Best Practices Badge Lead 邮件确认）。
> 本文档保留为**申报档案 + 材料总表**：每条准则一行，含当时判定（Met / N/A / Met+理由）与证据链接，供后续复核、年度维护复用。
> 数据来源：官方 `docs/other.md` 全量 + https://www.bestpractices.dev/criteria （2026-11 核对）。

## 0. 基本信息

| 项目 | 内容 |
|---|---|
| 项目名 | YSL语枢 · 盾甲WAF（Shield WAF） |
| 仓库 | https://github.com/anye1991/shield-waf-master |
| Best Practices 项目页 | https://www.bestpractices.dev/zh-CN/projects/13568 |
| 当前状态 | 🥇 **gold 已获**（项目 ID 13568，2026-11-10 授予） |
| 官方标准（全量） | https://www.bestpractices.dev/criteria |
| 徽章嵌入（Markdown） | `[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13568/badge)](https://www.bestpractices.dev/projects/13568)` |

> 链接规范：下表中的 `https://github.com/anye1991/shield-waf-master/blob/main/...` 为可读页；若需直链文件，把 `blob` 换成 `raw.githubusercontent.com/anye1991/shield-waf-master/main`（去掉 `/blob`）即可。

---

## 1. 一级 · Passing（已达成）

### Basics
| 准则 | 级别 | 要求 | 证据链接 |
|---|---|---|---|
| description_good | MUST | 站点简明描述软件用途 | https://waf.duduziy.com |
| interact | MUST | 提供获取/反馈/贡献方式 | https://github.com/anye1991/shield-waf-master/issues |
| contribution | MUST | 说明贡献流程（PR？） | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| floss_license | MUST | 以 FLOSS 许可发布 | https://github.com/anye1991/shield-waf-master/blob/main/LICENSE |
| license_location | MUST | 许可证置于仓库标准位置 | https://github.com/anye1991/shield-waf-master/blob/main/LICENSE |
| documentation_basics | MUST | 提供基础文档 | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| documentation_interface | MUST | 描述对外接口（输入/输出） | https://github.com/anye1991/shield-waf-master/blob/main/docs/ARCHITECTURE.md |
| sites_https | MUST | 站点/仓库/下载支持 HTTPS/TLS | https://waf.duduziy.com |
| discussion | MUST | 可检索、可按 URL 定位的讨论机制 | https://github.com/anye1991/shield-waf-master/issues |
| maintained | MUST | 项目处于维护状态 | https://github.com/anye1991/shield-waf-master/commits/main |

### Change Control
| 准则 | 级别 | 要求 | 证据链接 |
|---|---|---|---|
| repo_public | MUST | 公开可读的版本控制仓库 | https://github.com/anye1991/shield-waf-master |
| repo_track | MUST | 记录改动/作者/时间 | https://github.com/anye1991/shield-waf-master/commits/main |
| repo_interim | MUST | 含发布间的中间版本 | https://github.com/anye1991/shield-waf-master/commits/main |
| version_unique | MUST | 每次发布有唯一版本号 | https://github.com/anye1991/shield-waf-master/blob/main/docs/CHANGELOG.md |
| release_notes | MUST | 每次发布有人类可读发布说明 | https://github.com/anye1991/shield-waf-master/blob/main/docs/CHANGELOG.md |
| release_notes_vulns | MUST | 发布说明列出已修复公开漏洞 | https://github.com/anye1991/shield-waf-master/releases |

### Reporting
| 准则 | 级别 | 要求 | 证据链接 |
|---|---|---|---|
| report_process | MUST | 提供用户提交 bug 的流程 | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| report_responses | MUST | 近 2–12 月内 majority bug 有回应 | https://github.com/anye1991/shield-waf-master/issues?q=is%3Aissue |

### Quality / Security / Analysis
| 准则 | 级别 | 要求 | 证据链接 |
|---|---|---|---|
| build | MUST | 能用常见工具构建/安装 | https://github.com/anye1991/shield-waf-master/blob/main/install.php |
| tests | MUST | 有自动化测试套件 | https://github.com/anye1991/shield-waf-master/tree/main/tests |
| vulnerabilities_fixed / critical_fixed | SHOULD | 及时修复已报告漏洞 | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| crypto_weaknesses | MUST | 默认安全机制不依赖已知弱算法 | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY-REVIEW.md |
| static_analysis | MUST | 使用静态分析工具 | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| dependency_monitoring | MUST | 监控外部依赖漏洞 | https://github.com/anye1991/shield-waf-master/blob/main/.github/dependabot.yml |

---

## 2. 二级 · Silver（已达成）

### 由 passing 升级为 MUST 的条目
| 准则 | 级别 | N/A? | 证据链接 |
|---|---|---|---|
| contribution_requirements | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| report_tracker | MUST | — | https://github.com/anye1991/shield-waf-master/issues |
| tests_documented_added | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| warnings_strict | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| crypto_weaknesses | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY-REVIEW.md |
| static_analysis_common_vulnerabilities | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/tools/static_check.php |
| dynamic_analysis_unsafe | MUST | ✅ N/A（PHP 内存安全） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY-REVIEW.md |
| automated_integration_testing | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| test_policy_mandated | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| regression_tests_added50 | MUST | — | https://github.com/anye1991/shield-waf-master/tree/main/tests |
| test_statement_coverage80 | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| coding_standards | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CODING_STANDARDS.md |
| coding_standards_enforced | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/tools/static_check.php |
| external_dependencies | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/composer.json |
| updateable_reused_components | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/composer.json |
| build_standard_variables | MUST | ✅ N/A（无原生二进制） | https://github.com/anye1991/shield-waf-master/blob/main/install.php |
| build_non_recursive | MUST | ✅ N/A（无编译） | https://github.com/anye1991/shield-waf-master/blob/main/install.php |
| build_repeatable | MUST | ✅ N/A（PHP 解释执行） | https://github.com/anye1991/shield-waf-master/blob/main/install.php |
| installation_common | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| installation_standard_variables | MUST | ✅ N/A（无安装系统） | https://github.com/anye1991/shield-waf-master/blob/main/install.php |
| installation_development_quick | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| implement_secure_design | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| input_validation | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY-REVIEW.md |
| crypto_certificate_verification | MUST | ✅ N/A（库本身不用 TLS） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| crypto_verification_private | MUST | ✅ N/A（库本身不用 TLS） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| signed_releases | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| dependency_monitoring | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/dependabot.yml |

### Silver 新增条目（★）
| # | 准则 | 级别 | N/A? | 证据链接 |
|---|---|---|---|---|
| S1★ | dco | SHOULD | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| S2★ | code_of_conduct | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CODE_OF_CONDUCT.md |
| S3★ | governance | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/GOVERNANCE.md |
| S4★ | roles_responsibilities | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/GOVERNANCE.md |
| S5★ | documentation_roadmap | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/ROADMAP.md |
| S6★ | documentation_architecture | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/ARCHITECTURE.md |
| S7★ | documentation_security | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S8★ | documentation_quick_start | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| S9★ | documentation_current | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| S10★ | documentation_achievements | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| S11★ | crypto_password_storage | MUST | ✅ N/A（软件不存密码） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S12★ | accessibility_best_practices | SHOULD | ⚠️ N/A（控制台为服务端渲染，非面向公众的 UI 库） | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| S13★ | internationalization | SHOULD | ⚠️ N/A（单一中文产品形态） | https://github.com/anye1991/shield-waf-master/blob/main/README.md |
| S14★ | access_continuity | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/GOVERNANCE.md |
| S15★ | bus_factor | SHOULD | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/GOVERNANCE.md |
| S16★ | maintenance_or_update | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/ROADMAP.md |
| S17★ | vulnerability_report_credit | MUST | ✅ N/A（近 12 月无漏洞修复） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S18★ | vulnerability_response_process | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S19★ | hardening | SHOULD | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S20★ | crypto_used_network | SHOULD | ✅ N/A（库本身不发网络） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S21★ | crypto_tls12 | SHOULD | ✅ N/A（库本身不用 TLS） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| S22★ | crypto_algorithm_agility | SHOULD | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY-REVIEW.md |
| S23★ | crypto_credential_agility | SHOULD | ✅ N/A（不处理凭证） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |

---

## 3. 三级 · Gold（已达成）

### 由 lower 升级为 MUST 的条目
| 准则 | 级别 | N/A? | 证据链接 |
|---|---|---|---|
| bus_factor | MUST（原 SHOULD） | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/GOVERNANCE.md |
| hardening | MUST（原 SHOULD） | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| dynamic_analysis | MUST（原 SUGGESTED） | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| repo_distributed | MUST（原 SUGGESTED） | — | https://github.com/anye1991/shield-waf-master |
| test_invocation | MUST（原 SHOULD） | — | https://github.com/anye1991/shield-waf-master/tree/main/tests |
| test_continuous_integration | MUST（原 SUGGESTED） | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| crypto_used_network | MUST NOT（原 SHOULD） | ✅ N/A（库本身不发网络） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| crypto_tls12 | MUST（原 SHOULD） | ✅ N/A（库本身不用 TLS） | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY.md |
| dynamic_analysis_enable_assertions | MUST（原 SUGGESTED） | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |

### Gold 新增条目（★）
| # | 准则 | 级别 | N/A / 补救 | 证据链接 |
|---|---|---|---|---|
| G1★ | copyright_per_file | MUST | **Met+理由**（核心加密，版权统一在 LICENSE/NOTICE） | https://github.com/anye1991/shield-waf-master/blob/main/NOTICE |
| G2★ | license_per_file | MUST | **Met+理由**（同上，SPDX 已在明文文件头） | https://github.com/anye1991/shield-waf-master/blob/main/NOTICE |
| G3★ | contributors_unassociated | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/GOVERNANCE.md |
| G4★ | small_tasks | MUST | — | https://github.com/anye1991/shield-waf-master/issues?q=label%3Agood-first-issue |
| G5★ | require_2FA | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| G6★ | secure_2FA | SHOULD | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| G7★ | two_person_review | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| G8★ | code_review_standards | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/CONTRIBUTING.md |
| G9★ | build_reproducible | MUST | ✅ **N/A**（PHP 解释执行，无编译产物） | https://github.com/anye1991/shield-waf-master/blob/main/install.php |
| G10★ | test_statement_coverage90 | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| G11★ | test_branch_coverage80 | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/.github/workflows/ci.yml |
| G12★ | security_review | MUST | — | https://github.com/anye1991/shield-waf-master/blob/main/docs/SECURITY-REVIEW.md |
| G13★ | hardened_site | MUST | — | https://waf.duduziy.com |

---

## 4. 官方「补救 / 例外」机制（申报实际依据）

官方**没有独立申诉窗口**，但提供以下合规弹性，本项目申报时按此处理：

1. **逐条 N/A + 理由**：凡标注 `N/A allowed` 的准则，可填「不适用理由」免测。本项目实际使用的 N/A：
   - `build_reproducible` / `build_repeatable` / `build_standard_variables` / `build_non_recursive`（PHP 解释执行，无编译产物）
   - `crypto_used_network` / `crypto_tls12` / `crypto_certificate_verification` / `crypto_verification_private`（WAF 为库，TLS 由宿主负责）
   - `dynamic_analysis_unsafe`（PHP 内存安全）
   - `crypto_password_storage` / `crypto_credential_agility`（软件不处理凭证/密码）
   - `vulnerability_report_credit`（近 12 月无漏洞修复）
   - `accessibility_best_practices` / `internationalization`（产品形态不涉及）
2. **Met + 理由**：`copyright_per_file` / `license_per_file` 采用「未逐字合规但可论证达标」——核心已加密，理由中说明版权/许可统一在 `LICENSE` 与 `NOTICE`，明文文件头带 `SPDX-License-Identifier: MIT`。
3. **准则反馈渠道**：对准则本身有疑问可到 `ossf/best-practices-badge` 提 issue。

---

## 5. 申报过程中补齐的工程与文档（获证依据）

| 类别 | 产出 |
|---|---|
| 许可证 | `LICENSE`（MIT）、`NOTICE`（加密核心版权/许可统一声明） |
| 治理与流程 | `GOVERNANCE.md`、`CODE_OF_CONDUCT.md`、`CONTRIBUTING.md`（DCO + 测试政策 + 复核标准 + 2FA 要求） |
| 安全 | `SECURITY.md`（响应流程 + 威胁模型 + 信任边界）、`SECURITY-REVIEW.md`（安全评审报告） |
| 技术文档 | `ARCHITECTURE.md`、`CODING_STANDARDS.md`、`ROADMAP.md`（含 non-goals）、`CHANGELOG.md` |
| 自动化 | `.github/workflows/ci.yml`（语法 + `tools/static_check.php` 静态安全检查 + 测试）、`.github/dependabot.yml`（依赖监控） |
| 机器可读依赖 | `composer.json` |
| 文件头合规 | 21 个明文 PHP 文件加 `SPDX-License-Identifier: MIT`；`rand()` 整改为 `random_int()` |
| 成就公示 | README 头部嵌入 gold 徽章（`documentation_achievements`） |

---

## 6. 获证后维护

1. **徽章已挂在 README 头部**（13568 + 16060 两枚），官方实时 SVG 会自动显示当前等级；点击直达项目页。

   项目官网首页同步放置用的 HTML 片段（深色/浅色页面均适用）：

   ```html
   <div class="openSSF-badges" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
     <a href="https://www.bestpractices.dev/zh-CN/projects/13568" target="_blank" rel="noopener">
       <img src="https://www.bestpractices.dev/projects/13568/badge" alt="OpenSSF Best Practices · Gold" height="20">
     </a>
     <a href="https://www.bestpractices.dev/zh-CN/projects/16060" target="_blank" rel="noopener">
       <img src="https://www.bestpractices.dev/projects/16060/badge" alt="OpenSSF Best Practices · 16060" height="20">
     </a>
   </div>
   ```
2. **年度复核**：条目有效期靠持续满足维持，重点复查 `maintained`、`report_responses`、`vulnerability_report_credit`、`documentation_current`、`test_*_coverage*`。
3. **每条准则的「理由文本」可继续完善**：官方明确鼓励补充 justification 与 URL，材料变强不会掉级。
4. **仓库结构变动时**（例如文档改名、目录调整），同步更新本表「证据链接」列，避免链接失效。
5. **公开影响页**：官方可能把本项目改进列入 https://github.com/ossf/best-practices-badge/wiki/Impacts ；若不愿公开，按邮件指引回复说明。

---

*本文档为申报档案；准则原文与最新要求以官方页面 https://www.bestpractices.dev/criteria 为准。*
