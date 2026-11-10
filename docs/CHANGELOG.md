# 更新日志（Changelog / Release Notes）

> 对应 OpenSSF 准则 `release_notes` / `release_notes_vulns` / `maintenance_or_update`。
> 格式参照 Keep a Changelog；版本遵循 SemVer（MAJOR.MINOR.PATCH）。
> 「已修复的公开漏洞」栏：若无公开 CVE 级漏洞，记「无」。

## [Unreleased]

### 新增
- 治理与合规文档体系：`GOVERNANCE.md`、`CODE_OF_CONDUCT.md`、`SECURITY.md`、`CONTRIBUTING.md`、`ROADMAP.md`、`ARCHITECTURE.md`、`CODING_STANDARDS.md`（对齐 OpenSSF 最佳实践 silver/gold 申请）
- CI：GitHub Actions（语法检查 + 静态安全检查 + 测试套件）
- 依赖监控：Dependabot 配置
- MIT `LICENSE` 文件与 `NOTICE`（加密核心版权/许可统一声明）

### 变更
- README 版权徽章由「保留所有权利」改为「授权 MIT」，与仓库实际许可证一致

### 已修复
- **检测**：序列化载荷经 base64 编码后再整块大写 / 小写 / 大小写翻转可绕过检测。
  归一化层新增 `base64_case_flip`（三变体还原），并增加「大小写无关的序列化前缀指纹」
  确定性判定；极限对抗 2376 条样本由漏放 6 条降为 **漏放 0**（实测）。
  可用 `WAF_BASE64_MASK_GUARD=0` 单独回退指纹判定。
- **可观测性**：模块降级（自动回退内联实现）不再以 error 级刷日志，统一降为 debug
  （`WAF_DEBUG=1` 时输出并带异常消息与位置）；审计落盘、子系统装配、熔断计数三类
  失败仍保留 error。此前干净请求会偶发 `YslArbiter::arbitrate failed (Error)` 噪音。

### 已修复的公开漏洞
- 无（本次为自测发现的内核检测缺口，未对外披露、无 CVE）

## [6.5.0] - 2026

### 新增
- 蜜罐改为**默认停用**且受控启用：确认短语 / 有效期 / 审批留痕 / 到期自动回退（四道闸）
- 控制台「阻断详情」输出可机器复核的证据证书（子图 + 命中规则 + 归一化轨迹）
- 展示层全中文化（`i18n.php`）：状态、原因、响应页、控制台文案

### 变更
- 入口每请求读取 `var/data/runtime.json`，大屏控制台写入的运行时配置实时生效
- 前置接入层 QPS 限流 / 熔断，统一由 `pages.php` 输出美化响应页

### 已修复的公开漏洞
- 无（截至本版本未收到并修复公开披露的 CVE 级漏洞）

## [6.4.1] - 2026

### 变更
- 展示层统一中文化，内部状态枚举与 JSON 契约不变

## [6.4.0] - 2026

### 新增
- 前置接入层 QPS 限流 / 熔断（滑动窗口 → 429 / 502）

## [6.3.0] - 2026

### 变更
- 入口每请求读取运行时配置文件，控制台改动即时生效

## 升级路径（maintenance_or_update）

- 6.x → 6.x：覆盖仓库后重跑 `php install.php --site=<docroot>` 即可；`.user.ini` 幂等更新。
- ≤5.x → 6.x：配置键有调整，请对照 `config.php` 注释与 `ARCHITECTURE.md` §2 契约说明迁移；如接口有变更，以 `CHANGELOG` 各版本「变更」节为准。

## 致谢

- 感谢所有通过 Issue / PR 反馈问题的用户（按愿披露署名；近 12 个月暂无已修复公开漏洞的报告者，故本节暂列为占位）。
