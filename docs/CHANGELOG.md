# 更新日志（Changelog / Release Notes）

> 对应 OpenSSF 准则 `release_notes` / `release_notes_vulns` / `maintenance_or_update`。
> 格式参照 Keep a Changelog；版本遵循 SemVer（MAJOR.MINOR.PATCH）。
> 「已修复的公开漏洞」栏：若无公开 CVE 级漏洞，记「无」。

## [Unreleased]

### 新增
- 治理与合规文档体系：`GOVERNANCE.md`、`CODE_OF_CONDUCT.md`、`SECURITY.md`、`CONTRIBUTING.md`、`ROADMAP.md`、`ARCHITECTURE.md`、`CODING_STANDARDS.md`（对齐 OpenSSF 最佳实践 silver/gold 申请）
- CI：GitHub Actions（语法检查 + 静态安全检查 + 测试套件）
- 极限测试工具：`tools/stress_extreme.sh` + `tools/stress/`，一键跑边界/畸形、深层混淆逃逸、
  多 worker 并发、20s 长稳、限流熔断状态五个阶段；报告见 `docs/EXTREME.md`
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
- **可用性 / DoS**：`YslNormalizer::calculateEntropy()` 用逐字符 `mb_substr($str,$i,1)`
  统计频次，是 O(n²)（每次都要从串首扫到第 i 个码点）。长文本 ≥64KB 单请求耗时
  超过 20 秒，8 个 worker 被几个大请求就能打满，等于把 WAF 自己变成 DoS 放大器。
  改为一次性 `preg_split` + `array_count_values`（O(n)，熵值逐位一致）；白盒实测
  65536B 由 9245ms 降到 10ms，端到端 64KB 由超时降到约 350ms，全部长度恢复线性。
- **可用性 / 500**：`NaiveBayesClassifier::tokenize()` 对整串做 2/3-gram，1MB 文本
  会生成约 200 万个 token，PHP 数组扩容一次性申请 256MB 触发 Fatal error，
  正常长文章直接 500。加入 4KB「头 + 尾」特征窗口预算（真实载荷都在前若干 KB，
  且保留长尾判别能力），1MB 请求恢复 200，服务日志零 Fatal。
- **检测 / 长尾夹带**：`collectParamText()` 只取参数文本前 4000 字节，而确定性硬规则
  与误报复核都基于这份文本——攻击藏在长文本尾部时完全看不见，实测
  64KB 填充 + `<script>alert(1)</script>` 被放行 200。改为头尾各半（预算仍 4000 字节，
  下游长度门槛不变），64KB / 1MB 长尾 XSS 与 SQLi 均恢复 403。
- **检测 / 可逆混淆**：base64 大小写翻转变体的采纳门槛只认序列化、代码执行、
  敏感路径等硬结构，SQL 恒真式 / SSTI 插值 / CRLF 响应头注入解出后不被采纳，
  极限测试暴露 6 条漏放。两处 `looksLikeDangerousPayload()` 同步补齐通用攻击结构，
  143 条有效绕过向量漏放 6 → 0（不可逆的 b64 全大写/全小写仍按无效变异记录）。

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
