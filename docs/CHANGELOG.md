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
- **可用性 / 性能退化**：`YslAudit::flush()` 每次都调用 `findLatestHash()` 逐行解码
  **全部**历史日志只为取哈希链末端值，而 php -S / php-fpm 下每个请求都是独立实例、
  析构时 flush 1 条，于是单请求成本与累计日志量成正比；再叠加全局 `.audit.lock` 让
  多 worker 串行等待，表现为并发 64 时 P50 1.3s、20s 长稳 P50 从 983ms 持续上浮到
  1209ms。改为优先读由同一把锁保护的 `.last_hash`（O(1)），回退路径只读最新日志
  末尾 64KB，总量检查从每请求挪到仅在轮转时执行。白盒：8000 行时 flush 由 27.6ms
  降到 0.44ms 且与日志量无关，哈希链（含缓存丢失后续链）验证连续；端到端并发 64
  P50 1311.2→46.1ms、长稳 1085.0→23.2ms、吞吐 40→1160 req/s，延迟不再随时间漂移。

### 已修复的公开漏洞
- 无（本次为自测发现的内核检测缺口，未对外披露、无 CVE）

## [6.5.1] - 2026-11-14

### 已修复
- **兼容性 / 加固环境 500**：`shield-waf.php` 无条件调用 `putenv()`，而宝塔等面板会把
  `putenv` 列入 `disable_functions`，导致每个请求 Fatal → 整站 500。改为
  `function_exists('putenv')` 守卫；不可用时沿用启动默认值（`enforce`、守卫全开、蜜罐停用，
  全部 fail-closed，不静默放行），并同步 `$_ENV` / `$_SERVER`、暴露 `WAF_PUTENV_AVAILABLE`。
- **兼容性 / 控制台 Fatal**：`control.php` 三处 DNA 命令执行依赖 `exec()`，禁用后点 DNA
  按钮直接 Fatal。补 `function_exists('exec')` 兜底，优先 `posix_kill`，返回结构化错误；
  同时收敛为 `ctlDnaRun(string $cmd, array $args)`、PID 强转 `(int)`、`escapeshellarg`、
  固定动作映射，参数不再拼接进 shell。
- **自检可信度**：`install.php --check` 新增运行时依赖函数检查，如实报告 `putenv` / `exec`
  被禁时的降级影响与修复建议，不再出现「自检全绿、上线炸」。
- **CI 恒红 / 静态检查**：`tools/static_check.php` 改为显式审计豁免——仅带
  `waf-audited:exec:` 行级理由标注的合规 `exec` 降级为可见 `[AUDIT]`；`eval`、
  `create_function`、`pcntl_exec`、`rand`、`mt_rand` 永不豁免；新增裸 `exec` 仍 `FAIL`，
  规则强度未降低。
- **CI 恒红 / 编排**：新增 `tools/e2e/ci.sh` 作为 GitHub Actions 与本地通用编排，自动选空闲
  端口、准备 `console.key`、重建 DNA baseline、起 `php -S` + beast，跑全套验收并补回此前
  漏跑的官方向量、`control_check`、`qps_check`；把「禁用 putenv / exec」与「缺扩展 503」
  变为常驻回归项；失败时上传诊断日志。tests 不再依赖 `/app` 软链。
- **可移植性**：`feature_matrix_check.php`、`honeypot_check.php`、`i18n_check.php`、
  `control_check.php`、`qps_check.php` 去除 `/app`、8080 硬编码，支持 `WAF_TEST_BASE` /
  `WAF_TEST_HOME` 覆盖，默认值仍兼容官方容器 `/app:8080`。

- **php-fpm 部署下文件 DNA 控制台整体失效**：`control.php` 用 `PHP_BINARY` 拼接
  `dna.php <子命令>`，但在 php-fpm / cgi-fcgi SAPI 下 `PHP_BINARY` 指向
  `php-fpm` / `php-cgi` 二进制而非 CLI 解释器，命令会以 Usage 报错退出，导致
  `plan/status/selftest/scan/audit/baseline/rebaseline/restore/apply/watch`
  在真实生产站点上全部点了没反应（此前只在 `php -S` 的 cli-server 下验收，未暴露）。
  新增 `ctlCliPhp()` 统一解析：优先 `PHP_BINDIR/php`，再从 `PHP_BINARY` 推导
  `sbin → bin`，排除 fpm/cgi/dbg 二进制，最后交 PATH 兜底；解释器与子命令、
  参数全部 `escapeshellarg()`。守护进程 `/proc` 探活逻辑保持不变。
- **自检漏报 CLI 解释器**：`install.php --check` 新增 `PHP_BINDIR/php` 可执行性
  探测，并如实提示「CLI 与 FPM 可能使用不同 php.ini」，避免自检全绿、上线后 DNA
  按钮才发现不可用。
- **CI runner 浮动导致加密内核无法加载**：`ubuntu-latest` 自 2026-10-19 起迁移到
  Ubuntu 26，而随附 `ext/beast-8.1.so` 绑定 PHP 8.1 ABI / GLIBC_2.33。两个 job
  固定为 `ubuntu-22.04`（glibc 2.35、PHP 8.1 一等支持），并写明升级 PHP 主版本时
  必须同步重编译扩展。
- **CI 扩展安装静默失效**：`PHP_CONFIG_FILE_SCAN_DIR` 为空或只读时兜底从
  `php --ini` 解析 conf.d，显式写 `beast.enable=On`，并增加 `extension_loaded()`
  硬校验，不再只靠 `php -m` 目视。
- **CI 编排在加固主机上误判**：`php -S` 走 cli-server SAPI 加载 php.ini，而 CLI
  测试脚本走 php-cli.ini；宝塔等只在 php.ini 禁 `exec/putenv`，会让
  `control_check` 的 13 个 DNA 用例在加固主机上误报 FAIL。主服务改为
  `php -d disable_functions= -S`，使任意主机结论与 GitHub Actions 一致；
  「禁用 putenv 不整站 500」「缺扩展 503」两项降级回归仍由独立进程覆盖。
- **静态检查覆盖缺口**：`tools/static_check.php` 扫描范围与 CI 语法检查对齐，
  新增 `tools/e2e/*.php`、`demo/*.php`；`ci.yml` 语法检查补 `demo/*.php`。
  `tests/` 仍按原设计不纳入 FAIL 规则（含攻击载荷）。实测 FAIL=0 / AUDIT=3 不变。

### 变更
- 版本徽章、运行时版本常量与验收报告统一升至 v6.5.1（核心功能不变）。
- README「30 秒上手」补上 FPM 侧扩展复验方法与 `bash tools/e2e/ci.sh` 本地一键验收入口；
  原先只给 `php -m | grep beast`，与同段「CLI 不算」的告诫自相矛盾，容易误导部署者。

### 已修复的公开漏洞
- 无（本次为代码审计自测发现的兼容性 / 工程缺陷，未对外披露、无 CVE）

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
