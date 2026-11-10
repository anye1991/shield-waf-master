<p align="center">
  <img src="docs/banner.gif" alt="YSL语枢-盾甲WAF">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/版本-v6.5.0-blue" alt="版本">
  <img src="https://img.shields.io/badge/PHP-8.1%2B-777BB4" alt="PHP">
  <img src="https://img.shields.io/badge/核心保护-已加密-2ea043" alt="核心加密">
  <img src="https://img.shields.io/badge/语言-中文-important" alt="语言">
  <img src="https://img.shields.io/badge/作者-暗夜铭少-blueviolet" alt="作者">
  <img src="https://img.shields.io/badge/授权-MIT-green" alt="授权 MIT">
  <a href="https://www.bestpractices.dev/zh-CN/projects/13568"><img src="https://www.bestpractices.dev/projects/13568/badge" alt="OpenSSF Best Practices · Gold"></a>
  <a href="https://www.bestpractices.dev/zh-CN/projects/16060"><img src="https://www.bestpractices.dev/projects/16060/badge" alt="OpenSSF Best Practices · 16060"></a>
</p>

<p align="center"><sub>工程实践通过 OpenSSF Best Practices 认证（<a href="https://www.bestpractices.dev/zh-CN/projects/13568">Shield WAF</a> · <a href="https://www.bestpractices.dev/zh-CN/projects/16060">YSL 语枢</a>，2026-11 授予）</sub></p>

**嵌入式 PHP Web 应用防火墙**：以自研语义内核 **YSL-1** 判定攻击，不靠正则特征库；每个请求先过内核再进业务代码，拦截理由可查、可回放。

> **不做 Docker 镜像**：本版靠 `auto_prepend_file` 挂在站点自己的 PHP 进程里，是库不是网关——原因见 [docs/FEATURES.md §11](docs/FEATURES.md#11-为什么-php-版不提供-docker-镜像)。

<p align="center">
  <a href="#30-秒上手">快速开始</a> ·
  <a href="#核心能力">能力</a> ·
  <a href="#技术内核--ysl-1">内核</a> ·
  <a href="#实测数字">数据</a> ·
  <a href="#部署必装扩展">部署</a> ·
  <a href="#能力边界">边界</a> ·
  <a href="#文档">文档</a>
</p>

---

## 核心能力

| 能力 | 一句话说明 |
|---|---|
| **多假设语义判定** | 不猜单一上下文，保留一组解析假设，逐层归一到语法结构再定分，变形绕过在结构层现形 |
| **证据链仲裁** | 每条拦截带完整证据（规则、路径、评分、耗时），可回放定位，不做黑箱打分 |
| **AI 自学习** | 贝叶斯 / Fisher / SimHash 三路信号 + 样本审核队列，学习结果反哺权重，纯离线不联网 |
| **文件 DNA 防篡改** | 独立 CLI 守护进程，主机层第二道防线；高置信后门精准手术，中置信只告警 |
| **限流与熔断** | 1 秒滑动窗口（全局 + 单 IP），软阈值 429、硬阈值 502，真实生效（不是摆设开关） |
| **零 JS 控制台 + 大屏** | 服务端渲染，40 项功能矩阵逐项真开关，全中文，无 CDN / 图表库依赖 |

> 细节、开关清单、控制面与大屏、压测全量记录：**[docs/FEATURES.md](docs/FEATURES.md)**

## 30 秒上手

> ### ⚠️ 一条硬依赖，不是可选项
> `core/`、`ai/` 是**加密分发**，必须由随附的 **php-beast 扩展**解密才能运行。
> **没装扩展 ≠ 少个功能，而是每个请求都 503、整站不可用**（fail-closed：宁可拒绝服务，也不无防护放行）。
>
> 三个硬条件：① **PHP 必须 8.1**（`ext/beast-8.1.so` 按 ABI 编译，8.2/8.3 加载失败）；② 扩展要装进**网站进程（FPM）**那套 PHP，CLI 不算；③ 装完**必须重启 PHP-FPM**。
> 一条命令验收：`php -m | grep beast` —— 有输出才算过。

```bash
git clone <本仓库地址> /opt/ysl-waf && cd /opt/ysl-waf   # 1) 放站点之外
php install.php --check                                  # 2) 自检（缺扩展会直接中止）
php install.php --site=/var/www/html                     # 3) 接入（只写 .user.ini）
systemctl restart php8.1-fpm                             # 4) 重启生效
```

装完会打印控制台与大屏的 URL（含一次性 key）。完整步骤、报错对照表见 **[部署](#部署必装扩展)**。

## 技术内核 · YSL-1

盾甲 WAF 的判定内核是作者自研的**可执行语义规则语言「语枢 / YSL-1」**：

- **USG 超图 + 部分解析森林**：同一段载荷保留多种语法解释，不做单一路径猜测
- **四值证据域（⊥ · S · M · T）**：未知 / 结构 / 语用 / 污点四类证据分别记账，再合成判定
- **四级确定性流水线**：归一化 → 多假设解析 → 污点与路径搜索 → 仲裁，全程可复核、无 LLM 调用

> **结论边界（与论文一致）**：YSL-1 的收益在**检出率与抗变形保持率**，不在误报——语法层拿不到参数 sink 与业务上下文，误报靠 HTTP 层证据压制。论文评测为合成语料 + CSIC 2010 + 四方言留一 + 参考原型；本仓库是设计理念的 PHP 工程化落地，生产指标请以自身流量实测为准。

## 实测数字

**延迟**（PHP 8.1，正常请求 20 次；主要开销是磁盘 IO，不是 AI）

| 配置 | p50 |
|---|---|
| 默认 `var/logs`（最差情形） | 323 ms |
| `WAF_LOG_DIR=/dev/shm/waf-logs` | **52 ms** |
| tmpfs + `WAF_AI_ENABLED=0` | **29 ms** |

**检出与误报**（Docker，346 请求/轮）

| 实例 | 检出 | 误报 | p50 |
|---|---|---|---|
| A 完整 AI（默认） | **100%** | **0%** | 172 ms |
| B 纯内核（关 AI） | 99.3% | 18.89% | ~155 ms |
| C 旧版参考实现 | 75.35% | 7.22% | 684 ms |

> 口径说明：以上为自制样本 + 单站点实测，非 OWASP / CSIC 标准跑分，不作普遍性能承诺。全量压测与逐项验证记录见 [docs/FEATURES.md §12](docs/FEATURES.md#12-性能与压测明细)。

## 部署（必装扩展）

### 必装清单（按序执行，别跳步）

| # | 动作 | 完成判据 |
|---|---|---|
| 1 | 确认站点的 PHP 版本 | `php -v` 为 **8.1.x** |
| 2 | 把 `ext/beast-8.1.so` 复制到**该 PHP 的**扩展目录，命名 `beast.so` | `php -i \| grep "^extension_dir"` 查目录 |
| 3 | 启用扩展：`ext/beast.ini` 放进该 SAPI 的 `conf.d`（宝塔：PHP 设置 → 配置修改） | 内容为 `extension=beast.so` |
| 4 | **重启 PHP-FPM** | `systemctl restart php8.1-fpm` / 宝塔重载配置 |
| 5 | 验证扩展在**网站进程**生效 | `php -m \| grep beast` 有输出；站点 `phpinfo()` 里 SAPI 为 `fpm-fcgi`、扩展目录一致 |
| 6 | 自检并接入 | `php install.php --check` → `php install.php --site=/站点目录` |

> 第 5 步最容易翻车：命令行 `php` 与 FPM 常是两套（宝塔多版本尤甚）。**以站点 `phpinfo()` 的 `extension_dir` / `Loaded Configuration File` 为准**。

### 安装扩展（三种方式选一）

1. **宝塔**：装 PHP 8.1 →「设置 → 扩展」搜 `beast`；没有则用方式 2/3。
2. **手动编译**（版本须严格对应）：取 beast 源码 → `phpize && ./configure && make && make install` → `extension=beast.so`。
3. **容器**：`docker-php-ext-install beast` 不可用，把 `ext/beast-8.1.so` COPY 进**业务镜像**的扩展目录并写 `ext/beast.ini`（不是给 WAF 单开容器）。

### 验证与排错

```bash
php -v | head -1          # 必须 8.1.x
php -m | grep -i beast    # 必须有输出
php install.php --check   # 应显示「php-beast 扩展已加载」
```

| 症状 | 原因 | 处理 |
|---|---|---|
| 全站 **503**，页面写「运行环境缺少解密扩展」 | 扩展未装 / 未重启 / 装错版本 | 按上面 6 步核对 |
| 全站 **500 白屏**，日志 `Parse error` 指向 `core/Ysl*.php` | 加密内核被当明文解析，即扩展未加载 | 同上（本版已加前置体检，正常走不到这里） |
| CLI `php -m` 有 beast，网站仍 503 | CLI 与 FPM 是两套 PHP | 按站点 `phpinfo()` 的路径核对 |
| `Unable to load dynamic library 'beast.so'` | `.so` 与 PHP 主版本 ABI 不匹配 | 本包只支持 8.1 |
| 站点正常，但控制台 AI 显示未启用 | AI 层加载异常 / 缺 `pdo_sqlite` | 查 `var/logs` 的 `[ShieldWAF] AI layer` 记录，主检测不受影响 |

> 取舍说明：环境不完整时**宁可 503 也不静默放行**，所以扩展这一环必须在交付前确认——否则用户看到的是"网站打不开"，而不是"防护没生效"。

## 能力边界

- 不宣称「比雷池 / ModSecurity / 旧版更厉害」：仅自制小样本对比，无 CSIC / OWASP 标准评测、无真实绕过对抗。可确认的是**误报更少、AI 真跑、拦截不静默退化**。
- 嵌入式 WAF：护不了静态资源，也护不了 Java / Node / Go 后端；**不是反向代理**。
- `WAF_SECURITY_PATH` 未挂：内核期望的 6 个扩展类旧版并不存在，不硬凑；缺失时内核降级，主检测不受影响。
- `pdo_sqlite` 缺失时 C2 监控降级；AI 层加载失败会记日志，内核照常拦截。
- 每请求仍有多个状态 JSON + `.lock` 写盘，可用 `WAF_LOG_DIR` 挪 tmpfs；异步写留待下一阶段。
- 性能仍有偶发尖峰（单次 SLOW REQUEST），未根治，tmpfs + 关闭 AI 可显著压低 p50。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/FEATURES.md](docs/FEATURES.md) | 功能与运行细节：开关、控制台/大屏、限流熔断、DNA、压测全量 |
| [docs/E2E.md](docs/E2E.md) | 容器化验收报告：21 项功能向量、2376 条对抗样本、延迟数据、失败姿态 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 高层架构、模块边界、请求流水线、形态边界 |
| [docs/SECURITY.md](docs/SECURITY.md) | 漏洞报告流程、威胁模型、信任边界 |
| [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) | 内部安全评审报告 |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | 贡献流程、DCO、复核标准、小任务 |
| [docs/GOVERNANCE.md](docs/GOVERNANCE.md) | 治理模型、角色职责、连续性保障 |
| [docs/CODING_STANDARDS.md](docs/CODING_STANDARDS.md) | 编码规范与安全约定 |
| [docs/CODE_OF_CONDUCT.md](docs/CODE_OF_CONDUCT.md) | 行为准则 |
| [docs/ROADMAP.md](docs/ROADMAP.md) | 路线图与 non-goals |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | 更新日志与升级路径 |
| [docs/badge-application/](docs/badge-application/) | OpenSSF 徽章申报档案 |
| [LICENSE](LICENSE) · [NOTICE](NOTICE) | MIT 许可证 · 版权与许可声明 |

## 目录结构

<details>
<summary>展开查看</summary>

| 层 | 文件 | 职责 |
|---|---|---|
| 内核 | `core/Ysl*.php` × 19 | 归一化、多假设、污点追踪、路径搜索、评分、仲裁、攻击链、时间窗、蜜罐、熔断、审计 |
| AI 自学习 | `ai/*.php` × 12 | 贝叶斯、Fisher、SimHash 指纹、样本采集 / 过滤、审核队列、训练调度、AutoLearn |
| 支撑 | `Support/Functions.php` | 通用函数（JSON 原子读写等） |
| 外壳 | `shield-waf.php`、`config.php`、`console.php`、`screen.php`、`runtime.php`、`i18n.php`、`features.php`、`control.php`、`qps.php`、`pages.php`、`install.php`、`build.php` | 入口、配置、控制台、大屏、运行时、中文层、注册表、控制端点、限流 / 熔断、响应页、安装、打包 |
| 扩展 | `ext/beast-8.1.so`、`ext/beast.ini` | 解密扩展与启用配置（**硬性依赖**） |
| 验证 | `demo/`、`tests/` | 演示站与回归，不属于发行文件 |

</details>

> **语义解析层**：早期 AST 式语义层运行时开销大，v6.1.0 起默认不加载，能力由「核心结构规则 + AI 自学习」覆盖；插拔口保留，需要时设 `WAF_SEMANTIC_LAYER=1` 并放回 `semantic/`。

## 真实大屏截图

文档顶部的 GIF 是程序化**示意**。要真实截图，在有 PHP 8.1 + 扩展 + 浏览器的机器上按 [docs/SCREENSHOT.md](docs/SCREENSHOT.md) 跑一条命令即可生成。

## 版权与署名

- **作者**：暗夜铭少（anye1991）· 网站 https://waf.duduziy.com · 邮箱 azgq@foxmail.com
- **版权与许可**：© 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors，以 [MIT 许可证](LICENSE) 发布。
