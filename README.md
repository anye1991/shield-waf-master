# YSL语枢-盾甲WAF · PHP 版 v6.5.0

> **交付状态**：所有者已全权授权。本目录已本地 git 封版（v6.0.0 → v6.0.1 → v6.0.2 → v6.1.0 → v6.2.0 → v6.2.1 → v6.2.2 → v6.2.3 → v6.2.4 → v6.3.0 → v6.4.0 → v6.4.1 → v6.5.0），未配置远端、未对外推送；
> 对外发布由所有者另行决定。内核母本 `D:\core` 的 19 个 PHP 完整保留、逐字节未动；
> 本版仅 `core/YslEngine.php` 一个文件与母本不同（+350 / −3 行）。旧开源版 `D:\shield-waf-php` 未改动。
>
> v6.1.0 精简：**去掉 AST 式语义解析层（原 `semantic/` 37 个 PHP）**，只保留「核心 + AI 自学习」组合。
> 理由：语义层运行时开销大、早期还触发过 403 退化 200，对服务器资源不友好；其检测能力已由
> 核心结构规则（`hasHardAttackStructure` / `hasSqlBooleanTautology` / 污点/证据评分）+ AI 贝叶斯/费雪/指纹自学习
> 完整覆盖。语义层改为可选（`WAF_SEMANTIC_LAYER=1` 才加载），内核 `YslEngine` 的插拔口保留。
> 误报复核改为纯结构兜底，不依赖语义层，反而更稳。详见「v6.1.0 精简模式」。

## 一句话

把旧开源版 118 个 PHP / 7.2 万行里混在一起的控制台、安装器、Docker 与检测逻辑拆开，
换成 `D:\core` 语枢内核，并把旧版**本来就有、但一次都没跑起来**的完整 AI 接上；
治掉误报、堵住漏放、修掉「403 退化 200」，最后以**源码目录**交付给用户部署（`core/`、`ai/` 已用 php-beast 加密，源码不可读）。

用户站点只多一行 `.user.ini` 配置（指向本仓库的 `shield-waf.php`）。**不做 Docker 镜像**：
这是嵌入式 PHP WAF，靠 `auto_prepend_file` 在每个 PHP 请求前生效，不是反向代理网关。

## 目录结构（41 个 PHP，不含演示/测试）

| 层 | 文件 | 职责 |
|---|---|---|
| 内核 | `core/Ysl*.php` × 19 | 归一化、语义图、多假设、污点追踪、路径搜索、评分、仲裁、攻击链、时间窗、蜜罐、熔断、审计。仅 `YslEngine.php` 经授权改动 |
| AI 自学习 | `ai/*.php` × 12 | 朴素贝叶斯、Robinson-Fisher、SimHash 指纹、样本采集/过滤、审核队列、训练调度、权重反哺、AutoLearn + `bootstrap.php` 接线 |
| 支撑 | `Support/Functions.php` × 1 | 旧版通用函数（JSON 原子读写等） |
| 外壳 | `shield-waf.php`、`config.php`、`console.php`、`screen.php`、`runtime.php`、`i18n.php`、`features.php`、`control.php`、`qps.php`、`pages.php`、`install.php`、`build.php` × 12 | 入口、配置、零 JS 控制台、态势大屏、运行时配置、中文展示层、全功能注册表、控制端点、接入层 QPS 限流 / 熔断、统一响应页、安装、打包。**零检测逻辑** |
| 验证 | `demo/index.php`、`tests/ai_check.php`、`tests/fp_regression.sh` | 演示站与回归，不属于发行文件 |
| 扩展 | `ext/beast-8.1.so`、`ext/beast.ini` | php-beast 加密扩展（含本项目定制密钥）与启用配置，部署必需 |

> **语义解析层（`semantic/`，原 37 个 PHP）已在 v6.1.0 移除**：AST 式深度解析运行时开销大、对服务器资源不友好。
> 其能力由「核心结构规则 + AI 自学习」覆盖；如需启用，设 `WAF_SEMANTIC_LAYER=1` 且放回应有的 `semantic/` 目录，内核插拔口已预留。

> **核心与 AI 已加密**：`core/`、`ai/` 下的 PHP 均用 **php-beast** 加密（源码不可直接阅读），部署前必须先安装 php-beast 扩展才能运行；加密前明文在私有目录 `core-src/`、`ai-src/`（不入库，仅供作者二次开发 / 重新加密）。详见下方「核心加密与 php-beast 扩展」。

## 部署（源码模式，推荐）

> 前提：目标机 PHP >= 8.1，且已安装 **php-beast 扩展**（`core/`、`ai/` 为加密文件，不装 beast 无法运行；扩展安装见下方「核心加密与 php-beast 扩展」）。

```bash
# 0) 把本仓库放到站点之外的安全路径，如 /opt/ysl-waf
git clone <本仓库地址> /opt/ysl-waf

# 1) 环境自检（PHP >= 8.1；会提示是否已装 beast 扩展）
cd /opt/ysl-waf && php install.php --check

# 2) 一键接入已有站点（只写站点目录的 .user.ini，不碰任何业务代码）
php install.php --site=/var/www/html
#    安装结束会打印只读控制台 / 态势大屏的完整 URL（含一次性生成的 key）

# 3) 重启 PHP-FPM 使 .user.ini 生效（默认有 300 秒缓存）

# 4) 先观察再拦：在 PHP-FPM 环境设 WAF_MODE=observe，看几天误报再切回 enforce（默认）
#    /etc/php/8.1/fpm/pool.d/www.conf 里加一行：env[WAF_MODE] = observe

# 5) 卸载：还原 .user.ini
php install.php --site=/var/www/html --uninstall
```

`install.php` 做的事：在站点目录写一行 `auto_prepend_file=/opt/ysl-waf/shield-waf.php`（指向本包入口），并创建 `var/logs`、`var/data` 运行目录；**不复制任何 WAF 代码进站点**。运行时由 php-beast 在加载 `core/`、`ai/` 时透明解密，对功能与性能零影响（已实测：正常请求 200，SQL 注入 / 路径穿越 / XSS 均 403）。

本地演示（开发用，需先装 beast）：

```bash
WAF_HOME=/opt/ysl-waf \
php -d auto_prepend_file=/opt/ysl-waf/shield-waf.php \
    -S 0.0.0.0:8080 -t demo
```

> 单文件 `phar` 模式（`build.php`）为可选实验能力；phar 内加密文件与 beast 的兼容性尚未验证，**不推荐用于生产**，故本项目不开箱提供预构建 phar。

## 运行开关

> v6.3.0 起：下表开关与运行模式均可在**控制台**实时切换，写入 `var/data/runtime.json`，
> 入口每请求读取并覆盖环境变量 / 常量，下一个请求立即生效，不需要重启 PHP。
> 「恢复出厂」回到启动时的环境快照（入口在 putenv 之前冻结 `WAF_ENV_DEFAULTS`），
> 不会误把「当前值」当默认值。

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `WAF_MODE=observe` | `enforce` | 只写审计不拦截，上线前观察误报 |
| `WAF_AI_ENABLED=0` | 开 | 退回纯内核快路径；不加载 AI 自学习，叙述性误报复核自动停用 |
| `WAF_FP_GUARD=0` | 开 | 关掉叙述性误报复核，恢复母本 evidence 硬旁路 |
| `WAF_TAUTOLOGY_GUARD=0` | 开 | 关掉确定性布尔加固，交回内核/语义层原有判定（纯内核模式下即母本 `arbiter_low` 放行） |
| `WAF_BYPASS_GUARD=0` | 开 | 关掉绕过结构加固（SQL 注释拆分 / JNDI / PHP 流包装器 / SSRF / 反序列化 / CRLF / LDAP / HPP），恢复母本原有判定 |
| `WAF_SEMANTIC_LAYER=1` | 关 | **默认不加载**语义解析层（v6.1.0 起精简为核心+AI 模式）。设 1 且 `semantic/` 存在才加载 AST 式深度解析 |
| `WAF_LOG_DIR=/dev/shm/waf-logs` | `<站点>/var/logs` | 把高频状态/审计写放到内存盘，**性能提升最大的一项** |
| `WAF_DATA_DIR=...` | `<站点>/var/data` | 控制台密钥目录 |
| `WAF_KEEP_DISPLAY_ERRORS=1` | 关 | 排查时临时恢复错误输出（生产不要开） |

`WAF_LOG_DIR` 放 tmpfs 时审计日志会在重启后丢失，需要留存审计的场景请用持久化磁盘；
`install.php` 写出的 `.user.ini` 与运行时读同一组变量，设了自定义目录请在 PHP-FPM 环境里设同样的值。

## 性能（Docker / PHP 8.1，正常请求 20 次）

内核每请求要写攻击链、时间窗、熔断状态与审计，磁盘 IO 是主要开销，不是 AI 计算。
以下为源码模式实测；Docker / Windows bind mount 是最差情形，仅用于对比。

| 配置 | p50 | 相对默认 |
|---|---|---|
| 默认 `var/logs`（Windows bind mount，最差情形） | 323 ms | — |
| `WAF_LOG_DIR=/dev/shm/waf-logs` | **52 ms** | −84% |
| tmpfs + `WAF_AI_ENABLED=0` | **29 ms** | −91% |

参考：同为源码目录模式，挂载方式不同也会带来差异（如 Windows Docker bind mount 上 phar 映射约 354 ms、源码模式约 229 ms）；生产 Linux + PHP-FPM + OPcache 不适用这组数字，以上表 tmpfs 实测为准。
`WAF_AI_ENABLED=0` 是可选的快路径，代价是没有语义层与自学习增强，误报复核也不启用。

## 内核改了什么（仅 `core/YslEngine.php`）

1. **修语义层作用域**：本文件通常在 `YslWaf::inspectCurrentRequest()` 方法内部被 require，
   原 `$semanticAvailable` 只是局部变量，而 `layer2Semantic()` 读 `$GLOBALS`。结果 CLI 自检
   显示 `semantic=true`，HTTP 请求里语义层一次都没跑。现在显式同步 `$GLOBALS`。
2. **堵住 403 退化 200**：语义层真跑起来后，`LogicInference.php` 与
   `RegexdosSemanticParser.php` 的未定义键 Warning 输出到响应体、提前发出 header，
   使 `reject()` 的 `http_response_code(403)` 失效。入口统一 `display_errors=0` +
   错误导向日志，并修掉两处未定义键。
3. **叙述性误报复核**：语义图是词法驱动的，普通英文里的 `union`、`<script>` 也会被当成
   SQL/XSS 节点，一旦 `evidence_decision=block` 就给 100 分一票否决。现在仅当
   「语义层已接线 + 参数是纯自然语言（字母空白 ≥80%、≥4 个词）+ **没有任何真实攻击结构**
   + 语义层未识别出具体攻击意图」时，把 block 降级为 monitor（200 但照常写审计，
   `reason=fp_narrative_override`、`arbiter.fp_narrative_override=true` 可回溯）。
   结构黑名单覆盖引号闭合逻辑、`union…from`、SQL 注释/延时函数/系统表、`<script>` 后跟
   可执行 JS、事件属性、伪协议、路径穿越、命令注入、模板/反序列化骨架；任一命中保持 403。
4. **布尔恒真式加固**：母本对无引号布尔条件（`id=1 OR 1=1`）只给 33 分走
   `arbiter_low` 放行。现在用确定性结构判定（`or/and` + 两侧字面量比较）补齐 403，
   `reason=sql_boolean_tautology`；不依赖 AI/语义层，纯内核模式同样生效，
   已有 hard block 时不重复介入以保持原有审计语义。回退 `WAF_TAUTOLOGY_GUARD=0` 后
   由内核/语义层原有判定接手（实测 reason 变为 `arbiter_high`，纯内核下回到 `arbiter_low` 放行）。
5. **绕过结构加固**：横向对比发现母本 + 语义层对 SQL 注释拆分
   （`UN/**/ION SEL/**/ECT … FROM users`）、JNDI（`${jndi:ldap://…}`）、
   PHP 流包装器（`php://filter/…`）会给低分放行，而旧开源版规则层能拦。
   这三类有确定语法特征、不会出现在自然语言里，用 `hasHardAttackStructure()`
   在仲裁前确定性拦截，`reason=bypass_structure_block`；不依赖 AI/语义层，
   纯内核模式同样生效。回退 `WAF_BYPASS_GUARD=0`。
6. **PHP 8.1 Deprecated**：`scoreToRisk(int $score)` 一处调用直接传 float（45.2），
   PHP 8.1+ 报 `Implicit conversion from float to int`；改为显式 `(int)round()`，
   全仓 0 Fatal / 0 Warning / 0 Deprecated。
7. **v6.0.2 Docker 压测暴露的漏放 + 中文误报**：疯狂测试里完整 AI 冷态仍有 9 条漏放
   （metadata SSRF `http://169.254.169.254/...`、`gopher://` / `dict://` 危险协议、
   `rO0AB…` Java 序列化、`cos\n…system…` pickle 反序列化骨架、CRLF 头注入、
   LDAP `)(cn=*)(|(objectClass=*` 骨架、`id=1&id=2&id=3` HTTP 参数污染、CRLF + 参数污染），
   以及 2 条中文叙述性热态误报（含 `select、from、where` 的 SQL 教程句）。
   前者在 `hasHardAttackStructure()` 补上危险协议 / 序列化 magic / CRLF / LDAP 骨架 /
   HPP 等确定性结构，并与安全黑名单联动，任一命中保持 403；后者修
   `isNarrativeFalsePositive()` 的 Unicode 自然语判定，让中文叙述句也走
   `fp_narrative_override` 降级，不再被 `arbiter` 误判成 403。

其余 18 个 `Ysl*.php` 与母本逐字节一致。

## AI：代码本来就在，之前是「线没接上」

旧开源版 `D:\shield-waf-php` 的 `src/Learn`（11 个）与 `src/Semantic`（36 个）是完整实现，
语枢内核 `YslAiBridge.php` 的类名本来就是照这套写的。断在四处，现已接通：

| # | 断点 | 处理 |
|---|---|---|
| 1 | `YslAiBridge` 在 `core/` 找 9 个 `Learning_*.php`，实际文件名无前缀 → 全部跳过 | `ai/bootstrap.php` 预加载，类名全部对上 |
| 2 | `checkColdStart()` 读 `total_samples`，旧版给 `*_count` → 每次判冷启动 | 副本补 3 个别名；训练 30 条后 `cold_start=false` |
| 3 | `WAF_SEMANTIC_PATH` 未定义 → 16 个解析器与误报卫士全闲置 | bootstrap 定义常量并加载 `SemanticEngine` + `WafNormalizer` |
| 4 | `collectAttack` / `add` / `get` / `adjustWeights` / `getWeights` 契约不一致 | 在 `ai/` 副本里做最小适配，三条样本分流实跑通过 |

接线时修掉 3 个真实运行期缺陷：`predict()` 与 `getScoreDimensionsSafe()` 无限递归撑爆内存；
中文 UTF-8 按字节切出半个字符导致 `json_encode` 失败、`bayes_model.json` 写成 0 字节；
以及上面两处作用域/Warning 问题。

## v6.1.0 精简模式（核心 + AI）

> 背景：早期版本把「AST 式语义解析层」（`semantic/`，37 个 PHP、`SemanticEngine` + 16 个深度解析器 +
> `WafNormalizer` 同形字映射）默认加载。压测与运行期都显示它开销大、还曾触发 403 退化 200，
> 对服务器资源不友好。v6.1.0 起**默认不再加载该层**，只留「核心结构规则 + AI 自学习」组合。

检测能力由以下两部分承担，不再依赖语义树解析：

- **核心结构规则**（`core/YslEngine.php`，纯 PHP、零外部依赖）：
  `hasHardAttackStructure()`（SQL 注释拆分 / JNDI / `php://filter` / metadata SSRF / gopher·dict 协议 /
  Java·pickle 反序列化 / CRLF 头注入 / LDAP 注入骨架 / HTTP 参数污染）、
  `hasSqlBooleanTautology()`（无引号布尔恒真）、污点追踪、证据评分、`YslArbiter` 多票仲裁。
- **AI 自学习**（`ai/`）：朴素贝叶斯、Robinson-Fisher、SimHash 指纹、样本采集/审核队列、训练调度、
  AutoLearn 权重反哺，全部在原始载荷文本上跑，不建语法树。

误报复核（`isNarrativeFalsePositive()`）从「依赖语义层意图确认」改为**纯结构兜底**：
只要没有任何真实攻击结构、且主体是自然语言（Unicode 字符数 + 字母/空白占比判定，中文同样识别），
就降级放行。删掉语义层后这条路径反而更稳，不再有「语义层没接线就不放行」的死锁。

语义层并非删除不可恢复：设 `WAF_SEMANTIC_LAYER=1` 且把 `semantic/` 放回，内核 `YslEngine` 顶部
经 `WAF_SEMANTIC_PATH` 预留的插拔口会自动重新接线（旧版 `AiBridge` / `Arbiter` 的语义维度本就支持缺失降级）。

## 控制台（零 JavaScript）

`/waf-console?key=<安装时打印的 key>`。上半部分是**只读统计**：审计事件、拦截原因分布、
最近事件、熔断状态，以及从审计日志真实字段统计的 AI 信号覆盖、贝叶斯样本数、
冷启动降级、语义分命中、误报复核放行、布尔加固拦截、绕过结构拦截与当前运行配置。
没有数据就显示「暂无」。下半部分是**原生 POST 表单操作**：直接提交到 `/waf-control`，
经密钥 + CSRF 校验后真实执行，结果页回显，不做「点了保存其实没落盘」的假功能；
危险操作用勾选框做零 JS 二次确认。只读区另有**接入层 QPS 状态快照**，
下半部分表单可改 5 个 QPS 阈值、启停保护、复位与演练熔断。完整分组控制面在态势大屏的控制台抽屉。

## 态势大屏

`/waf-screen?key=<同一把 key>`，全屏可视化 + **控制台抽屉**，与零 JS 控制台互补：
控制台保持零图表以便在 CSP 与离线环境工作，大屏专注演示、值守与实际操作。

- 纯服务端渲染 + 内联 CSS/SVG，原生 JS 仅做 5 秒增量刷新，不引 CDN、图表库、外部字体
- 全部指标由 `attack.log` 与状态文件真实聚合：流量趋势面积图（拦截 / 观察）、决策分布
  环形图、拦截原因 TOP、攻击类型 TOP、威胁评分直方图与处置耗时分位、实时审计事件流、
  来源 IP 与攻击链阶段、**文件 DNA 完整性**（主机层第二道防线）、加固开关与熔断状态
- 无数据即显示「暂无」，不放占位数字；时间统一按北京时间 UTC+8 展示并标注
- `?format=fragment` 返回可增量替换的视图片段，`?format=json` 供外部系统取数，
  `?static=1` 输出**不含密钥**的静态快照，可另存为独立 HTML 演示
- **QPS 限流与熔断面板**：当前 QPS 大数字 + 阈值进度条 + 8 项真实指标（峰值 / 状态 /
  冷却剩余 / 累计请求 / 单 IP 阈值 / 累计拒绝 / 追踪来源 / 触发原因）+ 5 盏分项灯；
  标题总灯与底栏汇总灯同源，`?format=json` 同步输出 `qps` / `qps_lamps`
- **文件 DNA 指示灯**：标题总灯 + 面板分项灯（巡检心跳 / 基线签名 / 本轮完整性 / 处置模式）
  + 底栏汇总灯；绿=正常、琥珀=注意或只读降级、红=签名异常或本轮检出后门、青=未建档。
  灯位全部取自 `dna-status.json` 真实字段，带呼吸动效，随 5 秒片段刷新，且是只读指示不可点击
- key 鉴权（复用 `var/data/console.key`；运行目录指向 tmpfs 时回退到持久副本），
  大屏与控制台路由均在检测之前分发，自身轮询不会计入攻击日志；控制操作另经
  CSRF + 动作白名单 + 危险二次确认，静态快照不含密钥 / CSRF 且禁用全部控制按钮

## 控制面与运行时配置（v6.3.0）

原版开关都是「进程启动时读环境变量」，Web 请求改不动已启动进程的环境。
v6.3.0 引入持久化运行时覆盖，让控制台按钮真能生效：

- `var/data/runtime.json`：只接受白名单字段（模式 / 5 个开关 / body 上限 / 硬旁路白名单），原子写 + 0600
- `shield-waf.php` 每请求读取 → 覆盖 `$wafConfig`（mode / max_payload_bytes / whitelist_cidrs）、
  `putenv()` 重置 getenv 型开关、`define('WAF_FP_NARRATIVE_GUARD')` 常量；文件不存在时与旧版完全等价
- `/waf-control`：唯一写入口。仅 POST + key + 无状态 CSRF（HMAC(key, 小时时间片)）+ 动作白名单；
  危险动作必须 `confirm=1`；每个动作真实落盘 / 真实执行后**回读状态**返回，前端据此更新按钮与指示灯
- 操作审计写 `logs/ysl/control.log`，单独于 `attack.log`，不污染态势指标

动作清单（39 个后端动作 + 10 个视图控制，大屏 44 个控制按钮）：

| 分组 | 动作 |
|---|---|
| 运行配置 | 模式切换、5 个防护开关、body 上限、白名单增 / 删 / 清空、恢复出厂 |
| 熔断与状态 | 熔断复位 / 演练 open / 强制关闭；清理 window / chain / honeypot / lock |
| QPS 限流 | 5 个阈值配置、启停保护、复位计数、演练 502 熔断、强制恢复、读取实时状态 |
| AI 自学习 | 重置贝叶斯模型、清空训练与审核队列、清空 SimHash 指纹库 |
| 审计日志 | 归档 attack.log、导出 jsonl、清空 attack.log |
| 文件 DNA | plan / baseline / scan / audit / apply / rebaseline / status / selftest / restore / watch 启停 |
| 访问控制 | 轮换控制台密钥（返回新 key 与新 CSRF）、读取控制审计 |
| 大屏视图 | 暂停轮询、3/5/10/30s 间隔、立即刷新、全屏、静态快照、只读控制台、关闭面板 |

未做成按钮的功能（如实标注）：`Support/Functions.php` 里的 webhook 告警、信任 CF IP、
日志大小上限、测试模式等旧版函数**未被当前内核调用**，做成按钮只会是假功能，
因此只保留在代码里、不在控制台暴露；`semantic/` 语义层自 v6.1.0 起默认不打包，
`WAF_SEMANTIC_LAYER` 开关同样无实际作用。

## 蜜罐受控启用 + 全功能控制矩阵（v6.5.0）

反馈两句：「蜜罐这个不能随便开启」「我在监控没有看到所有功能都能控制」。
核查结论：原先蜜罐在内核里每请求自动实例化并检测，控制面只有「清理蜜罐索引」，
既没有总开关、也没有风险闸门；大屏底栏那排状态灯被标成「只读指示 · 非按钮」，
所有开关又都藏在右上角抽屉里，监控主界面确实看不到逐项控制。

### 蜜罐：默认停用，启用要过四道闸

蜜罐不是普通检测规则：触碰诱饵会延迟响应、投喂假数据、把来源 IP 标记为
「确认恶意」（仲裁加 40 分）。误开会拖慢正常流量、污染攻击链，因此改成默认关闭。

- `runtime.json` 新增 `honeypot` 段（enabled / until / enabled_at / by / reason），
  默认停用；入口每请求下发 `WAF_HONEYPOT_ENABLED`
- `core/YslEngine.php` 只加两处守卫：`initSubsystems()` 不实例化 `YslHoneypot`、
  `checkHoneyPot()` 直接短路，**检测逻辑一行不改**，模块检测与内联兜底一起关
- 控制端点新增 `honeypot.enable` / `honeypot.disable` / `honeypot.state`。
  启用必须同时满足：二次点击确认 + 手动输入「启用蜜罐」四个字 + 有效期 1~240 分钟
  + 用途留痕；少一项都不写盘。关闭是安全侧动作，一键立即生效、无需确认
- 有效期届满由入口原子写回停用并写 `control.log`，避免「演练完忘记关」
- 大屏蜜罐专区用红色高危样式，显示状态灯、倒计时、用途、触碰次数；
  零 JS 控制台同步提供中文状态表与原生表单

`tests/honeypot_check.php` **32/32**：反射进内核验证关闭时不实例化蜜罐、
`checkHoneyPot()` 直接返回 false，开启时才实例化；四道闸门逐项拒绝、合规启用回读一致、
审计中文留痕、到期自动停用、页面可见可控、收尾环境复位。

另做真实 HTTP 行为复核（不是只看状态）：停用态 `/panel/debug/` 266 ms、
`/dev/console` 209 ms、命中日志 0 条；合规启用后同路径 4229 ms / 7288 ms
（诱捕延迟）并各写入 1 条命中日志 —— 开关确实改变了内核行为。
顺带修掉一个真实缺陷：蜜罐命中写在 `honeypot/hits_*.jsonl`，
而 `attack.log` 里 `honeypot` 字段恒为 `false`，原先按 attack.log 统计触碰次数会永远是 0；
现在统一从命中日志统计，`honeypot.clear` 也一并清理 `.jsonl` 与索引锁文件。

### 全功能控制矩阵：监控里逐项可见、逐项可点

- 新增 `features.php` 作为唯一功能注册表：**40 项功能分 5 组**，状态灯与状态文字
  全部取自 `runtime.json` / QPS 快照 / DNA 状态 / 熔断快照 / 日志大小 / 守护 PID，
  **不编数字**；每条记录都绑定 `control.php` 里真实存在的动作
- 大屏主区域新增「全功能控制矩阵」面板，显示 `40/40 项可控`；每张卡片有状态灯、
  中文状态、功能说明、真实操作按钮和「详细」直达按钮
- 底栏状态灯从「只读指示 · 非按钮」改成**可点击**，点击打开控制台并滚动到对应分区高亮；
  新增蜜罐指示灯；抽屉 9 个分区全部带定位 id
- 常驻内核能力（污点追踪、仲裁器、C2 监测等）如实标注为「只读 / 可维护」，
  配真实的状态回读或状态文件维护动作，**不冒充开关、不放假按钮**
- JSON 接口与静态快照输出同一份矩阵；静态快照仍不含密钥 / CSRF，所有控制按钮禁用

`tests/feature_matrix_check.php` **37/37**：逐条比对页面所有 `data-act` 与
`control.php` 动作白名单（无假按钮）、覆盖数 = 总数、灯态合法、定位目标存在、
静态快照安全约束、零 JS 控制台与全中文展示。

## 界面全中文化（v6.4.1）

反馈：控制台「熔断状态」直接显示 `closed`，普通用户看不懂。核查后发现不止这一处：
运行模式（`enforce` / `observe`）、QPS 触发原因码、响应页英文徽标、按钮上的命令名
（`plan` / `scan` / `status`）、以及控制台把整段英文 JSON 快照原样输出，都是同类问题。

改动原则是**只改展示层、不动机器契约**：

- 新增 `i18n.php`，集中映射熔断状态 / 运行模式 / 原因码 / 防护开关 / QPS 参数 /
  文件 DNA 命令 / 控制动作名。状态文件、`runtime.json`、控制端点 JSON 里的枚举
  **仍保留英文原值**，状态机判断与外部对接不受影响
- `closed` → 正常放行、`open` → 熔断中、`half_open` → 半开试探、
  `enforce` → 强制拦截、`observe` → 观察模式；未知值统一中文兼底
- 零 JS 控制台的熔断 / QPS 快照从「整段英文 JSON」改成**中文键值表**，原始快照
  收进可折叠的「排障用」区域，既不丢信息又不再砸给用户一堆英文
- 403 / 429 / 502 / 503 / 413 页面的英文徽标、品牌副标、页脚标签改为中文；
  风险等级、拦截原因、触发维度、熔断状态全部中文
- 控制台按钮、大屏抽屉按钮、操作结果回显、控制审计列表全部中文；按钮 `title`
  也是中文动作名。大屏轮询回显通过内嵌的同源中文映射表转换
- `control.log` 是只追加的真实审计，中文化之前写入的历史英文记录**不改写文件内容**，
  而是由 `wafCtlRecent()` 在读取时补一份中文视图（`detail_cn` / `action_cn`）
- 刻意保留的技术标识：WAF / QPS / IP / AI / DNA 等通用缩写、真实文件名
  （`attack.log`、`runtime.json`）、请求路径、请求编号 —— 这些是数据或行业术语，
  翻译成汉语反而会让运维对不上

`tests/i18n_check.php` **31/31**：按「剔掉脚本 / 样式 / 折叠区后取可见文本」的方式逐页断言
不裸露英文状态枚举，同时反向断言 JSON 契约里的 `qps.state` 仍是英文原值。

## QPS 限流、熔断与美化响应页（v6.4.0）

### 先说清楚原来「有代码但没生效」

内核 `core/YslCircuitBreaker.php` 写了四档 QPS 降级与一套 429 熔断页，但滑动窗口
`$requestTimestamps` 是**对象实例属性**：PHP 每个请求重建对象，窗口计数恒为 0/1，
`circuit_state.json` 长期是 `qps:0 / total_requests:1` —— 自动熔断从未被真实触发，
只有控制端点手工写 `open` 才有效；那套 429 页面也从未被调用。实际拦截响应是
`YslWaf::reject()` 输出的一句纯文本 `Request rejected.`（text/plain）。
`core/` 是封存原版禁止改动，因此 v6.4.0 在外壳补齐真实生效的接入层与统一呈现层。

### 接入层 `qps.php`

- `flock` 独占锁 + `logs/ysl/qps_state.json`，10 个 100ms 桶组成 1 秒滑动窗口（O(1)，不存大数组），
  全局与单 IP 双维度；IP 只存 sha256 前 12 位，60 秒不活跃自动清理，最多 128 个
- 软阈值 → **429 限流**；硬阈值 → **502 保护性熔断**；熔断期间到达的请求不再累加窗口
  （否则窗口永远满、半开时立刻重新熔断），冷却结束自动半开试探，连续 3 次成功转 `closed`
- 默认：全局 300 / 600 QPS，单 IP 80 / 160 QPS，冷却 30 秒；全部可在控制台实时改
- 配置写 `var/data/runtime.json` 的 `qps` 段，逐字段范围校验，非法值回落默认；
  停用保护后仍照常计数，只是不拦截
- 管理路由在入口分发时已 `exit`，**大屏轮询 / 控制台 / 控制端点天然豁免**，不会把自己熔断
- 状态文件不可写时 fail-open 并记 `error_log`，绝不因限流模块把站点打挂
- 内核 `YslCircuitBreaker` 保留为内核内部降级信号，但不再承担跨请求限流判定

### 统一响应页 `pages.php`

| 状态码 | 含义 | 页面内容 |
|---|---|---|
| 403 | 安全规则拦截 | 红色 · 中文拦截原因、原始规则标识、威胁评分、风险等级、检测耗时 |
| 429 | QPS 限流 | 琥珀 · 当前 QPS、软/硬阈值、窗口峰值、触发维度、`Retry-After`、倒计时环 |
| 502 | 保护性熔断 | 红色 · 电路波形、冷却剩余、自动重试、`X-WAF-Circuit: open` |
| 503 | 故障关闭 | 紫色 · 内核异常 / 缺失，拒绝带病服务 |
| 413 | 请求体超限 | 琥珀 · 提示在控制台调整上限 |

- 零外部资源、零 JavaScript：内联 CSS / 内联 SVG / 系统字体，倒计时用 CSS 动画 + meta refresh；
  不会再出现「整页 JS 被 CSP 挡」
- 严格 CSP `script-src 'none'`、no-store / nosniff / DENY / no-referrer
- 所有字段来自真实上下文（请求编号、北京时间、客户端 IP、URI、内核 reason、QPS 快照），
  全部转义后输出；没有演示占位数字，也不回显堆栈

### 大屏与控制面

- 新增「QPS 限流与熔断」面板：当前 QPS 大数字 + 阈值进度条 + 8 项真实指标 + 5 盏分项灯；
  标题总灯 / 底栏汇总灯同源，`?format=json` 同步输出 `qps` 与 `qps_lamps`
- 控制台抽屉与零 JS 控制台都能：改 5 个阈值、启停保护、复位计数、演练 502 熔断、
  强制恢复、读取实时状态；演练熔断后另开窗口访问站点首页即可看到 502 美化页
- 静态快照仍然不含密钥 / CSRF，全部 44 个控制按钮禁用

## 文件 DNA 防篡改（主机层）

请求内检测是网络层第一道防线；`dna.php` 是**独立 CLI 进程**，负责主机层第二道防线：
站点脚本被插马 / 被改配置时，即使请求没触发任何 WAF 规则也能发现并处置。
它不在 `auto_prepend_file` 管线里，不增加任何请求耗时。对齐 Go 母本 `internal/dna` 的口径：

| 能力 | 实现 |
|---|---|
| 建档 | 递归扫描 `.php/.phtml/.phar/.inc/.jsp/.asp/.py/.sh/.cgi` 与 `.htaccess/.user.ini`，排除 uploads/cache/var/logs/tests/dist 等噪音目录；记录 SHA-256、权限、大小、mtime |
| 基线防伪 | HMAC-SHA256 签名，密钥独立存 `.baseline.key`（0600、O_EXCL 创建）。**签名不可信时强制只读**，绝不拿可疑基线覆盖生产文件 |
| 备份自证 | 每轮复验备份副本哈希，文件与备份同时异常判 `dual_tamper` 并拒绝还原 |
| 恶意识别 | 高 / 中置信分级 + 递归解码（base64 / gzinflate / rot13 / hex / url，最多 5 层）后复扫，抓编码链后门 |
| 处置铁律 | **只有高置信才动手**：精准手术切除恶意语句 → 术后复扫自校验 → 失败才整体还原；中置信（`system`/`exec`/`include` 在 CMS 插件里是合法写法）只告警 |
| 留档 | `infected` / `quarantine` / `surgery` 三类副本 |
| 新文件 | 落地即扫，高置信后门直接隔离并移出站点目录 |
| 大屏 | 状态快照 `var/data/dna-status.json` 单独落盘（不碰审计哈希链），面板展示健康度、建档数、签名、篡改 / 隔离 / 手术计数与最近事件；心跳超 180 秒判「未运行」。标题总灯、面板四盏分项灯与底栏汇总灯按真实字段亮绿 / 琥珀 / 红 / 青，`?format=json` 同步输出 `dna_lamps` |

```bash
php dna.php plan                          # 试算范围，不建基线、不写文件
php dna.php baseline                      # 建档 + 备份 + 签名
php dna.php scan                          # 巡检（默认只读告警）
php dna.php scan --apply                  # 处置高置信篡改
php dna.php rebaseline                    # 更新插件 / 主题后接受新状态
php dna.php restore --file=demo/x.php     # 从备份还原单个文件
php dna.php status                        # 状态快照 JSON
php dna.php selftest                      # 能力自检（不写文件，19 项）
php dna.php watch --interval=30 --apply   # 轮询守护
```

默认只读，`--apply` 才处置；`--no-surgery` / `--restore-any` / `--adopt-new` 调整处置口径。
**默认不对「无恶意特征的普通变更」自动还原**，避免把运维正常改的文件覆盖掉；
需要强防篡改语义时显式加 `--restore-any`。PHP 版没有 inotify，用轮询守护兜底，
实时性弱于 Go 母本的事件驱动——这是如实标注的边界。

## 能力边界（如实标注）

- **不宣称「比雷池 / ModSecurity / 旧版更厉害」**：本版只在一组自制用例上与旧开源版
  做过同组请求对比（下节），没有 CSIC / OWASP 等标准数据集的检出率与误报率评测，
  也没有做过真实绕过对抗。可确认的是「误报更少、AI 真跑、拦截不静默退化」，
  不是「总体能力更强」。
- **嵌入式 PHP WAF**，护不了静态资源，也护不了 Java / Node / Go 后端；不是反向代理网关。
- **不做 Docker 镜像**。目标是把文件收少、把不可信路径删掉，以源码目录交付（`core/`、`ai/` 已加密，需装 php-beast）。
- `WAF_SECURITY_PATH` 仍**未挂**：内核期望的 6 个扩展类
  （`UploadSecurity`/`Sandbox`/`AntiCrawler`/`CcProtection`/`MagicGate`/`Auth`）旧开源版里
  并不存在，不硬凑；缺失时内核降级，主检测不受影响。
- `pdo_sqlite` 缺失时 C2 监控降级；AI 层加载失败会被外壳捕获记日志，内核照常拦截。
- `healthCheck` 的 fingerprint 项首次运行恒为 `false`（内核相对路径检查 + 指纹库为空），
  属内核硬编码，不影响检测。
- 攻击日志只展示 `attack.log` 最近 300 条；内核 `YslAudit` 有完整检索接口，未接 Web 端。
- 每请求仍有 chain / window / circuit 多个 JSON + `.lock` 写盘；可用 `WAF_LOG_DIR`
  挪到 tmpfs，未改内核的写入语义。异步写留待下一阶段。
- 性能仍有偶发尖峰：回归过程中出现过单次 2.0 s 的 `SLOW REQUEST`（母本状态写 +
  早期语义层首次加载），tmpfs 与 `WAF_AI_ENABLED=0` 可显著压低 p50，但未根治。
  v6.1.0 精简模式去掉语义层后，该「首次加载」尖峰已消除，稳态更平稳。

## 与旧开源版的横向对比（自制小样本，非权威评测）

同一组请求分别打旧版 `D:\shield-waf-php`（`WAF_ALLOW_PRIVATE_HOST=true`，
排除私网 Host 误拦）与本版 phar。为避免旧版连续攻击后自动封禁测试 IP，
每组用例在清理其运行数据后单独起容器。

| 类别 | 旧版 | 本版 v6.0.2 |
|---|---|---|
| 正常 / 叙述性文本（6 条） | 4 条 403（误报） | 6 条 200 |
| 常见注入 / XSS / 路径穿越（7 条） | 全 403 | 全 403 |
| 绕过载荷（SQL 注释拆分、双重编码、大小写混合、JNDI、SSTI、反序列化、`php://filter`、XXE 等） | 全 403 | 修前 3 条 200（SQL 注释拆分 / JNDI / `php://filter`），v6.0.1 后全 403 |

结论：本版在**误报**上明确优于旧版，在**这组用例的检出**上打平；
但这只说明「自制小样本里没变差」，不能外推为整体能力更强。旧版还带有
自动封禁、蜜罐、CC 防护、沙箱、后台配置等本版刻意精简掉的功能面，
产品能力与覆盖面本版更窄。

## Docker 疯狂测试压测结果（自制小样本，非权威评测）

按「丢进 Docker 自己狂测」的要求搭了 `wafstress-net` + 三套服务容器：
`wafs-a`（本版完整 AI，phar 单文件）、`wafs-b`（本版纯内核 `WAF_AI_ENABLED=0`）、
`wafs-c`（旧开源版对照，`WAF_ALLOW_PRIVATE_HOST=true` + `WAF_TEST_MODE=true` 排除私网 Host 误拦与自动封禁干扰），
外加 `stressbox` 用 208 条载荷展开为** 346 请求/轮**，跑冷态 + 热态，结果同步落 `tests/result_*.json`。

| 实例（配置） | recall | fpr | accuracy | evade | p50 | p99 | max | 备注 |
|---|---|---|---|---|---|---|---|---|
| A 完整 AI（冷态） | **100%** | **0%** | **100%** | 22/24 | 172.2 ms | 259.9 ms | 573.4 ms | 0 漏放 / 0 误报 |
| A 完整 AI（热态） | **100%** | **0%** | **100%** | 22/24 | 173.3 ms | 5221.7 ms* | 8234.8 ms* | 0 漏放 / 0 误报；p99/max 偶发尖峰见下 |
| B 纯内核（冷/热） | 99.3% | 18.89% | 89.13% | 21/24 | ~155 ms | ~177 ms | ~280 ms | 漏 1 条 `'; DROP TABLE users--`；误报 34 条含普通英文 `union` / `<script>` 文档句 |
| C 旧版（冷态） | 75.35% | 7.22% | 85.09% | 22/24 | 684.1 ms | 855.8 ms | 886.7 ms | 漏 35 条（基础 `' OR 1=1` 也漏）、误报 13 条 |

（*A 热态 p99/max 的 5–8 s 尖峰是单次请求在 Docker / Windows bind mount 上的 IO 抖动，非稳定延迟；
冷态与稳态 p50 仅 172–173 ms，且全程 0 Fatal / 0 Warning / 0 Deprecated。）

**关键结论（只在本组自制样本内成立，不宣称权威）**：
- 完整 AI 模式（A）相对旧版（C）：检出率 **100% vs 75.35%**，误报率 **0% vs 7.22%**，延迟 **172 ms vs 684 ms**，三项全面占优。
- 纯内核快路径（B）是「不要 AI、只要快」的取舍：检出率仍 99.3%，但因没有语义层/自学习去歧义，
  普通英文 `union`、`<script>` 文档句等被误拦（fpr 18.89%）。生产默认走 A。
- 旧版（C）连基础 `' OR 1=1--`、`admin'--`、`<details open ontoggle=...>` 都漏，说明其规则面虽宽、本组样本下实际检出弱。
- B 漏的 `'; DROP TABLE users--`（堆叠注入）属母本 `arbiter` 在纯内核下的已知边界，A 模式靠语义/AI 兜住，本版未为纯内核专门补。

压测语料与脚本存于 `stressbox:/tmp/stress.php`（明文攻击语料只在容器内、不落 Windows 盘，避免 Defender 误判）；
结果 JSON 在 `tests/result_*.json`。

### v6.1.0 精简模式压测复核（核心 + AI，无语义层）

去掉 `semantic/` 后，单独搭 `waflean-net` + `waflean2`（精简 phar 单文件，`WAF_AI_ENABLED` 默认开）+ `stressbox2`
用端到端载荷做复核，确认「丢语义层不漏关键攻击」。首轮用 67 条，随后**扩充到 78 条**（12 良性 + 66 攻击，
覆盖 sqli / xss / traversal / cmdi / ssti / jndi / deser / ssrf / crlf / xxe / ldap / nosql / hpp，
并特意加入多种斜杠形态 `C:\windows` / `C:/windows` / `C://windows` / `..\..\windows` / `....//....//boot.ini`），
正是这次更狠的压测又揪出 2 个真 bug（见下表第三轮）。

| 轮次 | 配置 | 误报（良性被拦） | 漏放（攻击放过） | 备注 |
|---|---|---|---|---|
| 首轮（67 条） | 仅核心 + AI，未补结构规则 | 0 | **3** | `'; DROP TABLE users--`、`` || ping -c 1 127.0.0.1 ``、`C://windows//win.ini` |
| 补 3 条确定性结构规则后（67 条） | 核心 + AI + 新增结构规则 | 0 | **0** | 堆叠查询 / 命令链扩充名单 / Windows 绝对路径（含双斜杠）全部命中 |
| **扩展压测（78 条，多斜杠形态）** | 核心 + AI + 3 规则 | **1** | **1** | 真 bug：① 良性中文叙述「含 select/from/where…」被 AI 自学习推到 80+ 分误拦，且随 AI 状态抖动（403/200 非确定性）；② `....//....//boot.ini` 点填充穿越漏放 |
| **修 2 处后（78 条，clean + poisoned 两态）** | 核心 + AI + 全部结构规则 | **0** | **0** | 叙述性误报复核去掉分数门槛；穿越正则支持点填充/双斜杠；clean 与 AI 被攻击流量污染两种状态下均 0/0 |

新增的 3 条确定性结构规则 + 2 处压测暴露的修复（`core/YslEngine.php`）：

1. SQL 引号闭合段内堆叠查询：`/;\s*(?:drop|delete|insert|update|truncate|alter|create|exec|replace|grant)\b/i`（兜 `'; DROP TABLE users--`）；
2. 命令链段扩充可执行命令名单（含 `ping`/`telnet`/`nslookup`/`dig`/`ftp`/`sleep`/`powershell`/`cmd`/`kill`/`rm`/`mv`/`cp` 等）；
3. Windows 绝对路径读取，斜杠类型与数量通配：`/(?:[a-z]:[\\\/]+)(?:windows|winnt|system32|boot|inetpub|users|program)/i`
   （兜 `C:\windows\win.ini` / `C:/windows/win.ini` / `C://windows//win.ini` 等形式）；
4. **（压测修复）叙述性误报复核去分数门槛**：`isNarrativeFalsePositive()` 判为真时**不再受 `finalScore<80` 限制**，一律降级 monitor（仍写审计）。原门槛会让被 AI 推到 80+ 分的叙述文被 `arbiter_critical` 误拦，且因 AI 自学习状态而抖动 → 非确定性。硬条件已含「无任何攻击结构 + 自然语言占比 ≥0.80」，真实攻击不会通过，故放开安全；
5. **（压测修复）路径穿越正则加固**：原 `/\.{2,}\/\.{2,}\//` 不匹配点填充 `....//` 与双斜杠，改为 `/(?:\.{2,}\/{1,2}){2,}/`，覆盖 `../../etc/passwd`、`....//....//boot.ini` 等（反斜杠由归一化统一转 `/`）。

**结论（只在本组自制样本内成立，不宣称权威）**：去掉 AST 式语义层后，靠「核心结构规则 + AI 自学习」组合
在 78 条小样本上达到 **0 误报 / 0 漏放**，且**与 AI 学习状态无关（确定性）**；漏放缺口全部用确定性结构规则补齐，
没有把语义层加回。体积从 v6.0.2 的 2.59 MiB / 72 文件降到 **0.94 MiB / 35 文件（约降 64%）**，
服务器运行期不再加载语义层，资源占用更友好。
压测语料存于 `stressbox2:/tmp/stress.php`（明文攻击语料只在容器内、不落 Windows 盘）。

## 验证记录（Docker + PHP 8.1.34 / 8.5.12，全部实跑）

> 注：下表多数用例以 `build.php` 产出的 **phar** 作为测试载体跑通（检测逻辑与源码目录模式完全一致）；**生产部署走源码目录模式**（见「部署」），即装好 php-beast 后 `install.php --site=...` 一键接入。源码模式下已单独实测：正常请求 200，SQL 注入 / 路径穿越 / XSS 均 403，`ai/` 加密文件可正常加载并实例化全部 11 个 AI 类。

| 项 | 结果 |
|---|---|
| 语法 | 全仓 37 个 PHP（不含 demo/tests）`php -l`，8.1 与 8.5 均 0 错误 |
| AI 接线自检 | `tests/ai_check.php` 全通过（8.1 / 8.5 各一次）：12 个 AI 自学习类加载、30 条基线训练、贝叶斯 1.000 vs 0.000、Fisher/指纹出信号、走出冷启动、三条样本分流队列真实落盘；语义层断言在 `WAF_SEMANTIC_LAYER=1` 未设时自动 SKIP（v6.1.0 默认精简模式） |
| **误报 + 攻击回归** | `tests/fp_regression.sh` **37 条 HTTP 断言全通过**：9 条误报/正常文本 200（含超长英文段落、中文 SQL 教程叙述），28 条真实攻击 403（SQLi、UNION SELECT、`<script>` 执行、document.cookie、window.location、img onerror、事件属性、路径穿越、编码穿越、命令注入、叙述包裹攻击、**无引号布尔注入 ×4**、**SQL 注释拆分 / JNDI / `php://filter` ×3**、**metadata SSRF / gopher / dict / Java 序列化 / pickle / CRLF / LDAP / HPP ×9**）；核心+AI 精简模式下全过 |
| 开关验证 | phar 多配置各 6 用例：默认（误报 200 / 攻击 403）、`WAF_FP_GUARD=0`（误报回 403）、`WAF_AI_ENABLED=0`（误报回 403、攻击仍 403）、`WAF_BYPASS_GUARD=0`（绕过载荷回到 200）、tmpfs（行为一致且更快）；`WAF_TAUTOLOGY_GUARD=0` 经审计 reason 核对确已关闭确定性加固（`sql_boolean_tautology` → `arbiter_high`）；0 Fatal / 0 Warning / 0 Deprecated |
| 源码模式 | 正常 200、SQLi/XSS/路径穿越 403、首页「已加载 v6.1.0」、控制台无 key 403 / 有 key 200、0 Fatal / 0 Warning / 0 Deprecated |
| 单文件模式 | `auto_prepend_file=dist/shield-waf.phar`：正常 200、攻击 403，phar 内仅含内核/AI/支撑/外壳（无语义层），0 Fatal / 0 Warning / 0 Deprecated |
| 观察模式 | 注入请求 200 且业务代码继续执行，审计照常写入 |
| 强制拦截 | 注入请求返回 **403 美化页**（text/html + 严格 CSP + 真实规则标识），业务代码未执行 |
| 故障关闭 | `core/` 缺失或内核异常 → **503 美化页**（不再输出纯文本） |
| 安装 | `--check`、安装、重复安装去重、卸载还原 `.user.ini` 全部通过 |\n| **控制台按钮端到端（v6.3.0）** | `tests/control_check.php` **70/70**：鉴权矩阵（GET 405 / 无 key 403 / 错 CSRF 403 / 未知动作 400 / 危险动作未确认 400）、observe↔enforce 真实放行与拦截、误报复核开关真实改变 403↔200、白名单硬旁路 200、熔断 open 回读且大屏 JSON 同步、日志归档 / 清空后按备份原样恢复、DNA 11 个命令与守护启停（PID 真实存活）、密钥轮换后旧 key 403 / 新 key 200 再恢复、恢复出厂含 errors 关、控制审计可读、环境复位；静态快照不含 key / CSRF 且禁用控制按钮 |
| **蜜罐受控启用（v6.5.0）** | `tests/honeypot_check.php` **32/32**：内核反射验证默认不实例化蜜罐 / `checkHoneyPot()` 短路、开启时才实例化；未确认 / 短语错 / 时长越界逐项拒绝且不写盘、合规启用回读与留痕、重复开启被拒、中文控制审计、大屏与零 JS 控制台可见可控、有效期届满自动停用、环境复位；`feature_matrix_check 37/37`、`control_check 70/70`、`qps_check 55/55`、`i18n_check 31/31`、`stress78 90/90`、`fp_regression 37/37` 全过 |
| **全功能控制矩阵（v6.5.0）** | `tests/feature_matrix_check.php` **37/37**：页面所有 `data-act` 逐条比对 `control.php` 白名单（无假按钮）、40/40 项可控、5 个分组与灯态合法、底栏状态灯可点击、9 个抽屉分区定位目标存在、蜜罐高危专区与确认短语输入、静态快照不含密钥 / CSRF 且禁用操作、零 JS 控制台与全中文展示 |
| **极限对抗复核（v6.5.0）** | 12 变异 × 3 投放面分片并行全量回放 **2376 条：2370 拦截 / 6 漏放（0.25%）**；6 条全部是 `upper` / `lower` 大小写翻转后已无法解码成有效 PHP 序列化串的无效 base64，非可利用载荷，与 v6.4.1 全量结果完全一致。蜜罐默认停用后内容检测层零改动，召回未下降；`stress78 90/90`、`fp_regression 37/37` |
| **界面中文端到端（v6.4.1）** | `tests/i18n_check.php` **31/31**：403/429/502/503/413 可见文本、大屏与零 JS 控制台可见文本、中文键值表与折叠排障区、按钮文案、熔断态实时「熔断中」，以及 JSON 契约仍保留英文枚举；`qps_check 55/55`、`control_check 70/70`、`stress78 90/90`、`fp_regression 37/37`、`dna selftest 19/19`、AI 自检与 51 个 PHP lint 全过 |
| **QPS 与响应页端到端（v6.4.0）** | `tests/qps_check.php` **55/55**（v6.4.1 增补状态中文断言）：403 美化页（中文原因 / 规则标识 / 风险等级中文化 / 请求编号 / 严格 CSP / 零脚本零外链 / no-store / nosniff / DENY）、大屏 QPS 面板与 JSON、零 JS 控制台表单、阈值写入回读与越界拒绝、**真实连续请求触发 429 → 502 且限流先于熔断**、429/502 页面含倒计时与 Retry-After、熔断期间管理路由豁免、冷却结束自动半开恢复正常放行、演练熔断 / 强制恢复 / 停用保护 / 复位、错误 CSRF 403 与未知动作 400、收尾环境复位；`stress78 90/90`、`fp_regression 37/37`、`control_check 70/70`、`dna selftest 19/19`、AI 自检与 51 个 PHP lint 全过 |
| 构建 | `build.php` 产出 **1.22 MiB / 43 文件**的精简 phar（含 `i18n.php` / `features.php` / `qps.php` / `pages.php` / `dna.php`；v6.0.2 为 2.59 MiB / 72 文件） |
| **精简模式压测复核** | `waflean2` + `stressbox2` 78 条端到端载荷（12 良性 + 66 攻击，含多斜杠形态遍历）：扩展压测先揪出 2 个真 bug（良性中文叙述被 AI 推高误拦且抖动非确定性、`....//....//boot.ini` 点填充穿越漏放），修复后 **clean 与 AI 被污染两态均 0 误报 / 0 漏放**；另 `tests/fp_regression.sh` 37/37、`tests/ai_check.php` 全过；phar 0 Fatal / 0 Warning / 0 Deprecated |
| 内核改动范围 | 仅 `core/YslEngine.php` 与母本不同（v6.2.0 接回完整核心 +350 / −3 行，v6.5.0 追加 2 处蜜罐开关守卫）；`D:\core` 19 个 PHP 完好保留 |
| 横向对比 | 与旧开源版同组请求对比：6 条正常文本旧版误拦 4 条、本版全放行；7 条常见攻击两版均拦；绕过载荷修前漏 3 条、v6.0.1 补齐 |
| **Docker 疯狂测试** | 346 请求/轮 × 冷态+热态 × 完整 AI / 纯内核 / 旧版对照：**完整 AI 召回 100% / 误报 0% / 准确率 100% / p50 172 ms**；旧版召回 75.35% / 误报 7.22% / p50 684 ms；纯内核召回 99.3% / 误报 18.89%（快路径取舍）。详见「Docker 疯狂测试压测结果」 |

## 核心加密与 php-beast 扩展（部署必读）

`core/` 与 `ai/` 两个目录下的内核 / AI 自学习 PHP 均已用 **php-beast**（开源免费的 PHP 加密扩展）加密，源码不可直接阅读；
运行时由 php-beast 扩展在加载时自动解密，对 WAF 功能与性能**零影响**（已实测：正常请求返回
200，SQL 注入 / 路径穿越 / XSS 均被拦截返回 403）。

**部署前必须先安装 php-beast 扩展**，否则加密的 `core/*.php` 与 `ai/*.php` 无法被 PHP 解析（会报语法错误或文件损坏）。

仓库随附：

- `ext/beast-8.1.so` —— 已编译好的 Linux PHP 8.1 扩展（含本项目**定制密钥与文件头**，与仓库 `core/`、`ai/` 一一对应）
- `ext/beast.ini` —— 启用配置（`extension=beast.so` + `beast.enable=On`）

安装方式（任选其一）：

1. **宝塔**：软件商店装好对应 PHP 8.1 后，进「PHP 设置 → 扩展」搜索 `beast` 安装；若需本项目定制版，
   把 `ext/beast-8.1.so` 放到该 PHP 的扩展目录，并在 `php.ini` 追加 `extension=beast.so`。
2. **手动编译**（其它 PHP 版本 / Windows DLL）：克隆 `jmluang/php-beast`，
   `phpize && ./configure && make && make install`，再 `extension=beast.so`。
3. **Docker**：`php:8.1-cli` 镜像不支持 `docker-php-ext-install beast`，请
   `COPY ext/beast-8.1.so 到扩展目录` 并写入 `beast.ini`（片段见下方「Docker」）。

验证：装好后执行 `php -m | grep beast`，能看到 `beast` 即生效。

> 说明：加密密钥与文件头已固化进 `ext/beast-8.1.so`，与仓库内 `core/`、`ai/` 严格对应；
> 自行编译的 beast 若未使用同一密钥，将无法解密本仓库的 `core/`、`ai/`。
> 需要重新加密时，明文源码在私有目录 `core-src/`、`ai-src/`，构建脚本在 `.build/`（二者均已在 `.gitignore` 排除，不入库）。

## 交付清单

- **本仓库（源码目录模式）** —— `shield-waf.php` 入口、`core/`（加密内核）、`ai/`（加密 AI 自学习）、`Support/`、`config.php`、`console.php`、`screen.php`、`control.php`、`qps.php`、`pages.php`、`install.php` 等，克隆即完整可运行
- `ext/beast-8.1.so` + `ext/beast.ini` —— php-beast 扩展与启用配置（**部署必需**，含本项目定制密钥，与仓库 `core/`、`ai/` 严格对应）
- `install.php` —— 环境自检 / 一键安装 / 卸载（只写站点 `.user.ini`）
- `demo/` —— 演示站；`tests/ai_check.php`、`tests/fp_regression.sh` —— 可重复验证
- `core-src/`、`ai-src/`（**不入库**） —— 加密前的明文源码，仅供作者二次开发 / 重新加密
- `build.php` —— 可选 phar 打包（实验性，未验证与 beast 兼容）
- 本 README

> 仓库克隆即完整可运行：装好 beast 扩展 + 跑 `install.php --site=...` 即可上线。明文 `core-src/`、`ai-src/` 与 `.build/` 已在 `.gitignore` 排除，不会进入公开仓库。
