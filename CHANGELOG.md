# 变更记录

所有重要变更将记录在此文件中。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> 署名：暗夜铭少

---

## [v5.1.0] - 2026-07-21

### 🧬 语义上下文分析器体系（L7-L12 六大分析器）

本次版本完成"语义上下文分析器深入骨髓"增强，构建从单请求到跨请求的完整上下文分析体系。现有 4 个分析器全面增强，新增 2 个分析器，全部接入 SemanticEngine 权重融合。

#### 增强 4 个现有分析器

**L7 IntentInference（攻击意图链推理）**
- 新增 7×7 Kill Chain 阶段转移概率矩阵 `$phaseTransitionMatrix`：定义阶段间转移概率（正向推进 0.7 / 同阶段停留 0.3 / 大跳跃 0.05 等）
- 新增意图转移图 `$intentTransitions`：5 条跨意图转移边（sql→path / sql→code / xss→cmd / path→code / code→cmd）
- 新增方法 `inferPhaseTransition()`：基于概率矩阵返回转移异常分（0-70）
- 新增方法 `calcPhaseConfidence()`：基于证据数+阶段深度+证据强度的精细化置信度
- 新增方法 `inferIntentTransition()`：检测意图切换（横向移动信号）
- `analyze()` 激活 `$history` 参数，新增 3 个返回字段：`phase_confidence_detail` / `phase_transition` / `intent_transition`

**L8 AttackChainAnalyzer（攻击链时序关联）**
- 新增 7×7 阶段转移概率矩阵 `$phaseTransitionProbabilities`
- 新增 3 个攻击链模板（共 8 个）：`lateral_movement_chain` / `ssrf_to_rce_chain` / `credential_stuffing_chain`
- 新增方法 `detectMultiChains()`：多链并行检测 + 链切换识别
- 新增方法 `analyzeTimingPattern()`：三窗口时序分析（Burst/Sustained/Slow Burn）
- 新增方法 `detectLateralMovement()`：跨 URI 路径横向移动检测
- 新增方法 `calcTransitionAnomaly()`：基于概率矩阵的转移异常评分
- 新增方法 `calcEnhancedScore()`：整合四类异常分的增强评分
- `getPrediction()` 新增 4 个返回字段：`active_chain_count` / `timing_pattern` / `lateral_movement` / `transition_anomaly`

**L9 SemanticMemoryPool（行为基线偏差检测）**
- 新增方法 `buildMultiDimBaseline()`：6 维基线建模（URI 集中度/参数统计/payload/活跃小时/风险趋势/UA 多样性）
- 新增方法 `detectBaselineDrift()`：精细化漂移检测（URI 突变 +15 / payload 2σ +10 / 时段 +20 / UA +15 / 趋势 +25）
- 新增方法 `extractFeatureVector()`：12 维归一化特征向量
- 新增方法 `calcFeatureDistance()`：欧氏距离计算（>0.5 触发 +15）
- 新增方法 `accumulateWithWeights()`：加权累积（drift 0.5x / pattern 0.8x / velocity 0.6x，单次上限 30）
- 新增方法 `compareWithPopulation()`：全局群体对比（前 100 IP，95 分位离群 +20）
- 新增方法 `extractBehaviorSequence()` / `detectBehaviorAnomaly()`：行为序列模式突变检测
- `analyzeEvolution()` 新增 5 个返回字段：`drift_score` / `drift_dimensions` / `feature_distance` / `is_outlier` / `behavior_change_score`

**FalsePositiveGuard（误报控制引擎）**
- 业务模式库扩展：17 → 23 个模式（新增 wp_heartbeat / graphql_request / api_pagination / i18n_param / csrf_token_param / wp_cron）
- 新增 `$learnedPatterns`：运行时业务模式自学习（样本 ≥10 启用，误报 ≥3 降级）
- 新增 `$paramWhitelist`：动态参数白名单（safe ≥20 + block=0 → confidence=1.0）
- 新增公共方法 `learnPattern()` / `observeParam()` / `reportFalsePositive()`
- 新增私有方法 `matchLearnedPattern()` / `isParamWhitelisted()` / `checkContextConsistency()` / `smartScoreReduction()`
- 智能降分策略：高可信业务模式 + 单一弱证据 → 降 50%（而非完全豁免）
- `analyze()` 新增 4 个返回字段：`learned_pattern_match` / `param_whitelist_match` / `context_consistency` / `reduction_applied`

#### 新增 2 个分析器

**L11 ParamPositionAnalyzer（参数位置语义分析）**
- 新文件：[src/Semantic/ParamPositionAnalyzer.php](file:///workspace/shield-waf-master/src/Semantic/ParamPositionAnalyzer.php)
- 核心理念：同一 payload 在不同位置威胁等级不同（`id` 在 query 是 IDOR，在 cookie 是会话篡改，在 header 是注入）
- 5 个位置权重：query=1.0 / post=1.1 / cookie=1.3 / header=1.4 / json=1.2
- 13 个参数名位置规则：id / redirect / url / file / cmd / template / user-agent / referer / x-forwarded-for / token / session / q / search
- 跨位置模式检测：同名参数在多处出现 +10 / 跨位置值不一致 +15
- 位置异常检测：Cookie 含查询串 / Header 含 SQL/XSS / JSON 深度 >5 / 参数数 >20
- 高风险参数识别：规则匹配 / 超长值 / 特殊字符

**L12 RequestContextAnalyzer（跨请求上下文分析）**
- 新文件：[src/Semantic/RequestContextAnalyzer.php](file:///workspace/shield-waf-master/src/Semantic/RequestContextAnalyzer.php)
- 核心理念：识别需要跨请求上下文才能判断的攻击（CSRF / 重放 / 会话伪造 / 自动化 / API 滥用）
- CSRF 风险评估：Referer/Origin 不匹配 +30 / Origin/Host 不一致 +25 / POST 无 Token +15
- 重放攻击检测：请求签名 MD5 + 60s 内 ≥3 次相同 +25 / 5 分钟重复率 >50% +20
- 会话异常检测：同 session UA 切换 +20 / IP 切换 +25 / 新 session 访问敏感端点 +30
- 时序异常检测：间隔 σ<0.5s +25 / 变异系数 <5% +20 / 连续 5 间隔 <100ms +30
- API 滥用检测：5 分钟 >20 不同端点 +30 / 覆盖率 >50% +25 / 后台扫描 +20
- 跨请求模式识别：参数枚举 / payload 演进 / 横向移动
- 持久化到 `WAF_STORAGE_DIR/request_context/`，30 分钟过期清理

#### SemanticEngine 集成

- 新增权重：`param_position=0.05` / `request_context=0.06`
- 跨位置加成：参数位置异常 + 注入证据 → +10 / 跨位置模式 → +8
- 跨请求强证据直接加成：CSRF +12 / 重放 +10 / 会话异常 +12 / 时序异常 +8 / API 滥用 +10
- `baseEmpty()` 同步补全新字段，保证结构一致
- 配置开关：`WAF_PARAM_POSITION_ANALYZER` / `WAF_REQUEST_CONTEXT_ANALYZER`（默认启用，可通过 .env 关闭）
- `Scorer.php` 新增 `cookie_array` 字段供位置分析器使用

### 📊 测试验证

- **71/71 极限测试全部通过**（无回归）
- 首页访问正常（无拦截）
- SQL 注入 payload 检测正常（score=100）
- CSRF 攻击场景检测正常（Origin 不匹配触发拦截）
- 重放攻击场景检测正常（10 次重复请求触发拦截）
- 5 个新增/增强文件 `php -l` 语法检查全部通过

---

## [v5.0.0] - 2026-07-21

### 🧠 语义引擎架构级重构

本次大版本针对「14 层编码归一化未全局接入」和「语义解析器未真正发挥作用」两大架构性问题进行全面修复，并完成极限测试和代码审计。

#### 14 层归一化全局统一接入

- **新增 `waf_normalize_inputs()`**：在所有防御模块前统一归一化 `$_GET`/`$_POST`/`$_COOKIE`/URI/body/headers
- **修复架构缺陷**：原各模块直接查询原始输入，14 层归一化引擎从未被调用
- **MySQL 内联注释处理**：`/*!50000UNION*/` → `UNION`（两侧加空格避免关键字粘连）
- **八进制编码解码**：`\163\171\163\164\145\155` → `system`

#### 11 解析器内容类型路由

- **新增 `routeParsers()`**：根据 Content-Type 和输入特征激活对应解析器，避免所有解析器分析同一份混合文本
- **SQL**：URI 参数 + body 字符串
- **HTML**：仅 Content-Type 为 html 或 body 含 `<` 时激活
- **XXE**：仅 Content-Type 含 xml 或 body 含 `<?xml` 时激活
- **SSRF**：URL 相关参数 + URL 模式值
- **反序列化**：仅 body 含序列化签名时激活
- **CRLF**：headers + URI 参数 + body 字符串

#### 双证据融合架构

- **规则引擎 + 语义引擎双路评分**：取较高值作为最终判定
- **双证据增强**：规则匹配 + 解析器确认互相印证提升置信度
- **解析器兜底**：强解析器证据可独立触发检测（即使规则未匹配）
- **签名保底机制**：`calcSignatureBonus()` 对短 payload 提供底线分数

### 🔒 代码审计修复（9 项）

- **P0 JWT 算法白名单**：删除误判的合法算法（HS256/RS256/ES256 等）
- **P0 日志目录权限**：`0777` → `0750`，`/tmp` 降级 `0777` → `0700`
- **P1 默认密钥硬编码**：默认值改为空，自动生成失败时 `die()` 拒绝启动
- **P1 JWT exp 容差**：添加 60 秒容差窗口，避免时钟不同步误拦截
- **P2 API 速率限制竞争条件**：APCu 优先，文件降级用 `flock(LOCK_EX)`
- **P2 DashboardApi 请求大小限制**：新增 413 Request Entity Too Large
- **P2 JWT typ 校验**：放宽为"包含 jwt 子串"
- **P2 rand() 弃用**：替换为 `mt_rand()`
- **P2 SVG 检测变量初始化**：显式 `$scriptFound = false`

### 📋 配置文件完善

- **命名统一**：`WAF_LOG_MAX_FILESIZE` → `WAF_LOG_MAX_SIZE`（保留旧别名）
- **命名统一**：`WAF_ALLOWED_ORIGINS` → `WAF_CORS_ALLOWED_ORIGINS`（保留旧别名）
- **补齐 8 个缺失配置项**：`WAF_DEBUG`/`WAF_STORAGE_DIR`/`WAF_UPLOAD_PATH`/`WAF_PASSWORD_WP_INTEGRATION`/`WAF_CC_LIMIT_AJAX`/`WAF_CC_FILE_MAX_PER_IP`/`WAF_CC_CLEANUP_INTERVAL`/`WAF_SKIP_RATELIMIT`
- **同步 `.env.example`**：所有配置项均支持 .env 统一配置

### 📊 极限测试

- **71/71 全通过**：覆盖 14 大类攻击（编码绕过/SQL/XSS/命令注入/路径遍历/XXE/SSRF/SSTI/模板/CRLF/反序列化/OpenRedirect/误报/路由）
- **误报率 0%**：10 个正常请求全部放行，分数均 <30
- **拦截率 100%**：61 个攻击用例全部检测到

---

## [v4.2.0] - 2026-07-20

### 🌍 3D 全球攻击地图

控制台「安全总览」全球攻击分布全面升级为 3D 旋转地球，真实 IP 地理定位 + 实时攻击可视化。

#### 新增 IP 地理定位模块

- **`src/Support/IpGeo.php`**：轻量级 IP → 国家/经纬度映射，零依赖
  - 内置 50+ 国家 CIDR 段（中国/美国/俄罗斯/日本/韩国/欧洲等主要国家）
  - 支持本地 IP（127.0.0.1/192.168/10/172.16-31）识别为「内网」
  - 未匹配 IP 标记为「未知」，不影响主流程
  - 内存哈希缓存，重复查询零开销

#### 3D 地球可视化

- **CSS 3D 旋转地球**：直径 220px，30 秒匀速旋转，大气辉光效果
- **球面坐标投影**：经纬度 → 3D 笛卡尔坐标（x/y/z），真实地理位置
- **攻击点脉冲动画**：严重攻击更大更亮，动态脉冲效果
- **5 秒自动刷新**：概览页面每 5 秒刷新攻击数据、日志流、地图点位

### 📦 沙箱系统全面增强

针对用户反馈"沙箱部署后看不出痕迹"的问题，从可见性、可靠性、安全性三方面全面增强。

#### 可见性增强

- **启动心跳日志**：沙箱启动时记录心跳日志 + `.started` 文件标记，每小时刷新
  - 日志路径：`logs/sandbox_heartbeat.log`
  - 标记文件：`logs/quarantine/.started`
- **健康状态 API**：`getHealthStatus()` 提供运行状态、最后扫描时间、文件数等查询

#### 性能与可靠性

- **异步扫描不阻塞**：初始扫描和自动扫描改为 `register_shutdown_function` + `ignore_user_abort(true)` 异步执行
  - 首次访问不再因扫描慢而超时
  - 学习模式自动跳过初始扫描
- **实时监控缓存修复**：`realtimeMonitor` 中调用 `takeSnapshot(true)` 强制刷新
  - 修复了「before 和 after 快照相同，检测不到变化」的 bug
- **精准切割备份**：切割前自动备份原始文件到 `quarantine/cut_backup/`
- **基线锁定备份**：锁定基线时自动备份所有受监控文件原始副本

#### Bug 修复（6 项）

1. ✅ 实时监控快照缓存导致检测失效
2. ✅ 初始扫描阻塞请求导致超时
3. ✅ 精准切割无备份，误操作无法回滚
4. ✅ 扫描历史缺少 id/type/status 等字段
5. ✅ 模式切换逻辑不完善
6. ✅ 沙箱 API 缺少 CSRF 防护

### 🎛️ 控制台修复

- **全量按钮审计修复**：40+ 个按钮 `onclick` 函数逐一核对，确保函数存在、功能匹配
  - 基线管理：锁定/解锁基线
  - 扫描操作：立即扫描
  - 隔离区：批量恢复/批量删除
  - 文件分析：分析/隔离/预览切割/应用切割
- **沙箱 API 安全加固**：所有 POST 请求增加 CSRF token 验证
- **路径遍历防护**：`waf_sandbox_validate_path()` 严格验证文件路径，防止目录遍历

### 📚 文档

- **README.md**：版本升级 v4.2.0，新增 3D 全球攻击地图、沙箱增强、文件上传检测详细描述等章节
- **CHANGELOG.md**：新增 v4.2.0 完整变更记录
- **.env.example**：版本号 v3.1.0 → v4.2.0，新增 12 个 v4.x 配置项，修复 2 处配置值不一致

---

## [v4.1.1] - 2026-07-19

### 🔧 深度 PHP 7.4 兼容性审计

针对用户反馈"7.4 就报错"的问题，对全项目 105 个 PHP 文件进行了系统性扫描，全面修复 PHP 版本兼容性问题。

#### 新增兼容性 Polyfill

- **`src/Support/Functions.php`** 新增 5 个 PHP 8.0+ 函数的 polyfill：
  - `array_key_first()` / `array_key_last()`（PHP 7.3+ 引入）
  - `str_contains()` / `str_starts_with()` / `str_ends_with()`（PHP 8.0+ 引入）
  - 全部使用 `function_exists` 守护，避免与原生函数冲突

#### 修复的兼容性问题

- **`src/Support/Password.php`**：
  - 类常量使用 `??` 表达式（PHP 8.3+ 才支持类常量表达式）→ 改为静态属性 + getter 方法
- **`src/Learn/AutoLearn.php`**、**`src/Semantic/BusinessSemantics.php`**：
  - 5 处 `private const` 改为 `public const`（向下兼容更广 PHP 版本）

#### 扫描结果

| 检查项 | PHP 版本要求 | 发现问题 | 修复状态 |
|--------|-------------|---------|---------|
| match 表达式 | PHP 8.0+ | 0 | ✅ 未使用 |
| nullsafe 运算符 `?->` | PHP 8.0+ | 0 | ✅ 未使用 |
| 联合类型 `A\|B` | PHP 8.0+ | 0 | ✅ 未使用 |
| 构造器属性提升 | PHP 8.0+ | 0 | ✅ 未使用 |
| mixed 类型 | PHP 8.0+ | 0 | ✅ 未使用 |
| static 返回类型 | PHP 8.0+ | 0 | ✅ 未使用 |
| throw 表达式 | PHP 8.0+ | 0 | ✅ 未使用 |
| enum 枚举 | PHP 8.1+ | 0 | ✅ 未使用 |
| readonly 属性 | PHP 8.1+ | 0 | ✅ 未使用 |

#### 验证测试

- **105 个 PHP 文件语法检查**：全部通过
- **密码模块测试**：41/41 通过
- **密码模块完整测试**：68/68 通过
- **首页兼容性测试**：17/17 通过
- **FP 压力测试**：37/37 通过，0 误报
- **管理员白名单+测试模式**：11/11 通过

### 📚 文档

- **SECURITY_AUDIT_REPORT.md**：新增「PHP 版本兼容性审计」章节（17 项全部修复）
- **README.md**：新增 v4.1.1 版本历程
- **CHANGELOG.md**：新增 v4.1.1 记录

---

## [v4.1.0] - 2026-07-19

### 🆕 新增功能

- **管理员 IP 白名单（`WAF_ADMIN_IPS`）**：在 `config.php` 直接配置 IP 或 CIDR 网段，无需登录控制台
  - 支持 CIDR 网段：`10.0.0.0/8` 命中 `10.1.2.3`
  - 可通过 `.env` 配置：`WAF_ADMIN_IPS=127.0.0.1,192.168.1.100,10.0.0.0/8`
  - 白名单 IP 跳过速率限制、封禁检查、累进封禁

- **测试模式（`WAF_TEST_MODE`）**：一键开启「只拦截不封IP」
  - `waf_smart_ban` / `waf_ban` 不执行实际封禁，只记录到 `logs/test_mode_ban.log`
  - `waf_is_banned` 跳过封禁检查（避免历史 ban 影响测试）
  - 403 页面显示拦截原因（方便调试）
  - 响应头 `X-ShieldWAF-TestMode: 1` 标识

- **日志三级兜底机制**：解决 logs 目录不可写时日志丢失问题
  - 主路径：`WAF_LOG_PATH/block_*.log`（自动 mkdir 0775）
  - 兜底1：PHP `error_log()`（写入 nginx/php-fpm error log）
  - 兜底2：`/tmp/shield_waf_block.log`（Web 用户一般可写）

- **部署诊断**：`shield-waf.php` 启动时检测 logs 目录可写性，不可写时通过 `error_log` 输出修复命令提示

### 🐛 修复（首页403 + PHP兼容性深度审计）

#### 首页403误拦截根因链

- **CachePoisoning Host 字符类正则误匹配 localhost**：`/[\r\n%0d%0a]/i` 是字符类，会把 `%`、`0`、`d`、`a` 当单独字符匹配，导致 "localhost" 含 0/d/a 被命中 → 改为字面量匹配 `/(?:\r\n|\n|\r|%0d%0a|%0a%0d|%0d|%0a)/i`
- **`getAllHeadersCompat()` 无限递归**：`self::getAllHeadersCompat()` 自调用 → 改为 `getallheaders()`
- **`$_SERVER` 当 headers 传给 BotManager**：环境变量(PATH/HTTP_PROXY等)被当成 header 参与 Bot 指纹分析 → 只提取 `HTTP_` 开头的请求头
- **CRLF `\u000d\u000a` PCRE2 非法转义**：每次请求编译失败 → 改为字面量 `\\u000d\\u000a`
- **`BotFingerprint` 数组值强转(string)警告**：`$_SERVER['argv']` 是数组 → 跳过非标量值

#### PHP 兼容性修复

- **10 处箭头函数 `fn()`**（PHP 7.4+ 专有）全部改为传统 closure
- **`str_ends_with`**（PHP 8.0+ 专有）添加 `function_exists` 守护
- **`getallheaders()`**（nginx/php-fpm/CLI 不存在）添加 `$_SERVER` 回退
- **`ABSPATH` 未定义**致命错误：自动定义指向正确目录

#### 评分与拦截逻辑修复

- **`Scorer.observe` 阈值失效**：observe=70 与 block=70 相等被短路 → 改为 50（严格递增）
- **`FalsePositiveGuard` 短载荷漏检**：`system(ls)` 误判为正常请求 → 添加 `containsAttackKeyword` 检查解析器布尔标志位
- **短载荷攻击得分偏低**：69.6分差0.4到block → 新增 `calcClearAttackEvidenceBonus` 保底（在FP调整后应用）
- **`HoneypotLinks` 误判**：短值含敏感词即触发 → 要求值长度≥8且含2+敏感词
- **`Detector` 阈值不一致**：60 与 Scorer 70 不一致 → 统一为 70
- **`WordPressIntegration.ABSPATH` 路径错误**：`dirname(__FILE__)` → `dirname(__DIR__, 2)`

#### 阈值统一

- `Scorer` block = 70
- `Detector` isAttack = 70
- `shield-waf.php` $blockThreshold = 70
- `config.php` `WAF_SCORE_BLOCK` = 70

### 📚 文档

- **README.md**：v4.0.0 → v4.1.0，新增「部署必读：常见陷阱与解决方案」章节
  - 首页403排查方法
  - 测试模式使用指南
  - 管理员白名单配置
  - PHP 版本兼容性表
  - 部署检查清单
- **SECURITY.md**：新增 v4.1 深度代码审计修复章节
- **TEST_REPORT.md**：新增 v4.1 增量测试结果（35/35 通过）
- **CHANGELOG.md**：本次新增

### 🧪 测试

新增 3 个测试套件：

- `test_homepage_compat.php`：首页403回归测试（17 用例）
- `test_admin_whitelist.php`：管理员白名单+测试模式（11 用例）
- `test_parser_scores.php`：攻击载荷评分详情（7 用例）

---

## [v4.0.0] - 2026-07-18

### 🆕 新增功能

- **可视化控制台**：12 个功能页面，33 个防御模块，大厂级交互体验
- **双重密码加密**：业界首创「主层 + 副层」双重哈希
- **多数据库适配**：MySQL / PostgreSQL / SQLite / MSSQL
- **全量视觉动效升级**

### 🐛 修复

- HTML 实体 SQL 检测偏弱
- 明文攻击得分偏低
- 全量解码测试通过率 94.1% → 100%
- E2E 测试通过率 83.3% → 88.9%

---

## [v3.1.0] - 2026-07-15

### 🆕 新增功能

- 统一归一化引擎
- 沙箱/上传双引擎重优化
- 学习闭环
- 全配置 .env 化

---

## [v3.0.0] - 2026-07-10

### 🆕 新增功能

- 8 个高级防护模块
- 语义分析引擎
- 机器人防护
- 沙箱系统

---

## [v2.0.0] - 2026-07-05

### 🆕 新增功能

- 10 层编码归一化
- 评分系统
- 自学习
- WordPress 深度集成

---

## [v1.0.0] - 2026-07-01

### 🆕 初始版本

- 基础 SQL/XSS 防护
- IP 封禁
- 速率限制
