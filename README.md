# 盾甲 WAF (Shield WAF)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13568/badge)](https://www.bestpractices.dev/projects/13568)
**全球顶级编码归一化 · 智能语义分析 · 主动路径围堵 · 模块化 PHP Web 应用防火墙**

盾甲 WAF 是一款专为 WordPress（或任意 PHP 站点）设计的 Web 应用防火墙，核心战略是**不追着攻击者跑，而是在必经之路设防**。以 **14 层递归编码归一化**、**500+ 全球同形字符映射**、**10 维深度语义分析**、**四维智能评分**和**攻击路径预判围堵**为核心，实现从被动拦截到主动围堵的革命性安全架构。

---

## 核心架构总览

```
请求输入
  ↓
┌─────────────────────────────────────────────────────┐
│  14 层编码归一化引擎 (normalizer.php)                │
│  URL递归 → HTML实体 → Unicode → UTF-7 → Base64 →   │
│  NFKC → 全角半角 → 同形字 → 零宽字符 → SQL注释 →   │
│  空格压缩 → 大小写 → 语义上下文 → 双重编码检测       │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│  10 维语义分析引擎 (semantic/)                       │
│  L1 字符语义 → L2 词汇语义 → L3 结构语义 →          │
│  L4 参数语义 → L5 业务语义 → L6 逻辑推理 →          │
│  L7 意图推理 → L8 攻击链关联 → L9 语义记忆池 →      │
│  L10 对抗样本防御                                    │
│  + 多向量语义融合 (URL/Body/Header/Cookie/UA/Referer)│
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│  四维智能评分引擎 (Scorer.php)                       │
│  熵值分析(20%) + 语义分析(30%) +                     │
│  编译偏差(25%) + 编码偏离(25%)                       │
└──────────────────────┬──────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│  误报控制 + 路径预判 + 主动防御                      │
│  7层误报确认 → 攻击者画像 → 路径预判 →              │
│  蜜罐部署 → 预判拦截 → 攻击链提前封堵 →             │
│  阶段进阶拦截 → 累进惩罚                             │
└──────────────────────┬──────────────────────────────┘
                       ↓
              allow / monitor / block
```

---

## 功能清单

### 一、编码归一化引擎

| 分类 | 模块 | 说明 |
|------|------|------|
| **14层编码归一化** | `normalizer.php` | L1 URL递归解码 → L2 HTML实体 → L3 Unicode转义 → L4 UTF-7 → L5 Base64智能解码 → L6 NFKC规范化 → L7 全角半角 → L8 同形字符映射(500+) → L9 零宽/控制字符清除 → L10 SQL注释移除 → L11 空格压缩 → L12 大小写统一 → L13 语义上下文归一化 → L14 双重编码检测与深度解码 |
| **上下文感知** | `normalizer.php` | 对 JSON/XML 载荷进行结构保留式归一化；返回编码深度、变换次数、编码类型、双重编码标记等上下文数据 |

### 二、语义分析引擎

| 层级 | 模块 | 说明 |
|------|------|------|
| **L1 字符语义** | `semantic/CharSemantics.php` | 识别SQL/HTML/代码/自然语言/Base64，特殊字符频率、不可打印字符、零宽字符、字符熵 |
| **L2 词汇语义** | `semantic/WordSemantics.php` | SQL关键字、表名、列名、函数、变量、自然词、危险函数、HTML/JS标签 |
| **L3 结构语义** | `semantic/StructureSemantics.php` | SQL/HTML/JS语法结构解析（编译器级），路径结构、编码结构、嵌套深度 |
| **L4 参数语义** | `semantic/ParamSemantics.php` | 参数名与参数值类型匹配度检测，参数类别推断、预期类型匹配 |
| **L5 业务语义** | `semantic/BusinessSemantics.php` | 9种业务场景识别（搜索/登录/评论/上传/管理后台/API等），场景违规检测 |
| **L6 逻辑推理** | `semantic/LogicInference.php` | 恒真式检测(1=1)、恒假式、逻辑组合攻击、时间盲注(sleep/benchmark)、报错注入(extractvalue/updatexml)、布尔盲注 |
| **L7 意图推理** | `semantic/IntentInference.php` | 识别攻击者阶段：侦察→探测→尝试→攻击→利用，预判下一步行动 |
| **L8 攻击链关联** | `semantic/AttackChainAnalyzer.php` | 8种攻击链模式（SQL注入链/XSS链/RCE链等），关联同一IP多步攻击行为，进度追踪，提前拦截 |
| **L9 语义记忆池** | `semantic/SemanticMemoryPool.php` | 跨请求深层语义指纹记忆，正常基线建立，演化异常检测（熵突变/风险跃升/阶段突进） |
| **L10 对抗防御** | `semantic/AdversarialDefense.php` | 6种对抗攻击检测：语义稀释、阈值规避、归一化欺骗、上下文切换、时间分散、多向量协同 |
| **MV 多向量融合** | `semantic/MultiVectorFusion.php` | 8向量统一分析：URI路径/Query/POST/Headers/UA/Referer/Cookie/Raw Body，跨向量异常检测 |

### 三、智能评分与决策

| 分类 | 模块 | 说明 |
|------|------|------|
| **四维智能评分** | `Scorer.php` | 熵值分析(20%) + 语义分析(30%) + 编译偏差(25%) + 编码偏离(25%)，交叉证据加成，多规则命中加成 |
| **自动学习** | `auto_learning.php` | 攻击载荷记录、模式提取、规则生成、动态权重调整 |
| **误报控制** | `semantic/FalsePositiveGuard.php` | 7层确认机制：业务模式匹配→参数名白名单→指标质量检查→行为基线→维度一致性→危险特征检查→归一化检查 |
| **路径预判** | `semantic/AttackPathPredictor.php` | 攻击者画像识别（脚本小子/扫描器/高级攻击者/APT/渗透测试员），5阶段攻击路径图，8种攻击类型路径映射 |
| **主动防御** | `semantic/ActiveDefense.php` | 蜜罐部署(8种)→预判路径拦截→攻击链提前封堵→阶段进阶拦截→累进惩罚(最大10倍) |

### 四、沙箱与上传防御

| 分类 | 模块 | 说明 |
|------|------|------|
| **虚拟沙箱** | `sandbox.php` | 实时文件监控、自动定时扫描、精确恶意代码定位(行号+字符范围)、文件隔离与恢复、新恶意文件秒删除 |
| **后门扫描** | `malware_scanner.php` | 集成沙箱多引擎分析，特征码+启发式扫描全站PHP文件 |
| **7层上传检测** | `upload.php` | 扩展名白名单→MIME检测→GD库图像验证→SVG专用检测→编码归一化→语义分析→智能评分，防御图像马/SVG恶意文件 |

### 五、协议层与IP管理

| 分类 | 模块 | 说明 |
|------|------|------|
| **协议层防御** | `shield-waf.php` + `chunked.php` | 请求方法白名单、Content-Type校验、HTTP参数污染检测、分块传输自动重组 |
| **IP管理** | `ip_manager.php` | 封禁/解封、管理员白名单(CIDR支持)、暴力尝试计数器、4阶段累进惩罚 |
| **速率限制** | `rate_limit.php` + `api_rate_limit.php` | 单IP窗口计数器；敏感路径独立限流 |
| **搜索引擎蜘蛛豁免** | `bot/BotManager.php` | DNS反查验证、头部异常豁免，确保正常蜘蛛放行 |

### 六、其他安全模块

| 分类 | 模块 | 说明 |
|------|------|------|
| **CSRF 防护** | `csrf_protect.php` | 检查 Origin/Referer 头，状态改变请求必须与本站同源 |
| **CORS 策略** | `cors_policy.php` | 仅允许本站域名跨域，自动处理 OPTIONS 预检 |
| **安全响应头** | `security_headers.php` | 注入 HSTS、CSP、X-Frame-Options 等 |
| **会话加固** | `session_security.php` | 强制 Cookie 属性 HttpOnly、Secure、SameSite=Lax |
| **WebSocket 阻断** | `websocket_block.php` | 直接拒绝 WebSocket 升级请求 |
| **GraphQL 注入** | `graphql_injection.php` | 检测 $where、$regex、__schema 等内省攻击 |
| **暗门保护** | `darkgate.php` | 魔法密钥 + 二次密码双重验证 |
| **输出过滤** | `output_filter.php` | 捕获含敏感错误的响应，替换为通用500页面 |
| **可视化仪表盘** | `dashboard.php` + `dashboard_api.php` | 7日攻击趋势、攻击类型分布、TOP10攻击IP、IP黑白名单管理、沙箱告警、后门扫描结果 |

---

## 目录结构

```
shield-waf/
├── shield-waf.php                  # 主入口（加载器 + 核心流程）
├── config.php                      # 配置常量
├── functions.php                   # 通用函数
├── normalizer.php                  # 14层编码归一化引擎
├── detector.php                    # 攻击检测（双引擎）
├── Scorer.php                      # 四维智能评分引擎
├── auto_learning.php               # 自动学习系统
├── upload.php                      # 7层文件上传防护
├── sandbox.php                     # 虚拟沙箱（文件监控+隔离+恢复）
├── malware_scanner.php             # 后门/木马扫描引擎
├── ip_manager.php                  # IP封禁/白名单/累进惩罚
├── rate_limit.php                  # CC攻击防护
├── api_rate_limit.php              # API独立速率限制
├── darkgate.php                    # 暗门二次验证
├── output_filter.php               # 输出过滤
├── chunked.php                     # 分块传输解码
├── security_headers.php            # 安全响应头
├── cors_policy.php                 # 跨域请求控制
├── csrf_protect.php                # CSRF防护
├── graphql_injection.php           # GraphQL注入检测
├── session_security.php            # 会话Cookie安全
├── websocket_block.php             # WebSocket阻断
├── dashboard.php                   # 仪表盘页面
├── dashboard_api.php               # 仪表盘数据接口
├── stats.php                       # 攻击日志统计
├── homoglyph_map.json              # 同形字符扩展文件
├── semantic/                       # 🔥 语义分析引擎
│   ├── SemanticEngine.php          #   总引擎（10维+围堵策略）
│   ├── CharSemantics.php           #   L1 字符语义
│   ├── WordSemantics.php           #   L2 词汇语义
│   ├── StructureSemantics.php      #   L3 结构语义
│   ├── ParamSemantics.php          #   L4 参数语义
│   ├── BusinessSemantics.php       #   L5 业务语义
│   ├── LogicInference.php          #   L6 逻辑推理
│   ├── IntentInference.php         #   L7 意图推理
│   ├── AttackChainAnalyzer.php     #   L8 攻击链关联
│   ├── SemanticMemoryPool.php      #   L9 语义记忆池
│   ├── AdversarialDefense.php      #   L10 对抗样本防御
│   ├── MultiVectorFusion.php       #   多向量语义融合
│   ├── FalsePositiveGuard.php      #   误报控制引擎
│   ├── AttackPathPredictor.php     #   攻击路径预判引擎
│   └── ActiveDefense.php           #   主动防御引擎（蜜罐+围堵）
├── bot/
│   └── BotManager.php              # 搜索引擎蜘蛛识别与豁免
└── waf_logs/                       # 日志目录（自动创建）
```

---

## 安装部署

### 环境要求

- PHP 7.4 或更高版本
- 推荐启用扩展：`mbstring`、`json`、`fileinfo`、`intl`、`dom`
- 目录 `waf_logs/` 需要 PHP 进程可写

### 步骤（适用于 WordPress）

1. 将整个 `shield-waf` 文件夹上传至 `/wp-content/plugins/`。
2. 确保 `waf_logs/` 目录存在并可写（若不存在程序会自动创建，但需确保父目录有写入权限）。
3. 在 WordPress 主题的 `functions.php` 末尾添加：

```php
require_once WP_CONTENT_DIR . '/plugins/shield-waf/shield-waf.php';
```

4. 立即修改 `config.php` 中的 `WAF_MAGIC_KEY` 和 `WAF_2FA_PASS`（支持从环境变量读取）。
5. 访问网站首页，确认无异常；若被拦截，请检查 IP 是否已封禁或通过暗门验证。

### 非 WordPress 站点

将文件夹放在任意位置，在入口文件（如 `index.php`）最顶部添加：

```php
require_once '/path/to/shield-waf/shield-waf.php';
```

> 注意：需要自行定义 `ABSPATH` 常量，或修改所有文件中 `defined('ABSPATH') || exit;` 为合适的验证。

---

## 配置说明

编辑 `config.php` 可调整以下核心参数：

| 常量 | 说明 | 默认值 |
|------|------|--------|
| `WAF_MAGIC_KEY` | 暗门魔法密钥（第一因子） | 从环境变量读取 |
| `WAF_2FA_PASS` | 二次验证密码 | 从环境变量读取 |
| `WAF_MAGIC_EXPIRE` | 第一因子有效期（秒） | 3600 |
| `WAF_CC_LIMIT` | CC攻击阈值 | 60 |
| `WAF_CC_WINDOW` | CC攻击时间窗口（秒） | 60 |
| `WAF_NORMALIZE_SQL_COMMENTS` | 是否移除SQL注释 | true |
| `WAF_SANDBOX_SCAN_INTERVAL` | 沙箱自动扫描间隔（秒） | 300 |
| `WAF_WEBHOOK_URL` | 告警Webhook地址 | 空 |

---

## 使用指南

### 管理员如何免拦截？

1. 访问 `https://你的域名/wp-admin?magic=你的WAF_MAGIC_KEY`
2. 输入 `WAF_2FA_PASS` 中的密码完成二次验证
3. 验证通过后即可正常访问后台

### 查看攻击仪表盘

通过暗门验证后，访问 `https://你的域名/waf-dashboard`。页面每5秒自动刷新，显示攻击趋势、类型分布、TOP10攻击IP、IP黑白名单管理、沙箱告警和后门扫描结果。

### 添加自定义同形字符

编辑 `homoglyph_map.json`，按 `"混淆字符": "映射后的ASCII"` 格式添加条目。保存后立即生效。

### 测试防护效果

```bash
# SQL注入（恒真式）
curl "https://your-domain.com/?id=1' OR '1'='1"

# XSS
curl "https://your-domain.com/?q=<script>alert(1)</script>"

# 双重URL编码绕过
curl "https://your-domain.com/?id=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

# 全球同形字符（高棉文 s）
curl "https://your-domain.com/?q=%E1%9E%9Flect"

# 时间盲注
curl "https://your-domain.com/?id=1 AND SLEEP(5)"
```

---

## 核心防御策略

### 预判路径围堵（革命性架构）

传统WAF追着攻击者跑，攻击者永远领先。盾甲WAF在攻击者必经之路设防：

1. **攻击者画像识别** — 判断攻击者类型（脚本小子/扫描器/高级攻击者/APT/渗透测试员）
2. **5阶段路径预判** — 侦察→探测→尝试→攻击→利用，每个阶段预测下一步路径和参数
3. **蜜罐部署** — 8种虚假入口（管理后台/phpMyAdmin/Git仓库/配置文件/SSH密钥等）
4. **预判路径拦截** — 命中高概率预判路径直接封禁
5. **攻击链提前封堵** — 攻击链进度≥40%自动拦截
6. **阶段进阶拦截** — 检测阶段跳变立即封禁

### 7层误报控制

确保不误杀正常请求：业务模式匹配→参数名白名单→指标质量检查→行为基线→维度一致性→危险特征检查→归一化检查。**宁可漏网，绝不误杀。**

### 4阶段累进惩罚

- 第1次：1天
- 第2次：7天
- 第3次：30天
- 第4次及以上：永久封禁

主动防御引擎封禁还有额外累进（最大10倍），攻击越多次封越久。

---

## 性能考虑

- 所有正则均为预编译，归一化有深度/长度限制
- 语义分析各模块独立，可按需启用/禁用
- 文件操作有完整路径验证和错误处理
- 个人博客、中小站点无需额外配置即可流畅运行
- 若日请求量超过百万，建议将计数器和封禁列表迁移至 Redis

---

## 常见问题

**Q：为什么我清空白名单文件后仍然能直接访问后台？**

> A：您的浏览器可能仍持有之前暗门验证的 PHP 会话 Cookie。请使用无痕窗口测试，或清除 PHPSESSID Cookie。

**Q：仪表盘无数据？**

> A：检查 `waf_logs/` 目录下是否存在 `block_*.log` 文件，以及 PHP 进程是否可写入。

**Q：上传合法图片被拦截？**

> A：检查 `upload.php` 中的 MIME 白名单和扩展名白名单，或临时注释掉 fileinfo 检测部分测试。

**Q：正常搜索被误拦？**

> A：误报控制引擎会自动识别搜索场景。如仍误拦，可将搜索参数名加入 `FalsePositiveGuard` 的可信参数名列表。

**Q：如何临时关闭WAF？**

> A：在 `wp-config.php` 中将引入行注释掉即可完全跳过所有防护。

---

## 版权

© 2026 暗夜铭少 (DarkNightMing)
官网网站：https://waf.duduziy.com

---

## License

This project is licensed under the **Business Source License 1.1**.

- ✅ Free for non-production use (learning, testing, personal projects)
- 🔒 Commercial production use requires a commercial license
- 📅 Changes to Apache 2.0 on 2029-07-01

For commercial licensing: https://duduziy.com/license.html

See the [LICENSE](./LICENSE) file for full details.

守护每一行代码，从盾甲开始。
