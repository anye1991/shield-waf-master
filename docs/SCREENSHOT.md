# 生成真实大屏截图

文档顶部的 `docs/dashboard.gif` 是**程序化生成的动态示意**，并非真实运行界面。
如果你要放一张**真实的大屏截图**进 README，按下面步骤在有浏览器的机器上跑一次即可。

## 前置条件

- 本仓库已克隆到本地（如 `/opt/ysl-waf`）
- 目标机 **PHP ≥ 8.1**，且已安装随附的扩展（见 README「部署」）
- 已装有 **Chromium / Google Chrome**（用于无头截图；沙箱/服务器通常没有，需本机或带桌面的机器）

## 一键生成

```bash
bash tools/shot_dashboard.sh
```

脚本会：

1. 临时起一个 PHP 内置服务器，用 `shield-waf.php` 作 `auto_prepend_file` 加载本仓库
2. 用 Chromium 无头模式访问 `/waf-screen?key=<安装时生成的 key>`
3. 截图保存到 `docs/dashboard-real.png`

## 把真实截图替换进 README

生成后，把 `README.md` 里态势大屏章节的：

```markdown
<p align="center">
  <img src="docs/dashboard.gif" alt="YSL语枢-盾甲WAF 态势大屏动态预览" width="720"/>
</p>
```

替换为：

```markdown
<p align="center">
  <img src="docs/dashboard-real.png" alt="YSL语枢-盾甲WAF 态势大屏真实截图" width="720"/>
</p>
```

（保留 GIF 也行，两者各有好处：GIF 会自动播放动效，PNG 是真实数据。）

## 手动步骤（不依赖脚本）

```bash
# 1) 起临时服务
WAF_HOME=/opt/ysl-waf \
php -d auto_prepend_file=/opt/ysl-waf/shield-waf.php \
    -S 127.0.0.1:8099 -t demo &
SVPID=$!

# 2) 无头截图（需先装好扩展，否则内核无法加载）
KEY=$(cat /opt/ysl-waf/var/data/console.key 2>/dev/null || echo demo)
chromium --headless --no-sandbox --disable-gpu --window-size=1280,800 \
  --screenshot=/opt/ysl-waf/docs/dashboard-real.png \
  "http://127.0.0.1:8099/waf-screen?key=$KEY"

# 3) 收尾
kill $SVPID
```

> 提示：想看到有数据的大屏，截图前先用 `ab` / `wrk` / `curl` 灌一点正常与攻击请求，
> 让 `attack.log` 和大屏指标有内容，截出来的图才好看。
