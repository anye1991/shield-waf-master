#!/usr/bin/env bash
#
# 生成 YSL语枢-盾甲WAF 态势大屏的真实截图。
# 前置：本仓库已克隆、目标机 PHP>=8.1 且已装随附扩展、已装 chromium/chrome。
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PORT=8099
OUT="$HERE/docs/dashboard-real.png"
KEY="$(cat "$HERE/var/data/console.key" 2>/dev/null || echo demo)"

echo "==> 启动临时服务器 (127.0.0.1:$PORT)"
php -d auto_prepend_file="$HERE/shield-waf.php" -S "127.0.0.1:$PORT" -t demo >/tmp/waf_shot.log 2>&1 &
SVPID=$!
trap 'kill $SVPID 2>/dev/null || true' EXIT
sleep 3

CHROME="$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)"
if [ -z "$CHROME" ]; then
  echo "ERR: 未找到 google-chrome / chromium，请先安装浏览器" >&2
  exit 1
fi

echo "==> 无头截图 -> $OUT"
"$CHROME" --headless --no-sandbox --disable-gpu --hide-scrollbars \
  --window-size=1280,800 \
  --screenshot="$OUT" \
  "http://127.0.0.1:$PORT/waf-screen?key=$KEY"

echo "==> 完成：$OUT"
echo "    把 README 里态势大屏的 docs/dashboard.gif 换成 docs/dashboard-real.png 即可。"
