#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
#
# 加密发行版 · 容器内极限测试总控（由 tools/stress_extreme.sh 调用）
# 环境：php:8.1-cli；仓库只读挂 /src，全部动作在 /app 副本里进行。
# 与功能验收的区别：这里启用 PHP_CLI_SERVER_WORKERS 多进程，专打并发、
# 超大请求体、深层编码逃逸、长稳与状态竞态。

set -u

APP=/app
SRC=/src
PORT=8080
WORKERS="${STRESS_WORKERS:-8}"
LOGDIR="$APP/var/logs"
LOG=/tmp/stress-server.log

step() { printf '\n\033[36m======== %s ========\033[0m\n' "$1"; }
ok()   { printf '  \033[32m[OK]\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; }
note() { printf '  \033[33m[NOTE]\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------- 0. 副本
step "0. 准备干净副本"
rm -rf "$APP"
cp -a "$SRC" "$APP"
mkdir -p "$APP/var/logs/ysl" "$APP/var/data"
KEY=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '%s' "$KEY" > "$APP/var/data/console.key"
ok "副本就绪 /app（控制台密钥 ${KEY:0:8}…）"

# ---------------------------------------------------------------- 1. 扩展
step "1. 安装随附解密扩展"
EXTDIR=$(php -r 'echo ini_get("extension_dir");')
cp "$APP/ext/beast-8.1.so" "$EXTDIR/beast.so"
cp "$APP/ext/beast.ini" /usr/local/etc/php/conf.d/beast.ini
if php -r 'exit(extension_loaded("beast") ? 0 : 1);'; then
    ok "beast 扩展已加载"
else
    bad "beast 扩展未加载，终止"
    exit 1
fi

# ---------------------------------------------------------------- 2. 语法
step "2. 新增探针语法检查"
if php -l "$APP/tools/stress/extreme.php" >/dev/null 2>&1; then
    ok "extreme.php 语法通过"
else
    php -l "$APP/tools/stress/extreme.php"
    bad "探针语法错误，终止"
    exit 1
fi

# ---------------------------------------------------------------- 3. 起服务
step "3. 启动多 worker 服务（PHP_CLI_SERVER_WORKERS=$WORKERS）"
# 提高 PHP 自身限制，把边界测试聚焦在 WAF 内核而不是 PHP 的 post_max_size / max_input_vars
cd "$APP" || exit 1
PHP_CLI_SERVER_WORKERS="$WORKERS" \
WAF_HOME="$APP" WAF_LOG_DIR="$LOGDIR" WAF_MODE=enforce \
php -d post_max_size=64M -d max_input_vars=100000 -d memory_limit=512M \
    -d max_execution_time=0 -d default_socket_timeout=30 \
    -S 127.0.0.1:$PORT -t "$APP/demo" "$APP/tools/e2e/router.php" \
    >"$LOG" 2>&1 &
SRV=$!

wait_http() {
    i=0
    while [ "$i" -lt 80 ]; do
        if timeout 3 php -d default_socket_timeout=1 -r \
            'exit(@file_get_contents("http://127.0.0.1:'"$PORT"'/") === false ? 1 : 0);' 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}
if wait_http; then ok "服务已起（8 worker）"; else bad "服务启动失败"; tail -30 "$LOG"; exit 1; fi

# 关闭限流：并发吞吐阶段不能被 429 污染；state 阶段单独打开
qps_off() { printf '{"qps":{"enabled":false}}' > "$APP/var/data/runtime.json"; }
# state 阶段：把阈值压到容器能实际打到的量级（8 worker 实测吞吐 ~30-50 req/s），
# 否则默认 80/s 单 IP 软阈值在 1s 窗口里根本触发不了，测不到状态一致性。
qps_on()  {
    printf '{"qps":{"enabled":true,"soft":200,"hard":400,"ip_soft":20,"ip_hard":80,"cooldown":3}}' \
        > "$APP/var/data/runtime.json"
    rm -f "$LOGDIR/ysl/qps_state.json" "$LOGDIR/ysl/circuit_state.json"
}
clean_state() {
    rm -f "$LOGDIR/ysl/qps_state.json" "$LOGDIR/ysl/circuit_state.json" 2>/dev/null
    rm -f "$LOGDIR"/ysl/chain_*.json "$LOGDIR"/ysl/window_*.json 2>/dev/null
    return 0
}
qps_off
clean_state

# ---------------------------------------------------------------- 4. 跑阶段
declare -A RC
run_stage() {
    local name="$1"; shift
    step "阶段：$name"
    local logf="/tmp/stress-$name.log"
    php "$APP/tools/stress/extreme.php" "http://127.0.0.1:$PORT" "$name" "$@" 2>&1 | tee "$logf"
    RC[$name]=${PIPESTATUS[0]}
    if [ "${RC[$name]}" = 0 ]; then
        ok "阶段 $name 通过"
    else
        bad "阶段 $name 存在失败项（exit=${RC[$name]}）"
    fi
}

STAGES="${STRESS_STAGES:-boundary evasion concurrency soak state}"
for s in $STAGES; do
    case "$s" in
        boundary)
            clean_state; run_stage boundary ;;
        evasion)
            clean_state; run_stage evasion ;;
        concurrency)
            clean_state; run_stage concurrency "${STRESS_N:-600}" "${STRESS_CC:-32}" ;;
        soak)
            clean_state; run_stage soak "${STRESS_N:-600}" "${STRESS_CC:-32}" ;;
        state)
            # 本阶段要真实开启限流/熔断
            qps_on; run_stage state; qps_off; clean_state ;;
        profile)
            clean_state; run_stage profile ;;
        *)
            note "未知阶段 $s，跳过" ;;
    esac
done

# ---------------------------------------------------------------- 5. 存活 / 噪音
step "5. 长稳后存活与日志体检"
FINAL=$(timeout 10 php -r '
$c = stream_context_create(["http" => ["ignore_errors" => true, "timeout" => 3]]);
@file_get_contents("http://127.0.0.1:8080/?final=1", false, $c);
echo preg_match("#HTTP/\S+\s+(\d{3})#", $http_response_header[0] ?? "", $m) ? $m[1] : "0";
' 2>/dev/null)
if [ "$FINAL" = "200" ]; then ok "极限打完后服务仍正常响应（200）"; else bad "最终探测实得 $FINAL"; fi

NOISE=$(grep -Ec 'arbitrate failed|degraded|Deprecated|PHP Warning|PHP Fatal|Parse error|Uncaught' "$LOG" 2>/dev/null || true)
AUDIT=$(find "$LOGDIR" -type f 2>/dev/null | wc -l)
SIZE=$(du -sh "$LOGDIR" 2>/dev/null | cut -f1)
printf '  服务日志噪音行：%s | 审计落盘文件：%s | 日志目录体积：%s\n' "$NOISE" "$AUDIT" "$SIZE"
if [ "$NOISE" = "0" ]; then ok "零日志噪音"; else note "存在 $NOISE 行日志噪音（详见服务日志）"; grep -E 'arbitrate failed|degraded|Deprecated|PHP Warning|PHP Fatal|Parse error|Uncaught' "$LOG" | head -8 | sed 's/^/    /'; fi

# ---------------------------------------------------------------- 6. 汇总
step "极限测试汇总"
TOTAL=0
for s in $STAGES; do
    r="${RC[$s]:-NA}"
    printf '  %-12s %s\n' "$s" "$r"
    [ "$r" = "0" ] || TOTAL=$((TOTAL + 1))
done
if [ "$TOTAL" = 0 ]; then
    printf '  \033[32m全部阶段通过\033[0m\n'
else
    printf '  \033[31m%d 个阶段存在失败项\033[0m（明细见各 /tmp/stress-*.log）\n' "$TOTAL"
fi

# ---------------------------------------------------------------- 收尾
pkill -f "dna.php watch" 2>/dev/null
kill "$SRV" 2>/dev/null
pkill -f "php -S 127.0.0.1:$PORT" 2>/dev/null
true
exit "$TOTAL"
