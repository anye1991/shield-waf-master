#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
#
# GitHub Actions / 本地通用端到端验收编排（非 Docker）。
#
#   bash tools/e2e/ci.sh
#
# 与 tools/e2e/inner.sh 的区别：inner.sh 是容器内验收（假定 /src 只读挂载、
# /app 可写、可改 /usr/local/etc/php/conf.d）；本脚本面向 GitHub Actions runner
# 与普通 Linux 主机，路径全部由脚本位置推导，不依赖 /src、不需要特权改 php 配置，
# 通过 WAF_TEST_BASE / WAF_TEST_HOME 把地址与源码根传给测试套件。
#
# 前提：PHP 8.1 + 随附 php-beast 扩展已由调用方装好（CI 的 setup-php 步骤）。
# 任一步骤失败即累计 FAILED，退出码非 0 —— 不再把功能用例失败降级为 WARN。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT_START="${WAF_TEST_PORT:-8080}"
FAILED=0

# 找一个当前未被占用的回环端口（跳开生产机上其它服务占用的端口），
# 避免兼容性回归的实例与既有监听冲突导致误判。
free_port() {
    local p
    for p in $(seq "$1" $(( $1 + 200 ))); do
        # 能绑定 => 端口空闲 => php 退出 0
        if php -r '$s=@stream_socket_server("tcp://127.0.0.1:'"$p"'",$e,$m); exit($s?0:1);' 2>/dev/null; then
            echo "$p"; return 0
        fi
    done
    echo "$1"; return 1
}

step() { printf '\n\033[36m== %s ==\033[0m\n' "$1"; }
ok()   { printf '  \033[32m[OK]\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAILED=$((FAILED + 1)); }

PORT="$(free_port "$PORT_START")"
BASE="http://127.0.0.1:${PORT}"

export WAF_TEST_BASE="$BASE"
export WAF_TEST_HOME="$ROOT"
export WAF_HOME="$ROOT"
export WAF_LOG_DIR="$ROOT/var/logs"
export WAF_MODE=enforce

mkdir -p "$ROOT/var/logs" "$ROOT/var/data"
if [ ! -s "$ROOT/var/data/console.key" ]; then
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ROOT/var/data/console.key"
fi
KEY="$(cat "$ROOT/var/data/console.key")"

# 每次从「与当前源码匹配的干净基线」开始：
# 本地反复运行或源码被重新解压后，上一次留下的 baseline.json 会与当前文件
# HMAC 失配；而 status/scan/audit/restore 又要求基线必须存在（plan/selftest 不需要）。
# 因此不能简单删除，而是按当前文件重建一份（CI 全新 checkout 同样适用）。
php "$ROOT/dna.php" baseline --root="$ROOT" >/dev/null 2>&1 \
    || echo "  [WARN] 初始 DNA 基线建立失败（control_check 会自行重建，通常不影响）"

# 功能用例阶段关限流，避免 429 污染判定（qps_check 会自行通过控制端点开启限流）
set_qps_off() { printf '{"qps":{"enabled":false}}' > "$ROOT/var/data/runtime.json"; }
reset_state() {
    rm -f "$ROOT/var/logs/ysl/qps_state.json" "$ROOT/var/logs/ysl/circuit_state.json" 2>/dev/null
    rm -f "$ROOT"/var/logs/ysl/chain_*.json "$ROOT"/var/logs/ysl/window_*.json 2>/dev/null
    return 0
}

wait_http() {
    local i=0 p="${1:-$PORT}"
    while [ "$i" -lt 80 ]; do
        if WAF_TEST_BASE="http://127.0.0.1:${p}" \
           php -r 'exit(@file_get_contents(getenv("WAF_TEST_BASE")."/") === false ? 1 : 0);' 2>/dev/null; then
            return 0
        fi
        i=$((i + 1)); sleep 0.15
    done
    return 1
}

SRV=""
cleanup() {
    if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; SRV=""; fi
    # control_check 会真实拉起 dna.php watch 守护，收尾必须清掉，避免残留进程
    pkill -f "dna.php watch" 2>/dev/null || true
    rm -f "$ROOT/var/data/runtime.json"   # 恢复出厂，不把测试态留给后续步骤
}
trap cleanup EXIT

# 每个用例独立日志，失败打印尾部便于 CI 定位
run_case() {
    local name="$1"; shift
    if timeout 180 "$@" >"/tmp/ysl-ci-${name}.log" 2>&1; then
        ok "$name"
    else
        bad "$name (exit=$?)"
        tail -20 "/tmp/ysl-ci-${name}.log" | sed 's/^/      /'
    fi
}

step "0. 环境"
php -v | head -1
php -m | grep -i beast >/dev/null && ok "php-beast 已加载" || bad "php-beast 未加载（core/、ai/ 无法解密）"
ok "BASE=$BASE  HOME=$ROOT"

step "1. 内核解密判定 / 安装器自检 / 静态规则"
run_case kernel_check  php "$ROOT/tools/e2e/kernel_check.php" "$ROOT" "$ROOT/var/logs"
run_case install_check php "$ROOT/install.php" --check
run_case static_check  php "$ROOT/tools/static_check.php"

step "2. 启动演示站点（auto_prepend_file 注入，业务代码零改造）"
set_qps_off
cd "$ROOT" || exit 1
php -S "127.0.0.1:${PORT}" -t "$ROOT/demo" "$ROOT/tools/e2e/router.php" \
    >/tmp/ysl-ci-server.log 2>&1 &
SRV=$!
if wait_http; then ok "服务就绪：$BASE"; else bad "服务未就绪"; tail -30 /tmp/ysl-ci-server.log; fi

step "3. 官方向量验收（放行面 / 拦截面 / 管理面）"
run_case vectors php "$ROOT/tools/e2e/vectors.php" "$BASE" "$KEY"

step "4. 自包含测试（内核语义 / AI 自学习 / 对抗语料）"
run_case ai_check     php "$ROOT/tests/ai_check.php"
run_case adversarial  php "$ROOT/tests/adversarial.php" "$BASE" engine

step "5. HTTP 功能套件（关限流，逐个按退出码判死）"
for t in i18n_check feature_matrix_check honeypot_check control_check; do
    reset_state; set_qps_off
    run_case "$t" php "$ROOT/tests/${t}.php" "$BASE"
done

step "6. 限流专项（qps_check 自行经控制端点开启限流）"
reset_state
rm -f "$ROOT/var/data/runtime.json"
run_case qps_check php "$ROOT/tests/qps_check.php" "$BASE"
set_qps_off

# 收掉主服务，后续冒烟用独立端口，避免 TIME_WAIT 抢占
cleanup

step "7. 兼容性回归：disable_functions=putenv 不应整站 500"
P2="$(free_port $((PORT + 1)))"
set_qps_off
php -d disable_functions=putenv -S "127.0.0.1:${P2}" -t "$ROOT/demo" \
    "$ROOT/tools/e2e/router.php" >/tmp/ysl-ci-putenv.log 2>&1 &
SRV=$!
if wait_http "$P2"; then
    CODE=$(php -r '
        $c = stream_context_create(["http" => ["ignore_errors" => true, "timeout" => 5]]);
        @file_get_contents("http://127.0.0.1:'"$P2"'/", false, $c);
        echo preg_match("#HTTP/\S+\s+(\d{3})#", $http_response_header[0] ?? "", $m) ? $m[1] : "0";
    ' 2>/dev/null)
    if [ "$CODE" = "200" ]; then ok "禁用 putenv 仍返回 200（v6.5.1 兜底生效）";
    else bad "禁用 putenv 实得 HTTP $CODE，期望 200"; grep -i "fatal" /tmp/ysl-ci-putenv.log | head -3; fi
else
    bad "禁用 putenv 的演示站点未就绪"; tail -12 /tmp/ysl-ci-putenv.log
fi
cleanup

step "8. 兼容性回归：缺解密扩展应显式 503，而非白屏"
P3="$(free_port $((P2 + 1)))"
set_qps_off
php -n -S "127.0.0.1:${P3}" -t "$ROOT/demo" "$ROOT/tools/e2e/router.php" \
    >/tmp/ysl-ci-noext.log 2>&1 &
SRV=$!
CODE=""
for _i in $(seq 1 60); do
    CODE=$(php -n -r '
        $c = stream_context_create(["http" => ["ignore_errors" => true, "timeout" => 2]]);
        @file_get_contents("http://127.0.0.1:'"$P3"'/", false, $c);
        echo preg_match("#HTTP/\S+\s+(\d{3})#", $http_response_header[0] ?? "", $m) ? $m[1] : "0";
    ' 2>/dev/null)
    [ "$CODE" != "0" ] && break
    sleep 0.15
done
if [ "$CODE" = "503" ]; then ok "缺扩展返回 503（fail-closed，非白屏）";
else bad "缺扩展实得 HTTP ${CODE:-无响应}，期望 503"; tail -12 /tmp/ysl-ci-noext.log; fi
cleanup

step "验收汇总"
if [ "$FAILED" -eq 0 ]; then
    printf '  \033[32m全部检查通过\033[0m（CI 与本地一致）\n'
else
    printf '  \033[31m%d 项检查未通过\033[0m\n' "$FAILED"
fi
exit "$FAILED"
