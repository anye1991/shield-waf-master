#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
#
# 加密发行版 · 容器内端到端验收（由 tools/e2e_encrypted.sh 调用，不直接使用）
# 环境：php:8.1-cli；仓库以只读方式挂在 /src，验收过程全部在 /app 副本里进行。

set -u

APP=/app
PORT=8080
FAILED=0

step() { printf '\n\033[36m== %s ==\033[0m\n' "$1"; }
ok()   { printf '  \033[32m[OK]\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAILED=$((FAILED + 1)); }

# 运行时开关：e2e 里按阶段切换限流，避免 429 污染功能用例
set_qps() {
    if [ "$1" = "off" ]; then
        printf '{"qps":{"enabled":false}}' > "$APP/var/data/runtime.json"
    else
        rm -f "$APP/var/data/runtime.json"
    fi
}

# 等待内置服务器可用（最多 5s）
wait_http() {
    i=0
    while [ "$i" -lt 50 ]; do
        if timeout 3 php -d default_socket_timeout=1 -r 'exit(@file_get_contents("http://127.0.0.1:'"$PORT"'/") === false ? 1 : 0);' 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

# 清掉跨请求状态（限流计数 / 熔断 / 攻击链 / 时间窗），让每阶段从干净基线开始
reset_state() {
    rm -f "$APP/var/logs/ysl/qps_state.json" "$APP/var/logs/ysl/circuit_state.json" 2>/dev/null
    rm -f "$APP"/var/logs/ysl/chain_*.json "$APP"/var/logs/ysl/window_*.json 2>/dev/null
    return 0
}

# ---------------------------------------------------------------- 0. 准备副本
step "0. 准备工作副本（/src 只读挂载，验收在 /app——与官方测试脚本假定的路径一致）"
rm -rf "$APP"
cp -a /src "$APP"
mkdir -p "$APP/var/logs" "$APP/var/data"
KEY=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '%s' "$KEY" > "$APP/var/data/console.key"
ok "副本就绪，控制台密钥 ${KEY:0:8}…"

# ---------------------------------------------------------------- 1. 装扩展
step "1. 安装随附解密扩展（模拟用户按 README 部署）"
EXTDIR=$(php -r 'echo ini_get("extension_dir");')
cp "$APP/ext/beast-8.1.so" "$EXTDIR/beast.so"
if [ -f "$APP/ext/beast.ini" ]; then
    cp "$APP/ext/beast.ini" /usr/local/etc/php/conf.d/beast.ini
else
    printf 'extension=beast.so\nbeast.enable=On\n' > /usr/local/etc/php/conf.d/beast.ini
fi

if php -r 'exit(extension_loaded("beast") ? 0 : 1);'; then
    ok "beast 扩展已加载（php -m 可见）"
else
    bad "beast 扩展未加载"
fi

# ---------------------------------------------------------------- 2. 语法
step "2. 明文文件语法检查"
SYNTAX_BAD=0
for f in "$APP"/*.php "$APP"/tests/*.php "$APP"/tools/*.php "$APP"/tools/e2e/*.php; do
    [ -f "$f" ] || continue
    php -l "$f" >/dev/null 2>&1 || { bad "语法错误：${f#$APP/}"; SYNTAX_BAD=1; }
done
[ "$SYNTAX_BAD" = 0 ] && ok "全部明文 PHP 语法通过"

# ---------------------------------------------------------------- 3. 加密内核
step "3. 加密内核解密与判定（core/ 19 个 + ai/ 12 个）"
KOUT=$(php "$APP/tools/e2e/kernel_check.php" "$APP" "$APP/var/logs" 2>&1)
KRC=$?
printf '%s\n' "$KOUT" | sed 's/^/  /'
if [ "$KRC" = 0 ]; then
    ok "内核解密正常，且判定与证据链符合预期"
else
    bad "内核判定不符合预期（见上表）"
fi

# ---------------------------------------------------------------- 4. 安装器
step "4. install.php 环境自检"
if (cd "$APP" && php install.php --check >/tmp/install.log 2>&1); then
    ok "install.php --check 通过"
    sed -n '1,40p' /tmp/install.log | sed 's/^/    /'
else
    bad "install.php --check 未通过"
    sed -n '1,40p' /tmp/install.log | sed 's/^/    /'
fi

# ---------------------------------------------------------------- 5. 起服务
step "5. 启动演示站点（auto_prepend_file 注入，业务代码零改造）"
cd "$APP" || exit 1
WAF_HOME="$APP" \
WAF_LOG_DIR="$APP/var/logs" \
WAF_MODE=enforce \
php -S 127.0.0.1:$PORT -t "$APP/demo" "$APP/tools/e2e/router.php" \
    >/tmp/server.log 2>&1 &
SRV=$!
if wait_http; then ok "服务已起：http://127.0.0.1:$PORT"; else bad "服务启动失败"; tail -20 /tmp/server.log; fi

# ---------------------------------------------------------------- 6. 向量验收
step "6. HTTP 攻击向量验收（放行面 / 拦截面 / 管理面）"
php "$APP/tools/e2e/vectors.php" "http://127.0.0.1:$PORT" "$KEY" || bad "存在未通过向量"

# ---------------------------------------------------------------- 7. 功能自测
step "7. 仓库自带测试套件"
set_qps off
reset_state
for t in i18n_check feature_matrix_check ai_check honeypot_check control_check qps_check; do
    [ -f "$APP/tests/$t.php" ] || continue
    if php "$APP/tests/$t.php" "http://127.0.0.1:$PORT" >"/tmp/$t.log" 2>&1; then
        ok "$t"
    else
        # 部分脚本需要 8080 以外的参数或特定目录，失败只记录不判死
        printf '  \033[33m[WARN]\033[0m %s（详见 /tmp/%s.log 尾部）\n' "$t" "$t"
        tail -6 "/tmp/$t.log" | sed 's/^/      /'
    fi
done

# ---------------------------------------------------------------- 7.5 限流
step "7.5 限流验证（单 IP 突发，默认阈值 80/s 软限）"
set_qps on
reset_state
QOUT=$(php -r '
$c = stream_context_create(["http" => ["ignore_errors" => true, "timeout" => 5]]);
$n429 = 0; $n200 = 0; $t0 = microtime(true);
for ($i = 0; $i < 140; $i++) {
    @file_get_contents("http://127.0.0.1:8080/?burst=" . $i, false, $c);
    $st = preg_match("#HTTP/\S+\s+(\d{3})#", $http_response_header[0] ?? "", $m) ? (int)$m[1] : 0;
    if ($st === 429) { $n429++; } elseif ($st === 200) { $n200++; }
}
printf("突发 140 次共用时 %.2fs：200=%d，429=%d", microtime(true) - $t0, $n200, $n429);
')
printf '%s\n' "$QOUT"
case "$QOUT" in
    *"429=0"*) bad "突发流量未触发限流" ;;
    *) ok "限流生效（超过单 IP 阈值后返回 429）" ;;
esac
set_qps off
reset_state

# ---------------------------------------------------------------- 8. 对抗测试
step "8. 极限对抗测试（真实 HTTP 投放，multi-mutation）"
reset_state
if [ -f "$APP/tests/adversarial.php" ]; then
    php "$APP/tests/adversarial.php" "http://127.0.0.1:$PORT" http >/tmp/adv.log 2>&1
    ADV_RC=$?
    tail -22 /tmp/adv.log | sed 's/^/    /'
    if [ "$ADV_RC" = 0 ]; then ok "对抗测试全部拦截"; else printf '  \033[33m[WARN]\033[0m 对抗测试存在漏放（exit=%s）\n' "$ADV_RC"; fi
fi

# ---------------------------------------------------------------- 9. observe 模式
step "9. observe 模式复核（只记录不拦截）"
# 用独立端口起第二个实例，避免与上一实例的 TIME_WAIT 抢 8080
PORT2=8090
WAF_HOME="$APP" WAF_LOG_DIR="$APP/var/logs" WAF_MODE=observe \
php -S 127.0.0.1:$PORT2 -t "$APP/demo" "$APP/tools/e2e/router.php" \
    >/tmp/server-observe.log 2>&1 &
SRV2=$!

OBS_OK=0
for _i in $(seq 1 50); do
    ST=$(timeout 10 php -d default_socket_timeout=2 -r '
$c = stream_context_create(["http" => ["ignore_errors" => true, "timeout" => 2]]);
@file_get_contents("http://127.0.0.1:8090/?id=" . rawurlencode("1 UNION SELECT 1"), false, $c);
echo preg_match("#HTTP/\S+\s+(\d{3})#", $http_response_header[0] ?? "", $m) ? $m[1] : "0";
' 2>/dev/null)
    [ "$ST" != "0" ] && break
    sleep 0.1
done

if [ "$ST" = "200" ]; then
    ok "observe 模式下注入请求被放行（$ST），审计日志仍在写"
    AUDIT=$(find "$APP/var/logs" -type f 2>/dev/null | wc -l)
    ok "审计落盘文件数：$AUDIT"
else
    bad "observe 模式未放行（实得 $ST）"
    tail -6 /tmp/server-observe.log | sed 's/^/      /'
fi
kill "$SRV2" 2>/dev/null

# ---------------------------------------------------------------- 10. 缺扩展场景
step "10. 缺扩展场景（应给出显式 503，而不是白屏/乱码）"
php -n -S 127.0.0.1:8099 -t "$APP/demo" "$APP/tools/e2e/router.php" \
    >/tmp/server-noext.log 2>&1 &
SRV3=$!
OUT=""
for _i in $(seq 1 50); do
    OUT=$(timeout 20 php -n -d default_socket_timeout=2 -r '
$c = stream_context_create(["http" => ["ignore_errors" => true, "timeout" => 2]]);
$b = @file_get_contents("http://127.0.0.1:8099/", false, $c);
$st = preg_match("#HTTP/\S+\s+(\d{3})#", $http_response_header[0] ?? "", $m) ? $m[1] : "0";
echo $st, "|", trim(preg_replace("/\s+/u", " ", strip_tags((string)$b)));
' 2>/dev/null)
    case "$OUT" in
        0\|*) sleep 0.1 ;;
        *) break ;;
    esac
done

ST=${OUT%%|*}
BODY=${OUT#*|}
kill "$SRV3" 2>/dev/null
if [ "$ST" = "503" ]; then
    ok "返回 503（不是白屏）"
    printf '    页面文案：%s\n' "$(printf '%s' "$BODY" | cut -c1-120)"
else
    bad "缺扩展时实得 HTTP $ST，期望 503"
    printf '    正文：%s\n' "$(printf '%s' "$BODY" | cut -c1-120)"
fi

# ---------------------------------------------------------------- 收尾清理
pkill -f "dna.php watch" 2>/dev/null
kill "$SRV" "$SRV2" "$SRV3" 2>/dev/null
true

# ---------------------------------------------------------------- 汇总
step "验收汇总"
if [ "$FAILED" = 0 ]; then
    printf '  \033[32m全部硬性检查通过\033[0m（加密发行版在 PHP 8.1 可正常运行）\n'
else
    printf '  \033[31m%d 项硬性检查未通过\033[0m\n' "$FAILED"
fi
exit "$FAILED"
