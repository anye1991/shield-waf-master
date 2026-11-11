#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
#
# 加密发行版 · 一键极限测试
#
#   bash tools/stress_extreme.sh
#   STRESS_N=1000 STRESS_CC=64 bash tools/stress_extreme.sh
#
# 在干净的 php:8.1-cli 里按 README 装好扩展，以多 worker 起服务，然后跑
# 边界/畸形、深度混淆逃逸、并发吞吐、20s 长稳、限流状态一致性五个阶段。
# 需要：本机已装 Docker。仓库只读挂载，测试全在容器副本 /app 内进行。

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${STRESS_IMAGE:-php:8.1-cli}"

echo "仓库：$REPO"
echo "镜像：$IMAGE"
echo "参数：N=${STRESS_N:-600} CC=${STRESS_CC:-32} WORKERS=${STRESS_WORKERS:-8}"
echo

MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$REPO:/src:ro" \
    -e "STRESS_N=${STRESS_N:-600}" \
    -e "STRESS_CC=${STRESS_CC:-32}" \
    -e "STRESS_WORKERS=${STRESS_WORKERS:-8}" \
    -e "STRESS_STAGES=${STRESS_STAGES:-boundary evasion concurrency soak state}" \
    "$IMAGE" \
    bash /src/tools/stress/inner.sh
