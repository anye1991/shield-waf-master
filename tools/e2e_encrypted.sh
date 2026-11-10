#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
#
# 加密发行版 · 一键容器验收
#
#   bash tools/e2e_encrypted.sh
#
# 作用：在干净的 php:8.1-cli 里按 README 的部署步骤装扩展，把仓库以只读挂载，
#      跑「向量拦截 + 内核解密 + 安装器自检 + observe 放行 + 缺扩展 503」全套检查。
# 需要：本机已装 Docker。

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${E2E_IMAGE:-php:8.1-cli}"

echo "仓库：$REPO"
echo "镜像：$IMAGE"
echo

# 说明：不改工作目录（Git Bash 会把容器内绝对路径错误改写成本机路径），
#       inner.sh 自己切到 /tmp/app 副本里执行。
MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$REPO:/src:ro" \
    "$IMAGE" \
    bash /src/tools/e2e/inner.sh
