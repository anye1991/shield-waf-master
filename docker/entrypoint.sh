#!/bin/sh
# ============================================
# 盾甲 WAF Docker 入口脚本
# ============================================

set -e

# 创建必要的运行时目录
mkdir -p /var/www/html/logs /var/www/html/data /var/log/supervisor /var/log/nginx /var/run
chown -R www-data:www-data /var/www/html/logs /var/www/html/data
chmod 750 /var/www/html/logs /var/www/html/data

# 如果 .env 文件不存在，从环境变量生成
ENV_FILE="/var/www/html/.env"
if [ ! -s "$ENV_FILE" ]; then
    echo "# 盾甲 WAF 环境变量（由 Docker 自动生成）" > "$ENV_FILE"
    echo "WAF_MAGIC_KEY=${WAF_MAGIC_KEY:-change-me-magic-key-32-chars-min}" >> "$ENV_FILE"
    echo "WAF_2FA_PASS=${WAF_2FA_PASS:-change-me-2fa-password}" >> "$ENV_FILE"
    echo "WAF_WEBHOOK_URL=${WAF_WEBHOOK_URL:-}" >> "$ENV_FILE"
    echo "WAF_TRUST_CF_IP=${WAF_TRUST_CF_IP:-false}" >> "$ENV_FILE"
    echo "WAF_BOT_VERIFY_DNS=${WAF_BOT_VERIFY_DNS:-false}" >> "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    chown www-data:www-data "$ENV_FILE"
    echo "[entrypoint] .env 文件已生成"
fi

# 确保 PHP session 目录可写
mkdir -p /var/lib/php/sessions
chown -R www-data:www-data /var/lib/php/sessions

# 确保 nginx 临时目录可写
mkdir -p /var/cache/nginx
chown -R www-data:www-data /var/cache/nginx

# 如果传入了自定义命令，执行它
if [ "$1" != "supervisord" ]; then
    exec "$@"
fi

echo "=========================================="
echo "  盾甲 WAF v3.0.0 启动中..."
echo "  仪表盘: http://<host>:<port>/waf-dashboard"
echo "  日志:   /var/www/html/logs/"
echo "=========================================="

exec "$@"
