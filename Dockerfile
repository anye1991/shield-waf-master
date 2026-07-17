# ============================================
# 盾甲 WAF v3.0.0 Docker 镜像
# ============================================
# 构建：docker build -t shield-waf .
# 运行：docker run -d -p 80:80 --name shield-waf shield-waf
#
# 官方镜像（GitHub Container Registry）：
#   ghcr.io/anye1991/shield-waf:3.0.0
#
# 快速启动：
#   docker run -d -p 8080:80 ghcr.io/anye1991/shield-waf:3.0.0
#
# 带自定义环境变量：
#   docker run -d -p 8080:80 \
#     -e WAF_MAGIC_KEY=your-magic-key \
#     -e WAF_2FA_PASS=your-2fa-pass \
#     ghcr.io/anye1991/shield-waf:3.0.0
# ============================================

FROM php:8.2-fpm-alpine

LABEL org.opencontainers.image.title="Shield WAF"
LABEL org.opencontainers.image.description="盾甲 WAF v3.0.0 - 全球顶级编码归一化 · 10维语义分析 · 主动路径围堵"
LABEL org.opencontainers.image.version="3.0.0"
LABEL org.opencontainers.image.source="https://github.com/anye1991/shield-waf-master"

# 安装 Nginx 和常用工具
RUN apk add --no-cache nginx supervisor curl && \
    rm -rf /var/cache/apk/*

# 复制 Nginx 配置
COPY docker/nginx.conf /etc/nginx/nginx.conf

# 复制 Supervisor 配置（管理 nginx + php-fpm）
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 创建工作目录
WORKDIR /var/www/html

# 复制项目文件
COPY config.php stats.php shield-waf.php .env.example .htaccess /var/www/html/
COPY src /var/www/html/src

# 创建日志和数据目录（运行时 volume 挂载点）
RUN mkdir -p /var/www/html/logs /var/www/html/data && \
    chown -R www-data:www-data /var/www/html/logs /var/www/html/data && \
    chmod 750 /var/www/html/logs /var/www/html/data

# 设置 .env 权限（如果有的话）
RUN touch /var/www/html/.env && chown www-data:www-data /var/www/html/.env && chmod 600 /var/www/html/.env

# PHP 优化：安装常见扩展
RUN docker-php-ext-install opcache && \
    docker-php-ext-enable opcache

# 复制 PHP 优化配置
COPY docker/php.ini /usr/local/etc/php/conf.d/99-shield-waf.ini

# 复制入口脚本
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/waf-dashboard || exit 1

# 暴露 80 端口
EXPOSE 80

# 入口
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
