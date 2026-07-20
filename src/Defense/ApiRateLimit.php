<?php
defined('ABSPATH') || exit;
class ApiRateLimit {
    private static $paths = [
        '/wp-login.php' => ['limit' => 5, 'window' => 300],
        '/wp-json/'     => ['limit' => 30, 'window' => 60],
    ];
    public static function check() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        // 提取精确路径，避免前缀匹配过宽（如 /wp-login.php.bak 误匹配）
        $path = parse_url($uri, PHP_URL_PATH);
        if ($path === false || $path === null) {
            $path = $uri;
        }
        foreach (self::$paths as $rule => $cfg) {
            if ($path === $rule || strpos($path, $rule) === 0) {
                self::checkLimit($rule, $cfg['limit'], $cfg['window']);
                break;
            }
        }
    }
    private static function checkLimit($key, $limit, $window) {
        $ip = waf_get_real_ip();
        $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
        $file = $logDir . 'api_rate_' . md5($key) . '.txt';
        $now = time();

        // 使用 fopen + flock(LOCK_EX) 持有锁完成整个读改写周期，避免 TOCTOU 竞态
        $fp = fopen($file, 'c+');
        if (!$fp) {
            if (defined('WAF_DEBUG') && WAF_DEBUG) {
                error_log('ShieldWAF ApiRateLimit: cannot open log file: ' . $file);
            }
            return;
        }

        flock($fp, LOCK_EX);

        $contents = stream_get_contents($fp);
        $lines = $contents ? explode("\n", trim($contents)) : [];

        $new = [];
        $count = 0;
        foreach ($lines as $line) {
            $parts = explode('|', $line, 2);
            $ts = (int)$parts[0];
            $lip = $parts[1] ?? '';
            if ($ts > $now - $window) {
                if ($lip === $ip) {
                    $count++;
                }
                $new[] = $line;
            }
        }

        // 阻塞计数逻辑：将当前请求计入后再判断
        if ($count + 1 > $limit) {
            flock($fp, LOCK_UN);
            fclose($fp);
            waf_smart_ban($ip);
            waf_block("API rate limit exceeded for $key");
        }

        // 净化 IP 防止注入
        $cleanIp = filter_var($ip, FILTER_VALIDATE_IP);
        if (!$cleanIp) {
            $cleanIp = '0.0.0.0';
        }
        $cleanIp = str_replace(["\n", "\r", "|"], '', $cleanIp);
        $new[] = "$now|$cleanIp";

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, implode("\n", $new) . "\n");
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
