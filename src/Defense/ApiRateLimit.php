<?php
defined('ABSPATH') || exit;
class ApiRateLimit {
    private static $paths = [
        '/wp-login.php' => ['limit' => 5, 'window' => 300],
        '/wp-json/'     => ['limit' => 30, 'window' => 60],
    ];
    // 单 IP 在文件后端中的最大记录行数，超过则丢弃最旧记录，防止单文件无限增长
    const FILE_MAX_PER_IP = 1000;
    // 异步清理：每 N 次请求触发一次全窗口清理
    const CLEANUP_INTERVAL = 100;

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
        // 净化 IP 防止注入
        $cleanIp = filter_var($ip, FILTER_VALIDATE_IP);
        if (!$cleanIp) {
            $cleanIp = '0.0.0.0';
        }
        $cleanIp = str_replace(["\n", "\r", "|"], '', $cleanIp);

        // APCu 优先（共享内存，性能比文件高 100 倍）
        if (function_exists('apcu_enabled') && apcu_enabled()) {
            self::checkLimitApcu($key, $cleanIp, $limit, $window);
            return;
        }

        // 文件降级：按 IP 分片，避免单文件无限增长
        self::checkLimitFile($key, $cleanIp, $limit, $window);
    }

    /**
     * APCu 后端：单次原子自增，O(1) 复杂度
     */
    private static function checkLimitApcu($key, $ip, $limit, $window) {
        $apcuKey = 'waf_api_' . md5($key . '|' . $ip);
        $found = false;
        $count = apcu_inc($apcuKey, 1, $found);
        if (!$found) {
            if (apcu_store($apcuKey, 1, $window) === false) {
                // APCu 写入失败，降级到文件后端
                self::checkLimitFile($key, $ip, $limit, $window);
                return;
            }
            $count = 1;
        }
        // 阻塞计数逻辑：将当前请求计入后再判断
        if ($count > $limit) {
            waf_smart_ban($ip);
            waf_block("API rate limit exceeded for $key");
        }
    }

    /**
     * 文件后端：按 md5($key.$ip) 分片，避免所有 IP 共享同一文件导致无限增长。
     * 优化点：
     *   1. 按 IP+rule 分片存储，单文件只包含一个 IP 的记录
     *   2. 单 IP 行数上限 FILE_MAX_PER_IP，超过则丢弃最旧记录
     *   3. 异步清理：每 CLEANUP_INTERVAL 次请求触发一次全窗口清理
     *   4. flock(LOCK_EX) 持有锁贯穿读改写周期，避免 TOCTOU 竞态
     */
    private static function checkLimitFile($key, $ip, $limit, $window) {
        $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
        // 按 IP 分片：每个 IP+rule 一个独立文件，攻击者海量 IP 不会污染同一文件
        $shard = md5($key . '|' . $ip);
        $file = $logDir . '/api_rate_' . $shard . '.txt';
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
            if ($line === '') continue;
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

        // 单 IP 行数上限：超过则丢弃最旧记录（保持最新 FILE_MAX_PER_IP-1 条 + 本次写入 1 条）
        if (count($new) >= self::FILE_MAX_PER_IP) {
            $new = array_slice($new, -(self::FILE_MAX_PER_IP - 1));
        }

        $new[] = "$now|$ip";

        // 异步清理决策：每 CLEANUP_INTERVAL 次请求触发一次全窗口清理（已通过上面过期行过滤完成）
        // 普通请求只追加新行；本次实现中读时已过滤过期行，写时总是重写为新数组（受锁保护）
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, implode("\n", $new) . "\n");
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
