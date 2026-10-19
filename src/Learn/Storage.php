<?php
/**
 * 存储适配层
 * 职责：统一 JSON 读写，优先复用项目现成函数，兜底本地原子写
 * 兼容：PHP 7.4+，无命名空间，无顶层副作用
 */
defined('ABSPATH') || exit;

class Learning_Storage {

    /** @var bool 是否优先使用项目原生函数 */
    private static $prefer_native = true;

    /** @var array 进程内读缓存 */
    private static $cache = [];
    private static $cache_ts = [];
    const CACHE_TTL = 5;

    public static function setPreferNative(bool $flag): void {
        self::$prefer_native = $flag;
    }

    /** 读 JSON */
    public static function read(string $file, array $default = []): array {
        $now = time();
        if (isset(self::$cache[$file]) && isset(self::$cache_ts[$file])
            && ($now - self::$cache_ts[$file]) < self::CACHE_TTL) {
            return self::$cache[$file];
        }

        $data = null;
        if (self::$prefer_native && function_exists('waf_safe_read_json')) {
            try {
                $r = @waf_safe_read_json($file, $default);
                if (is_array($r)) $data = $r;
            } catch (\Throwable $e) { $data = null; }
        }
        if ($data === null) {
            $data = self::localRead($file, $default);
        }

        self::$cache[$file] = $data;
        self::$cache_ts[$file] = $now;
        return $data;
    }

    /** 写 JSON */
    public static function write(string $file, array $data): bool {
        $ok = false;
        if (self::$prefer_native && function_exists('waf_safe_write_json')) {
            try {
                $r = @waf_safe_write_json($file, $data);
                if ($r !== false) $ok = true;
            } catch (\Throwable $e) { $ok = false; }
        }
        if (!$ok) {
            $ok = self::localWrite($file, $data);
        }
        if ($ok) {
            self::$cache[$file] = $data;
            self::$cache_ts[$file] = time();
        }
        return $ok;
    }

    public static function invalidate(string $file): void {
        unset(self::$cache[$file], self::$cache_ts[$file]);
    }

    private static function localRead(string $file, array $default): array {
        if (!is_file($file)) return $default;
        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') return $default;
        $data = json_decode($raw, true);
        return is_array($data) ? $data : $default;
    }

    private static function localWrite(string $file, array $data): bool {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0775, true) && !is_dir($dir)) return false;
        }
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) return false;

        $tmp = $file . '.tmp.' . getmypid() . '.' . mt_rand(1000, 9999);
        if (@file_put_contents($tmp, $json, LOCK_EX) === false) return false;
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }
}