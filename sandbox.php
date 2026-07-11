<?php
defined('ABSPATH') || exit;

class WafSandbox {
    private static $protected_ext = ['php', 'phtml', 'php5', 'php7', 'inc', 'shtml', 'cgi', 'pl', 'py', 'asp', 'aspx', 'jsp'];
    private static $log_file = null;

    public static function init() {
        self::$log_file = WAF_LOG_PATH . 'sandbox.log';
        if (php_sapi_name() === 'cli') return;
        if (waf_is_admin_ip()) return;
        register_shutdown_function(['WafSandbox', 'checkFileChanges']);
    }

    private static function fileSnapshot() {
        $cache = WAF_LOG_PATH . 'sandbox_snapshot.json';
        if (is_file($cache) && time() - filemtime($cache) < 300) {
            return json_decode(file_get_contents($cache), true);
        }
        $snapshot = [];
        $dirs = [ABSPATH];
        foreach ($dirs as $dir) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $path = $file->getPathname();
                    $ext = strtolower($file->getExtension());
                    if (in_array($ext, self::$protected_ext)) {
                        $snapshot[$path] = md5_file($path);
                    }
                }
            }
        }
        @file_put_contents($cache, json_encode($snapshot));
        return $snapshot;
    }

    public static function checkFileChanges() {
        $before = self::fileSnapshot();
        $after = [];
        $dirs = [ABSPATH];
        foreach ($dirs as $dir) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $path = $file->getPathname();
                    $ext = strtolower($file->getExtension());
                    if (in_array($ext, self::$protected_ext)) {
                        $after[$path] = md5_file($path);
                    }
                }
            }
        }
        $new_files = array_diff_key($after, $before);
        $modified = [];
        foreach ($after as $path => $hash) {
            if (isset($before[$path]) && $before[$path] !== $hash) {
                $modified[] = $path;
            }
        }
        if (!empty($new_files) || !empty($modified)) {
            $msg = sprintf("沙箱告警！新增: %s, 修改: %s",
                implode(', ', array_keys($new_files)),
                implode(', ', $modified));
            @file_put_contents(self::$log_file, date('Y-m-d H:i:s') . " | $msg\n", FILE_APPEND);
        }
    }

    public static function checkFileWrite($filename) {
        if (waf_is_admin_ip()) return true;
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (in_array($ext, self::$protected_ext)) {
            @file_put_contents(self::$log_file, date('Y-m-d H:i:s') . " | 拦截写入: $filename\n", FILE_APPEND);
            return false;
        }
        return true;
    }
}