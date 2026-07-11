<?php
defined('ABSPATH') || exit;

class WafStats {
    public static function getAttacks($days = 7) {
        $logDir = WAF_LOG_PATH;
        $attacks = [];
        $now = time();
        for ($i = 0; $i < $days; $i++) {
            $date = date('Y-m-d', $now - $i * 86400);
            $file = $logDir . 'block_' . $date . '.log';
            if (!is_file($file)) continue;
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (preg_match('/^([\d\-]+ [\d:]+) \| IP: ([^|]+) \| URI: ([^|]+) \| Msg: (.+)$/', $line, $m)) {
                    $attacks[] = [
                        'time' => $m[1],
                        'ip'   => trim($m[2]),
                        'uri'  => trim($m[3]),
                        'msg'  => trim($m[4]),
                    ];
                }
            }
        }
        return $attacks;
    }

    public static function classify($msg) {
        $msg = strtolower($msg);
        if (strpos($msg, 'sql') !== false || strpos($msg, 'union') !== false || strpos($msg, 'select') !== false) return 'SQL 注入';
        if (strpos($msg, 'xss') !== false || strpos($msg, 'script') !== false || strpos($msg, 'onerror') !== false) return 'XSS 攻击';
        if (strpos($msg, '文件包含') !== false || strpos($msg, 'upload') !== false || strpos($msg, '上传') !== false) return '文件上传攻击';
        if (strpos($msg, 'cc') !== false || strpos($msg, '频繁') !== false || strpos($msg, 'rate') !== false) return 'CC 攻击';
        if (strpos($msg, '参数污染') !== false) return '参数污染';
        if (strpos($msg, '遍历') !== false || strpos($msg, '../') !== false) return '路径遍历';
        if (strpos($msg, '命令') !== false || strpos($msg, 'exec') !== false) return '命令注入';
        return '其他攻击';
    }

    public static function summary($attacks) {
        $total = count($attacks);
        $ips = $types = $daily = [];
        $latest = array_slice($attacks, -20);
        foreach ($attacks as $a) {
            $ips[$a['ip']] = ($ips[$a['ip']] ?? 0) + 1;
            $type = self::classify($a['msg']);
            $types[$type] = ($types[$type] ?? 0) + 1;
            $day = substr($a['time'], 0, 10);
            $daily[$day] = ($daily[$day] ?? 0) + 1;
        }
        ksort($daily);
        arsort($ips);
        return [
            'total'   => $total,
            'top_ips' => array_slice($ips, 0, 10, true),
            'types'   => $types,
            'daily'   => $daily,
            'latest'  => $latest,
        ];
    }
}