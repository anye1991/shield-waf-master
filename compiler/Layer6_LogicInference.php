<?php
defined('ABSPATH') || exit;

/**
 * Layer6：逻辑推理层
 *
 * 通过模式识别检测输入中的逻辑矛盾、条件绕过、永真/永假表达式等，
 * 并据此推理攻击者的可能意图。
 */
class Layer6_LogicInference {

    /**
     * 分析输入中的逻辑特征
     *
     * @param string $text 待分析文本
     * @return array ['score'=>0-100, 'inferences'=>[...]]
     */
    public static function analyze(string $text): array {
        $result = [
            'score'      => 0,
            'inferences' => [],
        ];

        if ($text === '') {
            return $result;
        }

        $score = 0;
        $lower = strtolower($text);

        // 1. 永真表达式检测（OR 1=1 类）
        $tautologyPatterns = [
            ['pattern' => '/\bor\s+1\s*=\s*1\b/i',         'name' => 'OR 1=1 永真',         'weight' => 25],
            ['pattern' => '/\bor\s+\'?1\'?\s*=\s*\'?1\'?/i', 'name' => 'OR 1=1 永真(引号)',   'weight' => 25],
            ['pattern' => '/\bor\s+true\b/i',               'name' => 'OR true 永真',        'weight' => 22],
            ['pattern' => '/\bor\s+\w+\s*=\s*\w+\s*--/i',   'name' => 'OR 注释截断永真',     'weight' => 25],
            ['pattern' => '/\band\s+1\s*=\s*1\b/i',         'name' => 'AND 1=1 永真',        'weight' => 20],
            ['pattern' => '/\band\s+1\s*=\s*2\b/i',         'name' => 'AND 1=2 永假(盲注探测)', 'weight' => 18],
            ['pattern' => '/\bor\s+1\s*=\s*2\b/i',          'name' => 'OR 1=2 永假(盲注探测)',  'weight' => 18],
            ['pattern' => '/\bor\s+\d+\s*=\s*\d+\b/i',      'name' => 'OR 数值永真',         'weight' => 22],
            ['pattern' => '/\bor\s+\'[^\']*\'\s*=\s*\'[^\']*\'/i', 'name' => 'OR 字符串永真', 'weight' => 22],
        ];
        foreach ($tautologyPatterns as $rule) {
            if (preg_match($rule['pattern'], $text)) {
                $score += $rule['weight'];
                $result['inferences'][] = [
                    'type'  => 'tautology',
                    'name'  => $rule['name'],
                    'desc'  => '检测到永真/永假表达式，用于绕过认证或盲注探测',
                ];
            }
        }

        // 2. 条件绕过检测
        $bypassPatterns = [
            ['pattern' => '/--\s*$/',                       'name' => 'SQL 行尾注释截断', 'weight' => 18],
            ['pattern' => '/\/\*.*?\*\//s',                 'name' => 'SQL 块注释绕过',   'weight' => 15],
            ['pattern' => '/#\s*$/',                        'name' => 'SQL #注释截断',    'weight' => 15],
            ['pattern' => '/\bunion\s+(?:all\s+)?select\b/i','name' => 'UNION 查询叠加',   'weight' => 22],
            ['pattern' => '/\bexists\s*\(/i',               'name' => 'EXISTS 子查询绕过','weight' => 15],
            ['pattern' => '/\blike\s+[\'"]%/i',             'name' => 'LIKE 通配符绕过',  'weight' => 12],
            ['pattern' => '/\bin\s*\(/i',                   'name' => 'IN 子句绕过',      'weight' => 12],
            ['pattern' => '/\bcase\s+when\b/i',             'name' => 'CASE WHEN 条件',   'weight' => 18],
            ['pattern' => '/\bif\s*\(/i',                   'name' => 'IF 条件分支',      'weight' => 15],
            ['pattern' => '/\bwaitfor\s+delay\b/i',         'name' => 'WAITFOR 延时',     'weight' => 20],
            ['pattern' => '/\bsleep\s*\(/i',                'name' => 'SLEEP 延时',       'weight' => 22],
            ['pattern' => '/\bbenchmark\s*\(/i',            'name' => 'BENCHMARK 延时',   'weight' => 22],
        ];
        foreach ($bypassPatterns as $rule) {
            if (preg_match($rule['pattern'], $text)) {
                $score += $rule['weight'];
                $result['inferences'][] = [
                    'type'  => 'bypass',
                    'name'  => $rule['name'],
                    'desc'  => '检测到条件绕过技术',
                ];
            }
        }

        // 3. 编码/混淆推理
        $obfuscationPatterns = [
            ['pattern' => '/0x[0-9a-f]{4,}/i',          'name' => '十六进制编码载荷', 'weight' => 12],
            ['pattern' => '/\\\\x[0-9a-fA-F]{2}/',      'name' => '转义序列',         'weight' => 12],
            ['pattern' => '/char\s*\(\s*\d+/i',         'name' => 'CHAR() 编码',      'weight' => 15],
            ['pattern' => '/concat\s*\(/i',             'name' => 'CONCAT 拼接绕过',  'weight' => 12],
            ['pattern' => '/%[0-9a-f]{2}%[0-9a-f]{2}/i','name' => '密集 URL 编码',    'weight' => 10],
            ['pattern' => '/[a-z]+\([a-z]+\(/i',        'name' => '嵌套函数调用',     'weight' => 12],
        ];
        foreach ($obfuscationPatterns as $rule) {
            if (preg_match($rule['pattern'], $text)) {
                $score += $rule['weight'];
                $result['inferences'][] = [
                    'type'  => 'obfuscation',
                    'name'  => $rule['name'],
                    'desc'  => '检测到混淆/编码技术',
                ];
            }
        }

        // 4. 攻击者意图推理：基于已识别特征综合判断
        $intent = [];
        if (preg_match('/union\s+select|information_schema|load_file|into\s+outfile/i', $text)) {
            $intent[] = '数据窃取';
        }
        if (preg_match('/\b(?:drop|alter|create|truncate)\s+/i', $text)) {
            $intent[] = '数据库破坏';
        }
        if (preg_match('/\b(?:insert|update)\s+/i', $text) && preg_match('/\b(?:admin|root|password|passwd)\b/i', $text)) {
            $intent[] = '权限提升/后门植入';
        }
        if (preg_match('/\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b/i', $text)) {
            $intent[] = '盲注探测';
        }
        if (preg_match('/<script|on\w+\s*=|javascript:/i', $text)) {
            $intent[] = 'XSS 投递';
        }
        if (preg_match('/\b(?:eval|system|exec|shell_exec|passthru)\s*\(/i', $text)) {
            $intent[] = '远程代码执行';
        }
        if (preg_match('/\.\.[\/\\\\]/', $text)) {
            $intent[] = '敏感文件读取';
        }
        if (preg_match('/<\?(?:php|=)?/i', $text)) {
            $intent[] = 'Webshell 投递';
        }

        if (!empty($intent)) {
            $result['inferences'][] = [
                'type'  => 'intent',
                'name'  => '攻击者意图',
                'desc'  => '推测意图：' . implode('、', $intent),
                'intents' => $intent,
            ];
            // 多意图叠加加分
            $score += min(count($intent) * 5, 20);
        }

        $result['score'] = max(0, min(100, (int) round($score)));
        return $result;
    }
}
