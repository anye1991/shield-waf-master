<?php
defined('ABSPATH') || exit;

/**
 * Layer8：攻击链识别与阻断层
 *
 * 综合前面各层的分析结果，识别请求所处的攻击链阶段，
 * 计算整体攻击链风险等级、识别攻击类型，并给出是否阻断的决策。
 */
class Layer8_AttackChain {

    /**
     * 攻击类型识别规则
     */
    private static $attackTypeRules = [
        'sqli' => [
            'patterns' => [
                '/\bunion\s+(?:all\s+)?select\b/i',
                '/\b(?:or|and)\s+\d+\s*=\s*\d+/i',
                '/\b(?:select|insert|update|delete|drop|alter)\b.*\b(?:from|into|set|table)\b/is',
                '/information_schema/i',
                '/\b(?:sleep|benchmark|waitfor\s+delay)\b/i',
                '/into\s+outfile/i',
                '/load_file\s*\(/i',
                '/\bextractvalue\s*\(|\bupdatexml\s*\(/i',
            ],
            'weight' => 30,
        ],
        'xss' => [
            'patterns' => [
                '/<script\b/i',
                '/<\/script>/i',
                '/\bon\w+\s*=/i',
                '/javascript:/i',
                '/vbscript:/i',
                '/data:text\/html/i',
                '/<iframe\b/i',
                '/<svg\b/i',
                '/<img\b[^>]*onerror/i',
            ],
            'weight' => 25,
        ],
        'rce' => [
            'patterns' => [
                '/\b(?:eval|system|exec|shell_exec|passthru|assert|popen|proc_open)\s*\(/i',
                '/\bxp_cmdshell\b/i',
                '/\b(?:create_function|call_user_func|preg_replace)\s*\(.*\/e/i',
            ],
            'weight' => 35,
        ],
        'webshell' => [
            'patterns' => [
                '/<\?(?:php|=)?.*\b(?:eval|system|exec|shell_exec|passthru|assert)\b/is',
                '/<\?(?:php|=)?/i',
                '/webshell|c99|r57|b374k/i',
                '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{20,}/i',
            ],
            'weight' => 30,
        ],
        'path_traversal' => [
            'patterns' => [
                '/\.\.[\/\\\\]/',
                '/(?:\/etc\/passwd|\/etc\/shadow|boot\.ini|win\.ini)/i',
                '/\.\.[\/\\\\]\.\.[\/\\\\]\.\./',
            ],
            'weight' => 22,
        ],
        'file_inclusion' => [
            'patterns' => [
                '/\b(?:include|require)(?:_once)?\s*[\(\'"]\s*(?:php|data|zip|phar|expect)\s*:/i',
                '/(?:php|data|zip|phar)\s*:\s*\/\//i',
            ],
            'weight' => 28,
        ],
        'xxe' => [
            'patterns' => [
                '/<!ENTITY\s+[^>]+SYSTEM/i',
                '/<\?xml[^>]+encoding/i',
            ],
            'weight' => 25,
        ],
    ];

    /**
     * 分析攻击链
     *
     * @param string $text 待分析文本
     * @return array ['score'=>0-100, 'chain'=>[...], 'attack_type'=>'...', 'block'=>bool]
     */
    public static function analyze(string $text): array {
        $result = [
            'score'       => 0,
            'chain'       => [],
            'attack_type' => 'clean',
            'block'       => false,
        ];

        if ($text === '') {
            return $result;
        }

        $score = 0;
        $chain = [];

        // 1. 攻击链阶段识别（基于 Kill Chain 模型）
        $stages = [
            'recon'      => ['patterns' => ['/information_schema/i', '/\b(?:version|user|database)\s*\(/i', '/\b(?:sleep|benchmark)\s*\(/i', '/\b(?:or|and)\s+1\s*=\s*[12]\b/i'], 'weight' => 15],
            'weaponize'  => ['patterns' => ['/union\s+select/i', '/<script/i', '/\bon\w+\s*=/i', '/\.\.[\/\\\\]/', '/<\?(?:php|=)?/i', '/\b(?:eval|system)\s*\(/i'], 'weight' => 20],
            'exploit'    => ['patterns' => ['/union\s+select.*(?:password|admin)/is', '/into\s+outfile/i', '/load_file\s*\(/i', '/xp_cmdshell/i'], 'weight' => 25],
            'install'    => ['patterns' => ['/<\?.*\b(?:eval|system|exec)\b/is', '/into\s+outfile.*\.php/is', '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{20,}/i'], 'weight' => 30],
            'objective'  => ['patterns' => ['/\b(?:drop|truncate)\s+(?:table|database)/i', '/delete\s+from.*1\s*=\s*1/is', '/sleep\s*\(\s*\d{3,}/i'], 'weight' => 30],
        ];

        foreach ($stages as $stage => $def) {
            $hitCount = 0;
            foreach ($def['patterns'] as $p) {
                if (preg_match($p, $text)) {
                    $hitCount++;
                }
            }
            if ($hitCount > 0) {
                $stageScore = $def['weight'] + $hitCount * 5;
                $chain[] = [
                    'stage'  => $stage,
                    'score'  => min($stageScore, 100),
                    'hits'   => $hitCount,
                ];
                $score += $stageScore * 0.6;
            }
        }

        // 2. 攻击类型识别
        $typeScores = [];
        foreach (self::$attackTypeRules as $type => $rule) {
            $hitCount = 0;
            foreach ($rule['patterns'] as $p) {
                if (preg_match($p, $text)) {
                    $hitCount++;
                }
            }
            if ($hitCount > 0) {
                $typeScore = $rule['weight'] + $hitCount * 6;
                $typeScores[$type] = $typeScore;
            }
        }

        if (!empty($typeScores)) {
            arsort($typeScores);
            $result['attack_type'] = array_key_first($typeScores);
            // 最高类型分加权进总分
            $score += max($typeScores) * 0.4;
        }

        $result['chain'] = $chain;

        // 3. 多阶段叠加：如果命中多个攻击链阶段，说明是完整攻击链
        if (count($chain) >= 3) {
            $score += 20;
        } elseif (count($chain) >= 2) {
            $score += 10;
        }

        // 4. 多攻击类型叠加：复合攻击
        if (count($typeScores) >= 3) {
            $score += 15;
        } elseif (count($typeScores) >= 2) {
            $score += 8;
        }

        $score = max(0, min(100, (int) round($score)));
        $result['score'] = $score;

        // 5. 阻断决策：分数高于 60 或命中 install/objective 阶段或攻击类型为 webshell/rce
        $block = false;
        if ($score >= 60) {
            $block = true;
        }
        foreach ($chain as $c) {
            if (in_array($c['stage'], ['install', 'objective'], true) && $c['hits'] > 0) {
                $block = true;
                break;
            }
        }
        if (in_array($result['attack_type'], ['webshell', 'rce'], true) && $score >= 40) {
            $block = true;
        }

        $result['block'] = $block;
        return $result;
    }
}
