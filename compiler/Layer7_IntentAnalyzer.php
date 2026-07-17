<?php
defined('ABSPATH') || exit;

/**
 * Layer7：攻击意图阶段分析层
 *
 * 基于洛克希德·马丁 Kill Chain 模型，识别攻击者所处的攻击阶段：
 * 侦察(recon) → 武器化(weaponize) → 利用(exploit) → 安装(install) → 目标达成(objective)
 * 并给出置信度评估。
 */
class Layer7_IntentAnalyzer {

    /**
     * 攻击阶段定义与对应特征
     */
    private static $stageSignatures = [
        'recon' => [
            'patterns' => [
                '/information_schema/i',
                '/\b(?:version|user|database|current_user|@@version)\s*\(/i',
                '/\b(?:select\s+count|select\s+top|select\s+1)\b/i',
                '/\b(?:sleep|benchmark|waitfor\s+delay)\s*\(?\s*\d+/i',
                '/\b(?:or|and)\s+1\s*=\s*[12]\b/i',
                '/\b(?:order\s+by|group\s+by)\s+\d+/i',
            ],
            'base_weight' => 18,
            'desc' => '侦察阶段：信息探测、版本探测、盲注探测',
        ],
        'weaponize' => [
            'patterns' => [
                '/\bunion\s+(?:all\s+)?select\b/i',
                '/\b(?:select|insert|update|delete)\b.*\b(?:from|into|set)\b/is',
                '/<script\b/i',
                '/\bon\w+\s*=/i',
                '/javascript:/i',
                '/\.\.[\/\\\\]/',
                '/<\?(?:php|=)?/i',
                '/\b(?:eval|system|exec|shell_exec|passthru)\s*\(/i',
            ],
            'base_weight' => 25,
            'desc' => '武器化阶段：构造注入载荷、XSS、Webshell',
        ],
        'exploit' => [
            'patterns' => [
                '/\bunion\s+select.*(?:password|passwd|pwd|admin|user)/is',
                '/into\s+outfile/i',
                '/load_file\s*\(/i',
                '/xp_cmdshell/i',
                '/<script.*src\s*=/is',
                '/<\?(?:php|=)?.*\b(?:eval|system|exec)/is',
                '/\b(?:include|require)(?:_once)?\s*[\(\'"]\s*(?:php|data|zip|phar)\s*:/i',
            ],
            'base_weight' => 30,
            'desc' => '利用阶段：数据窃取、文件读写、命令执行',
        ],
        'install' => [
            'patterns' => [
                '/<\?(?:php|=)?.*\b(?:eval|system|exec|shell_exec|passthru|assert)\b/is',
                '/into\s+outfile.*\.(?:php|jsp|asp|aspx)/is',
                '/\b(?:file_put_contents|fwrite|move_uploaded_file)\s*\(.*\b(?:php|shell|webshell)/is',
                '/webshell|c99|r57|b374k/i',
                '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{20,}/i',
            ],
            'base_weight' => 35,
            'desc' => '安装阶段：植入 Webshell、持久化后门',
        ],
        'objective' => [
            'patterns' => [
                '/\b(?:drop|alter|truncate)\s+(?:table|database)/i',
                '/\b(?:delete\s+from|update\s+.*set)\s+.*\b(?:where\s+1\s*=\s*1|;\s*$)/is',
                '/<\?(?:php|=)?.*(?:file_get_contents|fopen|readfile)\s*\(.*\/etc\/(?:passwd|shadow)/is',
                '/xp_cmdshell.*(?:net\s+user|net\s+localgroup|whoami|id;)/is',
                '/\bsleep\s*\(\s*\d{3,}/i',
            ],
            'base_weight' => 40,
            'desc' => '目标达成：数据破坏、权限提升、横向移动',
        ],
    ];

    /**
     * 分析攻击意图阶段
     *
     * @param string $text 待分析文本
     * @return array ['score'=>0-100, 'stage'=>'...', 'confidence'=>0-100]
     */
    public static function analyze(string $text): array {
        $result = [
            'score'      => 0,
            'stage'      => 'benign',
            'confidence' => 0,
            'stage_hits' => [],
        ];

        if ($text === '') {
            return $result;
        }

        $stageScores = [];
        $stageHits = [];

        // 对每个阶段计算命中分
        foreach (self::$stageSignatures as $stage => $def) {
            $hits = 0;
            $matchedPatterns = [];
            foreach ($def['patterns'] as $p) {
                if (preg_match($p, $text)) {
                    $hits++;
                    $matchedPatterns[] = $p;
                }
            }
            if ($hits > 0) {
                // 该阶段得分 = 基础权重 + 命中数 × 8
                $stageScore = $def['base_weight'] + $hits * 8;
                $stageScores[$stage] = min($stageScore, 100);
                $stageHits[$stage] = [
                    'hits'     => $hits,
                    'desc'     => $def['desc'],
                    'patterns' => $matchedPatterns,
                ];
            }
        }

        $result['stage_hits'] = $stageHits;

        if (empty($stageScores)) {
            // 未命中任何阶段特征
            $result['stage'] = 'benign';
            $result['confidence'] = 0;
            $result['score'] = 0;
            return $result;
        }

        // 选择得分最高的阶段作为主阶段
        arsort($stageScores);
        $mainStage = array_key_first($stageScores);
        $mainScore = $stageScores[$mainStage];

        $result['stage'] = $mainStage;
        $result['score'] = $mainScore;

        // 置信度计算：基于命中模式数与阶段独占性
        $mainHits = $stageHits[$mainStage]['hits'];
        $stageCount = count($stageScores);

        $confidence = 0;
        // 基础分：每命中一个模式 +20
        $confidence += min($mainHits * 20, 60);
        // 阶段独占性：若只命中一个阶段，置信度更高
        if ($stageCount === 1) {
            $confidence += 25;
        } elseif ($stageCount === 2) {
            $confidence += 15;
        } else {
            $confidence += 5;
        }
        // 高危阶段加分
        if (in_array($mainStage, ['exploit', 'install', 'objective'], true)) {
            $confidence += 15;
        }

        $result['confidence'] = max(0, min(100, $confidence));
        $result['score'] = max(0, min(100, $mainScore));

        return $result;
    }
}
