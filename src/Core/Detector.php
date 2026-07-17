<?php
defined('ABSPATH') || exit;

require_once __DIR__ . '/../Learn/AutoLearn.php';

class WafRiskScore {
    private static $attack_signatures = [
        ['pattern' => 'union select', 'type' => 'sqli', 'severity' => 80, 'name' => 'UNION SELECT注入'],
        ['pattern' => 'union all select', 'type' => 'sqli', 'severity' => 85, 'name' => 'UNION ALL SELECT注入'],
        ['pattern' => 'or 1=1', 'type' => 'sqli', 'severity' => 75, 'name' => 'OR永真注入'],
        ['pattern' => 'and 1=1', 'type' => 'sqli', 'severity' => 70, 'name' => 'AND永真注入'],
        ['pattern' => 'or 1=2', 'type' => 'sqli', 'severity' => 65, 'name' => 'OR永假注入'],
        ['pattern' => 'and 1=2', 'type' => 'sqli', 'severity' => 60, 'name' => 'AND永假注入'],
        ['pattern' => 'insert into', 'type' => 'sqli', 'severity' => 90, 'name' => 'INSERT注入'],
        ['pattern' => 'drop table', 'type' => 'sqli', 'severity' => 95, 'name' => 'DROP TABLE注入'],
        ['pattern' => 'alter table', 'type' => 'sqli', 'severity' => 90, 'name' => 'ALTER TABLE注入'],
        ['pattern' => 'delete from', 'type' => 'sqli', 'severity' => 85, 'name' => 'DELETE注入'],
        ['pattern' => 'update set', 'type' => 'sqli', 'severity' => 80, 'name' => 'UPDATE注入'],
        ['pattern' => 'select * from', 'type' => 'sqli', 'severity' => 75, 'name' => 'SELECT查询注入'],
        ['pattern' => 'sleep(', 'type' => 'sqli_blind', 'severity' => 85, 'name' => '时间盲注Sleep'],
        ['pattern' => 'benchmark(', 'type' => 'sqli_blind', 'severity' => 80, 'name' => '时间盲注Benchmark'],
        ['pattern' => 'waitfor delay', 'type' => 'sqli_blind', 'severity' => 85, 'name' => 'MSSQL时间盲注'],
        ['pattern' => 'information_schema', 'type' => 'sqli', 'severity' => 80, 'name' => '信息_schema查询'],
        ['pattern' => 'mysql_error', 'type' => 'sqli', 'severity' => 70, 'name' => 'MySQL错误信息'],
        ['pattern' => 'xp_cmdshell', 'type' => 'sqli', 'severity' => 95, 'name' => 'MSSQL命令执行'],
        ['pattern' => 'into outfile', 'type' => 'sqli', 'severity' => 90, 'name' => 'SQL写文件'],
        ['pattern' => 'load_file', 'type' => 'sqli', 'severity' => 85, 'name' => 'SQL读文件'],
        ['pattern' => '../', 'type' => 'path_traversal', 'severity' => 70, 'name' => '路径遍历'],
        ['pattern' => '..\\', 'type' => 'path_traversal', 'severity' => 70, 'name' => 'Windows路径遍历'],
        ['pattern' => '/etc/passwd', 'type' => 'path_traversal', 'severity' => 90, 'name' => '读取passwd文件'],
        ['pattern' => '/etc/shadow', 'type' => 'path_traversal', 'severity' => 95, 'name' => '读取shadow文件'],
        ['pattern' => 'boot.ini', 'type' => 'path_traversal', 'severity' => 85, 'name' => '读取boot.ini'],
        ['pattern' => 'win.ini', 'type' => 'path_traversal', 'severity' => 80, 'name' => '读取win.ini'],
        ['pattern' => 'onerror=', 'type' => 'xss', 'severity' => 75, 'name' => 'XSS onerror事件'],
        ['pattern' => 'onload=', 'type' => 'xss', 'severity' => 70, 'name' => 'XSS onload事件'],
        ['pattern' => 'onclick=', 'type' => 'xss', 'severity' => 65, 'name' => 'XSS onclick事件'],
        ['pattern' => 'onmouseover=', 'type' => 'xss', 'severity' => 60, 'name' => 'XSS onmouseover事件'],
        ['pattern' => '<script', 'type' => 'xss', 'severity' => 85, 'name' => 'Script标签注入'],
        ['pattern' => '</script', 'type' => 'xss', 'severity' => 80, 'name' => 'Script闭合标签'],
        ['pattern' => 'javascript:', 'type' => 'xss', 'severity' => 80, 'name' => 'JavaScript伪协议'],
        ['pattern' => 'vbscript:', 'type' => 'xss', 'severity' => 75, 'name' => 'VBScript伪协议'],
        ['pattern' => 'data:text/html', 'type' => 'xss', 'severity' => 80, 'name' => 'Data URI XSS'],
        ['pattern' => '<iframe', 'type' => 'xss', 'severity' => 70, 'name' => 'Iframe注入'],
        ['pattern' => '<img', 'type' => 'xss', 'severity' => 60, 'name' => 'IMG标签XSS'],
        ['pattern' => '<svg', 'type' => 'xss', 'severity' => 75, 'name' => 'SVG XSS'],
        ['pattern' => 'eval(', 'type' => 'rce', 'severity' => 85, 'name' => 'Eval代码执行'],
        ['pattern' => 'system(', 'type' => 'rce', 'severity' => 90, 'name' => 'System命令执行'],
        ['pattern' => 'exec(', 'type' => 'rce', 'severity' => 90, 'name' => 'Exec命令执行'],
        ['pattern' => 'shell_exec', 'type' => 'rce', 'severity' => 90, 'name' => 'Shell_exec命令执行'],
        ['pattern' => 'passthru', 'type' => 'rce', 'severity' => 85, 'name' => 'Passthru命令执行'],
        ['pattern' => 'popen(', 'type' => 'rce', 'severity' => 80, 'name' => 'Popen命令执行'],
        ['pattern' => 'proc_open', 'type' => 'rce', 'severity' => 85, 'name' => 'Proc_open命令执行'],
        ['pattern' => 'assert(', 'type' => 'rce', 'severity' => 85, 'name' => 'Assert代码执行'],
        ['pattern' => 'preg_replace', 'type' => 'rce', 'severity' => 80, 'name' => 'Preg_replace代码执行'],
        ['pattern' => 'base64_decode(', 'type' => 'rce', 'severity' => 60, 'name' => 'Base64解码'],
        ['pattern' => 'str_rot13(', 'type' => 'rce', 'severity' => 55, 'name' => 'ROT13编码'],
        ['pattern' => 'gzinflate(', 'type' => 'rce', 'severity' => 70, 'name' => 'Gzinflate解压'],
        ['pattern' => 'eval(gzuncompress', 'type' => 'rce', 'severity' => 90, 'name' => '压缩免杀执行'],
        ['pattern' => 'eval(base64_decode', 'type' => 'rce', 'severity' => 95, 'name' => 'Base64免杀执行'],
        ['pattern' => '<?php', 'type' => 'webshell', 'severity' => 90, 'name' => 'PHP标签'],
        ['pattern' => '<?=', 'type' => 'webshell', 'severity' => 85, 'name' => 'PHP短标签'],
        ['pattern' => '<%', 'type' => 'webshell', 'severity' => 80, 'name' => 'ASP标签'],
        ['pattern' => '<!ENTITY', 'type' => 'xxe', 'severity' => 85, 'name' => 'XXE实体注入'],
        ['pattern' => 'SYSTEM', 'type' => 'xxe', 'severity' => 80, 'name' => 'XXE SYSTEM实体'],
        ['pattern' => '<?xml', 'type' => 'xxe', 'severity' => 50, 'name' => 'XML声明'],
        ['pattern' => 'file_get_contents(', 'type' => 'file_read', 'severity' => 70, 'name' => '文件读取函数'],
        ['pattern' => 'fopen(', 'type' => 'file_read', 'severity' => 60, 'name' => 'Fopen函数'],
        ['pattern' => 'readfile(', 'type' => 'file_read', 'severity' => 65, 'name' => 'Readfile函数'],
        ['pattern' => 'include(', 'type' => 'file_inclusion', 'severity' => 85, 'name' => 'Include文件包含'],
        ['pattern' => 'require(', 'type' => 'file_inclusion', 'severity' => 85, 'name' => 'Require文件包含'],
        ['pattern' => 'include_once(', 'type' => 'file_inclusion', 'severity' => 80, 'name' => 'Include_once'],
        ['pattern' => 'require_once(', 'type' => 'file_inclusion', 'severity' => 80, 'name' => 'Require_once'],
        ['pattern' => 'php://input', 'type' => 'file_inclusion', 'severity' => 90, 'name' => 'PHP输入流'],
        ['pattern' => 'php://filter', 'type' => 'file_inclusion', 'severity' => 85, 'name' => 'PHP过滤器'],
        ['pattern' => 'data://', 'type' => 'file_inclusion', 'severity' => 80, 'name' => 'Data协议'],
    ];

    private static $regex_rules = [
        ['pattern' => '/\b(?:union\s+(?:all\s+)?select|select\s+.*\s+from)\b/iu', 'type' => 'sqli', 'severity' => 85, 'name' => 'SQL UNION/SELECT正则'],
        ['pattern' => '/\b(?:or|and)\s+[\d\w\'"]+\s*=\s*[\d\w\'"]+/iu', 'type' => 'sqli', 'severity' => 70, 'name' => 'SQL逻辑注入正则'],
        ['pattern' => '/\b(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b/iu', 'type' => 'sqli_blind', 'severity' => 85, 'name' => '时间盲注正则'],
        ['pattern' => '/\/\*.*?\*\//s', 'type' => 'sqli', 'severity' => 50, 'name' => 'SQL注释混淆'],
        ['pattern' => '/\.{2,}[\/\\\\]/', 'type' => 'path_traversal', 'severity' => 75, 'name' => '路径遍历正则'],
        ['pattern' => '/\b(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onchange|onsubmit|onkeydown|onkeypress|onkeyup)\s*=/iu', 'type' => 'xss', 'severity' => 75, 'name' => 'XSS事件处理器正则'],
        ['pattern' => '/\b(?:eval\s*\(|system\s*\(|exec\s*\(|shell_exec|passthru|popen\s*\(|proc_open|assert\s*\()\b/iu', 'type' => 'rce', 'severity' => 90, 'name' => '命令执行函数正则'],
        ['pattern' => '/<\?php|<\?=/iu', 'type' => 'webshell', 'severity' => 90, 'name' => 'PHP标签正则'],
        ['pattern' => '/<!ENTITY\s+[^>]+SYSTEM/iu', 'type' => 'xxe', 'severity' => 85, 'name' => 'XXE正则'],
        ['pattern' => '/<\?xml[^>]+encoding/iu', 'type' => 'xxe', 'severity' => 55, 'name' => 'XML编码声明'],
        ['pattern' => '/\b(?:include|require)(?:_once)?\s*\(\s*[\$_\'"]/i', 'type' => 'file_inclusion', 'severity' => 85, 'name' => '文件包含正则'],
        ['pattern' => '/\b(?:char|ascii|ord|conv|cast|concat|group_concat|substring|substr|mid|left|right|length|replace)\s*\(/iu', 'type' => 'sqli', 'severity' => 55, 'name' => 'SQL函数正则'],
        ['pattern' => '/\b(?:0x[0-9a-f]+|0b[01]+)\b/iu', 'type' => 'obfuscation', 'severity' => 50, 'name' => '十六进制/二进制编码'],
        ['pattern' => '/\b(?:unhex|hex2bin|pack|unpack)\s*\(/iu', 'type' => 'obfuscation', 'severity' => 60, 'name' => '编码转换函数'],
    ];

    private static $type_weights = [
        'sqli' => 1.2,
        'sqli_blind' => 1.3,
        'xss' => 1.0,
        'rce' => 1.4,
        'path_traversal' => 1.1,
        'webshell' => 1.5,
        'xxe' => 1.2,
        'file_read' => 0.9,
        'file_inclusion' => 1.3,
        'obfuscation' => 0.7,
    ];

    public static function analyze($cleanText, $normalizerContext = []) {
        $result = [
            'is_attack' => false,
            'total_score' => 0,
            'attack_type_scores' => [],
            'matched_rules' => [],
            'encoding_penalty' => 0,
            'semantic_penalty' => 0,
            'risk_level' => 'clean',
            'confidence' => 0,
            'learned_hits' => 0,
        ];

        // 获取自动学习系统动态权重
        $dynamicWeights = WafAutoLearner::getAdjustedWeights();

        $signatureHits = [];
        foreach (self::$attack_signatures as $sig) {
            if (strpos($cleanText, $sig['pattern']) !== false) {
                $signatureHits[] = $sig;
            }
        }

        $regexHits = [];
        foreach (self::$regex_rules as $rule) {
            if (preg_match($rule['pattern'], $cleanText)) {
                $regexHits[] = $rule;
            }
        }

        // 加载自动学习规则
        $learnedRules = WafAutoLearner::getLearnedRules();
        $learnedHits = [];
        foreach ($learnedRules as $rule) {
            if (strpos($cleanText, $rule['pattern']) !== false) {
                $learnedHits[] = $rule;
            }
        }

        $allHits = array_merge($signatureHits, $regexHits, $learnedHits);

        $typeScores = [];
        foreach ($allHits as $hit) {
            $type = $hit['type'];
            $sev = $hit['severity'];
            $weight = $dynamicWeights[$type] ?? 1.0;
            if (!isset($typeScores[$type])) {
                $typeScores[$type] = 0;
            }
            $typeScores[$type] += $sev * $weight;
        }

        foreach ($typeScores as $type => $score) {
            $typeScores[$type] = min($score, 100);
        }

        $baseScore = !empty($typeScores) ? max($typeScores) : 0;

        $encodingPenalty = 0;
        if (!empty($normalizerContext)) {
            $encodingComplexity = $normalizerContext['encoding_complexity'] ?? 0;
            $encodingDepth = $normalizerContext['encoding_depth'] ?? 0;
            $semanticScore = $normalizerContext['semantic_score'] ?? 0;
            $encodingPenalty = $encodingComplexity * 0.4 + $semanticScore * 0.3;

            if ($baseScore > 0) {
                if ($encodingDepth >= 4) {
                    $baseScore = min($baseScore * 1.5, 100);
                } elseif ($encodingDepth >= 2) {
                    $baseScore = min($baseScore * 1.2, 100);
                }
                if ($semanticScore >= 50) {
                    $baseScore = min($baseScore * 1.3, 100);
                }
            }
        }

        $numHits = count($allHits);
        if ($numHits >= 5) {
            $baseScore = min($baseScore * 1.4, 100);
        } elseif ($numHits >= 3) {
            $baseScore = min($baseScore * 1.2, 100);
        }

        $highSeverityCount = 0;
        foreach ($allHits as $hit) {
            if ($hit['severity'] >= 80) $highSeverityCount++;
        }
        if ($highSeverityCount >= 2) {
            $baseScore = min($baseScore * 1.3, 100);
        }

        $totalScore = min($baseScore + $encodingPenalty * 0.3, 100);

        if ($totalScore >= 80) {
            $riskLevel = 'critical';
        } elseif ($totalScore >= 60) {
            $riskLevel = 'high';
        } elseif ($totalScore >= 40) {
            $riskLevel = 'medium';
        } elseif ($totalScore >= 20) {
            $riskLevel = 'low';
        } else {
            $riskLevel = 'clean';
        }

        $isAttack = $totalScore >= 60;

        $confidence = 0;
        if ($numHits > 0) {
            $confidence = min(50 + $numHits * 10 + $highSeverityCount * 15, 100);
        }

        return [
            'is_attack' => $isAttack,
            'total_score' => round($totalScore, 1),
            'attack_type_scores' => $typeScores,
            'matched_rules' => array_map(function($h) {
                return ['name' => $h['name'], 'type' => $h['type'], 'severity' => $h['severity']];
            }, $allHits),
            'encoding_penalty' => round($encodingPenalty, 1),
            'semantic_score' => $normalizerContext['semantic_score'] ?? 0,
            'encoding_depth' => $normalizerContext['encoding_depth'] ?? 0,
            'double_encoding' => $normalizerContext['double_encoding_detected'] ?? false,
            'risk_level' => $riskLevel,
            'confidence' => $confidence,
            'hit_count' => $numHits,
            'high_severity_count' => $highSeverityCount,
            'learned_hits' => count($learnedHits),
        ];
    }

    public static function getRiskLevel($score) {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 20) return 'low';
        return 'clean';
    }
}

function waf_is_attack($clean) {
    $result = WafRiskScore::analyze($clean);
    return $result['is_attack'];
}

function waf_analyze_attack($clean, $normalizerContext = []) {
    return WafRiskScore::analyze($clean, $normalizerContext);
}
