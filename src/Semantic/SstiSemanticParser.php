<?php
/**
 * SSTI（服务端模板注入）语义解析器
 * 职责：基于模板语法结构进行深度解析，识别不同模板引擎的语法特征，
 *       检测模板注入攻击，包括表达式嵌套、危险标签、常见payload等。
 */
defined('ABSPATH') || exit;

class SstiSemanticParser {

    private static $enginePatterns = [
        'twig_jinja2' => [
            'name' => 'Twig/Jinja2',
            'output' => '/\{\{\s*(.+?)\s*\}\}/s',
            'statement' => '/\{%\s*(.+?)\s*%\}/s',
            'comment' => '/\{#\s*(.+?)\s*#\}/s',
            'filter' => '/\|\s*[a-zA-Z_]\w*/',
            'danger_level' => 4,
        ],
        'smarty' => [
            'name' => 'Smarty',
            'variable' => '/\{\$\s*[a-zA-Z_]\w*(?:\.\w+|\[[^\]]+\])*\s*\}/',
            'foreach' => '/\{foreach\s+[^}]*\}/i',
            'section' => '/\{section\s+[^}]*\}/i',
            'php' => '/\{php\}/i',
            'literal' => '/\{literal\}/i',
            'danger_level' => 4,
        ],
        'velocity' => [
            'name' => 'Velocity',
            'set' => '/#set\s*\(\s*\$[a-zA-Z_]\w*\s*=/i',
            'if' => '/#if\s*\(/i',
            'foreach' => '/#foreach\s*\(/i',
            'variable' => '/\$[a-zA-Z_]\w*(?:\.\w+)*(?=\s|\)|$|,|\})/',
            'variable_brace' => '/\$\{[a-zA-Z_]\w*(?:\.\w+)*\}/',
            'danger_level' => 4,
        ],
        'freemarker' => [
            'name' => 'Freemarker',
            'output' => '/\$\{(.+?)\}/s',
            'if' => '/<#if\s+/i',
            'list' => '/<#list\s+/i',
            'assign' => '/<#assign\s+/i',
            'include' => '/<#include\s+/i',
            'danger_level' => 4,
        ],
        'erb' => [
            'name' => 'ERB',
            'output' => '/<%=\s*(.+?)\s*%>/s',
            'script' => '/<%\s*(.+?)\s*%>/s',
            'danger_level' => 5,
        ],
        'mustache_handlebars' => [
            'name' => 'Mustache/Handlebars',
            'output' => '/\{\{\s*(#|\^|\/|>|&|\.)?\s*[a-zA-Z_@][\w\.\/\-]*\s*\}\}/',
            'section' => '/\{\{#\s*[a-zA-Z_]\w*\s*\}\}/',
            'inverted' => '/\{\{\^\s*[a-zA-Z_]\w*\s*\}\}/',
            'danger_level' => 2,
        ],
        'php_template' => [
            'name' => 'PHP Template',
            'short_echo' => '/<\?=\s*(.+?)\s*\?>/s',
            'full' => '/<\?php\s+(.+?)\s*\?>/is',
            'danger_level' => 5,
        ],
        'asp_aspx' => [
            'name' => 'ASP/ASPX',
            'output' => '/<%=\s*(.+?)\s*%>/s',
            'script' => '/<%\s*(.+?)\s*%>/s',
            'danger_level' => 5,
        ],
    ];

    private static $dangerousTags = [
        '{php}' => ['engine' => 'smarty', 'level' => 5, 'desc' => 'Smarty PHP代码标签'],
        '<?php' => ['engine' => 'php_template', 'level' => 5, 'desc' => 'PHP代码标签'],
        '<?=' => ['engine' => 'php_template', 'level' => 5, 'desc' => 'PHP短输出标签'],
        '<%=' => ['engine' => 'asp_aspx', 'level' => 5, 'desc' => 'ASP输出标签'],
        '<%' => ['engine' => 'asp_aspx', 'level' => 4, 'desc' => 'ASP脚本标签'],
        '#set' => ['engine' => 'velocity', 'level' => 4, 'desc' => 'Velocity变量赋值'],
        '<#assign' => ['engine' => 'freemarker', 'level' => 4, 'desc' => 'Freemarker变量赋值'],
        '{%' => ['engine' => 'twig_jinja2', 'level' => 3, 'desc' => 'Twig/Jinja2语句块'],
    ];

    private static $sstiPayloadPatterns = [
        'math_operation' => [
            'pattern' => '/\{\{\s*(\d+)\s*[\*\+\-\%]\s*(\d+)\s*\}\}/',
            'level' => 4,
            'desc' => '数学运算表达式（SSTI探测）',
            'examples' => ['{{7*7}}', '{{9*9}}', '{{7+7}}'],
        ],
        'config_access' => [
            'pattern' => '/\{\{\s*config\s*(\.[a-zA-Z_]\w*)*\s*\}\}/i',
            'level' => 4,
            'desc' => '访问config对象',
        ],
        'class_access' => [
            'pattern' => "/\{\{[^}]*['\"]['\"]\.class[^}]*\}\}/i",
            'level' => 5,
            'desc' => '字符串class属性访问（Java SSTI）',
        ],
        'mro_access' => [
            'pattern' => '/\{\{[^}]*__mro__[^}]*\}\}/i',
            'level' => 5,
            'desc' => '__mro__继承链访问（Python SSTI）',
        ],
        'subclasses_access' => [
            'pattern' => '/\{\{[^}]*__subclasses__[^}]*\}\}/i',
            'level' => 5,
            'desc' => '__subclasses__子类枚举（Python SSTI）',
        ],
        'builtins_access' => [
            'pattern' => '/\{\{[^}]*__builtins__[^}]*\}\}/i',
            'level' => 5,
            'desc' => '__builtins__内置函数访问（Python SSTI）',
        ],
        'globals_access' => [
            'pattern' => '/\{\{[^}]*__globals__[^}]*\}\}/i',
            'level' => 5,
            'desc' => '__globals__全局变量访问（Python SSTI）',
        ],
        'getattribute' => [
            'pattern' => '/\{\{[^}]*__getattribute__[^}]*\}\}/i',
            'level' => 4,
            'desc' => '__getattribute__方法访问',
        ],
        'os_system' => [
            'pattern' => '/\{\{[^}]*os\.system[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'os.system命令执行（Python SSTI）',
        ],
        'popen' => [
            'pattern' => '/\{\{[^}]*popen[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'popen命令执行',
        ],
        'exec_eval' => [
            'pattern' => '/\{\{[^}]*(\bexec\b|\beval\b)[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'exec/eval代码执行',
        ],
        'request_access' => [
            'pattern' => '/\{\{\s*request(\.[a-zA-Z_]\w*)*\s*\}\}/i',
            'level' => 3,
            'desc' => 'request对象访问',
        ],
        'self_environment' => [
            'pattern' => '/\{\{\s*self\s*\.\s*environment\s*(\.[a-zA-Z_]\w*)*\s*\}\}/i',
            'level' => 4,
            'desc' => 'self.environment访问（Jinja2 SSTI）',
        ],
        'cycler' => [
            'pattern' => '/\{\{\s*cycler\s*\.\s*next\s*\.\s*__globals__[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'cycler.next.__globals__利用链',
        ],
        'namespace' => [
            'pattern' => '/\{\{\s*namespace\s*\.\s*__init__\s*\.\s*__globals__[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'namespace.__init__.__globals__利用链',
        ],
        'lipsum' => [
            'pattern' => '/\{\{\s*lipsum\s*\.\s*__globals__[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'lipsum.__globals__利用链（Jinja2）',
        ],
        'get_flashed_messages' => [
            'pattern' => '/\{\{\s*get_flashed_messages\s*\.\s*__globals__[^}]*\}\}/i',
            'level' => 5,
            'desc' => 'get_flashed_messages.__globals__利用链',
        ],
        'freemarker_new' => [
            'pattern' => '/\$\{\s*new\s*\(/i',
            'level' => 5,
            'desc' => 'Freemarker new() 利用',
        ],
        'freemarker_execute' => [
            'pattern' => '/\?exec\b/i',
            'level' => 5,
            'desc' => 'Freemarker ?exec 命令执行',
        ],
        'freemarker_api' => [
            'pattern' => '/\?api\b/i',
            'level' => 4,
            'desc' => 'Freemarker ?api 内省',
        ],
        'velocity_rce' => [
            'pattern' => '/#set\s*\(\s*\$[a-zA-Z_]\w*\s*=\s*["\'].*\bruntime\b.*["\']\s*\)/i',
            'level' => 5,
            'desc' => 'Velocity Runtime.getRuntime() 利用',
        ],
        'smarty_php' => [
            'pattern' => '/\{php\}/i',
            'level' => 5,
            'desc' => 'Smarty {php} 标签',
        ],
        'erb_system' => [
            'pattern' => '/<%[=\s].*system\s*\(/i',
            'level' => 5,
            'desc' => 'ERB system() 调用',
        ],
    ];

    private static $filterPatterns = [
        'dangerous_filters' => [
            'system' => 5,
            'exec' => 5,
            'shell_exec' => 5,
            'passthru' => 5,
            'eval' => 5,
            'assert' => 5,
            'include' => 4,
            'file_get_contents' => 4,
            'readfile' => 4,
            'phpinfo' => 4,
            'base64_decode' => 3,
            'base64_encode' => 2,
            'json_decode' => 2,
            'json_encode' => 2,
            'url_decode' => 2,
            'raw' => 3,
            'safe' => 3,
            'nl2br' => 1,
            'upper' => 1,
            'lower' => 1,
            'trim' => 1,
            'length' => 1,
            'capitalize' => 1,
            'title' => 1,
            'sort' => 1,
            'reverse' => 1,
            'default' => 1,
            'escape' => 1,
            'e' => 1,
            'first' => 1,
            'last' => 1,
            'join' => 1,
            'split' => 2,
            'slice' => 1,
            'striptags' => 1,
            'date' => 1,
            'replace' => 2,
            'format' => 1,
            'number_format' => 1,
            'abs' => 1,
            'round' => 1,
            'max' => 1,
            'min' => 1,
            'sum' => 1,
            'merge' => 1,
            'random' => 1,
            'shuffle' => 1,
            'batch' => 1,
            'column' => 1,
            'map' => 2,
            'reduce' => 2,
            'filter' => 2,
        ],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $testInputs = [
            'original' => $input,
            'urldecoded' => urldecode($input),
            'double_decoded' => urldecode(urldecode($input)),
        ];

        $allExpressions = [];
        $detectedEngines = [];
        $dangerousTagsFound = [];
        $payloadHits = [];
        $maxExpressionDepth = 0;
        $totalExpressions = 0;
        $hasObfuscation = false;
        $obfuscationIndicators = [];

        foreach ($testInputs as $sourceKey => $testInput) {
            if ($testInput === '') continue;

            foreach (self::$enginePatterns as $engineKey => $engineInfo) {
                $engineExpressions = [];
                $engineDetected = false;

                foreach ($engineInfo as $patternType => $pattern) {
                    if ($patternType === 'name' || $patternType === 'danger_level') continue;
                    if (!is_string($pattern) || strpos($pattern, '/') !== 0) continue;

                    if (preg_match_all($pattern, $testInput, $matches, PREG_OFFSET_CAPTURE)) {
                        foreach ($matches[0] as $idx => $match) {
                            $fullMatch = $match[0];
                            $offset = $match[1];
                            $innerContent = isset($matches[1][$idx]) ? $matches[1][$idx][0] : '';

                            $depth = self::calculateExpressionDepth($fullMatch);
                            if ($depth > $maxExpressionDepth) {
                                $maxExpressionDepth = $depth;
                            }

                            $hasDangerousFilter = false;
                            $dangerousFiltersFound = [];
                            if ($patternType === 'filter' || $patternType === 'output') {
                                $filterResult = self::detectDangerousFilters($innerContent);
                                if (!empty($filterResult)) {
                                    $hasDangerousFilter = true;
                                    $dangerousFiltersFound = $filterResult;
                                }
                            }

                            $expressionInfo = [
                                'engine' => $engineKey,
                                'engine_name' => $engineInfo['name'],
                                'type' => $patternType,
                                'full_match' => $fullMatch,
                                'inner_content' => $innerContent,
                                'offset' => $offset,
                                'depth' => $depth,
                                'source' => $sourceKey,
                                'has_dangerous_filter' => $hasDangerousFilter,
                                'dangerous_filters' => $dangerousFiltersFound,
                            ];

                            $engineExpressions[] = $expressionInfo;
                            $allExpressions[] = $expressionInfo;
                            $totalExpressions++;
                            $engineDetected = true;
                        }
                    }
                }

                if ($engineDetected && !isset($detectedEngines[$engineKey])) {
                    $detectedEngines[$engineKey] = [
                        'engine' => $engineKey,
                        'name' => $engineInfo['name'],
                        'danger_level' => $engineInfo['danger_level'],
                        'expression_count' => count($engineExpressions),
                        'source' => $sourceKey,
                    ];
                }
            }

            foreach (self::$dangerousTags as $tag => $tagInfo) {
                if (stripos($testInput, $tag) !== false) {
                    $tagKey = $tag . '_' . $sourceKey;
                    if (!isset($dangerousTagsFound[$tagKey])) {
                        $dangerousTagsFound[$tagKey] = [
                            'tag' => $tag,
                            'engine' => $tagInfo['engine'],
                            'level' => $tagInfo['level'],
                            'desc' => $tagInfo['desc'],
                            'source' => $sourceKey,
                            'count' => substr_count(strtolower($testInput), strtolower($tag)),
                        ];
                    }
                }
            }

            foreach (self::$sstiPayloadPatterns as $payloadKey => $payloadInfo) {
                if (preg_match($payloadInfo['pattern'], $testInput)) {
                    if (!isset($payloadHits[$payloadKey])) {
                        $payloadHits[$payloadKey] = [
                            'key' => $payloadKey,
                            'level' => $payloadInfo['level'],
                            'desc' => $payloadInfo['desc'],
                            'source' => $sourceKey,
                        ];
                    }
                }
            }
        }

        $urlEncodeCount = preg_match_all('/%[0-9a-fA-F]{2}/', $input);
        if ($urlEncodeCount > 5) {
            $hasObfuscation = true;
            $obfuscationIndicators[] = 'url_encoding:' . $urlEncodeCount;
        }

        $doubleEncodeCount = preg_match_all('/%25[0-9a-fA-F]{2}/i', $input);
        if ($doubleEncodeCount > 0) {
            $hasObfuscation = true;
            $obfuscationIndicators[] = 'double_url_encoding:' . $doubleEncodeCount;
        }

        $hasUnicodeEscape = preg_match('/\\\u[0-9a-fA-F]{4}/', $input);
        if ($hasUnicodeEscape) {
            $hasObfuscation = true;
            $obfuscationIndicators[] = 'unicode_escape';
        }

        $hasHtmlEntity = preg_match('/&#[xX]?[0-9a-fA-F]+;/', $input);
        if ($hasHtmlEntity) {
            $hasObfuscation = true;
            $obfuscationIndicators[] = 'html_entity';
        }

        $concatPatterns = [
            '/["\']\s*~\s*["\']/',
            '/["\']\s*\.\s*["\']/',
            '/["\']\s*\+\s*["\']/',
        ];
        $concatCount = 0;
        foreach ($concatPatterns as $cp) {
            $concatCount += preg_match_all($cp, $input);
        }
        if ($concatCount > 3) {
            $hasObfuscation = true;
            $obfuscationIndicators[] = 'string_concat:' . $concatCount;
        }

        $engineCount = count($detectedEngines);
        $hasMixedEngines = $engineCount > 1;

        $score = 0;
        $indicators = [];

        $maxEngineLevel = 0;
        foreach ($detectedEngines as $engine) {
            if ($engine['danger_level'] > $maxEngineLevel) {
                $maxEngineLevel = $engine['danger_level'];
            }
        }

        if ($engineCount >= 4) {
            $score += 25;
            $indicators[] = 'multiple_engines_mixed';
        } elseif ($engineCount >= 3) {
            $score += 18;
            $indicators[] = 'three_engines_mixed';
        } elseif ($engineCount >= 2) {
            $score += 12;
            $indicators[] = 'two_engines_mixed';
        } elseif ($engineCount === 1) {
            $score += 5;
            $indicators[] = 'single_engine_detected';
        }

        if ($maxEngineLevel >= 5) {
            $score += 20;
            $indicators[] = 'high_risk_engine';
        } elseif ($maxEngineLevel >= 4) {
            $score += 15;
            $indicators[] = 'medium_high_risk_engine';
        } elseif ($maxEngineLevel >= 3) {
            $score += 10;
            $indicators[] = 'medium_risk_engine';
        }

        if ($totalExpressions >= 10) {
            $score += 15;
            $indicators[] = 'many_expressions';
        } elseif ($totalExpressions >= 5) {
            $score += 10;
            $indicators[] = 'multiple_expressions';
        } elseif ($totalExpressions >= 2) {
            $score += 5;
            $indicators[] = 'few_expressions';
        }

        if ($maxExpressionDepth >= 5) {
            $score += 20;
            $indicators[] = 'deep_expression_nesting';
        } elseif ($maxExpressionDepth >= 3) {
            $score += 12;
            $indicators[] = 'moderate_expression_nesting';
        } elseif ($maxExpressionDepth >= 2) {
            $score += 6;
            $indicators[] = 'shallow_expression_nesting';
        }

        $maxTagLevel = 0;
        foreach ($dangerousTagsFound as $tag) {
            if ($tag['level'] > $maxTagLevel) {
                $maxTagLevel = $tag['level'];
            }
        }

        if ($maxTagLevel >= 5) {
            $score += 30;
            $indicators[] = 'critical_dangerous_tag';
        } elseif ($maxTagLevel >= 4) {
            $score += 20;
            $indicators[] = 'high_dangerous_tag';
        } elseif ($maxTagLevel >= 3) {
            $score += 12;
            $indicators[] = 'medium_dangerous_tag';
        }

        $maxPayloadLevel = 0;
        $criticalPayloadCount = 0;
        $highPayloadCount = 0;
        foreach ($payloadHits as $hit) {
            if ($hit['level'] > $maxPayloadLevel) {
                $maxPayloadLevel = $hit['level'];
            }
            if ($hit['level'] >= 5) $criticalPayloadCount++;
            elseif ($hit['level'] >= 4) $highPayloadCount++;
        }

        if ($maxPayloadLevel >= 5) {
            $score += 35;
            $indicators[] = 'critical_ssti_payload';
        } elseif ($maxPayloadLevel >= 4) {
            $score += 25;
            $indicators[] = 'high_ssti_payload';
        } elseif ($maxPayloadLevel >= 3) {
            $score += 15;
            $indicators[] = 'medium_ssti_payload';
        }

        if ($criticalPayloadCount >= 2) {
            $score += 15;
            $indicators[] = 'multiple_critical_payloads';
        }
        if ($highPayloadCount >= 3) {
            $score += 10;
            $indicators[] = 'multiple_high_payloads';
        }

        $dangerousFilterCount = 0;
        $maxFilterLevel = 0;
        foreach ($allExpressions as $expr) {
            if (!empty($expr['dangerous_filters'])) {
                foreach ($expr['dangerous_filters'] as $f) {
                    $dangerousFilterCount++;
                    if ($f['level'] > $maxFilterLevel) {
                        $maxFilterLevel = $f['level'];
                    }
                }
            }
        }

        if ($maxFilterLevel >= 5) {
            $score += 25;
            $indicators[] = 'critical_dangerous_filter';
        } elseif ($maxFilterLevel >= 4) {
            $score += 18;
            $indicators[] = 'high_dangerous_filter';
        } elseif ($maxFilterLevel >= 3) {
            $score += 10;
            $indicators[] = 'medium_dangerous_filter';
        }

        if ($hasObfuscation) {
            $obfScore = min(20, count($obfuscationIndicators) * 6);
            $score += $obfScore;
            $indicators[] = 'obfuscation_detected';
        }

        if ($hasMixedEngines && $maxPayloadLevel >= 4) {
            $score += 15;
            $indicators[] = 'mixed_engines_plus_payload';
        }

        if ($maxExpressionDepth >= 3 && $maxPayloadLevel >= 4) {
            $score += 10;
            $indicators[] = 'deep_nested_payload';
        }

        $riskLevel = 'low';
        if ($score >= 75) $riskLevel = 'critical';
        elseif ($score >= 55) $riskLevel = 'high';
        elseif ($score >= 35) $riskLevel = 'medium';
        elseif ($score >= 15) $riskLevel = 'low';
        else $riskLevel = 'clean';

        return [
            'score' => min(100, $score),
            'risk_level' => $riskLevel,
            'is_ssti' => $score >= 30,
            'detected_engines' => array_values($detectedEngines),
            'engine_count' => $engineCount,
            'total_expressions' => $totalExpressions,
            'expression_depth' => $maxExpressionDepth,
            'dangerous_tags' => array_values($dangerousTagsFound),
            'payload_hits' => array_values($payloadHits),
            'expressions' => array_slice($allExpressions, 0, 50),
            'has_mixed_engines' => $hasMixedEngines,
            'has_obfuscation' => $hasObfuscation,
            'obfuscation_indicators' => $obfuscationIndicators,
            'indicators' => $indicators,
        ];
    }

    private static function defaultResult(): array {
        return [
            'score' => 0,
            'risk_level' => 'clean',
            'is_ssti' => false,
            'detected_engines' => [],
            'engine_count' => 0,
            'total_expressions' => 0,
            'expression_depth' => 0,
            'dangerous_tags' => [],
            'payload_hits' => [],
            'expressions' => [],
            'has_mixed_engines' => false,
            'has_obfuscation' => false,
            'obfuscation_indicators' => [],
            'indicators' => [],
        ];
    }

    private static function calculateExpressionDepth(string $expression): int {
        $maxDepth = 0;
        $currentDepth = 0;
        $len = strlen($expression);
        $i = 0;

        while ($i < $len) {
            $ch = $expression[$i];
            $twoChar = substr($expression, $i, 2);
            $threeChar = substr($expression, $i, 3);

            if ($twoChar === '{{' || $twoChar === '{%' || $twoChar === '{#' || $twoChar === '${' || $twoChar === '<%') {
                $currentDepth++;
                if ($currentDepth > $maxDepth) $maxDepth = $currentDepth;
                $i += 2;
                continue;
            }

            if ($twoChar === '}}' || $twoChar === '%}' || $twoChar === '#}' || $twoChar === '%>') {
                if ($currentDepth > 0) $currentDepth--;
                $i += 2;
                continue;
            }

            if ($threeChar === '<?=' || $threeChar === '<?p') {
                $currentDepth++;
                if ($currentDepth > $maxDepth) $maxDepth = $currentDepth;
                $i += 3;
                continue;
            }

            if ($ch === '(' || $ch === '[' || $ch === '{') {
                $currentDepth++;
                if ($currentDepth > $maxDepth) $maxDepth = $currentDepth;
            } elseif ($ch === ')' || $ch === ']' || $ch === '}') {
                if ($currentDepth > 0) $currentDepth--;
            }

            $i++;
        }

        return $maxDepth;
    }

    private static function detectDangerousFilters(string $content): array {
        $found = [];

        if (preg_match_all('/\|\s*([a-zA-Z_]\w*)/', $content, $filterMatches)) {
            foreach ($filterMatches[1] as $filterName) {
                $filterLower = strtolower($filterName);
                if (isset(self::$filterPatterns['dangerous_filters'][$filterLower])) {
                    $level = self::$filterPatterns['dangerous_filters'][$filterLower];
                    $key = 'filter_' . $filterLower;
                    if (!isset($found[$key])) {
                        $found[$key] = [
                            'name' => $filterName,
                            'level' => $level,
                        ];
                    }
                }
            }
        }

        return array_values($found);
    }
}
