<?php
/**
 * SSTI（服务端模板注入）语义解析器
 * 职责：通过构建模板表达式AST真正理解模板结构，
 *       识别不同模板引擎的语法特征，检测模板注入攻击。
 */
defined('ABSPATH') || exit;

class SstiSemanticParser {

    const TOKEN_OUTPUT_START   = 'OUTPUT_START';
    const TOKEN_OUTPUT_END     = 'OUTPUT_END';
    const TOKEN_STMT_START     = 'STMT_START';
    const TOKEN_STMT_END       = 'STMT_END';
    const TOKEN_COMMENT_START  = 'COMMENT_START';
    const TOKEN_COMMENT_END    = 'COMMENT_END';
    const TOKEN_IDENT          = 'IDENT';
    const TOKEN_STRING         = 'STRING';
    const TOKEN_NUMBER         = 'NUMBER';
    const TOKEN_OPERATOR       = 'OPERATOR';
    const TOKEN_PUNCT          = 'PUNCT';
    const TOKEN_FILTER         = 'FILTER';
    const TOKEN_KEYWORD        = 'KEYWORD';
    const TOKEN_EOF            = 'EOF';

    private static $keywords = [
        'if', 'endif', 'else', 'elif', 'for', 'endfor', 'in', 'not',
        'and', 'or', 'is', 'true', 'false', 'null', 'none', 'nil',
        'set', 'endset', 'block', 'endblock', 'extends', 'include',
        'import', 'from', 'as', 'macro', 'endmacro', 'do', 'with',
        'endwith', 'without', 'context', 'ignore', 'missing',
        'defined', 'undefined', 'divisibleby', 'sameas', 'sequence',
    ];

    private static $dangerousFilters = [
        'system' => 5, 'exec' => 5, 'shell_exec' => 5, 'passthru' => 5,
        'eval' => 5, 'assert' => 5, 'include' => 4, 'file_get_contents' => 4,
        'readfile' => 4, 'phpinfo' => 4, 'raw' => 3, 'safe' => 3,
        'attr' => 4, 'format' => 4, 'map' => 4, 'batch' => 4,
        'reduce' => 4, 'filter' => 3, 'replace' => 3, 'split' => 2,
        'base64_decode' => 3, 'base64_encode' => 2, 'json_decode' => 2,
        'json_encode' => 2, 'url_decode' => 2, 'raw_url_decode' => 3,
    ];

    private static $dangerousFunctions = [
        'config' => 4, 'self' => 4, 'cycler' => 5, 'joiner' => 4,
        'namespace' => 5, 'lipsum' => 5, 'range' => 3, 'dict' => 3,
        'get_flashed_messages' => 5, 'url_for' => 3, 'render_template_string' => 5,
        'getattr' => 4, 'setattr' => 4, 'delattr' => 4, 'hasattr' => 4,
        'globals' => 5, 'locals' => 5, 'vars' => 5, 'dir' => 4,
        'eval' => 5, 'exec' => 5, 'compile' => 5, 'open' => 5,
        'file' => 4, 'import' => 5, '__import__' => 5,
        'subprocess' => 5, 'os' => 5, 'sys' => 4,
    ];

    private static $dangerousAttributes = [
        '__class__' => 5, '__mro__' => 5, '__subclasses__' => 5,
        '__builtins__' => 5, '__globals__' => 5, '__init__' => 4,
        '__dict__' => 4, '__getattribute__' => 5, '__getitem__' => 4,
        'class' => 3, 'environment' => 4, 'loader' => 4,
        'next' => 3, 'func_globals' => 5, 'func_code' => 5,
        'gi_frame' => 5, 'f_locals' => 5, 'f_globals' => 5,
    ];

    private static $enginePatterns = [
        'twig_jinja2' => [
            'name' => 'Twig/Jinja2',
            'output' => '/\{\{\s*(.+?)\s*\}\}/s',
            'statement' => '/\{%\s*(.+?)\s*%\}/s',
            'comment' => '/\{#\s*(.+?)\s*#\}/s',
            'danger_level' => 4,
        ],
        'smarty' => [
            'name' => 'Smarty',
            'variable' => '/\{\$\s*[a-zA-Z_]\w*(?:\.\w+|\[[^\]]+\])*\s*\}/',
            'foreach' => '/\{foreach\s+[^}]*\}/i',
            'php' => '/\{php\}/i',
            'danger_level' => 4,
        ],
        'velocity' => [
            'name' => 'Velocity',
            'set' => '/#set\s*\(\s*\$[a-zA-Z_]\w*\s*=/i',
            'if' => '/#if\s*\(/i',
            'foreach' => '/#foreach\s*\(/i',
            'variable' => '/\$[a-zA-Z_]\w*(?:\.\w+)*(?=\s|\)|$|,|\})/',
            'danger_level' => 4,
        ],
        'freemarker' => [
            'name' => 'Freemarker',
            'output' => '/\$\{(.+?)\}/s',
            'if' => '/<#if\s+/i',
            'list' => '/<#list\s+/i',
            'assign' => '/<#assign\s+/i',
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

    private static $sstiPayloadPatterns = [
        'math_operation' => ['pattern' => '/\{\{\s*(\d+)\s*[\*\+\-\%]\s*(\d+)\s*\}\}/', 'level' => 4, 'desc' => '数学运算表达式（SSTI探测）'],
        'mro_access' => ['pattern' => '/__mro__/i', 'level' => 5, 'desc' => '__mro__继承链访问（Python SSTI）'],
        'subclasses_access' => ['pattern' => '/__subclasses__/i', 'level' => 5, 'desc' => '__subclasses__子类枚举（Python SSTI）'],
        'builtins_access' => ['pattern' => '/__builtins__/i', 'level' => 5, 'desc' => '__builtins__内置函数访问（Python SSTI）'],
        'globals_access' => ['pattern' => '/__globals__/i', 'level' => 5, 'desc' => '__globals__全局变量访问（Python SSTI）'],
        'os_system' => ['pattern' => '/os\.system/i', 'level' => 5, 'desc' => 'os.system命令执行（Python SSTI）'],
        'popen' => ['pattern' => '/popen/i', 'level' => 5, 'desc' => 'popen命令执行'],
        'exec_eval' => ['pattern' => '/\b(exec|eval)\b/i', 'level' => 5, 'desc' => 'exec/eval代码执行'],
        'request_access' => ['pattern' => '/\brequest\b/i', 'level' => 3, 'desc' => 'request对象访问'],
        'self_environment' => ['pattern' => '/self\.environment/i', 'level' => 4, 'desc' => 'self.environment访问（Jinja2 SSTI）'],
        'freemarker_new' => ['pattern' => '/\bnew\s*\(/i', 'level' => 5, 'desc' => 'Freemarker new() 利用'],
        'freemarker_execute' => ['pattern' => '/\?exec\b/i', 'level' => 5, 'desc' => 'Freemarker ?exec 命令执行'],
        'smarty_php' => ['pattern' => '/\{php\}/i', 'level' => 5, 'desc' => 'Smarty {php} 标签'],
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
        $astSummaries = [];
        $totalTokenCount = 0;
        $parserUsed = 'regex';
        $astParseSuccess = false;

        foreach ($testInputs as $sourceKey => $testInput) {
            if ($testInput === '') continue;

            try {
                $tokens = self::tokenize($testInput);
                $tokenCount = count($tokens);
                if ($tokenCount > $totalTokenCount) $totalTokenCount = $tokenCount;

                if (!empty($tokens) && $tokenCount > 2) {
                    $ast = self::parseTemplate($tokens, $testInput);
                    if ($ast !== null && !empty($ast['nodes'])) {
                        $astParseSuccess = true;
                        $parserUsed = 'ast';

                        $walkerResult = self::walkAst($ast, $testInput);
                        $astSummaries[] = [
                            'source' => $sourceKey,
                            'summary' => self::summarizeAst($ast),
                            'walker' => $walkerResult,
                        ];

                        if ($walkerResult['max_depth'] > $maxExpressionDepth) {
                            $maxExpressionDepth = $walkerResult['max_depth'];
                        }

                        foreach ($walkerResult['dangerous_filters'] as $f) {
                            $key = 'filter_' . $f['name'] . '_' . $sourceKey;
                            if (!isset($dangerousTagsFound[$key])) {
                                $dangerousTagsFound[$key] = [
                                    'tag' => 'filter:' . $f['name'],
                                    'engine' => 'twig_jinja2',
                                    'level' => $f['level'],
                                    'desc' => '危险过滤器：' . $f['name'],
                                    'source' => $sourceKey,
                                    'count' => 1,
                                ];
                            }
                        }

                        foreach ($walkerResult['dangerous_functions'] as $fn) {
                            $key = 'func_' . $fn['name'] . '_' . $sourceKey;
                            if (!isset($dangerousTagsFound[$key])) {
                                $dangerousTagsFound[$key] = [
                                    'tag' => 'function:' . $fn['name'],
                                    'engine' => 'twig_jinja2',
                                    'level' => $fn['level'],
                                    'desc' => '危险函数：' . $fn['name'],
                                    'source' => $sourceKey,
                                    'count' => 1,
                                ];
                            }
                        }

                        foreach ($walkerResult['dangerous_attributes'] as $attr) {
                            $key = 'attr_' . $attr['name'] . '_' . $sourceKey;
                            if (!isset($dangerousTagsFound[$key])) {
                                $dangerousTagsFound[$key] = [
                                    'tag' => 'attribute:' . $attr['name'],
                                    'engine' => 'twig_jinja2',
                                    'level' => $attr['level'],
                                    'desc' => '危险属性访问：' . $attr['name'],
                                    'source' => $sourceKey,
                                    'count' => 1,
                                ];
                            }
                        }

                        $exprFromAst = self::extractExpressionsFromAst($ast, $testInput, $sourceKey);
                        foreach ($exprFromAst as $expr) {
                            $allExpressions[] = $expr;
                            $totalExpressions++;
                        }

                        foreach ($walkerResult['engines_detected'] as $engineKey => $engineInfo) {
                            if (!isset($detectedEngines[$engineKey])) {
                                $detectedEngines[$engineKey] = $engineInfo;
                            }
                        }

                        continue;
                    }
                }
            } catch (Exception $e) {
            }

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
                            if ($depth > $maxExpressionDepth) $maxExpressionDepth = $depth;

                            $hasDangerousFilter = false;
                            $dangerousFiltersFound = [];
                            if ($patternType === 'filter' || $patternType === 'output') {
                                $filterResult = self::detectDangerousFiltersRegex($innerContent);
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

        $concatPatterns = ['/["\']\s*~\s*["\']/', '/["\']\s*\.\s*["\']/', '/["\']\s*\+\s*["\']/'];
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
            if ($engine['danger_level'] > $maxEngineLevel) $maxEngineLevel = $engine['danger_level'];
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
            if ($tag['level'] > $maxTagLevel) $maxTagLevel = $tag['level'];
        }

        if ($maxTagLevel >= 5) {
            $score += 40;
            $indicators[] = 'critical_dangerous_tag';
        } elseif ($maxTagLevel >= 4) {
            $score += 28;
            $indicators[] = 'high_dangerous_tag';
        } elseif ($maxTagLevel >= 3) {
            $score += 18;
            $indicators[] = 'medium_dangerous_tag';
        }

        $maxPayloadLevel = 0;
        $criticalPayloadCount = 0;
        $highPayloadCount = 0;
        foreach ($payloadHits as $hit) {
            if ($hit['level'] > $maxPayloadLevel) $maxPayloadLevel = $hit['level'];
            if ($hit['level'] >= 5) $criticalPayloadCount++;
            elseif ($hit['level'] >= 4) $highPayloadCount++;
        }

        if ($maxPayloadLevel >= 5) {
            $score += 45;
            $indicators[] = 'critical_ssti_payload';
        } elseif ($maxPayloadLevel >= 4) {
            $score += 32;
            $indicators[] = 'high_ssti_payload';
        } elseif ($maxPayloadLevel >= 3) {
            $score += 20;
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
                    if ($f['level'] > $maxFilterLevel) $maxFilterLevel = $f['level'];
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

        if ($astParseSuccess) {
            $indicators[] = 'ast_parser_used';
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
            'parser_used' => $parserUsed,
            'token_count' => $totalTokenCount,
            'ast_summary' => $astSummaries,
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
            'parser_used' => 'regex',
            'token_count' => 0,
            'ast_summary' => [],
        ];
    }

    // ==================== Tokenizer ====================

    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);
        $keywordMap = array_flip(self::$keywords);

        while ($pos < $len) {
            $char = $input[$pos];
            $twoChar = substr($input, $pos, 2);

            if ($char === ' ' || $char === "\t" || $char === "\n" || $char === "\r") {
                $pos++;
                continue;
            }

            if ($twoChar === '{{') {
                $tokens[] = ['type' => self::TOKEN_OUTPUT_START, 'value' => '{{', 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if ($twoChar === '}}') {
                $tokens[] = ['type' => self::TOKEN_OUTPUT_END, 'value' => '}}', 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if ($twoChar === '{%') {
                $tokens[] = ['type' => self::TOKEN_STMT_START, 'value' => '{%', 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if ($twoChar === '%}') {
                $tokens[] = ['type' => self::TOKEN_STMT_END, 'value' => '%}', 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if ($twoChar === '{#') {
                $tokens[] = ['type' => self::TOKEN_COMMENT_START, 'value' => '{#', 'pos' => $pos];
                $pos += 2;
                $commentContent = '';
                while ($pos < $len - 1 && substr($input, $pos, 2) !== '#}') {
                    $commentContent .= $input[$pos];
                    $pos++;
                }
                if ($pos < $len - 1) $pos += 2;
                $tokens[] = ['type' => self::TOKEN_COMMENT_END, 'value' => '#}', 'pos' => $pos - 2, 'content' => $commentContent];
                continue;
            }

            if ($char === '"' || $char === "'") {
                $quote = $char;
                $start = $pos;
                $pos++;
                $value = '';
                while ($pos < $len) {
                    if ($input[$pos] === $quote) {
                        $pos++;
                        break;
                    }
                    if ($input[$pos] === '\\' && $pos + 1 < $len) {
                        $value .= $input[$pos] . $input[$pos + 1];
                        $pos += 2;
                    } else {
                        $value .= $input[$pos];
                        $pos++;
                    }
                }
                $tokens[] = [
                    'type' => self::TOKEN_STRING,
                    'value' => $value,
                    'raw' => substr($input, $start, $pos - $start),
                    'pos' => $start,
                    'quoted' => $quote,
                ];
                continue;
            }

            if (is_numeric($char) || ($char === '.' && $pos + 1 < $len && is_numeric($input[$pos + 1]))) {
                $start = $pos;
                $hasDot = false;
                while ($pos < $len && (is_numeric($input[$pos]) || ($input[$pos] === '.' && !$hasDot))) {
                    if ($input[$pos] === '.') $hasDot = true;
                    $pos++;
                }
                $tokens[] = [
                    'type' => self::TOKEN_NUMBER,
                    'value' => substr($input, $start, $pos - $start),
                    'pos' => $start,
                ];
                continue;
            }

            if ($char === '|') {
                $tokens[] = ['type' => self::TOKEN_FILTER, 'value' => '|', 'pos' => $pos];
                $pos++;
                continue;
            }

            if (ctype_alpha($char) || $char === '_' || $char === '$') {
                $start = $pos;
                while ($pos < $len && (ctype_alnum($input[$pos]) || $input[$pos] === '_' || $input[$pos] === '$')) {
                    $pos++;
                }
                $word = substr($input, $start, $pos - $start);
                $lower = strtolower($word);

                $type = isset($keywordMap[$lower]) ? self::TOKEN_KEYWORD : self::TOKEN_IDENT;
                $tokens[] = [
                    'type' => $type,
                    'value' => $word,
                    'lower' => $lower,
                    'pos' => $start,
                ];
                continue;
            }

            $threeChar = substr($input, $pos, 3);
            if (in_array($threeChar, ['===', '!==', '<=>'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $threeChar, 'pos' => $pos];
                $pos += 3;
                continue;
            }
            if (in_array($twoChar, ['!=', '<>', '<=', '>=', '==', '||', '&&', '..', '**', '//'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $twoChar, 'pos' => $pos];
                $pos += 2;
                continue;
            }
            if (in_array($char, ['=', '<', '>', '+', '-', '*', '/', '%', '~', '&', '!', '?', '#', '@'])) {
                $tokens[] = ['type' => self::TOKEN_OPERATOR, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            if (in_array($char, ['(', ')', ',', '.', '[', ']', '{', '}', ':', ';'])) {
                $tokens[] = ['type' => self::TOKEN_PUNCT, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            $pos++;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    // ==================== Parser ====================

    private static function parseTemplate(array $tokens, string $input): ?array {
        $state = [
            'tokens' => $tokens,
            'pos' => 0,
            'input' => $input,
        ];

        $ast = [
            'type' => 'template',
            'nodes' => [],
        ];

        while (!self::isEof($state)) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_OUTPUT_START) {
                $node = self::parseOutput($state);
                if ($node !== null) $ast['nodes'][] = $node;
            } elseif ($token['type'] === self::TOKEN_STMT_START) {
                $node = self::parseStatement($state);
                if ($node !== null) $ast['nodes'][] = $node;
            } elseif ($token['type'] === self::TOKEN_COMMENT_START) {
                self::next($state);
                if (self::current($state)['type'] === self::TOKEN_COMMENT_END) {
                    self::next($state);
                }
            } else {
                self::next($state);
            }
        }

        if (empty($ast['nodes'])) return null;
        return $ast;
    }

    private static function parseOutput(array &$state): ?array {
        $startToken = self::current($state);
        if ($startToken['type'] !== self::TOKEN_OUTPUT_START) return null;
        self::next($state);

        $expr = self::parseExpression($state);

        $endFound = false;
        while (!self::isEof($state)) {
            if (self::current($state)['type'] === self::TOKEN_OUTPUT_END) {
                self::next($state);
                $endFound = true;
                break;
            }
            self::next($state);
        }

        if ($expr === null) return null;

        return [
            'type' => 'output',
            'expression' => $expr,
            'start_pos' => $startToken['pos'],
            'has_end' => $endFound,
        ];
    }

    private static function parseStatement(array &$state): ?array {
        $startToken = self::current($state);
        if ($startToken['type'] !== self::TOKEN_STMT_START) return null;
        self::next($state);

        $stmt = null;
        $firstToken = self::current($state);

        if ($firstToken['type'] === self::TOKEN_KEYWORD) {
            $kw = strtolower($firstToken['value']);
            switch ($kw) {
                case 'if':
                    $stmt = self::parseIfStatement($state);
                    break;
                case 'for':
                    $stmt = self::parseForStatement($state);
                    break;
                case 'set':
                    $stmt = self::parseSetStatement($state);
                    break;
                default:
                    $stmt = self::parseGenericStatement($state);
            }
        } else {
            $stmt = self::parseGenericStatement($state);
        }

        while (!self::isEof($state)) {
            if (self::current($state)['type'] === self::TOKEN_STMT_END) {
                self::next($state);
                break;
            }
            self::next($state);
        }

        if ($stmt === null) return null;
        $stmt['start_pos'] = $startToken['pos'];
        return $stmt;
    }

    private static function parseIfStatement(array &$state): array {
        self::next($state);
        $condition = self::parseExpression($state);
        return [
            'type' => 'if_stmt',
            'condition' => $condition,
        ];
    }

    private static function parseForStatement(array &$state): array {
        self::next($state);
        $loopVar = null;
        $iterable = null;

        if (self::current($state)['type'] === self::TOKEN_IDENT) {
            $loopVar = self::current($state)['value'];
            self::next($state);
        }

        if (self::current($state)['type'] === self::TOKEN_KEYWORD &&
            strtolower(self::current($state)['value']) === 'in') {
            self::next($state);
            $iterable = self::parseExpression($state);
        }

        return [
            'type' => 'for_stmt',
            'loop_var' => $loopVar,
            'iterable' => $iterable,
        ];
    }

    private static function parseSetStatement(array &$state): array {
        self::next($state);
        $varName = null;
        $value = null;

        if (self::current($state)['type'] === self::TOKEN_IDENT) {
            $varName = self::current($state)['value'];
            self::next($state);
        }

        if (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '=') {
            self::next($state);
            $value = self::parseExpression($state);
        }

        return [
            'type' => 'set_stmt',
            'var_name' => $varName,
            'value' => $value,
        ];
    }

    private static function parseGenericStatement(array &$state): array {
        $content = [];
        while (!self::isEof($state) &&
               self::current($state)['type'] !== self::TOKEN_STMT_END) {
            $content[] = self::current($state);
            self::next($state);
        }
        return [
            'type' => 'generic_stmt',
            'tokens' => $content,
        ];
    }

    // ==================== Expression Parser ====================

    private static function parseExpression(array &$state): ?array {
        return self::parseTernary($state);
    }

    private static function parseTernary(array &$state): ?array {
        $left = self::parseOrExpr($state);
        if ($left === null) return null;

        if (self::current($state)['type'] === self::TOKEN_OPERATOR && self::current($state)['value'] === '?') {
            self::next($state);
            $trueExpr = self::parseOrExpr($state);
            $falseExpr = null;
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ':') {
                self::next($state);
                $falseExpr = self::parseTernary($state);
            }
            return [
                'type' => 'ternary',
                'condition' => $left,
                'true_expr' => $trueExpr,
                'false_expr' => $falseExpr,
            ];
        }

        return $left;
    }

    private static function parseOrExpr(array &$state): ?array {
        $left = self::parseAndExpr($state);
        if ($left === null) return null;

        while (true) {
            $token = self::current($state);
            $isOr = false;
            if ($token['type'] === self::TOKEN_KEYWORD && strtolower($token['value']) === 'or') {
                $isOr = true;
            } elseif ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '||') {
                $isOr = true;
            }

            if ($isOr) {
                self::next($state);
                $right = self::parseAndExpr($state);
                $left = [
                    'type' => 'logical_or',
                    'left' => $left,
                    'right' => $right,
                ];
            } else {
                break;
            }
        }
        return $left;
    }

    private static function parseAndExpr(array &$state): ?array {
        $left = self::parseNotExpr($state);
        if ($left === null) return null;

        while (true) {
            $token = self::current($state);
            $isAnd = false;
            if ($token['type'] === self::TOKEN_KEYWORD && strtolower($token['value']) === 'and') {
                $isAnd = true;
            } elseif ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '&&') {
                $isAnd = true;
            }

            if ($isAnd) {
                self::next($state);
                $right = self::parseNotExpr($state);
                $left = [
                    'type' => 'logical_and',
                    'left' => $left,
                    'right' => $right,
                ];
            } else {
                break;
            }
        }
        return $left;
    }

    private static function parseNotExpr(array &$state): ?array {
        $token = self::current($state);
        $isNot = false;

        if ($token['type'] === self::TOKEN_KEYWORD && strtolower($token['value']) === 'not') {
            $isNot = true;
        } elseif ($token['type'] === self::TOKEN_OPERATOR && $token['value'] === '!') {
            $isNot = true;
        }

        if ($isNot) {
            self::next($state);
            $expr = self::parseNotExpr($state);
            return ['type' => 'logical_not', 'expr' => $expr];
        }

        return self::parseComparison($state);
    }

    private static function parseComparison(array &$state): ?array {
        $left = self::parseAddExpr($state);
        if ($left === null) return null;

        $token = self::current($state);
        $op = null;

        if ($token['type'] === self::TOKEN_OPERATOR &&
            in_array($token['value'], ['==', '!=', '<>', '<', '>', '<=', '>=', '===', '!=='])) {
            $op = $token['value'];
        } elseif ($token['type'] === self::TOKEN_KEYWORD &&
                  in_array(strtolower($token['value']), ['is', 'in'])) {
            $op = strtolower($token['value']);
        }

        if ($op !== null) {
            self::next($state);
            $right = self::parseAddExpr($state);
            return [
                'type' => 'comparison',
                'op' => $op,
                'left' => $left,
                'right' => $right,
            ];
        }

        return $left;
    }

    private static function parseAddExpr(array &$state): ?array {
        $left = self::parseMulExpr($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['+', '-', '~'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseMulExpr($state);
            $left = [
                'type' => 'binary_op',
                'op' => $op,
                'left' => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    private static function parseMulExpr(array &$state): ?array {
        $left = self::parseUnary($state);
        if ($left === null) return null;

        while (self::current($state)['type'] === self::TOKEN_OPERATOR &&
               in_array(self::current($state)['value'], ['*', '/', '%', '//', '**'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $right = self::parseUnary($state);
            $left = [
                'type' => 'binary_op',
                'op' => $op,
                'left' => $left,
                'right' => $right,
            ];
        }
        return $left;
    }

    private static function parseUnary(array &$state): ?array {
        if (self::current($state)['type'] === self::TOKEN_OPERATOR &&
            in_array(self::current($state)['value'], ['+', '-', '!', '~'])) {
            $op = self::current($state)['value'];
            self::next($state);
            $expr = self::parseUnary($state);
            return ['type' => 'unary_op', 'op' => $op, 'expr' => $expr];
        }
        return self::parseFilter($state);
    }

    private static function parseFilter(array &$state): ?array {
        $left = self::parsePrimary($state);
        if ($left === null) return null;

        $filterChain = [];
        while (self::current($state)['type'] === self::TOKEN_FILTER) {
            self::next($state);
            $filterName = null;
            $filterArgs = [];

            if (self::current($state)['type'] === self::TOKEN_IDENT || self::current($state)['type'] === self::TOKEN_KEYWORD) {
                $filterName = self::current($state)['value'];
                self::next($state);

                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '(') {
                    self::next($state);
                    $filterArgs = self::parseExpressionList($state);
                    if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                        self::next($state);
                    }
                }
            }

            $filterChain[] = [
                'name' => $filterName,
                'arguments' => $filterArgs,
            ];
        }

        if (!empty($filterChain)) {
            return [
                'type' => 'filter_expression',
                'value' => $left,
                'filters' => $filterChain,
            ];
        }

        return $left;
    }

    private static function parsePrimary(array &$state): ?array {
        $token = self::current($state);

        if ($token['type'] === self::TOKEN_NUMBER) {
            self::next($state);
            $node = ['type' => 'literal', 'subtype' => 'number', 'value' => $token['value']];
            return self::parsePostfix($state, $node);
        }

        if ($token['type'] === self::TOKEN_STRING) {
            self::next($state);
            $node = ['type' => 'literal', 'subtype' => 'string', 'value' => $token['value']];
            return self::parsePostfix($state, $node);
        }

        if ($token['type'] === self::TOKEN_KEYWORD) {
            $kw = strtolower($token['value']);
            if ($kw === 'true' || $kw === 'false') {
                self::next($state);
                $node = ['type' => 'literal', 'subtype' => 'bool', 'value' => $kw === 'true'];
                return self::parsePostfix($state, $node);
            }
            if ($kw === 'null' || $kw === 'none' || $kw === 'nil') {
                self::next($state);
                $node = ['type' => 'literal', 'subtype' => 'null', 'value' => null];
                return self::parsePostfix($state, $node);
            }
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '(') {
            self::next($state);
            $expr = self::parseExpression($state);
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                self::next($state);
            }
            if ($expr === null) return null;
            return self::parsePostfix($state, $expr);
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '[') {
            self::next($state);
            $items = self::parseExpressionList($state);
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ']') {
                self::next($state);
            }
            $node = ['type' => 'array', 'items' => $items];
            return self::parsePostfix($state, $node);
        }

        if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '{') {
            self::next($state);
            $pairs = [];
            while (!self::isEof($state) && self::current($state)['value'] !== '}') {
                if (!empty($pairs) && self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ',') {
                    self::next($state);
                    continue;
                }
                $key = self::parseExpression($state);
                $value = null;
                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ':') {
                    self::next($state);
                    $value = self::parseExpression($state);
                }
                if ($key !== null) {
                    $pairs[] = ['key' => $key, 'value' => $value];
                }
                if (self::current($state)['type'] !== self::TOKEN_PUNCT || self::current($state)['value'] !== ',') {
                    break;
                }
            }
            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '}') {
                self::next($state);
            }
            $node = ['type' => 'dict', 'pairs' => $pairs];
            return self::parsePostfix($state, $node);
        }

        if ($token['type'] === self::TOKEN_IDENT || $token['type'] === self::TOKEN_KEYWORD) {
            $name = $token['value'];
            self::next($state);

            if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === '(') {
                self::next($state);
                $args = self::parseExpressionList($state);
                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ')') {
                    self::next($state);
                }
                $node = [
                    'type' => 'function_call',
                    'name' => $name,
                    'arguments' => $args,
                ];
                return self::parsePostfix($state, $node);
            }

            $node = ['type' => 'identifier', 'name' => $name];
            return self::parsePostfix($state, $node);
        }

        return null;
    }

    private static function parsePostfix(array &$state, ?array $node): ?array {
        if ($node === null) return null;

        while (true) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '.') {
                self::next($state);
                $attr = null;
                if (self::current($state)['type'] === self::TOKEN_IDENT || self::current($state)['type'] === self::TOKEN_KEYWORD) {
                    $attr = self::current($state)['value'];
                    self::next($state);
                }
                $node = [
                    'type' => 'attribute_access',
                    'object' => $node,
                    'attribute' => $attr,
                ];
                continue;
            }

            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === '[') {
                self::next($state);
                $index = self::parseExpression($state);
                if (self::current($state)['type'] === self::TOKEN_PUNCT && self::current($state)['value'] === ']') {
                    self::next($state);
                }
                $node = [
                    'type' => 'index_access',
                    'object' => $node,
                    'index' => $index,
                ];
                continue;
            }

            break;
        }

        return $node;
    }

    private static function parseExpressionList(array &$state): array {
        $exprs = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_PUNCT && in_array($token['value'], [')', ']', '}'])) {
                break;
            }
            if ($token['type'] === self::TOKEN_PUNCT && $token['value'] === ',') {
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_OUTPUT_END || $token['type'] === self::TOKEN_STMT_END) {
                break;
            }

            $expr = self::parseExpression($state);
            if ($expr !== null) {
                $exprs[] = $expr;
            } else {
                break;
            }

            if (self::current($state)['type'] !== self::TOKEN_PUNCT || self::current($state)['value'] !== ',') {
                break;
            }
        }
        return $exprs;
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function next(array &$state) {
        if ($state['pos'] < count($state['tokens']) - 1) {
            $state['pos']++;
        }
    }

    private static function isEof(array &$state): bool {
        $t = self::current($state);
        return $t['type'] === self::TOKEN_EOF;
    }

    // ==================== AST Walker ====================

    private static function walkAst(array $ast, string $input): array {
        $result = [
            'dangerous_filters' => [],
            'dangerous_functions' => [],
            'dangerous_attributes' => [],
            'engines_detected' => [],
            'filter_chain_depth' => 0,
            'max_depth' => 0,
            'has_complex_expression' => false,
            'has_string_concat' => false,
            'output_node_count' => 0,
            'stmt_node_count' => 0,
        ];

        $depth = self::calcAstDepth($ast);
        $result['max_depth'] = $depth;

        self::walkNode($ast, $result);

        $result['engines_detected'] = self::detectEnginesFromAst($ast, $input);

        return $result;
    }

    private static function walkNode(array $node, array &$result) {
        $type = $node['type'] ?? '';

        if ($type === 'output') {
            $result['output_node_count']++;
            if (isset($node['expression'])) {
                self::walkNode($node['expression'], $result);
            }
        } elseif ($type === 'if_stmt' || $type === 'for_stmt' || $type === 'set_stmt') {
            $result['stmt_node_count']++;
            if (isset($node['condition'])) self::walkNode($node['condition'], $result);
            if (isset($node['iterable'])) self::walkNode($node['iterable'], $result);
            if (isset($node['value'])) self::walkNode($node['value'], $result);
        } elseif ($type === 'filter_expression') {
            if (isset($node['value'])) {
                self::walkNode($node['value'], $result);
            }
            if (isset($node['filters'])) {
                $chainLen = count($node['filters']);
                if ($chainLen > $result['filter_chain_depth']) {
                    $result['filter_chain_depth'] = $chainLen;
                }
                foreach ($node['filters'] as $filter) {
                    $filterName = strtolower($filter['name'] ?? '');
                    if (isset(self::$dangerousFilters[$filterName])) {
                        $found = false;
                        foreach ($result['dangerous_filters'] as $df) {
                            if ($df['name'] === $filterName) { $found = true; break; }
                        }
                        if (!$found) {
                            $result['dangerous_filters'][] = [
                                'name' => $filterName,
                                'level' => self::$dangerousFilters[$filterName],
                            ];
                        }
                    }
                    if (!empty($filter['arguments'])) {
                        foreach ($filter['arguments'] as $arg) {
                            if (is_array($arg)) self::walkNode($arg, $result);
                        }
                    }
                }
            }
        } elseif ($type === 'function_call') {
            $fnName = strtolower($node['name'] ?? '');
            if (isset(self::$dangerousFunctions[$fnName])) {
                $found = false;
                foreach ($result['dangerous_functions'] as $df) {
                    if ($df['name'] === $fnName) { $found = true; break; }
                }
                if (!$found) {
                    $result['dangerous_functions'][] = [
                        'name' => $fnName,
                        'level' => self::$dangerousFunctions[$fnName],
                    ];
                }
            }
            if (!empty($node['arguments'])) {
                foreach ($node['arguments'] as $arg) {
                    if (is_array($arg)) self::walkNode($arg, $result);
                }
            }
        } elseif ($type === 'attribute_access') {
            $attr = strtolower($node['attribute'] ?? '');
            if (isset(self::$dangerousAttributes[$attr])) {
                $found = false;
                foreach ($result['dangerous_attributes'] as $da) {
                    if ($da['name'] === $attr) { $found = true; break; }
                }
                if (!$found) {
                    $result['dangerous_attributes'][] = [
                        'name' => $attr,
                        'level' => self::$dangerousAttributes[$attr],
                    ];
                }
            }
            if (isset($node['object']) && is_array($node['object'])) {
                self::walkNode($node['object'], $result);
            }
        } elseif ($type === 'index_access') {
            if (isset($node['object']) && is_array($node['object'])) {
                self::walkNode($node['object'], $result);
            }
            if (isset($node['index']) && is_array($node['index'])) {
                self::walkNode($node['index'], $result);
            }
        } elseif ($type === 'binary_op') {
            $op = $node['op'] ?? '';
            if ($op === '~' || $op === '+') {
                if (isset($node['left']) && isset($node['right'])) {
                    $leftIsStr = self::isLiteralString($node['left']);
                    $rightIsStr = self::isLiteralString($node['right']);
                    if ($leftIsStr || $rightIsStr) {
                        $result['has_string_concat'] = true;
                    }
                }
            }
            if (in_array($op, ['+', '-', '*', '/', '%', '**', '//'])) {
                $result['has_complex_expression'] = true;
            }
            if (isset($node['left']) && is_array($node['left'])) {
                self::walkNode($node['left'], $result);
            }
            if (isset($node['right']) && is_array($node['right'])) {
                self::walkNode($node['right'], $result);
            }
        } elseif ($type === 'logical_or' || $type === 'logical_and' || $type === 'comparison') {
            $result['has_complex_expression'] = true;
            if (isset($node['left']) && is_array($node['left'])) {
                self::walkNode($node['left'], $result);
            }
            if (isset($node['right']) && is_array($node['right'])) {
                self::walkNode($node['right'], $result);
            }
        } elseif ($type === 'unary_op') {
            if (isset($node['expr']) && is_array($node['expr'])) {
                self::walkNode($node['expr'], $result);
            }
        } elseif ($type === 'logical_not') {
            $result['has_complex_expression'] = true;
            if (isset($node['expr']) && is_array($node['expr'])) {
                self::walkNode($node['expr'], $result);
            }
        } elseif ($type === 'ternary') {
            $result['has_complex_expression'] = true;
            if (isset($node['condition']) && is_array($node['condition'])) {
                self::walkNode($node['condition'], $result);
            }
            if (isset($node['true_expr']) && is_array($node['true_expr'])) {
                self::walkNode($node['true_expr'], $result);
            }
            if (isset($node['false_expr']) && is_array($node['false_expr'])) {
                self::walkNode($node['false_expr'], $result);
            }
        } elseif ($type === 'array') {
            if (!empty($node['items'])) {
                foreach ($node['items'] as $item) {
                    if (is_array($item)) self::walkNode($item, $result);
                }
            }
        } elseif ($type === 'dict') {
            if (!empty($node['pairs'])) {
                foreach ($node['pairs'] as $pair) {
                    if (isset($pair['key']) && is_array($pair['key'])) {
                        self::walkNode($pair['key'], $result);
                    }
                    if (isset($pair['value']) && is_array($pair['value'])) {
                        self::walkNode($pair['value'], $result);
                    }
                }
            }
        } elseif ($type === 'template') {
            if (!empty($node['nodes'])) {
                foreach ($node['nodes'] as $n) {
                    if (is_array($n)) self::walkNode($n, $result);
                }
            }
        }
    }

    private static function isLiteralString(array $node): bool {
        return ($node['type'] ?? '') === 'literal' && ($node['subtype'] ?? '') === 'string';
    }

    private static function calcAstDepth(array $node): int {
        $type = $node['type'] ?? '';
        $maxChild = 0;

        $children = [];
        if (isset($node['expression'])) $children[] = $node['expression'];
        if (isset($node['value'])) $children[] = $node['value'];
        if (isset($node['condition'])) $children[] = $node['condition'];
        if (isset($node['left'])) $children[] = $node['left'];
        if (isset($node['right'])) $children[] = $node['right'];
        if (isset($node['iterable'])) $children[] = $node['iterable'];
        if (isset($node['object'])) $children[] = $node['object'];
        if (isset($node['index'])) $children[] = $node['index'];
        if (isset($node['expr'])) $children[] = $node['expr'];
        if (isset($node['true_expr'])) $children[] = $node['true_expr'];
        if (isset($node['false_expr'])) $children[] = $node['false_expr'];
        if (!empty($node['nodes'])) $children = array_merge($children, $node['nodes']);
        if (!empty($node['items'])) $children = array_merge($children, $node['items']);
        if (!empty($node['arguments'])) $children = array_merge($children, $node['arguments']);
        if (!empty($node['filters'])) {
            foreach ($node['filters'] as $f) {
                if (!empty($f['arguments'])) {
                    $children = array_merge($children, $f['arguments']);
                }
            }
        }
        if (!empty($node['pairs'])) {
            foreach ($node['pairs'] as $p) {
                if (isset($p['key'])) $children[] = $p['key'];
                if (isset($p['value'])) $children[] = $p['value'];
            }
        }

        foreach ($children as $child) {
            if (is_array($child)) {
                $d = self::calcAstDepth($child);
                if ($d > $maxChild) $maxChild = $d;
            }
        }

        return $maxChild + 1;
    }

    private static function detectEnginesFromAst(array $ast, string $input): array {
        $engines = [];

        $hasOutput = false;
        $hasStmt = false;
        $hasComment = false;

        if (!empty($ast['nodes'])) {
            foreach ($ast['nodes'] as $node) {
                $t = $node['type'] ?? '';
                if ($t === 'output') $hasOutput = true;
                if ($t === 'if_stmt' || $t === 'for_stmt' || $t === 'set_stmt' || $t === 'generic_stmt') $hasStmt = true;
            }
        }

        if ($hasOutput || $hasStmt) {
            if (strpos($input, '{{') !== false && strpos($input, '}}') !== false) {
                $engines['twig_jinja2'] = [
                    'engine' => 'twig_jinja2',
                    'name' => 'Twig/Jinja2',
                    'danger_level' => 4,
                    'expression_count' => 0,
                    'source' => 'ast',
                ];
            }
        }

        if (preg_match('/\$\{.+?\}/s', $input)) {
            $engines['freemarker'] = [
                'engine' => 'freemarker',
                'name' => 'Freemarker',
                'danger_level' => 4,
                'expression_count' => 0,
                'source' => 'ast',
            ];
        }

        if (preg_match('/\$[a-zA-Z_]\w*(?:\.\w+)*/', $input) && preg_match('/#(if|foreach|set)\b/i', $input)) {
            $engines['velocity'] = [
                'engine' => 'velocity',
                'name' => 'Velocity',
                'danger_level' => 4,
                'expression_count' => 0,
                'source' => 'ast',
            ];
        }

        if (preg_match('/<\?[=php]/i', $input)) {
            $engines['php_template'] = [
                'engine' => 'php_template',
                'name' => 'PHP Template',
                'danger_level' => 5,
                'expression_count' => 0,
                'source' => 'ast',
            ];
        }

        return $engines;
    }

    private static function summarizeAst(array $ast): array {
        $summary = [
            'node_count' => 0,
            'output_count' => 0,
            'statement_count' => 0,
            'function_calls' => 0,
            'filter_expressions' => 0,
            'max_depth' => 0,
        ];

        self::countNodes($ast, $summary);
        $summary['max_depth'] = self::calcAstDepth($ast);

        return $summary;
    }

    private static function countNodes(array $node, array &$summary) {
        $summary['node_count']++;
        $type = $node['type'] ?? '';

        if ($type === 'output') $summary['output_count']++;
        if (in_array($type, ['if_stmt', 'for_stmt', 'set_stmt', 'generic_stmt'])) $summary['statement_count']++;
        if ($type === 'function_call') $summary['function_calls']++;
        if ($type === 'filter_expression') $summary['filter_expressions']++;

        if (!empty($node['nodes'])) {
            foreach ($node['nodes'] as $n) {
                if (is_array($n)) self::countNodes($n, $summary);
            }
        }
        if (isset($node['expression']) && is_array($node['expression'])) {
            self::countNodes($node['expression'], $summary);
        }
        if (isset($node['value']) && is_array($node['value'])) {
            self::countNodes($node['value'], $summary);
        }
        if (isset($node['condition']) && is_array($node['condition'])) {
            self::countNodes($node['condition'], $summary);
        }
        if (isset($node['left']) && is_array($node['left'])) {
            self::countNodes($node['left'], $summary);
        }
        if (isset($node['right']) && is_array($node['right'])) {
            self::countNodes($node['right'], $summary);
        }
        if (isset($node['object']) && is_array($node['object'])) {
            self::countNodes($node['object'], $summary);
        }
        if (isset($node['index']) && is_array($node['index'])) {
            self::countNodes($node['index'], $summary);
        }
        if (!empty($node['arguments'])) {
            foreach ($node['arguments'] as $a) {
                if (is_array($a)) self::countNodes($a, $summary);
            }
        }
        if (!empty($node['items'])) {
            foreach ($node['items'] as $item) {
                if (is_array($item)) self::countNodes($item, $summary);
            }
        }
    }

    private static function extractExpressionsFromAst(array $ast, string $input, string $source): array {
        $expressions = [];
        if (empty($ast['nodes'])) return $expressions;

        foreach ($ast['nodes'] as $node) {
            $type = $node['type'] ?? '';
            if ($type === 'output') {
                $start = $node['start_pos'] ?? 0;
                $fullMatch = '';
                $endPos = strpos($input, '}}', $start);
                if ($endPos !== false) {
                    $fullMatch = substr($input, $start, $endPos - $start + 2);
                }
                $innerContent = self::exprToString($node['expression'] ?? null);

                $dangerousFilters = [];
                if (isset($node['expression']) && $node['expression']['type'] === 'filter_expression') {
                    foreach ($node['expression']['filters'] as $f) {
                        $fn = strtolower($f['name'] ?? '');
                        if (isset(self::$dangerousFilters[$fn])) {
                            $dangerousFilters[] = [
                                'name' => $fn,
                                'level' => self::$dangerousFilters[$fn],
                            ];
                        }
                    }
                }

                $expressions[] = [
                    'engine' => 'twig_jinja2',
                    'engine_name' => 'Twig/Jinja2',
                    'type' => 'output',
                    'full_match' => $fullMatch,
                    'inner_content' => $innerContent,
                    'offset' => $start,
                    'depth' => self::calcAstDepth($node),
                    'source' => $source,
                    'has_dangerous_filter' => !empty($dangerousFilters),
                    'dangerous_filters' => $dangerousFilters,
                ];
            }
        }

        return $expressions;
    }

    private static function exprToString(?array $expr): string {
        if ($expr === null) return '';
        $type = $expr['type'] ?? '';

        if ($type === 'literal') {
            $subtype = $expr['subtype'] ?? '';
            if ($subtype === 'string') return '"' . $expr['value'] . '"';
            return (string)($expr['value'] ?? '');
        }
        if ($type === 'identifier') {
            return $expr['name'] ?? '';
        }
        if ($type === 'attribute_access') {
            return self::exprToString($expr['object'] ?? null) . '.' . ($expr['attribute'] ?? '');
        }
        if ($type === 'index_access') {
            return self::exprToString($expr['object'] ?? null) . '[' . self::exprToString($expr['index'] ?? null) . ']';
        }
        if ($type === 'function_call') {
            $args = [];
            if (!empty($expr['arguments'])) {
                foreach ($expr['arguments'] as $a) {
                    $args[] = self::exprToString($a);
                }
            }
            return ($expr['name'] ?? '') . '(' . implode(', ', $args) . ')';
        }
        if ($type === 'filter_expression') {
            $s = self::exprToString($expr['value'] ?? null);
            if (!empty($expr['filters'])) {
                foreach ($expr['filters'] as $f) {
                    $s .= '|' . ($f['name'] ?? '');
                }
            }
            return $s;
        }
        if ($type === 'binary_op') {
            return self::exprToString($expr['left'] ?? null) . ' ' . ($expr['op'] ?? '') . ' ' . self::exprToString($expr['right'] ?? null);
        }
        if ($type === 'unary_op') {
            return ($expr['op'] ?? '') . self::exprToString($expr['expr'] ?? null);
        }

        return '';
    }

    // ==================== Regex Fallback Helpers ====================

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

    private static function detectDangerousFiltersRegex(string $content): array {
        $found = [];
        if (preg_match_all('/\|\s*([a-zA-Z_]\w*)/', $content, $filterMatches)) {
            foreach ($filterMatches[1] as $filterName) {
                $filterLower = strtolower($filterName);
                if (isset(self::$dangerousFilters[$filterLower])) {
                    $key = 'filter_' . $filterLower;
                    if (!isset($found[$key])) {
                        $found[$key] = [
                            'name' => $filterName,
                            'level' => self::$dangerousFilters[$filterLower],
                        ];
                    }
                }
            }
        }
        return array_values($found);
    }
}
