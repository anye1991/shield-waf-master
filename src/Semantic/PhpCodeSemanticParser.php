<?php
/**
 * PHP 代码语义解析器
 * 职责：基于 PHP 内置 tokenizer 进行词法分析，从 token 层面理解 PHP 代码结构，
 *       检测危险函数调用、回调型 WebShell、可变函数、输入输出链、混淆特征等。
 */
defined('ABSPATH') || exit;

class PhpCodeSemanticParser {

    /** 高危函数（命令执行类） */
    private static $high_risk_functions = [
        'system', 'exec', 'shell_exec', 'passthru', 'pcntl_exec', 'popen', 'proc_open',
    ];

    /** 中危函数（代码执行类） */
    private static $medium_risk_functions = [
        'eval', 'assert', 'create_function', 'call_user_func', 'call_user_func_array',
        'array_map', 'array_walk', 'array_filter',
    ];

    /** 文件操作类函数 */
    private static $file_functions = [
        'file_get_contents', 'file_put_contents', 'fopen', 'fwrite', 'readfile', 'fpassthru',
        'include', 'include_once', 'require', 'require_once',
    ];

    /** 信息收集类函数 */
    private static $info_functions = [
        'phpinfo', 'getenv', 'posix_getpwuid', 'posix_uname',
    ];

    /** 数据库操作类函数 */
    private static $db_functions = [
        'mysql_query', 'mysqli_query', 'pg_query', 'sqlite_query',
    ];

    /** 回调型危险函数（第一个或某个参数是回调） */
    private static $callback_functions = [
        'array_map' => 0,
        'array_walk' => 0,
        'array_filter' => 1,
        'call_user_func' => 0,
        'call_user_func_array' => 0,
        'usort' => 1,
        'uasort' => 1,
        'uksort' => 1,
        'array_reduce' => 1,
        'array_walk_recursive' => 0,
    ];

    /** 超全局变量 */
    private static $superglobals = [
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES', '$_ENV', '$_SESSION',
    ];

    /** 解码/混淆函数 */
    private static $decode_functions = [
        'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13',
        'hex2bin', 'convert_uudecode', 'base64_encode', 'pack', 'unpack',
    ];

    /**
     * 分析 PHP 代码
     *
     * @param string $code PHP 代码字符串
     * @return array
     */
    public static function analyze(string $code): array {
        $result = self::initResult();

        if ($code === '') {
            return $result;
        }

        $useTokenizer = function_exists('token_get_all');
        if ($useTokenizer) {
            $result['parser_used'] = 'tokenizer';
            try {
                self::analyzeWithTokenizer($code, $result);
            } catch (Throwable $e) {
                $result['parser_used'] = 'regex';
                self::analyzeWithRegex($code, $result);
            }
        } else {
            $result['parser_used'] = 'regex';
            self::analyzeWithRegex($code, $result);
        }

        self::calculateScore($result);

        return $result;
    }

    /**
     * 初始化结果数组
     */
    private static function initResult(): array {
        return [
            'detected' => false,
            'score' => 0,
            'parser_used' => 'tokenizer',
            'total_tokens' => 0,
            'dangerous_functions' => [],
            'input_sinks' => [],
            'variable_functions' => [],
            'callback_patterns' => [],
            'obfuscation_level' => 0,
            'obfuscation_indicators' => [],
            'has_eval' => false,
            'has_command_exec' => false,
            'has_file_operation' => false,
            'has_superglobal_in_danger' => false,
            'code_complexity' => 0,
            'string_to_code_ratio' => 0.0,
            'indicators' => [],
        ];
    }

    /**
     * 使用 tokenizer 分析
     */
    private static function analyzeWithTokenizer(string $code, array &$result): void {
        $wrapped = false;
        if (strpos($code, '<?php') === false && strpos($code, '<?') === false) {
            $code = '<?php ' . $code;
            $wrapped = true;
        }

        $tokens = @token_get_all($code);
        if ($tokens === false || empty($tokens)) {
            self::analyzeWithRegex($code, $result);
            return;
        }

        $result['total_tokens'] = count($tokens);

        $tokenCount = count($tokens);
        $nestingLevel = 0;
        $maxNesting = 0;
        $functionCount = 0;
        $stringTotalLen = 0;
        $codeLen = strlen($code);
        $concatCount = 0;
        $chrCount = 0;
        $decodeFuncCount = 0;
        $hexStrings = 0;
        $singleLetterVars = 0;
        $totalVars = 0;
        $evalNestedDecode = false;

        $assignedVariables = [];
        $currentVariable = null;
        $inAssignment = false;
        $assignmentHasSuperglobal = false;

        for ($i = 0; $i < $tokenCount; $i++) {
            $token = $tokens[$i];
            $tokenType = is_array($token) ? $token[0] : null;
            $tokenValue = is_array($token) ? $token[1] : $token;
            $tokenLine = is_array($token) ? ($token[2] ?? 0) : 0;

            if ($wrapped && $tokenLine > 0) {
                $tokenLine = $tokenLine - 1;
            }

            if ($tokenType === T_CURLY_OPEN || $tokenValue === '{') {
                $nestingLevel++;
                if ($nestingLevel > $maxNesting) {
                    $maxNesting = $nestingLevel;
                }
                continue;
            }
            if ($tokenValue === '}') {
                $nestingLevel--;
                continue;
            }

            if ($tokenType === T_FUNCTION) {
                $functionCount++;
                continue;
            }

            if ($tokenType === T_CONSTANT_ENCAPSED_STRING) {
                $stringTotalLen += strlen($tokenValue);
                if (preg_match('/\\\\x[0-9a-fA-F]{2}/', $tokenValue)) {
                    $hexStrings++;
                }
                continue;
            }

            if ($tokenType === T_VARIABLE) {
                $totalVars++;
                $varName = $tokenValue;
                if (strlen($varName) === 2 && preg_match('/^\$[a-zA-Z]$/', $varName)) {
                    $singleLetterVars++;
                }
                $nextIdx = self::findNextNonEmptyTokenIndex($tokens, $i + 1);
                if ($nextIdx !== null) {
                    $nextToken = $tokens[$nextIdx];
                    $nextValue = is_array($nextToken) ? $nextToken[1] : $nextToken;
                    if ($nextValue === '(') {
                        $paramsInfo = self::extractFunctionParams($tokens, $nextIdx + 1);
                        $result['variable_functions'][] = [
                            'variable' => $varName,
                            'line' => $tokenLine,
                            'has_superglobal' => $paramsInfo['has_superglobal'],
                        ];
                        if ($paramsInfo['has_superglobal']) {
                            $result['has_superglobal_in_danger'] = true;
                            $result['input_sinks'][] = [
                                'function' => $varName . '()',
                                'line' => $tokenLine,
                                'source' => 'superglobal',
                                'type' => 'variable_function',
                            ];
                        }
                    }
                }
                continue;
            }

            if ($tokenValue === '.') {
                $concatCount++;
                continue;
            }

            if ($tokenType === T_STRING) {
                $funcName = strtolower($tokenValue);

                if ($funcName === 'chr') {
                    $nextNonEmpty = self::findNextNonEmptyToken($tokens, $i + 1);
                    if ($nextNonEmpty !== null && $nextNonEmpty === '(') {
                        $chrCount++;
                    }
                }

                if (in_array($funcName, self::$decode_functions, true)) {
                    $nextNonEmpty = self::findNextNonEmptyToken($tokens, $i + 1);
                    if ($nextNonEmpty !== null && $nextNonEmpty === '(') {
                        $decodeFuncCount++;
                    }
                }

                $nextIdx = self::findNextNonEmptyTokenIndex($tokens, $i + 1);
                if ($nextIdx !== null) {
                    $nextToken = $tokens[$nextIdx];
                    $nextValue = is_array($nextToken) ? $nextToken[1] : $nextToken;

                    if ($nextValue === '(') {
                        $severity = self::getFunctionSeverity($funcName);
                        if ($severity !== null) {
                            $result['dangerous_functions'][] = [
                                'name' => $funcName,
                                'line' => $tokenLine,
                                'severity' => $severity,
                            ];

                            if ($funcName === 'eval' || $funcName === 'assert') {
                                $result['has_eval'] = true;
                            }
                            if (in_array($funcName, self::$high_risk_functions, true)) {
                                $result['has_command_exec'] = true;
                            }
                            if (in_array($funcName, self::$file_functions, true)) {
                                $result['has_file_operation'] = true;
                            }

                            $paramsInfo = self::extractFunctionParams($tokens, $nextIdx + 1);
                            $hasSuperglobal = $paramsInfo['has_superglobal'];
                            $paramText = $paramsInfo['text'];

                            if ($hasSuperglobal && ($severity === 'high' || $severity === 'medium')) {
                                $result['has_superglobal_in_danger'] = true;
                                $result['input_sinks'][] = [
                                    'function' => $funcName,
                                    'line' => $tokenLine,
                                    'source' => 'superglobal',
                                    'param' => $paramText,
                                ];
                            }

                            if ($funcName === 'eval' || $funcName === 'assert') {
                                if (self::paramsContainDecodeFunc($tokens, $nextIdx + 1)) {
                                    $evalNestedDecode = true;
                                }
                            }

                            if (isset(self::$callback_functions[$funcName])) {
                                $callbackParamIdx = self::$callback_functions[$funcName];
                                $callbackIsDangerous = self::checkCallbackParam(
                                    $tokens,
                                    $nextIdx + 1,
                                    $callbackParamIdx,
                                    $hasSuperglobal
                                );
                                if ($callbackIsDangerous) {
                                    $result['callback_patterns'][] = [
                                        'function' => $funcName,
                                        'line' => $tokenLine,
                                        'type' => 'callback_webshell',
                                    ];
                                }
                            }
                        }
                    }
                }
                continue;
            }

            if ($tokenType === T_EVAL) {
                $result['has_eval'] = true;
                $result['dangerous_functions'][] = [
                    'name' => 'eval',
                    'line' => $tokenLine,
                    'severity' => 'medium',
                ];
                $parenIdx = self::findNextNonEmptyTokenIndex($tokens, $i + 1);
                if ($parenIdx !== null) {
                    $parenToken = $tokens[$parenIdx];
                    $parenValue = is_array($parenToken) ? $parenToken[1] : $parenToken;
                    if ($parenValue === '(') {
                        $paramsInfo = self::extractFunctionParams($tokens, $parenIdx + 1);
                        if ($paramsInfo['has_superglobal']) {
                            $result['has_superglobal_in_danger'] = true;
                            $result['input_sinks'][] = [
                                'function' => 'eval',
                                'line' => $tokenLine,
                                'source' => 'superglobal',
                                'param' => $paramsInfo['text'],
                            ];
                        }
                        if (self::paramsContainDecodeFunc($tokens, $parenIdx + 1)) {
                            $evalNestedDecode = true;
                        }
                    }
                }
                continue;
            }

            if ($tokenType === T_INCLUDE || $tokenType === T_INCLUDE_ONCE
                || $tokenType === T_REQUIRE || $tokenType === T_REQUIRE_ONCE) {
                $includeNames = [
                    T_INCLUDE => 'include',
                    T_INCLUDE_ONCE => 'include_once',
                    T_REQUIRE => 'require',
                    T_REQUIRE_ONCE => 'require_once',
                ];
                $incName = $includeNames[$tokenType];
                $result['has_file_operation'] = true;
                $result['dangerous_functions'][] = [
                    'name' => $incName,
                    'line' => $tokenLine,
                    'severity' => 'low',
                ];
                continue;
            }

            if ($tokenValue === '$') {
                $nextIdx = self::findNextNonEmptyTokenIndex($tokens, $i + 1);
                if ($nextIdx !== null) {
                    $nextToken = $tokens[$nextIdx];
                    $nextValue = is_array($nextToken) ? $nextToken[1] : $nextToken;
                    if ($nextValue === '(') {
                        $paramsInfo = self::extractFunctionParams($tokens, $nextIdx + 1);
                        $result['variable_functions'][] = [
                            'variable' => '$(...)',
                            'line' => $tokenLine,
                            'has_superglobal' => $paramsInfo['has_superglobal'],
                            'type' => 'variable_function',
                        ];
                        if ($paramsInfo['has_superglobal']) {
                            $result['has_superglobal_in_danger'] = true;
                        }
                    }
                }
                continue;
            }
        }

        $result['code_complexity'] = $maxNesting + $functionCount;
        $result['string_to_code_ratio'] = $codeLen > 0 ? ($stringTotalLen / $codeLen) : 0.0;

        $obfuscationIndicators = [];
        $obfuscationScore = 0;

        if ($concatCount > 5) {
            $obfuscationScore += 15;
            $obfuscationIndicators[] = 'string_concat:' . $concatCount;
        }

        if ($chrCount > 3) {
            $obfuscationScore += 20;
            $obfuscationIndicators[] = 'chr_calls:' . $chrCount;
        }

        if ($decodeFuncCount > 0) {
            $obfuscationScore += min(30, $decodeFuncCount * 10);
            $obfuscationIndicators[] = 'decode_functions:' . $decodeFuncCount;
        }

        if ($hexStrings > 2) {
            $obfuscationScore += 18;
            $obfuscationIndicators[] = 'hex_strings:' . $hexStrings;
        }

        if ($totalVars > 5) {
            $singleLetterRatio = $singleLetterVars / $totalVars;
            if ($singleLetterRatio > 0.6) {
                $obfuscationScore += 12;
                $obfuscationIndicators[] = 'single_letter_vars:' . round($singleLetterRatio, 2);
            }
        }

        if ($evalNestedDecode) {
            $obfuscationScore += 25;
            $obfuscationIndicators[] = 'eval_nested_decode';
        }

        if ($result['string_to_code_ratio'] > 0.5) {
            $obfuscationScore += 10;
            $obfuscationIndicators[] = 'high_string_ratio:' . round($result['string_to_code_ratio'], 2);
        }

        $result['obfuscation_level'] = min(100, $obfuscationScore);
        $result['obfuscation_indicators'] = $obfuscationIndicators;

        if ($result['has_eval']) $result['indicators'][] = 'has_eval';
        if ($result['has_command_exec']) $result['indicators'][] = 'has_command_exec';
        if ($result['has_file_operation']) $result['indicators'][] = 'has_file_operation';
        if ($result['has_superglobal_in_danger']) $result['indicators'][] = 'superglobal_in_danger';
    }

    /**
     * 使用正则降级分析
     */
    private static function analyzeWithRegex(string $code, array &$result): void {
        $result['parser_used'] = 'regex';
        $lines = explode("\n", $code);
        $lineCount = count($lines);

        $allFuncs = array_merge(
            self::$high_risk_functions,
            self::$medium_risk_functions,
            self::$file_functions,
            self::$info_functions,
            self::$db_functions
        );

        foreach ($allFuncs as $func) {
            if (preg_match_all('/\b' . preg_quote($func, '/') . '\s*\(/i', $code, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $lineNum = $match[1] > 0 ? substr_count($code, "\n", 0, $match[1]) + 1 : 1;
                    $severity = self::getFunctionSeverity($func);
                    $result['dangerous_functions'][] = [
                        'name' => $func,
                        'line' => $lineNum,
                        'severity' => $severity,
                    ];
                    if ($func === 'eval' || $func === 'assert') {
                        $result['has_eval'] = true;
                    }
                    if (in_array($func, self::$high_risk_functions, true)) {
                        $result['has_command_exec'] = true;
                    }
                    if (in_array($func, self::$file_functions, true)) {
                        $result['has_file_operation'] = true;
                    }
                }
            }
        }

        $superglobalPattern = '\$_?(GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV|SESSION)';
        foreach ($result['dangerous_functions'] as $df) {
            $func = $df['name'];
            $severity = $df['severity'];
            $pattern = '/' . preg_quote($func, '/') . '\s*\([^)]*' . $superglobalPattern . '/i';
            if (preg_match($pattern, $code)) {
                if ($severity === 'high' || $severity === 'medium') {
                    $result['has_superglobal_in_danger'] = true;
                    $result['input_sinks'][] = [
                        'function' => $func,
                        'line' => $df['line'],
                        'source' => 'superglobal',
                    ];
                }
            }
        }

        if (preg_match('/\\$[a-zA-Z_]\w*\s*\(/', $code)) {
            $result['variable_functions'][] = [
                'variable' => 'detected',
                'line' => 0,
                'has_superglobal' => (bool)preg_match('/\\$[a-zA-Z_]\w*\s*\([^)]*\$_?(GET|POST|REQUEST)/', $code),
            ];
            if ($result['variable_functions'][0]['has_superglobal']) {
                $result['has_superglobal_in_danger'] = true;
            }
        }

        foreach (array_keys(self::$callback_functions) as $cbFunc) {
            $pattern = '/' . preg_quote($cbFunc, '/') . '\s*\([^)]*[\'"](eval|assert|system|exec)[\'"]/i';
            if (preg_match($pattern, $code)) {
                $result['callback_patterns'][] = [
                    'function' => $cbFunc,
                    'line' => 0,
                    'type' => 'callback_webshell',
                ];
            }
            $pattern2 = '/' . preg_quote($cbFunc, '/') . '\s*\([^)]*\$_?(GET|POST|REQUEST)/i';
            if (preg_match($pattern2, $code)) {
                $result['callback_patterns'][] = [
                    'function' => $cbFunc,
                    'line' => 0,
                    'type' => 'callback_superglobal',
                ];
            }
        }

        $obfuscationIndicators = [];
        $obfuscationScore = 0;

        $concatCount = substr_count($code, '.');
        if ($concatCount > 10) {
            $obfuscationScore += 10;
            $obfuscationIndicators[] = 'string_concat:' . $concatCount;
        }

        if (preg_match_all('/\bchr\s*\(/i', $code, $m)) {
            $chrCount = count($m[0]);
            if ($chrCount > 3) {
                $obfuscationScore += 20;
                $obfuscationIndicators[] = 'chr_calls:' . $chrCount;
            }
        }

        $decodeCount = 0;
        foreach (self::$decode_functions as $df) {
            if (preg_match_all('/\b' . preg_quote($df, '/') . '\s*\(/i', $code, $m)) {
                $decodeCount += count($m[0]);
            }
        }
        if ($decodeCount > 0) {
            $obfuscationScore += min(30, $decodeCount * 10);
            $obfuscationIndicators[] = 'decode_functions:' . $decodeCount;
        }

        $hexCount = preg_match_all('/\\\\x[0-9a-fA-F]{2}/', $code);
        if ($hexCount > 2) {
            $obfuscationScore += 18;
            $obfuscationIndicators[] = 'hex_strings:' . $hexCount;
        }

        if (preg_match('/eval\s*\(\s*(base64_decode|gzinflate|str_rot13)/i', $code)) {
            $obfuscationScore += 25;
            $obfuscationIndicators[] = 'eval_nested_decode';
        }

        $result['obfuscation_level'] = min(100, $obfuscationScore);
        $result['obfuscation_indicators'] = $obfuscationIndicators;

        $codeLen = strlen($code);
        $stringLen = 0;
        if (preg_match_all('/[\'"][^\'"]*[\'"]/', $code, $strMatches)) {
            foreach ($strMatches[0] as $s) {
                $stringLen += strlen($s);
            }
        }
        $result['string_to_code_ratio'] = $codeLen > 0 ? ($stringLen / $codeLen) : 0.0;

        $nesting = 0;
        $maxNest = 0;
        foreach (str_split($code) as $ch) {
            if ($ch === '{') {
                $nesting++;
                if ($nesting > $maxNest) $maxNest = $nesting;
            } elseif ($ch === '}') {
                $nesting--;
            }
        }
        $funcDefCount = preg_match_all('/\bfunction\s+\w+\s*\(/i', $code);
        $result['code_complexity'] = $maxNest + $funcDefCount;

        if ($result['has_eval']) $result['indicators'][] = 'has_eval';
        if ($result['has_command_exec']) $result['indicators'][] = 'has_command_exec';
        if ($result['has_file_operation']) $result['indicators'][] = 'has_file_operation';
        if ($result['has_superglobal_in_danger']) $result['indicators'][] = 'superglobal_in_danger';
    }

    /**
     * 获取函数的危险等级
     */
    private static function getFunctionSeverity(string $funcName): ?string {
        $funcName = strtolower($funcName);
        if (in_array($funcName, self::$high_risk_functions, true)) {
            return 'high';
        }
        if (in_array($funcName, self::$medium_risk_functions, true)) {
            return 'medium';
        }
        if (in_array($funcName, self::$file_functions, true)) {
            return 'low';
        }
        if (in_array($funcName, self::$info_functions, true)) {
            return 'info';
        }
        if (in_array($funcName, self::$db_functions, true)) {
            return 'db';
        }
        return null;
    }

    /**
     * 找到下一个非空白的 token 值
     */
    private static function findNextNonEmptyToken(array $tokens, int $startIdx) {
        for ($i = $startIdx; $i < count($tokens); $i++) {
            $token = $tokens[$i];
            $value = is_array($token) ? $token[1] : $token;
            $type = is_array($token) ? $token[0] : null;
            if ($type === T_WHITESPACE || $type === T_COMMENT || $type === T_DOC_COMMENT) {
                continue;
            }
            return $value;
        }
        return null;
    }

    /**
     * 找到下一个非空白的 token 索引
     */
    private static function findNextNonEmptyTokenIndex(array $tokens, int $startIdx): ?int {
        for ($i = $startIdx; $i < count($tokens); $i++) {
            $token = $tokens[$i];
            $type = is_array($token) ? $token[0] : null;
            if ($type === T_WHITESPACE || $type === T_COMMENT || $type === T_DOC_COMMENT) {
                continue;
            }
            return $i;
        }
        return null;
    }

    /**
     * 提取函数参数信息
     */
    private static function extractFunctionParams(array $tokens, int $startIdx): array {
        $depth = 1;
        $hasSuperglobal = false;
        $text = '';
        $i = $startIdx;
        $tokenCount = count($tokens);

        while ($i < $tokenCount && $depth > 0) {
            $token = $tokens[$i];
            $value = is_array($token) ? $token[1] : $token;
            $type = is_array($token) ? $token[0] : null;

            if ($value === '(') {
                $depth++;
            } elseif ($value === ')') {
                $depth--;
                if ($depth === 0) break;
            }

            if ($type === T_VARIABLE) {
                $varName = $value;
                if (self::isSuperglobal($varName)) {
                    $hasSuperglobal = true;
                }
            }

            if ($type !== T_WHITESPACE) {
                $text .= $value;
            }

            $i++;
        }

        return [
            'has_superglobal' => $hasSuperglobal,
            'text' => $text,
            'end_index' => $i,
        ];
    }

    /**
     * 检查参数中是否包含解码函数
     */
    private static function paramsContainDecodeFunc(array $tokens, int $startIdx): bool {
        $depth = 1;
        $i = $startIdx;
        $tokenCount = count($tokens);

        while ($i < $tokenCount && $depth > 0) {
            $token = $tokens[$i];
            $value = is_array($token) ? $token[1] : $token;
            $type = is_array($token) ? $token[0] : null;

            if ($value === '(') {
                $depth++;
            } elseif ($value === ')') {
                $depth--;
                if ($depth === 0) break;
            }

            if ($type === T_STRING) {
                if (in_array(strtolower($value), self::$decode_functions, true)) {
                    return true;
                }
            }

            $i++;
        }

        return false;
    }

    /**
     * 检查回调参数是否危险
     */
    private static function checkCallbackParam(
        array $tokens,
        int $startIdx,
        int $targetParamIdx,
        bool &$hasSuperglobal
    ): bool {
        $depth = 1;
        $currentParamIdx = 0;
        $paramBuffer = '';
        $i = $startIdx;
        $tokenCount = count($tokens);
        $foundDangerousCallback = false;
        $paramHasSuperglobal = false;

        while ($i < $tokenCount && $depth > 0) {
            $token = $tokens[$i];
            $value = is_array($token) ? $token[1] : $token;
            $type = is_array($token) ? $token[0] : null;

            if ($value === '(') {
                $depth++;
                if ($depth > 1) {
                    $paramBuffer .= $value;
                }
            } elseif ($value === ')') {
                $depth--;
                if ($depth === 0) {
                    if ($currentParamIdx === $targetParamIdx) {
                        $foundDangerousCallback = self::isDangerousCallbackParam(
                            $paramBuffer,
                            $tokens,
                            $startIdx,
                            $i - 1,
                            $paramHasSuperglobal
                        );
                    }
                    break;
                } else {
                    $paramBuffer .= $value;
                }
            } elseif ($value === ',' && $depth === 1) {
                if ($currentParamIdx === $targetParamIdx) {
                    $foundDangerousCallback = self::isDangerousCallbackParam(
                        $paramBuffer,
                        $tokens,
                        $startIdx,
                        $i - 1,
                        $paramHasSuperglobal
                    );
                }
                $currentParamIdx++;
                $paramBuffer = '';
                $paramHasSuperglobal = false;
            } else {
                if ($depth === 1) {
                    $paramBuffer .= $value;
                }
                if ($type === T_VARIABLE && self::isSuperglobal($value)) {
                    $paramHasSuperglobal = true;
                    $hasSuperglobal = true;
                }
            }

            $i++;
        }

        return $foundDangerousCallback;
    }

    /**
     * 判断回调参数是否危险
     */
    private static function isDangerousCallbackParam(
        string $paramStr,
        array $tokens,
        int $startIdx,
        int $endIdx,
        bool $hasSuperglobal
    ): bool {
        $clean = trim($paramStr);
        $cleanLower = strtolower($clean);

        $dangerousCallbacks = ['eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru'];
        foreach ($dangerousCallbacks as $dc) {
            if ($cleanLower === "'" . $dc . "'" || $cleanLower === '"' . $dc . '"') {
                return true;
            }
        }

        if ($hasSuperglobal) {
            return true;
        }

        return false;
    }

    /**
     * 判断是否是超全局变量
     */
    private static function isSuperglobal(string $varName): bool {
        static $superglobalSet = null;
        if ($superglobalSet === null) {
            $superglobalSet = array_fill_keys(self::$superglobals, true);
        }
        return isset($superglobalSet[$varName]);
    }

    /**
     * 计算最终评分
     */
    private static function calculateScore(array &$result): void {
        $score = 0;
        $attackVectors = 0;

        if ($result['has_eval'] && $result['has_superglobal_in_danger']) {
            $score += 50;
            $attackVectors++;
        } elseif ($result['has_eval']) {
            $score += 20;
            $attackVectors++;
        }

        $highRiskCount = 0;
        $highRiskWithSuperglobal = false;
        foreach ($result['dangerous_functions'] as $df) {
            if ($df['severity'] === 'high') {
                $highRiskCount++;
                foreach ($result['input_sinks'] as $sink) {
                    if ($sink['function'] === $df['name']) {
                        $highRiskWithSuperglobal = true;
                        break 2;
                    }
                }
            }
        }
        if ($highRiskCount > 0) {
            $score += $highRiskCount * 25;
            $attackVectors++;
            if ($highRiskWithSuperglobal) {
                $score += 25;
                $attackVectors++;
            }
        }

        if (!empty($result['variable_functions'])) {
            $varFuncScore = 0;
            foreach ($result['variable_functions'] as $vf) {
                if (!empty($vf['has_superglobal'])) {
                    $varFuncScore = 40;
                    $attackVectors++;
                    break;
                }
            }
            if ($varFuncScore === 0) {
                $varFuncScore = 15;
            }
            $score += $varFuncScore;
        }

        if (!empty($result['callback_patterns'])) {
            $score += 45;
            $attackVectors++;
        }

        $hasEval = false;
        $hasDecode = false;
        foreach ($result['dangerous_functions'] as $df) {
            if ($df['name'] === 'eval' || $df['name'] === 'assert') {
                $hasEval = true;
            }
        }
        foreach ($result['obfuscation_indicators'] as $ind) {
            if (strpos($ind, 'decode_functions') === 0 || strpos($ind, 'eval_nested_decode') === 0) {
                $hasDecode = true;
            }
        }
        if ($hasEval && $hasDecode) {
            $score += 35;
            $attackVectors++;
        }

        if ($result['obfuscation_level'] > 70) {
            $score += 20;
        }

        if ($attackVectors >= 3) {
            $score += 15;
        }

        $result['score'] = max(0, min(100, (int)$score));
        $result['detected'] = $result['score'] >= 30;
    }
}
