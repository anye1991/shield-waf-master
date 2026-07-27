<?php
/**
 * 路径遍历语义解析器（AST版）
 * 职责：通过构建路径 AST（抽象语法树）真正理解路径结构，
 *       深度解析路径段、规范化各种编码/混淆变体，
 *       识别路径遍历攻击和敏感文件访问意图，
 *       而非简单的关键词匹配。
 */
defined('ABSPATH') || exit;

class PathTraversalSemanticParser {

    // ==================== Token Types ====================

    const TOKEN_SEGMENT       = 'SEGMENT';
    const TOKEN_SEPARATOR     = 'SEPARATOR';
    const TOKEN_PARENT        = 'PARENT';
    const TOKEN_CURRENT       = 'CURRENT';
    const TOKEN_ROOT          = 'ROOT';
    const TOKEN_WIN_DRIVE     = 'WIN_DRIVE';
    const TOKEN_UNC_PREFIX    = 'UNC_PREFIX';
    const TOKEN_ENCODED       = 'ENCODED';
    const TOKEN_NULL_BYTE     = 'NULL_BYTE';
    const TOKEN_EOF           = 'EOF';

    // ==================== Sensitive Files ====================

    private static $linuxSensitiveFiles = [
        '/etc/passwd'           => ['level' => 5, 'desc' => '系统用户文件'],
        '/etc/shadow'           => ['level' => 5, 'desc' => '系统密码哈希'],
        '/etc/sudoers'          => ['level' => 5, 'desc' => 'sudo配置'],
        '/root/.ssh/id_rsa'     => ['level' => 5, 'desc' => 'root私钥'],
        '/root/.bash_history'   => ['level' => 4, 'desc' => 'root历史命令'],
        '/proc/self/environ'    => ['level' => 4, 'desc' => '进程环境变量'],
        '/proc/self/cmdline'    => ['level' => 4, 'desc' => '进程命令行'],
        '/proc/version'         => ['level' => 3, 'desc' => '内核版本信息'],
        '/etc/hosts'            => ['level' => 3, 'desc' => '主机名配置'],
        '/etc/apache2/apache2.conf' => ['level' => 4, 'desc' => 'Apache配置'],
        '/etc/nginx/nginx.conf' => ['level' => 4, 'desc' => 'Nginx配置'],
        '/var/log/auth.log'     => ['level' => 3, 'desc' => '认证日志'],
        '/var/log/apache2/access.log' => ['level' => 3, 'desc' => 'Apache访问日志'],
    ];

    private static $windowsSensitiveFiles = [
        'C:\\Windows\\System32\\config\\SAM'     => ['level' => 5, 'desc' => 'SAM账户数据库'],
        'C:\\Windows\\System32\\config\\SYSTEM'  => ['level' => 5, 'desc' => '系统配置'],
        'C:\\Windows\\win.ini'                   => ['level' => 3, 'desc' => 'Windows配置'],
        'C:\\Windows\\System32\\drivers\\etc\\hosts' => ['level' => 3, 'desc' => '主机名配置'],
        'C:\\boot.ini'                           => ['level' => 3, 'desc' => '启动配置'],
    ];

    private static $webSensitiveFiles = [
        '.htaccess'            => ['level' => 4, 'desc' => 'Apache访问控制'],
        '.htpasswd'            => ['level' => 4, 'desc' => '用户认证文件'],
        'config.php'           => ['level' => 5, 'desc' => '应用配置文件'],
        'web.config'           => ['level' => 4, 'desc' => 'IIS配置'],
        'wp-config.php'        => ['level' => 5, 'desc' => 'WordPress配置'],
        'database.php'         => ['level' => 5, 'desc' => '数据库配置'],
        'settings.php'         => ['level' => 4, 'desc' => '设置文件'],
        '.env'                 => ['level' => 5, 'desc' => '环境变量文件'],
        'composer.json'        => ['level' => 3, 'desc' => '依赖配置'],
        'id_rsa'               => ['level' => 5, 'desc' => 'SSH私钥'],
        '.git/config'          => ['level' => 4, 'desc' => 'Git配置泄露'],
    ];

    private static $traversalPatterns = [
        '../'           => '标准回溯',
        '..\\'          => 'Windows回溯',
        '..%2f'         => 'URL编码斜杠',
        '..%5c'         => 'URL编码反斜杠',
        '%2e%2e%2f'     => '双重URL编码',
        '%2e%2e/'       => '单点编码回溯',
        '..%252f'       => '三重URL编码',
        '%252e%252e%252f' => '三重编码全量',
        '....//'        => '双点双斜杠绕过',
        '....\\\\'      => '双点双反斜杠绕过',
        '.%2e/'         => '编码点绕过',
        '%c0%ae%c0%ae/' => 'Unicode超集编码绕过',
        '%c0%ae%c0%ae%c0%af' => 'Unicode超集编码全量',
    ];

    private static $nullBytePatterns = [
        '%00'       => 'URL空字节',
        '\\x00'     => '十六进制空字节',
        '\\0'       => '八进制空字节',
    ];

    // ==================== Public API ====================

    /**
     * 主入口：分析路径语义
     *
     * @param string $path
     * @return array
     */
    public static function analyze(string $path): array {
        $result = self::defaultResult();
        if ($path === '') return $result;

        $originalPath = $path;

        try {
            $tokens = self::tokenize($path);
            $tokenCount = count($tokens);
            $result['token_count'] = $tokenCount;

            if ($tokenCount <= 1) {
                $fallbackResult = self::regexFallbackAnalyze($path);
                return array_merge($result, $fallbackResult, ['parser_used' => 'regex_fallback']);
            }

            $ast = self::parse($tokens, $path);
            if (empty($ast) || !isset($ast['segments'])) {
                $fallbackResult = self::regexFallbackAnalyze($path);
                return array_merge($result, $fallbackResult, ['parser_used' => 'regex_fallback']);
            }

            $result['parser_used'] = 'ast';
            $result['ast_summary'] = self::summarizeAst($ast);

            $walkerResult = self::walkAst($ast, $originalPath);

            $result = array_merge($result, $walkerResult);

        } catch (Exception $e) {
            $fallbackResult = self::regexFallbackAnalyze($path);
            $result = array_merge($result, $fallbackResult, ['parser_used' => 'regex_fallback']);
            $result['indicators'][] = 'ast_parse_error';
        }

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'                  => 0,
            'risk_level'             => 'clean',
            'is_path_traversal'      => false,
            'traversal_depth'        => 0,
            'traversal_count'        => 0,
            'decode_depth'           => 0,
            'encode_types'           => [],
            'os_type'                => 'unknown',
            'normalized_path'        => '',
            'sensitive_hits'         => [],
            'has_null_byte'          => false,
            'has_unicode_bypass'     => false,
            'has_path_confusion'     => false,
            'has_absolute_escape'    => false,
            'indicators'             => [],
            'parser_used'            => 'none',
            'token_count'            => 0,
            'ast_summary'            => [],
            'has_windows_traversal'  => false,
            'has_unc_path'           => false,
            'has_double_encoding'    => false,
            'path_depth'             => 0,
            'extension'              => '',
            'is_absolute'            => false,
        ];
    }

    // ==================== Tokenizer ====================

    /**
     * 路径词法分析
     *
     * @param string $path
     * @return array
     */
    private static function tokenize(string $path): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($path);

        while ($pos < $len) {
            $char = $path[$pos];

            if ($char === '/' || $char === '\\') {
                $sepType = $char === '/' ? 'forward' : 'backward';

                if ($pos === 0 && $char === '\\' && $pos + 1 < $len && $path[$pos + 1] === '\\') {
                    $tokens[] = [
                        'type'  => self::TOKEN_UNC_PREFIX,
                        'value' => '\\\\',
                        'pos'   => $pos,
                    ];
                    $pos += 2;
                    continue;
                }

                $tokens[] = [
                    'type'      => self::TOKEN_SEPARATOR,
                    'value'     => $char,
                    'pos'       => $pos,
                    'sep_type'  => $sepType,
                    'is_encoded' => false,
                ];
                $pos++;
                continue;
            }

            if ($pos === 0 && ctype_alpha($char) && $pos + 1 < $len && $path[$pos + 1] === ':') {
                $driveLetter = strtoupper($char);
                $tokens[] = [
                    'type'   => self::TOKEN_WIN_DRIVE,
                    'value'  => $driveLetter . ':',
                    'pos'    => $pos,
                    'drive'  => $driveLetter,
                ];
                $pos += 2;
                continue;
            }

            if ($char === '%') {
                $encodedResult = self::decodeEncodedSequence($path, $pos, $len);
                if ($encodedResult !== null) {
                    $decodedChar = $encodedResult['decoded'];

                    if ($decodedChar === '/' || $decodedChar === '\\') {
                        $tokens[] = [
                            'type'          => self::TOKEN_SEPARATOR,
                            'value'         => $decodedChar,
                            'pos'           => $pos,
                            'sep_type'      => $decodedChar === '/' ? 'forward' : 'backward',
                            'is_encoded'    => true,
                            'encode_type'   => $encodedResult['type'],
                            'encode_depth'  => $encodedResult['depth'],
                            'raw_value'     => $encodedResult['raw'],
                        ];
                        $pos = $encodedResult['end_pos'];
                        continue;
                    }

                    if (ord($decodedChar) === 0) {
                        $tokens[] = [
                            'type'          => self::TOKEN_NULL_BYTE,
                            'value'         => $decodedChar,
                            'pos'           => $pos,
                            'encode_type'   => $encodedResult['type'],
                            'encode_depth'  => $encodedResult['depth'],
                            'raw_value'     => $encodedResult['raw'],
                        ];
                        $pos = $encodedResult['end_pos'];
                        continue;
                    }

                    if ($decodedChar === '.') {
                        $parentCheck = self::checkEncodedParentDir($path, $pos, $len, $encodedResult);
                        if ($parentCheck !== null) {
                            $tokens[] = [
                                'type'          => self::TOKEN_PARENT,
                                'value'         => '..',
                                'pos'           => $pos,
                                'is_encoded'    => true,
                                'encode_type'   => $parentCheck['type'],
                                'encode_depth'  => $parentCheck['depth'],
                                'raw_value'     => $parentCheck['raw'],
                            ];
                            $pos = $parentCheck['end_pos'];
                            continue;
                        }

                        $currentCheck = self::checkEncodedCurrentDir($path, $pos, $len, $encodedResult);
                        if ($currentCheck !== null) {
                            $tokens[] = [
                                'type'          => self::TOKEN_CURRENT,
                                'value'         => '.',
                                'pos'           => $pos,
                                'is_encoded'    => true,
                                'encode_type'   => $currentCheck['type'],
                                'encode_depth'  => $currentCheck['depth'],
                                'raw_value'     => $currentCheck['raw'],
                            ];
                            $pos = $currentCheck['end_pos'];
                            continue;
                        }
                    }

                    $tokens[] = [
                        'type'          => self::TOKEN_ENCODED,
                        'value'         => $encodedResult['raw'],
                        'pos'           => $pos,
                        'decoded'       => $decodedChar,
                        'encode_type'   => $encodedResult['type'],
                        'encode_depth'  => $encodedResult['depth'],
                    ];
                    $pos = $encodedResult['end_pos'];
                    continue;
                }
            }

            if ($char === '.' && $pos + 1 < $len && $path[$pos + 1] === '.') {
                $nextPos = $pos + 2;
                $isParent = false;

                if ($nextPos >= $len) {
                    $isParent = true;
                } else {
                    $nextChar = $path[$nextPos];
                    if ($nextChar === '/' || $nextChar === '\\') {
                        $isParent = true;
                    } elseif ($nextChar === '%') {
                        $encodedSep = self::decodeEncodedSequence($path, $nextPos, $len);
                        if ($encodedSep !== null && ($encodedSep['decoded'] === '/' || $encodedSep['decoded'] === '\\')) {
                            $isParent = true;
                        }
                    }
                }

                if ($isParent) {
                    $tokens[] = [
                        'type'       => self::TOKEN_PARENT,
                        'value'      => '..',
                        'pos'        => $pos,
                        'is_encoded' => false,
                    ];
                    $pos += 2;
                    continue;
                }
            }

            if ($char === '.') {
                $nextPos = $pos + 1;
                $isCurrent = false;

                if ($nextPos >= $len) {
                    $isCurrent = true;
                } else {
                    $nextChar = $path[$nextPos];
                    if ($nextChar === '/' || $nextChar === '\\') {
                        $isCurrent = true;
                    } elseif ($nextChar === '%') {
                        $encodedSep = self::decodeEncodedSequence($path, $nextPos, $len);
                        if ($encodedSep !== null && ($encodedSep['decoded'] === '/' || $encodedSep['decoded'] === '\\')) {
                            $isCurrent = true;
                        }
                    }
                }

                if ($isCurrent) {
                    $tokens[] = [
                        'type'       => self::TOKEN_CURRENT,
                        'value'      => '.',
                        'pos'        => $pos,
                        'is_encoded' => false,
                    ];
                    $pos++;
                    continue;
                }
            }

            $segmentResult = self::readPathSegment($path, $pos, $len);
            if ($segmentResult !== null && $segmentResult['value'] !== '') {
                $tokens[] = [
                    'type'          => self::TOKEN_SEGMENT,
                    'value'         => $segmentResult['value'],
                    'pos'           => $pos,
                    'has_encoded'   => $segmentResult['has_encoded'],
                    'encode_types'  => $segmentResult['encode_types'],
                    'max_encode_depth' => $segmentResult['max_depth'],
                    'has_null_byte' => $segmentResult['has_null_byte'],
                ];
                $pos = $segmentResult['end_pos'];
                continue;
            }

            $pos++;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    /**
     * 解码URL编码序列，支持多重编码
     */
    private static function decodeEncodedSequence(string $path, int $pos, int $len): ?array {
        $startPos = $pos;
        $raw = '';
        $currentDecoded = '';
        $depth = 0;
        $encodeTypes = [];
        $maxDepth = 0;

        if ($pos + 2 >= $len) return null;
        if ($path[$pos] !== '%') return null;

        $currentPos = $pos;
        $currentRaw = '';
        $firstByte = null;

        $hex1 = $path[$currentPos + 1] ?? '';
        $hex2 = $path[$currentPos + 2] ?? '';
        if (!ctype_xdigit($hex1) || !ctype_xdigit($hex2)) return null;

        $firstByte = chr(hexdec($hex1 . $hex2));
        $currentRaw = substr($path, $currentPos, 3);
        $currentDecoded = $firstByte;
        $depth = 1;
        $currentPos += 3;
        $encodeTypes[] = 'url';

        if ($firstByte === '%' && $currentPos + 2 < $len) {
            $hex3 = $path[$currentPos + 1] ?? '';
            $hex4 = $path[$currentPos + 2] ?? '';
            if (ctype_xdigit($hex3) && ctype_xdigit($hex4)) {
                $secondByte = chr(hexdec($hex3 . $hex4));
                $currentRaw .= substr($path, $currentPos, 3);
                $currentDecoded = $secondByte;
                $depth = 2;
                $currentPos += 3;
                $encodeTypes[] = 'double_url';

                if ($secondByte === '%' && $currentPos + 2 < $len) {
                    $hex5 = $path[$currentPos + 1] ?? '';
                    $hex6 = $path[$currentPos + 2] ?? '';
                    if (ctype_xdigit($hex5) && ctype_xdigit($hex6)) {
                        $thirdByte = chr(hexdec($hex5 . $hex6));
                        $currentRaw .= substr($path, $currentPos, 3);
                        $currentDecoded = $thirdByte;
                        $depth = 3;
                        $currentPos += 3;
                        $encodeTypes[] = 'triple_url';
                    }
                }
            }
        }

        $finalType = 'url';
        if ($depth >= 3) $finalType = 'triple_url';
        elseif ($depth >= 2) $finalType = 'double_url';

        if (ord($currentDecoded) === 0) {
            $finalType = 'null_byte';
        }

        return [
            'raw'       => $currentRaw,
            'decoded'   => $currentDecoded,
            'type'      => $finalType,
            'depth'     => $depth,
            'end_pos'   => $currentPos,
            'encode_types' => $encodeTypes,
        ];
    }

    /**
     * 检查编码的父目录（..）
     */
    private static function checkEncodedParentDir(string $path, int $pos, int $len, array $firstDot): ?array {
        $secondDotPos = $firstDot['end_pos'];
        if ($secondDotPos >= $len) return null;

        $secondChar = $path[$secondDotPos];
        $secondDot = null;

        if ($secondChar === '.') {
            $secondDot = [
                'raw'       => '.',
                'decoded'   => '.',
                'type'      => 'none',
                'depth'     => 0,
                'end_pos'   => $secondDotPos + 1,
            ];
        } elseif ($secondChar === '%') {
            $secondDot = self::decodeEncodedSequence($path, $secondDotPos, $len);
            if ($secondDot === null || $secondDot['decoded'] !== '.') {
                return null;
            }
        } else {
            return null;
        }

        $sepPos = $secondDot['end_pos'];
        if ($sepPos < $len) {
            $sepChar = $path[$sepPos];
            if ($sepChar === '/' || $sepChar === '\\') {
                $isParent = true;
            } elseif ($sepChar === '%') {
                $encodedSep = self::decodeEncodedSequence($path, $sepPos, $len);
                if ($encodedSep !== null && ($encodedSep['decoded'] === '/' || $encodedSep['decoded'] === '\\')) {
                    $isParent = true;
                } else {
                    $isParent = true;
                }
            } else {
                return null;
            }
        }

        $combinedRaw = $firstDot['raw'] . $secondDot['raw'];
        $maxDepth = max($firstDot['depth'], $secondDot['depth']);
        $encodeType = $maxDepth >= 2 ? 'double_url' : 'url';

        return [
            'raw'       => $combinedRaw,
            'type'      => $encodeType,
            'depth'     => $maxDepth,
            'end_pos'   => $secondDot['end_pos'],
        ];
    }

    /**
     * 检查编码的当前目录（.）
     */
    private static function checkEncodedCurrentDir(string $path, int $pos, int $len, array $firstDot): ?array {
        $sepPos = $firstDot['end_pos'];
        if ($sepPos < $len) {
            $sepChar = $path[$sepPos];
            if ($sepChar === '/' || $sepChar === '\\') {
                return [
                    'raw'       => $firstDot['raw'],
                    'type'      => $firstDot['type'],
                    'depth'     => $firstDot['depth'],
                    'end_pos'   => $firstDot['end_pos'],
                ];
            } elseif ($sepChar === '%') {
                $encodedSep = self::decodeEncodedSequence($path, $sepPos, $len);
                if ($encodedSep !== null && ($encodedSep['decoded'] === '/' || $encodedSep['decoded'] === '\\')) {
                    return [
                        'raw'       => $firstDot['raw'],
                        'type'      => $firstDot['type'],
                        'depth'     => $firstDot['depth'],
                        'end_pos'   => $firstDot['end_pos'],
                    ];
                }
            }
        } else {
            return [
                'raw'       => $firstDot['raw'],
                'type'      => $firstDot['type'],
                'depth'     => $firstDot['depth'],
                'end_pos'   => $firstDot['end_pos'],
            ];
        }

        return null;
    }

    /**
     * 读取路径段
     */
    private static function readPathSegment(string $path, int $pos, int $len): ?array {
        $startPos = $pos;
        $value = '';
        $hasEncoded = false;
        $encodeTypes = [];
        $maxDepth = 0;
        $hasNullByte = false;

        while ($pos < $len) {
            $char = $path[$pos];

            if ($char === '/' || $char === '\\') {
                break;
            }

            if ($char === '%') {
                $encodedResult = self::decodeEncodedSequence($path, $pos, $len);
                if ($encodedResult !== null) {
                    $decoded = $encodedResult['decoded'];

                    if ($decoded === '/' || $decoded === '\\') {
                        break;
                    }

                    if (ord($decoded) === 0) {
                        $hasNullByte = true;
                    }

                    $value .= $decoded;
                    $hasEncoded = true;
                    $encodeTypes[] = $encodedResult['type'];
                    if ($encodedResult['depth'] > $maxDepth) {
                        $maxDepth = $encodedResult['depth'];
                    }
                    $pos = $encodedResult['end_pos'];
                    continue;
                }
            }

            if ($char === "\0") {
                $hasNullByte = true;
                break;
            }

            $value .= $char;
            $pos++;
        }

        if ($pos === $startPos) return null;

        return [
            'value'         => $value,
            'has_encoded'   => $hasEncoded,
            'encode_types'  => array_values(array_unique($encodeTypes)),
            'max_depth'     => $maxDepth,
            'has_null_byte' => $hasNullByte,
            'end_pos'       => $pos,
        ];
    }

    // ==================== Parser ====================

    /**
     * 路径语法分析，构建 AST
     *
     * @param array $tokens
     * @param string $path
     * @return array|null
     */
    private static function parse(array $tokens, string $path): ?array {
        $state = [
            'tokens' => $tokens,
            'pos'    => 0,
            'path'   => $path,
        ];

        $ast = self::parsePath($state);
        if ($ast === null) {
            return null;
        }

        return $ast;
    }

    private static function parsePath(array &$state): ?array {
        $ast = [
            'type'              => 'path',
            'is_absolute'       => false,
            'is_unc'            => false,
            'drive_letter'      => null,
            'segments'          => [],
            'raw_path'          => $state['path'],
            'has_encoded'       => false,
            'encode_types'      => [],
            'decode_depth'      => 0,
            'has_null_byte'     => false,
            'has_windows_sep'   => false,
            'has_parent'        => false,
            'parent_count'      => 0,
            'encoded_parent_count' => 0,
        ];

        $token = self::current($state);

        if ($token['type'] === self::TOKEN_ROOT) {
            $ast['is_absolute'] = true;
            self::next($state);
            $token = self::current($state);
        } elseif ($token['type'] === self::TOKEN_UNC_PREFIX) {
            $ast['is_absolute'] = true;
            $ast['is_unc'] = true;
            self::next($state);
            $token = self::current($state);
        } elseif ($token['type'] === self::TOKEN_WIN_DRIVE) {
            $ast['drive_letter'] = $token['drive'];
            $ast['is_absolute'] = true;
            self::next($state);
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_SEPARATOR) {
                if (!empty($token['is_encoded'])) {
                    $ast['has_encoded'] = true;
                    $ast['encode_types'][] = $token['encode_type'];
                    if (($token['encode_depth'] ?? 0) > $ast['decode_depth']) {
                        $ast['decode_depth'] = $token['encode_depth'];
                    }
                }
                if ($token['sep_type'] === 'backward') {
                    $ast['has_windows_sep'] = true;
                }
                self::next($state);
                $token = self::current($state);
            }
        } elseif ($token['type'] === self::TOKEN_SEPARATOR) {
            $ast['is_absolute'] = true;
            if ($token['sep_type'] === 'backward') {
                $ast['has_windows_sep'] = true;
            }
            if (!empty($token['is_encoded'])) {
                $ast['has_encoded'] = true;
                $ast['encode_types'][] = $token['encode_type'];
                if (($token['encode_depth'] ?? 0) > $ast['decode_depth']) {
                    $ast['decode_depth'] = $token['encode_depth'];
                }
            }
            self::next($state);
            $token = self::current($state);
        }

        $segmentIndex = 0;
        while (!self::isEof($state)) {
            $token = self::current($state);

            if ($token['type'] === self::TOKEN_SEPARATOR) {
                if ($token['sep_type'] === 'backward') {
                    $ast['has_windows_sep'] = true;
                }
                if (!empty($token['is_encoded'])) {
                    $ast['has_encoded'] = true;
                    $ast['encode_types'][] = $token['encode_type'];
                    if (($token['encode_depth'] ?? 0) > $ast['decode_depth']) {
                        $ast['decode_depth'] = $token['encode_depth'];
                    }
                }
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_NULL_BYTE) {
                $ast['has_null_byte'] = true;
                $ast['has_encoded'] = true;
                $ast['encode_types'][] = 'null_byte';
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_PARENT) {
                $segmentNode = [
                    'type'      => 'parent',
                    'value'     => '..',
                    'index'     => $segmentIndex,
                    'pos'       => $token['pos'],
                    'is_encoded' => !empty($token['is_encoded']),
                ];
                if (!empty($token['is_encoded'])) {
                    $segmentNode['encode_type'] = $token['encode_type'];
                    $segmentNode['raw_value'] = $token['raw_value'];
                    $ast['has_encoded'] = true;
                    $ast['encode_types'][] = $token['encode_type'];
                    if (($token['encode_depth'] ?? 0) > $ast['decode_depth']) {
                        $ast['decode_depth'] = $token['encode_depth'];
                    }
                    $ast['encoded_parent_count']++;
                }
                $ast['segments'][] = $segmentNode;
                $ast['has_parent'] = true;
                $ast['parent_count']++;
                $segmentIndex++;
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_CURRENT) {
                $segmentNode = [
                    'type'      => 'current',
                    'value'     => '.',
                    'index'     => $segmentIndex,
                    'pos'       => $token['pos'],
                    'is_encoded' => !empty($token['is_encoded']),
                ];
                if (!empty($token['is_encoded'])) {
                    $segmentNode['encode_type'] = $token['encode_type'];
                    $segmentNode['raw_value'] = $token['raw_value'];
                    $ast['has_encoded'] = true;
                    $ast['encode_types'][] = $token['encode_type'];
                    if (($token['encode_depth'] ?? 0) > $ast['decode_depth']) {
                        $ast['decode_depth'] = $token['encode_depth'];
                    }
                }
                $ast['segments'][] = $segmentNode;
                $segmentIndex++;
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_ENCODED) {
                $decoded = $token['decoded'];
                $ast['has_encoded'] = true;
                $ast['encode_types'][] = $token['encode_type'];
                if (($token['encode_depth'] ?? 0) > $ast['decode_depth']) {
                    $ast['decode_depth'] = $token['encode_depth'];
                }

                $segmentInfo = self::analyzeSegment($decoded);
                $ast['segments'][] = array_merge($segmentInfo, [
                    'type'          => 'encoded',
                    'index'         => $segmentIndex,
                    'pos'           => $token['pos'],
                    'is_encoded'    => true,
                    'encode_type'   => $token['encode_type'],
                    'raw_value'     => $token['value'],
                ]);

                $segmentIndex++;
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_SEGMENT) {
                $segmentInfo = self::analyzeSegment($token['value']);
                $segmentNode = array_merge($segmentInfo, [
                    'type'      => 'normal',
                    'index'     => $segmentIndex,
                    'pos'       => $token['pos'],
                ]);

                if (!empty($token['has_encoded'])) {
                    $segmentNode['is_encoded'] = true;
                    $segmentNode['encode_types'] = $token['encode_types'];
                    $ast['has_encoded'] = true;
                    $ast['encode_types'] = array_merge($ast['encode_types'], $token['encode_types']);
                    if (($token['max_encode_depth'] ?? 0) > $ast['decode_depth']) {
                        $ast['decode_depth'] = $token['max_encode_depth'];
                    }
                }

                if (!empty($token['has_null_byte'])) {
                    $ast['has_null_byte'] = true;
                }

                $ast['segments'][] = $segmentNode;
                $segmentIndex++;
                self::next($state);
                continue;
            }

            if ($token['type'] === self::TOKEN_EOF) {
                break;
            }

            self::next($state);
        }

        $ast['encode_types'] = array_values(array_unique(array_filter($ast['encode_types'])));
        $ast['segment_count'] = count($ast['segments']);

        $normalized = self::normalizePathFromAst($ast);
        $ast['normalized_path'] = $normalized['path'];
        $ast['resolved_path'] = $normalized['resolved'];
        $ast['traversal_depth'] = $normalized['max_depth'];
        $ast['effective_depth'] = $normalized['effective_depth'];

        $lastSegment = null;
        for ($i = count($ast['segments']) - 1; $i >= 0; $i--) {
            $seg = $ast['segments'][$i];
            if ($seg['type'] === 'normal' || $seg['type'] === 'encoded') {
                $lastSegment = $seg;
                break;
            }
        }
        if ($lastSegment && isset($lastSegment['extension'])) {
            $ast['extension'] = $lastSegment['extension'];
        } else {
            $ast['extension'] = '';
        }

        return $ast;
    }

    /**
     * 分析单个路径段的详细信息
     */
    private static function analyzeSegment(string $segment): array {
        $info = [
            'value'         => $segment,
            'is_file'       => false,
            'is_dotfile'    => false,
            'name'          => $segment,
            'extension'     => '',
            'has_multiple_dots' => false,
            'dot_count'     => 0,
        ];

        if ($segment === '') return $info;

        $dotCount = substr_count($segment, '.');
        $info['dot_count'] = $dotCount;
        $info['has_multiple_dots'] = $dotCount > 1;

        if (isset($segment[0]) && $segment[0] === '.') {
            $info['is_dotfile'] = true;
        }

        if ($dotCount > 0 && !($segment === '.' || $segment === '..')) {
            $lastDotPos = strrpos($segment, '.');
            if ($lastDotPos > 0 && $lastDotPos < strlen($segment) - 1) {
                $info['is_file'] = true;
                $info['name'] = substr($segment, 0, $lastDotPos);
                $info['extension'] = substr($segment, $lastDotPos + 1);
            }
        }

        return $info;
    }

    /**
     * 从AST规范化路径
     */
    private static function normalizePathFromAst(array $ast): array {
        $segments = $ast['segments'];
        $resolved = [];
        $maxDepth = 0;
        $currentDepth = 0;
        $normalizedParts = [];

        foreach ($segments as $seg) {
            if ($seg['type'] === 'parent') {
                $normalizedParts[] = '..';
                if (!empty($resolved)) {
                    array_pop($resolved);
                    if ($currentDepth > 0) $currentDepth--;
                } else {
                    $currentDepth++;
                    if ($currentDepth > $maxDepth) $maxDepth = $currentDepth;
                }
            } elseif ($seg['type'] === 'current') {
                $normalizedParts[] = '.';
            } else {
                $normalizedParts[] = $seg['value'];
                $resolved[] = $seg['value'];
                $currentDepth = max(0, $currentDepth - 1);
            }
        }

        $prefix = '';
        if ($ast['is_unc']) {
            $prefix = '\\\\';
        } elseif ($ast['is_absolute']) {
            $prefix = '/';
        }

        $normalizedPath = $prefix . implode('/', $normalizedParts);
        $resolvedPath = $prefix . implode('/', $resolved);

        return [
            'path'           => $normalizedPath,
            'resolved'       => $resolvedPath,
            'max_depth'      => $maxDepth,
            'effective_depth' => count($resolved),
        ];
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function next(array &$state): void {
        if ($state['pos'] < count($state['tokens'])) {
            $state['pos']++;
        }
    }

    private static function peek(array &$state, int $offset = 1): ?array {
        $idx = $state['pos'] + $offset;
        return $state['tokens'][$idx] ?? null;
    }

    private static function isEof(array &$state): bool {
        $token = self::current($state);
        return $token['type'] === self::TOKEN_EOF;
    }

    // ==================== AST Summary ====================

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type'                  => $ast['type'] ?? 'path',
            'is_absolute'           => $ast['is_absolute'] ?? false,
            'is_unc'                => $ast['is_unc'] ?? false,
            'drive_letter'          => $ast['drive_letter'],
            'segment_count'         => $ast['segment_count'] ?? 0,
            'parent_count'          => $ast['parent_count'] ?? 0,
            'encoded_parent_count'  => $ast['encoded_parent_count'] ?? 0,
            'has_encoded'           => $ast['has_encoded'] ?? false,
            'decode_depth'          => $ast['decode_depth'] ?? 0,
            'has_null_byte'         => $ast['has_null_byte'] ?? false,
            'traversal_depth'       => $ast['traversal_depth'] ?? 0,
            'extension'             => $ast['extension'] ?? '',
            'path_depth'            => $ast['effective_depth'] ?? 0,
        ];

        if (!empty($ast['encode_types'])) {
            $summary['encode_types'] = $ast['encode_types'];
        }

        return $summary;
    }

    // ==================== AST Walker ====================

    /**
     * 遍历AST进行语义分析，检测路径遍历风险
     */
    private static function walkAst(array $ast, string $originalPath): array {
        $result = [
            'score'                  => 0,
            'risk_level'             => 'clean',
            'is_path_traversal'      => false,
            'traversal_depth'        => $ast['traversal_depth'] ?? 0,
            'traversal_count'        => $ast['parent_count'] ?? 0,
            'decode_depth'           => $ast['decode_depth'] ?? 0,
            'encode_types'           => $ast['encode_types'] ?? [],
            'os_type'                => 'unknown',
            'normalized_path'        => substr($ast['resolved_path'] ?? '', 0, 200),
            'sensitive_hits'         => [],
            'has_null_byte'          => $ast['has_null_byte'] ?? false,
            'has_unicode_bypass'     => false,
            'has_path_confusion'     => false,
            'has_absolute_escape'    => false,
            'indicators'             => [],
            'has_windows_traversal'  => false,
            'has_unc_path'           => $ast['is_unc'] ?? false,
            'has_double_encoding'    => false,
            'path_depth'             => $ast['effective_depth'] ?? 0,
            'extension'              => $ast['extension'] ?? '',
            'is_absolute'            => $ast['is_absolute'] ?? false,
        ];

        $segments = $ast['segments'] ?? [];

        $encodedParentCount = $ast['encoded_parent_count'] ?? 0;
        $doubleEncodedCount = 0;
        $unicodeBypassCount = 0;

        foreach ($segments as $seg) {
            if (!empty($seg['is_encoded'])) {
                $encodeType = $seg['encode_type'] ?? '';
                if ($encodeType === 'double_url' || $encodeType === 'triple_url') {
                    $doubleEncodedCount++;
                }
                if ($encodeType === 'unicode' || $encodeType === 'overlong_utf8') {
                    $unicodeBypassCount++;
                }
            }
            if (!empty($seg['encode_types']) && is_array($seg['encode_types'])) {
                foreach ($seg['encode_types'] as $et) {
                    if ($et === 'double_url' || $et === 'triple_url') {
                        $doubleEncodedCount++;
                    }
                    if ($et === 'unicode' || $et === 'overlong_utf8') {
                        $unicodeBypassCount++;
                    }
                }
            }
        }

        if (!empty($ast['encode_types'])) {
            foreach ($ast['encode_types'] as $et) {
                if ($et === 'double_url' || $et === 'triple_url') {
                    $doubleEncodedCount++;
                }
                if ($et === 'unicode' || $et === 'overlong_utf8' || $et === 'unicode_percent_u') {
                    $unicodeBypassCount++;
                }
            }
        }

        if ($doubleEncodedCount > 0) {
            $result['has_double_encoding'] = true;
        }

        if ($unicodeBypassCount > 0) {
            $result['has_unicode_bypass'] = true;
            $result['indicators'][] = 'unicode_bypass';
        }

        if (!empty($ast['has_windows_sep'])) {
            if (($ast['parent_count'] ?? 0) > 0) {
                $result['has_windows_traversal'] = true;
                $result['indicators'][] = 'windows_path_traversal';
            }
        }

        if ($result['has_unc_path']) {
            $result['indicators'][] = 'unc_path';
        }

        $osType = self::detectOsFromAst($ast);
        $result['os_type'] = $osType;

        $traversalDepth = $ast['traversal_depth'] ?? 0;
        if ($traversalDepth >= 8) {
            $result['score'] += 30;
            $result['indicators'][] = 'extreme_traversal_depth';
        } elseif ($traversalDepth >= 5) {
            $result['score'] += 22;
            $result['indicators'][] = 'high_traversal_depth';
        } elseif ($traversalDepth >= 3) {
            $result['score'] += 15;
            $result['indicators'][] = 'medium_traversal_depth';
        } elseif ($traversalDepth >= 1) {
            $result['score'] += 8;
            $result['indicators'][] = 'low_traversal_depth';
        }

        if ($encodedParentCount > 0) {
            $result['score'] += 10;
            $result['indicators'][] = 'encoded_traversal_segment';
        }

        $decodeDepth = $ast['decode_depth'] ?? 0;
        if ($decodeDepth >= 3) {
            $result['score'] += 20;
            $result['indicators'][] = 'multi_layer_encoding';
        } elseif ($decodeDepth >= 2) {
            $result['score'] += 12;
            $result['indicators'][] = 'double_encoding';
        } elseif ($decodeDepth >= 1) {
            $result['score'] += 6;
            $result['indicators'][] = 'single_encoding';
        }

        if ($result['has_null_byte']) {
            $result['score'] += 15;
            $result['indicators'][] = 'null_byte_truncation';
        }

        $pathConfusion = self::detectPathConfusionFromAst($ast, $originalPath);
        $result['has_path_confusion'] = $pathConfusion;
        if ($pathConfusion) {
            $result['score'] += 10;
            $result['indicators'][] = 'path_confusion';
        }

        $absoluteEscape = self::detectAbsoluteEscapeFromAst($ast);
        $result['has_absolute_escape'] = $absoluteEscape;
        if ($absoluteEscape) {
            $result['score'] += 15;
            $result['indicators'][] = 'absolute_path_escape';
        }

        if ($ast['is_absolute'] ?? false) {
            $result['score'] += 5;
            $result['indicators'][] = 'absolute_path';
        }

        $sensitiveHits = self::detectSensitiveFilesFromAst($ast, $osType);
        $result['sensitive_hits'] = $sensitiveHits;

        $maxSensitiveLevel = 0;
        foreach ($sensitiveHits as $hit) {
            if ($hit['level'] > $maxSensitiveLevel) $maxSensitiveLevel = $hit['level'];
        }
        if ($maxSensitiveLevel >= 5) {
            $result['score'] += 30;
            $result['indicators'][] = 'critical_sensitive_file';
        } elseif ($maxSensitiveLevel >= 4) {
            $result['score'] += 22;
            $result['indicators'][] = 'high_sensitive_file';
        } elseif ($maxSensitiveLevel >= 3) {
            $result['score'] += 14;
            $result['indicators'][] = 'medium_sensitive_file';
        } elseif ($maxSensitiveLevel >= 2) {
            $result['score'] += 8;
            $result['indicators'][] = 'low_sensitive_file';
        }

        if ($traversalDepth >= 3 && $maxSensitiveLevel >= 3) {
            $result['score'] += 15;
            $result['indicators'][] = 'traversal_plus_sensitive_combo';
        }

        if ($decodeDepth >= 2 && $traversalDepth >= 2) {
            $result['score'] += 10;
            $result['indicators'][] = 'encoded_traversal_combo';
        }

        if ($result['has_unc_path']) {
            $result['score'] += 8;
        }

        $score = $result['score'];
        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        $result['risk_level'] = $riskLevel;
        $result['is_path_traversal'] = $score >= 20;
        $result['score'] = min(100, $score);

        return $result;
    }

    private static function detectOsFromAst(array $ast): string {
        if (!empty($ast['drive_letter'])) {
            return 'windows';
        }
        if (!empty($ast['is_unc'])) {
            return 'windows';
        }
        if (!empty($ast['has_windows_sep'])) {
            return 'windows';
        }
        if (!empty($ast['is_absolute'])) {
            return 'linux';
        }
        return 'unknown';
    }

    private static function detectPathConfusionFromAst(array $ast, string $originalPath): bool {
        $normalized = $ast['normalized_path'] ?? '';
        if ($originalPath === $normalized) return false;

        if (strlen($originalPath) > strlen($normalized) + 3) return true;

        if (!empty($ast['has_encoded'])) return true;

        if (!empty($ast['has_windows_sep']) && strpos($normalized, '\\') === false) return true;

        return false;
    }

    private static function detectAbsoluteEscapeFromAst(array $ast): bool {
        $traversalDepth = $ast['traversal_depth'] ?? 0;
        if ($traversalDepth < 1) return false;

        if (!empty($ast['is_absolute'])) return true;

        if (!empty($ast['drive_letter'])) return true;

        return false;
    }

    private static function detectSensitiveFilesFromAst(array $ast, string $osType): array {
        $hits = [];
        $resolvedPath = $ast['resolved_path'] ?? '';
        $cleanPath = str_replace(chr(0), '', $resolvedPath);
        $lowerPath = strtolower($cleanPath);

        $segmentValues = [];
        foreach (($ast['segments'] ?? []) as $seg) {
            if (isset($seg['value'])) {
                $segmentValues[] = strtolower($seg['value']);
            }
        }
        $joinedSegments = implode('/', $segmentValues);

        if ($osType === 'linux' || $osType === 'unknown') {
            foreach (self::$linuxSensitiveFiles as $file => $info) {
                $fileLower = strtolower($file);
                $fileNoSlash = ltrim($fileLower, '/');
                if (self::pathEndsWith($lowerPath, $fileLower) ||
                    self::pathEndsWith($lowerPath, $fileNoSlash) ||
                    strpos($lowerPath, $fileLower) !== false ||
                    strpos($lowerPath, $fileNoSlash) !== false ||
                    self::pathEndsWith($joinedSegments, $fileLower) ||
                    self::pathEndsWith($joinedSegments, $fileNoSlash) ||
                    strpos($joinedSegments, $fileLower) !== false ||
                    strpos($joinedSegments, $fileNoSlash) !== false) {
                    $hits[] = [
                        'file'  => $file,
                        'level' => $info['level'],
                        'desc'  => $info['desc'],
                    ];
                }
            }
        }

        if ($osType === 'windows') {
            foreach (self::$windowsSensitiveFiles as $file => $info) {
                $fileNorm = strtolower(str_replace('\\', '/', $file));
                $pathNorm = strtolower(str_replace('\\', '/', $lowerPath));
                if (strpos($pathNorm, $fileNorm) !== false || self::pathEndsWith($pathNorm, $fileNorm)) {
                    $hits[] = [
                        'file'  => $file,
                        'level' => $info['level'],
                        'desc'  => $info['desc'],
                    ];
                }
            }
        }

        foreach (self::$webSensitiveFiles as $file => $info) {
            $fileLower = strtolower($file);
            if (self::pathEndsWith($lowerPath, $fileLower) ||
                strpos($lowerPath, '/' . $fileLower) !== false ||
                strpos($lowerPath, '\\' . $fileLower) !== false ||
                self::pathEndsWith($joinedSegments, $fileLower) ||
                in_array($fileLower, $segmentValues)) {
                $hits[] = [
                    'file'  => $file,
                    'level' => $info['level'],
                    'desc'  => $info['desc'],
                ];
            }
        }

        usort($hits, function($a, $b) { return $b['level'] - $a['level']; });
        return array_slice($hits, 0, 5);
    }

    private static function pathEndsWith(string $path, string $suffix): bool {
        $suffixLen = strlen($suffix);
        if ($suffixLen > strlen($path)) return false;
        return substr_compare($path, $suffix, -$suffixLen, $suffixLen) === 0;
    }

    // ==================== Regex Fallback ====================

    /**
     * 正则表达式降级分析（保留原有逻辑）
     */
    private static function regexFallbackAnalyze(string $path): array {
        $result = self::defaultResult();
        if ($path === '') return $result;

        $originalPath = $path;

        $decodeResult = self::decodePath($path);
        $normalizedPath = $decodeResult['normalized'];
        $decodeDepth = $decodeResult['depth'];
        $encodeTypes = $decodeResult['encode_types'];
        $isUnicodeBypass = $decodeResult['unicode_bypass'];

        $traversalCount = self::countTraversal($normalizedPath);
        $traversalDepth = self::calculateTraversalDepth($normalizedPath);
        $normalizedTraversal = self::normalizeAndResolve($normalizedPath);

        $osType = self::detectOs($normalizedPath);
        $sensitiveHits = self::detectSensitiveFiles($normalizedTraversal, $osType);

        $hasNullByte = self::detectNullByte($originalPath);
        $hasPathConfusion = self::detectPathConfusion($originalPath, $normalizedPath);
        $hasAbsoluteEscape = self::detectAbsoluteEscape($normalizedTraversal, $traversalDepth);

        $score = 0;
        $indicators = [];

        if ($traversalDepth >= 8) { $score += 30; $indicators[] = 'extreme_traversal_depth'; }
        elseif ($traversalDepth >= 5) { $score += 22; $indicators[] = 'high_traversal_depth'; }
        elseif ($traversalDepth >= 3) { $score += 15; $indicators[] = 'medium_traversal_depth'; }
        elseif ($traversalDepth >= 1) { $score += 8; $indicators[] = 'low_traversal_depth'; }

        if ($decodeDepth >= 3) { $score += 20; $indicators[] = 'multi_layer_encoding'; }
        elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
        elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

        if ($isUnicodeBypass) { $score += 18; $indicators[] = 'unicode_bypass'; }

        if ($hasNullByte) { $score += 15; $indicators[] = 'null_byte_truncation'; }

        if ($hasPathConfusion) { $score += 10; $indicators[] = 'path_confusion'; }

        if ($hasAbsoluteEscape) { $score += 15; $indicators[] = 'absolute_path_escape'; }

        $maxSensitiveLevel = 0;
        foreach ($sensitiveHits as $hit) {
            if ($hit['level'] > $maxSensitiveLevel) $maxSensitiveLevel = $hit['level'];
        }
        if ($maxSensitiveLevel >= 5) { $score += 30; $indicators[] = 'critical_sensitive_file'; }
        elseif ($maxSensitiveLevel >= 4) { $score += 22; $indicators[] = 'high_sensitive_file'; }
        elseif ($maxSensitiveLevel >= 3) { $score += 14; $indicators[] = 'medium_sensitive_file'; }
        elseif ($maxSensitiveLevel >= 2) { $score += 8; $indicators[] = 'low_sensitive_file'; }

        if ($traversalDepth >= 3 && $maxSensitiveLevel >= 3) {
            $score += 15;
            $indicators[] = 'traversal_plus_sensitive_combo';
        }

        if ($decodeDepth >= 2 && $traversalDepth >= 2) {
            $score += 10;
            $indicators[] = 'encoded_traversal_combo';
        }

        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        return [
            'score'                  => min(100, $score),
            'risk_level'             => $riskLevel,
            'is_path_traversal'      => $score >= 20,
            'traversal_depth'        => $traversalDepth,
            'traversal_count'        => $traversalCount,
            'decode_depth'           => $decodeDepth,
            'encode_types'           => $encodeTypes,
            'os_type'                => $osType,
            'normalized_path'        => substr($normalizedTraversal, 0, 200),
            'sensitive_hits'         => $sensitiveHits,
            'has_null_byte'          => $hasNullByte,
            'has_unicode_bypass'     => $isUnicodeBypass,
            'has_path_confusion'     => $hasPathConfusion,
            'has_absolute_escape'    => $hasAbsoluteEscape,
            'indicators'             => $indicators,
            'has_windows_traversal'  => self::detectWindowsTraversal($normalizedPath),
            'has_unc_path'           => self::detectUncPath($originalPath),
            'has_double_encoding'    => $decodeDepth >= 2,
            'path_depth'             => substr_count($normalizedTraversal, '/'),
            'extension'              => self::extractExtension($normalizedTraversal),
            'is_absolute'            => self::isAbsolutePath($normalizedTraversal),
        ];
    }

    // ==================== Legacy Helpers (for fallback) ====================

    private static function decodePath(string $path): array {
        $depth = 0;
        $encodeTypes = [];
        $current = $path;
        $hasUnicodeBypass = false;

        for ($i = 0; $i < 5; $i++) {
            $decoded = $current;

            if (preg_match('/%[0-9a-fA-F]{2}/', $decoded)) {
                $decoded = urldecode($decoded);
                if ($i === 0) $encodeTypes[] = 'url';
                else $encodeTypes[] = 'url_nested';
            }

            if (preg_match('/%u[0-9a-fA-F]{4}/', $decoded)) {
                $decoded = self::decodeUnicodePercentU($decoded);
                $encodeTypes[] = 'unicode_percent_u';
                $hasUnicodeBypass = true;
            }

            if (preg_match('/[\xC0-\xE0][\x80-\xBF]/', $decoded)) {
                $decoded = self::decodeOverlongUtf8($decoded);
                $encodeTypes[] = 'overlong_utf8';
                $hasUnicodeBypass = true;
            }

            if ($decoded === $current) break;

            $depth++;
            $current = $decoded;
        }

        $current = self::normalizePathObfuscation($current);

        return [
            'normalized'     => $current,
            'depth'          => $depth,
            'encode_types'   => array_unique($encodeTypes),
            'unicode_bypass' => $hasUnicodeBypass,
        ];
    }

    private static function normalizePathObfuscation(string $path): string {
        $prev = '';
        $current = $path;
        $iterations = 0;
        while ($prev !== $current && $iterations < 10) {
            $prev = $current;
            $current = str_replace('....//', '../', $current);
            $current = str_replace('....\\\\', '..\\', $current);
            $current = preg_replace('/\/+/', '/', $current);
            $current = str_replace('\\', '/', $current);
            $current = str_replace('.%2e/', '../', $current);
            $iterations++;
        }
        return $current;
    }

    private static function decodeUnicodePercentU(string $str): string {
        return preg_replace_callback('/%u([0-9a-fA-F]{4})/', function($m) {
            $code = hexdec($m[1]);
            if ($code < 0x80) return chr($code);
            if ($code < 0x800) return chr(0xC0 | ($code >> 6)) . chr(0x80 | ($code & 0x3F));
            return chr(0xE0 | ($code >> 12)) . chr(0x80 | (($code >> 6) & 0x3F)) . chr(0x80 | ($code & 0x3F));
        }, $str);
    }

    private static function decodeOverlongUtf8(string $str): string {
        $result = '';
        $len = strlen($str);
        $i = 0;
        while ($i < $len) {
            $byte = ord($str[$i]);
            if ($byte < 0x80) {
                $result .= chr($byte);
                $i++;
            } elseif (($byte & 0xE0) === 0xC0 && $i + 1 < $len) {
                $byte2 = ord($str[$i + 1]);
                $codepoint = (($byte & 0x1F) << 6) | ($byte2 & 0x3F);
                if ($codepoint < 0x80) {
                    $result .= chr($codepoint);
                } else {
                    $result .= chr($byte) . chr($byte2);
                }
                $i += 2;
            } elseif (($byte & 0xF0) === 0xE0 && $i + 2 < $len) {
                $byte2 = ord($str[$i + 1]);
                $byte3 = ord($str[$i + 2]);
                $codepoint = (($byte & 0x0F) << 12) | (($byte2 & 0x3F) << 6) | ($byte3 & 0x3F);
                if ($codepoint < 0x800) {
                    if ($codepoint < 0x80) {
                        $result .= chr($codepoint);
                    } else {
                        $result .= chr(0xC0 | ($codepoint >> 6)) . chr(0x80 | ($codepoint & 0x3F));
                    }
                } else {
                    $result .= chr($byte) . chr($byte2) . chr($byte3);
                }
                $i += 3;
            } else {
                $result .= chr($byte);
                $i++;
            }
        }
        return $result;
    }

    private static function countTraversal(string $path): int {
        $count = 0;
        $count += substr_count($path, '../');
        $count += substr_count($path, '..\\');
        $count += substr_count($path, '..' . DIRECTORY_SEPARATOR);
        return $count;
    }

    private static function calculateTraversalDepth(string $path): int {
        $depth = 0;
        $maxDepth = 0;

        $parts = preg_split('/[\/\\\\]/', $path);
        foreach ($parts as $part) {
            if ($part === '..') {
                $depth++;
                if ($depth > $maxDepth) $maxDepth = $depth;
            } elseif ($part !== '' && $part !== '.') {
                if ($depth > 0) $depth--;
            }
        }

        return $maxDepth;
    }

    private static function normalizeAndResolve(string $path): string {
        $path = str_replace('\\', '/', $path);
        $parts = explode('/', $path);
        $resolved = [];

        foreach ($parts as $part) {
            if ($part === '' || $part === '.') continue;
            if ($part === '..') {
                if (!empty($resolved)) array_pop($resolved);
            } else {
                $resolved[] = $part;
            }
        }

        $result = implode('/', $resolved);
        if (isset($path[0]) && ($path[0] === '/' || $path[0] === '\\')) {
            $result = '/' . $result;
        }

        return $result;
    }

    private static function detectOs(string $path): string {
        if (preg_match('/[a-zA-Z]:[\\\\\/]/', $path) || strpos($path, '\\') !== false) {
            return 'windows';
        }
        if (isset($path[0]) && $path[0] === '/') {
            return 'linux';
        }
        return 'unknown';
    }

    private static function detectSensitiveFiles(string $normalizedPath, string $osType): array {
        $hits = [];
        $cleanPath = str_replace(chr(0), '', $normalizedPath);
        $lowerPath = strtolower($cleanPath);

        if ($osType === 'linux' || $osType === 'unknown') {
            foreach (self::$linuxSensitiveFiles as $file => $info) {
                $fileLower = strtolower($file);
                $fileNoSlash = ltrim($fileLower, '/');
                if (self::pathEndsWith($lowerPath, $fileLower) ||
                    self::pathEndsWith($lowerPath, $fileNoSlash) ||
                    strpos($lowerPath, $fileLower) !== false ||
                    strpos($lowerPath, $fileNoSlash) !== false) {
                    $hits[] = [
                        'file'  => $file,
                        'level' => $info['level'],
                        'desc'  => $info['desc'],
                    ];
                }
            }
        }

        if ($osType === 'windows') {
            foreach (self::$windowsSensitiveFiles as $file => $info) {
                $fileNorm = strtolower(str_replace('\\', '/', $file));
                $pathNorm = strtolower(str_replace('\\', '/', $lowerPath));
                if (strpos($pathNorm, $fileNorm) !== false || self::pathEndsWith($pathNorm, $fileNorm)) {
                    $hits[] = [
                        'file'  => $file,
                        'level' => $info['level'],
                        'desc'  => $info['desc'],
                    ];
                }
            }
        }

        foreach (self::$webSensitiveFiles as $file => $info) {
            if (self::pathEndsWith($lowerPath, strtolower($file)) ||
                strpos($lowerPath, '/' . strtolower($file)) !== false ||
                strpos($lowerPath, '\\' . strtolower($file)) !== false) {
                $hits[] = [
                    'file'  => $file,
                    'level' => $info['level'],
                    'desc'  => $info['desc'],
                ];
            }
        }

        usort($hits, function($a, $b) { return $b['level'] - $a['level']; });
        return array_slice($hits, 0, 5);
    }

    private static function detectNullByte(string $path): bool {
        if (strpos($path, chr(0)) !== false) return true;
        foreach (self::$nullBytePatterns as $pattern => $desc) {
            if (stripos($path, $pattern) !== false) return true;
        }
        return false;
    }

    private static function detectPathConfusion(string $original, string $normalized): bool {
        if ($original === $normalized) return false;
        if (strlen($original) > strlen($normalized) + 3) return true;
        if (preg_match('/\.\.\.?+\//', $original)) return true;
        if (preg_match('/\/\//', $original)) return true;
        return false;
    }

    private static function detectAbsoluteEscape(string $resolvedPath, int $traversalDepth): bool {
        if ($traversalDepth < 1) return false;
        if (isset($resolvedPath[0]) && $resolvedPath[0] === '/') return true;
        if (preg_match('/^[a-zA-Z]:\//', $resolvedPath)) return true;
        return false;
    }

    private static function detectWindowsTraversal(string $path): bool {
        return strpos($path, '..\\') !== false || strpos($path, '..' . DIRECTORY_SEPARATOR) !== false;
    }

    private static function detectUncPath(string $path): bool {
        return isset($path[0]) && $path[0] === '\\' && isset($path[1]) && $path[1] === '\\';
    }

    private static function extractExtension(string $path): string {
        $basename = basename($path);
        $dotPos = strrpos($basename, '.');
        if ($dotPos !== false && $dotPos > 0 && $dotPos < strlen($basename) - 1) {
            return substr($basename, $dotPos + 1);
        }
        return '';
    }

    private static function isAbsolutePath(string $path): bool {
        if (empty($path)) return false;
        if ($path[0] === '/') return true;
        if ($path[0] === '\\') return true;
        if (preg_match('/^[a-zA-Z]:[\/\\\\]/', $path)) return true;
        return false;
    }
}
