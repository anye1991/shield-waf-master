<?php
/**
 * 路径遍历语义解析器
 * 职责：深度解析路径结构，规范化各种编码/混淆变体，计算回溯深度，
 *       识别敏感文件访问意图，而非简单的 ../ 关键词匹配。
 */
defined('ABSPATH') || exit;

class PathTraversalSemanticParser {

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

    public static function analyze(string $path): array {
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
            'score'               => min(100, $score),
            'risk_level'          => $riskLevel,
            'is_path_traversal'   => $score >= 20,
            'traversal_depth'     => $traversalDepth,
            'traversal_count'     => $traversalCount,
            'decode_depth'        => $decodeDepth,
            'encode_types'        => $encodeTypes,
            'os_type'             => $osType,
            'normalized_path'     => substr($normalizedTraversal, 0, 200),
            'sensitive_hits'      => $sensitiveHits,
            'has_null_byte'       => $hasNullByte,
            'has_unicode_bypass'  => $isUnicodeBypass,
            'has_path_confusion'  => $hasPathConfusion,
            'has_absolute_escape' => $hasAbsoluteEscape,
            'indicators'          => $indicators,
        ];
    }

    private static function defaultResult(): array {
        return [
            'score'               => 0,
            'risk_level'          => 'clean',
            'is_path_traversal'   => false,
            'traversal_depth'     => 0,
            'traversal_count'     => 0,
            'decode_depth'        => 0,
            'encode_types'        => [],
            'os_type'             => 'unknown',
            'normalized_path'     => '',
            'sensitive_hits'      => [],
            'has_null_byte'       => false,
            'has_unicode_bypass'  => false,
            'has_path_confusion'  => false,
            'has_absolute_escape' => false,
            'indicators'          => [],
        ];
    }

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

    private static function pathEndsWith(string $path, string $suffix): bool {
        $suffixLen = strlen($suffix);
        if ($suffixLen > strlen($path)) return false;
        return substr_compare($path, $suffix, -$suffixLen, $suffixLen) === 0;
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
}
