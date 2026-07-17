<?php
/**
 * 命令注入语义解析器
 * 职责：深度解析命令结构，识别命令注入意图，而非简单的关键词匹配。
 *       包括命令拆分、危险命令分级、管道链追踪、逃逸字符分析、编码混淆检测。
 */
defined('ABSPATH') || exit;

class CommandInjectionSemanticParser {

    private static $dangerousCommands = [
        'rm'         => ['level' => 5, 'desc' => '删除文件', 'category' => 'destructive'],
        'dd'         => ['level' => 5, 'desc' => '磁盘操作', 'category' => 'destructive'],
        'mkfs'       => ['level' => 5, 'desc' => '格式化磁盘', 'category' => 'destructive'],
        ':()'        => ['level' => 5, 'desc' => 'Fork炸弹', 'category' => 'dos'],
        'wget'       => ['level' => 4, 'desc' => '远程下载', 'category' => 'download'],
        'curl'       => ['level' => 4, 'desc' => '远程请求', 'category' => 'download'],
        'nc'         => ['level' => 4, 'desc' => '网络工具', 'category' => 'network'],
        'netcat'     => ['level' => 4, 'desc' => '网络工具', 'category' => 'network'],
        'bash'       => ['level' => 4, 'desc' => 'Shell执行', 'category' => 'shell'],
        'sh'         => ['level' => 4, 'desc' => 'Shell执行', 'category' => 'shell'],
        'zsh'        => ['level' => 4, 'desc' => 'Shell执行', 'category' => 'shell'],
        'python'     => ['level' => 4, 'desc' => '脚本执行', 'category' => 'script'],
        'perl'       => ['level' => 4, 'desc' => '脚本执行', 'category' => 'script'],
        'php'        => ['level' => 4, 'desc' => '脚本执行', 'category' => 'script'],
        'ruby'       => ['level' => 4, 'desc' => '脚本执行', 'category' => 'script'],
        'cat'        => ['level' => 3, 'desc' => '读取文件', 'category' => 'read'],
        'head'       => ['level' => 3, 'desc' => '读取文件', 'category' => 'read'],
        'tail'       => ['level' => 3, 'desc' => '读取文件', 'category' => 'read'],
        'more'       => ['level' => 3, 'desc' => '读取文件', 'category' => 'read'],
        'less'       => ['level' => 3, 'desc' => '读取文件', 'category' => 'read'],
        'find'       => ['level' => 3, 'desc' => '文件搜索', 'category' => 'search'],
        'ls'         => ['level' => 2, 'desc' => '文件列表', 'category' => 'enumeration'],
        'id'         => ['level' => 2, 'desc' => '用户信息', 'category' => 'enumeration'],
        'whoami'     => ['level' => 2, 'desc' => '当前用户', 'category' => 'enumeration'],
        'uname'      => ['level' => 2, 'desc' => '系统信息', 'category' => 'enumeration'],
        'pwd'        => ['level' => 1, 'desc' => '当前路径', 'category' => 'enumeration'],
        'echo'       => ['level' => 1, 'desc' => '输出命令', 'category' => 'utility'],
        'ping'       => ['level' => 1, 'desc' => '网络测试', 'category' => 'utility'],
        'sleep'      => ['level' => 2, 'desc' => '延迟测试', 'category' => 'blind'],
        'base64'     => ['level' => 3, 'desc' => '编码工具', 'category' => 'evasion'],
        'xxd'        => ['level' => 3, 'desc' => '十六进制转换', 'category' => 'evasion'],
        'od'         => ['level' => 2, 'desc' => '八进制转储', 'category' => 'evasion'],
        'chmod'      => ['level' => 3, 'desc' => '权限修改', 'category' => 'privilege'],
        'chown'      => ['level' => 3, 'desc' => '所有权修改', 'category' => 'privilege'],
        'sudo'       => ['level' => 4, 'desc' => '提权命令', 'category' => 'privilege'],
        'su'         => ['level' => 4, 'desc' => '切换用户', 'category' => 'privilege'],
    ];

    private static $injectionSeparators = [
        ';'    => ['level' => 4, 'desc' => '命令分隔符'],
        '|'    => ['level' => 4, 'desc' => '管道符'],
        '||'   => ['level' => 3, 'desc' => '逻辑或'],
        '&&'   => ['level' => 3, 'desc' => '逻辑与'],
        '&'    => ['level' => 3, 'desc' => '后台执行'],
        '`'    => ['level' => 5, 'desc' => '命令替换(反引号)'],
        '$('   => ['level' => 5, 'desc' => '命令替换($())'],
        '${'   => ['level' => 4, 'desc' => '变量替换(${})'],
        "\n"   => ['level' => 4, 'desc' => '换行注入'],
        "\r"   => ['level' => 3, 'desc' => '回车注入'],
    ];

    private static $blindIndicators = [
        'sleep'         => ['level' => 3, 'pattern' => '/sleep\s+\d+/i', 'desc' => '时间盲注-Sleep'],
        'ping_loop'     => ['level' => 3, 'pattern' => '/ping\s+(-c\s+\d+\s+)?[\d\w\.\-]+\s*(&|\|\||;|$)/i', 'desc' => '时间盲注-Ping'],
        'dns_lookup'    => ['level' => 4, 'pattern' => '/(nslookup|dig|host)\s+[\w\.\-]+\.(burpcollaborator|ceye|interactsh)/i', 'desc' => 'DNS外带'],
    ];

    private static $evasionPatterns = [
        'base64_decode'  => ['level' => 4, 'pattern' => '/base64\s+-d/', 'desc' => 'Base64解码执行'],
        'hex_decode'     => ['level' => 3, 'pattern' => '/echo\s+[0-9a-fA-F]+\s*\|\s*xxd\s+-r/', 'desc' => '十六进制解码执行'],
        'wildcard_cmd'   => ['level' => 2, 'pattern' => '/\/[a-z\?\*]+\s+\//i', 'desc' => '通配符命令绕过'],
        'path_traversal' => ['level' => 2, 'pattern' => '/\.\.\//', 'desc' => '路径遍历命令参数'],
        'env_variable'   => ['level' => 2, 'pattern' => '/\$\{[A-Z_]+\}/', 'desc' => '环境变量替换'],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $originalInput = $input;

        $decodeResult = self::decodeInput($input);
        $decodedInput = $decodeResult['decoded'];
        $decodeDepth = $decodeResult['depth'];
        $encodeTypes = $decodeResult['encode_types'];

        $commands = self::splitCommands($decodedInput);
        $commandCount = count($commands);

        $dangerousCommandsFound = [];
        $maxCmdLevel = 0;
        $categories = [];
        foreach ($commands as $cmd) {
            $cmdInfo = self::analyzeSingleCommand($cmd);
            if (!empty($cmdInfo['command'])) {
                $dangerousCommandsFound[] = $cmdInfo;
                if ($cmdInfo['level'] > $maxCmdLevel) $maxCmdLevel = $cmdInfo['level'];
                if (!in_array($cmdInfo['category'], $categories)) $categories[] = $cmdInfo['category'];
            }
        }

        $separatorsFound = self::detectSeparators($decodedInput);
        $maxSepLevel = 0;
        foreach ($separatorsFound as $sep) {
            if ($sep['level'] > $maxSepLevel) $maxSepLevel = $sep['level'];
        }

        $blindHits = self::detectBlindIndicators($decodedInput);
        $evasionHits = self::detectEvasionPatterns($decodedInput);

        $hasCommandSubstitution = self::detectCommandSubstitution($originalInput) || self::detectCommandSubstitution($decodedInput);
        $hasWildcardBypass = self::detectWildcardBypass($decodedInput);
        $hasStringConcatenation = self::detectStringConcatenation($decodedInput);

        $score = 0;
        $indicators = [];

        if ($commandCount >= 4) { $score += 15; $indicators[] = 'multi_command_chain'; }
        elseif ($commandCount >= 3) { $score += 10; $indicators[] = 'triple_command'; }
        elseif ($commandCount >= 2) { $score += 6; $indicators[] = 'double_command'; }

        if ($maxCmdLevel >= 5) { $score += 30; $indicators[] = 'critical_command'; }
        elseif ($maxCmdLevel >= 4) { $score += 22; $indicators[] = 'high_command'; }
        elseif ($maxCmdLevel >= 3) { $score += 14; $indicators[] = 'medium_command'; }
        elseif ($maxCmdLevel >= 2) { $score += 8; $indicators[] = 'low_command'; }

        if (!empty($dangerousCommandsFound) && $commandCount > 1) {
            $score += 10;
            $indicators[] = 'piped_dangerous_command';
        }

        if ($maxSepLevel >= 5) { $score += 25; $indicators[] = 'command_substitution'; }
        elseif ($maxSepLevel >= 4) { $score += 18; $indicators[] = 'command_separator_high'; }
        elseif ($maxSepLevel >= 3) { $score += 10; $indicators[] = 'command_separator_medium'; }

        if ($hasCommandSubstitution && $maxCmdLevel >= 3) {
            $score += 12;
            $indicators[] = 'substitution_plus_command_combo';
        }

        $maxBlindLevel = 0;
        foreach ($blindHits as $hit) {
            if ($hit['level'] > $maxBlindLevel) $maxBlindLevel = $hit['level'];
        }
        if ($maxBlindLevel >= 4) { $score += 20; $indicators[] = 'dns_out_of_band'; }
        elseif ($maxBlindLevel >= 3) { $score += 14; $indicators[] = 'blind_injection'; }

        if (!empty($evasionHits)) {
            foreach ($evasionHits as $ev) {
                if ($ev['level'] >= 4) $score += 15;
                elseif ($ev['level'] >= 3) $score += 10;
                else $score += 5;
                $indicators[] = $ev['key'];
            }
        }

        if ($hasWildcardBypass) { $score += 8; $indicators[] = 'wildcard_bypass'; }
        if ($hasStringConcatenation) { $score += 6; $indicators[] = 'string_concat_bypass'; }

        if ($decodeDepth >= 3) { $score += 18; $indicators[] = 'multi_layer_encoding'; }
        elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
        elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

        if (in_array('shell', $categories) && in_array('download', $categories)) {
            $score += 15;
            $indicators[] = 'download_and_execute';
        }
        if (in_array('destructive', $categories)) {
            $score += 10;
            $indicators[] = 'destructive_command';
        }
        if (in_array('privilege', $categories) && $maxCmdLevel >= 4) {
            $score += 10;
            $indicators[] = 'privilege_escalation';
        }

        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        return [
            'score'                  => min(100, $score),
            'risk_level'             => $riskLevel,
            'is_command_injection'   => $score >= 20,
            'command_count'          => $commandCount,
            'decode_depth'           => $decodeDepth,
            'encode_types'           => $encodeTypes,
            'dangerous_commands'     => $dangerousCommandsFound,
            'separators'             => $separatorsFound,
            'categories'             => $categories,
            'blind_indicators'       => $blindHits,
            'evasion_patterns'       => $evasionHits,
            'has_command_substitution' => $hasCommandSubstitution,
            'has_wildcard_bypass'    => $hasWildcardBypass,
            'has_string_concat'      => $hasStringConcatenation,
            'normalized_commands'    => array_slice($commands, 0, 5),
            'indicators'             => $indicators,
        ];
    }

    private static function defaultResult(): array {
        return [
            'score'                  => 0,
            'risk_level'             => 'clean',
            'is_command_injection'   => false,
            'command_count'          => 0,
            'decode_depth'           => 0,
            'encode_types'           => [],
            'dangerous_commands'     => [],
            'separators'             => [],
            'categories'             => [],
            'blind_indicators'       => [],
            'evasion_patterns'       => [],
            'has_command_substitution' => false,
            'has_wildcard_bypass'    => false,
            'has_string_concat'      => false,
            'normalized_commands'    => [],
            'indicators'             => [],
        ];
    }

    private static function decodeInput(string $input): array {
        $depth = 0;
        $encodeTypes = [];
        $current = $input;

        for ($i = 0; $i < 4; $i++) {
            $decoded = $current;

            if (preg_match('/%[0-9a-fA-F]{2}/', $decoded)) {
                $decoded = urldecode($decoded);
                $encodeTypes[] = 'url';
            }

            if ($decoded === $current) break;
            $depth++;
            $current = $decoded;
        }

        return [
            'decoded'      => $current,
            'depth'        => $depth,
            'encode_types' => array_unique($encodeTypes),
        ];
    }

    private static function splitCommands(string $input): array {
        $commands = [];
        $parts = preg_split('/[;\|\&\n\r]+/', $input, -1, PREG_SPLIT_NO_EMPTY);

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') continue;

            if (preg_match('/^\s*`([^`]+)`/', $part, $m)) {
                $commands[] = trim($m[1]);
                $part = trim(substr($part, strlen($m[0])));
            }
            if (preg_match('/^\s*\$\(([^)]+)\)/', $part, $m)) {
                $commands[] = trim($m[1]);
                $part = trim(substr($part, strlen($m[0])));
            }

            if ($part !== '') {
                $commands[] = $part;
            }
        }

        return array_values(array_unique($commands));
    }

    private static function analyzeSingleCommand(string $cmdStr): array {
        $cmdStr = trim($cmdStr);
        if ($cmdStr === '') return [];

        if (preg_match('/^([a-zA-Z0-9_\-\/\.]+)/', $cmdStr, $m)) {
            $cmdName = $m[1];
            $cmdBase = basename($cmdName);

            if (isset(self::$dangerousCommands[$cmdBase])) {
                $info = self::$dangerousCommands[$cmdBase];
                return [
                    'command'  => $cmdBase,
                    'full'     => substr($cmdStr, 0, 100),
                    'level'    => $info['level'],
                    'category' => $info['category'],
                    'desc'     => $info['desc'],
                ];
            }

            if (self::isWildcardCommand($cmdBase)) {
                return [
                    'command'  => $cmdBase,
                    'full'     => substr($cmdStr, 0, 100),
                    'level'    => 2,
                    'category' => 'evasion',
                    'desc'     => '通配符命令',
                ];
            }
        }

        return [];
    }

    private static function detectSeparators(string $input): array {
        $found = [];

        foreach (self::$injectionSeparators as $sep => $info) {
            if (strpos($input, $sep) !== false) {
                $count = substr_count($input, $sep);
                $found[] = [
                    'separator' => $sep,
                    'level'     => $info['level'],
                    'desc'      => $info['desc'],
                    'count'     => $count,
                ];
            }
        }

        usort($found, function($a, $b) { return $b['level'] - $a['level']; });
        return $found;
    }

    private static function detectBlindIndicators(string $input): array {
        $hits = [];
        foreach (self::$blindIndicators as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $hits[] = [
                    'key'   => $key,
                    'level' => $info['level'],
                    'desc'  => $info['desc'],
                ];
            }
        }
        return $hits;
    }

    private static function detectEvasionPatterns(string $input): array {
        $hits = [];
        foreach (self::$evasionPatterns as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $hits[] = [
                    'key'   => $key,
                    'level' => $info['level'],
                    'desc'  => $info['desc'],
                ];
            }
        }
        return $hits;
    }

    private static function detectCommandSubstitution(string $input): bool {
        if (strpos($input, '`') !== false) return true;
        if (strpos($input, '$(') !== false) return true;
        if (preg_match('/\$\{[^}]+\}/', $input)) return true;
        return false;
    }

    private static function detectWildcardBypass(string $input): bool {
        if (preg_match('/\/[a-zA-Z]*\?[a-zA-Z]*\//', $input)) return true;
        if (preg_match('/\/[a-zA-Z]*\*[a-zA-Z]*\//', $input)) return true;
        return false;
    }

    private static function detectStringConcatenation(string $input): bool {
        if (preg_match('/["\']\s*\+\s*["\']/', $input)) return true;
        if (preg_match('/\.\s*["\']/', $input)) return true;
        return false;
    }

    private static function isWildcardCommand(string $cmd): bool {
        if (preg_match('/^[a-z]*\?[a-z]*$/', $cmd)) return true;
        if (preg_match('/^[a-z]*\*[a-z]*$/', $cmd)) return true;
        return false;
    }
}
