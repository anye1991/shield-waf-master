<?php
/**
 * 命令注入语义解析器
 * 职责：通过Shell命令AST解析真正理解命令结构，
 *       包括词法分析(Tokenizer)、语法分析(Parser)、语义分析(AST Walker)，
 *       识别命令注入意图，而非简单的关键词匹配。
 */
defined('ABSPATH') || exit;

class CommandInjectionSemanticParser {

    const TOK_CMD        = 'CMD';
    const TOK_ARG        = 'ARG';
    const TOK_STRING     = 'STRING';
    const TOK_PIPE       = 'PIPE';
    const TOK_AND_IF     = 'AND_IF';
    const TOK_OR_IF      = 'OR_IF';
    const TOK_SEMI       = 'SEMI';
    const TOK_BG         = 'BG';
    const TOK_REDIRECT   = 'REDIRECT';
    const TOK_SUB_OPEN   = 'SUB_OPEN';
    const TOK_SUB_CLOSE  = 'SUB_CLOSE';
    const TOK_BTICK      = 'BTICK';
    const TOK_VAR        = 'VAR';
    const TOK_NEWLINE    = 'NEWLINE';
    const TOK_BRACE      = 'BRACE';
    const TOK_EOF        = 'EOF';

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
        'ssh'        => ['level' => 3, 'desc' => '远程登录', 'category' => 'network'],
        'telnet'     => ['level' => 3, 'desc' => '远程登录', 'category' => 'network'],
        'crontab'    => ['level' => 3, 'desc' => '定时任务', 'category' => 'persistence'],
        'history'    => ['level' => 2, 'desc' => '历史记录', 'category' => 'anti_forensics'],
        'shred'      => ['level' => 4, 'desc' => '安全删除', 'category' => 'anti_forensics'],
        'chattr'     => ['level' => 3, 'desc' => '文件属性', 'category' => 'privilege'],
        'passwd'     => ['level' => 3, 'desc' => '修改密码', 'category' => 'privilege'],
        'useradd'    => ['level' => 4, 'desc' => '添加用户', 'category' => 'privilege'],
        'usermod'    => ['level' => 4, 'desc' => '修改用户', 'category' => 'privilege'],
        'groupadd'   => ['level' => 3, 'desc' => '添加组', 'category' => 'privilege'],
        'grep'       => ['level' => 2, 'desc' => '文本搜索', 'category' => 'search'],
        'awk'        => ['level' => 3, 'desc' => '文本处理', 'category' => 'script'],
        'sed'        => ['level' => 3, 'desc' => '文本替换', 'category' => 'script'],
        'cut'        => ['level' => 2, 'desc' => '文本切割', 'category' => 'utility'],
        'sort'       => ['level' => 1, 'desc' => '排序', 'category' => 'utility'],
        'uniq'       => ['level' => 1, 'desc' => '去重', 'category' => 'utility'],
        'wc'         => ['level' => 1, 'desc' => '统计', 'category' => 'utility'],
        'tee'        => ['level' => 2, 'desc' => '读写分流', 'category' => 'utility'],
        'mkdir'      => ['level' => 2, 'desc' => '创建目录', 'category' => 'utility'],
        'touch'      => ['level' => 1, 'desc' => '创建文件', 'category' => 'utility'],
        'cp'         => ['level' => 2, 'desc' => '复制文件', 'category' => 'utility'],
        'mv'         => ['level' => 2, 'desc' => '移动文件', 'category' => 'utility'],
        'ln'         => ['level' => 2, 'desc' => '链接文件', 'category' => 'utility'],
        'tar'        => ['level' => 2, 'desc' => '打包压缩', 'category' => 'utility'],
        'gzip'       => ['level' => 2, 'desc' => '压缩', 'category' => 'utility'],
        'gunzip'     => ['level' => 2, 'desc' => '解压', 'category' => 'utility'],
        'unzip'      => ['level' => 2, 'desc' => '解压', 'category' => 'utility'],
        'iptables'   => ['level' => 4, 'desc' => '防火墙', 'category' => 'network'],
        'ifconfig'   => ['level' => 2, 'desc' => '网络配置', 'category' => 'enumeration'],
        'ip'         => ['level' => 2, 'desc' => '网络配置', 'category' => 'enumeration'],
        'netstat'    => ['level' => 2, 'desc' => '网络状态', 'category' => 'enumeration'],
        'ss'         => ['level' => 2, 'desc' => '套接字状态', 'category' => 'enumeration'],
        'ps'         => ['level' => 2, 'desc' => '进程查看', 'category' => 'enumeration'],
        'top'        => ['level' => 2, 'desc' => '进程监控', 'category' => 'enumeration'],
        'df'         => ['level' => 1, 'desc' => '磁盘使用', 'category' => 'enumeration'],
        'du'         => ['level' => 1, 'desc' => '目录大小', 'category' => 'enumeration'],
        'free'       => ['level' => 1, 'desc' => '内存使用', 'category' => 'enumeration'],
        'uptime'     => ['level' => 1, 'desc' => '运行时间', 'category' => 'enumeration'],
        'date'       => ['level' => 1, 'desc' => '日期时间', 'category' => 'utility'],
        'hostname'   => ['level' => 1, 'desc' => '主机名', 'category' => 'enumeration'],
        'env'        => ['level' => 2, 'desc' => '环境变量', 'category' => 'enumeration'],
        'set'        => ['level' => 2, 'desc' => '设置变量', 'category' => 'utility'],
        'export'     => ['level' => 2, 'desc' => '导出变量', 'category' => 'utility'],
        'source'     => ['level' => 3, 'desc' => '加载脚本', 'category' => 'shell'],
        '.'          => ['level' => 3, 'desc' => '加载脚本', 'category' => 'shell'],
        'nohup'      => ['level' => 2, 'desc' => '后台运行', 'category' => 'utility'],
        'disown'     => ['level' => 2, 'desc' => '脱离终端', 'category' => 'utility'],
        'kill'       => ['level' => 3, 'desc' => '杀死进程', 'category' => 'destructive'],
        'killall'    => ['level' => 3, 'desc' => '批量杀进程', 'category' => 'destructive'],
        'pkill'      => ['level' => 3, 'desc' => '模式杀进程', 'category' => 'destructive'],
    ];

    private static $attackIntentPatterns = [
        'info_gathering' => [
            'name' => '信息收集',
            'level' => 2,
            'commands' => ['id', 'whoami', 'uname', 'pwd', 'ls', 'cat', 'head', 'tail', 'find', 'ps', 'netstat', 'ss', 'ifconfig', 'ip', 'df', 'du', 'free', 'uptime', 'hostname', 'env', 'date', 'more', 'less', 'grep', 'cut', 'sort', 'uniq', 'wc'],
            'sensitive_files' => ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/hosts', '/etc/hostname', '/proc/self/environ', '/proc/cpuinfo', '/proc/meminfo', '/proc/version', '/root/.bash_history', '/root/.ssh/id_rsa', '~/.ssh/', '~/.bashrc'],
            'combo_patterns' => [
                ['cat', 'grep'],
                ['cat', 'head'],
                ['cat', 'tail'],
                ['find', 'grep'],
                ['ls', 'grep'],
                ['ps', 'grep'],
                ['netstat', 'grep'],
            ],
        ],
        'download_execute' => [
            'name' => '下载执行',
            'level' => 5,
            'commands' => ['wget', 'curl'],
            'executors' => ['bash', 'sh', 'zsh', 'python', 'perl', 'php', 'ruby'],
            'combo_patterns' => [
                ['wget', 'bash'],
                ['wget', 'sh'],
                ['curl', 'bash'],
                ['curl', 'sh'],
                ['wget', 'python'],
                ['curl', 'python'],
                ['wget', 'perl'],
                ['curl', 'perl'],
            ],
            'indicators' => ['-O', '-o', '|', '&&', ';'],
        ],
        'persistence' => [
            'name' => '持久化',
            'level' => 4,
            'commands' => ['chmod', 'crontab', 'echo', 'tee', 'cp', 'mv', 'ln', 'chattr'],
            'persistence_files' => ['~/.bashrc', '~/.bash_profile', '~/.profile', '~/.zshrc', '/etc/profile', '/etc/bash.bashrc', '/etc/cron.d/', '/etc/crontab', '/etc/init.d/', '/etc/systemd/system/'],
            'combo_patterns' => [
                ['echo', '>>'],
                ['tee', '-a'],
                ['chmod', '+x'],
                ['crontab', '-e'],
                ['cp', '/etc/init.d/'],
            ],
        ],
        'lateral_movement' => [
            'name' => '横向移动',
            'level' => 4,
            'commands' => ['ssh', 'nc', 'netcat', 'telnet', 'curl', 'wget'],
            'indicators' => ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.0.0.1', 'localhost'],
            'combo_patterns' => [
                ['ssh', '-p'],
                ['nc', '-e'],
                ['nc', '-lvp'],
                ['netcat', '-e'],
                ['telnet', '-l'],
            ],
        ],
        'privilege_escalation' => [
            'name' => '权限提升',
            'level' => 5,
            'commands' => ['sudo', 'su', 'chmod', 'chown', 'chattr', 'passwd', 'useradd', 'usermod', 'groupadd'],
            'indicators' => ['u+s', 'g+s', '4777', '777', '+x', '-u', '-g', '-aG', 'wheel', 'sudo', 'root'],
            'combo_patterns' => [
                ['sudo', 'su'],
                ['sudo', 'bash'],
                ['su', 'root'],
                ['chmod', 'u+s'],
                ['chmod', '4777'],
                ['usermod', '-aG', 'sudo'],
                ['usermod', '-aG', 'wheel'],
            ],
        ],
        'anti_forensics' => [
            'name' => '痕迹清除',
            'level' => 4,
            'commands' => ['rm', 'shred', 'history', 'echo', 'cat', 'dd'],
            'targets' => ['~/.bash_history', '/root/.bash_history', '/var/log/', 'history'],
            'combo_patterns' => [
                ['rm', '-rf'],
                ['history', '-c'],
                ['history', '-w'],
                ['echo', '>', 'history'],
                ['shred', '-u'],
                ['cat', '/dev/null', '>'],
                ['dd', '/dev/null'],
            ],
        ],
        'evasion' => [
            'name' => '逃逸绕过',
            'level' => 3,
            'commands' => ['base64', 'xxd', 'od', 'python', 'perl', 'php', 'ruby', 'bash', 'sh'],
            'indicators' => ['-d', '--decode', '-e', '-c', 'eval', 'exec', 'system', 'passthru', 'shell_exec'],
            'combo_patterns' => [
                ['base64', '-d'],
                ['base64', '--decode'],
                ['python', '-c'],
                ['perl', '-e'],
                ['php', '-r'],
                ['bash', '-c'],
                ['sh', '-c'],
            ],
        ],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $decoded = self::decodeInput($input);
        $result['decode_depth'] = $decoded['depth'];
        $result['encode_types'] = $decoded['encode_types'];

        try {
            $tokens = self::tokenize($decoded['decoded']);
            $result['token_count'] = count($tokens);

            $ast = self::parse($tokens);
            $result['ast'] = self::summarizeAst($ast);
            $result['parser_used'] = 'ast';

            $analysis = self::analyzeAst($ast);
            $result = array_merge($result, $analysis);

            $result['pipeline_analysis'] = self::analyzePipelineDataFlow($ast);
            $result['pipeline_depth'] = $result['pipeline_analysis']['max_pipeline_depth'];
            $result['max_pipeline_depth'] = $result['pipeline_analysis']['max_pipeline_depth'];

            $result['attack_intent'] = self::inferAttackIntent($ast, $result);

            $result['bypass_techniques'] = self::detectBypassTechniques($decoded['decoded'], $ast);
            foreach ($result['bypass_techniques'] as $bt) {
                $alreadyHas = false;
                foreach ($result['evasion_patterns'] as $ep) {
                    if (isset($ep['key']) && $ep['key'] === $bt['key']) {
                        $alreadyHas = true;
                        break;
                    }
                }
                if (!$alreadyHas) {
                    $result['evasion_patterns'][] = [
                        'key'   => $bt['key'],
                        'level' => $bt['level'],
                        'desc'  => $bt['name'] . ': ' . $bt['desc'],
                    ];
                }
            }

        } catch (Throwable $e) {
            $result['parser_used'] = 'regex_fallback';
            $fallback = self::regexFallback($decoded['decoded']);
            $result = array_merge($result, $fallback);

            $result['bypass_techniques'] = self::detectBypassTechniques($decoded['decoded'], ['type' => 'unknown']);
            foreach ($result['bypass_techniques'] as $bt) {
                $result['evasion_patterns'][] = [
                    'key'   => $bt['key'],
                    'level' => $bt['level'],
                    'desc'  => $bt['name'] . ': ' . $bt['desc'],
                ];
            }
        }

        $score = self::calculateScore($result);
        $result['score'] = min(100, $score);
        $result['risk_level'] = self::calcRiskLevel($result['score']);
        $result['is_command_injection'] = $result['score'] >= 20;

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'                    => 0,
            'risk_level'               => 'clean',
            'is_command_injection'     => false,
            'command_count'            => 0,
            'decode_depth'             => 0,
            'encode_types'             => [],
            'dangerous_commands'       => [],
            'separators'               => [],
            'categories'               => [],
            'blind_indicators'         => [],
            'evasion_patterns'         => [],
            'has_command_substitution' => false,
            'has_wildcard_bypass'      => false,
            'has_string_concat'        => false,
            'normalized_commands'      => [],
            'indicators'               => [],
            'parser_used'              => 'ast',
            'token_count'              => 0,
            'ast'                      => [],
            'pipeline_depth'           => 0,
            'max_pipeline_depth'       => 0,
            'has_dangerous_redirect'   => false,
            'subshell_count'           => 0,
            'max_cmd_level'            => 0,
            'max_sep_level'            => 0,
            'pipeline_analysis'        => [
                'data_flow'            => [],
                'chain_depth'          => 0,
                'max_pipeline_depth'   => 0,
                'pipeline_count'       => 0,
                'dangerous_pipelines'  => [],
            ],
            'attack_intent'            => [
                'intents'              => [],
                'confidence'           => 0.0,
                'primary_intent'       => null,
                'intent_details'       => [],
            ],
            'bypass_techniques'        => [],
        ];
    }

    // ==================== 词法分析 Tokenizer ====================

    private static function tokenize(string $input): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($input);

        while ($pos < $len) {
            $char = $input[$pos];

            if ($char === ' ' || $char === "\t") {
                $pos++;
                continue;
            }

            if ($char === "\n" || $char === "\r") {
                $tokens[] = ['type' => self::TOK_NEWLINE, 'value' => $char, 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === ';' ) {
                $tokens[] = ['type' => self::TOK_SEMI, 'value' => ';', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '|') {
                if ($pos + 1 < $len && $input[$pos + 1] === '|') {
                    $tokens[] = ['type' => self::TOK_OR_IF, 'value' => '||', 'pos' => $pos];
                    $pos += 2;
                } else {
                    $tokens[] = ['type' => self::TOK_PIPE, 'value' => '|', 'pos' => $pos];
                    $pos++;
                }
                continue;
            }

            if ($char === '&') {
                if ($pos + 1 < $len && $input[$pos + 1] === '&') {
                    $tokens[] = ['type' => self::TOK_AND_IF, 'value' => '&&', 'pos' => $pos];
                    $pos += 2;
                } else {
                    $tokens[] = ['type' => self::TOK_BG, 'value' => '&', 'pos' => $pos];
                    $pos++;
                }
                continue;
            }

            if ($char === '`') {
                $tokens[] = ['type' => self::TOK_BTICK, 'value' => '`', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '$' && $pos + 1 < $len) {
                if ($input[$pos + 1] === '(') {
                    $tokens[] = ['type' => self::TOK_SUB_OPEN, 'value' => '$(', 'pos' => $pos];
                    $pos += 2;
                    continue;
                }
                if ($input[$pos + 1] === '{') {
                    $end = strpos($input, '}', $pos + 2);
                    if ($end !== false) {
                        $varName = substr($input, $pos + 2, $end - $pos - 2);
                        $tokens[] = ['type' => self::TOK_VAR, 'value' => '${' . $varName . '}', 'pos' => $pos];
                        $pos = $end + 1;
                        continue;
                    }
                }
            }

            if ($char === ')') {
                $tokens[] = ['type' => self::TOK_SUB_CLOSE, 'value' => ')', 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === '>' || $char === '<') {
                $redirect = $char;
                $pos++;
                while ($pos < $len && ($input[$pos] === '>' || $input[$pos] === '<' || $input[$pos] === '&')) {
                    $redirect .= $input[$pos];
                    $pos++;
                }
                $tokens[] = ['type' => self::TOK_REDIRECT, 'value' => $redirect, 'pos' => $pos - strlen($redirect)];
                continue;
            }

            if (is_numeric($char) && $pos + 1 < $len && ($input[$pos + 1] === '>' || $input[$pos + 1] === '<')) {
                $fd = $char;
                $pos++;
                $redirect = $input[$pos];
                $pos++;
                while ($pos < $len && ($input[$pos] === '>' || $input[$pos] === '<' || $input[$pos] === '&')) {
                    $redirect .= $input[$pos];
                    $pos++;
                }
                $tokens[] = ['type' => self::TOK_REDIRECT, 'value' => $fd . $redirect, 'pos' => $pos - strlen($fd . $redirect)];
                continue;
            }

            if ($char === "'" || $char === '"') {
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
                    'type'   => self::TOK_STRING,
                    'value'  => $value,
                    'raw'    => substr($input, $start, $pos - $start),
                    'quote'  => $quote,
                    'pos'    => $start,
                ];
                continue;
            }

            if ($char === '$' && $pos + 1 < $len && (ctype_alpha($input[$pos + 1]) || $input[$pos + 1] === '_')) {
                $start = $pos;
                $pos++;
                while ($pos < $len && (ctype_alnum($input[$pos]) || $input[$pos] === '_')) {
                    $pos++;
                }
                $tokens[] = ['type' => self::TOK_VAR, 'value' => substr($input, $start, $pos - $start), 'pos' => $start];
                continue;
            }

            $start = $pos;
            $word = '';
            while ($pos < $len) {
                $c = $input[$pos];
                if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r" ||
                    $c === ';' || $c === '|' || $c === '&' || $c === '`' ||
                    $c === '>' || $c === '<' || $c === '(' || $c === ')' ||
                    $c === "'" || $c === '"') {
                    break;
                }
                if ($c === '$') {
                    break;
                }
                $word .= $c;
                $pos++;
            }
            if ($word !== '') {
                $type = (empty($tokens) || end($tokens)['type'] === self::TOK_SEMI ||
                         end($tokens)['type'] === self::TOK_PIPE ||
                         end($tokens)['type'] === self::TOK_AND_IF ||
                         end($tokens)['type'] === self::TOK_OR_IF ||
                         end($tokens)['type'] === self::TOK_BG ||
                         end($tokens)['type'] === self::TOK_BTICK ||
                         end($tokens)['type'] === self::TOK_SUB_OPEN ||
                         end($tokens)['type'] === self::TOK_NEWLINE)
                    ? self::TOK_CMD
                    : self::TOK_ARG;
                $tokens[] = ['type' => $type, 'value' => $word, 'pos' => $start];
            }

            if ($pos === $start) {
                $tokens[] = ['type' => 'UNKNOWN', 'value' => $char, 'pos' => $pos];
                $pos++;
            }
        }

        $tokens[] = ['type' => self::TOK_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    // ==================== 语法分析 Parser（递归下降） ====================

    private static function parse(array $tokens): array {
        $state = ['tokens' => $tokens, 'pos' => 0];
        return self::parseCommandList($state);
    }

    private static function parseCommandList(array &$state): array {
        $commands = [];
        $separators = [];

        while (!self::isEof($state)) {
            $pipeline = self::parsePipeline($state);
            if ($pipeline !== null) {
                $commands[] = $pipeline;
            }

            $tok = self::current($state);
            if ($tok['type'] === self::TOK_SEMI || $tok['type'] === self::TOK_NEWLINE ||
                $tok['type'] === self::TOK_AND_IF || $tok['type'] === self::TOK_OR_IF ||
                $tok['type'] === self::TOK_BG) {
                $separators[] = $tok;
                self::next($state);
            } elseif ($tok['type'] === self::TOK_EOF) {
                break;
            } elseif ($tok['type'] === self::TOK_SUB_CLOSE) {
                break;
            } elseif ($tok['type'] === self::TOK_BTICK) {
                break;
            } else {
                self::next($state);
            }
        }

        return [
            'type'       => 'command_list',
            'commands'   => $commands,
            'separators' => $separators,
            'command_count' => count($commands),
        ];
    }

    private static function parsePipeline(array &$state): ?array {
        $cmds = [];

        $cmd = self::parseSimpleCommand($state);
        if ($cmd === null) return null;
        $cmds[] = $cmd;

        while (self::current($state)['type'] === self::TOK_PIPE) {
            self::next($state);
            $nextCmd = self::parseSimpleCommand($state);
            if ($nextCmd !== null) {
                $cmds[] = $nextCmd;
            }
        }

        if (count($cmds) === 1) {
            return $cmds[0];
        }

        return [
            'type'          => 'pipeline',
            'commands'      => $cmds,
            'depth'         => count($cmds),
            'has_pipe'      => true,
        ];
    }

    private static function parseSimpleCommand(array &$state): ?array {
        $cmd = null;
        $args = [];
        $redirects = [];
        $hasSubstitution = false;
        $isWildcard = false;

        while (!self::isEof($state)) {
            $tok = self::current($state);

            if ($tok['type'] === self::TOK_CMD) {
                $cmd = $tok['value'];
                if (self::isWildcardPattern($cmd)) $isWildcard = true;
                self::next($state);
                continue;
            }

            if ($tok['type'] === self::TOK_ARG || $tok['type'] === self::TOK_STRING || $tok['type'] === self::TOK_VAR) {
                if ($cmd === null && $tok['type'] === self::TOK_ARG) {
                    $cmd = $tok['value'];
                    if (self::isWildcardPattern($cmd)) $isWildcard = true;
                    self::next($state);
                    continue;
                }
                $args[] = $tok;
                if ($tok['type'] === self::TOK_VAR || $tok['type'] === self::TOK_STRING) {
                    if (self::isWildcardPattern($tok['value'])) $isWildcard = true;
                }
                self::next($state);
                continue;
            }

            if ($tok['type'] === self::TOK_REDIRECT) {
                $redirects[] = $tok;
                self::next($state);
                if (!self::isEof($state) &&
                    (self::current($state)['type'] === self::TOK_ARG ||
                     self::current($state)['type'] === self::TOK_STRING ||
                     self::current($state)['type'] === self::TOK_VAR)) {
                    $redirects[] = ['type' => 'redirect_target', 'value' => self::current($state)['value']];
                    self::next($state);
                }
                continue;
            }

            if ($tok['type'] === self::TOK_SUB_OPEN) {
                $hasSubstitution = true;
                self::next($state);
                $subAst = self::parseCommandList($state);
                if (self::current($state)['type'] === self::TOK_SUB_CLOSE) {
                    self::next($state);
                }
                $args[] = ['type' => 'substitution', 'ast' => $subAst];
                continue;
            }

            if ($tok['type'] === self::TOK_BTICK) {
                $hasSubstitution = true;
                self::next($state);
                $subAst = self::parseCommandList($state);
                if (self::current($state)['type'] === self::TOK_BTICK) {
                    self::next($state);
                }
                $args[] = ['type' => 'backtick_substitution', 'ast' => $subAst];
                continue;
            }

            break;
        }

        if ($cmd === null && empty($args)) return null;

        return [
            'type'               => 'simple_command',
            'command'            => $cmd,
            'command_base'       => $cmd ? basename($cmd) : null,
            'args'               => $args,
            'arg_count'          => count($args),
            'redirects'          => $redirects,
            'has_substitution'   => $hasSubstitution,
            'has_wildcard'       => $isWildcard,
        ];
    }

    // ==================== 语义分析 AST Walker ====================

    private static function analyzeAst(array $ast): array {
        $result = [
            'dangerous_commands'       => [],
            'categories'               => [],
            'separators'               => [],
            'command_count'            => 0,
            'has_command_substitution' => false,
            'has_wildcard_bypass'      => false,
            'has_string_concat'        => false,
            'normalized_commands'      => [],
            'blind_indicators'         => [],
            'evasion_patterns'         => [],
            'indicators'               => [],
            'pipeline_depth'           => 0,
            'max_pipeline_depth'       => 0,
            'has_dangerous_redirect'   => false,
            'subshell_count'           => 0,
            'max_cmd_level'            => 0,
            'max_sep_level'            => 0,
        ];

        self::walkAst($ast, $result, 0);
        return $result;
    }

    private static function walkAst(array $node, array &$result, int $depth) {
        if (!isset($node['type'])) return;

        switch ($node['type']) {
            case 'command_list':
                $result['command_count'] += $node['command_count'] ?? 0;
                foreach ($node['commands'] ?? [] as $cmd) {
                    self::walkAst($cmd, $result, $depth + 1);
                }
                foreach ($node['separators'] ?? [] as $sep) {
                    $sepInfo = self::getSeparatorInfo($sep['value']);
                    if ($sepInfo) {
                        $result['separators'][] = $sepInfo;
                        if ($sepInfo['level'] > $result['max_sep_level']) {
                            $result['max_sep_level'] = $sepInfo['level'];
                        }
                    }
                }
                break;

            case 'pipeline':
                $pdepth = $node['depth'] ?? 0;
                if ($pdepth > $result['max_pipeline_depth']) {
                    $result['max_pipeline_depth'] = $pdepth;
                }
                foreach ($node['commands'] ?? [] as $cmd) {
                    self::walkAst($cmd, $result, $depth + 1);
                }
                break;

            case 'simple_command':
                $cmdBase = $node['command_base'] ?? null;
                if ($cmdBase && isset(self::$dangerousCommands[$cmdBase])) {
                    $info = self::$dangerousCommands[$cmdBase];
                    $result['dangerous_commands'][] = [
                        'command'  => $cmdBase,
                        'full'     => $cmdBase,
                        'level'    => $info['level'],
                        'category' => $info['category'],
                        'desc'     => $info['desc'],
                    ];
                    if ($info['level'] > $result['max_cmd_level']) {
                        $result['max_cmd_level'] = $info['level'];
                    }
                    if (!in_array($info['category'], $result['categories'])) {
                        $result['categories'][] = $info['category'];
                    }
                }

                if (!empty($cmdBase)) {
                    $result['normalized_commands'][] = $cmdBase;
                }

                if ($node['has_wildcard'] ?? false) {
                    $result['has_wildcard_bypass'] = true;
                }
                if ($node['has_substitution'] ?? false) {
                    $result['has_command_substitution'] = true;
                }

                if (!empty($node['redirects'])) {
                    foreach ($node['redirects'] as $r) {
                        if (isset($r['value']) && strpos($r['value'], '&') !== false) {
                            $result['has_dangerous_redirect'] = true;
                        }
                    }
                }

                foreach ($node['args'] ?? [] as $arg) {
                    if (is_array($arg) && isset($arg['ast'])) {
                        $result['subshell_count']++;
                        self::walkAst($arg['ast'], $result, $depth + 1);
                    }
                    if (is_array($arg) && isset($arg['value']) && is_string($arg['value'])) {
                        if (strpos($arg['value'], '..') !== false) {
                            $result['evasion_patterns'][] = ['key' => 'path_traversal', 'level' => 2, 'desc' => '路径遍历'];
                        }
                    }
                }

                if (strtolower($cmdBase) === 'sleep' && !empty($node['args'])) {
                    $result['blind_indicators'][] = ['key' => 'sleep', 'level' => 3, 'desc' => '时间盲注-Sleep'];
                }
                if (strtolower($cmdBase) === 'base64' && !empty($node['args'])) {
                    foreach ($node['args'] as $a) {
                        if (is_array($a) && isset($a['value']) && $a['value'] === '-d') {
                            $result['evasion_patterns'][] = ['key' => 'base64_decode', 'level' => 4, 'desc' => 'Base64解码执行'];
                            break;
                        }
                    }
                }

                break;
        }
    }

    // ==================== 辅助函数 ====================

    private static function isWildcardPattern(string $s): bool {
        return strpos($s, '*') !== false || strpos($s, '?') !== false;
    }

    private static function getSeparatorInfo(string $sep): ?array {
        $map = [
            ';'    => ['level' => 4, 'desc' => '命令分隔符', 'separator' => ';'],
            '|'    => ['level' => 4, 'desc' => '管道符', 'separator' => '|'],
            '||'   => ['level' => 3, 'desc' => '逻辑或', 'separator' => '||'],
            '&&'   => ['level' => 3, 'desc' => '逻辑与', 'separator' => '&&'],
            '&'    => ['level' => 3, 'desc' => '后台执行', 'separator' => '&'],
            "\n"   => ['level' => 4, 'desc' => '换行注入', 'separator' => "\n"],
            "\r"   => ['level' => 3, 'desc' => '回车注入', 'separator' => "\r"],
        ];
        return $map[$sep] ?? null;
    }

    private static function summarizeAst(array $ast): array {
        return [
            'type'              => $ast['type'] ?? 'unknown',
            'command_count'     => $ast['command_count'] ?? 0,
            'max_pipeline'      => $ast['max_pipeline_depth'] ?? 0,
        ];
    }

    private static function calculateScore(array $result): int {
        $score = 0;
        $indicators = [];

        $cc = $result['command_count'] ?? 0;
        if ($cc >= 4) { $score += 15; $indicators[] = 'multi_command_chain'; }
        elseif ($cc >= 3) { $score += 10; $indicators[] = 'triple_command'; }
        elseif ($cc >= 2) { $score += 6; $indicators[] = 'double_command'; }

        $maxCmd = $result['max_cmd_level'] ?? 0;
        if ($maxCmd >= 5) { $score += 30; $indicators[] = 'critical_command'; }
        elseif ($maxCmd >= 4) { $score += 22; $indicators[] = 'high_command'; }
        elseif ($maxCmd >= 3) { $score += 14; $indicators[] = 'medium_command'; }
        elseif ($maxCmd >= 2) { $score += 8; $indicators[] = 'low_command'; }

        $maxPipe = $result['max_pipeline_depth'] ?? 0;
        if ($maxPipe >= 4) { $score += 12; $indicators[] = 'deep_pipeline'; }
        elseif ($maxPipe >= 3) { $score += 8; $indicators[] = 'triple_pipe'; }
        elseif ($maxPipe >= 2) { $score += 5; $indicators[] = 'double_pipe'; }

        $maxSep = $result['max_sep_level'] ?? 0;
        if ($maxSep >= 5) { $score += 25; $indicators[] = 'command_substitution'; }
        elseif ($maxSep >= 4) { $score += 18; $indicators[] = 'command_separator_high'; }
        elseif ($maxSep >= 3) { $score += 10; $indicators[] = 'command_separator_medium'; }

        if (($result['has_command_substitution'] ?? false) && $maxCmd >= 3) {
            $score += 12;
            $indicators[] = 'substitution_plus_command_combo';
        }

        $blindCount = count($result['blind_indicators'] ?? []);
        $maxBlind = 0;
        foreach ($result['blind_indicators'] ?? [] as $b) {
            if ($b['level'] > $maxBlind) $maxBlind = $b['level'];
        }
        if ($maxBlind >= 4) { $score += 20; $indicators[] = 'dns_out_of_band'; }
        elseif ($maxBlind >= 3) { $score += 14; $indicators[] = 'blind_injection'; }

        $evasionCount = count($result['evasion_patterns'] ?? []);
        if ($evasionCount > 0) {
            foreach ($result['evasion_patterns'] as $ev) {
                if ($ev['level'] >= 4) $score += 15;
                elseif ($ev['level'] >= 3) $score += 10;
                else $score += 5;
                $indicators[] = $ev['key'];
            }
        }

        if ($result['has_wildcard_bypass'] ?? false) { $score += 8; $indicators[] = 'wildcard_bypass'; }
        if ($result['has_dangerous_redirect'] ?? false) { $score += 8; $indicators[] = 'dangerous_redirect'; }
        if (($result['subshell_count'] ?? 0) >= 2) { $score += 10; $indicators[] = 'nested_subshell'; }

        $decodeDepth = $result['decode_depth'] ?? 0;
        if ($decodeDepth >= 3) { $score += 18; $indicators[] = 'multi_layer_encoding'; }
        elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
        elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

        $cats = $result['categories'] ?? [];
        if (in_array('shell', $cats) && in_array('download', $cats)) {
            $score += 15;
            $indicators[] = 'download_and_execute';
        }
        if (in_array('destructive', $cats)) {
            $score += 10;
            $indicators[] = 'destructive_command';
        }
        if (in_array('privilege', $cats) && $maxCmd >= 4) {
            $score += 10;
            $indicators[] = 'privilege_escalation';
        }

        if ($result['parser_used'] === 'ast') {
            $score += 0;
        }

        $dangerousPipelines = $result['pipeline_analysis']['dangerous_pipelines'] ?? [];
        if (!empty($dangerousPipelines)) {
            foreach ($dangerousPipelines as $dp) {
                $risk = $dp['risk_level'] ?? 'low';
                switch ($risk) {
                    case 'critical':
                        $score += 25;
                        $indicators[] = 'critical_pipeline';
                        break;
                    case 'high':
                        $score += 18;
                        $indicators[] = 'high_risk_pipeline';
                        break;
                    case 'medium':
                        $score += 10;
                        $indicators[] = 'medium_risk_pipeline';
                        break;
                    default:
                        $score += 5;
                        $indicators[] = 'low_risk_pipeline';
                        break;
                }
            }
        }

        $attackIntent = $result['attack_intent'] ?? [];
        $intents = $attackIntent['intents'] ?? [];
        $confidence = $attackIntent['confidence'] ?? 0.0;
        $primaryIntent = $attackIntent['primary_intent'] ?? null;

        if (!empty($intents)) {
            $intentCount = count($intents);
            if ($intentCount >= 3) {
                $score += 15;
                $indicators[] = 'multi_attack_intent';
            } elseif ($intentCount >= 2) {
                $score += 10;
                $indicators[] = 'dual_attack_intent';
            } else {
                $score += 5;
                $indicators[] = 'single_attack_intent';
            }

            if ($primaryIntent && isset($attackIntent['intent_details'][$primaryIntent])) {
                $detail = $attackIntent['intent_details'][$primaryIntent];
                $intentLevel = $detail['level'] ?? 1;
                $intentScore = $detail['score'] ?? 0;
                if ($intentScore >= 70 && $intentLevel >= 4) {
                    $score += 20;
                    $indicators[] = 'high_confidence_' . $primaryIntent;
                } elseif ($intentScore >= 40 && $intentLevel >= 3) {
                    $score += 12;
                    $indicators[] = 'medium_confidence_' . $primaryIntent;
                } elseif ($intentScore >= 20) {
                    $score += 6;
                    $indicators[] = 'low_confidence_' . $primaryIntent;
                }
            }

            if ($confidence >= 0.8) {
                $score += 8;
                $indicators[] = 'high_intent_confidence';
            } elseif ($confidence >= 0.5) {
                $score += 4;
                $indicators[] = 'medium_intent_confidence';
            }
        }

        $bypassTechs = $result['bypass_techniques'] ?? [];
        if (!empty($bypassTechs)) {
            $highLevelBypass = 0;
            foreach ($bypassTechs as $bt) {
                $level = $bt['level'] ?? 1;
                if ($level >= 5) {
                    $highLevelBypass++;
                    $score += 18;
                } elseif ($level >= 4) {
                    $highLevelBypass++;
                    $score += 12;
                } elseif ($level >= 3) {
                    $score += 7;
                } else {
                    $score += 3;
                }
                $indicators[] = 'bypass_' . $bt['key'];
            }
            if ($highLevelBypass >= 2) {
                $score += 10;
                $indicators[] = 'multi_high_level_bypass';
            }
        }

        $dataFlows = $result['pipeline_analysis']['data_flow'] ?? [];
        if (!empty($dataFlows)) {
            foreach ($dataFlows as $flow) {
                if (!empty($flow['classic_pattern'])) {
                    $cat = $flow['classic_pattern']['category'] ?? '';
                    if ($cat === 'download_execute') {
                        $score += 20;
                        $indicators[] = 'classic_download_execute_flow';
                    } elseif ($cat === 'code_execution') {
                        $score += 15;
                        $indicators[] = 'classic_code_exec_flow';
                    } elseif ($cat === 'evasion') {
                        $score += 12;
                        $indicators[] = 'classic_evasion_flow';
                    } elseif ($cat === 'info_gathering') {
                        $score += 5;
                        $indicators[] = 'classic_info_gather_flow';
                    } elseif ($cat === 'destructive') {
                        $score += 15;
                        $indicators[] = 'classic_destructive_flow';
                    }
                }
            }
        }

        $result['indicators'] = array_merge($result['indicators'] ?? [], $indicators);
        return $score;
    }

    private static function calcRiskLevel(int $score): string {
        if ($score >= 70) return 'critical';
        if ($score >= 50) return 'high';
        if ($score >= 30) return 'medium';
        if ($score >= 10) return 'low';
        return 'clean';
    }

    // ==================== Level 5: 管道数据流分析 ====================

    private static function analyzePipelineDataFlow(array $ast): array {
        $analysis = [
            'data_flow'           => [],
            'chain_depth'         => 0,
            'max_pipeline_depth'  => 0,
            'pipeline_count'      => 0,
            'dangerous_pipelines' => [],
        ];

        self::walkPipelines($ast, $analysis, 0);
        return $analysis;
    }

    private static function walkPipelines(array $node, array &$analysis, int $depth) {
        if (!isset($node['type'])) return;

        switch ($node['type']) {
            case 'command_list':
                foreach ($node['commands'] ?? [] as $cmd) {
                    self::walkPipelines($cmd, $analysis, $depth + 1);
                }
                break;

            case 'pipeline':
                $analysis['pipeline_count']++;
                $pdepth = $node['depth'] ?? 0;
                if ($pdepth > $analysis['max_pipeline_depth']) {
                    $analysis['max_pipeline_depth'] = $pdepth;
                }
                if ($depth > $analysis['chain_depth']) {
                    $analysis['chain_depth'] = $depth;
                }

                $flow = self::buildDataFlow($node);
                if (!empty($flow)) {
                    $analysis['data_flow'][] = $flow;
                }

                $danger = self::assessPipelineDanger($node);
                if ($danger['is_dangerous']) {
                    $analysis['dangerous_pipelines'][] = $danger;
                }

                foreach ($node['commands'] ?? [] as $cmd) {
                    self::walkPipelines($cmd, $analysis, $depth + 1);
                }
                break;

            case 'simple_command':
                foreach ($node['args'] ?? [] as $arg) {
                    if (is_array($arg) && isset($arg['ast'])) {
                        self::walkPipelines($arg['ast'], $analysis, $depth + 1);
                    }
                }
                break;
        }
    }

    private static function buildDataFlow(array $pipelineNode): array {
        $commands = $pipelineNode['commands'] ?? [];
        if (count($commands) < 2) return [];

        $flow = [
            'stages' => [],
            'source' => null,
            'sink' => null,
            'transforms' => [],
            'description' => '',
        ];

        $cmdNames = [];
        foreach ($commands as $i => $cmd) {
            if ($cmd['type'] !== 'simple_command') continue;

            $cmdBase = $cmd['command_base'] ?? 'unknown';
            $cmdNames[] = $cmdBase;

            $args = self::extractArgValues($cmd);
            $stage = [
                'position' => $i,
                'command' => $cmdBase,
                'args' => $args,
                'role' => self::classifyCommandRole($cmdBase, $args, $i, count($commands)),
            ];
            $flow['stages'][] = $stage;

            if ($i === 0) {
                $flow['source'] = $stage;
            }
            if ($i === count($commands) - 1) {
                $flow['sink'] = $stage;
            }
            if ($i > 0 && $i < count($commands) - 1) {
                $flow['transforms'][] = $stage;
            }
        }

        $flow['description'] = implode(' | ', $cmdNames);
        $flow['classic_pattern'] = self::identifyClassicPattern($cmdNames, $flow);

        return $flow;
    }

    private static function classifyCommandRole(string $cmd, array $args, int $pos, int $total): string {
        $readCmds = ['cat', 'head', 'tail', 'more', 'less', 'find', 'ls', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'wc', 'tee'];
        $writeCmds = ['tee', 'dd', 'cp', 'mv', '>', '>>'];
        $filterCmds = ['grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'head', 'tail', 'wc'];
        $execCmds = ['bash', 'sh', 'zsh', 'python', 'perl', 'php', 'ruby', 'nc', 'netcat'];

        if (in_array($cmd, $execCmds) && $pos === $total - 1) return 'exec_sink';
        if (in_array($cmd, $readCmds) && $pos === 0) return 'data_source';
        if (in_array($cmd, $filterCmds)) return 'filter_transform';
        if (in_array($cmd, $writeCmds)) return 'write_sink';

        return 'transform';
    }

    private static function identifyClassicPattern(array $cmdNames, array $flow): ?array {
        $patterns = [
            ['pattern' => ['cat', 'grep'], 'name' => '文件内容搜索', 'risk' => 'medium', 'category' => 'info_gathering'],
            ['pattern' => ['cat', 'head'], 'name' => '文件头部读取', 'risk' => 'low', 'category' => 'info_gathering'],
            ['pattern' => ['cat', 'tail'], 'name' => '文件尾部读取', 'risk' => 'low', 'category' => 'info_gathering'],
            ['pattern' => ['find', 'grep'], 'name' => '文件搜索过滤', 'risk' => 'medium', 'category' => 'info_gathering'],
            ['pattern' => ['ls', 'grep'], 'name' => '目录列表过滤', 'risk' => 'low', 'category' => 'info_gathering'],
            ['pattern' => ['ps', 'grep'], 'name' => '进程搜索', 'risk' => 'low', 'category' => 'info_gathering'],
            ['pattern' => ['netstat', 'grep'], 'name' => '网络连接搜索', 'risk' => 'medium', 'category' => 'info_gathering'],
            ['pattern' => ['cat', 'base64'], 'name' => '文件内容编码', 'risk' => 'medium', 'category' => 'evasion'],
            ['pattern' => ['base64', 'bash'], 'name' => '编码后执行', 'risk' => 'high', 'category' => 'evasion'],
            ['pattern' => ['base64', 'sh'], 'name' => '编码后执行', 'risk' => 'high', 'category' => 'evasion'],
            ['pattern' => ['wget', 'bash'], 'name' => '下载执行', 'risk' => 'critical', 'category' => 'download_execute'],
            ['pattern' => ['wget', 'sh'], 'name' => '下载执行', 'risk' => 'critical', 'category' => 'download_execute'],
            ['pattern' => ['curl', 'bash'], 'name' => '下载执行', 'risk' => 'critical', 'category' => 'download_execute'],
            ['pattern' => ['curl', 'sh'], 'name' => '下载执行', 'risk' => 'critical', 'category' => 'download_execute'],
            ['pattern' => ['curl', 'python'], 'name' => '下载执行', 'risk' => 'high', 'category' => 'download_execute'],
            ['pattern' => ['wget', 'python'], 'name' => '下载执行', 'risk' => 'high', 'category' => 'download_execute'],
            ['pattern' => ['cat', 'bash'], 'name' => '脚本执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['cat', 'sh'], 'name' => '脚本执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['echo', 'bash'], 'name' => '命令执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['echo', 'sh'], 'name' => '命令执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['printf', 'bash'], 'name' => '命令执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['awk', 'sh'], 'name' => 'AWK执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['sed', 'bash'], 'name' => 'SED执行', 'risk' => 'high', 'category' => 'code_execution'],
            ['pattern' => ['rm', 'xargs'], 'name' => '批量删除', 'risk' => 'high', 'category' => 'destructive'],
            ['pattern' => ['find', 'rm'], 'name' => '搜索删除', 'risk' => 'high', 'category' => 'destructive'],
        ];

        foreach ($patterns as $p) {
            $pattern = $p['pattern'];
            $match = true;
            $idx = 0;
            foreach ($cmdNames as $cmd) {
                if ($idx < count($pattern) && $cmd === $pattern[$idx]) {
                    $idx++;
                }
            }
            if ($idx === count($pattern)) {
                return $p;
            }
        }

        return null;
    }

    private static function assessPipelineDanger(array $pipelineNode): array {
        $commands = $pipelineNode['commands'] ?? [];
        $result = [
            'is_dangerous' => false,
            'risk_level' => 'low',
            'reason' => '',
            'dangerous_commands' => [],
        ];

        $cmdBases = [];
        foreach ($commands as $cmd) {
            if ($cmd['type'] === 'simple_command' && !empty($cmd['command_base'])) {
                $cmdBases[] = $cmd['command_base'];
                if (isset(self::$dangerousCommands[$cmd['command_base']])) {
                    $info = self::$dangerousCommands[$cmd['command_base']];
                    if ($info['level'] >= 3) {
                        $result['dangerous_commands'][] = $cmd['command_base'];
                    }
                }
            }
        }

        $flow = self::buildDataFlow($pipelineNode);
        if (!empty($flow['classic_pattern'])) {
            $result['is_dangerous'] = true;
            $result['risk_level'] = $flow['classic_pattern']['risk'];
            $result['reason'] = $flow['classic_pattern']['name'];
        }

        $hasDownload = in_array('wget', $cmdBases) || in_array('curl', $cmdBases);
        $hasExec = in_array('bash', $cmdBases) || in_array('sh', $cmdBases) || in_array('zsh', $cmdBases) ||
                   in_array('python', $cmdBases) || in_array('perl', $cmdBases) || in_array('php', $cmdBases) ||
                   in_array('ruby', $cmdBases);
        if ($hasDownload && $hasExec) {
            $result['is_dangerous'] = true;
            $result['risk_level'] = 'critical';
            $result['reason'] = '下载并执行模式';
        }

        $hasRead = count(array_intersect($cmdBases, ['cat', 'head', 'tail', 'more', 'less', 'find'])) > 0;
        $hasFilter = count(array_intersect($cmdBases, ['grep', 'awk', 'sed', 'cut'])) > 0;
        if ($hasRead && $hasFilter && count($result['dangerous_commands']) > 0) {
            if (!$result['is_dangerous']) {
                $result['is_dangerous'] = true;
                $result['risk_level'] = 'medium';
                $result['reason'] = '信息收集管道';
            }
        }

        return $result;
    }

    private static function extractArgValues(array $simpleCmd): array {
        $values = [];
        foreach ($simpleCmd['args'] ?? [] as $arg) {
            if (is_array($arg) && isset($arg['value'])) {
                $values[] = $arg['value'];
            } elseif (is_array($arg) && isset($arg['type']) && $arg['type'] === 'substitution') {
                $values[] = '$(...)';
            } elseif (is_array($arg) && isset($arg['type']) && $arg['type'] === 'backtick_substitution') {
                $values[] = '`...`';
            }
        }
        return $values;
    }

    // ==================== Level 5: 攻击意图推理 ====================

    private static function inferAttackIntent(array $ast, array $analysisResult): array {
        $allCommands = [];
        $allArgs = [];
        self::collectAllCommands($ast, $allCommands, $allArgs);

        $intents = [];
        $intentDetails = [];
        $totalScore = 0;
        $maxIntentScore = 0;
        $primaryIntent = null;

        foreach (self::$attackIntentPatterns as $key => $pattern) {
            $intentResult = self::evaluateIntent($key, $pattern, $allCommands, $allArgs, $analysisResult);
            if ($intentResult['score'] > 0) {
                $intents[] = $key;
                $intentDetails[$key] = $intentResult;
                $totalScore += $intentResult['score'];
                if ($intentResult['score'] > $maxIntentScore) {
                    $maxIntentScore = $intentResult['score'];
                    $primaryIntent = $key;
                }
            }
        }

        $confidence = 0.0;
        if ($maxIntentScore > 0) {
            $confidence = min(1.0, $maxIntentScore / 100.0);
        }

        return [
            'intents'        => $intents,
            'confidence'     => round($confidence, 2),
            'primary_intent' => $primaryIntent,
            'intent_details' => $intentDetails,
        ];
    }

    private static function evaluateIntent(string $intentKey, array $pattern, array $commands, array $allArgs, array $analysisResult): array {
        $score = 0;
        $evidence = [];
        $matchedCommands = [];

        foreach ($commands as $cmd) {
            if (in_array($cmd, $pattern['commands'] ?? [])) {
                $matchedCommands[] = $cmd;
                $score += 10;
                $evidence[] = "命中命令: $cmd";
            }
        }

        if (!empty($pattern['executors'] ?? [])) {
            foreach ($commands as $cmd) {
                if (in_array($cmd, $pattern['executors'])) {
                    $matchedCommands[] = $cmd;
                    $score += 15;
                    $evidence[] = "命中执行器: $cmd";
                }
            }
        }

        $comboMatches = 0;
        foreach ($pattern['combo_patterns'] ?? [] as $combo) {
            $match = true;
            $lastIdx = -1;
            foreach ($combo as $needle) {
                $found = false;
                for ($i = $lastIdx + 1; $i < count($commands); $i++) {
                    if ($commands[$i] === $needle) {
                        $lastIdx = $i;
                        $found = true;
                        break;
                    }
                    foreach ($allArgs as $arg) {
                        if (is_string($arg) && strpos($arg, $needle) !== false) {
                            $found = true;
                            break;
                        }
                    }
                    if ($found) break;
                }
                if (!$found) {
                    $match = false;
                    break;
                }
            }
            if ($match) {
                $comboMatches++;
                $score += 25;
                $evidence[] = "命中组合: " . implode(' + ', $combo);
            }
        }

        if (!empty($pattern['sensitive_files'] ?? [])) {
            foreach ($allArgs as $arg) {
                if (!is_string($arg)) continue;
                foreach ($pattern['sensitive_files'] as $file) {
                    if (strpos($arg, $file) !== false) {
                        $score += 20;
                        $evidence[] = "敏感文件: $file";
                        break 2;
                    }
                }
            }
        }

        if (!empty($pattern['persistence_files'] ?? [])) {
            foreach ($allArgs as $arg) {
                if (!is_string($arg)) continue;
                foreach ($pattern['persistence_files'] as $file) {
                    if (strpos($arg, $file) !== false) {
                        $score += 20;
                        $evidence[] = "持久化路径: $file";
                        break 2;
                    }
                }
            }
        }

        if (!empty($pattern['indicators'] ?? [])) {
            foreach ($allArgs as $arg) {
                if (!is_string($arg)) continue;
                foreach ($pattern['indicators'] as $ind) {
                    if (strpos($arg, $ind) !== false) {
                        $score += 5;
                        $evidence[] = "特征参数: $ind";
                    }
                }
            }
        }

        if (!empty($pattern['targets'] ?? [])) {
            foreach ($allArgs as $arg) {
                if (!is_string($arg)) continue;
                foreach ($pattern['targets'] as $target) {
                    if (strpos($arg, $target) !== false) {
                        $score += 15;
                        $evidence[] = "目标: $target";
                        break 2;
                    }
                }
            }
        }

        if ($intentKey === 'lateral_movement') {
            $hasNetwork = in_array('ssh', $commands) || in_array('nc', $commands) ||
                          in_array('netcat', $commands) || in_array('telnet', $commands);
            if ($hasNetwork) {
                foreach ($allArgs as $arg) {
                    if (!is_string($arg)) continue;
                    foreach ($pattern['indicators'] as $ipPrefix) {
                        if (strpos($arg, $ipPrefix) !== false) {
                            $score += 20;
                            $evidence[] = "内网IP: $ipPrefix";
                            break 2;
                        }
                    }
                }
            }
        }

        if ($analysisResult['has_command_substitution'] ?? false) {
            $score += 5;
            $evidence[] = '命令替换';
        }
        if ($analysisResult['has_wildcard_bypass'] ?? false) {
            $score += 5;
            $evidence[] = '通配符绕过';
        }
        if (($analysisResult['subshell_count'] ?? 0) >= 1) {
            $score += 5;
            $evidence[] = '子Shell嵌套';
        }

        $level = $pattern['level'] ?? 1;
        $score = min(100, $score * ($level / 3));

        return [
            'name'      => $pattern['name'],
            'score'     => (int)$score,
            'level'     => $level,
            'evidence'  => array_unique($evidence),
            'commands'  => array_unique($matchedCommands),
            'combo_count' => $comboMatches,
        ];
    }

    private static function collectAllCommands(array $node, array &$commands, array &$allArgs) {
        if (!isset($node['type'])) return;

        switch ($node['type']) {
            case 'command_list':
                foreach ($node['commands'] ?? [] as $cmd) {
                    self::collectAllCommands($cmd, $commands, $allArgs);
                }
                break;

            case 'pipeline':
                foreach ($node['commands'] ?? [] as $cmd) {
                    self::collectAllCommands($cmd, $commands, $allArgs);
                }
                break;

            case 'simple_command':
                if (!empty($node['command_base'])) {
                    $commands[] = $node['command_base'];
                }
                foreach ($node['args'] ?? [] as $arg) {
                    if (is_array($arg) && isset($arg['value'])) {
                        $allArgs[] = $arg['value'];
                    } elseif (is_array($arg) && isset($arg['ast'])) {
                        self::collectAllCommands($arg['ast'], $commands, $allArgs);
                    }
                }
                break;
        }
    }

    // ==================== Level 5: 逃逸绕过检测 ====================

    private static function detectBypassTechniques(string $rawInput, array $ast): array {
        $techniques = [];

        self::detectCommandSubstitutionNesting($rawInput, $techniques);
        self::detectVariableConcat($rawInput, $techniques);
        self::detectWildcardBypass($rawInput, $techniques);
        self::detectBraceExpansion($rawInput, $techniques);
        self::detectIFSBypass($rawInput, $techniques);
        self::detectBase64Chains($rawInput, $ast, $techniques);
        self::detectHexOctalEncoding($rawInput, $techniques);

        return $techniques;
    }

    private static function detectCommandSubstitutionNesting(string $input, array &$techniques) {
        $dollarCount = preg_match_all('/\$\(/', $input);
        $backtickCount = preg_match_all('/`/', $input);
        $backtickPairs = floor($backtickCount / 2);

        $nestedDollar = 0;
        $depth = 0;
        $maxDepth = 0;
        for ($i = 0; $i < strlen($input); $i++) {
            if ($input[$i] === '$' && $i + 1 < strlen($input) && $input[$i + 1] === '(') {
                $depth++;
                if ($depth > 1) $nestedDollar++;
                if ($depth > $maxDepth) $maxDepth = $depth;
                $i++;
            } elseif ($input[$i] === ')') {
                if ($depth > 0) $depth--;
            }
        }

        if ($maxDepth >= 2 || $nestedDollar > 0 || $backtickPairs >= 2) {
            $techniques[] = [
                'key'         => 'nested_substitution',
                'name'        => '嵌套命令替换',
                'level'       => 4,
                'desc'        => '多层命令替换嵌套增加检测难度',
                'dollar_depth' => $maxDepth,
                'backtick_pairs' => $backtickPairs,
            ];
        } elseif ($dollarCount > 0 || $backtickPairs > 0) {
            $techniques[] = [
                'key'         => 'command_substitution',
                'name'        => '命令替换',
                'level'       => 3,
                'desc'        => '使用 $() 或反引号进行命令替换',
                'dollar_count' => $dollarCount,
                'backtick_pairs' => $backtickPairs,
            ];
        }

        $mixed = ($dollarCount > 0 && $backtickPairs > 0);
        if ($mixed) {
            $techniques[] = [
                'key'   => 'mixed_substitution',
                'name'  => '混合命令替换',
                'level' => 4,
                'desc'  => '同时使用 $() 和反引号',
            ];
        }
    }

    private static function detectVariableConcat(string $input, array &$techniques) {
        $patterns = [
            [
                'pattern' => '/\$\{[a-zA-Z_][a-zA-Z0-9_]*\}\$\{[a-zA-Z_][a-zA-Z0-9_]*\}/',
                'key'     => 'var_concat_brace',
                'name'    => '花括号变量拼接',
                'level'   => 3,
                'desc'    => '使用 ${a}${b} 形式拼接变量绕过检测',
            ],
            [
                'pattern' => '/\$[a-zA-Z_][a-zA-Z0-9_]*\$[a-zA-Z_][a-zA-Z0-9_]*/',
                'key'     => 'var_concat_simple',
                'name'    => '简单变量拼接',
                'level'   => 2,
                'desc'    => '使用 $a$b 形式拼接变量',
            ],
            [
                'pattern' => '/\$\{[a-zA-Z_][a-zA-Z0-9_]*:-?[^}]*\}/',
                'key'     => 'var_default_value',
                'name'    => '变量默认值绕过',
                'level'   => 3,
                'desc'    => '使用 ${var:-default} 形式绕过',
            ],
            [
                'pattern' => '/\$\{[a-zA-Z_][a-zA-Z0-9_]*:\d+[:+]?\d*\}/',
                'key'     => 'var_substring',
                'name'    => '变量子串绕过',
                'level'   => 4,
                'desc'    => '使用 ${var:offset:length} 形式提取子串',
            ],
            [
                'pattern' => '/\$\{#[a-zA-Z_][a-zA-Z0-9_]*\}/',
                'key'     => 'var_length',
                'name'    => '变量长度',
                'level'   => 2,
                'desc'    => '使用 ${#var} 获取变量长度',
            ],
        ];

        foreach ($patterns as $p) {
            if (preg_match_all($p['pattern'], $input, $m) > 0) {
                $techniques[] = [
                    'key'   => $p['key'],
                    'name'  => $p['name'],
                    'level' => $p['level'],
                    'desc'  => $p['desc'],
                    'count' => count($m[0]),
                    'matches' => array_slice($m[0], 0, 5),
                ];
            }
        }
    }

    private static function detectWildcardBypass(string $input, array &$techniques) {
        $patterns = [
            [
                'pattern' => '/\/[?*]+\/[?*]+/',
                'key'     => 'wildcard_path',
                'name'    => '通配符路径绕过',
                'level'   => 4,
                'desc'    => '使用 /???/?? 形式绕过路径过滤',
            ],
            [
                'pattern' => '/\b[a-zA-Z0-9]*[?*][a-zA-Z0-9]*[?*]/',
                'key'     => 'wildcard_command',
                'name'    => '通配符命令绕过',
                'level'   => 3,
                'desc'    => '使用通配符匹配命令名',
            ],
            [
                'pattern' => '/\.\.[?*]/',
                'key'     => 'wildcard_traversal',
                'name'    => '通配符路径遍历',
                'level'   => 3,
                'desc'    => '结合通配符和路径遍历',
            ],
        ];

        foreach ($patterns as $p) {
            if (preg_match_all($p['pattern'], $input, $m) > 0) {
                $techniques[] = [
                    'key'   => $p['key'],
                    'name'  => $p['name'],
                    'level' => $p['level'],
                    'desc'  => $p['desc'],
                    'count' => count($m[0]),
                    'matches' => array_slice($m[0], 0, 5),
                ];
            }
        }
    }

    private static function detectBraceExpansion(string $input, array &$techniques) {
        if (preg_match_all('/\{[^}]+,[^}]+\}/', $input, $m) > 0) {
            $examples = [];
            foreach ($m[0] as $match) {
                $parts = explode(',', trim($match, '{}'));
                if (count($parts) >= 2) {
                    $examples[] = [
                        'expansion' => $match,
                        'parts' => array_slice($parts, 0, 5),
                        'part_count' => count($parts),
                    ];
                }
            }

            if (!empty($examples)) {
                $techniques[] = [
                    'key'      => 'brace_expansion',
                    'name'     => '花括号展开绕过',
                    'level'    => 4,
                    'desc'     => '使用 {cmd,arg} 或 {a,b,c} 形式绕过关键词过滤',
                    'count'    => count($m[0]),
                    'examples' => array_slice($examples, 0, 3),
                ];
            }
        }
    }

    private static function detectIFSBypass(string $input, array &$techniques) {
        $patterns = [
            [
                'pattern' => '/[a-zA-Z0-9]\$IFS/',
                'key'     => 'ifs_bypass_direct',
                'name'    => 'IFS 直接绕过',
                'level'   => 4,
                'desc'    => '使用 $IFS 替代空格绕过空格过滤',
            ],
            [
                'pattern' => '/\$\{IFS\}/',
                'key'     => 'ifs_bypass_brace',
                'name'    => 'IFS 花括号绕过',
                'level'   => 4,
                'desc'    => '使用 ${IFS} 替代空格',
            ],
            [
                'pattern' => '/\$IFS\$[0-9]/',
                'key'     => 'ifs_bypass_positional',
                'name'    => 'IFS 位置参数绕过',
                'level'   => 5,
                'desc'    => '使用 $IFS$9 等组合绕过',
            ],
            [
                'pattern' => '/\{\$IFS\}/',
                'key'     => 'ifs_brace_var',
                'name'    => 'IFS 变量展开绕过',
                'level'   => 4,
                'desc'    => '使用 {$IFS} 形式',
            ],
        ];

        foreach ($patterns as $p) {
            if (preg_match_all($p['pattern'], $input, $m) > 0) {
                $techniques[] = [
                    'key'   => $p['key'],
                    'name'  => $p['name'],
                    'level' => $p['level'],
                    'desc'  => $p['desc'],
                    'count' => count($m[0]),
                    'matches' => array_slice($m[0], 0, 5),
                ];
            }
        }
    }

    private static function detectBase64Chains(string $input, array $ast, array &$techniques) {
        if (preg_match('/base64.*\|\s*(bash|sh|zsh|python|perl|php|nc|netcat)/i', $input) ||
            preg_match('/(bash|sh|zsh|python|perl|php).*base64.*-d/i', $input)) {
            $techniques[] = [
                'key'   => 'base64_decode_exec',
                'name'  => 'Base64 解码执行链',
                'level' => 5,
                'desc'  => 'Base64 解码后直接执行命令，典型的编码绕过',
            ];
        }
    }

    private static function detectHexOctalEncoding(string $input, array &$techniques) {
        $hexCount = preg_match_all('/\\\\x[0-9a-fA-F]{2}/', $input);
        $octCount = preg_match_all('/\\\\[0-7]{3}/', $input);

        if ($hexCount >= 3) {
            $techniques[] = [
                'key'   => 'hex_encoding',
                'name'  => '十六进制编码绕过',
                'level' => 4,
                'desc'  => '使用 \xHH 十六进制编码绕过关键词检测',
                'count' => $hexCount,
            ];
        }

        if ($octCount >= 3) {
            $techniques[] = [
                'key'   => 'octal_encoding',
                'name'  => '八进制编码绕过',
                'level' => 3,
                'desc'  => '使用 \NNN 八进制编码绕过关键词检测',
                'count' => $octCount,
            ];
        }
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

        return ['decoded' => $current, 'depth' => $depth, 'encode_types' => array_unique($encodeTypes)];
    }

    private static function regexFallback(string $input): array {
        $commands = preg_split('/[;\|\&\n\r]+/', $input, -1, PREG_SPLIT_NO_EMPTY);
        $dangerous = [];
        $maxLevel = 0;
        $categories = [];

        foreach ($commands as $cmd) {
            $cmd = trim($cmd);
            if (preg_match('/^([a-zA-Z0-9_\-\/\.]+)/', $cmd, $m)) {
                $base = basename($m[1]);
                if (isset(self::$dangerousCommands[$base])) {
                    $info = self::$dangerousCommands[$base];
                    $dangerous[] = ['command' => $base, 'level' => $info['level'], 'category' => $info['category']];
                    if ($info['level'] > $maxLevel) $maxLevel = $info['level'];
                    if (!in_array($info['category'], $categories)) $categories[] = $info['category'];
                }
            }
        }

        return [
            'command_count' => count($commands),
            'dangerous_commands' => $dangerous,
            'categories' => $categories,
            'max_cmd_level' => $maxLevel,
            'max_sep_level' => 0,
            'normalized_commands' => array_slice(array_map(function($c) { return basename(trim($c)); }, $commands), 0, 5),
            'blind_indicators' => [],
            'evasion_patterns' => [],
        ];
    }

    // ==================== Parser 辅助 ====================

    private static function current(array $state): array {
        return $state['tokens'][$state['pos']] ?? end($state['tokens']);
    }

    private static function next(array &$state) {
        if ($state['pos'] < count($state['tokens']) - 1) {
            $state['pos']++;
        }
    }

    private static function isEof(array $state): bool {
        return self::current($state)['type'] === self::TOK_EOF;
    }
}
