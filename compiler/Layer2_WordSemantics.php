<?php
defined('ABSPATH') || exit;

/**
 * Layer2：词汇语义分析层
 *
 * 对输入文本进行词法分析，识别 SQL 关键字、操作符、表名、列名，
 * 以及 PHP/JS 函数名等，并为每个 token 标注语义角色。
 */
class Layer2_WordSemantics {

    /**
     * SQL 关键字集合
     */
    private static $sqlKeywords = [
        'select', 'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate',
        'from', 'into', 'where', 'and', 'or', 'not', 'null', 'union', 'all', 'distinct',
        'join', 'left', 'right', 'inner', 'outer', 'on', 'group', 'by', 'order', 'having',
        'limit', 'offset', 'as', 'like', 'in', 'between', 'is', 'exists', 'case', 'when',
        'then', 'else', 'end', 'if', 'exists', 'schema', 'table', 'column', 'database',
        'index', 'view', 'grant', 'revoke', 'set', 'values', 'primary', 'foreign', 'key',
        'references', 'constraint', 'default', 'auto_increment', 'commit', 'rollback',
        'begin', 'transaction', 'exec', 'execute', 'waitfor', 'delay', 'top', 'merge',
    ];

    /**
     * SQL 函数集合
     */
    private static $sqlFunctions = [
        'count', 'sum', 'avg', 'min', 'max', 'concat', 'group_concat', 'substring',
        'substr', 'mid', 'left', 'right', 'length', 'len', 'replace', 'trim', 'ltrim',
        'rtrim', 'upper', 'lower', 'now', 'current_timestamp', 'version', 'user',
        'database', 'current_user', 'char', 'ascii', 'ord', 'hex', 'unhex', 'cast',
        'convert', 'sleep', 'benchmark', 'load_file', 'into', 'outfile', 'dumpfile',
        'xp_cmdshell', 'extractvalue', 'updatexml', 'row', 'ifnull', 'coalesce',
    ];

    /**
     * SQL 操作符
     */
    private static $sqlOperators = ['=', '<>', '!=', '<=', '>=', '<', '>', '+', '-', '*', '/', '%', '&&', '||', '|', '&', '^', '~'];

    /**
     * PHP 危险函数集合
     */
    private static $phpFunctions = [
        'eval', 'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'assert', 'preg_replace', 'create_function', 'call_user_func', 'call_user_func_array',
        'include', 'require', 'include_once', 'require_once', 'file_get_contents',
        'file_put_contents', 'fopen', 'readfile', 'fwrite', 'fread', 'unlink',
        'move_uploaded_file', 'copy', 'rename', 'chmod', 'chown', 'mkdir', 'rmdir',
        'base64_decode', 'base64_encode', 'gzinflate', 'gzuncompress', 'gzdecode',
        'str_rot13', 'pack', 'unpack', 'hex2bin', 'bin2hex', 'urldecode', 'rawurldecode',
        'session_start', 'setcookie', 'header', 'highlight_file', 'show_source',
    ];

    /**
     * JS 危险函数/属性集合
     */
    private static $jsFunctions = [
        'eval', 'atob', 'btoa', 'unescape', 'escape', 'decodeURI', 'decodeURIComponent',
        'encodeURI', 'encodeURIComponent', 'Function', 'setTimeout', 'setInterval',
        'document', 'window', 'location', 'cookie', 'innerHTML', 'outerHTML',
        'insertAdjacentHTML', 'write', 'writeln', 'src', 'href', 'XMLHttpRequest',
        'fetch', 'ajax', 'post', 'get', 'alert', 'prompt', 'confirm',
    ];

    /**
     * 分析词汇语义
     *
     * @param string $text 待分析文本
     * @return array ['score'=>0-100, 'tokens'=>[...]]
     */
    public static function analyze(string $text): array {
        $result = [
            'score'  => 0,
            'tokens' => [],
        ];

        if ($text === '') {
            return $result;
        }

        // 词法切分：保留标识符、数字、字符串、操作符、符号
        $pattern = '/\s+|[a-zA-Z_][a-zA-Z0-9_]*|\d+\.\d+|\d+|0x[0-9a-fA-F]+|"(?:\\\\.|[^"\\\\])*"|\'(?:\\\\.|[^\'\\\\])*\'|<>|!=|<=|>=|&&|\|\||[=\+\-\*\/%<>&\|^~!;,()\[\]{}.@#$?\'":\/\\\\]/u';
        if (!preg_match_all($pattern, $text, $m)) {
            return $result;
        }

        $rawTokens = $m[0];
        $sqlKeywordSet = array_flip(self::$sqlKeywords);
        $sqlFunctionSet = array_flip(self::$sqlFunctions);
        $phpFunctionSet = array_flip(self::$phpFunctions);
        $jsFunctionSet = array_flip(self::$jsFunctions);
        $sqlOperatorSet = array_flip(self::$sqlOperators);

        $score = 0;
        $tokens = [];

        foreach ($rawTokens as $idx => $tok) {
            // 跳过空白
            if (trim($tok) === '') {
                continue;
            }

            $role = 'unknown';
            $risk = 0;
            $lower = strtolower($tok);

            // 字符串字面量
            if (strlen($tok) >= 2 && (($tok[0] === '"' && substr($tok, -1) === '"') || ($tok[0] === '\'' && substr($tok, -1) === '\''))) {
                $role = 'string';
                $risk = 5;
            } elseif (isset($sqlKeywordSet[$lower])) {
                $role = 'sql_keyword';
                // 高危关键字加权
                $highRisk = ['union', 'select', 'drop', 'insert', 'delete', 'update', 'exec', 'execute', 'xp_cmdshell', 'sleep', 'benchmark', 'load_file', 'outfile'];
                $risk = in_array($lower, $highRisk) ? 15 : 8;
                $score += $risk;
            } elseif (isset($sqlFunctionSet[$lower])) {
                $role = 'sql_function';
                $highRisk = ['sleep', 'benchmark', 'load_file', 'xp_cmdshell', 'extractvalue', 'updatexml', 'char', 'concat', 'group_concat'];
                $risk = in_array($lower, $highRisk) ? 18 : 10;
                $score += $risk;
            } elseif (isset($phpFunctionSet[$lower])) {
                $role = 'php_function';
                $highRisk = ['eval', 'system', 'exec', 'shell_exec', 'passthru', 'assert', 'proc_open', 'popen', 'preg_replace', 'create_function'];
                $risk = in_array($lower, $highRisk) ? 20 : 10;
                $score += $risk;
            } elseif (isset($jsFunctionSet[$lower])) {
                $role = 'js_function';
                $highRisk = ['eval', 'Function', 'innerHTML', 'document', 'cookie', 'write'];
                $risk = in_array($lower, $highRisk) ? 15 : 8;
                $score += $risk;
            } elseif (isset($sqlOperatorSet[$tok])) {
                $role = 'operator';
                $risk = 3;
            } elseif (preg_match('/^0x[0-9a-fA-F]+$/', $tok)) {
                $role = 'hex_literal';
                $risk = 12;
                $score += $risk;
            } elseif (preg_match('/^\d+(\.\d+)?$/', $tok)) {
                $role = 'number';
                $risk = 1;
            } elseif (preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $tok)) {
                // 启发式：紧邻 FROM/INTO/UPDATE/JOIN 的标识符视为表名
                $prev = $idx > 0 ? strtolower($rawTokens[$idx - 1]) : '';
                $next = $idx < count($rawTokens) - 1 ? strtolower($rawTokens[$idx + 1]) : '';
                if (in_array($prev, ['from', 'into', 'update', 'join', 'table'])) {
                    $role = 'table_name';
                    $risk = 6;
                } elseif (in_array($prev, ['select', 'where', 'and', 'or', 'by', 'having', 'set']) || in_array($next, ['=', 'like', 'in', 'between', 'is'])) {
                    $role = 'column_name';
                    $risk = 5;
                } else {
                    $role = 'identifier';
                    $risk = 2;
                }
            } else {
                $role = 'symbol';
                $risk = 1;
            }

            $tokens[] = [
                'token' => $tok,
                'role'  => $role,
                'risk'  => $risk,
            ];
        }

        // 检测可疑词汇组合：union select / or 1=1 / sleep( 等
        $lowerText = strtolower($text);
        $comboPatterns = [
            '/union\s+(?:all\s+)?select/' => 20,
            '/\bor\s+1\s*=\s*1\b/'         => 18,
            '/\band\s+1\s*=\s*1\b/'        => 15,
            '/\bor\s+1\s*=\s*2\b/'         => 12,
            '/\bsleep\s*\(/'                => 18,
            '/\bbenchmark\s*\(/'            => 18,
            '/\beval\s*\(/'                 => 18,
            '/\bsystem\s*\(/'               => 20,
            '/\bexec\s*\(/'                 => 18,
            '/information_schema/'          => 15,
            '/into\s+outfile/'              => 20,
            '/load_file\s*\(/'              => 18,
            '/<script/i'                    => 15,
            '/onerror\s*=/i'                => 15,
            '/javascript:/i'                => 15,
        ];
        foreach ($comboPatterns as $p => $w) {
            if (preg_match($p, $lowerText)) {
                $score += $w;
            }
        }

        $result['tokens'] = $tokens;
        $result['score'] = max(0, min(100, (int) round($score)));
        return $result;
    }
}
