<?php
/**
 * 词汇语义分析引擎（基于上下文的词法语义分析）
 *
 * 职责：在词汇层面理解攻击语义，而非简单的关键词字典匹配（in_array）。
 * 通过以下能力从词汇层面评估输入的攻击意图：
 *   1. 词汇共现分析（Collocation Analysis）—— 关键词的组合意图而非单点命中
 *   2. 词汇角色标注（POS-like Tagging）—— 每个 token 在攻击中的角色
 *   3. 词汇序列模式（N-gram Analysis）—— token 序列的攻击模式
 *   4. 词汇语义场（Semantic Field）—— 语义场激活强度分析
 *   5. 词汇异常度评估（Lexical Anomaly）—— 密度 / 多样性 / 罕见度
 *   6. 保留的辅助识别能力（SQL / DB / 函数 / HTML / JS，降为辅助）
 *
 * 返回结构：['score' => 0-100, 'roles' => [], 'keywords' => []]
 */
defined('ABSPATH') || exit;

class WordSemantics {
    /* =====================================================================
     * 词汇词典
     * ===================================================================== */

    /** SQL 关键字（KEYWORD_SQL / OP_LOGIC 角色标注 + SQL 语义场） */
    private static $sql_keywords = [
        'select','union','insert','update','delete','drop','alter','create',
        'truncate','from','where','into','table','database','schema','or',
        'and','not','null','having','group','order','by','limit','concat',
        'group_concat','substring','substr','benchmark','sleep','waitfor',
        'delay','xp_cmdshell','load_file','outfile','dumpfile','exec',
        'execute','declare','cast','convert','like','between','exists',
        'case','when','distinct','as','join','inner','left','right','outer',
        'values','set','count','char','ascii','hex','unhex','if','ifnull',
        'coalesce','extractvalue','updatexml','autocommit','begin','commit',
        'rollback','shutdown','version','current_user',
    ];

    /** 逻辑运算符（从 SQL 关键字中分离出 OP_LOGIC 角色） */
    private static $logic_operators = ['and', 'or', 'not'];

    /** 命令执行 / 危险函数关键字（KEYWORD_CMD） */
    private static $cmd_keywords = [
        'eval','system','exec','shell_exec','passthru','popen','proc_open',
        'assert','preg_replace','create_function','call_user_func',
        'call_user_func_array','unserialize','base64_decode','base64_encode',
        'gzinflate','gzuncompress','str_rot13','pack','unpack','hex2bin',
        'convert_uudecode','file_get_contents','file_put_contents','fopen',
        'readfile','include','require','include_once','require_once','fputs',
        'fwrite','move_uploaded_file','curl_exec','pcntl_exec','expect_popen',
        'dl','putenv','mail','mb_sendmail','imap_open','ini_set',
        'ini_restore','posix_getpwuid','posix_kill',
    ];

    /** 数据库敏感对象（表名 / 列名 → IDENT_TABLE） */
    private static $db_objects = [
        'users','user','admin','administrator','password','passwd','pwd',
        'username','user_name','login','email','mail','session','token',
        'information_schema','mysql','sysobjects','syscolumns','master',
        'wp_users','accounts','members','credit_card','ssn','secret',
        'credentials','api_key','private_key','salt','hash','role','is_admin',
        'superuser','root','authorized','privilege','grant',
    ];

    /** HTML / JS 标签（CONTEXT_HTML） */
    private static $html_tags = [
        'script','iframe','img','svg','body','object','embed','video',
        'audio','style','link','meta','form','input','textarea','details',
        'marquee','base','applet','frame','frameset','xml','template',
    ];

    /** JS 事件处理器（CONTEXT_HTML） */
    private static $js_events = [
        'onerror','onload','onclick','onmouseover','onfocus','onblur',
        'onchange','onsubmit','onkeydown','onkeypress','onkeyup','onunload',
        'ondblclick','oninput','ontoggle','onanimationstart','onpointerover',
        'onanimationend','onstart','onfinish','onbounce','onpointerdown',
    ];

    /* =====================================================================
     * 语义场定义（Semantic Field）
     * 每个语义场是一组词汇；激活强度 = 命中词汇数 / 该场词汇总数
     * 纯字母数字_ 走 token 集合匹配，其余走子串匹配
     * ===================================================================== */
    private static $semantic_fields = [
        'sql_injection' => [
            'select','union','insert','update','delete','drop','alter','create',
            'truncate','from','where','into','table','schema','or','and',
            'having','group_concat','concat','substring','substr','benchmark',
            'sleep','waitfor','load_file','outfile','dumpfile','xp_cmdshell',
            'exec','execute','declare','cast','convert','information_schema',
            '--','#','/*','*/','extractvalue','updatexml','@@version',
            '@@datadir','values',
        ],
        'xss' => [
            'script','onerror','onload','onclick','onmouseover','onfocus',
            'javascript','alert','prompt','confirm','document','cookie',
            'innerhtml','location','href','window','eval','fromcharcode',
            'string','unescape','srcdoc','svg','img','iframe','onpointerover',
            '<','>',
        ],
        'command_injection' => [
            'system','exec','shell_exec','passthru','popen','proc_open',';',
            '|','&&','||','`','$(','/bin/sh','/bin/bash','sh','bash','cmd',
            'whoami','id','uname','ifconfig','netstat','wget','curl','nc',
            'python','perl','ruby','php','chmod','chown','rm','cat','ls',
        ],
        'path_traversal' => [
            '../','..\\','/etc/','/proc/','/var/','/tmp/','/root/','/home/',
            'c:\\','d:\\','/windows/','/system32/','php://','file://','data://',
            'expect://','zip://','phar://','/etc/passwd','/etc/shadow',
            'boot.ini','win.ini','..%2f','..%5c',
        ],
        'encoding_obfuscation' => [
            'base64','base64_decode','base64_encode','eval','chr','hex','hex2bin',
            'pack','unpack','str_rot13','gzinflate','gzuncompress',
            'convert_uudecode','\\x','&#','%','0x','fromcharcode','unescape',
            'rawurldecode','urldecode','concat','ord',
        ],
        'template_injection' => [
            '{{','}}','${','#{','*{','__class__','__bases__','__subclasses__',
            '__mro__','__globals__','__builtins__','getclass','loadclass',
            'mro','subclasses','popen','subprocess','tornado','jinja2',
            'freemarker','velocity','smarty','twig',
        ],
    ];

    /* =====================================================================
     * 高危共现模式（Collocation Patterns）
     * 每条：[required 词列表, intent 标签, 分值]
     * required 中：纯字母数字_ 走 token 集合匹配，其余走子串匹配
     * ===================================================================== */
    private static $collocations = [
        // SQL 元数据窃取
        [['select','from','information_schema'], 'colloc:metadata_theft', 28],
        [['select','from','mysql'], 'colloc:mysql_probe', 22],
        [['select','from','sysobjects'], 'colloc:mssql_probe', 22],
        // 联合查询注入
        [['union','select','from'], 'colloc:union_injection', 26],
        [['union','select'], 'colloc:union_select', 20],
        // 破坏性操作 + 注释截断
        [['drop','table'], 'colloc:drop_table', 22],
        [['drop','table','--'], 'colloc:drop_table_comment', 30],
        [['delete','from'], 'colloc:delete_from', 18],
        [['truncate','table'], 'colloc:truncate_table', 22],
        // 提权 / 登录绕过
        [['insert','into','admin'], 'colloc:insert_admin', 25],
        [['update','set','admin'], 'colloc:update_admin', 22],
        [['or','admin'], 'colloc:or_admin_bypass', 20],
        // 盲注 / 时间盲注
        [['sleep','and'], 'colloc:time_blind_sleep', 24],
        [['benchmark','and'], 'colloc:time_blind_benchmark', 26],
        [['if','sleep'], 'colloc:conditional_sleep', 24],
        // 文件读写
        [['load_file','into','outfile'], 'colloc:file_read_write', 28],
        [['load_file','dumpfile'], 'colloc:file_dump', 26],
        // WebShell（eval + 超全局输入）
        [['eval','$_post'], 'colloc:webshell_post_eval', 30],
        [['eval','$_get'], 'colloc:webshell_get_eval', 30],
        [['eval','$_request'], 'colloc:webshell_request_eval', 30],
        [['assert','$_post'], 'colloc:webshell_post_assert', 28],
        // 混淆 WebShell
        [['base64_decode','eval'], 'colloc:obfuscated_webshell', 30],
        [['base64_decode','assert'], 'colloc:obfuscated_assert', 28],
        [['gzinflate','eval'], 'colloc:gz_webshell', 28],
        [['str_rot13','eval'], 'colloc:rot13_webshell', 26],
        // 命令执行
        [['system',';'], 'colloc:system_chain', 24],
        [['system','|'], 'colloc:system_pipe', 24],
        [['exec',';'], 'colloc:exec_chain', 22],
        [['passthru','$_'], 'colloc:passthru_input', 26],
        // XSS
        [['script','alert'], 'colloc:xss_alert', 22],
        [['img','onerror'], 'colloc:xss_img_onerror', 24],
        [['svg','onload'], 'colloc:xss_svg_onload', 24],
        [['javascript:','alert'], 'colloc:xss_js_uri', 22],
        // 路径遍历 + 敏感文件
        [['../','etc/passwd'], 'colloc:lfi_etc_passwd', 28],
        [['php://','input'], 'colloc:php_filter_input', 26],
        [['php://','filter'], 'colloc:php_filter', 24],
        // 模板注入
        [['{{','__class__'], 'colloc:ssti_jinja2', 26],
        [['${','__'], 'colloc:ssti_el', 22],
    ];

    /* =====================================================================
     * 高危 N-gram 序列模式（顺序敏感，连续匹配）
     * 序列元素与 token 的 canonical 形式比较
     * ===================================================================== */
    private static $ngrams = [
        // 2-gram
        [['union','select'], 'ng:union_select', 18],
        [['or','1'], 'ng:or_1', 10],
        [[';','drop'], 'ng:stacked_drop', 16],
        [[';','insert'], 'ng:stacked_insert', 14],
        [[';','update'], 'ng:stacked_update', 12],
        [[';','delete'], 'ng:stacked_delete', 14],
        // 3-gram
        [['or','1','=','1'], 'ng:tautology_or_1_eq_1', 20],
        [['or',"'1'","=","'1'"], 'ng:tautology_quote', 20],
        [['or','true'], 'ng:or_true', 12],
        [['and','1','=','1'], 'ng:tautology_and', 18],
        [['union','select','from'], 'ng:union_select_from', 18],
        // 4-gram
        [['select','*','from','information_schema'], 'ng:metadata_select', 20],
        [['select','*','from','mysql'], 'ng:mysql_select', 16],
        [['select','*','from','admin'], 'ng:admin_select', 16],
        [['insert','into','admin','values'], 'ng:insert_admin_values', 18],
        // 混淆链
        [['base64_decode','(','eval'], 'ng:b64_eval_chain', 18],
        [['chr','(','eval'], 'ng:chr_eval_chain', 16],
    ];

    /* =====================================================================
     * 罕见技术特征（用于异常度评估）
     * ===================================================================== */
    private static $rare_patterns = [
        '/0x[0-9a-f]{8,}/i',              // 长十六进制串
        '/\b[a-z0-9]{32}\b/i',            // 32 位 hash 样串
        '/\$_(get|post|request|cookie|server|files)/i', // PHP 超全局
        '/\\\\x[0-9a-f]{2}/i',            // \xHH 十六进制转义
        '/&#\d+;/',                       // HTML 实体编码
        '/\bfromcharcode\b/i',           // JS 混淆函数
        '/\bsubclasses__\b/i',           // Python 沙箱逃逸
        '/@@(version|datadir|hostname)/i', // MySQL 系统变量
    ];

    /**
     * 基于上下文的词法语义分析入口。
     *
     * @param string $text
     * @return array{score:int, roles:array, keywords:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return ['score' => 0, 'roles' => [], 'keywords' => []];
        }

        // ---- 1. 分词与角色标注（POS-like Tagging） ----
        $tokens  = self::tokenize($text);
        $tagged  = self::tagTokens($tokens);

        $wordSet = [];       // 小写词集合（用于共现 / 语义场匹配）
        $canonicalSeq = [];  // 规范化 token 序列（用于 N-gram）
        foreach ($tagged as $tok) {
            if ($tok['word'] !== '') {
                $wordSet[$tok['word']] = true;
            }
            $canonicalSeq[] = $tok['canonical'];
        }
        $lowerText = function_exists('mb_strtolower')
            ? mb_strtolower($text, 'UTF-8')
            : strtolower($text);

        $score    = 0;
        $roles    = [];
        $keywords = [];

        // ---- 2. 语义场激活分析（Semantic Field） ----
        $fieldResults = self::analyzeSemanticFields($wordSet, $lowerText);
        $activeFields = [];
        foreach ($fieldResults as $name => $info) {
            if ($info['activated']) {
                $activeFields[$name] = $info;
                $roles[]    = 'field:' . $name;
                $score     += $info['score'];
                $keywords[] = sprintf('field:%s(strength=%.2f,hits=%d/%d)',
                    $name, $info['strength'], $info['hits'], $info['total']);
            }
        }

        // ---- 3. 高危共现模式（Collocation） ----
        $collocHits = self::detectCollocations($wordSet, $lowerText);
        foreach ($collocHits as $hit) {
            $keywords[] = $hit['intent'];
            $score     += $hit['score'];
        }
        if (!empty($collocHits)) {
            $roles[] = 'collocation';
        }

        // ---- 4. N-gram 序列模式 ----
        $ngramHits = self::detectNgrams($canonicalSeq);
        foreach ($ngramHits as $hit) {
            $keywords[] = $hit['label'];
            $score     += $hit['score'];
        }
        if (!empty($ngramHits)) {
            $roles[] = 'ngram_pattern';
        }

        // ---- 5. 辅助识别（保留能力，降为辅助）：SQL / DB / 函数 / HTML / JS ----
        $aux = self::collectAuxiliaryRoles($tagged);
        foreach ($aux['keywords'] as $k) {
            $keywords[] = $k;
        }
        foreach ($aux['roles'] as $r) {
            $roles[] = $r;
        }

        // ---- 6. 词汇异常度评估（Lexical Anomaly） ----
        $anomaly = self::assessAnomaly($tagged, $lowerText);
        if ($anomaly['score'] > 0) {
            $score     += $anomaly['score'];
            $keywords[] = sprintf('anomaly(score=%.0f,density=%.2f,diversity=%d,rare=%d)',
                $anomaly['score'], $anomaly['density'],
                $anomaly['diversity'], $anomaly['rare_count']);
            if ($anomaly['score'] >= 8) {
                $roles[] = 'lexical_anomaly';
            }
        }

        // ---- 7. 多语义场交叉加成 ----
        $fieldCount = count($activeFields);
        if ($fieldCount >= 2) {
            $crossBonus = ($fieldCount - 1) * 6;
            $score     += $crossBonus;
            $keywords[] = 'cross_field:' . $fieldCount . '(+' . $crossBonus . ')';
            $roles[]    = 'multi_field';
        }

        // ---- 8. 自然语言占比调节 ----
        $naturalRatio = $anomaly['natural_ratio'];
        if ($naturalRatio > 0.85 && empty($activeFields) && empty($collocHits) && empty($ngramHits)) {
            // 自然语言占比高且无任何技术语义场激活 → 降分
            $score = max(0, $score - 15);
            $roles[] = 'natural_language';
        } elseif ($naturalRatio < 0.15 && count($wordSet) > 2) {
            // 几乎全是技术词 → 适度加分
            $score += 8;
        }

        // ---- 9. 多角色混合加成 ----
        if (count(array_unique($roles)) >= 3) {
            $score += 5;
        }

        $score = max(0, min(100, (int) round($score)));
        return [
            'score'    => $score,
            'roles'    => array_values(array_unique($roles)),
            'keywords' => $keywords,
        ];
    }

    /* =====================================================================
     * 分词器（Tokenizer）
     * 保留顺序，捕获：HTML 标签、字符串、十六进制、数字、路径遍历、模板注入、
     * 命令链操作符、反引号、$()、PHP 超全局变量、注释、比较运算符、分隔符、标识符。
     * ===================================================================== */
    private static function tokenize(string $text): array {
        // 注意：html_tag 仅匹配 <tagname / </tagname（不含属性），
        // 让标签内部的属性（如 onerror=alert(1)）被后续规则单独分词，
        // 从而支持事件处理器、函数调用等的共现 / N-gram 分析。
        $pattern = '/'
            . '(?<html_tag><\/?[a-zA-Z][a-zA-Z0-9]*)'
            . '|(?<string>"(?:[^"\\\\]|\\\\.)*"|\'(?:[^\'\\\\]|\\\\.)*\')'
            . '|(?<hex>0x[0-9a-fA-F]+)'
            . '|(?<number>\d+(?:\.\d+)?)'
            . '|(?<path_trav>\.\.[\\\\\/])'
            . '|(?<template>\{\{|\}\}|\$\{|\#\{|\*\{)'
            . '|(?<cmd_chain>&&|\|\||\|)'
            . '|(?<backtick>`)'
            . '|(?<dollar_paren>\$\()'
            . '|(?<php_var>\$_[a-zA-Z][a-zA-Z0-9_]*)'
            . '|(?<comment>--|\/\*|\*\/|\#)'
            . '|(?<compare>!=|<=|>=|<>|=|<|>)'
            . '|(?<delim>[;,\(\)\[\]\{\}])'
            . '|(?<ident>[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
            . '|(?<other>\S)'
            . '/ux';

        $matches = [];
        preg_match_all($pattern, $text, $matches, PREG_SET_ORDER);

        $tokens = [];
        foreach ($matches as $m) {
            $tokens[] = [
                'value' => $m[0],
                'kind'  => self::matchKind($m),
            ];
        }
        return $tokens;
    }

    /** 根据命名捕获组确定 token 类型 */
    private static function matchKind(array $m): string {
        foreach (['html_tag','string','hex','number','path_trav','template',
                  'cmd_chain','backtick','dollar_paren','php_var','comment',
                  'compare','delim','ident'] as $k) {
            if (!empty($m[$k])) {
                return $k;
            }
        }
        return 'other';
    }

    /* =====================================================================
     * 词汇角色标注（POS-like Tagging）
     * 角色：KEYWORD_SQL / OP_LOGIC / KEYWORD_CMD / IDENT_TABLE / IDENT_FUNC /
     *       IDENT_VAR / IDENT / LITERAL_STRING / LITERAL_NUMBER / OP_COMPARE /
     *       DELIMITER / CONTEXT_HTML / CONTEXT_CMD / CONTEXT_PATH /
     *       CONTEXT_TEMPLATE / COMMENT / OTHER
     * ===================================================================== */
    private static function tagTokens(array $tokens): array {
        $sqlSet = array_flip(self::$sql_keywords);
        $cmdSet = array_flip(self::$cmd_keywords);
        $dbSet  = array_flip(self::$db_objects);
        $tagSet = array_flip(self::$html_tags);
        $evtSet = array_flip(self::$js_events);
        $logSet = array_flip(self::$logic_operators);

        $tagged = [];
        $n = count($tokens);
        for ($i = 0; $i < $n; $i++) {
            $value = $tokens[$i]['value'];
            $kind  = $tokens[$i]['kind'];
            $lower = function_exists('mb_strtolower')
                ? mb_strtolower($value, 'UTF-8') : strtolower($value);

            $role      = 'OTHER';
            $word      = '';
            $canonical = $lower;

            switch ($kind) {
                case 'html_tag':
                    $role = 'CONTEXT_HTML';
                    if (preg_match('/<\/?([a-zA-Z][a-zA-Z0-9]*)/', $value, $tn)) {
                        $tnLower   = strtolower($tn[1]);
                        $word      = $tnLower;
                        $canonical = '<' . $tnLower;
                    }
                    break;

                case 'string':
                    $role      = 'LITERAL_STRING';
                    $word      = $lower;
                    $canonical = $lower;
                    break;

                case 'hex':
                case 'number':
                    $role      = 'LITERAL_NUMBER';
                    $canonical = $lower;
                    break;

                case 'path_trav':
                    $role      = 'CONTEXT_PATH';
                    $canonical = $lower;
                    break;

                case 'template':
                    $role      = 'CONTEXT_TEMPLATE';
                    $canonical = $lower;
                    break;

                case 'cmd_chain':
                case 'backtick':
                case 'dollar_paren':
                    $role      = 'CONTEXT_CMD';
                    $canonical = $lower;
                    break;

                case 'php_var':
                    $role      = 'IDENT_VAR';
                    $word      = $lower;
                    $canonical = $lower;
                    break;

                case 'comment':
                    $role      = 'COMMENT';
                    $canonical = $lower;
                    break;

                case 'compare':
                    $role      = 'OP_COMPARE';
                    $canonical = $lower;
                    break;

                case 'delim':
                    $role      = 'DELIMITER';
                    $canonical = $lower;
                    break;

                case 'ident':
                    // 取首段做角色判定（忽略 table.column 的点号）
                    $firstSeg = $lower;
                    if (strpos($lower, '.') !== false) {
                        $parts     = explode('.', $lower);
                        $firstSeg  = $parts[0];
                    }
                    $canonical = $firstSeg;
                    $word      = $firstSeg;

                    if (isset($logSet[$firstSeg])) {
                        $role = 'OP_LOGIC';
                    } elseif (isset($sqlSet[$firstSeg])) {
                        $role = 'KEYWORD_SQL';
                    } elseif (isset($cmdSet[$firstSeg])) {
                        $role = 'KEYWORD_CMD';
                    } elseif (isset($dbSet[$firstSeg])) {
                        $role = 'IDENT_TABLE';
                    } elseif (isset($tagSet[$firstSeg])) {
                        $role = 'CONTEXT_HTML';
                    } elseif (isset($evtSet[$firstSeg])) {
                        $role = 'CONTEXT_HTML';
                    } elseif (self::looksLikeFunction($tokens, $i)) {
                        $role = 'IDENT_FUNC';
                    } else {
                        $role = 'IDENT';
                    }
                    break;
            }

            $tagged[] = [
                'value'     => $value,
                'lower'     => $lower,
                'kind'      => $kind,
                'role'      => $role,
                'word'      => $word,
                'canonical' => $canonical,
            ];
        }
        return $tagged;
    }

    /** 判断标识符是否像函数调用（后接可选空白 + ( ） */
    private static function looksLikeFunction(array $tokens, int $i): bool {
        $n = count($tokens);
        for ($j = $i + 1; $j < $n; $j++) {
            $k = $tokens[$j]['kind'];
            $v = $tokens[$j]['value'];
            if ($k === 'delim' && $v === '(') {
                return true;
            }
            // 非括号则不是函数调用
            return false;
        }
        return false;
    }

    /* =====================================================================
     * 语义场激活分析
     * 分值：基础 10（命中即得）+ 命中数加成（最多 +15 → 最高 25）
     * ===================================================================== */
    private static function analyzeSemanticFields(array $wordSet, string $lowerText): array {
        $results = [];
        foreach (self::$semantic_fields as $name => $vocab) {
            $total    = count($vocab);
            $hits     = 0;
            $hitWords = [];
            foreach ($vocab as $w) {
                if (self::fieldWordPresent($w, $wordSet, $lowerText)) {
                    $hits++;
                    $hitWords[] = $w;
                }
            }
            $activated = $hits > 0;
            $strength  = $total > 0 ? $hits / $total : 0.0;
            $score     = $activated ? 10 + (int) round(min(1.0, $hits / 4) * 15) : 0;
            $results[$name] = [
                'activated' => $activated,
                'hits'      => $hits,
                'total'     => $total,
                'strength'  => $strength,
                'score'     => $score,
                'hit_words' => $hitWords,
            ];
        }
        return $results;
    }

    /** 语义场词汇命中判定：纯字母数字_ 走词集合，其余走子串 */
    private static function fieldWordPresent(string $w, array $wordSet, string $lowerText): bool {
        if ($w === '') {
            return false;
        }
        if (preg_match('/^[a-z0-9_]+$/', $w)) {
            return isset($wordSet[$w]);
        }
        return strpos($lowerText, $w) !== false;
    }

    /* =====================================================================
     * 共现模式检测
     * ===================================================================== */
    private static function detectCollocations(array $wordSet, string $lowerText): array {
        $hits = [];
        foreach (self::$collocations as $rule) {
            $required = $rule[0];
            $intent   = $rule[1];
            $score    = $rule[2];
            if ($score <= 0) {
                continue;
            }
            $all = true;
            foreach ($required as $w) {
                if (!self::fieldWordPresent($w, $wordSet, $lowerText)) {
                    $all = false;
                    break;
                }
            }
            if ($all) {
                $hits[] = ['intent' => $intent, 'score' => $score, 'required' => $required];
            }
        }
        return $hits;
    }

    /* =====================================================================
     * N-gram 序列检测（顺序敏感，连续匹配；每条规则至多计一次）
     * ===================================================================== */
    private static function detectNgrams(array $canonicalSeq): array {
        $hits  = [];
        $seqLen = count($canonicalSeq);
        foreach (self::$ngrams as $rule) {
            $pattern = $rule[0];
            $label   = $rule[1];
            $score   = $rule[2];
            if ($score <= 0 || empty($pattern)) {
                continue;
            }
            $patLen = count($pattern);
            if ($patLen > $seqLen) {
                continue;
            }
            for ($i = 0; $i <= $seqLen - $patLen; $i++) {
                $match = true;
                for ($j = 0; $j < $patLen; $j++) {
                    if ($canonicalSeq[$i + $j] !== $pattern[$j]) {
                        $match = false;
                        break;
                    }
                }
                if ($match) {
                    $hits[] = ['label' => $label, 'score' => $score, 'pos' => $i];
                    break;
                }
            }
        }
        return $hits;
    }

    /* =====================================================================
     * 辅助角色收集（保留原有能力，降为辅助）
     * ===================================================================== */
    private static function collectAuxiliaryRoles(array $tagged): array {
        $roles    = [];
        $keywords = [];

        $sqlHits = $cmdHits = $dbHits = $funcHits = $tagHits = $evtHits = [];
        foreach ($tagged as $t) {
            $w = $t['word'];
            switch ($t['role']) {
                case 'KEYWORD_SQL':
                    $sqlHits[]  = $w;
                    $keywords[] = 'sql:' . $w;
                    break;
                case 'OP_LOGIC':
                    $sqlHits[]  = $w;
                    $keywords[] = 'logic:' . $w;
                    break;
                case 'KEYWORD_CMD':
                    $cmdHits[]  = $w;
                    $keywords[] = 'cmd:' . $w;
                    break;
                case 'IDENT_TABLE':
                    $dbHits[]   = $w;
                    $keywords[] = 'db:' . $w;
                    break;
                case 'IDENT_FUNC':
                    $funcHits[] = $w;
                    $keywords[] = 'func:' . $w;
                    break;
                case 'CONTEXT_HTML':
                    if ($w !== '') {
                        $evtSet = array_flip(self::$js_events);
                        if (isset($evtSet[$w])) {
                            $evtHits[]  = $w;
                            $keywords[] = 'event:' . $w;
                        } else {
                            $tagHits[]  = $w;
                            $keywords[] = 'tag:' . $w;
                        }
                    }
                    break;
            }
        }

        if (!empty($sqlHits))           $roles[] = 'sql';
        if (!empty($cmdHits))           $roles[] = 'cmd_function';
        if (!empty($dbHits))            $roles[] = 'db_object';
        if (!empty($funcHits))          $roles[] = 'function_call';
        if (!empty($tagHits) || !empty($evtHits)) $roles[] = 'html_js';

        return ['roles' => $roles, 'keywords' => $keywords];
    }

    /* =====================================================================
     * 词汇异常度评估
     * 指标：技术词密度、技术词多样性、罕见特征数、自然语言占比
     * 分值：0-15（密度×多样性 → 0-10，罕见特征 +1 each，上限 +5）
     * ===================================================================== */
    private static function assessAnomaly(array $tagged, string $lowerText): array {
        $totalTokens  = count($tagged);
        $techCount    = 0;
        $naturalCount = 0;
        $techTypeSet  = [];

        foreach ($tagged as $t) {
            $role = $t['role'];
            $w    = $t['word'];
            if ($role === 'IDENT') {
                if (self::isLikelyTechnical($w)) {
                    $techCount++;
                    if ($w !== '') {
                        $techTypeSet[$w] = true;
                    }
                } else {
                    $naturalCount++;
                }
            } elseif ($role === 'OTHER') {
                // 随机标点噪声，视作自然（中性）
                $naturalCount++;
            } else {
                // 所有结构化角色（关键字、函数、字面量、操作符、分隔符、上下文）→ 技术
                $techCount++;
                if ($w !== '') {
                    $techTypeSet[$w] = true;
                }
            }
        }

        $density       = $totalTokens > 0 ? $techCount / $totalTokens : 0.0;
        $diversity     = count($techTypeSet);
        $naturalRatio  = $totalTokens > 0 ? $naturalCount / $totalTokens : 1.0;

        // 罕见特征计数
        $rareCount = 0;
        foreach (self::$rare_patterns as $re) {
            if (preg_match($re, $lowerText)) {
                $rareCount++;
            }
        }

        $base       = (int) round(min(1.0, $density) * min(1.0, $diversity / 6) * 10);
        $rareBonus  = min(5, $rareCount);
        $anomalyScore = min(15, $base + $rareBonus);

        return [
            'score'         => $anomalyScore,
            'density'       => $density,
            'diversity'     => $diversity,
            'rare_count'    => $rareCount,
            'natural_ratio' => $naturalRatio,
            'tech_count'    => $techCount,
        ];
    }

    /**
     * 启发式判断一个 token 是否可能为技术词
     */
    private static function isLikelyTechnical(string $token): bool {
        if ($token === '') {
            return false;
        }
        if (ctype_digit($token)) {
            return true;
        }
        if (preg_match('/^0x[0-9a-f]+$/i', $token)) {
            return true;
        }
        // 长度极短的纯字母片段（如 as、by、or）多为技术片段
        if (strlen($token) <= 2 && preg_match('/^[a-z]+$/', $token)) {
            return true;
        }
        // snake_case 技术名（含下划线连接，长度>=4）
        if (strpos($token, '_') !== false && strlen($token) >= 4) {
            return true;
        }
        return false;
    }
}
