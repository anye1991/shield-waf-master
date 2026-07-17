<?php
/**
 * 词汇语义分析引擎
 * 职责：识别输入文本中词汇的角色（SQL关键字、数据库对象、危险函数、HTML/JS标签等），
 *       并结合自然语言占比判断输入是攻击载荷还是普通文本。
 */
defined('ABSPATH') || exit;

class WordSemantics {
    /** SQL 关键字及其权重 */
    private static $sql_keywords = [
        'select' => 8, 'union' => 9, 'insert' => 8, 'update' => 7, 'delete' => 8,
        'drop' => 9, 'alter' => 8, 'create' => 6, 'truncate' => 9, 'from' => 5,
        'where' => 5, 'into' => 5, 'table' => 5, 'database' => 5, 'schema' => 5,
        'or' => 4, 'and' => 3, 'not' => 2, 'null' => 3, 'true' => 2, 'false' => 2,
        'having' => 6, 'group' => 4, 'order' => 3, 'by' => 2, 'limit' => 4,
        'concat' => 6, 'group_concat' => 8, 'substring' => 5, 'substr' => 5,
        'benchmark' => 9, 'sleep' => 8, 'waitfor' => 8, 'delay' => 5,
        'xp_cmdshell' => 10, 'load_file' => 8, 'outfile' => 8, 'dumpfile' => 8,
        'exec' => 6, 'execute' => 6, 'declare' => 5, 'cast' => 4, 'convert' => 4,
        'like' => 3, 'between' => 3, 'exists' => 4, 'case' => 3, 'when' => 3,
        'distinct' => 4, 'as' => 2, 'join' => 4, 'inner' => 3, 'left' => 3,
    ];

    /** 数据库敏感表名 / 列名 */
    private static $db_objects = [
        'users', 'user', 'admin', 'administrator', 'password', 'passwd', 'pwd',
        'username', 'user_name', 'login', 'email', 'mail', 'session', 'token',
        'information_schema', 'mysql', 'sysobjects', 'syscolumns', 'master',
        'wp_users', 'accounts', 'members', 'credit_card', 'ssn',
    ];

    /** 危险函数名（PHP / 通用） */
    private static $danger_functions = [
        'eval', 'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'assert', 'preg_replace', 'create_function', 'call_user_func', 'unserialize',
        'base64_decode', 'base64_encode', 'gzinflate', 'gzuncompress', 'str_rot13',
        'pack', 'unpack', 'hex2bin', 'convert_uudecode', 'file_get_contents',
        'file_put_contents', 'fopen', 'readfile', 'include', 'require', 'fputs',
        'fwrite', 'move_uploaded_file', 'curl_exec',
    ];

    /** HTML / JS 标签 */
    private static $html_tags = [
        'script', 'iframe', 'img', 'svg', 'body', 'object', 'embed', 'video',
        'audio', 'style', 'link', 'meta', 'form', 'input', 'textarea', 'details',
        'marquee', 'base', 'applet', 'frame', 'frameset',
    ];

    /** JS 事件处理器 */
    private static $js_events = [
        'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur',
        'onchange', 'onsubmit', 'onkeydown', 'onkeypress', 'onkeyup', 'onunload',
        'ondblclick', 'oninput', 'ontoggle', 'onanimationstart', 'onpointerover',
    ];

    /**
     * 词汇角色识别
     *
     * @param string $text
     * @return array{score:int, roles:array, keywords:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return ['score' => 0, 'roles' => [], 'keywords' => []];
        }

        $roles = [];
        $keywords = [];
        $score = 0;

        // 统一小写用于关键词匹配
        $lower = function_exists('mb_strtolower') ? mb_strtolower($text, 'UTF-8') : strtolower($text);
        // 按非字母数字（含下划线）分割为 token
        $split = preg_split('/[^0-9a-z_]+/u', $lower);
        $tokens = [];
        if ($split) {
            foreach ($split as $t) {
                if ($t !== '') {
                    $tokens[] = $t;
                }
            }
        }
        $tokenCount = count($tokens);
        $tokenSet = array_flip($tokens);

        // ---- 1. SQL 关键字识别 ----
        $sqlHits = [];
        $sqlWeight = 0;
        foreach (self::$sql_keywords as $kw => $w) {
            if (isset($tokenSet[$kw])) {
                $sqlHits[] = $kw;
                $sqlWeight += $w;
                $keywords[] = 'sql:' . $kw;
            }
        }
        if (!empty($sqlHits)) {
            $roles[] = 'sql';
            $score += min(40, $sqlWeight);
        }

        // ---- 2. 数据库对象识别 ----
        $dbHits = [];
        foreach (self::$db_objects as $obj) {
            if (isset($tokenSet[$obj]) || strpos($lower, $obj) !== false) {
                $dbHits[] = $obj;
                $keywords[] = 'db:' . $obj;
            }
        }
        if (!empty($dbHits)) {
            $roles[] = 'db_object';
            $score += min(20, count($dbHits) * 6);
        }

        // ---- 3. 危险函数识别（通常后接括号） ----
        $funcHits = [];
        foreach (self::$danger_functions as $fn) {
            if (preg_match('/\b' . preg_quote($fn, '/') . '\s*\(/i', $text)) {
                $funcHits[] = $fn;
                $keywords[] = 'func:' . $fn;
            }
        }
        if (!empty($funcHits)) {
            $roles[] = 'function_call';
            $score += min(25, count($funcHits) * 8);
        }

        // ---- 4. HTML / JS 标签与事件识别 ----
        $tagHits = [];
        foreach (self::$html_tags as $tag) {
            if (preg_match('/<' . preg_quote($tag, '/') . '\b/i', $text) || isset($tokenSet[$tag])) {
                $tagHits[] = $tag;
                $keywords[] = 'tag:' . $tag;
            }
        }
        $evtHits = [];
        foreach (self::$js_events as $evt) {
            if (preg_match('/\b' . preg_quote($evt, '/') . '\s*=/i', $text)) {
                $evtHits[] = $evt;
                $keywords[] = 'event:' . $evt;
            }
        }
        if (!empty($tagHits) || !empty($evtHits)) {
            $roles[] = 'html_js';
            $score += min(25, count($tagHits) * 5 + count($evtHits) * 6);
        }

        // ---- 5. 自然语言占比判断 ----
        $technicalTokens = array_merge($sqlHits, $dbHits, $funcHits, $tagHits, $evtHits);
        $techSet = array_flip($technicalTokens);
        $naturalCount = 0;
        foreach ($tokens as $t) {
            if (!isset($techSet[$t]) && !self::isLikelyTechnical($t)) {
                $naturalCount++;
            }
        }
        $naturalRatio = $tokenCount > 0 ? $naturalCount / $tokenCount : 1.0;
        // 自然语言占比越高，越倾向于正常输入（适度降低分数）
        if ($naturalRatio > 0.85 && empty($sqlHits) && empty($funcHits) && empty($tagHits) && empty($evtHits)) {
            $score = max(0, $score - 15);
            $roles[] = 'natural_language';
        } elseif ($naturalRatio < 0.15 && $tokenCount > 2) {
            // 几乎全是技术词
            $score += 10;
            $keywords[] = 'low_natural_ratio:' . round($naturalRatio, 2);
        }

        // 同时命中多类角色说明混合载荷，攻击意图更强
        if (count($roles) >= 2) {
            $score += 5;
        }

        $score = max(0, min(100, (int) round($score)));
        return [
            'score'    => $score,
            'roles'    => array_values(array_unique($roles)),
            'keywords' => $keywords,
        ];
    }

    /**
     * 启发式判断一个 token 是否可能为技术词
     * （纯数字、十六进制、极短辅音串等）
     */
    private static function isLikelyTechnical(string $token): bool {
        if ($token === '') {
            return false;
        }
        if (ctype_digit($token)) {
            return true;
        }
        // 0x 开头的十六进制
        if (preg_match('/^0x[0-9a-f]+$/i', $token)) {
            return true;
        }
        // 长度极短的纯字母片段（很可能是技术片段，如 as、by、or）
        if (strlen($token) <= 2 && preg_match('/^[a-z]+$/', $token)) {
            return true;
        }
        return false;
    }
}
