<?php
/**
 * L4 参数语义分析引擎（参数关联 + 类型推断）
 *
 * 职责：从单参数正则匹配升级为"参数间关联分析 + 参数值类型推断"。
 *   A. 参数名语义推断：状态机 token 化（下划线/驼峰分段）+ 词根归一化
 *   B. 参数值类型推断：多维特征检测真实类型（数字/布尔/URL/邮箱/JSON/HTML/SQL/命令/路径）
 *   C. 参数名-值类型一致性推理：语义预期 vs 实际类型的冲突判定（核心升级）
 *   D. 参数间关联分析（analyzeBatch）：异常分页/矛盾参数/冗余参数/注入迹象/枚举攻击
 *   E. 参数值结构异常检测：多编码层、SQL关键词密度、HTML标签密度、命令分隔符密度
 *   F. 参数上下文推理：URI 路径与参数、参数集与端点的关联
 *   G. 参数行为模式：长度异常、熵异常、字符集异常
 *
 * 公共 API：
 *   analyze($key, $value):       单参数分析，max 60 分
 *   analyzeBatch($params, $uri): 跨参数关联，加成 max 40 分；总分上限 100
 */
defined('ABSPATH') || exit;

class ParamSemantics {
    /** A. 参数名词根词典（token → 语义类别），用于 token 归一化（user_id/userId/uid/u_id → identifier 等） */
    private static $name_roots = [
        'id' => 'identifier', 'uid' => 'identifier', 'gid' => 'identifier', 'pid' => 'identifier',
        'cid' => 'identifier', 'aid' => 'identifier', 'fid' => 'identifier', 'tid' => 'identifier',
        'nid' => 'identifier', 'rid' => 'identifier', 'sid' => 'identifier', 'eid' => 'identifier', 'oid' => 'identifier',
        'page' => 'numeric', 'p' => 'numeric', 'limit' => 'numeric', 'offset' => 'numeric', 'size' => 'numeric',
        'count' => 'numeric', 'num' => 'numeric', 'number' => 'numeric', 'qty' => 'numeric', 'quantity' => 'numeric',
        'amount' => 'numeric', 'total' => 'numeric', 'index' => 'numeric', 'pos' => 'numeric', 'per' => 'numeric',
        'name' => 'name', 'username' => 'name', 'user' => 'name', 'uname' => 'name', 'login' => 'name',
        'account' => 'name', 'author' => 'name', 'nickname' => 'name', 'nick' => 'name',
        'q' => 'search', 'query' => 'search', 'keyword' => 'search', 'keywords' => 'search', 'kw' => 'search',
        'search' => 'search', 'term' => 'search', 'terms' => 'search', 'k' => 'search',
        'content' => 'content', 'body' => 'content', 'text' => 'content', 'message' => 'content', 'msg' => 'content',
        'comment' => 'content', 'desc' => 'content', 'description' => 'content', 'detail' => 'content',
        'bio' => 'content', 'about' => 'content', 'title' => 'content', 'subject' => 'content',
        'topic' => 'content', 'summary' => 'content',
        'action' => 'action', 'cmd' => 'action', 'command' => 'action', 'op' => 'action', 'do' => 'action',
        'task' => 'action', 'method' => 'action', 'func' => 'action', 'function' => 'action',
        'type' => 'flag', 't' => 'flag', 'category' => 'flag', 'cat' => 'flag', 'tag' => 'flag', 'tags' => 'flag',
        'status' => 'flag', 'state' => 'flag', 'level' => 'flag', 'mode' => 'flag', 'enabled' => 'flag',
        'disabled' => 'flag', 'active' => 'flag', 'checked' => 'flag', 'selected' => 'flag', 'remember' => 'flag',
        'agree' => 'flag', 'subscribe' => 'flag', 'verified' => 'flag',
        'password' => 'credential', 'passwd' => 'credential', 'pwd' => 'credential', 'pass' => 'credential',
        'token' => 'credential', 'secret' => 'credential', 'apikey' => 'credential', 'key' => 'credential',
        'signature' => 'credential', 'sign' => 'credential', 'hash' => 'credential', 'captcha' => 'credential',
        'email' => 'contact', 'mail' => 'contact', 'phone' => 'contact', 'tel' => 'contact', 'mobile' => 'contact',
        'url' => 'contact', 'website' => 'contact', 'ip' => 'contact', 'address' => 'contact',
        'file' => 'file', 'upload' => 'file', 'attachment' => 'file', 'avatar' => 'file', 'image' => 'file',
        'img' => 'file', 'logo' => 'file', 'pic' => 'file', 'photo' => 'file',
        'redirect' => 'redirect', 'redirect_to' => 'redirect', 'return' => 'redirect', 'returnurl' => 'redirect',
        'returnto' => 'redirect', 'next' => 'redirect', 'callback' => 'redirect', 'target' => 'redirect',
        'to' => 'redirect', 'ref' => 'redirect', 'referer' => 'redirect', 'origin' => 'redirect',
        'forward' => 'redirect', 'goto' => 'redirect',
        'date' => 'date', 'time' => 'date', 'start' => 'date', 'end' => 'date', 'begin' => 'date',
        'expire' => 'date', 'expiry' => 'date', 'from' => 'date', 'created' => 'date', 'updated' => 'date',
        'timestamp' => 'date',
    ];

    /** C. 每个类别对应的预期值类型 */
    private static $category_expect = [
        'identifier' => 'numeric', 'numeric' => 'numeric', 'flag' => 'enum', 'action' => 'word',
        'name' => 'word', 'search' => 'freetext', 'content' => 'freetext', 'contact' => 'format',
        'file' => 'filename', 'redirect' => 'path', 'credential' => 'freetext', 'date' => 'date',
    ];

    /** B/E. SQL 关键词集合（值类型推断 + 密度检测） */
    private static $sql_keywords = [
        'select','union','insert','update','delete','drop','alter','create','truncate','from','where',
        'into','table','database','schema','or','and','not','null','having','group','order','by','limit',
        'concat','substring','substr','benchmark','sleep','waitfor','load_file','outfile','dumpfile',
        'exec','execute','declare','cast','convert','like','between','exists','case','when','distinct',
        'as','join','values','set','count','char','ascii','hex','if','ifnull','version','extractvalue',
        'updatexml','information_schema','mysql','sysobjects','xp_cmdshell','admin',
    ];

    /** C. 危险伪协议（重定向参数检测） */
    private static $danger_protocols = [
        'javascript:', 'vbscript:', 'data:', 'file:', 'php:', 'expect:', 'phar:',
        'zip:', 'ssh2:', 'gopher:', 'dict:', 'ldap:',
    ];

    /** C. 路径遍历敏感目标（上下文加成） */
    private static $sensitive_paths = [
        '/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self', '/var/log', '/root/',
        '/home/', 'windows/system32', 'boot.ini', 'win.ini', 'c:\\', 'd:\\',
    ];

    /* ======================================================================
     * 公共 API 1：单参数分析（max 60 分）
     * ====================================================================== */

    /**
     * 单参数语义分析
     * @param string $key   参数名
     * @param string $value 参数值
     * @return array{score:int, category:string, mismatch:bool, reasons:array}
     */
    public static function analyze(string $key, string $value): array {
        $reasons = [];
        $score = 0;
        $mismatch = false;

        // A. 参数名语义推断
        $category = self::inferCategory($key);
        // B. 参数值类型推断
        $valueType = self::inferValueType($value);

        // C. 参数名-值类型一致性推理（核心）
        $consistency = self::checkConsistency($key, $category, $value, $valueType);
        foreach ($consistency['reasons'] as $r) $reasons[] = $r;
        $score += $consistency['score'];
        if ($consistency['mismatch']) $mismatch = true;

        // E. 参数值结构异常检测
        $structure = self::detectValueStructureAnomaly($value);
        foreach ($structure['reasons'] as $r) $reasons[] = $r;
        $score += $structure['score'];

        // G. 参数行为模式
        $behavior = self::detectBehaviorAnomaly($key, $value, $valueType);
        foreach ($behavior['reasons'] as $r) $reasons[] = $r;
        $score += $behavior['score'];

        $score = max(0, min(60, (int) round($score)));
        return ['score' => $score, 'category' => $category, 'mismatch' => $mismatch, 'reasons' => $reasons];
    }

    /* ======================================================================
     * 公共 API 2：批量分析 + 跨参数关联（加成 max 40，总分上限 100）
     * ====================================================================== */

    /**
     * 批量参数分析 + 跨参数关联分析
     * @param array  $params 参数键值对（key => value）
     * @param string $uri    请求 URI（用于上下文推理）
     * @return array{score:int, anomalies:array, correlations:array}
     */
    public static function analyzeBatch(array $params, string $uri = ''): array {
        if (empty($params)) {
            return ['score' => 0, 'anomalies' => [], 'correlations' => []];
        }
        $analyzed = [];
        $maxSingleScore = 0;
        foreach ($params as $k => $v) {
            $key = (string) $k;
            $val = (string) $v;
            $result = self::analyze($key, $val);
            $analyzed[$key] = [
                'value' => $val, 'category' => $result['category'],
                'score' => $result['score'], 'mismatch' => $result['mismatch'],
                'reasons' => $result['reasons'],
            ];
            if ($result['score'] > $maxSingleScore) $maxSingleScore = $result['score'];
        }
        // D. 跨参数关联分析（加成 max 40）
        $corr = self::detectCorrelations($analyzed, $uri);
        $totalScore = max(0, min(100, (int) round($maxSingleScore + $corr['score'])));
        return [
            'score' => $totalScore,
            'anomalies' => $corr['anomalies'],
            'correlations' => $corr['correlations'],
        ];
    }

    /* ======================================================================
     * A. 参数名语义推断：状态机 token 化 + 词根归一化
     * ====================================================================== */

    /** 参数名 token 化：user_id → [user, id]; userId → [user, id]; u_id → [u, id] */
    private static function tokenizeParamName(string $key): array {
        if ($key === '') return [];
        $tokens = [];
        $current = '';
        $len = strlen($key);
        $prevUpper = false;
        for ($i = 0; $i < $len; $i++) {
            $ch = $key[$i];
            $o = ord($ch);
            $isUpper = ($o >= 0x41 && $o <= 0x5A);
            if ($ch === '_' || $ch === '-' || $ch === '.') {
                if ($current !== '') { $tokens[] = strtolower($current); $current = ''; }
                $prevUpper = false;
                continue;
            }
            // 驼峰边界：lower→Upper 转换处切分
            if ($isUpper && !$prevUpper && $current !== '') {
                $tokens[] = strtolower($current);
                $current = $ch;
            } else {
                $current .= $ch;
            }
            $prevUpper = $isUpper;
        }
        if ($current !== '') $tokens[] = strtolower($current);
        return $tokens;
    }

    /** 基于词根推断参数语义类别；后缀 token 优先（user_id → id → identifier） */
    private static function inferCategory(string $key): string {
        $lowerKey = strtolower($key);
        if (isset(self::$name_roots[$lowerKey])) return self::$name_roots[$lowerKey];
        $tokens = self::tokenizeParamName($key);
        if (empty($tokens)) return 'unknown';
        $last = $tokens[count($tokens) - 1];
        if (isset(self::$name_roots[$last])) return self::$name_roots[$last];
        foreach ($tokens as $tok) {
            if (isset(self::$name_roots[$tok])) return self::$name_roots[$tok];
        }
        if (substr($lowerKey, -3) === '_id') return 'identifier';
        return 'unknown';
    }

    /* ======================================================================
     * B. 参数值类型推断：多维特征检测
     * ====================================================================== */

    /** 推断参数值的真实类型（基于字符分布、长度、特殊字符模式、结构） */
    private static function inferValueType(string $value): array {
        $len = strlen($value);
        if ($len === 0) {
            return ['type' => 'empty', 'features' => [], 'sql_count' => 0, 'angle_count' => 0, 'entropy' => 0.0];
        }
        $lower = strtolower($value);
        $features = [];

        // 1. 纯整数 / 浮点
        if (preg_match('/^-?\d+$/', $value)) {
            return ['type' => 'numeric', 'features' => ['int'], 'sql_count' => 0, 'angle_count' => 0, 'entropy' => self::shannonEntropy($value)];
        }
        if (preg_match('/^-?\d+\.\d+$/', $value)) {
            return ['type' => 'numeric', 'features' => ['float'], 'sql_count' => 0, 'angle_count' => 0, 'entropy' => self::shannonEntropy($value)];
        }
        // 2. 布尔
        if (in_array($lower, ['true','false','1','0','yes','no','on','off','y','n','enabled','disabled','active','inactive'], true)) {
            return ['type' => 'boolean', 'features' => ['bool'], 'sql_count' => 0, 'angle_count' => 0, 'entropy' => 0.0];
        }
        // 3. URL / 邮箱 / JSON
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.\-]{1,32}://#', $value) || self::startsWith($value, '//')) $features[] = 'url';
        if (preg_match('/^[^@\s]{1,64}@[^@\s]{1,64}\.[^@\s]{2,24}$/', $value)) $features[] = 'email';
        if (($value[0] === '{' && substr($value, -1) === '}') || ($value[0] === '[' && substr($value, -1) === ']')) {
            if (function_exists('json_decode') && json_decode($value) !== null) $features[] = 'json';
        }

        // 4. 结构化特征统计
        $angleCount = substr_count($value, '<') + substr_count($value, '>');
        $sqlCount = self::countSqlKeywords($value, $lower);
        $hasQuote = (bool) preg_match('#[\'"`]#', $value);
        $cmdSepHit = (bool) preg_match('#[;|&`]\s*[a-zA-Z$_(]#', $value);
        $hasDollarParen = (strpos($value, '$(') !== false);
        $hasTraversal = (strpos($value, '../') !== false || strpos($value, '..\\') !== false);
        $hasPathSep = (strpos($value, '/') !== false || strpos($value, '\\') !== false);

        if ($angleCount >= 2 && preg_match('#<[a-zA-Z/]#', $value)) $features[] = 'html';
        if ($sqlCount > 0 && ($hasQuote || (bool) preg_match('#=\s*[\'"]?#', $value) || (bool) preg_match('#\b(or|and|union|select)\b#i', $value))) $features[] = 'sql';
        if ($cmdSepHit || $hasDollarParen) $features[] = 'command';
        if ($hasTraversal) {
            $features[] = 'traversal';
        } elseif ($hasPathSep && preg_match('#[/\\\\][a-zA-Z0-9_\-.]+#', $value)) {
            $features[] = 'path';
        }
        foreach (self::$danger_protocols as $proto) {
            if (self::startsWith($lower, $proto)) { $features[] = 'danger_protocol'; break; }
        }

        // 5. 主类型裁决（按危险度优先级）
        $type = 'text';
        if (in_array('traversal', $features, true)) $type = 'traversal';
        elseif (in_array('danger_protocol', $features, true)) $type = 'danger_protocol';
        elseif (in_array('sql', $features, true)) $type = 'sql';
        elseif (in_array('command', $features, true)) $type = 'command';
        elseif (in_array('html', $features, true)) $type = 'html';
        elseif (in_array('json', $features, true)) $type = 'json';
        elseif (in_array('email', $features, true)) $type = 'email';
        elseif (in_array('url', $features, true)) $type = 'url';
        elseif (in_array('path', $features, true)) $type = 'path';

        return ['type' => $type, 'features' => $features, 'sql_count' => $sqlCount, 'angle_count' => $angleCount, 'entropy' => self::shannonEntropy($value)];
    }

    /** 统计值中出现的 SQL 关键词数（去重 token 词边界匹配，避免 "and" 命中 "android"） */
    private static function countSqlKeywords(string $value, $lower = null): int {
        if ($lower === null) $lower = strtolower($value);
        $count = 0;
        foreach (self::$sql_keywords as $kw) {
            if (preg_match('#\b' . preg_quote($kw, '#') . '\b#', $lower)) $count++;
        }
        return $count;
    }

    /* ======================================================================
     * C. 参数名-值类型一致性推理（核心升级）
     * ====================================================================== */

    /** 检查参数名语义预期与实际值类型的一致性 */
    private static function checkConsistency(string $key, string $category, string $value, array $valueType): array {
        $reasons = [];
        $score = 0;
        $mismatch = false;
        $expect = self::$category_expect[$category] ?? null;
        if ($expect === null) return ['reasons' => [], 'score' => 0, 'mismatch' => false];

        $valueLen = strlen($value);
        $features = $valueType['features'] ?? [];
        $isNumeric = ($valueType['type'] === 'numeric');
        $hasSql = in_array('sql', $features, true);
        $hasCmd = in_array('command', $features, true);
        $hasHtml = in_array('html', $features, true);
        $hasTraversal = in_array('traversal', $features, true);
        $hasDangerProto = in_array('danger_protocol', $features, true);
        $lower = strtolower($value);

        switch ($expect) {
            case 'numeric':
                // 数值参数(id/page/limit)出现非数字 → 高度可疑
                if (!$isNumeric) {
                    $mismatch = true;
                    if ($hasSql) { $score += 45; $reasons[] = 'numeric_param_with_sql_injection'; }
                    elseif ($hasCmd) { $score += 35; $reasons[] = 'numeric_param_with_command'; }
                    elseif ($hasHtml) { $score += 30; $reasons[] = 'numeric_param_with_html'; }
                    elseif ($hasTraversal) { $score += 32; $reasons[] = 'numeric_param_with_traversal'; }
                    elseif ($hasDangerProto) { $score += 30; $reasons[] = 'numeric_param_with_danger_protocol'; }
                    else { $score += 18; $reasons[] = 'numeric_param_non_numeric'; }
                }
                break;
            case 'enum':
                // 布尔/枚举参数(remember/active)出现长字符串 → 异常
                $validEnums = ['0','1','true','false','yes','no','on','off','enabled','disabled','active','inactive','checked','unchecked','y','n'];
                if ($value !== '' && !in_array($lower, $validEnums, true)) {
                    if ($valueLen > 20 || (bool) preg_match('#[<>\'"`;|&$(){}\[\]\\\\]#', $value)) {
                        $mismatch = true; $score += 25; $reasons[] = 'flag_param_with_complex_value';
                    }
                }
                break;
            case 'word':
                // 名称类不应包含代码结构字符
                if ((bool) preg_match('#[<>\'"`;|&$(){}\[\]\\\\]#', $value)) {
                    $mismatch = true; $score += 22; $reasons[] = 'name_param_with_special_chars';
                }
                break;
            case 'filename':
                // 文件参数(avatar)出现路径遍历 → 路径注入
                if ($hasTraversal) {
                    $mismatch = true; $score += 38; $reasons[] = 'file_param_with_path_traversal';
                    foreach (self::$sensitive_paths as $sp) {
                        if (strpos($lower, $sp) !== false) { $score += 8; $reasons[] = 'traversal_to_sensitive_path'; break; }
                    }
                } elseif ((bool) preg_match('#[/\\\\]#', $value)) {
                    $mismatch = true; $score += 22; $reasons[] = 'file_param_with_path_separator';
                }
                break;
            case 'path':
                // 重定向参数(returnUrl)出现 javascript: → XSS 注入
                if ($hasDangerProto) {
                    $mismatch = true; $score += 40;
                    foreach (self::$danger_protocols as $proto) {
                        if (self::startsWith($lower, $proto)) { $reasons[] = 'redirect_to_dangerous_protocol:' . substr($proto, 0, -1); break; }
                    }
                }
                break;
            case 'format':
                // 邮箱/URL 等格式校验
                if (($key === 'email' || $key === 'mail') && $value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    if ((bool) preg_match('#[<>\'"`;|&]#', $value)) {
                        $mismatch = true; $score += 18; $reasons[] = 'malformed_email_with_special_chars';
                    }
                }
                break;
            case 'freetext':
                // 凭证参数(password)出现 SQL 结构 → 凭证注入
                if ($hasSql && $category === 'credential') {
                    $mismatch = true; $score += 32; $reasons[] = 'credential_param_with_sql_structure';
                } elseif ($hasSql) {
                    // 内容/搜索类：仅当 SQL 关键词密度高时判定
                    $sqlCount = $valueType['sql_count'] ?? 0;
                    if ($sqlCount >= 2) { $mismatch = true; $score += 22; $reasons[] = 'freetext_with_sql_density'; }
                }
                break;
            case 'date':
                // 日期参数应符合日期格式
                $isDate = (bool) preg_match('#^\d{4}[-/]\d{1,2}[-/]\d{1,2}#', $value)
                       || (bool) preg_match('#^\d{1,2}[-/]\d{1,2}[-/]\d{4}#', $value)
                       || (bool) preg_match('#^\d{10,13}$#', $value);
                if (!$isDate && (bool) preg_match('#[<>\'"`;|&$`]#', $value)) {
                    $mismatch = true; $score += 20; $reasons[] = 'date_param_with_injection_chars';
                }
                break;
        }
        return ['reasons' => $reasons, 'score' => $score, 'mismatch' => $mismatch];
    }

    /* ======================================================================
     * E. 参数值结构异常检测
     * ====================================================================== */

    /** 检测值内结构异常：多编码层、SQL关键词密度、HTML标签密度、命令分隔符密度 */
    private static function detectValueStructureAnomaly(string $value): array {
        $reasons = [];
        $score = 0;
        if (strlen($value) < 4) return ['reasons' => [], 'score' => 0];

        // 多编码层：URL编码 + Base64 + HTML实体
        $hasUrlEnc = (bool) preg_match('#%[0-9a-fA-F]{2}#', $value);
        $hasHexEntity = (bool) preg_match('~&#[xX]?[0-9a-fA-F]{2,4};~', $value);
        $hasBase64 = self::looksLikeBase64Payload($value);
        $layers = ($hasUrlEnc ? 1 : 0) + ($hasBase64 ? 1 : 0) + ($hasHexEntity ? 1 : 0);
        if ($layers >= 2) { $score += 12; $reasons[] = 'multi_encoding_layer:' . $layers; }

        // SQL 关键词密度：3+ / 2+
        $sqlCount = self::countSqlKeywords($value);
        if ($sqlCount >= 3) { $score += 10; $reasons[] = 'sql_keyword_density:' . $sqlCount; }
        elseif ($sqlCount >= 2) { $score += 5; $reasons[] = 'sql_keyword_density:' . $sqlCount; }

        // HTML 标签密度
        $ltCount = substr_count($value, '<');
        if ($ltCount >= 2) { $score += 8; $reasons[] = 'html_tag_density:' . $ltCount; }

        // 命令分隔符密度
        $cmdSepCount = preg_match_all('#[;|&`]#', $value);
        if ($cmdSepCount >= 2) { $score += 8; $reasons[] = 'cmd_sep_density:' . $cmdSepCount; }

        return ['reasons' => $reasons, 'score' => min(15, $score)];
    }

    /** 启发式判定值是否疑似 Base64 载荷 */
    private static function looksLikeBase64Payload(string $value): bool {
        if (!preg_match('#[A-Za-z0-9+/]{16,}={0,2}#', $value, $m)) return false;
        $candidate = $m[0];
        $variety = (preg_match('#[A-Z]#', $candidate) ? 1 : 0) + (preg_match('#[a-z]#', $candidate) ? 1 : 0) + (preg_match('#[0-9]#', $candidate) ? 1 : 0);
        if ($variety < 2) return false;
        return self::shannonEntropy($candidate) > 4.0;
    }

    /* ======================================================================
     * G. 参数行为模式
     * ====================================================================== */

    /** 检测参数行为异常：长度异常、熵异常、字符集异常 */
    private static function detectBehaviorAnomaly(string $key, string $value, array $valueType): array {
        $reasons = [];
        $score = 0;
        $valueLen = strlen($value);
        $keyLen = strlen($key);

        // 短参数名 + 超长值（>500 强异常；>200 弱异常）
        if ($keyLen <= 4 && $valueLen > 500) { $score += 8; $reasons[] = 'short_key_long_value:' . $valueLen; }
        elseif ($keyLen <= 4 && $valueLen > 200) { $score += 4; $reasons[] = 'short_key_long_value:' . $valueLen; }

        // 熵异常：极高熵值可能是加密 payload
        if ($valueLen >= 32) {
            $entropy = $valueType['entropy'] ?? 0.0;
            if ($entropy > 4.7) { $score += 6; $reasons[] = 'high_entropy:' . round($entropy, 2); }
        }

        // 字符集异常：参数值含二进制/不可打印字符
        if (self::hasHighBinaryRatio($value)) { $score += 6; $reasons[] = 'binary_chars_in_value'; }

        return ['reasons' => $reasons, 'score' => min(10, $score)];
    }

    /* ======================================================================
     * D. 跨参数关联分析（analyzeBatch 核心）
     * ====================================================================== */

    /** 跨参数关联分析总入口 */
    private static function detectCorrelations(array $analyzed, string $uri): array {
        $anomalies = [];
        $correlations = [];
        $score = 0;
        $score += self::detectAbnormalPagination($analyzed, $anomalies, $correlations);
        $score += self::detectDateContradiction($analyzed, $anomalies, $correlations);
        $score += self::detectRedundantIdentifiers($analyzed, $anomalies, $correlations);
        $score += self::detectIsolatedInjection($analyzed, $anomalies, $correlations);
        $score += self::detectEnumerationPattern($analyzed, $anomalies, $correlations);
        $score += self::detectUriContextAnomaly($analyzed, $uri, $anomalies, $correlations);
        return ['score' => min(40, $score), 'anomalies' => $anomalies, 'correlations' => $correlations];
    }

    /** D-1. 异常分页：page + size 中 size 过大（如 size=999999） */
    private static function detectAbnormalPagination(array $analyzed, array &$anomalies, array &$correlations): int {
        $hasPage = false;
        $candidates = [];
        foreach ($analyzed as $k => $info) {
            if ($info['category'] !== 'numeric') continue;
            $lk = strtolower($k);
            if ($lk === 'page' || $lk === 'p') $hasPage = true;
            elseif (in_array($lk, ['size','pagesize','per_page','per','limit'], true)) $candidates[] = [$k, $info['value']];
        }
        if (!$hasPage) return 0;
        foreach ($candidates as $pair) {
            list($kk, $vv) = $pair;
            if ($vv === '' || !preg_match('/^\d+$/', $vv)) continue;
            $iv = (int) $vv;
            if ($iv > 10000) {
                $anomalies[] = 'abnormal_pagination:' . $kk . '=' . $vv;
                $correlations[] = ['type' => 'abnormal_pagination', 'key' => $kk, 'value' => $vv, 'severity' => 'mid'];
                return 22;
            }
            if ($iv > 1000) {
                $anomalies[] = 'large_pagination:' . $kk . '=' . $vv;
                $correlations[] = ['type' => 'large_pagination', 'key' => $kk, 'value' => $vv, 'severity' => 'low'];
                return 12;
            }
        }
        return 0;
    }

    /** D-2. 矛盾日期参数：start_date > end_date */
    private static function detectDateContradiction(array $analyzed, array &$anomalies, array &$correlations): int {
        $start = null; $end = null; $startKey = null; $endKey = null;
        foreach ($analyzed as $k => $info) {
            if ($info['category'] !== 'date') continue;
            $lk = strtolower($k);
            $tokens = self::tokenizeParamName($k);
            $isStart = ($lk === 'start' || $lk === 'begin' || $lk === 'from'
                || in_array('start', $tokens, true) || in_array('begin', $tokens, true) || in_array('from', $tokens, true));
            $isEnd = ($lk === 'end' || $lk === 'expire' || $lk === 'expiry'
                || in_array('end', $tokens, true) || in_array('expire', $tokens, true) || in_array('expiry', $tokens, true));
            if ($isStart && $start === null) { $start = $info['value']; $startKey = $k; }
            elseif ($isEnd && $end === null) { $end = $info['value']; $endKey = $k; }
        }
        if ($start === null || $end === null || $start === '' || $end === '') return 0;
        $sTs = self::parseDateToTimestamp($start);
        $eTs = self::parseDateToTimestamp($end);
        if ($sTs === null || $eTs === null) return 0;
        if ($sTs > $eTs) {
            $anomalies[] = 'date_contradiction:' . $startKey . '>' . $endKey;
            $correlations[] = ['type' => 'date_contradiction', 'start' => $startKey, 'end' => $endKey, 'severity' => 'mid'];
            return 18;
        }
        return 0;
    }

    /** D-3. 冗余 ID：相同语义不同 key（id=1&uid=2） */
    private static function detectRedundantIdentifiers(array $analyzed, array &$anomalies, array &$correlations): int {
        $identKeys = [];
        foreach ($analyzed as $k => $info) {
            if ($info['category'] === 'identifier') $identKeys[] = $k;
        }
        if (count($identKeys) < 2) return 0;
        $values = [];
        foreach ($identKeys as $k) $values[$k] = $analyzed[$k]['value'];
        $uniqueVals = array_unique(array_values($values));
        $anomalies[] = 'redundant_identifiers:' . implode(',', $identKeys);
        $severity = count($uniqueVals) > 1 ? 'mid' : 'low';
        $correlations[] = ['type' => 'redundant_identifier', 'keys' => $identKeys, 'values' => $values, 'severity' => $severity];
        return count($uniqueVals) > 1 ? 12 : 8;
    }

    /** D-4. 注入迹象：参数集中仅 1 个含异常字符（3+ 参数且恰好 1 个异常 → 定向注入） */
    private static function detectIsolatedInjection(array $analyzed, array &$anomalies, array &$correlations): int {
        $anomalyKeys = [];
        $normalCount = 0;
        $totalParams = count($analyzed);
        foreach ($analyzed as $k => $info) {
            if ($info['mismatch'] || $info['score'] > 0) $anomalyKeys[] = $k;
            else $normalCount++;
        }
        if ($totalParams < 3 || count($anomalyKeys) !== 1) return 0;
        $anomalies[] = 'isolated_injection_target:' . $anomalyKeys[0];
        $correlations[] = ['type' => 'isolated_injection', 'target' => $anomalyKeys[0], 'normal_count' => $normalCount, 'severity' => 'mid'];
        return 15;
    }

    /** D-5. 枚举攻击：多个 ID 类参数值序列化（id=1&uid=2&gid=3） */
    private static function detectEnumerationPattern(array $analyzed, array &$anomalies, array &$correlations): int {
        $identVals = [];
        foreach ($analyzed as $k => $info) {
            if ($info['category'] === 'identifier' && preg_match('/^\d+$/', $info['value'])) $identVals[$k] = (int) $info['value'];
        }
        if (count($identVals) < 3) return 0;
        $vals = array_values($identVals);
        sort($vals, SORT_NUMERIC);
        $isSequential = true;
        $n = count($vals);
        for ($i = 1; $i < $n; $i++) {
            if ($vals[$i] - $vals[$i - 1] !== 1) { $isSequential = false; break; }
        }
        if ($isSequential) {
            $anomalies[] = 'enumeration_pattern:sequential_ids';
            $correlations[] = ['type' => 'enumeration', 'pattern' => 'sequential', 'severity' => 'mid'];
            return 18;
        }
        return 0;
    }

    /* ======================================================================
     * F. URI 上下文推理
     * ====================================================================== */

    /** F. URI 路径与参数集的关联异常 */
    private static function detectUriContextAnomaly(array $analyzed, string $uri, array &$anomalies, array &$correlations): int {
        if ($uri === '') return 0;
        $lowerUri = strtolower($uri);
        $score = 0;

        // F-1. 登录/认证端点出现文件参数（异常）
        $isAuthEndpoint = (strpos($lowerUri, '/login') !== false || strpos($lowerUri, '/signin') !== false
            || strpos($lowerUri, '/auth') !== false || strpos($lowerUri, '/register') !== false);
        if ($isAuthEndpoint) {
            foreach ($analyzed as $k => $info) {
                if ($info['category'] === 'file') {
                    $anomalies[] = 'file_param_on_auth_endpoint:' . $k;
                    $correlations[] = ['type' => 'context_mismatch', 'endpoint' => 'auth', 'param' => $k, 'severity' => 'mid'];
                    $score += 18;
                    break;
                }
            }
        }
        // F-2. 用户端点出现 SQL 注入 ID
        if (strpos($lowerUri, '/user') !== false) {
            foreach ($analyzed as $k => $info) {
                if ($info['category'] === 'identifier' && $info['mismatch']) {
                    $anomalies[] = 'user_endpoint_id_injection:' . $k;
                    $correlations[] = ['type' => 'context_injection', 'endpoint' => 'user', 'param' => $k, 'severity' => 'high'];
                    $score += 10;
                    break;
                }
            }
        }
        // F-3. 静态资源端点出现查询参数（异常）
        if (preg_match('#\.(jpg|jpeg|png|gif|css|js|ico|svg)$#', $lowerUri) && count($analyzed) >= 2) {
            $anomalies[] = 'static_resource_with_params:' . count($analyzed);
            $correlations[] = ['type' => 'context_mismatch', 'endpoint' => 'static', 'severity' => 'low'];
            $score += 8;
        }
        return min(20, $score);
    }

    /* ======================================================================
     * 工具方法
     * ====================================================================== */

    /** 解析日期字符串为时间戳（YYYY-MM-DD / DD-MM-YYYY / 时间戳） */
    private static function parseDateToTimestamp(string $value) {
        if ($value === '') return null;
        if (preg_match('#^\d{10,13}$#', $value)) {
            $ts = (int) $value;
            return strlen($value) === 13 ? (int) ($ts / 1000) : $ts;
        }
        if (preg_match('#^(\d{4})[-/](\d{1,2})[-/](\d{1,2})#', $value, $m)) {
            $ts = gmmktime(0, 0, 0, (int) $m[2], (int) $m[3], (int) $m[1]);
            return $ts === false ? null : $ts;
        }
        if (preg_match('#^(\d{1,2})[-/](\d{1,2})[-/](\d{4})#', $value, $m)) {
            $ts = gmmktime(0, 0, 0, (int) $m[2], (int) $m[1], (int) $m[3]);
            return $ts === false ? null : $ts;
        }
        $ts = strtotime($value);
        return $ts === false ? null : $ts;
    }

    /** 计算 Shannon 熵（按字节） */
    private static function shannonEntropy(string $text): float {
        $len = strlen($text);
        if ($len === 0) return 0.0;
        $freq = count_chars($text, 1);
        $entropy = 0.0;
        foreach ($freq as $cnt) {
            $p = $cnt / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    /** 判断字符串是否以指定前缀开头 */
    private static function startsWith(string $hay, string $needle): bool {
        return $needle !== '' && strncmp($hay, $needle, strlen($needle)) === 0;
    }

    /** 检测值中是否含有高比例二进制/不可打印字符 */
    private static function hasHighBinaryRatio(string $value): bool {
        $len = strlen($value);
        if ($len < 8) return false;
        $binary = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($value[$i]);
            if (($o < 0x20 && $o !== 0x09 && $o !== 0x0A && $o !== 0x0D) || $o === 0x7F) $binary++;
        }
        return ($binary / $len) > 0.05;
    }
}
