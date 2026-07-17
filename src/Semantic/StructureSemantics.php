<?php
/**
 * 结构语义分析引擎（基于状态机的结构识别）
 *
 * 职责：从整体结构层面识别输入是否构成可执行的代码结构、SQL结构、
 *       命令行结构或路径结构。结构比单点字符/词汇更具攻击意图证明力。
 *
 * 升级说明：从正则匹配模式升级为六大状态机联合识别，包括：
 *   A. SQL结构状态机 - token化+状态转移识别SQL语法结构
 *   B. HTML结构状态机 - 逐字符解析标签结构
 *   C. 命令结构状态机 - 命令分隔符语义识别
 *   D. 路径结构状态机 - 字符级路径遍历检测
 *   E. 结构复杂度分析 - AST-like深度、熵、密度
 *   F. 结构上下文分析 - 多结构类型互证与组合模式
 */
defined('ABSPATH') || exit;

class StructureSemantics {

    private static $sql_dql = ['select', 'from', 'where', 'having', 'group', 'order', 'by', 'limit', 'union', 'join', 'inner', 'left', 'right', 'outer', 'as', 'distinct'];
    private static $sql_dml = ['insert', 'update', 'delete', 'into', 'values', 'set'];
    private static $sql_ddl = ['create', 'drop', 'alter', 'truncate', 'table', 'database', 'schema', 'index'];
    private static $sql_other = ['and', 'or', 'not', 'null', 'true', 'false', 'like', 'between', 'exists', 'in', 'is', 'concat', 'substring', 'sleep', 'benchmark', 'load_file', 'outfile', 'dumpfile', 'exec', 'execute', 'declare', 'cast', 'convert', 'information_schema'];
    private static $sensitive_paths = ['/etc/', '/proc/', '/var/', '/root/', '/tmp/', '/home/', '/bin/', '/sbin/', '/usr/', '/boot/', '/dev/'];
    private static $php_wrappers = ['php://', 'file://', 'data://', 'expect://', 'zip://', 'phar://'];

    /**
     * 结构语义分析主入口
     *
     * @param string $text 待分析文本
     * @return array{score:int, structures:array}
     */
    public static function analyze(string $text): array {
        if ($text === '') {
            return ['score' => 0, 'structures' => []];
        }

        $structures = [];
        $hits = [];

        $sqlResult = self::analyzeSqlStructure($text);
        if ($sqlResult['score'] > 0) {
            $hits['sql'] = $sqlResult['score'];
            foreach ($sqlResult['structures'] as $s) $structures[] = $s;
        }

        $htmlResult = self::analyzeHtmlStructure($text);
        if ($htmlResult['score'] > 0) {
            $hits['html'] = $htmlResult['score'];
            foreach ($htmlResult['structures'] as $s) $structures[] = $s;
        }

        $cmdResult = self::analyzeCommandStructure($text);
        if ($cmdResult['score'] > 0) {
            $hits['cmd'] = $cmdResult['score'];
            foreach ($cmdResult['structures'] as $s) $structures[] = $s;
        }

        $pathResult = self::analyzePathStructure($text);
        if ($pathResult['score'] > 0) {
            $hits['path'] = $pathResult['score'];
            foreach ($pathResult['structures'] as $s) $structures[] = $s;
        }

        $complexResult = self::analyzeComplexity($text);
        if ($complexResult['score'] > 0) {
            $hits['complexity'] = $complexResult['score'];
            foreach ($complexResult['structures'] as $s) $structures[] = $s;
        }

        $ctxResult = self::analyzeContext($hits, $structures);
        $score = $ctxResult['score'];
        foreach ($ctxResult['structures'] as $s) $structures[] = $s;

        $score = max(0, min(100, (int) round($score)));
        return ['score' => $score, 'structures' => $structures];
    }

    /* =============== A. SQL结构状态机 =============== */

    /**
     * SQL结构状态机分析
     * @param string $text
     * @return array{score:int, structures:array}
     */
    private static function analyzeSqlStructure(string $text): array {
        $structures = [];
        $score = 0;
        $tokens = self::sqlTokenize($text);
        $state = 'IDLE';
        $currentKeyword = '';
        $hasSelect = $hasFrom = $hasUnion = $hasWhere = false;
        $dmlDetected = $ddlDetected = $commentDetected = false;
        $logicChainCount = 0;
        $inSqlContext = false;

        $sqlKeywords = array_flip(array_merge(self::$sql_dql, self::$sql_dml, self::$sql_ddl, self::$sql_other));

        foreach ($tokens as $tok) {
            $lower = strtolower($tok['value']);
            $isKw = $tok['type'] === 'IDENT' && isset($sqlKeywords[$lower]);
            $isLogic = $lower === 'and' || $lower === 'or';

            if ($isKw) {
                $inSqlContext = true;
                if ($lower === 'select') $hasSelect = true;
                if ($lower === 'from') $hasFrom = true;
                if ($lower === 'union') $hasUnion = true;
                if ($lower === 'where') $hasWhere = true;
                if (in_array($lower, self::$sql_dml, true)) $dmlDetected = true;
                if (in_array($lower, self::$sql_ddl, true)) $ddlDetected = true;
                if ($isLogic && $inSqlContext) $logicChainCount++;
                $currentKeyword = $lower;
            }

            if ($tok['type'] === 'COMMENT') {
                $commentDetected = true;
                if ($inSqlContext) $inSqlContext = true;
            }

            switch ($state) {
                case 'IDLE':
                    if ($isKw) $state = 'KEYWORD';
                    break;
                case 'KEYWORD':
                    if ($isLogic) $state = 'EXPECT_CLAUSE';
                    elseif ($tok['type'] === 'OP') $state = 'EXPECT_CLAUSE';
                    elseif ($tok['type'] !== 'WS' && $tok['type'] !== 'IDENT') $state = 'EXPECT_CLAUSE';
                    break;
                case 'EXPECT_CLAUSE':
                    if ($isKw && !$isLogic) $state = 'KEYWORD';
                    break;
            }
        }

        if ($hasSelect && $hasFrom) { $score += 25; $structures[] = ['type' => 'sql_select_from', 'desc' => 'SELECT...FROM查询结构', 'weight' => 25]; }
        if ($hasUnion) { $score += 20; $structures[] = ['type' => 'sql_union', 'desc' => 'UNION联合查询结构', 'weight' => 20]; }
        if ($dmlDetected) { $score += 18; $structures[] = ['type' => 'sql_dml', 'desc' => 'SQL DML结构', 'weight' => 18]; }
        if ($ddlDetected) { $score += 20; $structures[] = ['type' => 'sql_ddl', 'desc' => 'SQL DDL结构', 'weight' => 20]; }
        if ($hasWhere) { $score += 10; $structures[] = ['type' => 'sql_where', 'desc' => 'WHERE条件结构', 'weight' => 10]; }
        if ($logicChainCount >= 1) {
            $w = min(15, $logicChainCount * 8);
            $score += $w;
            $structures[] = ['type' => 'sql_logic_chain', 'desc' => 'SQL逻辑链结构', 'count' => $logicChainCount, 'weight' => $w];
        }
        if ($commentDetected) { $score += 8; $structures[] = ['type' => 'sql_comment', 'desc' => 'SQL注释结构', 'weight' => 8]; }

        return ['score' => min(40, $score), 'structures' => $structures];
    }

    /**
     * SQL tokenizer - 手动字符级扫描，不用正则
     * @param string $text
     * @return array<int, array{type:string, value:string}>
     */
    private static function sqlTokenize(string $text): array {
        $tokens = [];
        $len = strlen($text);
        $i = 0;
        $current = '';

        while ($i < $len) {
            $c = $text[$i];
            $o = ord($c);

            if ($o === 0x20 || $o === 0x09 || $o === 0x0A || $o === 0x0D) {
                if ($current !== '') { $tokens[] = ['type' => 'IDENT', 'value' => $current]; $current = ''; }
                $ws = '';
                while ($i < $len && (ord($text[$i]) === 0x20 || ord($text[$i]) === 0x09 || ord($text[$i]) === 0x0A || ord($text[$i]) === 0x0D)) {
                    $ws .= $text[$i]; $i++;
                }
                $tokens[] = ['type' => 'WS', 'value' => $ws];
                continue;
            }

            if (($o >= 0x41 && $o <= 0x5A) || ($o >= 0x61 && $o <= 0x7A) || $o === 0x5F || ($o >= 0x30 && $o <= 0x39) || $o === 0x2E || $o === 0x40 || $o === 0x23) {
                $current .= $c; $i++; continue;
            }

            if ($o === 0x27 || $o === 0x22) {
                if ($current !== '') { $tokens[] = ['type' => 'IDENT', 'value' => $current]; $current = ''; }
                $quote = $c; $str = $c; $i++;
                while ($i < $len) {
                    $str .= $text[$i];
                    if ($text[$i] === $quote && $i + 1 < $len && $text[$i + 1] === $quote) { $str .= $text[$i + 1]; $i += 2; continue; }
                    if ($text[$i] === $quote) { $i++; break; }
                    if ($text[$i] === '\\' && $i + 1 < $len) { $str .= $text[$i + 1]; $i += 2; continue; }
                    $i++;
                }
                $tokens[] = ['type' => 'STRING', 'value' => $str];
                continue;
            }

            if (($c === '-' && $i + 1 < $len && $text[$i + 1] === '-') || $c === '#') {
                if ($current !== '') { $tokens[] = ['type' => 'IDENT', 'value' => $current]; $current = ''; }
                $comment = '';
                while ($i < $len && ord($text[$i]) !== 0x0A) { $comment .= $text[$i]; $i++; }
                $tokens[] = ['type' => 'COMMENT', 'value' => $comment];
                continue;
            }

            if ($c === '/' && $i + 1 < $len && $text[$i + 1] === '*') {
                if ($current !== '') { $tokens[] = ['type' => 'IDENT', 'value' => $current]; $current = ''; }
                $comment = '/*'; $i += 2;
                while ($i < $len) {
                    if ($text[$i] === '*' && $i + 1 < $len && $text[$i + 1] === '/') { $comment .= '*/'; $i += 2; break; }
                    $comment .= $text[$i]; $i++;
                }
                $tokens[] = ['type' => 'COMMENT', 'value' => $comment];
                continue;
            }

            if ($current !== '') { $tokens[] = ['type' => 'IDENT', 'value' => $current]; $current = ''; }
            if ($i + 1 < $len) {
                $two = $c . $text[$i + 1];
                if ($two === '>=' || $two === '<=' || $two === '!=' || $two === '<>' || $two === '||' || $two === '&&') {
                    $tokens[] = ['type' => 'OP', 'value' => $two]; $i += 2; continue;
                }
            }
            $tokens[] = ['type' => 'OP', 'value' => $c]; $i++;
        }
        if ($current !== '') $tokens[] = ['type' => 'IDENT', 'value' => $current];
        return $tokens;
    }

    /* =============== B. HTML结构状态机 =============== */

    /**
     * HTML结构状态机分析
     * @param string $text
     * @return array{score:int, structures:array}
     */
    private static function analyzeHtmlStructure(string $text): array {
        $structures = [];
        $score = 0;
        $state = 'TEXT';
        $len = strlen($text);
        $i = 0;
        $tagCount = $eventCount = $jsProtocolCount = $nestingDepth = $maxDepth = 0;
        $scriptTag = $svgTag = $iframeTag = $imgEvent = false;
        $tagName = $attrName = $attrValue = $quoteChar = '';
        $isClosing = false;

        while ($i < $len) {
            $c = $text[$i];
            switch ($state) {
                case 'TEXT':
                    if ($c === '<') { $state = 'TAG_OPEN'; $tagName = ''; $attrName = ''; $isClosing = false; }
                    $i++; break;
                case 'TAG_OPEN':
                    if ($c === '/') { $isClosing = true; $i++; break; }
                    if ($c === '!' || $c === '?') { $state = 'TEXT'; $i++; break; }
                    if (self::isAlpha($c)) { $state = 'TAG_NAME'; $tagName = strtolower($c); $i++; break; }
                    $state = 'TEXT'; $i++; break;
                case 'TAG_NAME':
                    if (self::isAlpha($c) || self::isDigit($c) || $c === '-') { $tagName .= strtolower($c); $i++; break; }
                    if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") { $state = 'ATTR_NAME'; $attrName = ''; $i++; break; }
                    if ($c === '/') { $state = 'TAG_CLOSE'; $i++; break; }
                    if ($c === '>') { $state = 'TAG_CLOSE'; break; }
                    $state = 'TEXT'; $i++; break;
                case 'ATTR_NAME':
                    if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                        if ($attrName !== '' && self::startsWith($attrName, 'on')) { $eventCount++; if ($tagName === 'img') $imgEvent = true; }
                        $attrName = ''; $i++; break;
                    }
                    if ($c === '=') {
                        if (self::startsWith($attrName, 'on')) { $eventCount++; if ($tagName === 'img') $imgEvent = true; }
                        $state = 'ATTR_VALUE'; $attrValue = ''; $quoteChar = ''; $i++; break;
                    }
                    if ($c === '>') {
                        if ($attrName !== '' && self::startsWith($attrName, 'on')) { $eventCount++; if ($tagName === 'img') $imgEvent = true; }
                        $state = 'TAG_CLOSE'; break;
                    }
                    if ($c === '/') {
                        if ($attrName !== '' && self::startsWith($attrName, 'on')) $eventCount++;
                        $state = 'TAG_CLOSE'; $i++; break;
                    }
                    $attrName .= strtolower($c); $i++; break;
                case 'ATTR_VALUE':
                    if ($quoteChar === '') {
                        if ($c === '"' || $c === "'") { $quoteChar = $c; $i++; break; }
                        if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                            if (self::startsWith(strtolower($attrValue), 'javascript:')) $jsProtocolCount++;
                            $state = 'ATTR_NAME'; $attrName = ''; $attrValue = ''; $i++; break;
                        }
                        if ($c === '>') {
                            if (self::startsWith(strtolower($attrValue), 'javascript:')) $jsProtocolCount++;
                            $state = 'TAG_CLOSE'; break;
                        }
                        $attrValue .= $c; $i++; break;
                    }
                    if ($c === $quoteChar) {
                        if (self::startsWith(strtolower($attrValue), 'javascript:')) $jsProtocolCount++;
                        $state = 'ATTR_NAME'; $attrName = ''; $attrValue = ''; $quoteChar = ''; $i++; break;
                    }
                    if ($c === '\\' && $i + 1 < $len) { $attrValue .= $c . $text[$i + 1]; $i += 2; break; }
                    $attrValue .= $c; $i++; break;
                case 'TAG_CLOSE':
                    if ($tagName !== '') {
                        $tagCount++;
                        if (!$isClosing) { $nestingDepth++; if ($nestingDepth > $maxDepth) $maxDepth = $nestingDepth; }
                        elseif ($nestingDepth > 0) $nestingDepth--;
                        if ($tagName === 'script') $scriptTag = true;
                        if ($tagName === 'svg') $svgTag = true;
                        if ($tagName === 'iframe') $iframeTag = true;
                    }
                    $state = 'TEXT'; if ($c !== '>') $i++; break;
            }
        }

        if ($tagCount > 0) { $w = min(15, $tagCount * 5); $score += $w; $structures[] = ['type' => 'html_tag', 'desc' => 'HTML标签结构', 'count' => $tagCount, 'weight' => $w]; }
        if ($eventCount > 0) { $w = min(25, $eventCount * 12); $score += $w; $structures[] = ['type' => 'html_event_handler', 'desc' => 'HTML事件处理器结构', 'count' => $eventCount, 'weight' => $w]; }
        if ($jsProtocolCount > 0) { $score += 22; $structures[] = ['type' => 'js_pseudo_protocol', 'desc' => 'JavaScript伪协议结构', 'count' => $jsProtocolCount, 'weight' => 22]; }
        if ($scriptTag) { $score += 20; $structures[] = ['type' => 'js_script_block', 'desc' => 'script脚本块结构', 'weight' => 20]; }
        if ($svgTag) { $score += 15; $structures[] = ['type' => 'svg_payload', 'desc' => 'SVG载荷结构', 'weight' => 15]; }
        if ($iframeTag) { $score += 15; $structures[] = ['type' => 'iframe_payload', 'desc' => 'iframe载荷结构', 'weight' => 15]; }
        if ($imgEvent) { $score += 18; $structures[] = ['type' => 'img_event_xss', 'desc' => 'img事件XSS结构', 'weight' => 18]; }
        if ($maxDepth >= 3) { $score += 8; $structures[] = ['type' => 'html_nesting_deep', 'desc' => 'HTML深层嵌套', 'depth' => $maxDepth, 'weight' => 8]; }

        return ['score' => min(40, $score), 'structures' => $structures];
    }

    private static function isAlpha(string $c): bool {
        $o = ord($c);
        return ($o >= 0x41 && $o <= 0x5A) || ($o >= 0x61 && $o <= 0x7A);
    }

    private static function isDigit(string $c): bool {
        return ord($c) >= 0x30 && ord($c) <= 0x39;
    }

    private static function startsWith(string $haystack, string $needle): bool {
        return strpos($haystack, $needle) === 0;
    }

    /* =============== C. 命令结构状态机 =============== */

    /**
     * 命令结构状态机分析
     * @param string $text
     * @return array{score:int, structures:array}
     */
    private static function analyzeCommandStructure(string $text): array {
        $structures = [];
        $score = 0;
        $state = 'CMD_START';
        $len = strlen($text);
        $i = 0;
        $semicolonChain = $pipeCount = $logicalChain = $backtickCount = $dollarParenCount = $cmdCount = 0;
        $inBacktick = $inDollarParen = $inSingleQuote = $inDoubleQuote = false;
        $parenDepth = 0;

        while ($i < $len) {
            $c = $text[$i];
            if ($state !== 'SEPARATOR') {
                if ($c === "'" && !$inDoubleQuote) { $inSingleQuote = !$inSingleQuote; $i++; continue; }
                if ($c === '"' && !$inSingleQuote) { $inDoubleQuote = !$inDoubleQuote; $i++; continue; }
                if ($c === '\\' && $i + 1 < $len) { $i += 2; continue; }
            }

            switch ($state) {
                case 'CMD_START':
                    if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") { $i++; break; }
                    if (self::isAlpha($c) || $c === '.' || $c === '/' || $c === '\\') { $state = 'CMD_BODY'; $cmdCount++; $i++; break; }
                    if ($c === '`' && !$inSingleQuote && !$inDoubleQuote) { $backtickCount++; $inBacktick = !$inBacktick; $i++; break; }
                    if ($c === '$' && $i + 1 < $len && $text[$i + 1] === '(' && !$inSingleQuote && !$inDoubleQuote) {
                        $dollarParenCount++; $inDollarParen = true; $parenDepth = 1; $i += 2; break;
                    }
                    $i++; break;
                case 'CMD_BODY':
                    if ($c === ';' && !$inSingleQuote && !$inDoubleQuote && !$inBacktick && !$inDollarParen) {
                        $semicolonChain++; $state = 'SEPARATOR'; $i++; break;
                    }
                    if ($c === '|' && $i + 1 < $len && $text[$i + 1] === '|' && !$inSingleQuote && !$inDoubleQuote && !$inBacktick && !$inDollarParen) {
                        $logicalChain++; $state = 'SEPARATOR'; $i += 2; break;
                    }
                    if ($c === '&' && $i + 1 < $len && $text[$i + 1] === '&' && !$inSingleQuote && !$inDoubleQuote && !$inBacktick && !$inDollarParen) {
                        $logicalChain++; $state = 'SEPARATOR'; $i += 2; break;
                    }
                    if ($c === '|' && !$inSingleQuote && !$inDoubleQuote && !$inBacktick && !$inDollarParen) {
                        $pipeCount++; $state = 'SEPARATOR'; $i++; break;
                    }
                    if ($c === '`' && !$inSingleQuote && !$inDoubleQuote) { $backtickCount++; $inBacktick = !$inBacktick; $i++; break; }
                    if ($c === '$' && $i + 1 < $len && $text[$i + 1] === '(' && !$inSingleQuote && !$inDoubleQuote) {
                        $dollarParenCount++; $inDollarParen = true; $parenDepth = 1; $i += 2; break;
                    }
                    if ($inDollarParen && $c === '(') $parenDepth++;
                    elseif ($inDollarParen && $c === ')') { $parenDepth--; if ($parenDepth <= 0) $inDollarParen = false; }
                    $i++; break;
                case 'SEPARATOR':
                    if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") { $i++; break; }
                    if (self::isAlpha($c) || $c === '.' || $c === '/' || $c === '\\') { $state = 'CMD_BODY'; $cmdCount++; $i++; break; }
                    $state = 'CMD_BODY'; break;
            }
        }

        if ($semicolonChain > 0) { $w = min(15, $semicolonChain * 8); $score += $w; $structures[] = ['type' => 'cmd_chain_semicolon', 'desc' => '分号命令链结构', 'count' => $semicolonChain, 'weight' => $w]; }
        if ($pipeCount > 0) { $w = min(18, $pipeCount * 10); $score += $w; $structures[] = ['type' => 'cmd_pipe', 'desc' => '管道命令结构', 'count' => $pipeCount, 'weight' => $w]; }
        if ($logicalChain > 0) { $w = min(18, $logicalChain * 10); $score += $w; $structures[] = ['type' => 'cmd_chain_logical', 'desc' => '逻辑命令链结构', 'count' => $logicalChain, 'weight' => $w]; }
        if ($backtickCount >= 2) {
            $btPairs = (int) floor($backtickCount / 2);
            $w = min(20, $btPairs * 12);
            $score += $w;
            $structures[] = ['type' => 'cmd_backtick', 'desc' => '反引号命令替换结构', 'count' => $btPairs, 'weight' => $w];
        }
        if ($dollarParenCount > 0) { $w = min(20, $dollarParenCount * 12); $score += $w; $structures[] = ['type' => 'cmd_subshell', 'desc' => '$()命令替换结构', 'count' => $dollarParenCount, 'weight' => $w]; }
        if ($cmdCount >= 2) { $score += 5; $structures[] = ['type' => 'cmd_multi', 'desc' => '多命令结构', 'count' => $cmdCount, 'weight' => 5]; }

        return ['score' => min(40, $score), 'structures' => $structures];
    }

    /* =============== D. 路径结构状态机 =============== */

    /**
     * 路径结构状态机分析
     * @param string $text
     * @return array{score:int, structures:array}
     */
    private static function analyzePathStructure(string $text): array {
        $structures = [];
        $score = 0;
        $len = strlen($text);
        $i = 0;
        $traversalCount = $sensitivePathCount = $wrapperCount = 0;
        $dotCount = 0;
        $state = 'NORMAL';
        $buffer = '';

        while ($i < $len) {
            $c = $text[$i];
            $lower = ($c >= 'A' && $c <= 'Z') ? chr(ord($c) + 32) : $c;

            switch ($state) {
                case 'NORMAL':
                    if ($c === '.') {
                        $dotCount++;
                        if ($dotCount === 2) $state = 'TWO_DOTS';
                        $i++; break;
                    }
                    $dotCount = 0;
                    if ($c === '/') { $state = 'PATH_SLASH'; $buffer = '/'; $i++; break; }
                    if (self::isAlpha($c)) { $state = 'WRAPPER_CHECK'; $buffer = $lower; $i++; break; }
                    $i++; break;
                case 'TWO_DOTS':
                    if ($c === '/' || $c === '\\') { $traversalCount++; $state = 'NORMAL'; $dotCount = 0; $i++; break; }
                    if ($c === '.') { $dotCount = 2; $i++; break; }
                    $state = 'NORMAL'; $dotCount = 0; break;
                case 'PATH_SLASH':
                    $buffer .= $lower;
                    if ($c === '/') {
                        foreach (self::$sensitive_paths as $sp) {
                            if (self::startsWith($buffer, $sp)) { $sensitivePathCount++; break; }
                        }
                        $state = 'NORMAL'; $buffer = ''; $i++; break;
                    }
                    if (strlen($buffer) > 12) { $state = 'NORMAL'; $buffer = ''; break; }
                    $i++; break;
                case 'WRAPPER_CHECK':
                    $buffer .= $lower;
                    if ($c === ':' && $i + 1 < $len && ($text[$i + 1] === '/' || $text[$i + 1] === '\\')) {
                        $buffer .= ':/';
                        foreach (self::$php_wrappers as $w) {
                            if (self::startsWith($buffer, $w)) { $wrapperCount++; break; }
                        }
                        $state = 'NORMAL'; $buffer = ''; $i += 2; break;
                    }
                    if (!self::isAlpha($c) && !self::isDigit($c) && $c !== '_') { $state = 'NORMAL'; $buffer = ''; break; }
                    if (strlen($buffer) > 15) { $state = 'NORMAL'; $buffer = ''; break; }
                    $i++; break;
            }
        }

        if ($traversalCount > 0) { $w = min(25, $traversalCount * 10); $score += $w; $structures[] = ['type' => 'path_traversal', 'desc' => '路径遍历结构', 'count' => $traversalCount, 'weight' => $w]; }
        if ($sensitivePathCount > 0) { $w = min(20, $sensitivePathCount * 12); $score += $w; $structures[] = ['type' => 'unix_sensitive_path', 'desc' => 'Unix敏感路径结构', 'count' => $sensitivePathCount, 'weight' => $w]; }
        if ($wrapperCount > 0) { $w = min(25, $wrapperCount * 15); $score += $w; $structures[] = ['type' => 'php_wrapper', 'desc' => 'PHP流封装结构', 'count' => $wrapperCount, 'weight' => $w]; }

        return ['score' => min(40, $score), 'structures' => $structures];
    }

    /* =============== E. 结构复杂度分析 =============== */

    /**
     * 结构复杂度分析
     * @param string $text
     * @return array{score:int, structures:array}
     */
    private static function analyzeComplexity(string $text): array {
        $structures = [];
        $score = 0;
        $len = strlen($text);
        if ($len < 10) return ['score' => 0, 'structures' => []];

        $parenDepth = $maxParenDepth = $bracketDepth = $maxBracketDepth = $braceDepth = $maxBraceDepth = 0;
        $inSingleQuote = $inDoubleQuote = false;

        for ($i = 0; $i < $len; $i++) {
            $c = $text[$i];
            if ($c === '\\' && $i + 1 < $len) { $i++; continue; }
            if ($c === "'" && !$inDoubleQuote) { $inSingleQuote = !$inSingleQuote; continue; }
            if ($c === '"' && !$inSingleQuote) { $inDoubleQuote = !$inDoubleQuote; continue; }
            if ($inSingleQuote || $inDoubleQuote) continue;
            if ($c === '(') { $parenDepth++; if ($parenDepth > $maxParenDepth) $maxParenDepth = $parenDepth; }
            elseif ($c === ')') { if ($parenDepth > 0) $parenDepth--; }
            elseif ($c === '[') { $bracketDepth++; if ($bracketDepth > $maxBracketDepth) $maxBracketDepth = $bracketDepth; }
            elseif ($c === ']') { if ($bracketDepth > 0) $bracketDepth--; }
            elseif ($c === '{') { $braceDepth++; if ($braceDepth > $maxBraceDepth) $maxBraceDepth = $braceDepth; }
            elseif ($c === '}') { if ($braceDepth > 0) $braceDepth--; }
        }

        $maxDepth = max($maxParenDepth, $maxBracketDepth, $maxBraceDepth);

        $charTypes = ['alpha' => 0, 'digit' => 0, 'special' => 0, 'space' => 0];
        for ($i = 0; $i < $len; $i++) {
            $o = ord($text[$i]);
            if (($o >= 0x41 && $o <= 0x5A) || ($o >= 0x61 && $o <= 0x7A)) $charTypes['alpha']++;
            elseif ($o >= 0x30 && $o <= 0x39) $charTypes['digit']++;
            elseif ($o === 0x20 || $o === 0x09 || $o === 0x0A || $o === 0x0D) $charTypes['space']++;
            else $charTypes['special']++;
        }

        $entropy = 0.0;
        foreach ($charTypes as $count) {
            if ($count > 0) { $p = $count / $len; $entropy -= $p * log($p, 2); }
        }

        $specialDensity = $len > 0 ? $charTypes['special'] / $len : 0;

        if ($maxDepth >= 5) { $score += 15; $structures[] = ['type' => 'deep_nesting', 'desc' => '深层括号嵌套', 'depth' => $maxDepth, 'weight' => 15]; }
        elseif ($maxDepth >= 3) { $score += 8; $structures[] = ['type' => 'moderate_nesting', 'desc' => '中度括号嵌套', 'depth' => $maxDepth, 'weight' => 8]; }
        if ($entropy > 1.5 && $len > 20) { $score += 10; $structures[] = ['type' => 'high_structural_entropy', 'desc' => '高结构熵', 'entropy' => round($entropy, 2), 'weight' => 10]; }
        if ($specialDensity > 0.25) { $score += 10; $structures[] = ['type' => 'high_special_density', 'desc' => '高特殊字符密度', 'density' => round($specialDensity, 2), 'weight' => 10]; }
        elseif ($specialDensity > 0.15) $score += 5;

        return ['score' => min(25, $score), 'structures' => $structures];
    }

    /* =============== F. 结构上下文分析 =============== */

    /**
     * 结构上下文分析（交叉加成）
     * @param array $hits 各状态机得分
     * @param array $structures 已识别结构
     * @return array{score:int, structures:array}
     */
    private static function analyzeContext(array $hits, array $structures): array {
        $totalScore = array_sum($hits);
        $newStructures = [];

        $activeDims = 0;
        foreach ($hits as $s) { if ($s > 0) $activeDims++; }

        $crossBonus = 0;
        if ($activeDims >= 4) {
            $crossBonus = 20;
            $newStructures[] = ['type' => 'cross_bonus_4d', 'desc' => '4维以上结构交叉', 'dims' => $activeDims, 'weight' => 20];
        } elseif ($activeDims === 3) {
            $crossBonus = 10;
            $newStructures[] = ['type' => 'cross_bonus_3d', 'desc' => '3维结构交叉', 'dims' => $activeDims, 'weight' => 10];
        } elseif ($activeDims === 2) {
            $crossBonus = 5;
            $newStructures[] = ['type' => 'cross_bonus_2d', 'desc' => '2维结构交叉', 'dims' => $activeDims, 'weight' => 5];
        }

        if (isset($hits['sql']) && $hits['sql'] > 10 && isset($hits['complexity']) && $hits['complexity'] > 5) {
            $totalScore += 3;
            $newStructures[] = ['type' => 'pattern_sql_complex', 'desc' => 'SQL+复杂度组合模式', 'weight' => 3];
        }

        if (isset($hits['html']) && $hits['html'] > 15) {
            $hasEvent = $hasJsProto = false;
            foreach ($structures as $s) {
                if ($s['type'] === 'html_event_handler') $hasEvent = true;
                if ($s['type'] === 'js_pseudo_protocol') $hasJsProto = true;
            }
            if ($hasEvent && $hasJsProto) {
                $totalScore += 5;
                $newStructures[] = ['type' => 'pattern_xss_combo', 'desc' => 'XSS组合模式(事件+JS协议)', 'weight' => 5];
            }
        }

        if (isset($hits['cmd']) && $hits['cmd'] > 10 && isset($hits['path']) && $hits['path'] > 10) {
            $totalScore += 5;
            $newStructures[] = ['type' => 'pattern_cmd_path', 'desc' => '命令+路径组合模式', 'weight' => 5];
        }

        $totalScore += $crossBonus;
        return ['score' => $totalScore, 'structures' => $newStructures];
    }
}
