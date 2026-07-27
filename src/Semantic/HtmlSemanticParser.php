<?php
defined('ABSPATH') || exit;

class HtmlSemanticParser {

    const TOKEN_DOCTYPE      = 'DOCTYPE';
    const TOKEN_START_TAG    = 'START_TAG';
    const TOKEN_END_TAG      = 'END_TAG';
    const TOKEN_SELF_CLOSING = 'SELF_CLOSING';
    const TOKEN_TEXT         = 'TEXT';
    const TOKEN_COMMENT      = 'COMMENT';
    const TOKEN_CDATA        = 'CDATA';
    const TOKEN_PI           = 'PI';
    const TOKEN_ATTR_NAME    = 'ATTR_NAME';
    const TOKEN_ATTR_VALUE   = 'ATTR_VALUE';
    const TOKEN_EQUAL        = 'EQUAL';
    const TOKEN_SLASH        = 'SLASH';
    const TOKEN_EOF          = 'EOF';

    private static $dangerousTags = [
        'script'   => ['level' => 5, 'desc' => '脚本注入'],
        'iframe'   => ['level' => 5, 'desc' => '框架注入'],
        'svg'      => ['level' => 4, 'desc' => 'SVG XSS'],
        'img'      => ['level' => 3, 'desc' => '图片事件注入'],
        'object'   => ['level' => 5, 'desc' => '插件注入'],
        'embed'    => ['level' => 5, 'desc' => '插件注入'],
        'applet'   => ['level' => 5, 'desc' => '插件注入'],
        'form'     => ['level' => 3, 'desc' => '表单注入'],
        'meta'     => ['level' => 3, 'desc' => '重定向/字符集注入'],
        'link'     => ['level' => 3, 'desc' => '资源劫持'],
        'base'     => ['level' => 4, 'desc' => '基础路径劫持'],
        'frameset' => ['level' => 5, 'desc' => '框架注入'],
        'frame'    => ['level' => 5, 'desc' => '框架注入'],
    ];

    private static $eventHandlerAttrs = [
        'onload', 'onunload', 'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
        'onmouseover', 'onmousemove', 'onmouseout', 'onmouseenter', 'onmouseleave',
        'onkeydown', 'onkeypress', 'onkeyup', 'onfocus', 'onblur', 'onchange',
        'onselect', 'onsubmit', 'onreset', 'onabort', 'onerror', 'onresize',
        'onscroll', 'oncontextmenu', 'onwheel', 'onauxclick', 'onpointerdown',
        'onpointerup', 'onpointermove', 'onpointerover', 'onpointerout',
        'onpointerenter', 'onpointerleave', 'onpointercancel', 'ongotpointercapture',
        'onlostpointercapture', 'ontouchstart', 'ontouchend', 'ontouchmove',
        'ontouchcancel', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
        'ondragover', 'ondragstart', 'ondrop', 'onanimationend', 'onanimationiteration',
        'onanimationstart', 'ontransitionend', 'oncopy', 'oncut', 'onpaste',
        'onbeforecopy', 'onbeforecut', 'onbeforepaste', 'oncanplay', 'oncanplaythrough',
        'ondurationchange', 'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata',
        'onloadstart', 'onpause', 'onplay', 'onplaying', 'onprogress', 'onratechange',
        'onseeked', 'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
        'onvolumechange', 'onwaiting', 'oninput', 'oninvalid', 'onsearch',
        'onshow', 'ontoggle', 'onslotchange', 'onpopstate', 'onhashchange',
        'onpagehide', 'onpageshow', 'onstorage', 'onmessage', 'onlanguagechange',
        'ononline', 'onoffline', 'onbeforeunload', 'oncancel', 'onclose',
        'onfullscreenchange', 'onfullscreenerror', 'onvisibilitychange',
        'ondevicemotion', 'ondeviceorientation', 'onreadystatechange',
    ];

    private static $protocolAttrs = ['href', 'src', 'action', 'formaction', 'xlink:href', 'data', 'poster'];
    private static $dangerousProtocols = ['javascript:', 'vbscript:', 'data:text/html'];

    public static function analyze(string $html): array {
        $result = self::defaultResult();
        if ($html === '') return $result;

        try {
            $tokens = self::tokenize($html);
            $result['token_count'] = count($tokens);

            $ast = self::parse($tokens);
            $result['parser_used'] = 'ast';
            $result['ast'] = $ast;
            $result['ast_summary'] = self::summarizeAst($ast);

            $semanticResult = self::analyzeAst($ast);
            $result = array_merge($result, $semanticResult);
        } catch (Exception $e) {
            $result['parser_used'] = 'fallback';
            $result['parse_errors'][] = $e->getMessage();
            $result = array_merge($result, self::regexFallback($html));
        }

        $result['score'] = self::calculateScore($result);
        $result['risk_level'] = self::calculateRiskLevel($result['score']);
        $result['detected'] = $result['score'] > 0;

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'detected' => false, 'score' => 0, 'risk_level' => 'low',
            'parser_used' => 'ast', 'token_count' => 0,
            'tags' => [], 'event_handlers' => [], 'dangerous_protocols' => [],
            'has_script' => false, 'has_event_handler' => false,
            'has_javascript_protocol' => false, 'has_svg_payload' => false,
            'has_iframe' => false, 'max_nesting_depth' => 0,
            'js_dangerous_patterns' => [], 'total_tag_count' => 0,
            'indicators' => [], 'parse_errors' => [],
            'ast' => null, 'ast_summary' => [],
        ];
    }

    // ==================== Tokenizer ====================

    private static function tokenize(string $html): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($html);

        while ($pos < $len) {
            if ($pos + 8 < $len && substr($html, $pos, 9) === '<?DOCTYPE') {
                $end = strpos($html, '>', $pos);
                $tokens[] = ['type' => self::TOKEN_DOCTYPE, 'value' => substr($html, $pos, $end - $pos + 1), 'pos' => $pos];
                $pos = $end + 1;
                continue;
            }

            if ($pos + 1 < $len && $html[$pos] === '<' && $html[$pos + 1] === '!') {
                if ($pos + 3 < $len && substr($html, $pos, 4) === '<!--') {
                    $end = strpos($html, '-->', $pos);
                    if ($end !== false) {
                        $tokens[] = ['type' => self::TOKEN_COMMENT, 'value' => substr($html, $pos, $end - $pos + 3), 'pos' => $pos];
                        $pos = $end + 3;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_COMMENT, 'value' => substr($html, $pos), 'pos' => $pos];
                        $pos = $len;
                    }
                    continue;
                }

                if ($pos + 8 < $len && substr($html, $pos, 9) === '<![CDATA[') {
                    $end = strpos($html, ']]>', $pos);
                    if ($end !== false) {
                        $tokens[] = ['type' => self::TOKEN_CDATA, 'value' => substr($html, $pos, $end - $pos + 3), 'pos' => $pos];
                        $pos = $end + 3;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_CDATA, 'value' => substr($html, $pos), 'pos' => $pos];
                        $pos = $len;
                    }
                    continue;
                }

                $end = strpos($html, '>', $pos);
                $tokens[] = ['type' => self::TOKEN_PI, 'value' => substr($html, $pos, $end - $pos + 1), 'pos' => $pos];
                $pos = $end + 1;
                continue;
            }

            if ($pos + 1 < $len && $html[$pos] === '<' && $html[$pos + 1] === '/') {
                $end = strpos($html, '>', $pos);
                $tagName = trim(substr($html, $pos + 2, $end - $pos - 2));
                $tokens[] = ['type' => self::TOKEN_END_TAG, 'value' => $tagName, 'pos' => $pos];
                $pos = $end + 1;
                continue;
            }

            if ($html[$pos] === '<') {
                $tagEnd = strpos($html, '>', $pos);
                if ($tagEnd === false) break;

                $tagContent = substr($html, $pos + 1, $tagEnd - $pos - 1);
                $isSelfClosing = substr($tagContent, -2) === '/>';
                $tagContent = rtrim($tagContent, '/');
                $parts = preg_split('/\s+/', trim($tagContent), 2);
                $tagName = strtolower($parts[0]);
                $attrsRaw = isset($parts[1]) ? $parts[1] : '';

                $tokenType = $isSelfClosing ? self::TOKEN_SELF_CLOSING : self::TOKEN_START_TAG;
                $tokens[] = ['type' => $tokenType, 'value' => $tagName, 'pos' => $pos];

                foreach (self::parseAttrs($attrsRaw) as $attr) {
                    $tokens[] = ['type' => self::TOKEN_ATTR_NAME, 'value' => $attr['name'], 'pos' => $pos];
                    if ($attr['value'] !== null) {
                        $tokens[] = ['type' => self::TOKEN_EQUAL, 'value' => '=', 'pos' => $pos];
                        $tokens[] = ['type' => self::TOKEN_ATTR_VALUE, 'value' => $attr['value'], 'pos' => $pos];
                    }
                }

                $pos = $tagEnd + 1;
                continue;
            }

            $textEnd = strpos($html, '<', $pos);
            if ($textEnd === false) $textEnd = $len;
            $text = substr($html, $pos, $textEnd - $pos);
            if (trim($text) !== '') {
                $tokens[] = ['type' => self::TOKEN_TEXT, 'value' => $text, 'pos' => $pos];
            }
            $pos = $textEnd;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    private static function parseAttrs(string $raw): array {
        $attrs = [];
        $pos = 0;
        $len = strlen($raw);

        while ($pos < $len) {
            while ($pos < $len && ctype_space($raw[$pos])) $pos++;
            if ($pos >= $len) break;

            $nameStart = $pos;
            while ($pos < $len && !ctype_space($raw[$pos]) && $raw[$pos] !== '=' && $raw[$pos] !== '>') $pos++;
            $name = strtolower(substr($raw, $nameStart, $pos - $nameStart));
            if ($name === '') continue;

            while ($pos < $len && ctype_space($raw[$pos])) $pos++;
            $value = null;

            if ($pos < $len && $raw[$pos] === '=') {
                $pos++;
                while ($pos < $len && ctype_space($raw[$pos])) $pos++;

                if ($pos < $len && ($raw[$pos] === '"' || $raw[$pos] === "'")) {
                    $quote = $raw[$pos];
                    $pos++;
                    $valueStart = $pos;
                    while ($pos < $len && $raw[$pos] !== $quote) $pos++;
                    $value = substr($raw, $valueStart, $pos - $valueStart);
                    $pos++;
                } else {
                    $valueStart = $pos;
                    while ($pos < $len && !ctype_space($raw[$pos]) && $raw[$pos] !== '>' && $raw[$pos] !== '"' && $raw[$pos] !== "'") $pos++;
                    $value = substr($raw, $valueStart, $pos - $valueStart);
                }
            }

            $attrs[] = ['name' => $name, 'value' => $value];
        }

        return $attrs;
    }

    // ==================== Parser ====================

    private static function parse(array $tokens): array {
        $state = ['tokens' => $tokens, 'pos' => 0];
        return self::parseDocument($state);
    }

    private static function parseDocument(array &$state): array {
        $children = [];
        $doctype = null;

        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_DOCTYPE) {
                $doctype = $token['value'];
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_COMMENT) {
                $children[] = ['type' => 'comment', 'value' => $token['value'], 'pos' => $token['pos']];
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_CDATA) {
                $children[] = ['type' => 'cdata', 'value' => $token['value'], 'pos' => $token['pos']];
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_TEXT) {
                $children[] = ['type' => 'text', 'value' => $token['value'], 'pos' => $token['pos']];
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_START_TAG) {
                $children[] = self::parseElement($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_SELF_CLOSING) {
                $children[] = self::parseSelfClosingElement($state);
                continue;
            }
            self::next($state);
        }

        return ['type' => 'document', 'doctype' => $doctype, 'children' => $children];
    }

    private static function parseElement(array &$state): array {
        $startToken = self::current($state);
        $tagName = $startToken['value'];
        $attrs = [];

        self::next($state);
        while (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_ATTR_NAME) {
            $attrName = self::current($state)['value'];
            self::next($state);

            $attrValue = null;
            if (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_EQUAL) {
                self::next($state);
                if (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_ATTR_VALUE) {
                    $attrValue = self::current($state)['value'];
                    self::next($state);
                }
            }

            $attrs[$attrName] = $attrValue;
        }

        $children = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_END_TAG && $token['value'] === $tagName) {
                self::next($state);
                break;
            }
            if ($token['type'] === self::TOKEN_START_TAG) {
                $children[] = self::parseElement($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_SELF_CLOSING) {
                $children[] = self::parseSelfClosingElement($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_TEXT) {
                $children[] = ['type' => 'text', 'value' => $token['value'], 'pos' => $token['pos']];
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_COMMENT) {
                $children[] = ['type' => 'comment', 'value' => $token['value'], 'pos' => $token['pos']];
                self::next($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_CDATA) {
                $children[] = ['type' => 'cdata', 'value' => $token['value'], 'pos' => $token['pos']];
                self::next($state);
                continue;
            }
            self::next($state);
        }

        return [
            'type' => 'element', 'tag' => $tagName, 'attrs' => $attrs,
            'children' => $children, 'pos' => $startToken['pos'],
        ];
    }

    private static function parseSelfClosingElement(array &$state): array {
        $token = self::current($state);
        $tagName = $token['value'];
        $attrs = [];

        self::next($state);
        while (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_ATTR_NAME) {
            $attrName = self::current($state)['value'];
            self::next($state);

            $attrValue = null;
            if (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_EQUAL) {
                self::next($state);
                if (!self::isEof($state) && self::current($state)['type'] === self::TOKEN_ATTR_VALUE) {
                    $attrValue = self::current($state)['value'];
                    self::next($state);
                }
            }

            $attrs[$attrName] = $attrValue;
        }

        return [
            'type' => 'element', 'tag' => $tagName, 'attrs' => $attrs,
            'children' => [], 'self_closing' => true, 'pos' => $token['pos'],
        ];
    }

    // ==================== Parser Helpers ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => -1];
    }

    private static function next(array &$state): void {
        if ($state['pos'] < count($state['tokens']) - 1) $state['pos']++;
    }

    private static function isEof(array &$state): bool {
        return self::current($state)['type'] === self::TOKEN_EOF;
    }

    // ==================== AST Semantic Analysis ====================

    private static function analyzeAst(array $ast): array {
        $result = [
            'tags' => [], 'event_handlers' => [], 'dangerous_protocols' => [],
            'has_script' => false, 'has_event_handler' => false,
            'has_javascript_protocol' => false, 'has_svg_payload' => false,
            'has_iframe' => false, 'max_nesting_depth' => 0,
            'js_dangerous_patterns' => [], 'total_tag_count' => 0,
            'indicators' => [],
        ];

        self::walkAst($ast, $result, 0);
        return $result;
    }

    private static function walkAst(array $node, array &$result, int $depth): void {
        if ($depth > $result['max_nesting_depth']) {
            $result['max_nesting_depth'] = $depth;
        }

        if ($node['type'] === 'element') {
            $tagName = $node['tag'];
            $result['total_tag_count']++;

            if (isset(self::$dangerousTags[$tagName])) {
                $result['tags'][] = [
                    'tag' => $tagName,
                    'level' => self::$dangerousTags[$tagName]['level'],
                    'desc' => self::$dangerousTags[$tagName]['desc'],
                    'attrs' => array_keys($node['attrs']),
                ];

                if ($tagName === 'script') $result['has_script'] = true;
                if ($tagName === 'svg') $result['has_svg_payload'] = true;
                if ($tagName === 'iframe') $result['has_iframe'] = true;
            }

            foreach ($node['attrs'] as $attrName => $attrValue) {
                if (strpos($attrName, 'on') === 0) {
                    $result['has_event_handler'] = true;
                    $result['event_handlers'][] = [
                        'tag' => $tagName, 'event' => $attrName, 'value' => $attrValue,
                    ];

                    if ($attrValue !== null) {
                        $patterns = self::detectJsPatterns($attrValue);
                        foreach ($patterns as $p) {
                            if (!in_array($p, $result['js_dangerous_patterns'])) {
                                $result['js_dangerous_patterns'][] = $p;
                            }
                        }
                    }
                }

                if (in_array($attrName, self::$protocolAttrs) && $attrValue !== null) {
                    $decoded = html_entity_decode($attrValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    foreach (self::$dangerousProtocols as $proto) {
                        if (strpos(strtolower($decoded), strtolower($proto)) === 0) {
                            $result['has_javascript_protocol'] = true;
                            $result['dangerous_protocols'][] = ['attr' => $attrName, 'value' => $attrValue];
                            break;
                        }
                    }
                }
            }

            if ($tagName === 'script') {
                foreach ($node['children'] as $child) {
                    if ($child['type'] === 'text') {
                        $patterns = self::detectJsPatterns($child['value']);
                        foreach ($patterns as $p) {
                            if (!in_array($p, $result['js_dangerous_patterns'])) {
                                $result['js_dangerous_patterns'][] = $p;
                            }
                        }
                    }
                }
            }

            foreach ($node['children'] as $child) {
                self::walkAst($child, $result, $depth + 1);
            }
        }

        if ($node['type'] === 'document') {
            foreach ($node['children'] as $child) {
                self::walkAst($child, $result, $depth + 1);
            }
        }
    }

    private static function detectJsPatterns(string $code): array {
        $patterns = [];
        $jsPatterns = [
            'eval\s*\('                        => 'eval执行',
            'setTimeout\s*\(\s*[\'"]'          => 'setTimeout字符串执行',
            'setInterval\s*\(\s*[\'"]'         => 'setInterval字符串执行',
            'document\.cookie'                 => 'cookie操作',
            'document\.location'               => 'location跳转',
            'XMLHttpRequest'                   => 'XHR请求',
            '\.fetch\s*\('                     => 'fetch请求',
            'window\.open'                     => '窗口打开',
            'window\.location'                 => '窗口跳转',
            'String\.fromCharCode'             => 'CharCode编码绕过',
            'atob\s*\('                        => 'Base64解码',
            'btoa\s*\('                        => 'Base64编码',
        ];

        foreach ($jsPatterns as $pattern => $desc) {
            if (@preg_match('/' . $pattern . '/i', $code)) {
                $patterns[] = $desc;
            }
        }

        return $patterns;
    }

    // ==================== AST Summary ====================

    private static function summarizeAst(array $ast): array {
        $summary = ['type' => $ast['type'], 'total_elements' => 0, 'tag_distribution' => []];
        self::countNodes($ast, $summary);
        return $summary;
    }

    private static function countNodes(array $node, array &$summary): void {
        if ($node['type'] === 'element') {
            $summary['total_elements']++;
            $tag = $node['tag'];
            if (!isset($summary['tag_distribution'][$tag])) {
                $summary['tag_distribution'][$tag] = 0;
            }
            $summary['tag_distribution'][$tag]++;

            foreach ($node['children'] as $child) {
                self::countNodes($child, $summary);
            }
        }

        if ($node['type'] === 'document') {
            foreach ($node['children'] as $child) {
                self::countNodes($child, $summary);
            }
        }
    }

    // ==================== Regex Fallback ====================

    private static function regexFallback(string $html): array {
        $result = [
            'tags' => [], 'event_handlers' => [], 'dangerous_protocols' => [],
            'has_script' => false, 'has_event_handler' => false,
            'has_javascript_protocol' => false, 'has_svg_payload' => false,
            'has_iframe' => false, 'max_nesting_depth' => 0,
            'js_dangerous_patterns' => [], 'total_tag_count' => 0,
            'indicators' => [],
        ];

        if (preg_match_all('/<\s*(script|iframe|svg|img|object|embed|form|meta|link|base)[^>]*>/i', $html, $matches)) {
            $result['total_tag_count'] += count($matches[0]);
            foreach ($matches[1] as $tag) {
                $tagLower = strtolower($tag);
                if (isset(self::$dangerousTags[$tagLower])) {
                    $result['tags'][] = [
                        'tag' => $tagLower,
                        'level' => self::$dangerousTags[$tagLower]['level'],
                        'desc' => self::$dangerousTags[$tagLower]['desc'],
                    ];
                    if ($tagLower === 'script') $result['has_script'] = true;
                    if ($tagLower === 'svg') $result['has_svg_payload'] = true;
                    if ($tagLower === 'iframe') $result['has_iframe'] = true;
                }
            }
        }

        if (preg_match_all('/\bon\w+\s*=\s*["\']([^"\']+)["\']/i', $html, $matches)) {
            $result['has_event_handler'] = true;
            foreach ($matches[0] as $i => $full) {
                preg_match('/(\bon\w+)/i', $full, $eventMatch);
                $result['event_handlers'][] = [
                    'tag' => 'unknown', 'event' => strtolower($eventMatch[1] ?? ''),
                    'value' => $matches[1][$i],
                ];
            }
        }

        foreach (self::$dangerousProtocols as $proto) {
            if (preg_match('/href\s*=\s*["\']?' . preg_quote($proto, '/') . '/i', $html) ||
                preg_match('/src\s*=\s*["\']?' . preg_quote($proto, '/') . '/i', $html)) {
                $result['has_javascript_protocol'] = true;
                $result['dangerous_protocols'][] = ['proto' => $proto];
            }
        }

        return $result;
    }

    // ==================== Scoring ====================

    private static function calculateScore(array $result): int {
        $score = 0;

        if ($result['has_script']) {
            $score += 35;
            $result['indicators'][] = 'script_tag';
        }

        if ($result['has_javascript_protocol']) {
            $score += 30;
            $result['indicators'][] = 'javascript_protocol';
        }

        if ($result['has_event_handler']) {
            $score += 25;
            $result['indicators'][] = 'event_handler';
        }

        if ($result['has_iframe'] && !empty($result['dangerous_protocols'])) {
            $score += 20;
            $result['indicators'][] = 'iframe_with_dangerous_protocol';
        } elseif ($result['has_iframe']) {
            $score += 10;
            $result['indicators'][] = 'iframe';
        }

        if ($result['has_svg_payload']) {
            $score += 15;
            $result['indicators'][] = 'svg_xss';
        }

        if (!empty($result['js_dangerous_patterns'])) {
            $score += min(25, count($result['js_dangerous_patterns']) * 5);
            $result['indicators'][] = 'dangerous_js_patterns:' . count($result['js_dangerous_patterns']);
        }

        if ($result['max_nesting_depth'] > 10) {
            $score += 10;
            $result['indicators'][] = 'excessive_nesting:' . $result['max_nesting_depth'];
        }

        if ($result['parser_used'] === 'ast') {
            $score += 5;
        }

        return min(100, $score);
    }

    private static function calculateRiskLevel(int $score): string {
        if ($score >= 70) return 'critical';
        if ($score >= 50) return 'high';
        if ($score >= 30) return 'medium';
        if ($score >= 15) return 'low';
        return 'clean';
    }
}