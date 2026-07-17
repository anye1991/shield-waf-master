<?php
/**
 * HTML/JS 语义解析器
 * 职责：使用 DOMDocument 构建真正的 DOM 树，从节点层面理解 HTML 结构，
 *       检测 XSS 攻击语义，而非简单的正则字符串匹配。
 */
defined('ABSPATH') || exit;

class HtmlSemanticParser {

    private static $dangerous_tags = [
        'script'   => '脚本注入',
        'iframe'   => '框架注入',
        'svg'      => 'SVG XSS',
        'img'      => '图片事件注入',
        'body'     => 'body事件注入',
        'video'    => '媒体事件注入',
        'audio'    => '媒体事件注入',
        'form'     => '表单注入',
        'meta'     => '重定向/字符集注入',
        'link'     => '资源劫持',
        'base'     => '基础路径劫持',
        'object'   => '插件注入',
        'embed'    => '插件注入',
        'applet'   => '插件注入',
        'frameset' => '框架注入',
        'frame'    => '框架注入',
    ];

    private static $protocol_attrs = [
        'href', 'src', 'action', 'formaction', 'xlink:href', 'data', 'poster',
    ];

    private static $dangerous_protocols = [
        'javascript:', 'vbscript:', 'data:text/html',
    ];

    private static $js_dangerous_patterns = [
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
        '\'[^\']{0,5}\'\+'                 => '字符串拼接绕过',
        '\"[^\"]{0,5}\"\+'                 => '字符串拼接绕过',
    ];

    public static function analyze(string $html): array {
        $result = self::defaultResult();

        if ($html === '') {
            return $result;
        }

        $domAvailable = self::isDomAvailable();

        if ($domAvailable) {
            $parsed = self::analyzeWithDom($html);
            if ($parsed !== null) {
                $result = array_merge($result, $parsed);
                $result['parser_used'] = 'domdocument';
            } else {
                $result['parser_used'] = 'regex';
                $regexResult = self::analyzeWithRegex($html);
                $result = array_merge($result, $regexResult);
            }
        } else {
            $result['parser_used'] = 'regex';
            $regexResult = self::analyzeWithRegex($html);
            $result = array_merge($result, $regexResult);
        }

        $result['score'] = self::calculateScore($result);
        $result['detected'] = $result['score'] > 0;

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'detected'              => false,
            'score'                 => 0,
            'parser_used'           => 'domdocument',
            'tags'                  => [],
            'event_handlers'        => [],
            'dangerous_protocols'   => [],
            'has_script'            => false,
            'has_event_handler'     => false,
            'has_javascript_protocol' => false,
            'has_svg_payload'       => false,
            'has_iframe'            => false,
            'max_nesting_depth'     => 0,
            'js_dangerous_patterns' => [],
            'total_tag_count'       => 0,
            'indicators'            => [],
        ];
    }

    private static function isDomAvailable(): bool {
        return class_exists('DOMDocument');
    }

    private static function analyzeWithDom(string $html): ?array {
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);

        $prepended = false;
        if (stripos($html, '<!DOCTYPE') === false && stripos($html, '<html') === false) {
            $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>' . $html . '</body></html>';
            $prepended = true;
        }

        $loaded = @$dom->loadHTML($html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();

        if (!$loaded) {
            return null;
        }

        $result = [
            'tags'                  => [],
            'event_handlers'        => [],
            'dangerous_protocols'   => [],
            'has_script'            => false,
            'has_event_handler'     => false,
            'has_javascript_protocol' => false,
            'has_svg_payload'       => false,
            'has_iframe'            => false,
            'max_nesting_depth'     => 0,
            'js_dangerous_patterns' => [],
            'total_tag_count'       => 0,
            'indicators'            => [],
            '_tag_stats'            => [],
            '_hidden_elements'      => 0,
            '_br_count'             => 0,
            '_meta_refresh'         => false,
            '_base_hijack'          => false,
            '_js_code_snippets'     => [],
        ];

        $xpath = new DOMXPath($dom);

        $allElements = $xpath->query('//*');
        if ($allElements === false) {
            return null;
        }

        $result['total_tag_count'] = $allElements->length;

        $tagMap = [];

        foreach ($allElements as $element) {
            $tagName = strtolower($element->tagName);

            $depth = self::getNodeDepth($element);
            if ($depth > $result['max_nesting_depth']) {
                $result['max_nesting_depth'] = $depth;
            }

            $attrs = [];
            foreach ($element->attributes as $attr) {
                $attrs[strtolower($attr->name)] = $attr->value;
            }

            $isDangerous = isset(self::$dangerous_tags[$tagName]);
            if ($isDangerous) {
                if (!isset($tagMap[$tagName])) {
                    $tagMap[$tagName] = [
                        'tag'     => $tagName,
                        'count'   => 0,
                        'attrs'   => [],
                        'samples' => [],
                    ];
                }
                $tagMap[$tagName]['count']++;
                $tagMap[$tagName]['attrs'] = array_merge($tagMap[$tagName]['attrs'], array_keys($attrs));
                if (count($tagMap[$tagName]['samples']) < 3) {
                    $tagMap[$tagName]['samples'][] = $attrs;
                }

                if ($tagName === 'script') {
                    $result['has_script'] = true;
                    $scriptContent = $element->textContent;
                    if (trim($scriptContent) !== '') {
                        $result['_js_code_snippets'][] = $scriptContent;
                    }
                    if (!empty($attrs['src'])) {
                        $result['_js_code_snippets'][] = 'src:' . $attrs['src'];
                    }
                }
                if ($tagName === 'svg') {
                    $result['has_svg_payload'] = true;
                }
                if ($tagName === 'iframe') {
                    $result['has_iframe'] = true;
                }
                if ($tagName === 'meta') {
                    if (!empty($attrs['http-equiv']) && strtolower($attrs['http-equiv']) === 'refresh') {
                        $result['_meta_refresh'] = true;
                    }
                }
                if ($tagName === 'base') {
                    if (!empty($attrs['href'])) {
                        $result['_base_hijack'] = true;
                    }
                }
                if ($tagName === 'br') {
                    $result['_br_count']++;
                }
            }

            $isHidden = self::isElementHidden($element, $attrs);
            if ($isHidden) {
                $result['_hidden_elements']++;
            }

            foreach ($attrs as $attrName => $attrValue) {
                if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                    $result['has_event_handler'] = true;
                    $result['event_handlers'][] = [
                        'tag'   => $tagName,
                        'event' => $attrName,
                        'value' => $attrValue,
                    ];
                    $result['_js_code_snippets'][] = $attrValue;

                    if ($isHidden) {
                        $result['indicators'][] = 'hidden_element_with_event:' . $tagName . '.' . $attrName;
                    }
                }

                if (in_array($attrName, self::$protocol_attrs, true)) {
                    $protocolCheck = self::checkDangerousProtocol($attrValue);
                    if ($protocolCheck) {
                        $result['has_javascript_protocol'] = true;
                        $result['dangerous_protocols'][] = [
                            'attr'  => $attrName,
                            'value' => $attrValue,
                        ];
                    }
                }
            }
        }

        foreach ($tagMap as $tag => $info) {
            $info['attrs'] = array_values(array_unique($info['attrs']));
            $result['tags'][] = $info;
        }

        $result['js_dangerous_patterns'] = self::analyzeJsPatterns($result['_js_code_snippets']);

        if ($result['max_nesting_depth'] > 10) {
            $result['indicators'][] = 'excessive_nesting_depth:' . $result['max_nesting_depth'];
        }
        if ($result['_br_count'] > 20) {
            $result['indicators'][] = 'excessive_br_tags:' . $result['_br_count'];
        }
        if ($result['_hidden_elements'] > 0) {
            $result['indicators'][] = 'hidden_elements:' . $result['_hidden_elements'];
        }
        if ($result['_meta_refresh']) {
            $result['indicators'][] = 'meta_refresh';
        }
        if ($result['_base_hijack']) {
            $result['indicators'][] = 'base_hijack';
        }

        unset($result['_tag_stats'], $result['_hidden_elements'], $result['_br_count']);
        unset($result['_meta_refresh'], $result['_base_hijack'], $result['_js_code_snippets']);

        return $result;
    }

    private static function getNodeDepth(DOMNode $node): int {
        $depth = 0;
        $parent = $node->parentNode;
        while ($parent && $parent->nodeType === XML_ELEMENT_NODE) {
            $depth++;
            $parent = $parent->parentNode;
        }
        return $depth;
    }

    private static function isElementHidden(DOMElement $element, array $attrs): bool {
        if (isset($attrs['hidden'])) {
            return true;
        }
        if (!empty($attrs['style'])) {
            $style = strtolower($attrs['style']);
            if (strpos($style, 'display:none') !== false || strpos($style, 'display: none') !== false) {
                return true;
            }
            if (strpos($style, 'visibility:hidden') !== false || strpos($style, 'visibility: hidden') !== false) {
                return true;
            }
            if (strpos($style, 'opacity:0') !== false || strpos($style, 'opacity: 0') !== false) {
                return true;
            }
        }
        if (!empty($attrs['type']) && $attrs['type'] === 'hidden') {
            return true;
        }
        return false;
    }

    private static function checkDangerousProtocol(string $value): bool {
        $decoded = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $trimmed = preg_replace('/\s+/', '', $decoded);
        $lower = strtolower($trimmed);

        foreach (self::$dangerous_protocols as $proto) {
            if (strpos($lower, $proto) === 0) {
                return true;
            }
        }
        return false;
    }

    private static function analyzeJsPatterns(array $snippets): array {
        $patterns = [];
        foreach ($snippets as $snippet) {
            foreach (self::$js_dangerous_patterns as $pattern => $desc) {
                if (@preg_match('/' . $pattern . '/i', $snippet)) {
                    if (!in_array($desc, $patterns, true)) {
                        $patterns[] = $desc;
                    }
                }
            }
        }
        return $patterns;
    }

    private static function analyzeWithRegex(string $html): array {
        $result = [
            'tags'                  => [],
            'event_handlers'        => [],
            'dangerous_protocols'   => [],
            'has_script'            => false,
            'has_event_handler'     => false,
            'has_javascript_protocol' => false,
            'has_svg_payload'       => false,
            'has_iframe'            => false,
            'max_nesting_depth'     => 0,
            'js_dangerous_patterns' => [],
            'total_tag_count'       => 0,
            'indicators'            => [],
        ];

        $tagCounts = [];
        $jsSnippets = [];

        if (preg_match_all('/<\s*(\w+)([^>]*)>/i', $html, $tagMatches, PREG_SET_ORDER)) {
            $result['total_tag_count'] = count($tagMatches);

            $openTags = 0;
            $maxDepth = 0;
            $currentDepth = 0;

            foreach ($tagMatches as $match) {
                $tagName = strtolower($match[1]);
                $attrString = $match[2];

                $isSelfClosing = (bool)preg_match('/\/\s*$/', $attrString);

                if (!$isSelfClosing && !in_array($tagName, ['br', 'hr', 'img', 'input', 'meta', 'link'], true)) {
                    $currentDepth++;
                    if ($currentDepth > $maxDepth) {
                        $maxDepth = $currentDepth;
                    }
                }

                $attrs = self::parseAttributesRegex($attrString);

                if (isset(self::$dangerous_tags[$tagName])) {
                    if (!isset($tagCounts[$tagName])) {
                        $tagCounts[$tagName] = [
                            'tag'     => $tagName,
                            'count'   => 0,
                            'attrs'   => [],
                            'samples' => [],
                        ];
                    }
                    $tagCounts[$tagName]['count']++;
                    $tagCounts[$tagName]['attrs'] = array_merge($tagCounts[$tagName]['attrs'], array_keys($attrs));
                    if (count($tagCounts[$tagName]['samples']) < 3) {
                        $tagCounts[$tagName]['samples'][] = $attrs;
                    }

                    if ($tagName === 'script') {
                        $result['has_script'] = true;
                        if (preg_match('/<\s*script[^>]*>([\s\S]*?)<\s*\/\s*script\s*>/i', $html, $scriptMatch)) {
                            $jsSnippets[] = $scriptMatch[1];
                        }
                        if (!empty($attrs['src'])) {
                            $jsSnippets[] = 'src:' . $attrs['src'];
                        }
                    }
                    if ($tagName === 'svg') {
                        $result['has_svg_payload'] = true;
                    }
                    if ($tagName === 'iframe') {
                        $result['has_iframe'] = true;
                    }
                    if ($tagName === 'meta') {
                        if (!empty($attrs['http-equiv']) && strtolower($attrs['http-equiv']) === 'refresh') {
                            $result['indicators'][] = 'meta_refresh';
                        }
                    }
                    if ($tagName === 'base') {
                        if (!empty($attrs['href'])) {
                            $result['indicators'][] = 'base_hijack';
                        }
                    }
                }

                foreach ($attrs as $attrName => $attrValue) {
                    if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                        $result['has_event_handler'] = true;
                        $result['event_handlers'][] = [
                            'tag'   => $tagName,
                            'event' => $attrName,
                            'value' => $attrValue,
                        ];
                        $jsSnippets[] = $attrValue;
                    }

                    if (in_array($attrName, self::$protocol_attrs, true)) {
                        if (self::checkDangerousProtocol($attrValue)) {
                            $result['has_javascript_protocol'] = true;
                            $result['dangerous_protocols'][] = [
                                'attr'  => $attrName,
                                'value' => $attrValue,
                            ];
                        }
                    }
                }
            }

            $closeTagCount = preg_match_all('/<\s*\/\s*\w+\s*>/i', $html);
            $result['max_nesting_depth'] = $maxDepth;
        }

        foreach ($tagCounts as $tag => $info) {
            $info['attrs'] = array_values(array_unique($info['attrs']));
            $result['tags'][] = $info;
        }

        $result['js_dangerous_patterns'] = self::analyzeJsPatterns($jsSnippets);

        if ($result['max_nesting_depth'] > 10) {
            $result['indicators'][] = 'excessive_nesting_depth:' . $result['max_nesting_depth'];
        }

        return $result;
    }

    private static function parseAttributesRegex(string $attrString): array {
        $attrs = [];
        if (preg_match_all('/(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))/i', $attrString, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $name = strtolower($m[1]);
                $value = '';
                if (isset($m[2]) && $m[2] !== '') {
                    $value = $m[2];
                } elseif (isset($m[3]) && $m[3] !== '') {
                    $value = $m[3];
                } elseif (isset($m[4])) {
                    $value = $m[4];
                }
                $attrs[$name] = $value;
            }
        }
        return $attrs;
    }

    private static function calculateScore(array $result): int {
        $score = 0;

        $hasScriptWithContent = false;
        foreach ($result['tags'] as $tag) {
            if ($tag['tag'] === 'script' && $tag['count'] > 0) {
                $hasScriptWithContent = true;
                break;
            }
        }
        if ($hasScriptWithContent) {
            $score += 40;
        }

        $eventCount = count($result['event_handlers']);
        if ($eventCount > 0) {
            $eventScore = $eventCount * 15;
            $score += min(45, $eventScore);
        }

        if (!empty($result['dangerous_protocols'])) {
            $score += 35;
        }

        if ($result['has_svg_payload'] && $result['has_event_handler']) {
            $score += 40;
        }

        if ($result['has_iframe']) {
            $score += 20;
        }

        if (in_array('base_hijack', $result['indicators'], true)) {
            $score += 25;
        }

        if (in_array('meta_refresh', $result['indicators'], true)) {
            $score += 15;
        }

        $hasHiddenWithEvent = false;
        foreach ($result['indicators'] as $ind) {
            if (strpos($ind, 'hidden_element_with_event:') === 0) {
                $hasHiddenWithEvent = true;
                break;
            }
        }
        if ($hasHiddenWithEvent) {
            $score += 10;
        }

        $jsPatternCount = count($result['js_dangerous_patterns']);
        if ($jsPatternCount > 0) {
            $jsScore = $jsPatternCount * 10;
            $score += min(30, $jsScore);
        }

        $attackVectors = 0;
        if ($hasScriptWithContent) $attackVectors++;
        if ($eventCount > 0) $attackVectors++;
        if (!empty($result['dangerous_protocols'])) $attackVectors++;
        if ($result['has_svg_payload']) $attackVectors++;
        if ($result['has_iframe']) $attackVectors++;
        if ($attackVectors >= 2) {
            $score += 15;
        }

        return max(0, min(100, (int) round($score)));
    }
}
