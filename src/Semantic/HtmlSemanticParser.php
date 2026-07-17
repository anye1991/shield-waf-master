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
        if ($html === '') return $result;

        $domAvailable = self::isDomAvailable();
        if ($domAvailable) {
            $parsed = self::analyzeWithDom($html);
            if ($parsed !== null) {
                $result = array_merge($result, $parsed);
                $result['parser_used'] = 'domdocument';
            } else {
                $result['parser_used'] = 'regex';
                $result = array_merge($result, self::analyzeWithRegex($html));
            }
        } else {
            $result['parser_used'] = 'regex';
            $result = array_merge($result, self::analyzeWithRegex($html));
        }

        $result['score'] = self::calculateScore($result);
        $result['risk_level'] = self::calculateRiskLevel($result['score'], $result);
        $result['detected'] = $result['score'] > 0;
        return $result;
    }

    private static function defaultResult(): array {
        return [
            'detected' => false, 'score' => 0, 'risk_level' => 'low',
            'parser_used' => 'domdocument',
            'tags' => [], 'event_handlers' => [], 'dangerous_protocols' => [],
            'has_script' => false, 'has_event_handler' => false,
            'has_javascript_protocol' => false, 'has_svg_payload' => false,
            'has_iframe' => false, 'max_nesting_depth' => 0,
            'js_dangerous_patterns' => [], 'total_tag_count' => 0, 'indicators' => [],
            'context_analysis' => [
                'dangerous_in_head' => 0, 'dangerous_in_body' => 0,
                'dangerous_tag_clusters' => 0, 'deep_nested_events' => 0,
                'hidden_element_events' => 0,
            ],
            'attribute_semantics' => [
                'external_urls' => [], 'data_attr_payloads' => [],
                'style_danger' => [], 'event_code_complexity' => 0,
            ],
            'xss_types' => [],
            'obfuscation' => [
                'html_entity_encoded' => 0, 'uppercase_bypass' => 0,
                'unquoted_attrs' => 0, 'whitespace_bypass' => 0,
                'double_tag_bypass' => 0,
            ],
            'execution_chains' => [],
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
        if (!$loaded) return null;

        $result = self::newParseResult($html);
        $xpath = new DOMXPath($dom);
        $allElements = $xpath->query('//*');
        if ($allElements === false) return null;

        $result['total_tag_count'] = $allElements->length;
        $tagMap = [];

        foreach ($allElements as $element) {
            $tagName = strtolower($element->tagName);
            $depth = self::getNodeDepth($element);
            if ($depth > $result['max_nesting_depth']) $result['max_nesting_depth'] = $depth;

            $attrs = [];
            foreach ($element->attributes as $attr) {
                $attrs[strtolower($attr->name)] = $attr->value;
            }

            $isDangerous = isset(self::$dangerous_tags[$tagName]);
            $isHidden = self::isElementHiddenAttrs($attrs);

            $result['_element_data'][] = [
                'tag' => $tagName, 'depth' => $depth, 'attrs' => $attrs,
                'is_hidden' => $isHidden, 'is_dangerous' => $isDangerous,
                'in_head' => self::isInHead($element),
            ];

            if ($isDangerous) {
                if (!isset($tagMap[$tagName])) {
                    $tagMap[$tagName] = ['tag' => $tagName, 'count' => 0, 'attrs' => [], 'samples' => []];
                }
                $tagMap[$tagName]['count']++;
                $tagMap[$tagName]['attrs'] = array_merge($tagMap[$tagName]['attrs'], array_keys($attrs));
                if (count($tagMap[$tagName]['samples']) < 3) $tagMap[$tagName]['samples'][] = $attrs;

                if ($tagName === 'script') {
                    $result['has_script'] = true;
                    $scriptContent = $element->textContent;
                    if (trim($scriptContent) !== '') $result['_js_code_snippets'][] = $scriptContent;
                    if (!empty($attrs['src'])) $result['_js_code_snippets'][] = 'src:' . $attrs['src'];
                }
                if ($tagName === 'svg') $result['has_svg_payload'] = true;
                if ($tagName === 'iframe') $result['has_iframe'] = true;
                if ($tagName === 'meta' && !empty($attrs['http-equiv']) && strtolower($attrs['http-equiv']) === 'refresh') {
                    $result['_meta_refresh'] = true;
                }
                if ($tagName === 'base' && !empty($attrs['href'])) $result['_base_hijack'] = true;
                if ($tagName === 'br') $result['_br_count']++;
            }

            if ($isHidden) $result['_hidden_elements']++;

            foreach ($attrs as $attrName => $attrValue) {
                if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                    $result['has_event_handler'] = true;
                    $result['event_handlers'][] = ['tag' => $tagName, 'event' => $attrName, 'value' => $attrValue];
                    $result['_js_code_snippets'][] = $attrValue;
                    if ($isHidden) $result['indicators'][] = 'hidden_element_with_event:' . $tagName . '.' . $attrName;
                }
                if (in_array($attrName, self::$protocol_attrs, true) && self::checkDangerousProtocol($attrValue)) {
                    $result['has_javascript_protocol'] = true;
                    $result['dangerous_protocols'][] = ['attr' => $attrName, 'value' => $attrValue];
                }
            }
        }

        foreach ($tagMap as $tag => $info) {
            $info['attrs'] = array_values(array_unique($info['attrs']));
            $result['tags'][] = $info;
        }

        $result['js_dangerous_patterns'] = self::analyzeJsPatterns($result['_js_code_snippets']);

        if ($result['max_nesting_depth'] > 10) $result['indicators'][] = 'excessive_nesting_depth:' . $result['max_nesting_depth'];
        if ($result['_br_count'] > 20) $result['indicators'][] = 'excessive_br_tags:' . $result['_br_count'];
        if ($result['_hidden_elements'] > 0) $result['indicators'][] = 'hidden_elements:' . $result['_hidden_elements'];
        if ($result['_meta_refresh']) $result['indicators'][] = 'meta_refresh';
        if ($result['_base_hijack']) $result['indicators'][] = 'base_hijack';

        self::analyzeDomContext($result);
        self::analyzeAttributeSemantics($result);
        self::detectObfuscation($result);
        $result['xss_types'] = self::classifyXssPayload($result);
        $result['execution_chains'] = self::analyzeExecutionChains($result);

        unset($result['_tag_stats'], $result['_hidden_elements'], $result['_br_count']);
        unset($result['_meta_refresh'], $result['_base_hijack'], $result['_js_code_snippets']);
        unset($result['_raw_html'], $result['_element_data']);
        return $result;
    }

    private static function newParseResult(string $rawHtml): array {
        return [
            'tags' => [], 'event_handlers' => [], 'dangerous_protocols' => [],
            'has_script' => false, 'has_event_handler' => false,
            'has_javascript_protocol' => false, 'has_svg_payload' => false,
            'has_iframe' => false, 'max_nesting_depth' => 0,
            'js_dangerous_patterns' => [], 'total_tag_count' => 0,
            'indicators' => [], '_tag_stats' => [], '_hidden_elements' => 0,
            '_br_count' => 0, '_meta_refresh' => false, '_base_hijack' => false,
            '_js_code_snippets' => [], '_raw_html' => $rawHtml, '_element_data' => [],
            'context_analysis' => [
                'dangerous_in_head' => 0, 'dangerous_in_body' => 0,
                'dangerous_tag_clusters' => 0, 'deep_nested_events' => 0,
                'hidden_element_events' => 0,
            ],
            'attribute_semantics' => [
                'external_urls' => [], 'data_attr_payloads' => [],
                'style_danger' => [], 'event_code_complexity' => 0,
            ],
            'xss_types' => [],
            'obfuscation' => [
                'html_entity_encoded' => 0, 'uppercase_bypass' => 0,
                'unquoted_attrs' => 0, 'whitespace_bypass' => 0,
                'double_tag_bypass' => 0,
            ],
            'execution_chains' => [],
        ];
    }

    private static function isInHead(DOMNode $node): bool {
        $parent = $node->parentNode;
        while ($parent) {
            if ($parent->nodeType === XML_ELEMENT_NODE) {
                $pname = strtolower($parent->tagName);
                if ($pname === 'head') return true;
                if ($pname === 'body') return false;
            }
            $parent = $parent->parentNode;
        }
        return false;
    }

    /**
     * DOM上下文风险评估
     * @param array $result
     * @return void
     */
    private static function analyzeDomContext(array &$result): void {
        $headDangerous = 0;
        $bodyDangerous = 0;
        $clusters = 0;
        $deepNestedEvents = 0;
        $hiddenElementEvents = 0;
        $prevWasMalicious = false;
        $consecutiveMalicious = 0;

        foreach ($result['_element_data'] as $elem) {
            $isDangerous = $elem['is_dangerous'];
            $depth = $elem['depth'];
            $isHidden = $elem['is_hidden'];
            $attrs = $elem['attrs'];
            $inHead = isset($elem['in_head']) ? $elem['in_head'] : false;

            $hasMaliciousAttr = false;
            foreach ($attrs as $attrName => $attrValue) {
                if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                    $hasMaliciousAttr = true;
                    break;
                }
                if (in_array($attrName, self::$protocol_attrs, true) && self::checkDangerousProtocol($attrValue)) {
                    $hasMaliciousAttr = true;
                    break;
                }
            }
            $tagName = $elem['tag'];
            if (in_array($tagName, ['script', 'iframe', 'svg'], true)) {
                $hasMaliciousAttr = true;
            }

            $isMalicious = $isDangerous && $hasMaliciousAttr;

            if ($isDangerous) {
                if ($inHead) $headDangerous++;
                else $bodyDangerous++;
            }

            if ($isMalicious) {
                if ($prevWasMalicious) {
                    $consecutiveMalicious++;
                    if ($consecutiveMalicious >= 2) $clusters++;
                } else {
                    $consecutiveMalicious = 1;
                }
                $prevWasMalicious = true;
            } else {
                $prevWasMalicious = false;
                $consecutiveMalicious = 0;
            }

            $hasEventHandler = false;
            foreach ($attrs as $attrName => $attrValue) {
                if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                    $hasEventHandler = true;
                    break;
                }
            }

            if ($hasEventHandler) {
                if ($depth > 5) $deepNestedEvents++;
                if ($isHidden) $hiddenElementEvents++;
            }
        }

        $result['context_analysis']['dangerous_in_head'] = $headDangerous;
        $result['context_analysis']['dangerous_in_body'] = $bodyDangerous;
        $result['context_analysis']['dangerous_tag_clusters'] = $clusters;
        $result['context_analysis']['deep_nested_events'] = $deepNestedEvents;
        $result['context_analysis']['hidden_element_events'] = $hiddenElementEvents;

        if ($clusters > 0) $result['indicators'][] = 'dangerous_tag_clusters:' . $clusters;
        if ($deepNestedEvents > 0) $result['indicators'][] = 'deep_nested_events:' . $deepNestedEvents;
    }

    /**
     * 属性值语义分析
     * @param array $result
     * @return void
     */
    private static function analyzeAttributeSemantics(array &$result): void {
        $externalUrls = [];
        $dataAttrPayloads = [];
        $styleDangers = [];
        $totalComplexity = 0;
        $eventCount = 0;

        $jsKeywords = [
            'eval', 'setTimeout', 'setInterval', 'Function',
            'document.write', 'innerHTML', 'outerHTML',
            'document.cookie', 'document.location', 'window.location',
            'XMLHttpRequest', 'fetch', 'atob', 'btoa',
            'String.fromCharCode', 'createElement', 'appendChild',
        ];

        foreach ($result['_element_data'] as $elem) {
            $tagName = $elem['tag'];
            $attrs = $elem['attrs'];
            foreach ($attrs as $attrName => $attrValue) {
                if (in_array($attrName, self::$protocol_attrs, true)) {
                    $urlInfo = self::parseUrlInfo($attrValue);
                    if ($urlInfo && !empty($urlInfo['host'])) {
                        $externalUrls[] = [
                            'attr' => $attrName, 'tag' => $tagName,
                            'url' => $attrValue, 'host' => $urlInfo['host'],
                            'scheme' => $urlInfo['scheme'],
                        ];
                    }
                }

                if (strpos($attrName, 'data-') === 0) {
                    $lowerVal = strtolower($attrValue);
                    $suspicious = false;
                    foreach (['javascript', 'eval', 'script', '<script', 'onerror', 'onload', 'alert'] as $kw) {
                        if (strpos($lowerVal, $kw) !== false) { $suspicious = true; break; }
                    }
                    if ($suspicious) {
                        $dataAttrPayloads[] = ['attr' => $attrName, 'tag' => $tagName, 'value' => $attrValue];
                    }
                }

                if ($attrName === 'style') {
                    $styleLower = strtolower($attrValue);
                    $styleIssues = [];
                    if (strpos($styleLower, 'expression(') !== false) $styleIssues[] = 'expression';
                    if (preg_match('/url\s*\(\s*[\'"]?\s*javascript:/i', $attrValue)) $styleIssues[] = 'url_javascript';
                    if (strpos($styleLower, 'behavior:') !== false) $styleIssues[] = 'behavior';
                    if (!empty($styleIssues)) {
                        $styleDangers[] = ['tag' => $tagName, 'issues' => $styleIssues, 'value' => $attrValue];
                    }
                }

                if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                    $eventCount++;
                    $complexity = 0;
                    foreach ($jsKeywords as $kw) {
                        if (stripos($attrValue, $kw) !== false) $complexity += 2;
                    }
                    $complexity += min(5, substr_count($attrValue, '('));
                    $complexity += min(3, substr_count($attrValue, ';'));
                    if (strlen($attrValue) > 100) $complexity += 3;
                    $totalComplexity += $complexity;
                }
            }
        }

        $result['attribute_semantics']['external_urls'] = $externalUrls;
        $result['attribute_semantics']['data_attr_payloads'] = $dataAttrPayloads;
        $result['attribute_semantics']['style_danger'] = $styleDangers;
        $result['attribute_semantics']['event_code_complexity'] = $eventCount > 0 ? (int) round($totalComplexity / $eventCount) : 0;
    }

    /**
     * 混淆绕过检测
     * @param array $result
     * @return void
     */
    private static function detectObfuscation(array &$result): void {
        $rawHtml = $result['_raw_html'];
        $entityCount = 0;
        $upperCount = 0;
        $unquotedCount = 0;
        $whitespaceBypassCount = 0;
        $doubleTagCount = 0;

        if (preg_match_all('/&#x?[0-9a-fA-F]+;/', $rawHtml, $entityMatches)) {
            foreach ($entityMatches[0] as $entity) {
                $decoded = html_entity_decode($entity, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if (preg_match('/[a-zA-Z]/', $decoded)) $entityCount++;
            }
        }
        if (preg_match_all('/\s(ON[A-Z]+|SRC|HREF|ACTION|FORMACTION)\s*=/', $rawHtml, $upperMatches)) {
            $upperCount = count($upperMatches[0]);
        }
        if (preg_match_all('/<\s*\w+[^>]*\s+\w+\s*=\s*[^"\'\s>][^\s>]*/i', $rawHtml, $unquotedMatches)) {
            foreach ($unquotedMatches[0] as $match) {
                if (preg_match('/\s(on\w+|src|href|action|formaction|data-)\s*=\s*[^"\'\s>]/i', $match)) $unquotedCount++;
            }
        }
        if (preg_match_all('/\bon\s+[a-z]+\s*=/i', $rawHtml, $wsMatches)) {
            $whitespaceBypassCount = count($wsMatches[0]);
        }
        if (preg_match_all('/<<\s*(script|img|iframe|svg|video|audio)\s*>/i', $rawHtml, $doubleMatches)) {
            $doubleTagCount = count($doubleMatches[0]);
        }

        $result['obfuscation']['html_entity_encoded'] = $entityCount;
        $result['obfuscation']['uppercase_bypass'] = $upperCount;
        $result['obfuscation']['unquoted_attrs'] = $unquotedCount;
        $result['obfuscation']['whitespace_bypass'] = $whitespaceBypassCount;
        $result['obfuscation']['double_tag_bypass'] = $doubleTagCount;

        if ($entityCount > 0) $result['indicators'][] = 'html_entity_obfuscation:' . $entityCount;
        if ($upperCount > 0) $result['indicators'][] = 'uppercase_bypass:' . $upperCount;
        if ($whitespaceBypassCount > 0) $result['indicators'][] = 'whitespace_bypass:' . $whitespaceBypassCount;
        if ($doubleTagCount > 0) $result['indicators'][] = 'double_tag_bypass:' . $doubleTagCount;
    }

    /**
     * XSS载荷分类
     * @param array $result
     * @return array
     */
    private static function classifyXssPayload(array $result): array {
        $types = [];
        $hasDomXss = false;
        $domPatterns = ['document.write', 'innerHTML', 'outerHTML', 'document.location', 'window.location'];
        foreach ($result['js_dangerous_patterns'] as $patternDesc) {
            foreach ($domPatterns as $dp) {
                if (stripos($patternDesc, $dp) !== false) { $hasDomXss = true; break 2; }
            }
        }
        if ($hasDomXss) $types[] = 'dom_based';
        if (!empty($result['event_handlers'])) $types[] = 'event_based';

        if ($result['has_iframe'] && !empty($result['dangerous_protocols'])) {
            $types[] = 'iframe_injection';
        } elseif ($result['has_iframe']) {
            foreach ($result['attribute_semantics']['external_urls'] as $urlInfo) {
                if ($urlInfo['tag'] === 'iframe' && $urlInfo['attr'] === 'src') { $types[] = 'iframe_injection'; break; }
            }
        }

        $hasDataTheft = false;
        if (in_array('cookie操作', $result['js_dangerous_patterns'], true)) {
            foreach ($result['js_dangerous_patterns'] as $pattern) {
                if (in_array($pattern, ['location跳转', '窗口跳转', 'XHR请求', 'fetch请求'], true)) { $hasDataTheft = true; break; }
            }
        }
        if ($hasDataTheft) $types[] = 'data_theft';
        if ($result['has_script']) $types[] = 'script_injection';
        if (!empty($result['dangerous_protocols'])) $types[] = 'protocol_bypass';
        if ($result['has_svg_payload']) $types[] = 'svg_xss';

        return array_values(array_unique($types));
    }

    /**
     * 代码执行链分析
     * @param array $result
     * @return array
     */
    private static function analyzeExecutionChains(array $result): array {
        $chains = [];

        foreach ($result['dangerous_protocols'] as $proto) {
            $chains[] = [
                'type' => 'protocol_execution',
                'steps' => ['entry' => $proto['attr'], 'protocol' => $proto['value'], 'result' => 'direct_code_execution'],
                'severity' => 'critical',
            ];
        }

        foreach ($result['event_handlers'] as $handler) {
            $eventValue = $handler['value'];
            $steps = ['entry' => $handler['tag'] . '.' . $handler['event']];
            $severity = 'medium';

            $isHidden = false;
            if (!empty($result['context_analysis']['hidden_element_events']) && $result['context_analysis']['hidden_element_events'] > 0) {
                foreach ($result['_element_data'] as $elem) {
                    if ($elem['tag'] === $handler['tag'] && $elem['is_hidden']) {
                        $hasEvent = false;
                        foreach ($elem['attrs'] as $an => $av) {
                            if ($an === $handler['event']) {
                                $hasEvent = true;
                                break;
                            }
                        }
                        if ($hasEvent) {
                            $isHidden = true;
                            break;
                        }
                    }
                }
            }
            if ($isHidden) {
                $steps['context'] = 'hidden_element';
                $severity = 'high';
            }

            if (stripos($eventValue, 'eval(') !== false) { $steps['execution'] = 'eval()'; $severity = 'high'; }
            if (stripos($eventValue, 'setTimeout(') !== false || stripos($eventValue, 'setInterval(') !== false) {
                $steps['execution'] = 'timer_string_execution'; $severity = 'high';
            }
            if (stripos($eventValue, 'innerHTML') !== false || stripos($eventValue, 'outerHTML') !== false) {
                $steps['execution'] = 'dom_html_injection'; $severity = 'high';
            }
            if (stripos($eventValue, 'document.write') !== false) { $steps['execution'] = 'document.write'; $severity = 'high'; }
            if (stripos($eventValue, 'atob(') !== false || stripos($eventValue, 'base64') !== false) {
                $steps['decode'] = 'base64_decode';
                if ($severity === 'high') $severity = 'critical';
            }
            if (stripos($eventValue, 'String.fromCharCode') !== false) {
                $steps['decode'] = 'charcode_decode';
                if ($severity === 'high') $severity = 'critical';
            }

            $chains[] = ['type' => 'event_execution', 'steps' => $steps, 'severity' => $severity];
        }

        if ($result['has_script']) {
            $jsPatterns = $result['js_dangerous_patterns'];
            $steps = ['entry' => 'script_tag'];
            $severity = 'high';

            if (in_array('cookie操作', $jsPatterns, true) &&
                (in_array('location跳转', $jsPatterns, true) || in_array('窗口跳转', $jsPatterns, true) ||
                 in_array('XHR请求', $jsPatterns, true) || in_array('fetch请求', $jsPatterns, true))) {
                $steps['data_access'] = 'cookie';
                $steps['exfiltration'] = 'http_request';
                $severity = 'critical';
            }
            if (in_array('eval执行', $jsPatterns, true)) $steps['execution'] = 'eval()';
            if (in_array('Base64解码', $jsPatterns, true)) $steps['decode'] = 'base64_decode';

            if (count($steps) > 1) {
                $chains[] = ['type' => 'script_execution', 'steps' => $steps, 'severity' => $severity];
            }
        }

        return $chains;
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

    private static function isElementHiddenAttrs(array $attrs): bool {
        if (isset($attrs['hidden'])) return true;
        if (!empty($attrs['style'])) {
            $style = strtolower($attrs['style']);
            if (strpos($style, 'display:none') !== false || strpos($style, 'display: none') !== false) return true;
            if (strpos($style, 'visibility:hidden') !== false || strpos($style, 'visibility: hidden') !== false) return true;
            if (strpos($style, 'opacity:0') !== false || strpos($style, 'opacity: 0') !== false) return true;
        }
        if (!empty($attrs['type']) && $attrs['type'] === 'hidden') return true;
        return false;
    }

    private static function isElementHidden(DOMElement $element, array $attrs): bool {
        return self::isElementHiddenAttrs($attrs);
    }

    private static function checkDangerousProtocol(string $value): bool {
        $decoded = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $trimmed = preg_replace('/\s+/', '', $decoded);
        $lower = strtolower($trimmed);
        foreach (self::$dangerous_protocols as $proto) {
            if (strpos($lower, $proto) === 0) return true;
        }
        return false;
    }

    private static function parseUrlInfo(string $url): ?array {
        $decoded = html_entity_decode($url, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $parts = parse_url($decoded);
        if ($parts === false) return null;
        return [
            'scheme' => isset($parts['scheme']) ? strtolower($parts['scheme']) : '',
            'host' => isset($parts['host']) ? strtolower($parts['host']) : '',
            'path' => isset($parts['path']) ? $parts['path'] : '',
            'query' => isset($parts['query']) ? $parts['query'] : '',
            'fragment' => isset($parts['fragment']) ? $parts['fragment'] : '',
        ];
    }

    private static function analyzeJsPatterns(array $snippets): array {
        $patterns = [];
        foreach ($snippets as $snippet) {
            foreach (self::$js_dangerous_patterns as $pattern => $desc) {
                if (@preg_match('/' . $pattern . '/i', $snippet) && !in_array($desc, $patterns, true)) {
                    $patterns[] = $desc;
                }
            }
        }
        return $patterns;
    }

    private static function analyzeWithRegex(string $html): array {
        $result = self::newParseResult($html);
        $tagCounts = [];
        $jsSnippets = [];
        $elementData = [];

        if (preg_match_all('/<\s*(\w+)([^>]*)>/i', $html, $tagMatches, PREG_SET_ORDER)) {
            $result['total_tag_count'] = count($tagMatches);
            $maxDepth = 0;
            $currentDepth = 0;
            $inHead = false;

            foreach ($tagMatches as $match) {
                $tagName = strtolower($match[1]);
                $attrString = $match[2];
                $isSelfClosing = (bool)preg_match('/\/\s*$/', $attrString);

                if ($tagName === 'head') $inHead = true;
                elseif ($tagName === 'body') $inHead = false;

                if (!$isSelfClosing && !in_array($tagName, ['br', 'hr', 'img', 'input', 'meta', 'link'], true)) {
                    $currentDepth++;
                    if ($currentDepth > $maxDepth) $maxDepth = $currentDepth;
                }

                $attrs = self::parseAttributesRegex($attrString);
                $isDangerous = isset(self::$dangerous_tags[$tagName]);
                $isHidden = self::isElementHiddenAttrs($attrs);

                $elementData[] = [
                    'tag' => $tagName, 'depth' => $currentDepth, 'attrs' => $attrs,
                    'is_hidden' => $isHidden, 'is_dangerous' => $isDangerous,
                    'in_head' => $inHead,
                ];

                if ($isDangerous) {
                    if (!isset($tagCounts[$tagName])) {
                        $tagCounts[$tagName] = ['tag' => $tagName, 'count' => 0, 'attrs' => [], 'samples' => []];
                    }
                    $tagCounts[$tagName]['count']++;
                    $tagCounts[$tagName]['attrs'] = array_merge($tagCounts[$tagName]['attrs'], array_keys($attrs));
                    if (count($tagCounts[$tagName]['samples']) < 3) $tagCounts[$tagName]['samples'][] = $attrs;

                    if ($tagName === 'script') {
                        $result['has_script'] = true;
                        if (preg_match('/<\s*script[^>]*>([\s\S]*?)<\s*\/\s*script\s*>/i', $html, $scriptMatch)) {
                            $jsSnippets[] = $scriptMatch[1];
                        }
                        if (!empty($attrs['src'])) $jsSnippets[] = 'src:' . $attrs['src'];
                    }
                    if ($tagName === 'svg') $result['has_svg_payload'] = true;
                    if ($tagName === 'iframe') $result['has_iframe'] = true;
                    if ($tagName === 'meta' && !empty($attrs['http-equiv']) && strtolower($attrs['http-equiv']) === 'refresh') {
                        $result['indicators'][] = 'meta_refresh';
                    }
                    if ($tagName === 'base' && !empty($attrs['href'])) $result['indicators'][] = 'base_hijack';
                }

                foreach ($attrs as $attrName => $attrValue) {
                    if (strpos($attrName, 'on') === 0 && strlen($attrName) > 2) {
                        $result['has_event_handler'] = true;
                        $result['event_handlers'][] = ['tag' => $tagName, 'event' => $attrName, 'value' => $attrValue];
                        $jsSnippets[] = $attrValue;
                    }
                    if (in_array($attrName, self::$protocol_attrs, true) && self::checkDangerousProtocol($attrValue)) {
                        $result['has_javascript_protocol'] = true;
                        $result['dangerous_protocols'][] = ['attr' => $attrName, 'value' => $attrValue];
                    }
                }
            }
            $result['max_nesting_depth'] = $maxDepth;
        }

        foreach ($tagCounts as $tag => $info) {
            $info['attrs'] = array_values(array_unique($info['attrs']));
            $result['tags'][] = $info;
        }

        $result['js_dangerous_patterns'] = self::analyzeJsPatterns($jsSnippets);
        $result['_element_data'] = $elementData;

        if ($result['max_nesting_depth'] > 10) $result['indicators'][] = 'excessive_nesting_depth:' . $result['max_nesting_depth'];

        self::analyzeDomContext($result);
        self::analyzeAttributeSemantics($result);
        self::detectObfuscation($result);
        $result['xss_types'] = self::classifyXssPayload($result);
        $result['execution_chains'] = self::analyzeExecutionChains($result);

        return $result;
    }

    private static function parseAttributesRegex(string $attrString): array {
        $attrs = [];
        if (preg_match_all('/(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))/i', $attrString, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $name = strtolower($m[1]);
                $value = '';
                if (isset($m[2]) && $m[2] !== '') $value = $m[2];
                elseif (isset($m[3]) && $m[3] !== '') $value = $m[3];
                elseif (isset($m[4])) $value = $m[4];
                $attrs[$name] = $value;
            }
        }
        return $attrs;
    }

    private static function calculateScore(array $result): int {
        $baseScore = 0;

        $hasScriptWithContent = false;
        foreach ($result['tags'] as $tag) {
            if ($tag['tag'] === 'script' && $tag['count'] > 0) { $hasScriptWithContent = true; break; }
        }
        if ($hasScriptWithContent) $baseScore += 40;

        $eventCount = count($result['event_handlers']);
        if ($eventCount > 0) $baseScore += min(45, $eventCount * 15);
        if (!empty($result['dangerous_protocols'])) $baseScore += 35;
        if ($result['has_svg_payload'] && $result['has_event_handler']) $baseScore += 40;
        if ($result['has_iframe']) $baseScore += 20;
        if (in_array('base_hijack', $result['indicators'], true)) $baseScore += 25;
        if (in_array('meta_refresh', $result['indicators'], true)) $baseScore += 15;

        $hasHiddenWithEvent = false;
        foreach ($result['indicators'] as $ind) {
            if (strpos($ind, 'hidden_element_with_event:') === 0) { $hasHiddenWithEvent = true; break; }
        }
        if ($hasHiddenWithEvent) $baseScore += 10;

        $jsPatternCount = count($result['js_dangerous_patterns']);
        if ($jsPatternCount > 0) $baseScore += min(30, $jsPatternCount * 10);

        $attackVectors = 0;
        if ($hasScriptWithContent) $attackVectors++;
        if ($eventCount > 0) $attackVectors++;
        if (!empty($result['dangerous_protocols'])) $attackVectors++;
        if ($result['has_svg_payload']) $attackVectors++;
        if ($result['has_iframe']) $attackVectors++;
        if ($attackVectors >= 2) $baseScore += 15;

        $contextBonus = 0;
        if (!empty($result['context_analysis'])) {
            $ctx = $result['context_analysis'];
            if (!empty($ctx['dangerous_tag_clusters'])) $contextBonus += min(15, $ctx['dangerous_tag_clusters'] * 5);
            if (!empty($ctx['deep_nested_events'])) $contextBonus += 8;
            if (!empty($ctx['hidden_element_events'])) $contextBonus += 20;
        }

        $obfuscationBonus = 0;
        if (!empty($result['obfuscation'])) {
            $obf = $result['obfuscation'];
            if (!empty($obf['html_entity_encoded'])) $obfuscationBonus += min(15, $obf['html_entity_encoded'] * 3);
            if (!empty($obf['uppercase_bypass'])) $obfuscationBonus += 5;
            if (!empty($obf['whitespace_bypass'])) $obfuscationBonus += 8;
            if (!empty($obf['double_tag_bypass'])) $obfuscationBonus += 10;
        }

        $chainBonus = 0;
        if (!empty($result['execution_chains'])) {
            foreach ($result['execution_chains'] as $chain) {
                if (empty($chain['severity'])) continue;
                switch ($chain['severity']) {
                    case 'critical': $chainBonus += 25; break;
                    case 'high': $chainBonus += 15; break;
                    case 'medium': $chainBonus += 5; break;
                }
            }
            $chainBonus = min(30, $chainBonus);
        }

        if (!empty($result['attribute_semantics'])) {
            $attrSem = $result['attribute_semantics'];
            if (!empty($attrSem['style_danger'])) $baseScore += count($attrSem['style_danger']) * 8;
            if (!empty($attrSem['data_attr_payloads'])) $baseScore += count($attrSem['data_attr_payloads']) * 5;
            if (!empty($attrSem['event_code_complexity']) && $attrSem['event_code_complexity'] > 5) $baseScore += 5;
        }

        $totalScore = $baseScore + $contextBonus + $obfuscationBonus + $chainBonus;
        return max(0, min(100, (int) round($totalScore)));
    }

    /**
     * 计算风险等级
     * @param int $score
     * @param array $result
     * @return string
     */
    private static function calculateRiskLevel(int $score, array $result): string {
        $hasCriticalChain = false;
        if (!empty($result['execution_chains'])) {
            foreach ($result['execution_chains'] as $chain) {
                if (!empty($chain['severity']) && $chain['severity'] === 'critical') { $hasCriticalChain = true; break; }
            }
        }
        $hasDataTheft = in_array('data_theft', $result['xss_types'], true);

        if ($hasCriticalChain || $hasDataTheft || $score >= 85) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 30) return 'medium';
        return 'low';
    }
}
