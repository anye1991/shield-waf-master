<?php
defined('ABSPATH') || exit;

class XxeSemanticParser {

    const TOKEN_DECLARATION = 'DECLARATION';
    const TOKEN_DOCTYPE     = 'DOCTYPE';
    const TOKEN_ELEMENT     = 'ELEMENT';
    const TOKEN_END_ELEMENT = 'END_ELEMENT';
    const TOKEN_COMMENT     = 'COMMENT';
    const TOKEN_CDATA       = 'CDATA';
    const TOKEN_PI          = 'PI';
    const TOKEN_TEXT        = 'TEXT';
    const TOKEN_ENTITY_DECL = 'ENTITY_DECL';
    const TOKEN_NOTATION    = 'NOTATION';
    const TOKEN_ATTLIST     = 'ATTLIST';
    const TOKEN_XINCLUDE    = 'XINCLUDE';
    const TOKEN_EOF         = 'EOF';

    private static $dangerousSchemes = [
        'php://'     => ['level' => 5, 'desc' => 'PHP伪协议', 'category' => 'code_exec'],
        'expect://'  => ['level' => 5, 'desc' => 'Expect命令执行', 'category' => 'code_exec'],
        'gopher://'  => ['level' => 5, 'desc' => 'Gopher协议(SSRF)', 'category' => 'ssrf'],
        'file://'    => ['level' => 4, 'desc' => 'File协议读文件', 'category' => 'file_read'],
        'jar://'     => ['level' => 4, 'desc' => 'Jar协议', 'category' => 'file_read'],
        'netdoc://'  => ['level' => 4, 'desc' => 'Netdoc协议', 'category' => 'file_read'],
        'dict://'    => ['level' => 4, 'desc' => 'Dict协议', 'category' => 'ssrf'],
        'ldap://'    => ['level' => 4, 'desc' => 'LDAP协议', 'category' => 'ssrf'],
        'tftp://'    => ['level' => 4, 'desc' => 'TFTP协议', 'category' => 'ssrf'],
        'phar://'    => ['level' => 4, 'desc' => 'Phar反序列化', 'category' => 'deserialization'],
        'data://'    => ['level' => 4, 'desc' => 'Data URI', 'category' => 'file_read'],
        'zip://'     => ['level' => 3, 'desc' => 'Zip协议', 'category' => 'file_read'],
        'glob://'    => ['level' => 3, 'desc' => 'Glob协议', 'category' => 'file_read'],
        'http://'    => ['level' => 3, 'desc' => 'HTTP外带(Blind)', 'category' => 'ssrf'],
        'https://'   => ['level' => 3, 'desc' => 'HTTPS外带(Blind)', 'category' => 'ssrf'],
        'ftp://'     => ['level' => 3, 'desc' => 'FTP外带', 'category' => 'ssrf'],
    ];

    private static $sensitiveFiles = [
        '/etc/passwd'           => 5,
        '/etc/shadow'           => 5,
        'config.php'            => 5,
        'web.config'            => 4,
        '.htaccess'             => 4,
        '.env'                  => 5,
        'id_rsa'                => 5,
        '/etc/sudoers'          => 5,
        '/proc/self/environ'    => 4,
        'php://filter'          => 5,
    ];

    private static $cloudMetadataEndpoints = [
        '169.254.169.254' => 5,
        'metadata.google.internal' => 4,
        'metadata'       => 3,
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        try {
            $tokens = self::tokenize($input);
            $result['token_count'] = count($tokens);

            $ast = self::parse($tokens, $input);
            $result['parser_used'] = 'ast';
            $result['ast'] = $ast;
            $result['ast_summary'] = self::summarizeAst($ast);

            $semanticResult = self::analyzeAst($ast);
            $result = array_merge($result, $semanticResult);
        } catch (Exception $e) {
            $result['parser_used'] = 'fallback';
            $result['parse_errors'][] = $e->getMessage();
            $result = array_merge($result, self::regexFallback($input));
        }

        $score = self::calculateScore($result);
        $result['score'] = min(100, $score);
        $result['risk_level'] = self::calculateRiskLevel($score);
        $result['is_xxe'] = $score >= 25;
        $result['is_blind_xxe'] = self::isBlindXxe($result);

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'                 => 0,
            'risk_level'            => 'clean',
            'is_xxe'                => false,
            'is_xml'                => false,
            'is_blind_xxe'          => false,
            'has_doctype'           => false,
            'has_parameter_entity'  => false,
            'has_xinclude'          => false,
            'has_notation'          => false,
            'entity_count'          => 0,
            'external_entity_count' => 0,
            'entities'              => [],
            'schemes_found'         => [],
            'sensitive_targets'     => [],
            'cloud_metadata_hits'   => [],
            'entity_references'     => [],
            'indicators'            => [],
            'parser_used'           => 'ast',
            'token_count'           => 0,
            'ast'                   => null,
            'ast_summary'           => [],
            'parse_errors'          => [],
        ];
    }

    // ==================== Tokenizer ====================

    private static function tokenize(string $xml): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($xml);

        while ($pos < $len) {
            if ($pos + 4 < $len && substr($xml, $pos, 5) === '<?xml') {
                $end = strpos($xml, '?>', $pos);
                $tokens[] = ['type' => self::TOKEN_DECLARATION, 'value' => substr($xml, $pos, $end - $pos + 2), 'pos' => $pos];
                $pos = $end + 2;
                continue;
            }

            if ($pos + 1 < $len && $xml[$pos] === '<' && $xml[$pos + 1] === '!') {
                if ($pos + 8 < $len && substr($xml, $pos, 9) === '<!DOCTYPE') {
                    $end = strpos($xml, '>', $pos);
                    $tokens[] = ['type' => self::TOKEN_DOCTYPE, 'value' => substr($xml, $pos, $end - $pos + 1), 'pos' => $pos];
                    $pos = $end + 1;
                    continue;
                }

                if ($pos + 3 < $len && substr($xml, $pos, 4) === '<!--') {
                    $end = strpos($xml, '-->', $pos);
                    if ($end !== false) {
                        $tokens[] = ['type' => self::TOKEN_COMMENT, 'value' => substr($xml, $pos, $end - $pos + 3), 'pos' => $pos];
                        $pos = $end + 3;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_COMMENT, 'value' => substr($xml, $pos), 'pos' => $pos];
                        $pos = $len;
                    }
                    continue;
                }

                if ($pos + 8 < $len && substr($xml, $pos, 9) === '<![CDATA[') {
                    $end = strpos($xml, ']]>', $pos);
                    if ($end !== false) {
                        $tokens[] = ['type' => self::TOKEN_CDATA, 'value' => substr($xml, $pos, $end - $pos + 3), 'pos' => $pos];
                        $pos = $end + 3;
                    } else {
                        $tokens[] = ['type' => self::TOKEN_CDATA, 'value' => substr($xml, $pos), 'pos' => $pos];
                        $pos = $len;
                    }
                    continue;
                }

                if (preg_match('/^<!ENTITY\s+/i', substr($xml, $pos))) {
                    $end = strpos($xml, '>', $pos);
                    $tokens[] = ['type' => self::TOKEN_ENTITY_DECL, 'value' => substr($xml, $pos, $end - $pos + 1), 'pos' => $pos];
                    $pos = $end + 1;
                    continue;
                }

                if (preg_match('/^<!NOTATION\s+/i', substr($xml, $pos))) {
                    $end = strpos($xml, '>', $pos);
                    $tokens[] = ['type' => self::TOKEN_NOTATION, 'value' => substr($xml, $pos, $end - $pos + 1), 'pos' => $pos];
                    $pos = $end + 1;
                    continue;
                }

                if (preg_match('/^<!ATTLIST\s+/i', substr($xml, $pos))) {
                    $end = strpos($xml, '>', $pos);
                    $tokens[] = ['type' => self::TOKEN_ATTLIST, 'value' => substr($xml, $pos, $end - $pos + 1), 'pos' => $pos];
                    $pos = $end + 1;
                    continue;
                }

                $end = strpos($xml, '>', $pos);
                $tokens[] = ['type' => self::TOKEN_PI, 'value' => substr($xml, $pos, $end - $pos + 1), 'pos' => $pos];
                $pos = $end + 1;
                continue;
            }

            if ($pos + 1 < $len && $xml[$pos] === '<' && $xml[$pos + 1] === '/') {
                $end = strpos($xml, '>', $pos);
                $tagName = trim(substr($xml, $pos + 2, $end - $pos - 2));
                $tokens[] = ['type' => self::TOKEN_END_ELEMENT, 'value' => $tagName, 'pos' => $pos];
                $pos = $end + 1;
                continue;
            }

            if ($xml[$pos] === '<') {
                $end = strpos($xml, '>', $pos);
                $tagContent = substr($xml, $pos + 1, $end - $pos - 1);
                $isSelfClosing = substr($tagContent, -2) === '/>';
                $tagContent = rtrim($tagContent, '/');
                $parts = preg_split('/\s+/', trim($tagContent), 2);
                $tagName = $parts[0];

                $tokenValue = ['tag' => $tagName, 'self_closing' => $isSelfClosing];
                if (isset($parts[1])) {
                    $tokenValue['attrs'] = self::parseXmlAttrs($parts[1]);
                }

                $tokens[] = ['type' => self::TOKEN_ELEMENT, 'value' => $tokenValue, 'pos' => $pos];
                $pos = $end + 1;
                continue;
            }

            $textEnd = strpos($xml, '<', $pos);
            if ($textEnd === false) $textEnd = $len;
            $text = trim(substr($xml, $pos, $textEnd - $pos));
            if ($text !== '') {
                $tokens[] = ['type' => self::TOKEN_TEXT, 'value' => $text, 'pos' => $pos];
            }
            $pos = $textEnd;
        }

        $tokens[] = ['type' => self::TOKEN_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    private static function parseXmlAttrs(string $raw): array {
        $attrs = [];
        $pos = 0;
        $len = strlen($raw);

        while ($pos < $len) {
            while ($pos < $len && ctype_space($raw[$pos])) $pos++;
            if ($pos >= $len) break;

            $nameStart = $pos;
            while ($pos < $len && !ctype_space($raw[$pos]) && $raw[$pos] !== '=') $pos++;
            $name = substr($raw, $nameStart, $pos - $nameStart);
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
                    while ($pos < $len && !ctype_space($raw[$pos]) && $raw[$pos] !== '>') $pos++;
                    $value = substr($raw, $valueStart, $pos - $valueStart);
                }
            }

            $attrs[$name] = $value;
        }

        return $attrs;
    }

    // ==================== Parser ====================

    private static function parse(array $tokens, string $input): array {
        $state = ['tokens' => $tokens, 'pos' => 0, 'input' => $input];
        $ast = self::parseDocument($state);
        self::parseEntitiesFromDoctype($ast, $input);
        return $ast;
    }

    private static function parseDocument(array &$state): array {
        $children = [];
        $declaration = null;
        $doctype = null;

        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_DECLARATION) {
                $declaration = $token['value'];
                self::next($state);
                continue;
            }
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
            if ($token['type'] === self::TOKEN_ELEMENT) {
                $children[] = self::parseXmlElement($state);
                continue;
            }
            if ($token['type'] === self::TOKEN_ENTITY_DECL) {
                $children[] = self::parseEntityDeclaration($token);
                self::next($state);
                continue;
            }
            self::next($state);
        }

        return [
            'type'         => 'document',
            'declaration'  => $declaration,
            'doctype'      => $doctype,
            'children'     => $children,
            'entities'     => [],
        ];
    }

    private static function parseXmlElement(array &$state): array {
        $startToken = self::current($state);
        $tagName = $startToken['value']['tag'];
        $attrs = $startToken['value']['attrs'] ?? [];
        $selfClosing = $startToken['value']['self_closing'] ?? false;

        self::next($state);

        if ($selfClosing) {
            return ['type' => 'element', 'tag' => $tagName, 'attrs' => $attrs, 'children' => [], 'self_closing' => true, 'pos' => $startToken['pos']];
        }

        $children = [];
        while (!self::isEof($state)) {
            $token = self::current($state);
            if ($token['type'] === self::TOKEN_END_ELEMENT && $token['value'] === $tagName) {
                self::next($state);
                break;
            }
            if ($token['type'] === self::TOKEN_ELEMENT) {
                $children[] = self::parseXmlElement($state);
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

    private static function parseEntityDeclaration(array $token): array {
        $value = $token['value'];
        $matches = [];

        if (preg_match('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+(SYSTEM|PUBLIC)\s+["\']?([^"\'\s>]+)["\']?(?:\s+["\']([^"\']*)["\'])?\s*>/i', $value, $matches)) {
            $isParam = !empty($matches[1]);
            return [
                'type'          => 'entity',
                'name'          => $matches[2],
                'entity_type'   => strtoupper($matches[3]),
                'value'         => $matches[4],
                'public_id'     => isset($matches[5]) ? $matches[5] : null,
                'is_parameter'  => $isParam,
                'is_external'   => true,
                'pos'           => $token['pos'],
            ];
        }

        if (preg_match('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+"([^"]*)"\s*>/i', $value, $matches)) {
            $isParam = !empty($matches[1]);
            return [
                'type'          => 'entity',
                'name'          => $matches[2],
                'entity_type'   => 'INTERNAL',
                'value'         => $matches[3],
                'public_id'     => null,
                'is_parameter'  => $isParam,
                'is_external'   => false,
                'pos'           => $token['pos'],
            ];
        }

        return ['type' => 'entity', 'name' => 'unknown', 'value' => $value, 'pos' => $token['pos']];
    }

    private static function parseEntitiesFromDoctype(array &$ast, string $input): void {
        $doctype = $ast['doctype'] ?? '';
        if (empty($doctype)) return;

        if (preg_match('/<!DOCTYPE[^>]*\[([\s\S]*?)\]>/i', $doctype, $subsetMatch)) {
            $dtdText = $subsetMatch[1];
            $entities = [];

            if (preg_match_all('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+(SYSTEM|PUBLIC)\s+["\']?([^"\'\s>]+)["\']?(?:\s+["\']([^"\']*)["\'])?\s*>/i', $dtdText, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $m) {
                    $entities[] = [
                        'type'          => 'entity',
                        'name'          => $m[2],
                        'entity_type'   => strtoupper($m[3]),
                        'value'         => $m[4],
                        'public_id'     => isset($m[5]) ? $m[5] : null,
                        'is_parameter'  => !empty($m[1]),
                        'is_external'   => true,
                    ];
                }
            }

            if (preg_match_all('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+"([^"]*)"\s*>/i', $dtdText, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $m) {
                    $name = $m[2];
                    $alreadyExists = false;
                    foreach ($entities as $e) {
                        if ($e['name'] === $name) { $alreadyExists = true; break; }
                    }
                    if (!$alreadyExists) {
                        $entities[] = [
                            'type'          => 'entity',
                            'name'          => $name,
                            'entity_type'   => 'INTERNAL',
                            'value'         => $m[3],
                            'is_parameter'  => !empty($m[1]),
                            'is_external'   => false,
                        ];
                    }
                }
            }

            $ast['entities'] = array_merge($ast['entities'], $entities);
        }
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
            'has_doctype'           => false,
            'has_parameter_entity'  => false,
            'has_xinclude'          => false,
            'has_notation'          => false,
            'entity_count'          => 0,
            'external_entity_count' => 0,
            'entities'              => [],
            'schemes_found'         => [],
            'sensitive_targets'     => [],
            'cloud_metadata_hits'   => [],
            'entity_references'     => [],
            'indicators'            => [],
        ];

        if (!empty($ast['doctype'])) {
            $result['has_doctype'] = true;
        }

        $entities = $ast['entities'] ?? [];
        foreach ($entities as $entity) {
            $result['entity_count']++;
            $level = self::calcEntityDangerLevel($entity['value'], $entity['is_parameter'] ?? false, $entity['entity_type'] ?? 'INTERNAL');

            $entityWithLevel = $entity;
            $entityWithLevel['level'] = $level;
            $result['entities'][] = $entityWithLevel;

            if ($entity['is_external'] ?? false) {
                $result['external_entity_count']++;

                foreach (self::$dangerousSchemes as $scheme => $info) {
                    if (stripos($entity['value'], $scheme) !== false) {
                        $result['schemes_found'][] = [
                            'scheme'   => $scheme,
                            'entity'   => $entity['name'],
                            'level'    => $info['level'],
                            'category' => $info['category'],
                        ];
                    }
                }

                foreach (self::$sensitiveFiles as $file => $fileLevel) {
                    if (stripos($entity['value'], $file) !== false) {
                        $result['sensitive_targets'][] = [
                            'target' => $file,
                            'entity' => $entity['name'],
                            'level'  => $fileLevel,
                        ];
                    }
                }

                foreach (self::$cloudMetadataEndpoints as $endpoint => $epLevel) {
                    if (stripos($entity['value'], $endpoint) !== false) {
                        $result['cloud_metadata_hits'][] = [
                            'endpoint' => $endpoint,
                            'entity'   => $entity['name'],
                            'level'    => $epLevel,
                        ];
                    }
                }
            }

            if ($entity['is_parameter'] ?? false) {
                $result['has_parameter_entity'] = true;
            }
        }

        self::findEntityReferences($ast, $result);
        self::detectXInclude($ast, $result);
        self::detectEntityExpansion($ast, $result);

        return $result;
    }

    private static function findEntityReferences(array $node, array &$result): void {
        if ($node['type'] === 'text') {
            $text = $node['value'];
            if (preg_match_all('/&([a-zA-Z_][\w:-]*);/', $text, $matches)) {
                foreach ($matches[1] as $name) {
                    if (!in_array($name, ['amp', 'lt', 'gt', 'quot', 'apos']) && !in_array($name, $result['entity_references'])) {
                        $result['entity_references'][] = $name;
                    }
                }
            }
        }

        if ($node['type'] === 'element') {
            foreach ($node['attrs'] ?? [] as $attrValue) {
                if ($attrValue !== null && preg_match_all('/&([a-zA-Z_][\w:-]*);/', $attrValue, $matches)) {
                    foreach ($matches[1] as $name) {
                        if (!in_array($name, ['amp', 'lt', 'gt', 'quot', 'apos']) && !in_array($name, $result['entity_references'])) {
                            $result['entity_references'][] = $name;
                        }
                    }
                }
            }

            foreach ($node['children'] ?? [] as $child) {
                self::findEntityReferences($child, $result);
            }
        }

        if ($node['type'] === 'document') {
            foreach ($node['children'] ?? [] as $child) {
                self::findEntityReferences($child, $result);
            }
        }
    }

    private static function detectXInclude(array $ast, array &$result): void {
        self::walkForXInclude($ast, $result);
    }

    private static function walkForXInclude(array $node, array &$result): void {
        if ($node['type'] === 'element') {
            $tagLower = strtolower($node['tag']);
            if ($tagLower === 'xi:include' || $tagLower === 'xinclude' || $tagLower === 'include') {
                $result['has_xinclude'] = true;
                $result['indicators'][] = 'xinclude_injection';
            }

            foreach ($node['attrs'] ?? [] as $attrName => $attrValue) {
                if (stripos($attrName, 'xinclude') !== false || stripos($attrValue ?? '', 'XInclude') !== false) {
                    $result['has_xinclude'] = true;
                    $result['indicators'][] = 'xinclude_via_attribute';
                }
            }

            foreach ($node['children'] ?? [] as $child) {
                self::walkForXInclude($child, $result);
            }
        }

        if ($node['type'] === 'document') {
            foreach ($node['children'] ?? [] as $child) {
                self::walkForXInclude($child, $result);
            }
        }
    }

    private static function detectEntityExpansion(array $ast, array &$result): void {
        $entities = $ast['entities'] ?? [];
        if (count($entities) >= 10) {
            $result['indicators'][] = 'entity_expansion_dos';
        }

        $entityMap = [];
        foreach ($entities as $e) {
            $entityMap[$e['name']] = $e;
        }

        foreach ($entities as $entity) {
            $depth = self::calculateEntityDepth($entity['name'], $entityMap, []);
            if ($depth > 5) {
                $result['indicators'][] = 'deep_entity_nesting:' . $depth;
                break;
            }
        }

        $billionLaughsPatterns = [
            '/<!ENTITY\s+\w+\s+"&(\w+);&(\w+);"/i',
            '/ENTITY.*ENTITY.*ENTITY.*ENTITY.*ENTITY/si',
        ];
        $doctype = $ast['doctype'] ?? '';
        foreach ($billionLaughsPatterns as $pattern) {
            if (preg_match($pattern, $doctype)) {
                $result['indicators'][] = 'entity_expansion_attack';
                break;
            }
        }
    }

    private static function calculateEntityDepth(string $entityName, array $entityMap, array $visited): int {
        if (isset($visited[$entityName])) return 0;
        if (!isset($entityMap[$entityName])) return 0;

        $visited[$entityName] = true;
        $entity = $entityMap[$entityName];
        $value = $entity['value'];
        $maxDepth = 1;

        if (preg_match_all('/&([a-zA-Z_][\w:-]*);/', $value, $matches)) {
            foreach ($matches[1] as $refName) {
                $depth = 1 + self::calculateEntityDepth($refName, $entityMap, $visited);
                if ($depth > $maxDepth) $maxDepth = $depth;
            }
        }

        if (preg_match_all('/%([a-zA-Z_][\w:-]*);/', $value, $paramMatches)) {
            foreach ($paramMatches[1] as $refName) {
                $depth = 1 + self::calculateEntityDepth($refName, $entityMap, $visited);
                if ($depth > $maxDepth) $maxDepth = $depth;
            }
        }

        return $maxDepth;
    }

    // ==================== AST Summary ====================

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type'               => $ast['type'],
            'has_declaration'    => !empty($ast['declaration']),
            'has_doctype'        => !empty($ast['doctype']),
            'entity_count'       => count($ast['entities'] ?? []),
            'external_entities'  => 0,
        ];

        foreach ($ast['entities'] ?? [] as $e) {
            if ($e['is_external'] ?? false) $summary['external_entities']++;
        }

        return $summary;
    }

    // ==================== Regex Fallback ====================

    private static function regexFallback(string $input): array {
        $result = [
            'has_doctype'           => false,
            'has_parameter_entity'  => false,
            'has_xinclude'          => false,
            'has_notation'          => false,
            'entity_count'          => 0,
            'external_entity_count' => 0,
            'entities'              => [],
            'schemes_found'         => [],
            'sensitive_targets'     => [],
            'cloud_metadata_hits'   => [],
            'entity_references'     => [],
            'indicators'            => [],
        ];

        if (strpos($input, '<!DOCTYPE') !== false) {
            $result['has_doctype'] = true;
        }

        if (preg_match_all('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+(SYSTEM|PUBLIC)\s+["\']?([^"\'\s>]+)["\']?/i', $input, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $isParam = !empty($m[1]);
                $entity = [
                    'type'          => 'entity',
                    'name'          => $m[2],
                    'entity_type'   => strtoupper($m[3]),
                    'value'         => $m[4],
                    'is_parameter'  => $isParam,
                    'is_external'   => true,
                    'level'         => self::calcEntityDangerLevel($m[4], $isParam, strtoupper($m[3])),
                ];
                $result['entities'][] = $entity;
                $result['entity_count']++;
                $result['external_entity_count']++;

                if ($isParam) $result['has_parameter_entity'] = true;

                foreach (self::$dangerousSchemes as $scheme => $info) {
                    if (stripos($m[4], $scheme) !== false) {
                        $result['schemes_found'][] = ['scheme' => $scheme, 'entity' => $m[2], 'level' => $info['level']];
                    }
                }
            }
        }

        if (preg_match_all('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+"([^"]*)"/i', $input, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $result['entity_count']++;
            }
        }

        if (preg_match('/<!NOTATION/i', $input)) {
            $result['has_notation'] = true;
        }

        if (preg_match('/xi:include|xinclude/i', $input)) {
            $result['has_xinclude'] = true;
            $result['indicators'][] = 'xinclude_injection';
        }

        if (preg_match_all('/&([a-zA-Z_][\w:-]*);/', $input, $matches)) {
            foreach ($matches[1] as $name) {
                if (!in_array($name, ['amp', 'lt', 'gt', 'quot', 'apos']) && !in_array($name, $result['entity_references'])) {
                    $result['entity_references'][] = $name;
                }
            }
        }

        return $result;
    }

    // ==================== Scoring ====================

    private static function calculateScore(array $result): int {
        $score = 0;

        $externalEntities = $result['external_entity_count'] ?? 0;
        if ($externalEntities > 0) {
            $maxLevel = 0;
            foreach ($result['entities'] ?? [] as $ent) {
                if (($ent['is_external'] ?? false) && ($ent['level'] ?? 0) > $maxLevel) {
                    $maxLevel = $ent['level'];
                }
            }
            if ($maxLevel >= 5) { $score += 30; $result['indicators'][] = 'critical_external_entity'; }
            elseif ($maxLevel >= 4) { $score += 22; $result['indicators'][] = 'high_external_entity'; }
            elseif ($maxLevel >= 3) { $score += 14; $result['indicators'][] = 'medium_external_entity'; }
            else { $score += 8; }
        }

        if (($result['has_parameter_entity'] ?? false) && $externalEntities > 0) {
            $score += 18;
            $result['indicators'][] = 'parameter_entity_xxe';
        }

        if (($result['has_doctype'] ?? false)) {
            $score += 10;
        }

        if (($result['has_xinclude'] ?? false)) {
            $score += 18;
            $result['indicators'][] = 'xinclude_injection';
        }

        if (!empty($result['schemes_found'])) {
            $highSchemeCount = 0;
            foreach ($result['schemes_found'] as $s) {
                if ($s['level'] >= 5) $highSchemeCount++;
            }
            if ($highSchemeCount >= 1) { $score += 20; $result['indicators'][] = 'high_risk_scheme'; }
        }

        if (!empty($result['sensitive_targets'])) {
            $maxSens = 0;
            foreach ($result['sensitive_targets'] as $h) {
                if ($h['level'] > $maxSens) $maxSens = $h['level'];
            }
            if ($maxSens >= 5) { $score += 20; $result['indicators'][] = 'critical_file_target'; }
            elseif ($maxSens >= 4) { $score += 14; }
        }

        if (!empty($result['cloud_metadata_hits'])) {
            $score += 22;
            $result['indicators'][] = 'cloud_metadata_ssrf';
        }

        if (!empty($result['entity_references']) && $externalEntities > 0) {
            $score += 10;
            $result['indicators'][] = 'entity_reference_chain';
        }

        return min(100, $score);
    }

    private static function calculateRiskLevel(int $score): string {
        if ($score >= 70) return 'critical';
        if ($score >= 50) return 'high';
        if ($score >= 30) return 'medium';
        if ($score >= 10) return 'low';
        return 'clean';
    }

    private static function calcEntityDangerLevel(string $value, bool $isParam, string $type): int {
        $maxLevel = 2;

        foreach (self::$dangerousSchemes as $scheme => $info) {
            if (stripos($value, $scheme) !== false && $info['level'] > $maxLevel) {
                $maxLevel = $info['level'];
            }
        }

        if ($isParam) {
            $maxLevel = min(5, $maxLevel + 1);
        }

        foreach (self::$sensitiveFiles as $file => $level) {
            if (stripos($value, $file) !== false && $level > $maxLevel) {
                $maxLevel = $level;
            }
        }

        return $maxLevel;
    }

    private static function isBlindXxe(array $result): bool {
        foreach ($result['schemes_found'] ?? [] as $s) {
            if ($s['category'] === 'ssrf') return true;
        }
        foreach ($result['entities'] ?? [] as $e) {
            if (($e['is_external'] ?? false) &&
                (stripos($e['value'], 'http://') !== false || stripos($e['value'], 'https://') !== false)) {
                return true;
            }
        }
        return false;
    }
}