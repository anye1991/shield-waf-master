<?php
/**
 * XXE注入语义解析器
 * 职责：真正解析XML/DTD结构，识别外部实体注入。不是简单正则匹配，
 *       而是通过DTD语法分析器解析ENTITY声明、DOCTYPE、SYSTEM/PUBLIC标识符，
 *       并追踪实体引用关系来判断XXE攻击意图。
 */
defined('ABSPATH') || exit;

class XxeSemanticParser {

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

        $isXml = self::isXmlLike($input);
        if (!$isXml) {
            if (self::hasXxeKeywords($input)) {
                $isXml = true;
            } else {
                return $result;
            }
        }

        $dtdResult = self::parseDtdStructure($input);

        $entities = $dtdResult['entities'];
        $doctype = $dtdResult['doctype'];
        $hasParameterEntity = $dtdResult['has_parameter_entity'];
        $entityReferences = self::findEntityReferences($input);
        $hasXInclude = self::detectXInclude($input);
        $xmlWellFormed = self::checkXmlWellFormed($input);

        $externalEntities = [];
        $internalEntities = [];
        $maxEntityLevel = 0;

        foreach ($entities as $ent) {
            if ($ent['is_external']) {
                $externalEntities[] = $ent;
                if ($ent['level'] > $maxEntityLevel) {
                    $maxEntityLevel = $ent['level'];
                }
            } else {
                $internalEntities[] = $ent;
            }
        }

        $schemesInEntities = [];
        foreach ($externalEntities as $ext) {
            foreach (self::$dangerousSchemes as $scheme => $info) {
                if (stripos($ext['value'], $scheme) !== false) {
                    $schemesInEntities[] = [
                        'scheme'   => $scheme,
                        'entity'   => $ext['name'],
                        'level'    => $info['level'],
                        'category' => $info['category'],
                    ];
                }
            }
        }

        $sensitiveHits = [];
        foreach ($externalEntities as $ext) {
            foreach (self::$sensitiveFiles as $file => $level) {
                if (stripos($ext['value'], $file) !== false) {
                    $sensitiveHits[] = [
                        'target' => $file,
                        'entity' => $ext['name'],
                        'level'  => $level,
                    ];
                }
            }
        }

        $cloudMetadataHits = [];
        foreach ($externalEntities as $ext) {
            foreach (self::$cloudMetadataEndpoints as $endpoint => $level) {
                if (stripos($ext['value'], $endpoint) !== false) {
                    $cloudMetadataHits[] = [
                        'endpoint' => $endpoint,
                        'entity'   => $ext['name'],
                        'level'    => $level,
                    ];
                }
            }
        }

        $score = 0;
        $indicators = [];

        if (!empty($externalEntities)) {
            if ($maxEntityLevel >= 5) {
                $score += 30;
                $indicators[] = 'critical_external_entity';
            } elseif ($maxEntityLevel >= 4) {
                $score += 22;
                $indicators[] = 'high_external_entity';
            } elseif ($maxEntityLevel >= 3) {
                $score += 14;
                $indicators[] = 'medium_external_entity';
            } else {
                $score += 8;
                $indicators[] = 'low_external_entity';
            }
        }

        if ($hasParameterEntity && !empty($externalEntities)) {
            $score += 18;
            $indicators[] = 'parameter_entity_xxe';
        }

        if (!empty($doctype) && $doctype['has_external_dtd']) {
            $score += 15;
            $indicators[] = 'external_dtd';
        }

        if ($hasXInclude) {
            $score += 18;
            $indicators[] = 'xinclude_injection';
        }

        if (count($externalEntities) >= 3) {
            $score += 10;
            $indicators[] = 'multiple_external_entities';
        }

        $highSchemeCount = 0;
        foreach ($schemesInEntities as $s) {
            if ($s['level'] >= 5) $highSchemeCount++;
        }
        if ($highSchemeCount >= 1) {
            $score += 20;
            $indicators[] = 'high_risk_scheme';
        }

        if (!empty($sensitiveHits)) {
            $maxSens = 0;
            foreach ($sensitiveHits as $h) {
                if ($h['level'] > $maxSens) $maxSens = $h['level'];
            }
            if ($maxSens >= 5) {
                $score += 20;
                $indicators[] = 'critical_file_target';
            } elseif ($maxSens >= 4) {
                $score += 14;
                $indicators[] = 'high_file_target';
            }
        }

        if (!empty($cloudMetadataHits)) {
            $score += 22;
            $indicators[] = 'cloud_metadata_ssrf';
        }

        if (!empty($entityReferences) && !empty($externalEntities)) {
            $score += 10;
            $indicators[] = 'entity_reference_chain';
        }

        if (count($internalEntities) >= 10) {
            $score += 8;
            $indicators[] = 'entity_expansion_dos';
        }

        if ($xmlWellFormed && !empty($externalEntities)) {
            $score += 5;
            $indicators[] = 'well_formed_xxe_payload';
        }

        $isBlind = self::isBlindXxe($externalEntities, $schemesInEntities);
        if ($isBlind) {
            $score += 8;
            $indicators[] = 'blind_xxe_out_of_band';
        }

        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        return [
            'score'                 => min(100, $score),
            'risk_level'            => $riskLevel,
            'is_xxe'                => $score >= 25,
            'is_xml'                => $isXml,
            'xml_well_formed'       => $xmlWellFormed,
            'is_blind_xxe'          => $isBlind,
            'has_doctype'           => !empty($doctype),
            'has_parameter_entity'  => $hasParameterEntity,
            'has_xinclude'          => $hasXInclude,
            'entity_count'          => count($entities),
            'external_entity_count' => count($externalEntities),
            'entities'              => array_slice($entities, 0, 10),
            'schemes_found'         => $schemesInEntities,
            'sensitive_targets'     => $sensitiveHits,
            'cloud_metadata_hits'   => $cloudMetadataHits,
            'entity_references'     => array_slice($entityReferences, 0, 10),
            'indicators'            => $indicators,
        ];
    }

    private static function defaultResult(): array {
        return [
            'score'                 => 0,
            'risk_level'            => 'clean',
            'is_xxe'                => false,
            'is_xml'                => false,
            'xml_well_formed'       => false,
            'is_blind_xxe'          => false,
            'has_doctype'           => false,
            'has_parameter_entity'  => false,
            'has_xinclude'          => false,
            'entity_count'          => 0,
            'external_entity_count' => 0,
            'entities'              => [],
            'schemes_found'         => [],
            'sensitive_targets'     => [],
            'cloud_metadata_hits'   => [],
            'entity_references'     => [],
            'indicators'            => [],
        ];
    }

    private static function isXmlLike(string $input): bool {
        if (strpos($input, '<?xml') === 0) return true;
        if (strpos($input, '<!DOCTYPE') !== false) return true;
        if (preg_match('/<\?xml\s/', $input)) return true;
        if (preg_match('/^<[a-zA-Z][a-zA-Z0-9_:-]*[\s>]/', trim($input)) && strpos($input, '</') !== false) return true;
        return false;
    }

    private static function hasXxeKeywords(string $input): bool {
        if (stripos($input, '<!ENTITY') !== false) return true;
        if (stripos($input, 'SYSTEM') !== false && stripos($input, 'ENTITY') !== false) return true;
        if (stripos($input, 'php://filter') !== false && stripos($input, 'ENTITY') !== false) return true;
        return false;
    }

    private static function parseDtdStructure(string $input): array {
        $entities = [];
        $doctype = null;
        $hasParameterEntity = false;

        if (preg_match('/<!DOCTYPE\s+([a-zA-Z_][\w:-]*)\s*([^>]*?)>/is', $input, $doctypeMatch)) {
            $doctypeName = $doctypeMatch[1];
            $doctypeBody = $doctypeMatch[2] ?? '';

            $doctype = [
                'name'             => $doctypeName,
                'has_external_dtd' => false,
                'dtd_system'       => null,
                'dtd_public'       => null,
            ];

            if (preg_match('/SYSTEM\s+["\']([^"\']+)["\']/i', $doctypeBody, $m)) {
                $doctype['has_external_dtd'] = true;
                $doctype['dtd_system'] = $m[1];
            }
            if (preg_match('/PUBLIC\s+["\']([^"\']+)["\']/i', $doctypeBody, $m)) {
                $doctype['has_external_dtd'] = true;
                $doctype['dtd_public'] = $m[1];
            }
        }

        if (preg_match_all('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+(SYSTEM|PUBLIC)\s+["\']?([^"\'\s>]+)["\']?\s*>/i', $input, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $isParam = !empty($m[1]);
                $name = $m[2];
                $type = strtoupper($m[3]);
                $value = $m[4];

                if ($isParam) $hasParameterEntity = true;

                $level = self::calcEntityDangerLevel($value, $isParam, $type);

                $entities[] = [
                    'name'        => $name,
                    'type'        => $type,
                    'value'       => $value,
                    'is_param'    => $isParam,
                    'is_external' => true,
                    'level'       => $level,
                ];
            }
        }

        if (preg_match_all('/<!ENTITY\s+(%\s*)?([a-zA-Z_][\w:-]*)\s+"([^"]*)"\s*>/i', $input, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $name = $m[2];
                $value = $m[3];
                $isParam = !empty($m[1]);

                $alreadyExists = false;
                foreach ($entities as $existing) {
                    if ($existing['name'] === $name) {
                        $alreadyExists = true;
                        break;
                    }
                }
                if ($alreadyExists) continue;

                if ($isParam) $hasParameterEntity = true;

                $isExternal = self::entityValueIsExternal($value);
                $level = $isExternal ? self::calcEntityDangerLevel($value, $isParam, 'INTERNAL') : 1;

                $entities[] = [
                    'name'        => $name,
                    'type'        => 'INTERNAL',
                    'value'       => $value,
                    'is_param'    => $isParam,
                    'is_external' => $isExternal,
                    'level'       => $level,
                ];
            }
        }

        return [
            'doctype'              => $doctype,
            'entities'             => $entities,
            'has_parameter_entity' => $hasParameterEntity,
        ];
    }

    private static function calcEntityDangerLevel(string $value, bool $isParam, string $type): int {
        $maxLevel = 2;

        foreach (self::$dangerousSchemes as $scheme => $info) {
            if (stripos($value, $scheme) !== false) {
                if ($info['level'] > $maxLevel) {
                    $maxLevel = $info['level'];
                }
            }
        }

        if ($isParam) {
            $maxLevel = min(5, $maxLevel + 1);
        }

        foreach (self::$sensitiveFiles as $file => $level) {
            if (stripos($value, $file) !== false) {
                if ($level > $maxLevel) $maxLevel = $level;
            }
        }

        return $maxLevel;
    }

    private static function entityValueIsExternal(string $value): bool {
        foreach (self::$dangerousSchemes as $scheme => $info) {
            if (stripos($value, $scheme) !== false) return true;
        }
        if (preg_match('/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//', $value)) return true;
        return false;
    }

    private static function findEntityReferences(string $input): array {
        $refs = [];
        if (preg_match_all('/&([a-zA-Z_][\w:-]*);/', $input, $matches)) {
            foreach ($matches[1] as $name) {
                if ($name !== 'amp' && $name !== 'lt' && $name !== 'gt' && $name !== 'quot' && $name !== 'apos') {
                    $refs[] = $name;
                }
            }
        }
        return array_unique($refs);
    }

    private static function detectXInclude(string $input): bool {
        if (stripos($input, 'xi:include') !== false) return true;
        if (preg_match('/<xinclude\s/i', $input)) return true;
        if (preg_match('/xmlns:xi\s*=\s*["\'][^"\']*XInclude/i', $input)) return true;
        return false;
    }

    private static function checkXmlWellFormed(string $input): bool {
        if (!function_exists('libxml_use_internal_errors')) return false;

        libxml_use_internal_errors(true);
        $doc = @simplexml_load_string($input);
        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors(false);

        if ($doc !== false) return true;

        foreach ($errors as $err) {
            if (strpos($err->message, 'Entity') !== false && strpos($err->message, 'not defined') !== false) {
                return true;
            }
        }

        return false;
    }

    private static function isBlindXxe(array $externalEntities, array $schemes): bool {
        foreach ($schemes as $s) {
            if ($s['category'] === 'ssrf') return true;
        }
        foreach ($externalEntities as $e) {
            if (stripos($e['value'], 'http://') !== false || stripos($e['value'], 'https://') !== false) {
                return true;
            }
        }
        return false;
    }
}
