<?php
/**
 * PHP反序列化语义解析器
 * 职责：深度解析PHP序列化字符串结构，识别反序列化漏洞攻击特征，
 *       包括结构解析、危险类检测、POP链识别、嵌套深度分析、引用检测、长度异常检测等。
 */
defined('ABSPATH') || exit;

class DeserializationSemanticParser {

    private static $dangerousClasses = [
        'SoapClient'         => ['level' => 5, 'desc' => 'SSRF/命令执行', 'category' => 'rce'],
        'DirectoryIterator'  => ['level' => 4, 'desc' => '目录遍历', 'category' => 'file'],
        'GlobIterator'       => ['level' => 4, 'desc' => '文件枚举', 'category' => 'file'],
        'SplFileObject'      => ['level' => 4, 'desc' => '文件读取', 'category' => 'file'],
        'SplTempFileObject'  => ['level' => 3, 'desc' => '临时文件操作', 'category' => 'file'],
        'ReflectionClass'    => ['level' => 4, 'desc' => '反射类', 'category' => 'rce'],
        'ReflectionFunction' => ['level' => 4, 'desc' => '反射函数', 'category' => 'rce'],
        'ReflectionMethod'   => ['level' => 4, 'desc' => '反射方法', 'category' => 'rce'],
        'ReflectionObject'   => ['level' => 4, 'desc' => '反射对象', 'category' => 'rce'],
        'SimpleXMLElement'   => ['level' => 4, 'desc' => 'XXE/文件读取', 'category' => 'xxe'],
        'DOMDocument'        => ['level' => 3, 'desc' => 'XXE', 'category' => 'xxe'],
        'PDO'                => ['level' => 3, 'desc' => '数据库操作', 'category' => 'db'],
        'PDOStatement'       => ['level' => 3, 'desc' => 'SQL注入', 'category' => 'db'],
        'mysqli'             => ['level' => 3, 'desc' => 'SQL注入', 'category' => 'db'],
        'PHar'               => ['level' => 4, 'desc' => 'PHAR反序列化', 'category' => 'deserialization'],
        'finfo'              => ['level' => 2, 'desc' => '文件信息', 'category' => 'file'],
    ];

    private static $magicMethods = [
        '__destruct'   => ['level' => 5, 'desc' => '析构函数-反序列化自动调用', 'trigger' => 'unserialize'],
        '__wakeup'     => ['level' => 5, 'desc' => '反序列化唤醒方法', 'trigger' => 'unserialize'],
        '__toString'   => ['level' => 4, 'desc' => '字符串转换方法', 'trigger' => 'echo/cast'],
        '__get'        => ['level' => 3, 'desc' => '读取不可访问属性', 'trigger' => 'property_read'],
        '__set'        => ['level' => 3, 'desc' => '设置不可访问属性', 'trigger' => 'property_write'],
        '__isset'      => ['level' => 2, 'desc' => 'isset检测不可访问属性', 'trigger' => 'isset'],
        '__unset'      => ['level' => 2, 'desc' => 'unset不可访问属性', 'trigger' => 'unset'],
        '__call'       => ['level' => 4, 'desc' => '调用不可访问方法', 'trigger' => 'method_call'],
        '__callStatic' => ['level' => 3, 'desc' => '静态调用不可访问方法', 'trigger' => 'static_call'],
        '__invoke'     => ['level' => 4, 'desc' => '对象当函数调用', 'trigger' => 'invoke'],
        '__sleep'      => ['level' => 2, 'desc' => '序列化前清理', 'trigger' => 'serialize'],
        '__clone'      => ['level' => 2, 'desc' => '对象克隆', 'trigger' => 'clone'],
    ];

    private static $stringEscapeIndicators = [
        'quote_injection'     => ['level' => 4, 'pattern' => '/s:\d+:"[^"]*";s:\d+:"/', 'desc' => '字符串引号注入'],
        'premature_terminate' => ['level' => 4, 'pattern' => '/s:\d+:"[^"]*";}/', 'desc' => '提前终止结构'],
        'nested_serialize'    => ['level' => 3, 'pattern' => '/s:\d+:"[Oa]:\d+:/', 'desc' => '嵌套序列化字符串'],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $originalInput = $input;
        $decodeResult = self::decodeInput($input);
        $decodedInput = $decodeResult['decoded'];
        $decodeDepth = $decodeResult['depth'];
        $encodeTypes = $decodeResult['encode_types'];

        $result['decode_depth'] = $decodeDepth;
        $result['encode_types'] = $encodeTypes;

        $structure = self::parseSerializedStructure($decodedInput);

        if ($structure['is_valid'] || $structure['partial_match']) {
            $result['is_deserialization'] = true;
            $result['structure_valid'] = $structure['is_valid'];
            $result['partial_match'] = $structure['partial_match'];
            $result['parse_errors'] = $structure['errors'];

            $result['object_count'] = $structure['object_count'];
            $result['array_count'] = $structure['array_count'];
            $result['string_count'] = $structure['string_count'];
            $result['integer_count'] = $structure['integer_count'];
            $result['bool_count'] = $structure['bool_count'];
            $result['float_count'] = $structure['float_count'];
            $result['null_count'] = $structure['null_count'];
            $result['reference_count'] = $structure['reference_count'];
            $result['reference_r_count'] = $structure['reference_r_count'];

            $result['max_nesting_depth'] = $structure['max_depth'];
            $result['dangerous_classes'] = $structure['dangerous_classes'];
            $result['all_classes'] = $structure['all_classes'];
            $result['magic_methods_in_classes'] = self::detectMagicMethodsInClasses($structure['all_classes']);
            $result['length_anomalies'] = $structure['length_anomalies'];
            $result['total_length'] = strlen($decodedInput);

            $popChainFeatures = self::detectPopChainFeatures($structure);
            $result['pop_chain_indicators'] = $popChainFeatures;
            $result['has_pop_chain'] = !empty($popChainFeatures);

            $escapeFeatures = self::detectStringEscapeFeatures($decodedInput, $structure);
            $result['string_escape_indicators'] = $escapeFeatures;

            $indicators = [];
            $score = 0;

            if ($structure['object_count'] >= 5) { $score += 20; $indicators[] = 'multiple_objects'; }
            elseif ($structure['object_count'] >= 3) { $score += 12; $indicators[] = 'several_objects'; }
            elseif ($structure['object_count'] >= 2) { $score += 7; $indicators[] = 'two_objects'; }
            elseif ($structure['object_count'] >= 1) { $score += 3; $indicators[] = 'single_object'; }

            if ($structure['max_depth'] >= 10) { $score += 25; $indicators[] = 'extreme_nesting'; }
            elseif ($structure['max_depth'] >= 6) { $score += 18; $indicators[] = 'deep_nesting'; }
            elseif ($structure['max_depth'] >= 4) { $score += 10; $indicators[] = 'moderate_nesting'; }
            elseif ($structure['max_depth'] >= 2) { $score += 4; $indicators[] = 'light_nesting'; }

            $maxClassLevel = 0;
            $dangerousCategories = [];
            foreach ($structure['dangerous_classes'] as $dc) {
                if ($dc['level'] > $maxClassLevel) $maxClassLevel = $dc['level'];
                if (!in_array($dc['category'], $dangerousCategories)) $dangerousCategories[] = $dc['category'];
            }
            if ($maxClassLevel >= 5) { $score += 35; $indicators[] = 'critical_dangerous_class'; }
            elseif ($maxClassLevel >= 4) { $score += 25; $indicators[] = 'high_dangerous_class'; }
            elseif ($maxClassLevel >= 3) { $score += 15; $indicators[] = 'medium_dangerous_class'; }
            elseif ($maxClassLevel >= 2) { $score += 8; $indicators[] = 'low_dangerous_class'; }

            if (count($structure['dangerous_classes']) >= 3) { $score += 15; $indicators[] = 'multiple_dangerous_classes'; }
            elseif (count($structure['dangerous_classes']) >= 2) { $score += 10; $indicators[] = 'two_dangerous_classes'; }

            $magicMethodCount = count($result['magic_methods_in_classes']);
            if ($magicMethodCount >= 4) { $score += 25; $indicators[] = 'multiple_magic_methods'; }
            elseif ($magicMethodCount >= 2) { $score += 15; $indicators[] = 'several_magic_methods'; }
            elseif ($magicMethodCount >= 1) { $score += 8; $indicators[] = 'magic_method_present'; }

            if ($structure['reference_count'] > 0 || $structure['reference_r_count'] > 0) {
                $totalRefs = $structure['reference_count'] + $structure['reference_r_count'];
                if ($totalRefs >= 5) { $score += 18; $indicators[] = 'many_references'; }
                elseif ($totalRefs >= 3) { $score += 12; $indicators[] = 'multiple_references'; }
                else { $score += 6; $indicators[] = 'reference_present'; }
            }

            if (!empty($structure['length_anomalies'])) {
                $anomalyCount = count($structure['length_anomalies']);
                if ($anomalyCount >= 3) { $score += 30; $indicators[] = 'multiple_length_anomalies'; }
                elseif ($anomalyCount >= 1) { $score += 20; $indicators[] = 'length_anomaly'; }
            }

            if (!empty($popChainFeatures)) {
                $popScore = 0;
                foreach ($popChainFeatures as $pc) {
                    $popScore += isset($pc['level']) ? $pc['level'] * 5 : 10;
                }
                $score += min(35, $popScore);
                $indicators[] = 'pop_chain_detected';
            }

            if (!empty($escapeFeatures)) {
                $escapeScore = 0;
                foreach ($escapeFeatures as $ef) {
                    if ($ef['level'] >= 5) $escapeScore += 20;
                    elseif ($ef['level'] >= 4) $escapeScore += 15;
                    else $escapeScore += 8;
                }
                $score += min(30, $escapeScore);
                $indicators[] = 'string_escape_attempt';
            }

            if ($decodeDepth >= 3) { $score += 20; $indicators[] = 'multi_layer_encoding'; }
            elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
            elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

            if (in_array('rce', $dangerousCategories) && $structure['object_count'] >= 2) {
                $score += 15;
                $indicators[] = 'rce_class_chain';
            }
            if (in_array('rce', $dangerousCategories) && in_array('file', $dangerousCategories)) {
                $score += 10;
                $indicators[] = 'multi_category_exploit';
            }

            if (!$structure['is_valid'] && $structure['partial_match'] && !empty($structure['errors'])) {
                $score += 5;
                $indicators[] = 'malformed_structure';
            }

            $result['score'] = min(100, $score);
            $result['indicators'] = $indicators;

            $riskLevel = 'low';
            if ($result['score'] >= 75) $riskLevel = 'critical';
            elseif ($result['score'] >= 55) $riskLevel = 'high';
            elseif ($result['score'] >= 30) $riskLevel = 'medium';
            $result['risk_level'] = $riskLevel;

            $result['structure_tree'] = $structure['tree'];
        } else {
            $regexIndicators = self::regexQuickScan($decodedInput);
            if (!empty($regexIndicators)) {
                $result['is_deserialization'] = true;
                $result['regex_indicators'] = $regexIndicators;
                $result['score'] = 25;
                $result['risk_level'] = 'low';
                $result['indicators'] = ['regex_match'];
            }
        }

        return $result;
    }

    private static function defaultResult(): array {
        return [
            'score'                    => 0,
            'risk_level'               => 'clean',
            'is_deserialization'       => false,
            'structure_valid'          => false,
            'partial_match'            => false,
            'parse_errors'             => [],
            'object_count'             => 0,
            'array_count'              => 0,
            'string_count'             => 0,
            'integer_count'            => 0,
            'bool_count'               => 0,
            'float_count'              => 0,
            'null_count'               => 0,
            'reference_count'          => 0,
            'reference_r_count'        => 0,
            'max_nesting_depth'        => 0,
            'dangerous_classes'        => [],
            'all_classes'              => [],
            'magic_methods_in_classes' => [],
            'length_anomalies'         => [],
            'pop_chain_indicators'     => [],
            'string_escape_indicators' => [],
            'has_pop_chain'            => false,
            'total_length'             => 0,
            'decode_depth'             => 0,
            'encode_types'             => [],
            'indicators'               => [],
            'structure_tree'           => null,
        ];
    }

    private static function decodeInput(string $input): array {
        $depth = 0;
        $encodeTypes = [];
        $current = $input;

        for ($i = 0; $i < 4; $i++) {
            $decoded = $current;
            $changed = false;

            if (preg_match('/%[0-9a-fA-F]{2}/', $decoded)) {
                $newDecoded = urldecode($decoded);
                if ($newDecoded !== $decoded) {
                    $decoded = $newDecoded;
                    $encodeTypes[] = 'url';
                    $changed = true;
                }
            }

            if (preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', trim($decoded)) && strlen($decoded) > 20) {
                $base64Decoded = base64_decode($decoded, true);
                if ($base64Decoded !== false && self::looksLikeSerialized($base64Decoded)) {
                    $decoded = $base64Decoded;
                    $encodeTypes[] = 'base64';
                    $changed = true;
                }
            }

            if (!$changed) break;
            $depth++;
            $current = $decoded;
        }

        return [
            'decoded'      => $current,
            'depth'        => $depth,
            'encode_types' => array_unique($encodeTypes),
        ];
    }

    private static function looksLikeSerialized(string $str): bool {
        $str = trim($str);
        if ($str === '') return false;
        $firstChar = $str[0];
        return in_array($firstChar, ['O', 'a', 's', 'i', 'b', 'd', 'N', 'R', 'r', 'C'], true);
    }

    public static function parseSerializedStructure(string $data): array {
        $result = [
            'is_valid'           => false,
            'partial_match'      => false,
            'errors'             => [],
            'object_count'       => 0,
            'array_count'        => 0,
            'string_count'       => 0,
            'integer_count'      => 0,
            'bool_count'         => 0,
            'float_count'        => 0,
            'null_count'         => 0,
            'reference_count'    => 0,
            'reference_r_count'  => 0,
            'max_depth'          => 0,
            'dangerous_classes'  => [],
            'all_classes'        => [],
            'length_anomalies'   => [],
            'tree'               => null,
        ];

        $data = trim($data);
        if ($data === '') {
            $result['errors'][] = 'empty_input';
            return $result;
        }

        $offset = 0;
        $length = strlen($data);
        $depth = 0;
        $maxDepth = 0;

        $parsed = self::parseValue($data, $offset, $depth, $maxDepth, $result);

        $result['max_depth'] = $maxDepth;

        $trimmed = trim(substr($data, $offset));
        if (($offset >= $length || $trimmed === '') && $parsed !== null && empty($result['errors'])) {
            $result['is_valid'] = true;
        } else {
            if ($parsed !== null) {
                $result['partial_match'] = true;
                if ($trimmed !== '' && $offset < $length) {
                    $result['errors'][] = 'trailing_data_at_offset_' . $offset;
                }
            } else {
                $startPattern = '/^[OaSidbNRrC]:/';
                if (preg_match($startPattern, $data)) {
                    $result['partial_match'] = true;
                    if (empty($result['errors'])) {
                        $result['errors'][] = 'parse_failed_but_starts_with_serialized';
                    }
                }
            }
        }

        if ($parsed !== null) {
            $result['tree'] = $parsed;
        }

        $result['dangerous_classes'] = self::checkDangerousClasses($result['all_classes']);

        return $result;
    }

    private static function parseValue(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length) return null;

        if ($depth > $maxDepth) $maxDepth = $depth;

        $type = $data[$offset];
        $offset++;

        switch ($type) {
            case 'i':
                return self::parseInteger($data, $offset, $result);
            case 'b':
                return self::parseBool($data, $offset, $result);
            case 'd':
                return self::parseFloat($data, $offset, $result);
            case 's':
                return self::parseString($data, $offset, $result);
            case 'a':
                return self::parseArray($data, $offset, $depth, $maxDepth, $result);
            case 'O':
                return self::parseObject($data, $offset, $depth, $maxDepth, $result);
            case 'N':
                return self::parseNull($data, $offset, $result);
            case 'R':
                return self::parseReference($data, $offset, $result, 'R');
            case 'r':
                return self::parseReference($data, $offset, $result, 'r');
            case 'C':
                return self::parseCustomObject($data, $offset, $depth, $maxDepth, $result);
            default:
                $result['errors'][] = 'unknown_type_' . $type . '_at_' . ($offset - 1);
                return null;
        }
    }

    private static function parseInteger(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'integer_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $start = $offset;
        while ($offset < $length && $data[$offset] !== ';') {
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'integer_unterminated_at_' . $start;
            return null;
        }

        $valueStr = substr($data, $start, $offset - $start);
        $offset++;

        if (!preg_match('/^-?\d+$/', $valueStr)) {
            $result['errors'][] = 'invalid_integer_value_at_' . $start;
            return null;
        }

        $result['integer_count']++;
        return [
            'type'  => 'integer',
            'value' => (int)$valueStr,
        ];
    }

    private static function parseBool(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'bool_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        if ($offset >= $length) {
            $result['errors'][] = 'bool_unterminated';
            return null;
        }

        $value = $data[$offset];
        $offset++;

        if ($offset >= $length || $data[$offset] !== ';') {
            $result['errors'][] = 'bool_missing_semicolon_at_' . $offset;
            return null;
        }
        $offset++;

        if ($value !== '0' && $value !== '1') {
            $result['errors'][] = 'invalid_bool_value_at_' . ($offset - 2);
            return null;
        }

        $result['bool_count']++;
        return [
            'type'  => 'bool',
            'value' => $value === '1',
        ];
    }

    private static function parseFloat(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'float_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $start = $offset;
        while ($offset < $length && $data[$offset] !== ';') {
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'float_unterminated_at_' . $start;
            return null;
        }

        $valueStr = substr($data, $start, $offset - $start);
        $offset++;

        if (!preg_match('/^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?|INF|NAN$/', $valueStr)) {
            $result['errors'][] = 'invalid_float_value_at_' . $start;
            return null;
        }

        $result['float_count']++;
        return [
            'type'  => 'float',
            'value' => (float)$valueStr,
        ];
    }

    private static function parseString(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'string_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $lenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'string_length_invalid_char_at_' . $offset;
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'string_length_unterminated';
            return null;
        }

        $lenStr = substr($data, $lenStart, $offset - $lenStart);
        $declaredLength = (int)$lenStr;
        $offset++;

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'string_missing_opening_quote_at_' . $offset;
            return null;
        }
        $offset++;

        $stringStart = $offset;
        $actualLength = 0;

        while ($offset < $length && $actualLength < $declaredLength) {
            $offset++;
            $actualLength++;
        }

        $stringValue = substr($data, $stringStart, $actualLength);

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'string_missing_closing_quote_at_' . $offset;
            $result['length_anomalies'][] = [
                'type'       => 'missing_closing_quote',
                'position'   => $stringStart,
                'declared'   => $declaredLength,
                'actual'     => $actualLength,
            ];
            return null;
        }
        $offset++;

        if ($offset >= $length || $data[$offset] !== ';') {
            $result['errors'][] = 'string_missing_semicolon_at_' . $offset;
            return null;
        }
        $offset++;

        $realByteCount = strlen($stringValue);
        if ($realByteCount !== $declaredLength) {
            $result['length_anomalies'][] = [
                'type'     => 'length_mismatch',
                'position' => $lenStart,
                'declared' => $declaredLength,
                'actual'   => $realByteCount,
            ];
        }

        if (strpos($stringValue, '"') !== false || strpos($stringValue, ';') !== false) {
            if (self::containsNestedSerialization($stringValue)) {
                $result['length_anomalies'][] = [
                    'type'     => 'nested_serialized_string',
                    'position' => $stringStart,
                ];
            }
        }

        $result['string_count']++;
        return [
            'type'            => 'string',
            'value'           => $stringValue,
            'declared_length' => $declaredLength,
            'actual_length'   => $realByteCount,
        ];
    }

    private static function containsNestedSerialization(string $str): bool {
        return (bool)preg_match('/^(O:\d+:|a:\d+:{)/', $str);
    }

    private static function parseArray(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'array_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $countStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'array_count_invalid_char_at_' . $offset;
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'array_count_unterminated';
            return null;
        }

        $countStr = substr($data, $countStart, $offset - $countStart);
        $elementCount = (int)$countStr;
        $offset++;

        if ($offset >= $length || $data[$offset] !== '{') {
            $result['errors'][] = 'array_missing_opening_brace_at_' . $offset;
            return null;
        }
        $offset++;

        $result['array_count']++;
        $elements = [];
        $parsedCount = 0;

        for ($i = 0; $i < $elementCount; $i++) {
            if ($offset >= $length || $data[$offset] === '}') {
                $result['errors'][] = 'array_premature_end_at_' . $offset;
                break;
            }

            $key = self::parseValue($data, $offset, $depth + 1, $maxDepth, $result);
            if ($key === null) {
                $result['errors'][] = 'array_key_parse_failed_at_' . $offset;
                break;
            }

            if ($offset >= $length) {
                $result['errors'][] = 'array_value_missing_at_' . $offset;
                break;
            }

            $value = self::parseValue($data, $offset, $depth + 1, $maxDepth, $result);
            if ($value === null) {
                $result['errors'][] = 'array_value_parse_failed_at_' . $offset;
                break;
            }

            $elements[] = [
                'key'   => $key,
                'value' => $value,
            ];
            $parsedCount++;
        }

        if ($offset < $length && $data[$offset] === '}') {
            $offset++;
        } else {
            $result['errors'][] = 'array_missing_closing_brace_at_' . $offset;
        }

        if ($parsedCount !== $elementCount) {
            $result['length_anomalies'][] = [
                'type'     => 'array_element_count_mismatch',
                'declared' => $elementCount,
                'actual'   => $parsedCount,
                'position' => $countStart,
            ];
        }

        return [
            'type'      => 'array',
            'size'      => $elementCount,
            'elements'  => $elements,
            'depth'     => $depth,
        ];
    }

    private static function parseObject(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'object_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $nameLenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'object_namelength_invalid_char_at_' . $offset;
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'object_namelength_unterminated';
            return null;
        }

        $nameLenStr = substr($data, $nameLenStart, $offset - $nameLenStart);
        $nameLength = (int)$nameLenStr;
        $offset++;

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'object_missing_name_opening_quote_at_' . $offset;
            return null;
        }
        $offset++;

        $className = substr($data, $offset, $nameLength);
        $offset += $nameLength;

        if ($offset >= $length || $data[$offset] !== '"') {
            $result['errors'][] = 'object_missing_name_closing_quote_at_' . $offset;
            return null;
        }
        $offset++;

        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'object_missing_colon_after_name_at_' . $offset;
            return null;
        }
        $offset++;

        $propCountStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'object_propcount_invalid_char_at_' . $offset;
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'object_propcount_unterminated';
            return null;
        }

        $propCountStr = substr($data, $propCountStart, $offset - $propCountStart);
        $propertyCount = (int)$propCountStr;
        $offset++;

        if ($offset >= $length || $data[$offset] !== '{') {
            $result['errors'][] = 'object_missing_opening_brace_at_' . $offset;
            return null;
        }
        $offset++;

        $result['object_count']++;
        $result['all_classes'][] = $className;

        $properties = [];
        $parsedProps = 0;

        for ($i = 0; $i < $propertyCount; $i++) {
            if ($offset >= $length || $data[$offset] === '}') {
                $result['errors'][] = 'object_premature_end_at_' . $offset;
                break;
            }

            $propName = self::parseValue($data, $offset, $depth + 1, $maxDepth, $result);
            if ($propName === null) {
                $result['errors'][] = 'object_propname_parse_failed_at_' . $offset;
                break;
            }

            if ($offset >= $length) {
                $result['errors'][] = 'object_propvalue_missing_at_' . $offset;
                break;
            }

            $propValue = self::parseValue($data, $offset, $depth + 1, $maxDepth, $result);
            if ($propValue === null) {
                $result['errors'][] = 'object_propvalue_parse_failed_at_' . $offset;
                break;
            }

            $properties[] = [
                'name'  => $propName,
                'value' => $propValue,
            ];
            $parsedProps++;
        }

        if ($offset < $length && $data[$offset] === '}') {
            $offset++;
        } else {
            $result['errors'][] = 'object_missing_closing_brace_at_' . $offset;
        }

        if ($parsedProps !== $propertyCount) {
            $result['length_anomalies'][] = [
                'type'     => 'object_property_count_mismatch',
                'class'    => $className,
                'declared' => $propertyCount,
                'actual'   => $parsedProps,
                'position' => $propCountStart,
            ];
        }

        return [
            'type'       => 'object',
            'class'      => $className,
            'props'      => $propertyCount,
            'properties' => $properties,
            'depth'      => $depth,
        ];
    }

    private static function parseNull(string $data, int &$offset, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ';') {
            $result['errors'][] = 'null_missing_semicolon_at_' . $offset;
            return null;
        }
        $offset++;

        $result['null_count']++;
        return [
            'type'  => 'null',
            'value' => null,
        ];
    }

    private static function parseReference(string $data, int &$offset, array &$result, string $refType) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'reference_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $start = $offset;
        while ($offset < $length && $data[$offset] !== ';') {
            if (!ctype_digit($data[$offset])) {
                $result['errors'][] = 'reference_invalid_char_at_' . $offset;
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) {
            $result['errors'][] = 'reference_unterminated';
            return null;
        }

        $refValue = (int)substr($data, $start, $offset - $start);
        $offset++;

        if ($refType === 'R') {
            $result['reference_count']++;
        } else {
            $result['reference_r_count']++;
        }

        return [
            'type'      => 'reference',
            'ref_type'  => $refType,
            'ref_index' => $refValue,
        ];
    }

    private static function parseCustomObject(string $data, int &$offset, int $depth, int &$maxDepth, array &$result) {
        $length = strlen($data);
        if ($offset >= $length || $data[$offset] !== ':') {
            $result['errors'][] = 'custom_missing_colon_at_' . $offset;
            return null;
        }
        $offset++;

        $nameLenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) {
                return null;
            }
            $offset++;
        }

        if ($offset >= $length) return null;

        $nameLen = (int)substr($data, $nameLenStart, $offset - $nameLenStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '"') return null;
        $offset++;

        $className = substr($data, $offset, $nameLen);
        $offset += $nameLen;

        if ($offset >= $length || $data[$offset] !== '"') return null;
        $offset++;

        if ($offset >= $length || $data[$offset] !== ':') return null;
        $offset++;

        $dataLenStart = $offset;
        while ($offset < $length && $data[$offset] !== ':') {
            if (!ctype_digit($data[$offset])) return null;
            $offset++;
        }

        if ($offset >= $length) return null;

        $dataLen = (int)substr($data, $dataLenStart, $offset - $dataLenStart);
        $offset++;

        if ($offset >= $length || $data[$offset] !== '{') return null;
        $offset++;

        $result['object_count']++;
        $result['all_classes'][] = $className;

        $customData = substr($data, $offset, min($dataLen, $length - $offset));
        $offset += $dataLen;

        if ($offset < $length && $data[$offset] === '}') {
            $offset++;
        }

        return [
            'type'    => 'custom_object',
            'class'   => $className,
            'data'    => $customData,
            'depth'   => $depth,
        ];
    }

    private static function checkDangerousClasses(array $classNames): array {
        $dangerous = [];
        $found = [];

        foreach ($classNames as $className) {
            if (isset($found[$className])) continue;
            $found[$className] = true;

            if (isset(self::$dangerousClasses[$className])) {
                $info = self::$dangerousClasses[$className];
                $dangerous[] = [
                    'class'    => $className,
                    'level'    => $info['level'],
                    'desc'     => $info['desc'],
                    'category' => $info['category'],
                ];
            } else {
                foreach (self::$dangerousClasses as $knownClass => $info) {
                    if (stripos($className, $knownClass) !== false || stripos($knownClass, $className) !== false) {
                        if (strlen($className) > 2 && strlen($knownClass) > 2) {
                            $dangerous[] = [
                                'class'    => $className,
                                'level'    => max(1, $info['level'] - 2),
                                'desc'     => '疑似危险类: ' . $info['desc'],
                                'category' => $info['category'],
                                'similar_to' => $knownClass,
                            ];
                            break;
                        }
                    }
                }
            }
        }

        usort($dangerous, function($a, $b) { return $b['level'] - $a['level']; });
        return $dangerous;
    }

    private static function detectMagicMethodsInClasses(array $classNames): array {
        $found = [];
        $tracked = [];

        foreach ($classNames as $className) {
            $lowerClass = strtolower($className);
            foreach (self::$magicMethods as $method => $info) {
                $key = $method . '|' . $className;
                if (isset($tracked[$key])) continue;
                $tracked[$key] = true;

                if ($lowerClass === 'soapclient' && $method === '__call') {
                    $found[] = [
                        'class'     => $className,
                        'method'    => $method,
                        'level'     => $info['level'],
                        'desc'      => $info['desc'],
                        'trigger'   => $info['trigger'],
                        'confirmed' => true,
                    ];
                } elseif ($lowerClass === 'directoryiterator' && $method === '__toString') {
                    $found[] = [
                        'class'     => $className,
                        'method'    => $method,
                        'level'     => $info['level'],
                        'desc'      => $info['desc'],
                        'trigger'   => $info['trigger'],
                        'confirmed' => true,
                    ];
                } elseif ($lowerClass === 'globiterator' && $method === '__toString') {
                    $found[] = [
                        'class'     => $className,
                        'method'    => $method,
                        'level'     => $info['level'],
                        'desc'      => $info['desc'],
                        'trigger'   => $info['trigger'],
                        'confirmed' => true,
                    ];
                } elseif ($lowerClass === 'splfileobject' && $method === '__toString') {
                    $found[] = [
                        'class'     => $className,
                        'method'    => $method,
                        'level'     => $info['level'],
                        'desc'      => $info['desc'],
                        'trigger'   => $info['trigger'],
                        'confirmed' => true,
                    ];
                }
            }
        }

        if (!empty($classNames)) {
            foreach (self::$magicMethods as $method => $info) {
                if (in_array($method, ['__destruct', '__wakeup'])) {
                    $key = $method . '|*potential*';
                    if (!isset($tracked[$key])) {
                        $tracked[$key] = true;
                        $found[] = [
                            'class'     => '(potential)',
                            'method'    => $method,
                            'level'     => max(1, $info['level'] - 3),
                            'desc'      => '潜在魔法方法触发 - ' . $info['desc'],
                            'trigger'   => $info['trigger'],
                            'confirmed' => false,
                        ];
                    }
                }
            }
        }

        usort($found, function($a, $b) { return $b['level'] - $a['level']; });
        return $found;
    }

    private static function detectPopChainFeatures(array $structure): array {
        $features = [];

        if ($structure['object_count'] >= 2) {
            $features[] = [
                'name'  => 'multiple_objects',
                'level' => 2,
                'desc'  => '多个对象 - POP链基础特征',
            ];
        }

        if ($structure['object_count'] >= 2 && $structure['max_depth'] >= 3) {
            $features[] = [
                'name'  => 'nested_object_chain',
                'level' => 3,
                'desc'  => '嵌套对象结构 - POP链构造特征',
            ];
        }

        if ($structure['reference_count'] > 0 && $structure['object_count'] >= 2) {
            $features[] = [
                'name'  => 'object_references',
                'level' => 3,
                'desc'  => '对象引用 - POP链指针操作',
            ];
        }

        $dangerousCount = count($structure['dangerous_classes']);
        if ($dangerousCount >= 2) {
            $features[] = [
                'name'  => 'multi_dangerous_classes',
                'level' => 4,
                'desc'  => '多危险类组合 - 完整POP链',
            ];
        }

        if ($structure['array_count'] >= 2 && $structure['object_count'] >= 2) {
            $features[] = [
                'name'  => 'array_object_mix',
                'level' => 2,
                'desc'  => '数组对象混合 - 复杂利用链',
            ];
        }

        return $features;
    }

    private static function detectStringEscapeFeatures(string $data, array $structure): array {
        $found = [];

        $hasAnomaly = !empty($structure['length_anomalies']) || !empty($structure['errors']) || !$structure['is_valid'];

        if ($hasAnomaly) {
            foreach (self::$stringEscapeIndicators as $key => $info) {
                if (preg_match($info['pattern'], $data)) {
                    $found[] = [
                        'key'   => $key,
                        'level' => $info['level'],
                        'desc'  => $info['desc'],
                    ];
                }
            }
        }

        if ($hasAnomaly && preg_match_all('/s:(\d+):"/', $data, $lenMatches, PREG_OFFSET_CAPTURE)) {
            $suspiciousCount = 0;
            foreach ($lenMatches[1] as $idx => $match) {
                $declaredLen = (int)$match[0];
                $pos = $match[1];
                $quotePos = strpos($data, ':', $pos);
                if ($quotePos !== false) {
                    $contentStart = $quotePos + 2;
                    $actualContent = substr($data, $contentStart, min($declaredLen + 50, strlen($data) - $contentStart));
                    if (strpos($actualContent, '";s:') !== false || strpos($actualContent, '";O:') !== false || strpos($actualContent, '";a:') !== false) {
                        $suspiciousCount++;
                    }
                }
            }
            if ($suspiciousCount > 0) {
                $found[] = [
                    'key'   => 'string_escape_suspicious',
                    'level' => 4,
                    'desc'  => '字符串逃逸疑似特征 - ' . $suspiciousCount . '处',
                ];
            }
        }

        return $found;
    }

    private static function regexQuickScan(string $data): array {
        $indicators = [];

        if (preg_match('/O:\d+:"[A-Za-z_][\w]*"/', $data)) {
            $indicators[] = 'object_found';
        }
        if (preg_match('/a:\d+:{/', $data)) {
            $indicators[] = 'array_found';
        }
        if (preg_match('/R:\d+;/', $data)) {
            $indicators[] = 'reference_found';
        }
        if (preg_match('/r:\d+;/', $data)) {
            $indicators[] = 'reference_r_found';
        }

        $dangerousPattern = '/O:\d+:"(SoapClient|DirectoryIterator|GlobIterator|SplFileObject|SimpleXMLElement|ReflectionClass|PHar)"/i';
        if (preg_match($dangerousPattern, $data)) {
            $indicators[] = 'dangerous_class';
        }

        return $indicators;
    }
}
