<?php
defined('ABSPATH') || exit;

class NoSqlInjection {
    private static $mongoOperators = [
        '$gt', '$gte', '$lt', '$lte', '$ne', '$eq',
        '$in', '$nin', '$all', '$size', '$exists',
        '$type', '$mod', '$regex', '$options',
        '$where', '$expr', '$jsonSchema',
        '$elemMatch', '$match', '$lookup',
        '$addFields', '$project', '$unwind',
        '$group', '$sort', '$limit', '$skip',
        '$count', '$replaceRoot', '$replaceWith',
        '$out', '$merge', '$set', '$unset',
        '$rename', '$currentDate', '$inc',
        '$mul', '$max', '$min', '$setOnInsert',
        '$push', '$pop', '$pull', '$pullAll',
        '$addToSet', '$bit', '$arrayElemAt',
        '$concatArrays', '$filter', '$indexOfArray',
        '$isArray', '$map', '$objectToArray',
        '$range', '$reduce', '$reverseArray',
        '$zip', '$abs', '$add', '$ceil',
        '$divide', '$exp', '$floor', '$ln',
        '$log', '$log10', '$mod', '$multiply',
        '$pow', '$round', '$sqrt', '$subtract',
        '$trunc', '$concat', '$indexOfBytes',
        '$indexOfCP', '$split', '$strLenBytes',
        '$strLenCP', '$substr', '$substrBytes',
        '$substrCP', '$toLower', '$toUpper',
        '$trim', '$ltrim', '$rtrim', '$regexFind',
        '$regexFindAll', '$regexMatch', '$replaceOne',
        '$replaceAll', '$dateToString', '$dayOfMonth',
        '$dayOfWeek', '$dayOfYear', '$hour', '$isoDayOfWeek',
        '$isoWeek', '$isoWeekYear', '$millisecond', '$minute',
        '$month', '$second', '$week', '$year',
    ];

    private static $nosqlParamNames = [
        'username', 'user', 'email', 'password', 'pass',
        'id', '_id', 'uid', 'user_id', 'session_id',
        'query', 'q', 'search', 'filter',
        'sort', 'order', 'limit', 'offset',
        'page', 'skip', 'fields', 'projection',
        'aggregate', 'group', 'match',
        'where', 'condition', 'criteria',
        'data', 'doc', 'document', 'record',
    ];

    private static $dangerPatterns = [
        ['pattern' => '/\$where\s*:/i', 'severity' => 95, 'name' => 'MongoDB $where operator'],
        ['pattern' => '/\$regex\s*:/i', 'severity' => 85, 'name' => 'MongoDB $regex operator'],
        ['pattern' => '/\{\s*\$gt\s*:/i', 'severity' => 80, 'name' => 'MongoDB $gt operator'],
        ['pattern' => '/\{\s*\$lt\s*:/i', 'severity' => 80, 'name' => 'MongoDB $lt operator'],
        ['pattern' => '/\{\s*\$ne\s*:/i', 'severity' => 75, 'name' => 'MongoDB $ne operator'],
        ['pattern' => '/\{\s*\$exists\s*:/i', 'severity' => 70, 'name' => 'MongoDB $exists operator'],
        ['pattern' => '/\{\s*\$type\s*:/i', 'severity' => 65, 'name' => 'MongoDB $type operator'],
        ['pattern' => '/\{\s*\$in\s*:/i', 'severity' => 70, 'name' => 'MongoDB $in operator'],
        ['pattern' => '/\{\s*\$nin\s*:/i', 'severity' => 70, 'name' => 'MongoDB $nin operator'],
        ['pattern' => '/\{\s*\$regex\s*:/i', 'severity' => 85, 'name' => 'MongoDB regex object'],
        ['pattern' => '/\{\s*\$where\s*:/i', 'severity' => 95, 'name' => 'MongoDB where object'],
        ['pattern' => '/\{\s*\$expr\s*:/i', 'severity' => 80, 'name' => 'MongoDB $expr operator'],
        ['pattern' => '/\{\s*\$mod\s*:/i', 'severity' => 70, 'name' => 'MongoDB $mod operator'],
        ['pattern' => '/\{\s*\$elemMatch\s*:/i', 'severity' => 70, 'name' => 'MongoDB $elemMatch operator'],
        ['pattern' => '/\{\s*\$all\s*:/i', 'severity' => 65, 'name' => 'MongoDB $all operator'],
        ['pattern' => '/\{\s*\$size\s*:/i', 'severity' => 65, 'name' => 'MongoDB $size operator'],
        ['pattern' => '/\beval\s*\(/i', 'severity' => 95, 'name' => 'MongoDB eval'],
        ['pattern' => '/\bthis\.\w+\s*[=><]/i', 'severity' => 85, 'name' => 'MongoDB this reference'],
        ['pattern' => '/\bnew\s+Date\s*\(/i', 'severity' => 70, 'name' => 'JavaScript Date object'],
        ['pattern' => '/\bnew\s+RegExp\s*\(/i', 'severity' => 80, 'name' => 'JavaScript RegExp object'],
        ['pattern' => '/\bJSON\.parse\s*\(/i', 'severity' => 80, 'name' => 'JSON.parse'],
        ['pattern' => '/\bJSON\.stringify\s*\(/i', 'severity' => 70, 'name' => 'JSON.stringify'],
        ['pattern' => '/\bObject\.keys\s*\(/i', 'severity' => 70, 'name' => 'Object.keys'],
        ['pattern' => '/\bObject\.values\s*\(/i', 'severity' => 70, 'name' => 'Object.values'],
        ['pattern' => '/\bArray\.prototype\./i', 'severity' => 80, 'name' => 'Array prototype'],
        ['pattern' => '/\bString\.prototype\./i', 'severity' => 80, 'name' => 'String prototype'],
        ['pattern' => '/\bdelete\s+\w+/i', 'severity' => 85, 'name' => 'JavaScript delete'],
        ['pattern' => '/\btypeof\s+\w+/i', 'severity' => 70, 'name' => 'JavaScript typeof'],
        ['pattern' => '/\binstanceof\s+\w+/i', 'severity' => 70, 'name' => 'JavaScript instanceof'],
        ['pattern' => '/\bconstructor\s*[\[.]/i', 'severity' => 95, 'name' => 'JavaScript constructor access'],
        ['pattern' => '/\bprototype\s*\./i', 'severity' => 90, 'name' => 'JavaScript prototype access'],
        ['pattern' => '/\b__proto__\b/i', 'severity' => 95, 'name' => 'JavaScript __proto__'],
        ['pattern' => '/\b__defineGetter__\b/i', 'severity' => 95, 'name' => 'JavaScript defineGetter'],
        ['pattern' => '/\b__defineSetter__\b/i', 'severity' => 95, 'name' => 'JavaScript defineSetter'],
        ['pattern' => '/\b__lookupGetter__\b/i', 'severity' => 95, 'name' => 'JavaScript lookupGetter'],
        ['pattern' => '/\b__lookupSetter__\b/i', 'severity' => 95, 'name' => 'JavaScript lookupSetter'],
        ['pattern' => '/\b__hasOwnProperty__\b/i', 'severity' => 90, 'name' => 'JavaScript hasOwnProperty'],
        ['pattern' => '/\b__isPrototypeOf__\b/i', 'severity' => 90, 'name' => 'JavaScript isPrototypeOf'],
        ['pattern' => '/\b__propertyIsEnumerable__\b/i', 'severity' => 90, 'name' => 'JavaScript propertyIsEnumerable'],
        ['pattern' => '/\b__toLocaleString__\b/i', 'severity' => 90, 'name' => 'JavaScript toLocaleString'],
        ['pattern' => '/\b__toString__\b/i', 'severity' => 90, 'name' => 'JavaScript toString'],
        ['pattern' => '/\b__valueOf__\b/i', 'severity' => 90, 'name' => 'JavaScript valueOf'],
    ];

    public static function check() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            $result = self::analyzeValue($key, $value);
            if ($result['is_attack']) {
                waf_block('NoSQL injection detected - ' . $result['reason']);
            }
        }
    }

    private static function collectInputs() {
        $inputs = [];

        foreach ($_GET as $k => $v) {
            if (is_array($v)) {
                // 检查数组键是否含 MongoDB 操作符，保留结构以供后续检测
                $serialized = json_encode($v);
                $inputs[strtolower($k)] = $serialized;
            } else {
                $inputs[strtolower($k)] = (string)$v;
            }
        }
        foreach ($_POST as $k => $v) {
            if (is_array($v)) {
                $serialized = json_encode($v);
                $inputs[strtolower($k)] = $serialized;
            } else {
                $inputs[strtolower($k)] = (string)$v;
            }
        }

        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
        if (!empty($body)) {
            $inputs['body'] = $body;

            $json = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
                self::extractJsonValues($json, $inputs);
            }
        }

        return $inputs;
    }

    private static function extractJsonValues($data, &$inputs, $prefix = '') {
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                $key = $prefix . (($prefix === '' || $prefix === null) ? '' : '.') . $k;
                if (is_array($v) || is_object($v)) {
                    self::extractJsonValues($v, $inputs, $key);
                } else {
                    $inputs[strtolower($key)] = (string)$v;
                }
            }
        }
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);
        $lowerValue = strtolower($value);

        if (empty($value)) {
            return ['is_attack' => false, 'reason' => ''];
        }

        if (in_array($key, self::$nosqlParamNames)) {
            foreach (self::$dangerPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    return ['is_attack' => true, 'reason' => $pattern['name']];
                }
            }

            foreach (self::$mongoOperators as $op) {
                if (strpos($lowerValue, '"' . $op . '"') !== false ||
                    strpos($lowerValue, "'" . $op . "'") !== false ||
                    strpos($lowerValue, '\\' . $op . '\\') !== false) {
                    return ['is_attack' => true, 'reason' => "MongoDB operator: $op"];
                }
            }

            if (preg_match('/\{\s*\$[\w]+\s*:/', $value)) {
                return ['is_attack' => true, 'reason' => 'MongoDB operator injection pattern'];
            }

            if (preg_match('/\b(this\.\w+)/i', $value)) {
                return ['is_attack' => true, 'reason' => 'MongoDB this reference'];
            }

            if (preg_match('/\b(function\s*\(\s*\)\s*\{)/', $value)) {
                // 仅在与 this. 或 $where 同时出现时才视为注入，避免误报合法 JS 代码
                if (preg_match('/\$where/i', $value) || preg_match('/\bthis\.\w+/i', $value)) {
                    return ['is_attack' => true, 'reason' => 'JavaScript function injection'];
                }
            }
        }

        return ['is_attack' => false, 'reason' => ''];
    }
}
