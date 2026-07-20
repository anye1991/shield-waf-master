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

    // 缓存的合并 Mongo 操作符匹配大正则（首次使用时构建）
    // 替代原来 100 操作符 × 3 strpos = 300 次 strpos 循环
    private static $mongoOpPattern = null;

    /**
     * 构建一个合并大正则，一次匹配所有 MongoDB 操作符的注入形式。
     * 覆盖原 strpos 检查的三种形式：
     *   1. "$op"  (双引号包裹)
     *   2. '$op'  (单引号包裹)
     *   3. \$op\  (反斜杠转义形式)
     * 使用 /i 修饰符，与原代码 strtolower($value) 行为一致。
     */
    private static function getMongoOpPattern() {
        if (self::$mongoOpPattern !== null) {
            return self::$mongoOpPattern;
        }
        $opNames = [];
        foreach (self::$mongoOperators as $op) {
            // $op 形如 '$gt'，去掉前导 $，再 preg_quote 转义正则元字符
            $opNames[] = preg_quote(substr($op, 1), '/');
        }
        $alt = implode('|', $opNames);

        // 用 preg_quote 避免反斜杠转义混乱
        $q = '["\']';                  // 任一引号
        $bs = preg_quote('\\', '/');   // 字面反斜杠
        $d = preg_quote('$', '/');     // 字面美元符

        // 1) "$op" 或 '$op'  : ["']\$op["']
        // 2) \$op\            : \\\$op\\
        $quotedForm = $q . $d . '(?:' . $alt . ')' . $q;
        $backslashForm = $bs . $d . '(?:' . $alt . ')' . $bs;
        self::$mongoOpPattern = '/(?:' . $quotedForm . '|' . $backslashForm . ')/i';
        return self::$mongoOpPattern;
    }

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

        // 长度上限：超过 8KB 只扫前 8KB
        if (strlen($value) > 8192) {
            $value = substr($value, 0, 8192);
            // 重新计算 lowerValue 保持一致
            $lowerValue = strtolower($value);
        }

        if (in_array($key, self::$nosqlParamNames)) {
            foreach (self::$dangerPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    return ['is_attack' => true, 'reason' => $pattern['name']];
                }
            }

            // 合并大正则做一次廉价筛除：未命中则跳过 100 操作符 × 3 strpos 循环
            if (preg_match(self::getMongoOpPattern(), $value)) {
                // 大正则命中后，逐条 strpos 还原具体操作符名称（保留 reason 细节）
                foreach (self::$mongoOperators as $op) {
                    if (strpos($lowerValue, '"' . $op . '"') !== false ||
                        strpos($lowerValue, "'" . $op . "'") !== false ||
                        strpos($lowerValue, '\\' . $op . '\\') !== false) {
                        return ['is_attack' => true, 'reason' => "MongoDB operator: $op"];
                    }
                }
                // 大正则命中但 strpos 未命中（极少见，可能因大小写或边界差异），兜底告警
                return ['is_attack' => true, 'reason' => 'MongoDB operator'];
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
