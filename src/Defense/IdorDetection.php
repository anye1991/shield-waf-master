<?php
defined('ABSPATH') || exit;

class IdorDetection {
    private static $numericIdPatterns = [
        ['pattern' => '/^uid$/i', 'severity' => 40, 'name' => 'uid parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^user[_-]?id$/i', 'severity' => 45, 'name' => 'user_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^account[_-]?id$/i', 'severity' => 50, 'name' => 'account_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^order[_-]?id$/i', 'severity' => 55, 'name' => 'order_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^record[_-]?id$/i', 'severity' => 40, 'name' => 'record_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^post[_-]?id$/i', 'severity' => 40, 'name' => 'post_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^id$/i', 'severity' => 35, 'name' => 'Generic id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^product[_-]?id$/i', 'severity' => 40, 'name' => 'product_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^comment[_-]?id$/i', 'severity' => 35, 'name' => 'comment_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^message[_-]?id$/i', 'severity' => 40, 'name' => 'message_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^file[_-]?id$/i', 'severity' => 45, 'name' => 'file_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^doc(ument)?[_-]?id$/i', 'severity' => 45, 'name' => 'document_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^transaction[_-]?id$/i', 'severity' => 55, 'name' => 'transaction_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^payment[_-]?id$/i', 'severity' => 55, 'name' => 'payment_id parameter', 'category' => 'numeric_id'],
        ['pattern' => '/^invoice[_-]?id$/i', 'severity' => 50, 'name' => 'invoice_id parameter', 'category' => 'numeric_id'],
    ];

    private static $batchParamPatterns = [
        ['pattern' => '/^ids?$/i', 'severity' => 60, 'name' => 'Batch IDs parameter', 'category' => 'batch'],
        ['pattern' => '/^user[_-]?ids?$/i', 'severity' => 65, 'name' => 'Batch user IDs', 'category' => 'batch'],
        ['pattern' => '/^order[_-]?ids?$/i', 'severity' => 70, 'name' => 'Batch order IDs', 'category' => 'batch'],
        ['pattern' => '/^product[_-]?ids?$/i', 'severity' => 60, 'name' => 'Batch product IDs', 'category' => 'batch'],
        ['pattern' => '/selected[_-]?ids?/i', 'severity' => 55, 'name' => 'Selected IDs batch', 'category' => 'batch'],
        ['pattern' => '/bulk[_-]?ids?/i', 'severity' => 65, 'name' => 'Bulk IDs parameter', 'category' => 'batch'],
    ];

    private static $bypassPatterns = [
        ['pattern' => '/^-1$/', 'severity' => 75, 'name' => 'Negative ID bypass (id=-1)', 'category' => 'bypass'],
        ['pattern' => '/^0$/', 'severity' => 55, 'name' => 'Zero ID (id=0)', 'category' => 'bypass'],
        ['pattern' => '/^-?\d+$/', 'severity' => 10, 'name' => 'Numeric ID value', 'category' => 'bypass'],
        ['pattern' => '/^null$/i', 'severity' => 50, 'name' => 'Null value', 'category' => 'bypass'],
        ['pattern' => '/^true$/i', 'severity' => 45, 'name' => 'Boolean true value', 'category' => 'bypass'],
        ['pattern' => '/^false$/i', 'severity' => 40, 'name' => 'Boolean false value', 'category' => 'bypass'],
    ];

    private static $typeConfusionPatterns = [
        ['pattern' => '/^\d+\[\]$/', 'severity' => 65, 'name' => 'Type confusion: id[]=1', 'category' => 'type_confusion'],
        ['pattern' => '/^\d+\[\d+\]$/', 'severity' => 60, 'name' => 'Type confusion: id[0]=1', 'category' => 'type_confusion'],
        ['pattern' => '/\[.*\[.*\].*\]/', 'severity' => 55, 'name' => 'Nested array structure', 'category' => 'type_confusion'],
    ];

    private static $sensitiveEndpoints = [
        '/user', '/profile', '/account', '/order', '/payment',
        '/transaction', '/invoice', '/admin', '/api/user',
        '/api/order', '/api/payment', '/api/account',
    ];

    // 缓存 isSensitiveEndpoint() 的结果。
    // 一次请求内 $_SERVER['REQUEST_URI'] 不变，避免每个 ID 参数都重算一遍。
    private static $sensitiveEndpointCache = null;

    public static function detect($inputs) {
        $score = 0;
        $details = [];
        $detected = false;

        if (!is_array($inputs) || empty($inputs)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($inputs as $key => $value) {
            if (is_array($value)) {
                $arrResult = self::analyzeArrayParam((string)$key, $value);
                if ($arrResult['score'] > 0) {
                    $score = max($score, $arrResult['score']);
                    $details[] = $arrResult;
                    if ($arrResult['detected']) {
                        $detected = true;
                    }
                }
            } else {
                $result = self::analyzeValue((string)$key, (string)$value);
                if ($result['score'] > 0) {
                    $score = max($score, $result['score']);
                    $details[] = $result;
                    if ($result['detected']) {
                        $detected = true;
                    }
                }
            }
        }

        $consecutiveResult = self::checkConsecutiveIds($inputs);
        if ($consecutiveResult['score'] > 0) {
            $score = max($score, $consecutiveResult['score']);
            $details[] = $consecutiveResult;
            if ($consecutiveResult['detected']) {
                $detected = true;
            }
        }

        return [
            'detected' => $detected,
            'score' => min($score, 100),
            'details' => $details,
        ];
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);
        $lowerKey = strtolower($key);
        $score = 0;
        $findings = [];

        if (empty($value) && $value !== '0') {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        $hasNumericIdParam = false;
        // 廉价预筛：所有 numericIdPatterns 都包含 'id' 字符串
        // (uid/user_id/account_id/order_id/.../id 等)，未含 'id' 的 key 直接跳过
        if (strpos($lowerKey, 'id') !== false) {
            foreach (self::$numericIdPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $key)) {
                    $hasNumericIdParam = true;
                    $score = max($score, $pattern['severity']);
                    $findings[] = $pattern['name'];
                    break;
                }
            }
        }

        if ($hasNumericIdParam) {
            foreach (self::$bypassPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $bypassScore = $pattern['severity'];
                    if ($bypassScore > $score) {
                        $score = $bypassScore;
                    }
                    $findings[] = $pattern['name'];
                }
            }
        }

        $isSensitiveEndpoint = self::isSensitiveEndpoint();
        if ($hasNumericIdParam && $isSensitiveEndpoint) {
            $endpointScore = (int)($score * 1.3);
            if ($endpointScore > $score) {
                $score = min($endpointScore, 100);
            }
            $findings[] = 'ID parameter on sensitive endpoint';
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'value' => $value,
            'is_numeric_id_param' => $hasNumericIdParam,
        ];
    }

    private static function analyzeArrayParam($key, $value) {
        $lowerKey = strtolower($key);
        $score = 0;
        $findings = [];

        // 廉价预筛：所有 batchParamPatterns 都包含 'id' 字符串
        // (ids/user_ids/order_ids/.../bulk_ids 等)，未含 'id' 的 key 直接跳过
        if (strpos($lowerKey, 'id') !== false) {
            foreach (self::$batchParamPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $key)) {
                    $score = max($score, $pattern['severity']);
                    $findings[] = $pattern['name'];
                }
            }
        }

        // isIdParam 匹配的也是 'id' 子串，预筛安全
        $isIdParam = (strpos($lowerKey, 'id') !== false)
            && preg_match('/(^|[_-])id($|[_-])/i', $key) === 1;
        if ($isIdParam && is_array($value) && count($value) > 3) {
            $arrayScore = 55;
            if ($score < $arrayScore) {
                $score = $arrayScore;
            }
            $findings[] = 'Array-style ID parameter';
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'array_count' => is_array($value) ? count($value) : 0,
            'is_batch' => true,
        ];
    }

    private static function checkConsecutiveIds($inputs) {
        $findings = [];
        $score = 0;
        $idValues = [];

        foreach ($inputs as $key => $value) {
            $lowerKey = strtolower((string)$key);
            if (preg_match('/id$/', $lowerKey) && !is_array($value)) {
                if (is_numeric($value)) {
                    $idValues[] = (int)$value;
                }
            }
        }

        if (count($idValues) < 2) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'check' => 'consecutive_ids'];
        }

        sort($idValues, SORT_NUMERIC);
        $consecutiveCount = 1;
        $maxConsecutive = 1;

        for ($i = 1; $i < count($idValues); $i++) {
            if ($idValues[$i] == $idValues[$i - 1] + 1) {
                $consecutiveCount++;
                $maxConsecutive = max($maxConsecutive, $consecutiveCount);
            } else {
                $consecutiveCount = 1;
            }
        }

        if ($maxConsecutive >= 5) {
            $score = 70;
            $findings[] = "Highly consecutive IDs detected ($maxConsecutive in sequence)";
        } elseif ($maxConsecutive >= 3) {
            $score = 45;
            $findings[] = "Consecutive IDs detected ($maxConsecutive in sequence)";
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'consecutive_ids',
            'consecutive_count' => $maxConsecutive,
        ];
    }

    private static function isSensitiveEndpoint() {
        // 一次请求内 $_SERVER['REQUEST_URI'] 不变，结果缓存避免重复 parse_url + 遍历
        if (self::$sensitiveEndpointCache !== null) {
            return self::$sensitiveEndpointCache;
        }
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = parse_url($uri, PHP_URL_PATH);
        if ($path === false || $path === null) {
            $path = $uri;
        }
        $path = strtolower($path);

        $result = false;
        foreach (self::$sensitiveEndpoints as $endpoint) {
            // 精确匹配或路径段前缀匹配（避免 /admin 匹配 /administrator）
            if ($path === $endpoint) {
                $result = true;
                break;
            }
            if (strpos($path, $endpoint . '/') === 0) {
                $result = true;
                break;
            }
            if (strpos($path, $endpoint . '?') === 0) {
                $result = true;
                break;
            }
        }
        self::$sensitiveEndpointCache = $result;
        return self::$sensitiveEndpointCache;
    }
}
