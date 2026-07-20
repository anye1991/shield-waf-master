<?php
defined('ABSPATH') || exit;

class Deserialization {
    private static $phpSerializationPatterns = [
        ['pattern' => '/O:\d+:"/', 'severity' => 90, 'name' => 'PHP object serialization O:', 'category' => 'php_ser'],
        ['pattern' => '/a:\d+:\{/', 'severity' => 80, 'name' => 'PHP array serialization a:', 'category' => 'php_ser'],
        ['pattern' => '/s:\d+:"/', 'severity' => 60, 'name' => 'PHP string serialization s:', 'category' => 'php_ser'],
        ['pattern' => '/__PHP_Incomplete_Class/i', 'severity' => 95, 'name' => 'PHP incomplete class marker', 'category' => 'php_ser'],
        // 要求前导上下文为字符串起始或 } 后续，避免匹配任意 i:N; 文本
        ['pattern' => '/(?:^|})i:\d+;/', 'severity' => 40, 'name' => 'PHP integer serialization i:', 'category' => 'php_ser'],
        ['pattern' => '/(?:^|})b:[01];/', 'severity' => 35, 'name' => 'PHP boolean serialization b:', 'category' => 'php_ser'],
        ['pattern' => '/(?:^|})d:[\d.eE+-]+;/', 'severity' => 45, 'name' => 'PHP double serialization d:', 'category' => 'php_ser'],
        ['pattern' => '/(?:^|})N;/', 'severity' => 30, 'name' => 'PHP null serialization N;', 'category' => 'php_ser'],
        // 检测 PHP 序列化中自定义类名前缀 C: (Serializable 接口)
        ['pattern' => '/C:\d+:"/', 'severity' => 80, 'name' => 'PHP serializable C:', 'category' => 'php_ser'],
    ];

    private static $magicMethodPatterns = [
        ['pattern' => '/__wakeup/i', 'severity' => 95, 'name' => 'PHP __wakeup magic method', 'category' => 'magic'],
        ['pattern' => '/__destruct/i', 'severity' => 90, 'name' => 'PHP __destruct magic method', 'category' => 'magic'],
        ['pattern' => '/__toString/i', 'severity' => 80, 'name' => 'PHP __toString magic method', 'category' => 'magic'],
        ['pattern' => '/__invoke/i', 'severity' => 85, 'name' => 'PHP __invoke magic method', 'category' => 'magic'],
        ['pattern' => '/__call/i', 'severity' => 80, 'name' => 'PHP __call magic method', 'category' => 'magic'],
        ['pattern' => '/__callStatic/i', 'severity' => 75, 'name' => 'PHP __callStatic magic method', 'category' => 'magic'],
        ['pattern' => '/__get/i', 'severity' => 70, 'name' => 'PHP __get magic method', 'category' => 'magic'],
        ['pattern' => '/__set/i', 'severity' => 70, 'name' => 'PHP __set magic method', 'category' => 'magic'],
        ['pattern' => '/__isset/i', 'severity' => 65, 'name' => 'PHP __isset magic method', 'category' => 'magic'],
        ['pattern' => '/__unset/i', 'severity' => 65, 'name' => 'PHP __unset magic method', 'category' => 'magic'],
        // __autoload 在 PHP 8.0 已移除，降低 severity
        ['pattern' => '/__autoload/i', 'severity' => 20, 'name' => 'PHP __autoload magic method', 'category' => 'magic'],
        ['pattern' => '/__construct/i', 'severity' => 60, 'name' => 'PHP __construct magic method', 'category' => 'magic'],
        ['pattern' => '/__sleep/i', 'severity' => 75, 'name' => 'PHP __sleep magic method', 'category' => 'magic'],
    ];

    private static $javaPatterns = [
        ['pattern' => '/^rO0AB/', 'severity' => 95, 'name' => 'Java serialized object (Base64)', 'category' => 'java'],
        ['pattern' => '/\xAC\xED\x00\x05/', 'severity' => 95, 'name' => 'Java serialized object (raw)', 'category' => 'java'],
    ];

    private static $ysoserialPatterns = [
        ['pattern' => '/CommonsCollections/i', 'severity' => 95, 'name' => 'ysoserial CommonsCollections payload', 'category' => 'ysoserial'],
        ['pattern' => '/Jdk7u21/i', 'severity' => 95, 'name' => 'ysoserial Jdk7u21 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Spring1/i', 'severity' => 90, 'name' => 'ysoserial Spring1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Groovy1/i', 'severity' => 90, 'name' => 'ysoserial Groovy1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/BeanShell1/i', 'severity' => 90, 'name' => 'ysoserial BeanShell1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Clojure/i', 'severity' => 85, 'name' => 'ysoserial Clojure payload', 'category' => 'ysoserial'],
        ['pattern' => '/JRMP/i', 'severity' => 85, 'name' => 'ysoserial JRMP payload', 'category' => 'ysoserial'],
        ['pattern' => '/JSON1/i', 'severity' => 85, 'name' => 'ysoserial JSON1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Jython1/i', 'severity' => 85, 'name' => 'ysoserial Jython1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/MozillaRhino1/i', 'severity' => 85, 'name' => 'ysoserial MozillaRhino1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Myfaces1/i', 'severity' => 85, 'name' => 'ysoserial Myfaces1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/ROME/i', 'severity' => 85, 'name' => 'ysoserial ROME payload', 'category' => 'ysoserial'],
        ['pattern' => '/Spring2/i', 'severity' => 85, 'name' => 'ysoserial Spring2 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Vaadin1/i', 'severity' => 85, 'name' => 'ysoserial Vaadin1 payload', 'category' => 'ysoserial'],
        ['pattern' => '/Wicket1/i', 'severity' => 85, 'name' => 'ysoserial Wicket1 payload', 'category' => 'ysoserial'],
    ];

    private static $pharPatterns = [
        ['pattern' => '/phar:\/\//i', 'severity' => 90, 'name' => 'PHP phar:// wrapper', 'category' => 'phar'],
        ['pattern' => '/__HALT_COMPILER/i', 'severity' => 80, 'name' => 'PHP __HALT_COMPILER', 'category' => 'phar'],
    ];

    private static $deserParamNames = [
        'data', 'payload', 'body', 'content', 'input',
        'serialized', 'object', 'cache', 'session',
        'file', 'path', 'src', 'source', 'template',
        'cookie', 'token', 'state', 'viewstate',
    ];

    public static function detect($inputs, $rawBody) {
        $score = 0;
        $details = [];
        $detected = false;

        $allTargets = [];

        if (!empty($rawBody)) {
            $allTargets['raw_body'] = $rawBody;
        }

        if (is_array($inputs)) {
            foreach ($inputs as $key => $value) {
                if (is_array($value)) {
                    foreach ($value as $v) {
                        $allTargets[$key . '[]'] = (string)$v;
                    }
                } else {
                    $allTargets[$key] = (string)$value;
                }
            }
        }

        if (empty($allTargets)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($allTargets as $key => $value) {
            $result = self::analyzeValue((string)$key, (string)$value);
            if ($result['score'] > 0) {
                $score = max($score, $result['score']);
                $details[] = $result;
                if ($result['detected']) {
                    $detected = true;
                }
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
        $lowerValue = strtolower($value);
        $score = 0;
        $findings = [];

        if (empty($value)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        // 长度上限：超过 8KB 只扫前 8KB
        if (strlen($value) > 8192) {
            $value = substr($value, 0, 8192);
            $lowerValue = strtolower($value);
        }

        $isDeserParam = in_array($lowerKey, self::$deserParamNames);
        $paramMultiplier = $isDeserParam ? 1.0 : 0.6;

        // 廉价预筛：所有 deser patterns 都至少需要以下指示符之一才可能命中
        //   phpSerializationPatterns: ':' (O:/a:/s:/i:/b:/d:/C:) 或 '__' (__PHP_Incomplete_Class) 或 'N;'
        //   magicMethodPatterns:     '__' (所有 __XXX 魔术方法)
        //   javaPatterns:            'rO0AB' 或 \xAC\xED
        //   ysoserialPatterns:       'O:' / \xAC\xED / rO0AB (需 hasObjectContext)
        //   pharPatterns:            ':' (phar://) 或 '__' (__HALT_COMPILER)
        // 若均不含，跳过所有正则
        if (strpos($value, ':') !== false
            || strpos($value, '__') !== false
            || strpos($value, 'rO0AB') !== false
            || strpos($value, "\xAC\xED") !== false
            || strpos($value, 'N;') !== false) {

            foreach (self::$phpSerializationPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }

            foreach (self::$magicMethodPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }

            foreach (self::$javaPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $score = max($score, $pattern['severity']);
                    $findings[] = $pattern['name'];
                }
            }

            // ysoserial 仅在含对象上下文 (O: 或 \xAC\xED 或 rO0AB) 时才计分
            $hasObjectContext = strpos($value, 'O:') !== false
                || strpos($value, "\xAC\xED") !== false
                || strpos($value, "rO0AB") === 0;
            if ($hasObjectContext) {
                foreach (self::$ysoserialPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }
            }

            foreach (self::$pharPatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                    $score = max($score, $adjustedScore);
                    $findings[] = $pattern['name'];
                }
            }

            // 组合检测：PHP 对象 + 魔术方法
            if (strpos($value, 'O:') !== false && strpos($value, '__') !== false) {
                if (preg_match('/O:\d+:"/', $value) && preg_match('/__wakeup|__destruct/i', $value)) {
                    $comboScore = 98;
                    if ($score < $comboScore) {
                        $score = $comboScore;
                        $findings[] = 'PHP object + magic method combination';
                    }
                }
            }
        }

        // base64 解码预筛：只在 value 看起来像 base64 (长度 >20 且仅含 base64 字符) 时才解码
        // 避免 base64_decode 在每个 value 上调用（包括非 base64 的普通字符串）
        if (strlen($value) > 20) {
            $trimmedForCheck = trim($value);
            if (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $trimmedForCheck)) {
                $decoded = base64_decode($value, true);
                if ($decoded !== false && strlen($decoded) > 4) {
                    // 解码后内容用 strpos 预筛：只在含 \xAC\xED 或 O: 或 a: 时才进一步检测
                    if (strpos($decoded, "\xAC\xED") !== false
                        || strpos($decoded, 'O:') !== false
                        || strpos($decoded, 'a:') !== false) {
                        if (strpos($decoded, "\xAC\xED\x00\x05") === 0) {
                            $score = max($score, 95);
                            $findings[] = 'Java serialized object (Base64 decoded)';
                        }
                        if (preg_match('/O:\d+:"/', $decoded) || preg_match('/a:\d+:\{/', $decoded)) {
                            $adjustedScore = (int)(85 * $paramMultiplier);
                            $score = max($score, $adjustedScore);
                            $findings[] = 'PHP serialized data (Base64 decoded)';
                        }
                    }
                }
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_deser_param' => $isDeserParam,
        ];
    }
}
