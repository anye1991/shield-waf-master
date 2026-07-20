<?php
defined('ABSPATH') || exit;

class LdapInjection {
    private static $wildcardPatterns = [
        ['pattern' => '/\*\)\s*\(/i', 'severity' => 90, 'name' => 'LDAP wildcard injection *)(', 'category' => 'wildcard'],
        ['pattern' => '/\*\)\s*\(\s*uid\s*=\s*\*/i', 'severity' => 95, 'name' => 'LDAP uid wildcard injection', 'category' => 'wildcard'],
        ['pattern' => '/admin\s*\)\s*\(\s*password\s*=\s*\*/i', 'severity' => 95, 'name' => 'LDAP admin password bypass', 'category' => 'wildcard'],
        ['pattern' => '/\|\s*\(\s*uid\s*=\s*\*\s*\)\s*\(\s*userPassword\s*=\s*\*/i', 'severity' => 95, 'name' => 'LDAP OR filter password disclosure', 'category' => 'wildcard'],
        ['pattern' => '/\*\)\s*\|\s*\(\s*uid\s*=\s*\*/i', 'severity' => 90, 'name' => 'LDAP blind injection pattern', 'category' => 'blind'],
    ];

    private static $operatorPatterns = [
        ['pattern' => '/\(\s*\|/i', 'severity' => 70, 'name' => 'LDAP OR operator (|', 'category' => 'operator'],
        ['pattern' => '/\(\s*&/i', 'severity' => 65, 'name' => 'LDAP AND operator (&', 'category' => 'operator'],
        ['pattern' => '/\(\s*!/i', 'severity' => 60, 'name' => 'LDAP NOT operator (!', 'category' => 'operator'],
        // 要求 )( 后跟 LDAP 属性名（uid/cn/objectClass 等），避免与 SQL/数学表达式冲突
        ['pattern' => '/\)\s*\(\s*(uid|cn|sn|dn|dc|ou|objectClass|memberUid|mail|userPassword)\s*=/i', 'severity' => 55, 'name' => 'LDAP filter concatenation )(attr=', 'category' => 'operator'],
    ];

    private static $attributePatterns = [
        ['pattern' => '/objectClass\s*=\s*\*/i', 'severity' => 75, 'name' => 'LDAP objectClass wildcard', 'category' => 'attribute'],
        ['pattern' => '/ou\s*=\s*\*/i', 'severity' => 65, 'name' => 'LDAP ou wildcard', 'category' => 'attribute'],
        ['pattern' => '/dc\s*=\s*\*/i', 'severity' => 65, 'name' => 'LDAP dc wildcard', 'category' => 'attribute'],
        ['pattern' => '/cn\s*=\s*\*/i', 'severity' => 60, 'name' => 'LDAP cn wildcard', 'category' => 'attribute'],
        ['pattern' => '/sn\s*=\s*\*/i', 'severity' => 55, 'name' => 'LDAP sn wildcard', 'category' => 'attribute'],
        ['pattern' => '/uid\s*=\s*\*/i', 'severity' => 70, 'name' => 'LDAP uid wildcard', 'category' => 'attribute'],
    ];

    private static $ldapParamNames = [
        'username', 'user', 'email', 'login', 'dn', 'distinguishedname',
        'uid', 'cn', 'sn', 'ou', 'dc', 'filter', 'ldapfilter',
        'search', 'query', 'q', 'attribute', 'attr', 'base',
        'bind',
    ];

    // 缓存的合并大正则（首次使用时构建），覆盖全部 wildcard/operator/attribute patterns
    private static $combinedLdapPattern = null;

    /**
     * 把全部 3 类 patterns 合并为单个 alternation 大正则。
     * 原 patterns 全部带 /i，统一加 /i 不改变大小写行为。
     */
    private static function getCombinedPattern() {
        if (self::$combinedLdapPattern !== null) {
            return self::$combinedLdapPattern;
        }
        $parts = [];
        foreach (self::$wildcardPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$operatorPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$attributePatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        self::$combinedLdapPattern = '/' . implode('|', $parts) . '/i';
        return self::$combinedLdapPattern;
    }

    /**
     * 解析 /body/flags 形式的正则，仅取 body 部分。避免 trim($p, '/') 把
     * 带 /i 后缀的 pattern 末尾 'i' 残留进 body，导致合并大正则出现裸 '/'。
     */
    private static function patternBody($pattern) {
        $lastSlash = strrpos($pattern, '/');
        if ($lastSlash === false || $lastSlash === 0) {
            return substr($pattern, 1);
        }
        return substr($pattern, 1, $lastSlash - 1);
    }

    public static function detect($inputs) {
        $score = 0;
        $details = [];
        $detected = false;

        if (!is_array($inputs) || empty($inputs)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($inputs as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $result = self::analyzeValue((string)$key, (string)$v);
                    if ($result['score'] > 0) {
                        $score = max($score, $result['score']);
                        $details[] = $result;
                        if ($result['detected']) {
                            $detected = true;
                        }
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

        if (empty($value)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        // 长度上限：超过 8KB 只扫前 8KB
        if (strlen($value) > 8192) {
            $value = substr($value, 0, 8192);
        }

        $isLdapParam = in_array($lowerKey, self::$ldapParamNames);
        $paramMultiplier = $isLdapParam ? 1.0 : 0.6;

        // 廉价预筛：所有 3 类 patterns 都至少需要以下字符之一才可能命中
        //   wildcardPatterns:   '*' (LDAP 通配符)
        //   operatorPatterns:   '(' ')' (LDAP filter 操作符 | & ! 等)
        //   attributePatterns:   '*' (objectClass=* 等)
        // 后续 filter-like / unescaped parens 检查同样依赖 '(' 或 ')'
        if (strpos($value, '(') !== false
            || strpos($value, ')') !== false
            || strpos($value, '*') !== false) {

            // 合并大正则做一次廉价筛除：未命中则跳过 3 类逐条匹配
            if (preg_match(self::getCombinedPattern(), $value)) {
                foreach (self::$wildcardPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }

                foreach (self::$operatorPatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }

                foreach (self::$attributePatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        $adjustedScore = (int)($pattern['severity'] * $paramMultiplier);
                        $score = max($score, $adjustedScore);
                        $findings[] = $pattern['name'];
                    }
                }
            }

            // filter-like 结构检查（依然需要预筛通过才执行）
            if (preg_match('/^\s*\(/', $value) && preg_match('/\)\s*$/', $value)) {
                $parenScore = (int)(40 * $paramMultiplier);
                $score = max($score, $parenScore);
                $findings[] = 'LDAP filter-like structure';
            }

            $unescapedParens = 0;
            $len = strlen($value);
            for ($i = 0; $i < $len; $i++) {
                if ($value[$i] === '(' || $value[$i] === ')') {
                    // 统计前置连续反斜杠数量，奇数才视为已转义
                    $bs = 0;
                    $j = $i - 1;
                    while ($j >= 0 && $value[$j] === '\\') { $bs++; $j--; }
                    $isEscaped = ($bs % 2 === 1);
                    if (!$isEscaped) {
                        $unescapedParens++;
                    }
                }
            }
            if ($unescapedParens >= 4) {
                $parenScore = (int)(35 * $paramMultiplier);
                $score = max($score, $parenScore);
                $findings[] = 'Multiple unescaped parentheses';
            }
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_ldap_param' => $isLdapParam,
        ];
    }
}
