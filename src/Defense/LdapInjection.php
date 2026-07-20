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

        $isLdapParam = in_array($lowerKey, self::$ldapParamNames);
        $paramMultiplier = $isLdapParam ? 1.0 : 0.6;

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

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_ldap_param' => $isLdapParam,
        ];
    }
}
