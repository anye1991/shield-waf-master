<?php
defined('ABSPATH') || exit;

/**
 * Layer5：业务语义分析层
 *
 * 结合 URL 路由模式与参数组合，识别请求所处的业务场景，
 * 并对业务逻辑一致性进行验证。
 */
class Layer5_BusinessSemantics {

    /**
     * 已知业务路由模式（pattern => scene）
     */
    private static $routePatterns = [
        '/\/login/i'             => 'login',
        '/\/logout/i'            => 'logout',
        '/\/register/i'          => 'register',
        '/\/signup/i'            => 'register',
        '/\/admin/i'             => 'admin',
        '/\/dashboard/i'         => 'dashboard',
        '/\/api\/v\d+/i'         => 'api',
        '/\/api\//i'             => 'api',
        '/\/search/i'            => 'search',
        '/\/upload/i'            => 'upload',
        '/\/download/i'         => 'download',
        '/\/export/i'           => 'export',
        '/\/import/i'           => 'import',
        '/\/user/i'             => 'user',
        '/\/profile/i'          => 'profile',
        '/\/cart/i'             => 'cart',
        '/\/order/i'            => 'order',
        '/\/payment/i'          => 'payment',
        '/\/product/i'          => 'product',
        '/\/article/i'          => 'article',
        '/\/comment/i'          => 'comment',
        '/\/reset[_\/]?password/i' => 'password_reset',
        '/\/forgot[_\/]?password/i' => 'password_reset',
        '/\/captcha/i'          => 'captcha',
        '/\/debug/i'            => 'debug',
        '/\/config/i'           => 'config',
        '/\/backup/i'           => 'backup',
    ];

    /**
     * 业务场景期望的参数集合
     */
    private static $sceneExpectedParams = [
        'login'         => ['username', 'user', 'email', 'password', 'passwd', 'pwd', 'token', 'captcha'],
        'register'      => ['username', 'email', 'password', 'passwd', 'pwd', 'confirm', 'code'],
        'search'        => ['q', 'query', 'keyword', 'search', 'page', 'size', 'sort'],
        'upload'        => ['file', 'files', 'type', 'name'],
        'cart'          => ['id', 'sku', 'qty', 'quantity'],
        'order'         => ['id', 'oid', 'action', 'status'],
        'payment'       => ['amount', 'order_id', 'oid', 'currency', 'method'],
        'password_reset'=> ['token', 'email', 'new_password', 'password'],
    ];

    /**
     * 业务场景下不应出现的参数（出现即为可疑）
     */
    private static $sceneForbiddenPatterns = [
        'login'         => '/(?:union\s+select|<script|eval\s*\(|system\s*\()/i',
        'search'        => '/(?:union\s+select|into\s+outfile|load_file\s*\()/i',
        'upload'        => '/(?:<\?(?:php|=)?|<%|eval\s*\()/i',
        'payment'       => '/(?:union\s+select|<script|eval\s*\()/i',
    ];

    /**
     * 分析业务语义
     *
     * @param string $uri    请求 URI
     * @param array  $params 参数键值对
     * @return array ['score'=>0-100, 'scene'=>'...', 'valid'=>bool, ...]
     */
    public static function analyze(string $uri, array $params = []): array {
        $result = [
            'score'   => 0,
            'scene'   => 'unknown',
            'valid'   => true,
            'uri'     => $uri,
            'findings'=> [],
        ];

        if ($uri === '') {
            return $result;
        }

        $score = 0;

        // 1. URL 路由模式匹配
        $scene = 'unknown';
        foreach (self::$routePatterns as $pattern => $name) {
            if (preg_match($pattern, $uri)) {
                $scene = $name;
                break;
            }
        }
        $result['scene'] = $scene;

        // 2. 业务场景下的参数检查
        if ($scene !== 'unknown') {
            // 检查参数与场景的匹配度
            $expected = self::$sceneExpectedParams[$scene] ?? [];
            if (!empty($expected) && !empty($params)) {
                $provided = array_keys($params);
                $matched = 0;
                $unknown = 0;
                foreach ($provided as $p) {
                    if (in_array(strtolower($p), $expected, true)) {
                        $matched++;
                    } else {
                        $unknown++;
                    }
                }
                // 期望参数完全没有命中，但提供了未期望参数
                if ($matched === 0 && $unknown >= 1) {
                    $score += 12;
                    $result['findings'][] = ['type' => 'param_mismatch', 'desc' => "场景 '{$scene}' 收到非预期参数"];
                }
            }

            // 检查场景禁忌模式
            $forbidden = self::$sceneForbiddenPatterns[$scene] ?? null;
            if ($forbidden) {
                foreach ($params as $key => $value) {
                    if (is_string($value) && preg_match($forbidden, $value)) {
                        $score += 30;
                        $result['findings'][] = [
                            'type' => 'forbidden_payload',
                            'param' => $key,
                            'desc' => "场景 '{$scene}' 参数 '{$key}' 包含禁忌载荷",
                        ];
                    }
                }
            }
        }

        // 3. 敏感场景加分
        $sensitiveScenes = ['admin', 'debug', 'config', 'backup', 'password_reset'];
        if (in_array($scene, $sensitiveScenes, true)) {
            $score += 15;
            $result['findings'][] = ['type' => 'sensitive_scene', 'desc' => "访问敏感场景 '{$scene}'"];
        }

        // 4. URI 中的可疑路径段
        if (preg_match('/\.\.[\/\\\\]/', $uri)) {
            $score += 25;
            $result['findings'][] = ['type' => 'path_traversal', 'desc' => 'URI 中存在路径遍历'];
        }
        if (preg_match('/\/{2,}|\/\.(?:\/|$)/', $uri)) {
            $score += 8;
            $result['findings'][] = ['type' => 'path_anomaly', 'desc' => 'URI 路径异常'];
        }

        // 5. 参数键名异常
        foreach (array_keys($params) as $key) {
            // 超长参数名
            if (strlen($key) > 64) {
                $score += 10;
                $result['findings'][] = ['type' => 'long_param_name', 'param' => substr($key, 0, 16) . '...', 'desc' => '异常超长参数名'];
            }
            // 参数名包含代码字符
            if (preg_match('/[<>\'"$]/', $key)) {
                $score += 20;
                $result['findings'][] = ['type' => 'param_name_injection', 'param' => $key, 'desc' => '参数名包含代码字符'];
            }
        }

        // 6. 业务逻辑验证：参数数量异常
        if (count($params) > 30) {
            $score += 15;
            $result['findings'][] = ['type' => 'param_flood', 'count' => count($params), 'desc' => '参数数量异常（>30）'];
        }

        $score = max(0, min(100, $score));
        $result['score'] = $score;
        $result['valid'] = $score < 30;

        return $result;
    }
}
