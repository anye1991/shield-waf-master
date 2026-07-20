<?php
defined('ABSPATH') || exit;
class GraphQLDefender {
    public static function check() {
        // 使用 parse_url 提取 path 后做后缀匹配，避免误判 /api/notgraphql 等
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = parse_url($uri, PHP_URL_PATH);
        if ($path === false) $path = $uri;
        if (strpos($path, '/graphql') === false) return;

        // 优先使用原始 body，缺失时回退到 GET 参数（GET 也可能携带 query）
        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : '';
        if (empty($body)) {
            $body = isset($_GET['query']) ? $_GET['query'] : '';
        }
        if (empty($body)) return;

        // 计算查询深度（嵌套花括号层数），过深视为 DoS 攻击
        $depth = 0;
        $maxDepth = 0;
        $bodyLen = strlen($body);
        for ($i = 0; $i < $bodyLen; $i++) {
            if ($body[$i] === '{') {
                $depth++;
                if ($depth > $maxDepth) $maxDepth = $depth;
            } elseif ($body[$i] === '}') {
                $depth--;
            }
        }
        if ($maxDepth > 10) {
            waf_block('GraphQL query depth exceeds limit: ' . $maxDepth);
        }

        $patterns = [
            '/\$where\s*:/i',
            '/\$regex\s*:/i',
            '/__schema\b/',
            '/__type\b/',
            '/\bfragment\b.*\bon\s+\w+/i',
        ];
        foreach ($patterns as $p) {
            if (preg_match($p, $body)) waf_block('GraphQL injection detected');
        }
    }
}