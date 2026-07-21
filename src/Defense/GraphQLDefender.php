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
        // 使用状态机跳过 GraphQL 字符串字面量内的 '{' '}'：
        //   - "..."  普通字符串，\" 转义
        //   - """..."""  Block String，""" 转义（按 GraphQL spec 必须三连引号边界）
        // 避免如下 payload 利用字符串内花括号绕过深度限制：
        //   { user(name: "a{b}c{d}e{f}g{h}i{j}k{l}m") { id } }
        $depth = 0;
        $maxDepth = 0;
        $bodyLen = strlen($body);
        $inString = false;       // 是否在普通字符串中
        $inBlockString = false;  // 是否在 Block String 中
        $i = 0;
        while ($i < $bodyLen) {
            $ch = $body[$i];
            if ($inBlockString) {
                // Block String: 检测 """ 边界（前面可有奇数个 \ 表示转义）
                if ($ch === '\\' && $i + 2 < $bodyLen
                    && $body[$i + 1] === '"' && $body[$i + 2] === '"' && $body[$i + 3] === '"') {
                    // 转义的 """，跳过这 4 个字符
                    $i += 4;
                    continue;
                }
                if ($ch === '"' && $i + 2 < $bodyLen
                    && $body[$i + 1] === '"' && $body[$i + 2] === '"') {
                    // 结束 Block String
                    $inBlockString = false;
                    $i += 3;
                    continue;
                }
                $i++;
                continue;
            }
            if ($inString) {
                if ($ch === '\\' && $i + 1 < $bodyLen) {
                    // 转义任意字符（含 \" \\ \n 等）
                    $i += 2;
                    continue;
                }
                if ($ch === '"') {
                    $inString = false;
                    $i++;
                    continue;
                }
                $i++;
                continue;
            }
            // 状态：不在字符串中
            // 检查 Block String 起始 """
            if ($ch === '"' && $i + 2 < $bodyLen
                && $body[$i + 1] === '"' && $body[$i + 2] === '"') {
                $inBlockString = true;
                $i += 3;
                continue;
            }
            // 检查普通字符串起始 "
            if ($ch === '"') {
                $inString = true;
                $i++;
                continue;
            }
            // GraphQL 注释 # ... 行尾
            if ($ch === '#') {
                $nl = strpos($body, "\n", $i);
                if ($nl === false) {
                    break;
                }
                $i = $nl + 1;
                continue;
            }
            if ($ch === '{') {
                $depth++;
                if ($depth > $maxDepth) $maxDepth = $depth;
            } elseif ($ch === '}') {
                if ($depth > 0) {
                    $depth--;
                }
            }
            $i++;
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