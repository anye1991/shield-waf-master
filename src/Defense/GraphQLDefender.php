<?php
defined('ABSPATH') || exit;
class GraphQLDefender {
    public static function check() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($uri, '/graphql') === false) return;
        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
        if (empty($body)) return;
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