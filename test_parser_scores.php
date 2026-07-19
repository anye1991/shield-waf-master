<?php
error_reporting(E_ERROR | E_PARSE);
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["REMOTE_ADDR"] = "127.0.0.1";
$_SERVER["HTTP_USER_AGENT"] = "Mozilla/5.0 Chrome/120";
$_SERVER["HTTP_HOST"] = "localhost";
$_SERVER["HTTP_ACCEPT"] = "text/html";
$_SERVER["HTTP_ACCEPT_LANGUAGE"] = "zh-CN";
if (!defined('WAF_RAW_BODY')) define('WAF_RAW_BODY', '');

require_once __DIR__ . "/config.php";
require_once __DIR__ . "/src/Support/Functions.php";
require_once __DIR__ . "/src/Semantic/SemanticEngine.php";
require_once __DIR__ . "/src/Core/Scorer.php";

$attacks = [
    "<script>alert(1)</script>",
    ";cat /etc/passwd",
    "../../../etc/passwd",
    "eval(base64_decode)",
    "system(ls)",
    "1 UNION SELECT",
    "1' OR '1'='1",
];

echo "=== 各攻击载荷的解析器得分详情 ===\n";
foreach ($attacks as $payload) {
    $params = ["q" => $payload];
    $r = WafScorer::score($payload, "/?q=test", $params, [], "127.0.0.1");
    $sd = $r["semantic_detail"] ?? [];
    $pr = $sd["parser_results"] ?? [];
    printf("Payload: %s\n", $payload);
    printf("  final=%5.1f  action=%s\n", $r["total_score"], $r["action"]);
    printf("  semantic_total=%5.1f  encode_bonus=%5.1f  fp_adj=%d\n",
        $sd["total_score"] ?? 0,
        $r["encode_bypass_bonus"] ?? 0,
        $r["fp_adjustment"] ?? 0
    );
    foreach (["sql","html","command","php","path","xxe","ssrf","ssti","deser","crlf","expr"] as $type) {
        $v = $pr[$type] ?? null;
        if (is_array($v) && isset($v["score"]) && $v["score"] > 0) {
            printf("    %-10s = %5.1f  matched=%s\n", $type, $v["score"], $v["matched"] ?? "");
        }
    }
    echo "\n";
}
