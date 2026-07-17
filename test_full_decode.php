<?php
define('ABSPATH', '/workspace/shield-waf-master/');
require_once ABSPATH . 'src/Semantic/AdversarialDefense.php';
require_once ABSPATH . 'src/Semantic/SemanticEngine.php';

$map = (new ReflectionClass("AdversarialDefense"))->getStaticPropertyValue("homoglyph_map");
echo "同形字映射总数: " . count($map) . " 字符\n\n";

$tests = [
    // 编码绕过类
    ['name' => 'URL双编SQL', 'payload' => '%2527%2520OR%25201%253D1--', 'min' => 80],
    ['name' => 'Unicode超集路径', 'payload' => '%c0%ae%c0%ae%c0%afetc%c0%afpasswd', 'min' => 30],
    ['name' => 'Percent-U XSS', 'payload' => '%u003cscript%u003ealert(1)%u003c/script%u003e', 'min' => 40],
    ['name' => 'HTML实体SQL', 'payload' => '&#83;ELECT &#42; FROM users --', 'min' => 50],
    ['name' => 'Base64命令', 'payload' => base64_encode('id; cat /etc/passwd'), 'min' => 40],
    ['name' => '全角SQL', 'payload' => '＇ ＯＲ １＝１－－', 'min' => 80],
    ['name' => '西里尔SQL', 'payload' => "S\u{0435}LECT * FROM users --", 'min' => 30],
    ['name' => '零宽XSS', 'payload' => "<s\u{200b}cript>ale\u{200c}rt(1)</scr\u{200d}ipt>", 'min' => 40],
    ['name' => 'Unicode转义XSS', 'payload' => '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', 'min' => 40],
    ['name' => '数学粗体XSS', 'payload' => "<\u{1D41D}\u{1D42C}\u{1D42B}\u{1D422}\u{1D429}\u{1D42D}>alert(1)</\u{1D41D}\u{1D42C}\u{1D42B}\u{1D422}\u{1D429}\u{1D42D}>", 'min' => 30],
    ['name' => '斜十六进制XSS', 'payload' => '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e', 'min' => 40],
    ['name' => '数学斜体SQL', 'payload' => "\u{1D460}\u{1D452}\u{1D459}\u{1D452}\u{1D450}\u{1D461} * FROM users --", 'min' => 30],

    // 正常文本（无误报）
    ['name' => '正常搜索', 'payload' => '如何学习PHP编程入门教程', 'max' => 15],
    ['name' => '正常ID', 'payload' => '12345', 'max' => 10],
    ['name' => '正常邮件', 'payload' => 'user@example.com', 'max' => 10],
    ['name' => '正常URL', 'payload' => 'https://www.example.com/path?query=value', 'max' => 20],
    ['name' => '正常中文', 'payload' => '今天天气真好，适合出去散步', 'max' => 10],
];

printf("%-22s %5s %4s %4s  %s\n", "用例", "得分", "深度", "绕过分", "结果");
echo str_repeat("-", 80) . "\n";

$pass = 0; $fail = 0;
foreach ($tests as $t) {
    $r = SemanticEngine::analyze($t['payload']);
    $score = $r['total_score'];
    $depth = $r['decode_depth'] ?? 0;
    $bypass = $r['encode_bypass_score'] ?? 0;

    $ok = true;
    if (isset($t['min']) && $score < $t['min']) $ok = false;
    if (isset($t['max']) && $score > $t['max']) $ok = false;

    if ($ok) $pass++; else $fail++;
    $flag = $ok ? '✓' : '✗';

    printf("%-20s %5d %4d %4d   %s\n", $t['name'], $score, $depth, $bypass, $flag);
}

echo str_repeat("-", 80) . "\n";
echo "总计: " . count($tests) . " | 通过: $pass | 失败: $fail\n";
