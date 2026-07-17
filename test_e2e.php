<?php
define("ABSPATH", "/workspace/shield-waf-master/");
define("WAF_LOG_PATH", "/workspace/shield-waf-master/logs/");
if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0777, true);
require_once '/workspace/shield-waf-master/src/Core/Scorer.php';

// 模拟环境变量
$_GET = ['id' => '1'];
$_POST = [];
$_COOKIE = [];
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
$_SERVER['HTTP_REFERER'] = '';

$testCases = [
    // 编码绕过类
    ['name' => 'URL双编SQL', 'payload' => '%2527%2520OR%25201%253D1--', 'uri' => '/test.php'],
    ['name' => 'Percent-U XSS', 'payload' => '%u003cscript%u003ealert(1)%u003c/script%u003e', 'uri' => '/test.php'],
    ['name' => 'Base64命令', 'payload' => base64_encode('id; cat /etc/passwd'), 'uri' => '/test.php'],
    ['name' => '全角SQL', 'payload' => '＇ ＯＲ １＝１－－', 'uri' => '/test.php'],
    ['name' => '西里尔SQL', 'payload' => "S\u{0435}LECT * FROM users --", 'uri' => '/test.php'],
    ['name' => '零宽XSS', 'payload' => "<s\u{200b}cript>ale\u{200c}rt(1)</scr\u{200d}ipt>", 'uri' => '/test.php'],
    ['name' => 'Unicode转义XSS', 'payload' => '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', 'uri' => '/test.php'],
    ['name' => '数学粗体XSS', 'payload' => "<\u{1D41D}\u{1D42C}\u{1D42B}\u{1D422}\u{1D429}\u{1D42D}>alert(1)</\u{1D41D}\u{1D42C}\u{1D42B}\u{1D422}\u{1D429}\u{1D42D}>", 'uri' => '/test.php'],
    ['name' => '数学斜体SQL', 'payload' => "\u{1D460}\u{1D452}\u{1D459}\u{1D452}\u{1D450}\u{1D461} * FROM users --", 'uri' => '/test.php'],
    ['name' => '斜十六进制XSS', 'payload' => '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e', 'uri' => '/test.php'],
    ['name' => 'HTML实体XSS', 'payload' => '&#60;script&#62;alert(1)&#60;/script&#62;', 'uri' => '/test.php'],
    ['name' => 'UTF-8超集路径', 'payload' => '%c0%ae%c0%ae%c0%afetc%c0%afpasswd', 'uri' => '/test.php'],

    // 明文攻击（对照组）
    ['name' => '明文SQL注入', 'payload' => "' OR 1=1--", 'uri' => '/test.php'],
    ['name' => '明文XSS', 'payload' => '<script>alert(1)</script>', 'uri' => '/test.php'],
    ['name' => '明文命令注入', 'payload' => '; cat /etc/passwd', 'uri' => '/test.php'],

    // 正常文本（误报控制）
    ['name' => '正常搜索', 'payload' => '如何学习PHP编程入门教程', 'uri' => '/search.php'],
    ['name' => '正常ID', 'payload' => '12345', 'uri' => '/user.php'],
    ['name' => '正常邮件', 'payload' => 'user@example.com', 'uri' => '/register.php'],
];

echo "╔══════════════════════════════════════════════════════════════════════╗\n";
echo "║     端到端测试：14层解码 + 语义分析 + 智能评分  整体配合效果          ║\n";
echo "╚══════════════════════════════════════════════════════════════════════╝\n\n";

echo str_pad("用例", 20) . str_pad("总分", 8) . str_pad("熵值", 8) . str_pad("语义", 8) 
    . str_pad("编译", 8) . str_pad("偏离", 8) . str_pad("动作", 10) . "结果\n";
echo str_repeat("-", 90) . "\n";

$pass = 0;
$fail = 0;
$fp = 0;

foreach ($testCases as $tc) {
    $result = WafScorer::score($tc['payload'], $tc['uri'], ['q' => $tc['payload']], [], '127.0.0.1');
    
    $isAttack = (strpos($tc['name'], '正常') === false);
    $detected = $result['total_score'] >= 50; // 观察及以上算检测到
    
    if ($isAttack) {
        $ok = $detected ? '✓' : '✗';
        if ($detected) $pass++; else $fail++;
    } else {
        $ok = !$detected ? '✓' : '✗ 误报';
        if (!$detected) $pass++; else $fp++;
    }
    
    printf("%-18s %5.1f  %5.1f   %5.1f   %5.1f   %5.1f   %-8s %s\n",
        $tc['name'],
        $result['total_score'],
        $result['entropy_score'],
        $result['semantic_score'],
        $result['compiler_score'],
        $result['deviation_score'],
        $result['action'],
        $ok
    );
}

echo str_repeat("-", 90) . "\n";
echo "攻击检测: $pass/" . (count($testCases) - 3) . "  通过 | 误报: $fp/3\n";
echo "动作说明: pass=通过, log=记录, observe=观察, block=拦截\n";
