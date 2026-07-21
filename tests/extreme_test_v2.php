<?php
/**
 * 极端极限测试 v2 - 上下文分析器专项
 *
 * 新增测试维度：
 *   O. 参数位置语义（L11）：同 payload 不同位置
 *   P. 跨请求 CSRF（L12）
 *   Q. 重放攻击（L12）
 *   R. 会话异常（L12）
 *   S. 时序异常（L12）
 *   T. API 滥用（L12）
 *   U. 横向移动（L8+L12）
 *   V. Kill Chain 阶段转移（L7）
 *   W. 行为基线漂移（L9）
 *   X. 业务模式自学习（L10）
 *   Y. 极限绕过：多层编码+上下文组合
 *   Z. 误报压力：真实业务流量
 */
define('ABSPATH', __DIR__ . '/../');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../src/Support/Functions.php';
require_once __DIR__ . '/../src/Core/RequestContext.php';
require_once __DIR__ . '/../src/Semantic/SemanticEngine.php';

$pass = 0;
$fail = 0;
$failDetails = [];

function test(string $name, string $payload, string $uri = '/', array $extra = []) {
    global $pass, $fail, $failDetails;
    $shouldBlock = $extra['should_block'] ?? true;
    $maxScore = $extra['max_score'] ?? 100;
    $minScore = $extra['min_score'] ?? 0;

    $_SERVER['REQUEST_URI'] = $uri . (strpos($uri, '?') !== false ? '&' : '?') . 't=' . uniqid();
    $_SERVER['REQUEST_METHOD'] = $extra['method'] ?? 'GET';
    $_SERVER['HTTP_USER_AGENT'] = $extra['ua'] ?? 'Mozilla/5.0';
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    if (isset($extra['origin'])) $_SERVER['HTTP_ORIGIN'] = $extra['origin'];
    if (isset($extra['referer'])) $_SERVER['HTTP_REFERER'] = $extra['referer'];
    if (isset($extra['host'])) $_SERVER['HTTP_HOST'] = $extra['host'];

    // 构造 multiVectorData
    $params = [];
    if (isset($extra['get'])) { $_GET = $extra['get']; $params = $extra['get']; }
    if (isset($extra['post'])) $_POST = $extra['post'];
    if (isset($extra['cookie'])) $_COOKIE = $extra['cookie'];

    // 构造完整 headers（模拟 Scorer::extractHeaders 行为）
    $headers = ['User-Agent' => $extra['ua'] ?? 'Mozilla/5.0'];
    if (isset($extra['origin'])) $headers['Origin'] = $extra['origin'];
    if (isset($extra['referer'])) $headers['Referer'] = $extra['referer'];
    if (isset($extra['host'])) $headers['Host'] = $extra['host'];

    $multiVectorData = [
        'uri' => $uri,
        'get' => $extra['get'] ?? [],
        'post' => $extra['post'] ?? [],
        'cookie' => isset($extra['cookie']) ? http_build_query($extra['cookie']) : '',
        'cookie_array' => $extra['cookie'] ?? [],
        'headers' => $headers,
        'ua' => $extra['ua'] ?? 'Mozilla/5.0',
        'referer' => $extra['referer'] ?? '',
        'raw_body' => '',
        'raw_text' => $payload,
    ];

    $result = SemanticEngine::analyze(
        $payload,
        $uri,
        $params,
        [],
        '127.0.0.1',
        $multiVectorData,
        $headers,
        $_SERVER['REQUEST_METHOD'],
        '',
        $extra['content_type'] ?? ''
    );

    $score = $result['total_score'] ?? 0;
    $blocked = ($score >= 70);
    $ok = $shouldBlock ? ($score >= $minScore) : ($score < 70);

    if ($ok) {
        echo "[PASS] {$name} (score={$score})\n";
        $pass++;
    } else {
        echo "[FAIL] {$name} (score={$score}, expected " . ($shouldBlock ? ">= {$minScore}" : "< 70") . ")\n";
        $fail++;
        $failDetails[] = "{$name}: score={$score}, expected " . ($shouldBlock ? ">= {$minScore}" : "< 70");
    }
    return $result;
}

// 清理上下文数据
@mkdir('/tmp/shield-waf/request_context', 0755, true);
@file_put_contents('/tmp/shield-waf/request_context/context_data.json', '{"requestSignatures":{},"sessionFingerprints":{},"requestTimestamps":{},"apiAccessPatterns":{},"paramSamples":{}}');

echo "\n========== 极端极限测试 v2 - 上下文分析器专项 ==========\n\n";

// ============================================
// O. 参数位置语义（L11）：同 payload 不同位置
// ============================================
echo "--- O. 参数位置语义（L11）---\n";

// O1: id 参数在 query - IDOR 风险
test('O1-位置: id在query参数', '../../../etc/passwd', '/?id=1', [
    'get' => ['id' => '../../../etc/passwd'],
    'min_score' => 50,
]);

// O2: token 在 cookie - 会话劫持潜在风险（位置异常检测应识别）
//     注：cookie 中单纯 token 字符串不是攻击 payload，不应直接拦截
//     但 ParamPositionAnalyzer 应识别为高风险参数
$r = test('O2-位置: token在cookie', 'stolen_session_token_12345', '/', [
    'cookie' => ['token' => 'stolen_session_token_12345'],
    'should_block' => false,  // 不拦截（保护业务流量）
]);
$ppScore = $r['param_position_score'] ?? 0;
if ($ppScore >= 30) {
    echo "  [PASS] O2-位置: ParamPosition 识别 cookie token 风险 (L11={$ppScore})\n";
    $pass++;
} else {
    echo "  [FAIL] O2-位置: ParamPosition 未识别 cookie token 风险 (L11={$ppScore}, expected >=30)\n";
    $fail++;
    $failDetails[] = "O2 ParamPosition score={$ppScore}, expected >=30";
}

// O3: cmd 在 query - 命令注入
test('O3-位置: cmd在query参数', 'cat /etc/passwd', '/?cmd=cat+/etc/passwd', [
    'get' => ['cmd' => 'cat /etc/passwd'],
    'min_score' => 60,
]);

// O4: url 参数 - SSRF
test('O4-位置: url在query参数', 'http://169.254.169.254/latest/meta-data/', '/', [
    'get' => ['url' => 'http://169.254.169.254/latest/meta-data/'],
    'min_score' => 50,
]);

// O5: 同一参数 id 在 query + cookie (跨位置异常)
test('O5-位置: id跨位置出现', '1', '/', [
    'get' => ['id' => '1'],
    'cookie' => ['id' => '2'],  // 值不一致
    'min_score' => 20,  // 跨位置异常
]);

// O6: Header 中的 SQL 特征
test('O6-位置: Header含SQL特征', 'union select', '/', [
    'ua' => "Mozilla' UNION SELECT--",
    'min_score' => 30,
]);

// ============================================
// P. 跨请求 CSRF（L12）
// ============================================
echo "\n--- P. 跨请求 CSRF（L12）---\n";

// P1: POST + 恶意 Origin + 无 Token
//     注：Referer 与 Origin 同源（都是 evil.com），所以只触发 Origin/Host 不一致 +25 和 POST 无 Token +15 = 40
//     这是正确的——纯跨站请求不能仅凭 Origin 不一致就拦截，需结合其他信号
test('P1-CSRF: 恶意Origin无Token', 'amount=10000&to=attacker', '/transfer', [
    'method' => 'POST',
    'post' => ['amount' => '10000', 'to' => 'attacker'],
    'origin' => 'https://evil.com',
    'referer' => 'https://evil.com/phishing',
    'host' => 'bank.example.com',
    'min_score' => 40,  // Origin/Host 不一致 +25, POST 无 Token +15 = 40
]);

// P2: POST + 无 Referer (可疑)
test('P2-CSRF: POST无Referer', 'transfer=100', '/api/transfer', [
    'method' => 'POST',
    'post' => ['amount' => '100'],
    'min_score' => 30,
]);

// P3: 合法同源请求 (低分)
test('P3-CSRF: 合法同源请求', 'search=hello', '/search', [
    'method' => 'POST',
    'post' => ['q' => 'hello world'],
    'origin' => 'https://example.com',
    'referer' => 'https://example.com/',
    'host' => 'example.com',
    'should_block' => false,
]);

// ============================================
// Q. 重放攻击（L12）
// ============================================
echo "\n--- Q. 重放攻击（L12）---\n";

// Q1: 相同请求重复 5 次
$replayPayload = 'transfer=100&to=account123';
for ($i = 0; $i < 5; $i++) {
    $r = test("Q1-重放#{$i}", $replayPayload, '/api/transfer', [
        'method' => 'POST',
        'post' => ['transfer' => '100', 'to' => 'account123'],
        'should_block' => false,  // 单次不应拦截（重放需要累积）
    ]);
}
// 第6次应该触发重放检测
test('Q1-重放触发', $replayPayload, '/api/transfer', [
    'method' => 'POST',
    'post' => ['transfer' => '100', 'to' => 'account123'],
    'min_score' => 30,
]);

// ============================================
// R. 会话异常（L12）
// ============================================
echo "\n--- R. 会话异常（L12）---\n";

// R1: 同 session 多个 UA
@session_start();
$_SESSION['test'] = true;
$sid = session_id();
test('R1-会话: UA切换', 'normal request', '/dashboard', [
    'ua' => 'Mozilla/5.0 Chrome',
    'should_block' => false,
]);
test('R1-会话: UA再次切换', 'normal request', '/dashboard', [
    'ua' => 'curl/7.68.0',
    'should_block' => false,
]);
test('R1-会话: UA第三次切换', 'normal request', '/dashboard', [
    'ua' => 'python-requests/2.25.0',
    'min_score' => 30,
]);

// ============================================
// S. 时序异常（L12）
// ============================================
echo "\n--- S. 时序异常（L12）---\n";

// S1: 快速连续请求（模拟 burst）
for ($i = 0; $i < 8; $i++) {
    test("S1-时序#{$i}", "id={$i}", "/api/data?id={$i}", [
        'should_block' => false,
    ]);
}
// 第9次应该触发时序异常
test('S1-时序触发', 'id=999', '/api/data?id=999', [
    'min_score' => 25,
]);

// ============================================
// T. API 滥用（L12）
// ============================================
echo "\n--- T. API 滥用（L12）---\n";

// T1: 快速访问多个不同端点
$endpoints = ['/api/users', '/api/posts', '/api/comments', '/api/orders', '/api/products',
              '/api/admin', '/api/settings', '/api/profile', '/api/search', '/api/auth',
              '/api/files', '/api/logs', '/api/stats', '/api/health', '/api/version',
              '/api/config', '/api/backup', '/api/export', '/api/import', '/api/migrate'];
foreach ($endpoints as $i => $ep) {
    test("T1-API扫描#{$i}", '', $ep, ['should_block' => false]);
}
// 第21个端点应触发 API 滥用
test('T1-API滥用触发', '', '/api/sensitive', [
    'min_score' => 25,
]);

// ============================================
// U. 横向移动（L8+L12）
// ============================================
echo "\n--- U. 横向移动检测 ---\n";

// U1: 从登录到管理后台到 API (典型横向移动序列)
$moveSeq = [
    ['/login', 'POST', 'username=admin&password=test'],
    ['/admin', 'GET', ''],
    ['/admin/users', 'GET', ''],
    ['/api/users', 'GET', ''],
    ['/api/admin/list', 'GET', ''],
];
foreach ($moveSeq as $i => [$u, $m, $p]) {
    $post = [];
    if ($p) parse_str($p, $post);
    test("U1-横向#{$i}", $p, $u, [
        'method' => $m,
        'post' => $post,
        'should_block' => false,
    ]);
}

// ============================================
// V. Kill Chain 阶段转移（L7）
// ============================================
echo "\n--- V. Kill Chain 阶段转移（L7）---\n";

// V1: recon -> actions 大跳跃 (异常)
test('V1-阶段转移: recon直跳actions', 'union select 1,2,3,load_file("/etc/passwd")', '/?id=1', [
    'get' => ['id' => '1 union select 1,2,3,load_file("/etc/passwd")'],
    'min_score' => 70,
]);

// V2: SQL 注入 + 路径遍历组合 (意图转移)
test('V2-意图转移: SQL到路径遍历', '1 union select load_file("/etc/passwd")', '/', [
    'get' => ['id' => '1 union select load_file("/etc/passwd")'],
    'min_score' => 75,
]);

// ============================================
// W. 行为基线漂移（L9）
// ============================================
echo "\n--- W. 行为基线漂移（L9）---\n";

// W1: 建立 5 个正常请求基线
for ($i = 0; $i < 5; $i++) {
    test("W1-基线建立#{$i}", "q=hello+world+{$i}", '/search', [
        'get' => ['q' => "hello world {$i}"],
        'should_block' => false,
    ]);
}
// W2: 突然切换到攻击 payload (行为漂移)
test('W2-行为漂移: 突然攻击', "1' OR 1=1--", '/search', [
    'get' => ['q' => "1' OR 1=1--"],
    'min_score' => 60,
]);

// ============================================
// X. 业务模式自学习（L10）
// ============================================
echo "\n--- X. 业务模式自学习（L10）---\n";

// X1: 模拟 10 次正常搜索 (建立学习模式)
for ($i = 0; $i < 10; $i++) {
    test("X1-学习#{$i}", "search=technology+article+{$i}", '/search', [
        'get' => ['search' => "technology article {$i}"],
        'should_block' => false,
    ]);
}
// X2: 类似模式的新请求应该被识别为业务模式
test('X2-业务模式: 相似搜索', 'search=new+query', '/search', [
    'get' => ['search' => 'new query'],
    'should_block' => false,
]);

// ============================================
// Y. 极限绕过：多层编码+上下文组合
// ============================================
echo "\n--- Y. 极限绕过：多层编码+上下文组合 ---\n";

// Y1: 三层 URL 编码的 SQL 注入
test('Y1-极限: 三层编码SQLi', '%252527%252520OR%2525201%25253D1--', '/', [
    'get' => ['id' => '%252527%252520OR%2525201%25253D1--'],
    'min_score' => 30,
]);

// Y2: Base64 编码的 XSS
test('Y2-极限: Base64编码XSS', base64_encode('<script>alert(1)</script>'), '/', [
    'get' => ['data' => base64_encode('<script>alert(1)</script>')],
    'min_score' => 40,
]);

// Y3: Unicode 编码的命令注入
test('Y3-极限: Unicode编码CMD', '\u003b\u0063\u0061\u0074\u0020\u002f\u0065\u0074\u0063\u002f\u0070\u0061\u0073\u0073\u0077\u0064', '/', [
    'get' => ['cmd' => '\u003b\u0063\u0061\u0074\u0020\u002f\u0065\u0074\u0063\u002f\u0070\u0061\u0073\u0073\u0077\u0064'],
    'min_score' => 30,
]);

// Y4: 混合编码（URL+HTML实体）的 SSTI
test('Y4-极限: 混合编码SSTI', '&#123;&#123;7*7&#125;&#125;', '/', [
    'get' => ['tpl' => '&#123;&#123;7*7&#125;&#125;'],
    'min_score' => 30,
]);

// ============================================
// Z. 误报压力：真实业务流量
// ============================================
echo "\n--- Z. 误报压力：真实业务流量 ---\n";

// Z1: 正常分页请求
test('Z1-误报: 分页请求', '', '/products?page=2&per_page=20', [
    'get' => ['page' => '2', 'per_page' => '20'],
    'should_block' => false,
]);

// Z2: 正常 i18n 参数
test('Z2-误报: i18n参数', '', '/?lang=en_US', [
    'get' => ['lang' => 'en_US'],
    'should_block' => false,
]);

// Z3: 正常 JSON API 请求
test('Z3-误报: JSON API', '{"name":"John","email":"john@example.com"}', '/api/users', [
    'method' => 'POST',
    'content_type' => 'application/json',
    'post' => ['name' => 'John', 'email' => 'john@example.com'],
    'should_block' => false,
]);

// Z4: 正常 markdown 内容
test('Z4-误报: Markdown内容', '# Hello World\n\nThis is **bold** and *italic* text.', '/posts/create', [
    'method' => 'POST',
    'post' => ['content' => '# Hello World'],
    'should_block' => false,
]);

// Z5: 正常 CSRF token 参数
test('Z5-误报: CSRF Token参数', '', '/form/submit', [
    'method' => 'POST',
    'post' => ['_token' => 'csrf_token_abc123', 'data' => 'value'],
    'should_block' => false,
]);

// Z6: WordPress heartbeat
test('Z6-误报: WP heartbeat', '', '/wp-admin/admin-ajax.php', [
    'method' => 'POST',
    'post' => ['action' => 'heartbeat', '_nonce' => 'abc123'],
    'should_block' => false,
]);

// ============================================

echo "\n========================================\n";
echo " 测试结果汇总\n";
echo "========================================\n";
echo "通过: {$pass}\n";
echo "失败: {$fail}\n";
$failedPercent = ($pass + $fail) > 0 ? round($fail / ($pass + $fail) * 100, 2) : 0;
echo "失败率: {$failedPercent}%\n";
echo "总计: " . ($pass + $fail) . "\n";

if (!empty($failDetails)) {
    echo "\n失败详情:\n";
    foreach ($failDetails as $detail) {
        echo "  - {$detail}\n";
    }
}

exit($fail > 0 ? 1 : 0);
