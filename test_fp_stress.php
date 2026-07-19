<?php
define("ABSPATH", "/workspace/shield-waf-master/");
define("WAF_LOG_PATH", "/workspace/shield-waf-master/logs/");
if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0777, true);
require_once '/workspace/shield-waf-master/src/Core/Scorer.php';

$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
$_SERVER['HTTP_REFERER'] = '';

$normalCases = [
    // 基础正常文本
    ['name' => '纯数字ID', 'payload' => '12345', 'uri' => '/user.php'],
    ['name' => '英文单词', 'payload' => 'hello world', 'uri' => '/test.php'],
    ['name' => '中文句子', 'payload' => '今天天气真好适合出去散步', 'uri' => '/blog.php'],
    ['name' => '邮箱地址', 'payload' => 'user.name@example.com', 'uri' => '/register.php'],
    ['name' => 'URL地址', 'payload' => 'https://blog.example.com/article/123', 'uri' => '/redirect.php'],
    ['name' => '手机号', 'payload' => '13812345678', 'uri' => '/login.php'],
    ['name' => '日期时间', 'payload' => '2024-01-15 14:30:00', 'uri' => '/schedule.php'],
    ['name' => 'IP地址', 'payload' => '192.168.1.100', 'uri' => '/admin.php'],
    
    // 可能误报的边缘情况 - 含特殊字符的正常文本
    ['name' => '搜索SQL关键词', 'payload' => 'SQL注入教程学习笔记', 'uri' => '/search.php'],
    ['name' => '搜索XSS关键词', 'payload' => 'XSS跨站脚本攻击防御方法', 'uri' => '/search.php'],
    ['name' => '搜索PHP代码', 'payload' => 'PHP echo函数用法', 'uri' => '/search.php'],
    ['name' => '文章含代码片段', 'payload' => '使用mysql_query执行SELECT语句', 'uri' => '/blog/post.php'],
    ['name' => '技术文档引用', 'payload' => 'javascript中alert函数的使用', 'uri' => '/docs.php'],
    ['name' => '数学公式', 'payload' => 'a=1 AND b=2 计算结果', 'uri' => '/math.php'],
    ['name' => '含括号的文本', 'payload' => '这是（重要的）内容，请查看', 'uri' => '/test.php'],
    ['name' => '含引号的文本', 'payload' => "他说\"你好\"然后走了", 'uri' => '/test.php'],
    ['name' => '含单引号英文名', 'payload' => "O'Brien", 'uri' => '/register.php'],
    
    // URL参数常见特殊字符
    ['name' => '搜索加引号', 'payload' => '"精确匹配"', 'uri' => '/search.php'],
    ['name' => '搜索加减号', 'payload' => '关键词 -排除词 +必选词', 'uri' => '/search.php'],
    ['name' => '搜索通配符', 'payload' => 'php* 入门*教程', 'uri' => '/search.php'],
    
    // 富文本/Markdown内容
    ['name' => 'Markdown标题', 'payload' => '## 第一章 简介', 'uri' => '/edit.php'],
    ['name' => 'Markdown链接', 'payload' => '[点击这里](https://example.com)', 'uri' => '/edit.php'],
    ['name' => 'Markdown代码', 'payload' => '使用 `echo` 输出内容', 'uri' => '/edit.php'],
    ['name' => 'Markdown列表', 'payload' => "- 第一项\n- 第二项\n- 第三项", 'uri' => '/edit.php'],
    ['name' => 'Markdown粗体斜体', 'payload' => '**粗体**和*斜体*文本', 'uri' => '/edit.php'],
    
    // JSON数据
    ['name' => '简单JSON', 'payload' => '{"name":"test","id":123}', 'uri' => '/api/user.php'],
    ['name' => '复杂JSON', 'payload' => '{"user":{"name":"test","roles":["admin","user"]},"meta":{"version":1}}', 'uri' => '/api/data.php'],
    
    // Base64编码的正常数据（图片、token等）
    ['name' => '短Base64 token', 'payload' => base64_encode('user_token_abc123'), 'uri' => '/api/verify.php'],
    ['name' => '长Base64 数据', 'payload' => base64_encode('这是一段正常的业务数据，包含用户配置信息和偏好设置'), 'uri' => '/api/save.php'],
    
    // HTML富文本编辑器内容
    ['name' => 'HTML段落', 'payload' => '<p>这是一段正常的文字</p>', 'uri' => '/editor.php'],
    ['name' => 'HTML链接', 'payload' => '<a href="https://example.com">链接</a>', 'uri' => '/editor.php'],
    ['name' => 'HTML图片', 'payload' => '<img src="/images/test.jpg" alt="图片">', 'uri' => '/editor.php'],
    ['name' => 'HTML表格', 'payload' => '<table><tr><td>数据1</td><td>数据2</td></tr></table>', 'uri' => '/editor.php'],
    
    // 路径类正常请求
    ['name' => '文件路径', 'payload' => '/uploads/2024/01/photo.jpg', 'uri' => '/download.php'],
    ['name' => '相对路径', 'payload' => '../assets/css/style.css', 'uri' => '/theme.php'],
    
    // 命令行相关的正常搜索
    ['name' => '搜索Linux命令', 'payload' => 'Linux ls命令详解', 'uri' => '/search.php'],
    ['name' => '搜索cat命令', 'payload' => 'cat命令查看文件内容', 'uri' => '/search.php'],
];

echo "╔══════════════════════════════════════════════════════════════════════╗\n";
echo "║                    误报压力测试 - 40个正常用例                        ║\n";
echo "╚══════════════════════════════════════════════════════════════════════╝\n\n";

$fpCount = 0;
$fpCases = [];
$logCount = 0;
$observeCount = 0;
$blockCount = 0;

foreach ($normalCases as $tc) {
    $params = ['q' => $tc['payload']];
    $result = WafScorer::score($tc['payload'], $tc['uri'], $params, [], '127.0.0.1');
    
    $isFP = $result['total_score'] >= 50; // log及以上算误报
    $actionIcon = $isFP ? '✗' : '✓';
    
    if ($result['action'] === 'block') $blockCount++;
    elseif ($result['action'] === 'observe') $observeCount++;
    elseif ($result['action'] === 'log') $logCount++;
    
    if ($isFP) {
        $fpCount++;
        $fpCases[] = ['name' => $tc['name'], 'score' => $result['total_score'], 'action' => $result['action']];
    }
    
    printf("  %-22s %5.1f分  %-8s %s\n", $tc['name'], $result['total_score'], $result['action'], $actionIcon);
}

echo "\n" . str_repeat("═", 70) . "\n";
echo "误报统计:\n";
echo "  总用例: " . count($normalCases) . "\n";
echo "  误报数(≥50分): $fpCount\n";
echo "  误报率: " . round($fpCount/count($normalCases)*100, 1) . "%\n";
echo "  动作分布: pass=" . (count($normalCases) - $logCount - $observeCount - $blockCount) 
    . ", log=$logCount, observe=$observeCount, block=$blockCount\n";

if ($fpCases) {
    echo "\n误报详情:\n";
    foreach ($fpCases as $fp) {
        echo "  - {$fp['name']}: {$fp['score']}分 ({$fp['action']})\n";
    }
}

// 最高分的几个正常用例
echo "\n最高分TOP10正常用例:\n";
$scores = [];
foreach ($normalCases as $i => $tc) {
    $params = ['q' => $tc['payload']];
    $result = WafScorer::score($tc['payload'], $tc['uri'], $params, [], '127.0.0.1');
    $scores[] = ['name' => $tc['name'], 'score' => $result['total_score'], 'detail' => $result];
}
usort($scores, function($a, $b) { return $b['score'] <=> $a['score']; });
for ($i = 0; $i < min(10, count($scores)); $i++) {
    $s = $scores[$i];
    echo sprintf("  %2d. %-22s %5.1f分  语义=%.0f  加成=%.0f\n",
        $i+1, $s['name'], $s['score'],
        $s['detail']['semantic_score'],
        $s['detail']['encode_bypass_bonus'] ?? 0
    );
}
