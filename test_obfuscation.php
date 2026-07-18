<?php
/**
 * 抗混淆检测能力测试
 * 验证 analyzeLineForMalware() 能否识破各种混淆/加密手法
 *
 * 运行：php test_obfuscation.php
 */
define('ABSPATH', '/workspace/shield-waf-master/');
define('WAF_LOG_PATH', '/tmp/waf_test_logs/');
if (!is_dir(WAF_LOG_PATH)) mkdir(WAF_LOG_PATH, 0777, true);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Semantic/AdversarialDefense.php';
require_once __DIR__ . '/src/Admin/Sandbox.php';

WafSandbox::init();

// 通过反射访问 private static 方法
$ref = new ReflectionClass('WafSandbox');
$method = $ref->getMethod('analyzeLineForMalware');
$method->setAccessible(true);

$analyze = function (string $line, string $context = '') use ($method) {
    return $method->invoke(null, $line, $context);
};

echo "╔══════════════════════════════════════════════════════════════════════╗\n";
echo "║        抗混淆检测能力测试 - analyzeLineForMalware() 16 维检测           ║\n";
echo "╚══════════════════════════════════════════════════════════════════════╝\n\n";

// 测试用例：每条都应被判定为恶意（is_malicious=true）
// 这是绕过旧版简单正则的混淆手法
$maliciousCases = [
    // === 1. 变量函数 + 字符串拼接 ===
    ['$f=\'sy\'\'tem\'; $f($_GET[\'cmd\']);', '变量函数+字符串拼接'],
    ['$a="sys"."tem"; $a($_POST["x"]);',     '变量函数+双引号拼接'],

    // === 2. 注释插入混淆 ===
    ['ev/*xx*/al($_GET[\'cmd\']);',          '注释插入eval'],
    ['ev/*xx*/al(base64_decode($_POST[\'x\']));', '注释插入+base64'],

    // === 3. 字符串字面量拼接 ===
    ['("ev"."al")($_GET[\'cmd\']);',           '字符串拼接eval'],
    ['$f = "ev"."al"; $f($_POST[\'x\']);',     '变量赋值+拼接'],

    // === 4. chr() 拼装 ===
    ['chr(101).chr(118).chr(97).chr(108)($_GET[\'cmd\']);', 'chr拼装eval'],
    ['$f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f($_GET[\'cmd\']);', 'chr拼装system'],

    // === 5. Hex 转义序列 ===
    ['$x="\x65\x76\x61\x6c"; $x($_GET[\'cmd\']);', 'hex转义eval'],
    ['eval("\x73\x79\x73\x74\x65\x6d".$_GET[\'c\']);', 'hex转义+eval'],

    // === 6. 嵌套编码 ===
    ['eval(base64_decode(base64_decode($_POST[\'x\'])));', '嵌套base64'],
    ['eval(gzinflate(base64_decode($_POST[\'x\'])));',     'gzinflate+base64'],

    // === 7. 可变变量 $$ ===
    ['$name="system"; $$name($_GET[\'cmd\']);', '可变变量$$'],

    // === 8. create_function / preg_replace /e ===
    ['create_function(\'\',$_POST[\'x\']);',           'create_function'],
    ['preg_replace("/.*/e",$_POST[\'x\'],"in");',      'preg_replace /e'],

    // === 9. 反引号执行注入 ===
    ['$r=`$_GET[cmd]`;',                       '反引号执行'],

    // === 10. 文件写入+用户输入 ===
    ['file_put_contents($_GET[\'f\'],$_POST[\'c\']);', '文件写入+用户输入'],

    // === 11. include 用户输入 ===
    ['include($_GET[\'page\']);',                'include用户输入'],
    ['require($_POST[\'file\']);',               'require用户输入'],

    // === 12. URL/HTML 编码混淆 ===
    ['eval(base64_decode("%65%76%61%6c"));',     'URL编码混淆'],
    ['eval("%65%76%61%6c".$_GET[\'x\']);',       'URL编码+eval'],

    // === 13. 长Base64 payload ===
    ['eval(base64_decode("ZWNobyAnSEFDS0VEJzs=' . str_repeat('ZWNobyAnSEFDS0VEJzs=', 5) . '"));', '长Base64载荷'],

    // === 14. goto 混淆 ===
    ['goto a; eval($_POST[\'x\']); a:',           'goto混淆+eval'],

    // === 15. 跨行变量函数（context 测试） ===
    ['$runner($_GET[\'cmd\']);',                  '跨行变量函数调用'],
];

// 跨行上下文：前一行定义 $runner，后一行调用
$crossLineContext = '$runner = \'sy\'\'stem\';' . "\n";

$pass = 0;
$fail = 0;
$failedCases = [];

echo "【测试】每个混淆用例都应被识别为恶意 (score >= 20)\n";
echo str_repeat("-", 90) . "\n";
printf("%-3s  %-8s  %-5s  %-50s\n", '#', '结果', '分数', '原因');
echo str_repeat("-", 90) . "\n";

foreach ($maliciousCases as $i => $case) {
    list($line, $desc) = $case;
    $context = ($desc === '跨行变量函数调用') ? $crossLineContext : '';
    $r = $analyze($line, $context);

    $ok = $r['is_malicious'];
    if ($ok) {
        $pass++;
    } else {
        $fail++;
        $failedCases[] = ['desc' => $desc, 'line' => $line, 'result' => $r];
    }

    $status = $ok ? '✓通过' : '✗失败';
    $reasonShort = mb_substr($r['reason'], 0, 50);
    printf("[%2d] %-8s  %3d   %s\n", $i + 1, $status, $r['score'], $desc);
    if (!$ok) {
        printf("       原行: %s\n", mb_substr($line, 0, 80));
        printf("       原因: %s\n", $reasonShort);
    }
}

echo str_repeat("-", 90) . "\n\n";

// 测试用例：这些正常代码不应被误杀
echo "【误报测试】这些正常代码不应被误杀 (score < 20)\n";
echo str_repeat("-", 90) . "\n";

$cleanCases = [
    ['echo "Hello World";',                                '简单echo'],
    ['$name = "user_input"; echo $name;',                  '普通变量赋值'],
    ['if ($a > 0) { return $b; }',                          '正常if语句'],
    ['function add($x, $y) { return $x + $y; }',           '正常函数定义'],
    ['// This is a comment',                                '单纯注释行'],
    ['$sql = "SELECT * FROM users WHERE id = ?";',          '预编译SQL'],
    ['$data = ["name" => "John", "age" => 30];',            '数组定义'],
    ['foreach ($items as $item) { echo $item; }',           'foreach循环'],
    ['class User { public $name; }',                         '类定义'],
    ['const MAX = 100;',                                     '常量定义'],
];

$cleanPass = 0;
$cleanFail = 0;
$cleanFailedCases = [];

foreach ($cleanCases as $i => $case) {
    list($line, $desc) = $case;
    $r = $analyze($line);

    $ok = !$r['is_malicious'];
    if ($ok) {
        $cleanPass++;
    } else {
        $cleanFail++;
        $cleanFailedCases[] = ['desc' => $desc, 'line' => $line, 'result' => $r];
    }

    $status = $ok ? '✓通过' : '✗误报';
    printf("[%2d] %-8s  %3d   %s\n", $i + 1, $status, $r['score'], $desc);
    if (!$ok) {
        printf("       原行: %s\n", $line);
        printf("       原因: %s\n", mb_substr($r['reason'], 0, 50));
    }
}

echo str_repeat("-", 90) . "\n\n";

// 汇总
echo "════════════════════════════════════════════════════════════════════\n";
echo "【汇总】\n";
printf("  恶意识别：通过 %d / 失败 %d （共 %d 个）\n", $pass, $fail, $pass + $fail);
printf("  误报测试：通过 %d / 误报 %d （共 %d 个）\n", $cleanPass, $cleanFail, $cleanPass + $cleanFail);

$totalScore = $pass + $cleanPass;
$totalCases = $pass + $fail + $cleanPass + $cleanFail;
$passRate = $totalCases > 0 ? round($totalScore / $totalCases * 100, 1) : 0;
printf("  总通过率：%d/%d = %.1f%%\n", $totalScore, $totalCases, $passRate);
echo "════════════════════════════════════════════════════════════════════\n";

if ($fail > 0) {
    echo "\n【未识别的恶意用例】\n";
    foreach ($failedCases as $c) {
        echo "  - {$c['desc']}\n";
        echo "    行: {$c['line']}\n";
        echo "    分: {$c['result']['score']}\n";
        echo "    因: {$c['result']['reason']}\n";
    }
}
if ($cleanFail > 0) {
    echo "\n【误报的用例】\n";
    foreach ($cleanFailedCases as $c) {
        echo "  - {$c['desc']}\n";
        echo "    行: {$c['line']}\n";
        echo "    分: {$c['result']['score']}\n";
        echo "    因: {$c['result']['reason']}\n";
    }
}

exit(($fail === 0 && $cleanFail === 0) ? 0 : 1);
