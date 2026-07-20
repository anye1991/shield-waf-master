<?php
/**
 * Defense 性能基准测试
 * 自适应各 detect 方法签名
 */
define('ABSPATH', __DIR__ . '/');
define('WAF_LOG_PATH', __DIR__ . '/logs');
define('WAF_TEST_MODE', true);
define('WAF_RAW_BODY', '');

if (!is_dir(WAF_LOG_PATH)) @mkdir(WAF_LOG_PATH, 0700, true);

require_once __DIR__ . '/src/Support/Functions.php';
require_once __DIR__ . '/src/Support/Password.php';

$defenseFiles = glob(__DIR__ . '/src/Defense/*.php');
foreach ($defenseFiles as $file) {
    require_once $file;
}

echo "═══════════════════════════════════════════════════════════════\n";
echo "  Defense 性能基准测试\n";
echo "═══════════════════════════════════════════════════════════════\n\n";

$samples = [
    'normal'      => ['name' => '正常短',   'value' => 'hello world'],
    'normal_long' => ['name' => '正常5KB',  'value' => str_repeat('This is a normal text. ', 220)],
    'normal_huge' => ['name' => '正常50KB', 'value' => str_repeat('This is a normal text. ', 2200)],
    'sqli'        => ['name' => 'SQLi',    'value' => "1' UNION SELECT username,password FROM users WHERE '1'='1' -- -"],
    'xss'         => ['name' => 'XSS',     'value' => '<script>alert(document.cookie)</script>'],
    'ssti'        => ['name' => 'SSTI',    'value' => "{{7*7}}{{config.__class__.__mro__[1].__subclasses__()}}"],
    'xxe'         => ['name' => 'XXE',     'value' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    'ldap'        => ['name' => 'LDAP',    'value' => '*)(uid=*'],
    'nosql'       => ['name' => 'NoSQL',   'value' => '{"username":{"$gt":""},"password":{"$ne":""}}'],
];

// 仅测试兼容签名（单参数 detect）
$defenseClasses = [
    'CachePoisoning', 'CrlfInjection', 'OpenRedirect', 'NoSqlInjection',
    'TemplateInjection', 'LdapInjection', 'XPathInjection',
    'XxeInjection', 'Deserialization', 'IdorDetection', 'FileInclusion',
];

$iterations = 2000;
$results = [];

// 自适应调用：按类名决定调用签名
function callDetect($className, $value) {
    // detect($inputs) 单参数（数组）
    $singleParamClasses = ['LdapInjection', 'XPathInjection', 'OpenRedirect',
                            'IdorDetection', 'FileInclusion'];
    // detect($rawBody, $inputs) 双参数
    $doubleParamRawFirst = ['XxeInjection'];
    // detect($inputs, $rawBody) 双参数
    $doubleParamInputsFirst = ['Deserialization'];
    // check() 无参
    $noParamClasses = ['CachePoisoning', 'CrlfInjection', 'NoSqlInjection',
                       'TemplateInjection'];
    
    // 设定 $_GET 供 check() 使用
    $_GET = ['test' => $value];
    $_POST = [];
    $_SERVER['REQUEST_URI'] = '/?test=' . urlencode($value);
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    if (!defined('WAF_RAW_BODY')) define('WAF_RAW_BODY', $value);
    $GLOBALS['WAF_RAW_BODY'] = $value;
    
    if (in_array($className, $doubleParamRawFirst, true)) {
        return $className::detect($value, [$value]);
    }
    if (in_array($className, $doubleParamInputsFirst, true)) {
        return $className::detect([$value], $value);
    }
    if (in_array($className, $singleParamClasses, true)) {
        return $className::detect([$value]);
    }
    // check() 无参
    return $className::check();
}

foreach ($defenseClasses as $className) {
    if (!class_exists($className, false)) continue;
    if (!method_exists($className, 'detect') && !method_exists($className, 'check')) continue;
    
    echo "测试 {$className}... ";
    
    foreach ($samples as $sampleKey => $sample) {
        $value = $sample['value'];
        
        $start = microtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            try {
                $result = callDetect($className, $value);
            } catch (\Throwable $e) {
                // 跳过调用失败的
            }
        }
        $elapsed = microtime(true) - $start;
        
        $key = $className . '_' . $sampleKey;
        $results[$key] = [
            'class' => $className,
            'sample' => $sample['name'],
            'per_op_us' => round($elapsed * 1000000 / $iterations, 2),
        ];
    }
    echo "完成\n";
}

// 表格输出
echo "\n═══════════════════════════════════════════════════════════════\n";
echo "  性能结果（μs/次 · 2000次平均）\n";
echo "═══════════════════════════════════════════════════════════════\n\n";

echo str_pad('Defense 类', 20);
foreach (['normal', 'normal_long', 'normal_huge', 'sqli', 'xss', 'ssti', 'ldap', 'nosql'] as $k) {
    echo str_pad($samples[$k]['name'], 10);
}
echo "\n" . str_repeat('─', 100) . "\n";

foreach ($defenseClasses as $className) {
    echo str_pad($className, 20);
    foreach (['normal', 'normal_long', 'normal_huge', 'sqli', 'xss', 'ssti', 'ldap', 'nosql'] as $k) {
        $key = $className . '_' . $k;
        $val = isset($results[$key]) ? $results[$key]['per_op_us'] . 'μs' : 'N/A';
        echo str_pad($val, 10);
    }
    echo "\n";
}

// 关键指标：正常请求预筛效率
echo "\n--- 正常请求预筛效率（μs/次，越低越好）---\n";
$normalShort = [];
foreach ($defenseClasses as $className) {
    $key = $className . '_normal';
    if (isset($results[$key])) {
        $normalShort[$className] = $results[$key]['per_op_us'];
    }
}
asort($normalShort);
foreach ($normalShort as $cls => $time) {
    $bar = str_repeat('█', max(1, (int)($time / 2)));
    echo "  " . str_pad($cls, 20) . str_pad($time . ' μs', 12) . $bar . "\n";
}

file_put_contents(__DIR__ . '/test_perf_results.json', json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
echo "\n结果已保存到 test_perf_results.json\n";
