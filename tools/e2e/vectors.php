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
 * 加密发行版 · 端到端验收向量
 *
 * 不依赖 curl 扩展，纯 stream 发真实 HTTP 请求，逐条断言「应拦的拦、应放的放」。
 * 用法：php tools/e2e/vectors.php <base_url> <console_key>
 */
declare(strict_types=1);

$base = rtrim((string)($argv[1] ?? 'http://127.0.0.1:8080'), '/');
$key  = (string)($argv[2] ?? '');

/**
 * @return array{0:int,1:string,2:float}
 */
function req(string $url, array $o = []): array
{
    $method  = $o['method'] ?? 'GET';
    $body    = $o['body'] ?? '';
    $headers = $o['headers'] ?? [];
    $hdr = "Content-Type: application/x-www-form-urlencoded\r\nAccept: */*\r\n";
    foreach ($headers as $k => $v) {
        $hdr .= $k . ': ' . $v . "\r\n";
    }
    $ctx = stream_context_create(['http' => [
        'method'          => $method,
        'header'          => $hdr,
        'content'         => $body,
        'ignore_errors'   => true,
        'timeout'         => 15,
        'follow_location' => 0,
    ]]);
    $t0  = microtime(true);
    $out = @file_get_contents($url, false, $ctx);
    $ms  = (microtime(true) - $t0) * 1000;

    $status = 0;
    $lines  = $http_response_header ?? [];
    if (isset($lines[0]) && preg_match('#HTTP/\S+\s+(\d{3})#', $lines[0], $m)) {
        $status = (int)$m[1];
    }
    return [$status, (string)$out, $ms];
}

$pass = 0;
$fail = 0;
$soft = 0;
$rows = [];

/**
 * @param int|int[] $expect
 * @param bool $soft 软性用例：只记录不判失败（缺对应插件时属预期）
 */
function check(string $name, string $url, $expect, array $o = [], ?string $must = null, bool $soft = false): void
{
    global $pass, $fail, $soft, $rows;
    [$st, $body, $ms] = req($url, $o);
    $want = (array)$expect;
    $ok = in_array($st, $want, true);
    if ($ok && $must !== null && !str_contains($body, $must)) {
        $ok = false;
    }
    if ($soft) {
        $soft++;
        $rows[] = ['t' => 'INFO', 'name' => $name, 'got' => $st, 'want' => implode('/', $want), 'ms' => $ms];
        return;
    }
    $ok ? $pass++ : $fail++;
    $rows[] = [
        't'    => $ok ? 'PASS' : 'FAIL',
        'name' => $name,
        'got'  => $st,
        'want' => implode('/', $want),
        'ms'   => $ms,
        'snip' => trim(preg_replace('/\s+/u', ' ', mb_substr(strip_tags($body), 0, 46)) ?? ''),
    ];
}

$enc = 'application/x-www-form-urlencoded';

// ---------------------------------------------------------------- 放行面
check('正常首页', $base . '/', 200, [], '已加载');
check('正常查询参数', $base . '/?page=2&kw=' . rawurlencode('防火墙'), 200);
check('正常中文搜索', $base . '/?q=' . rawurlencode('服务器安全防护'), 200);
check('正常文章路径', $base . '/article/2026/11/' . rawurlencode('安全周报'), 200);

// ---------------------------------------------------------------- 拦截面
check('SQL 注入（引号闭合）', $base . '/?id=' . rawurlencode("1' OR '1'='1"), 403);
check('SQL 注入（UNION）', $base . '/?id=' . rawurlencode('1 UNION SELECT user,pass FROM admin'), 403);
check('XSS（script 标签）', $base . '/?q=' . rawurlencode('<script>alert(1)</script>'), 403);
check('XSS（事件属性）', $base . '/?q=' . rawurlencode('<img src=x onerror=alert(1)>'), 403);
check('路径穿越', $base . '/?file=' . rawurlencode('../../../../etc/passwd'), 403);
check('命令注入', $base . '/?cmd=' . rawurlencode(';cat /etc/passwd'), 403);
check('命令注入（反引号）', $base . '/?host=' . rawurlencode('`id`'), 403);
check('模板注入', $base . '/?tpl=' . rawurlencode('${7*7}{{7*7}}'), 403);
check('POST 表单注入', $base . '/', 403, [
    'method'  => 'POST',
    'body'    => http_build_query(['username' => "admin'--", 'password' => 'x']),
    'headers' => ['Content-Type' => $enc],
]);
check('POST XSS', $base . '/', 403, [
    'method'  => 'POST',
    'body'    => http_build_query(['comment' => '<svg/onload=alert(document.cookie)>']),
    'headers' => ['Content-Type' => $enc],
]);
check('POST 路径穿越', $base . '/', 403, [
    'method'  => 'POST',
    'body'    => http_build_query(['path' => '../../../etc/shadow']),
    'headers' => ['Content-Type' => $enc],
]);

// ---------------------------------------------------------------- 软性：依赖未随开源版分发的 security 插件
check('扫描器 UA（需 security 插件）', $base . '/', [200, 403], [
    'headers' => ['User-Agent' => 'sqlmap/1.7.2#stable'],
], null, true);

// ---------------------------------------------------------------- 管理面
check('控制台无 key', $base . '/waf-console', 403);
check('控制台错误 key', $base . '/waf-console?key=deadbeef', 403);
check('控制台正确 key', $base . '/waf-console?key=' . rawurlencode($key), 200, [], '控制台');
check('态势大屏', $base . '/waf-screen?key=' . rawurlencode($key), 200, [], '态势');
check('大屏 JSON 数据', $base . '/waf-screen?key=' . rawurlencode($key) . '&format=json', 200);

// ---------------------------------------------------------------- 延迟采样
$lat = [];
for ($i = 0; $i < 100; $i++) {
    [, , $ms] = req($base . '/?page=' . $i);
    $lat[] = $ms;
}
sort($lat);
$pick = static fn(float $q): float => $lat[(int)floor((count($lat) - 1) * $q)];

// ---------------------------------------------------------------- 输出
printf("%s\n", str_pad('结果', 8) . str_pad('用例', 32) . str_pad('实得', 8) . str_pad('期望', 8) . '耗时ms');
printf("%s\n", str_repeat('-', 68));
foreach ($rows as $r) {
    printf(
        "%s\n",
        str_pad($r['t'], 8)
        . str_pad($r['name'], 32)
        . str_pad((string)$r['got'], 8)
        . str_pad($r['want'], 8)
        . number_format($r['ms'], 1)
    );
}
printf("%s\n", str_repeat('-', 68));
printf(
    "通过 %d / %d，失败 %d%s\n",
    $pass,
    $pass + $fail,
    $fail,
    $soft > 0 ? sprintf('（另有 %d 项软性用例仅记录）', $soft) : ''
);
printf(
    "延迟（100 次正常请求，含网络往返）：P50 %.1f ms / P95 %.1f ms / 最大 %.1f ms\n",
    $pick(0.50),
    $pick(0.95),
    $lat[count($lat) - 1]
);

if ($fail > 0) {
    echo "\n失败详情：\n";
    foreach ($rows as $r) {
        if ($r['t'] === 'FAIL') {
            printf("  - %s：期望 %s，实得 %s，正文「%s」\n", $r['name'], $r['want'], $r['got'], $r['snip']);
        }
    }
}

exit($fail > 0 ? 1 : 0);
