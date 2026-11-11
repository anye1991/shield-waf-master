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
 * 加密发行版 · 极限测试探针（在干净容器的 /app 副本里运行）
 *
 * 与 e2e_encrypted.sh 的「功能验收」不同，这里只往边界和极限上打：
 *   boundary     超大请求体 / 8MB 上限 / 参数数量 / 嵌套深度 / 畸形字节 / 长尾夹带攻击
 *   evasion      多层编码、全角同形字、base64 大小写混淆、注释拆分等深层逃逸
 *   concurrency  多 worker 并发吞吐、延迟分位、并发下是否漏放或误报
 *   soak         持续混合流量长稳，检查 5xx、崩溃、日志噪音
 *   state        限流/熔断的并发状态一致性与冷却恢复
 *
 * 用法：php tools/stress/extreme.php <base_url> <stage> [n] [cc]
 *   例如：php tools/stress/extreme.php http://127.0.0.1:8080 concurrency 600 32
 *
 * 退出码：0 = 本阶段硬性断言全过；非 0 = 存在失败项（明细见 [FAIL] 行）。
 */
declare(strict_types=1);

$base  = rtrim((string)($argv[1] ?? 'http://127.0.0.1:8080'), '/');
$stage = (string)($argv[2] ?? 'all');
$N     = (int)($argv[3] ?? 600);
$CC    = (int)($argv[4] ?? 32);

// ---------------------------------------------------------------- HTTP 探针
final class Probe
{
    private string $base;

    public function __construct(string $base)
    {
        $this->base = rtrim($base, '/');
    }

    /** @return array{0:int,1:string,2:float,3:string} [status, body, ms, err] */
    public function one(array $job, float $timeout = 20.0): array
    {
        $ch = $this->handle($job, $timeout);
        $out = $this->collect($ch, $timeout);
        curl_close($ch);
        return $out;
    }

    /**
     * curl_multi 并发投放。$jobs 为索引数组，返回同索引的结果数组。
     * @return array<int,array{0:int,1:string,2:float,3:string}>
     */
    public function batch(array $jobs, int $cc, float $timeout = 20.0): array
    {
        $results = [];
        $queue   = $jobs;
        $active  = [];
        $mh      = curl_multi_init();

        while ($queue || $active) {
            while (count($active) < $cc && $queue) {
                $i = array_key_first($queue);
                $job = $queue[$i];
                unset($queue[$i]);
                $ch = $this->handle($job, $timeout, (string)$i);
                curl_multi_add_handle($mh, $ch);
                $active[$i] = $ch;
            }
            if (!$active) {
                break;
            }
            do {
                $st = curl_multi_exec($mh, $running);
            } while ($st === CURLM_CALL_MULTI_PERFORM);
            if ($running > 0) {
                curl_multi_select($mh, 0.2);
            }
            while ($info = curl_multi_info_read($mh)) {
                $ch = $info['handle'];
                $idx = (int)curl_getinfo($ch, CURLINFO_PRIVATE);
                $results[$idx] = $this->collect($ch, $timeout);
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($active[$idx]);
            }
        }
        curl_multi_close($mh);
        ksort($results);
        return $results;
    }

    private function handle(array $job, float $timeout, string $tag = ''): CurlHandle
    {
        $method  = (string)($job['method'] ?? 'GET');
        $path    = (string)($job['path'] ?? '/');
        $body    = (string)($job['body'] ?? '');
        $headers = (array)($job['headers'] ?? []);
        $headers[] = 'Expect:';  // 禁掉 100-continue，避免大 body 白等一秒

        $ch = curl_init($this->base . $path);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_HEADER          => true,
            CURLOPT_CUSTOMREQUEST   => $method,
            CURLOPT_HTTPHEADER      => $headers,
            CURLOPT_TIMEOUT_MS      => (int)($timeout * 1000),
            CURLOPT_CONNECTTIMEOUT  => 3,
            CURLOPT_NOSIGNAL        => true,
            CURLOPT_FOLLOWLOCATION  => false,
            CURLOPT_PRIVATE         => $tag,
        ]);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        return $ch;
    }

    /** @return array{0:int,1:string,2:float,3:string} */
    private function collect(CurlHandle $ch, float $timeout): array
    {
        $raw  = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $ms   = (float)curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000;
        $err  = curl_error($ch);
        $body = '';
        if (is_string($raw)) {
            $hs = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $body = substr($raw, $hs);
        }
        if ($code === 0 && $err !== '') {
            return [0, '', $ms, $err];
        }
        return [$code, (string)$body, $ms, ''];
    }
}

// ---------------------------------------------------------------- 输出助手
$GLOBALS['__fails'] = 0;
function out(string $s): void { echo $s, PHP_EOL; }
function ok(string $s): void  { out('  [OK]   ' . $s); }
function no(string $s): void  { out('  [FAIL] ' . $s); $GLOBALS['__fails']++; }
function info(string $s): void { out('  [INFO] ' . $s); }
function pct(array $v, float $p): float
{
    if (!$v) { return 0.0; }
    sort($v);
    $i = (int)ceil($p / 100 * count($v)) - 1;
    return round($v[max(0, $i)], 2);
}
function summarize(string $title, array $rows, float $wall): void
{
    $times = array_column($rows, 'ms');
    $codes = [];
    $err = 0;
    foreach ($rows as $r) {
        $codes[$r['st']] = ($codes[$r['st']] ?? 0) + 1;
        if ($r['st'] === 0 || $r['st'] >= 500) { $err++; }
    }
    ksort($codes);
    $dist = [];
    foreach ($codes as $k => $v) { $dist[] = "$k:$v"; }
    info(sprintf(
        '%s | 请求 %d | 耗时 %.2fs | 吞吐 %.1f req/s | P50 %.1fms P95 %.1fms P99 %.1fms MAX %.1fms | 状态 %s | 异常 %d',
        $title, count($rows), $wall, $wall > 0 ? count($rows) / $wall : 0,
        pct($times, 50), pct($times, 95), pct($times, 99), $times ? round(max($times), 2) : 0,
        implode(' ', $dist), $err
    ));
}

/** @return array{0:int,1:string,2:float,3:string} */
function fire(Probe $p, array $job, float $timeout = 20.0): array
{
    return $p->one($job, $timeout);
}

$p = new Probe($base);

// =========================================================================
// 1. boundary —— 体积 / 数量 / 畸形 / 长尾夹带
// =========================================================================
function stageBoundary(Probe $p): void
{
    out('== 阶段 1：边界与畸形输入 ==');
    $cases = [];
    $add = static function (string $label, string $method, string $path, string $body, array $hdr, array $expect, float $to = 25.0) use (&$cases): void {
        $cases[] = compact('label', 'method', 'path', 'body', 'hdr', 'expect', 'to');
    };
    $form = ['Content-Type: application/x-www-form-urlencoded'];

    // 体积梯度（良性文本，期望 200；若安全侧直接 413 亦属可接受的保守行为）
    $filler = str_repeat('The quick brown fox jumps over the lazy dog. ', 32); // ~1.4KB
    foreach ([1024, 65536, 1048576, 4194304] as $sz) {
        $v = substr(str_repeat($filler, (int)ceil($sz / strlen($filler))), 0, $sz);
        $add("良性大文本 {$sz}B", 'POST', '/', 'q=' . rawurlencode($v), $form, [200, 413], 30.0);
    }
    // 8MB 上限两侧：超限必须 413（fail-closed），绝不能 5xx 或 200 放行
    $near = str_repeat('a', 8380000);
    $add('临界 8MB 以下', 'POST', '/', 'q=' . $near, $form, [200, 413], 40.0);
    $over = str_repeat('a', 8388608);
    $add('超过 8MB 上限', 'POST', '/', 'q=' . $over, $form, [413], 40.0);
    $add('16MB 巨型请求', 'POST', '/', 'q=' . str_repeat('a', 16777216), $form, [413], 45.0);

    // 攻击夹在超长文本尾部 —— 检出不能被长度截断吃掉
    foreach ([65536, 1048576] as $sz) {
        $v = substr(str_repeat($filler, (int)ceil($sz / strlen($filler))), 0, $sz);
        $add("长尾 XSS @{$sz}B", 'POST', '/', 'q=' . rawurlencode($v . '<script>alert(1)</script>'), $form, [403], 35.0);
        $add("长尾 SQLi @{$sz}B", 'POST', '/', 'q=' . rawurlencode($v . "' OR 1=1--"), $form, [403], 35.0);
    }

    // 参数数量极限
    foreach ([100, 1000, 5000] as $n) {
        $parts = [];
        for ($i = 0; $i < $n; $i++) { $parts[] = "p$i=" . $i; }
        $add("参数数量 $n", 'POST', '/', implode('&', $parts), $form, [200, 413], 35.0);
    }
    // 深度嵌套（内核 encodePayloadValue 深度上限 64）
    $deep = 'v=' . rawurlencode(str_repeat('[', 70) . '1' . str_repeat(']', 70));
    $add('嵌套深度 70', 'POST', '/', $deep, $form, [200, 403, 413], 25.0);

    // 超长 query / 畸形字节
    $add('超长 query 64KB', 'GET', '/?q=' . str_repeat('a', 65536), '', [], [200, 400, 403, 413, 414], 25.0);
    $add('NUL 字节', 'POST', '/', "q=a%00b", $form, [200, 403], 20.0);
    $add('非法 UTF-8', 'POST', '/', 'q=' . rawurlencode("abc\xFF\xFE\x80def"), $form, [200, 403], 20.0);
    $add('CRLF 注入', 'GET', '/?q=' . rawurlencode("x\r\nSet-Cookie: admin=1"), '', [], [403], 20.0);
    $add('空 body POST', 'POST', '/', '', $form, [200], 20.0);

    // 管理面在极端输入下不能被打挂
    // 控制台未带密钥时返回 403 属预期（未授权），只有 5xx 才算被打挂
    $add('控制台存活', 'GET', '/waf-console', '', [], [200, 403], 20.0);

    foreach ($cases as $c) {
        [$st, $body, $ms, $err] = fire($p, [
            'method' => $c['method'], 'path' => $c['path'], 'body' => $c['body'],
            'headers' => $c['hdr'],
        ], $c['to']);
        $want = $c['expect'];
        $good = in_array($st, $want, true);
        $txt = sprintf('%-24s 期望 %s 实得 %s  %.0fms%s', $c['label'], implode('/', $want), $st, $ms, $err ? " err={$err}" : '');
        if ($good) { ok($txt); } else { no($txt . ' body=' . substr(trim(preg_replace('/\s+/', ' ', strip_tags($body))), 0, 80)); }
        // 任何 500+ 都是硬性缺陷
        if ($st >= 500) { no('  ↳ 服务端错误：' . $c['label']); }
    }
}

// =========================================================================
// 2. evasion —— 深层编码 / 混淆逃逸
// =========================================================================
function stageEvasion(Probe $p): void
{
    out('== 阶段 2：深度混淆逃逸（期望一律拦截） ==');
    $enc = static fn(string $s): string => rawurlencode($s);
    $nEnc = static function (string $s, int $n) use ($enc): string {
        for ($i = 0; $i < $n; $i++) { $s = $enc($s); }
        return $s;
    };
    $swap = static fn(string $s): string => strtr($s,
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
    $fw = static function (string $s): string {
        $o = '';
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $c = ord($s[$i]);
            if ($c >= 65 && $c <= 90)      { $o .= mb_chr(0xFF21 + $c - 65, 'UTF-8'); }
            elseif ($c >= 97 && $c <= 122) { $o .= mb_chr(0xFF41 + $c - 97, 'UTF-8'); }
            else                           { $o .= $s[$i]; }
        }
        return $o;
    };
    $entities = static fn(string $s): string => str_replace(
        ['<', '>', '"', "'", '(', ')'], ['&lt;', '&gt;', '&quot;', '&#39;', '&#40;', '&#41;'], $s);

    $payloads = [
        'SQLi union'        => "1' union select user,password from users--",
        'SQLi tautology'    => "1' or '1'='1",
        'XSS script'        => '<script>alert(1)</script>',
        'XSS img onerror'   => '<img src=x onerror=alert(1)>',
        'Path traversal'    => '../../../etc/passwd',
        'Cmd injection'     => ';cat /etc/shadow',
        'SSTI'              => '{{7*7}}',
        'JNDI'              => '${jndi:ldap://x/a}',
        'PHP deserialize'   => 'O:4:"User":2:{s:4:"name";s:3:"abc";s:3:"age";i:1;}',
        'XXE'               => '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        'CRLF'              => "x\r\nSet-Cookie: admin=1",
    ];

    // hard=true 属于「业务端可还原」的有效绕过，漏放必须判失败；
    // hard=false（b64 全部大写/小写）信息已不可逆，业务端自己都解不回来，
    // 只记录不判失败，避免把无效变异当成产品缺陷。
    $cases = [];
    foreach ($payloads as $label => $raw) {
        $b64 = base64_encode($raw);
        $defs = [
            'asis'        => [$raw, true],
            'url x1'      => [$enc($raw), true],
            'url x2'      => [$nEnc($raw, 2), true],
            'url x4'      => [$nEnc($raw, 4), true],
            'upper'       => [strtoupper($raw), true],
            'fullwidth'   => [$fw($raw), true],
            'html entity' => [$entities($raw), true],
            'mixed'       => [$nEnc($fw($entities($raw)), 2), true],
            'comment'     => [str_replace(' ', '/**/', $raw), true],
            'nul tail'    => [$raw . "\0", true],
            'b64'         => [$b64, true],
            'b64 flip'    => [$swap($b64), true],
            'b64+url'     => [$enc($swap($b64)), true],
            'b64 upper'   => [strtoupper($b64), false],
            'b64 lower'   => [strtolower($b64), false],
        ];
        foreach ($defs as $vn => [$v, $hard]) {
            $cases["$label / $vn"] = ['v' => $v, 'hard' => $hard];
        }
    }

    // 投放层统一 URL 编码一次：保证 curl 不会因为空格/换行/全角字符直接拒绝 URL，
    // 也与真实浏览器行为一致（所有向量在同一基准上比较）。
    $rows = [];
    foreach ($cases as $label => $c) {
        $rows[] = ['label' => $label, 'hard' => $c['hard'], 'method' => 'GET',
                   'path' => '/?q=' . rawurlencode($c['v']), 'body' => '', 'headers' => [], 'timeout' => 20.0];
    }
    $t0 = microtime(true);
    $res = $p->batch($rows, 24);
    $wall = microtime(true) - $t0;
    $stat = [];
    $miss = 0;
    $hard = 0;
    $soft = 0;
    foreach ($rows as $i => $j) {
        [$st, $body, $ms, $err] = $res[$i] ?? [0, '', 0, 'no result'];
        $stat[$st] = ($stat[$st] ?? 0) + 1;
        $blocked = in_array($st, [400, 403, 413, 429, 502], true);
        if ($j['hard']) { $hard++; } else { $soft++; }
        if (!$j['hard']) {
            continue; // 不可逆变异只做记录
        }
        if (!$blocked) {
            $miss++;
            no(sprintf('%-34s 实得 %s (%.0fms)%s', $j['label'], $st, $ms, $err ? " err=$err" : ''));
        } elseif ($st >= 500 && $st !== 502) {
            no(sprintf('%-34s 服务端错误 %s', $j['label'], $st));
        }
    }
    ksort($stat);
    $d = [];
    foreach ($stat as $k => $v) { $d[] = "$k:$v"; }
    info(sprintf('%d 条向量（有效绕过 %d / 不可逆变异 %d）| 有效绕过漏放 %d | %.2fs | 状态 %s',
        count($rows), $hard, $soft, $miss, $wall, implode(' ', $d)));
    if ($miss === 0) { ok('深层混淆全部被拦截'); } else { no("存在 $miss 条有效绕过漏放"); }
    summarize('evasion', array_map(static fn($r) => ['ms' => $r[2], 'st' => $r[0]], array_values($res)), $wall);
}

// =========================================================================
// 3. concurrency —— 并发吞吐 / 延迟分位 / 并发下判定一致性
// =========================================================================
function mixedJob(int $i): array
{
    $r = $i % 10;
    if ($r < 7) {
        return ['kind' => 'benign', 'method' => 'GET', 'path' => '/?id=' . $i . '&q=hello', 'body' => '', 'headers' => []];
    }
    $atk = [
        "/?q=" . rawurlencode('<script>alert(1)</script>'),
        "/?id=" . rawurlencode("1' OR 1=1--"),
        "/?p=" . rawurlencode('../../etc/passwd'),
    ];
    return ['kind' => 'attack', 'method' => 'GET', 'path' => $atk[$i % 3], 'body' => '', 'headers' => []];
}

function runMixed(Probe $p, int $n, int $cc, string $title): array
{
    $jobs = [];
    for ($i = 0; $i < $n; $i++) {
        $j = mixedJob($i);
        // 分散来源 IP，避免行为态（攻击链）把后续良性请求连带拦掉
        $j['headers'][] = 'X-Forwarded-For: 10.' . ($i % 200) . '.' . (($i * 7) % 200) . '.' . (($i * 13) % 200);
        $jobs[$i] = $j;
    }
    $t0 = microtime(true);
    $res = $p->batch($jobs, $cc, 20.0);
    $wall = microtime(true) - $t0;

    $rows = [];
    $bad5xx = $fp = $miss = $neterr = 0;
    foreach ($jobs as $i => $j) {
        [$st, $body, $ms, $err] = $res[$i] ?? [0, '', 0, 'no result'];
        $rows[] = ['ms' => $ms, 'st' => $st];
        if ($st === 0) { $neterr++; continue; }
        if ($st >= 500 && $st !== 502) { $bad5xx++; continue; }
        if ($j['kind'] === 'benign' && $st !== 200) { $fp++; }
        if ($j['kind'] === 'attack' && $st !== 403 && $st !== 429) { $miss++; }
    }
    summarize($title, $rows, $wall);
    info(sprintf('  判定一致性 | 5xx %d | 网络错误 %d | 良性误拦 %d | 攻击漏放 %d', $bad5xx, $neterr, $fp, $miss));
    if ($bad5xx === 0) { ok('并发下无 5xx'); } else { no("并发下出现 $bad5xx 次 5xx"); }
    if ($neterr === 0) { ok('并发下无连接失败/超时'); } else { no("并发下 $neterr 次连接失败或超时"); }
    if ($fp === 0)     { ok('并发下良性零误拦'); } else { no("并发下良性被拦 $fp 次"); }
    if ($miss === 0)   { ok('并发下攻击零漏放'); } else { no("并发下攻击漏放 $miss 次"); }
    return $rows;
}

function stageConcurrency(Probe $p, int $n, int $cc): void
{
    out('== 阶段 3：并发极限 ==');
    foreach ([16, 32, 64] as $c) {
        out("-- 并发 $c / 请求 $n --");
        runMixed($p, $n, $c, "cc=$c");
    }
    out("-- 指定并发 {$cc} / 请求 {$n}（复测）--");
    runMixed($p, $n, $cc, "cc=$cc");
}

// =========================================================================
// 4. soak —— 持续混合流量
// =========================================================================
function stageSoak(Probe $p, int $cc): void
{
    out('== 阶段 4：持续混合流量（20s） ==');
    $deadline = microtime(true) + 20.0;
    $round = 0;
    $all = [];
    while (microtime(true) < $deadline) {
        $res = runMixed($p, 200, $cc, 'soak r' . (++$round));
        $all = array_merge($all, $res);
    }
    summarize('soak 总计', $all, 20.0);
}

// =========================================================================
// 5. state —— 限流状态并发一致性与恢复
// =========================================================================
function stageState(Probe $p, string $logDir): void
{
    out('== 阶段 5：限流 / 熔断状态一致性 ==');
    $jobs = [];
    for ($i = 0; $i < 400; $i++) {
        $jobs[$i] = ['method' => 'GET', 'path' => '/?burst=' . $i, 'body' => '', 'headers' => []];
    }
    $t0 = microtime(true);
    $res = $p->batch($jobs, 48, 20.0);
    $wall = microtime(true) - $t0;
    $cnt = [];
    foreach ($res as $r) { $cnt[$r[0]] = ($cnt[$r[0]] ?? 0) + 1; }
    ksort($cnt);
    $d = [];
    foreach ($cnt as $k => $v) { $d[] = "$k:$v"; }
    info(sprintf('400 次突发 %.2fs | 状态 %s', $wall, implode(' ', $d)));
    if (($cnt[429] ?? 0) > 0 || ($cnt[502] ?? 0) > 0) {
        ok('突发触发限流/熔断');
    } else {
        no('突发未触发任何限流（状态可能未生效）');
    }

    $stateFile = rtrim($logDir, '/') . '/ysl/qps_state.json';
    if (is_file($stateFile)) {
        $raw = (string)file_get_contents($stateFile);
        $j = json_decode($raw, true);
        if (is_array($j)) {
            ok('并发写入后状态文件仍是合法 JSON（' . strlen($raw) . ' 字节）');
        } else {
            no('并发写入把状态文件写坏了：' . substr($raw, 0, 120));
        }
    } else {
        info('状态文件不在预期路径（可能走了 tmpfs 兜底），跳过结构校验');
    }

    // 冷却后必须能自行恢复，不能永久 502
    out('  等待 6s 让滑动窗口清空…');
    sleep(6);
    $probe = [];
    for ($i = 0; $i < 10; $i++) {
        $probe[$i] = ['method' => 'GET', 'path' => '/?recover=' . $i, 'body' => '', 'headers' => []];
    }
    $rr = $p->batch($probe, 2, 10.0);
    $codes = array_map(static fn($r) => $r[0], $rr);
    info('冷却后 10 次探测状态：' . implode(',', $codes));
    if (in_array(200, $codes, true)) {
        ok('限流/熔断可自行恢复（存在 200）');
    } else {
        no('冷却后仍未恢复 200，存在永久拒绝风险');
    }
}

// =========================================================================
// P. profile —— 长度-耗时曲线（诊断用，判失败不影响其他阶段）
// =========================================================================
function stageProfile(Probe $p): void
{
    out('== 阶段 P：长度-耗时曲线（诊断，找分析管线爆炸点） ==');
    $filler = str_repeat('The quick brown fox jumps over the lazy dog. ', 32);
    $form = ['Content-Type: application/x-www-form-urlencoded'];
    foreach ([512, 2048, 8192, 16384, 32768, 65536, 131072, 262144] as $sz) {
        $v = substr(str_repeat($filler, (int)ceil($sz / strlen($filler))), 0, $sz);
        [$st1, , $ms1, $e1] = fire($p, [
            'method' => 'POST', 'path' => '/', 'body' => 'q=' . rawurlencode($v), 'headers' => $form,
        ], 20.0);
        [$st2, , $ms2, $e2] = fire($p, [
            'method' => 'POST', 'path' => '/', 'body' => 'q=' . $v, 'headers' => $form,
        ], 20.0);
        info(sprintf(
            '%-7s B | 含%%20：HTTP %-3s %8.1fms %-4s | 纯文本：HTTP %-3s %8.1fms %s',
            $sz, $st1, $ms1, $e1 ? 'TIMEOUT' : '', $st2, $ms2, $e2 ? 'TIMEOUT' : ''
        ));
    }
}

// ---------------------------------------------------------------- 调度
$stages = $stage === 'all'
    ? ['boundary', 'evasion', 'concurrency', 'soak', 'state']
    : [$stage];

foreach ($stages as $s) {
    switch ($s) {
        case 'boundary':    stageBoundary($p); break;
        case 'evasion':     stageEvasion($p); break;
        case 'concurrency': stageConcurrency($p, $N, $CC); break;
        case 'soak':        stageSoak($p, $CC); break;
        case 'profile':     stageProfile($p); break;
        case 'state':
            $dir = getenv('WAF_LOG_DIR') ?: '/app/var/logs';
            stageState($p, $dir);
            break;
        default:
            no("未知阶段：$s");
    }
}

out('== 汇总 ==');
if ($GLOBALS['__fails'] === 0) {
    out('  RESULT: PASS（本阶段所有硬性断言通过）');
    exit(0);
}
out(sprintf('  RESULT: FAIL（%d 项硬性断言未通过）', $GLOBALS['__fails']));
exit(1);
