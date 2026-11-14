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
 * YSL语枢-盾甲WAF · 静态安全检查（CI 用）
 *
 * 对应 OpenSSF 准则 static_analysis_common_vulnerabilities / coding_standards_enforced。
 * 基于 PHP tokenizer 的规则扫描：只分析「代码位置」的调用（字符串字面量与注释
 * 不参与匹配，避免误伤 WAF 检测规则与测试载荷）。
 *
 * 扫描范围：仓库根 *.php 与 tools/*.php（明文生产代码）。
 *   tests/ 不纳入 FAIL 规则：测试文件刻意包含攻击载荷与随机数采样（非安全用途），
 *   其正确性由动态执行（tests/ 套件）验证。
 *
 * FAIL：命中即退出码 1（阻断 CI）。
 * WARN：仅提示，不阻断（需人工复核确认非安全用途）。
 */
declare(strict_types=1);

$root = dirname(__DIR__);

/** FAIL 规则：代码位置调用即违规 */
$FAIL = [
    'eval'           => 'eval() 是最高危构造，禁止出现在生产路径',
    'create_function'=> 'create_function() 已废弃且等效 eval()',
    'shell_exec'     => 'shell_exec() 禁止，命令执行请走白名单包装',
    'system'         => 'system() 禁止，命令执行请走白名单包装',
    'exec'           => 'exec() 禁止，命令执行请走白名单包装',
    'passthru'       => 'passthru() 禁止，命令执行请走白名单包装',
    'proc_open'      => 'proc_open() 禁止，命令执行请走白名单包装',
    'pcntl_exec'     => 'pcntl_exec() 禁止',
    'popen'          => 'popen() 禁止',
    'rand'           => 'rand() 非加密安全，涉及随机性请用 random_int()/random_bytes()',
    'mt_rand'        => 'mt_rand() 非加密安全，涉及随机性请用 random_int()/random_bytes()',
];

/** WARN 规则：需人工确认非安全用途 */
$WARN = [
    'uniqid'  => 'uniqid() 非加密安全；用于请求 ID 采样可接受，用于令牌/口令不可接受',
    'assert'  => 'assert() 生产路径禁用（PHP7+ 默认不执行，仍建议移除）',
];

/**
 * 可「显式审计豁免」的函数白名单（仅命令执行族）。
 * 这些函数在命令完全由固定映射构造、参数经 escapeshellarg()/(int) 强转、
 * 不含任何原始用户输入时是合规的（见 control.php 的三处 DNA 动作）。
 * eval/create_function/pcntl_exec/rand/mt_rand 永不豁免——规则牙齿不能被拔掉。
 *
 * 豁免不是按文件/行号硬编码（一改行号就失效），而是要求调用处写明：
 *     // waf-audited:exec: <经复核的理由>
 * 标记位于调用行本身或其紧邻上一行，且必须带非空理由、函数名精确匹配。
 * 因此**任何新增的裸 exec() 依旧 FAIL**，CI 的检测强度不变，只是把
 * 已人工复核的合规调用从 FAIL 降级为可见的 AUDIT 记录。
 */
$EXEMPTABLE = ['exec', 'system', 'shell_exec', 'passthru', 'proc_open', 'popen'];
$AUDIT_MARKER = 'waf-audited:';

/** 预扫描：收集每个文件的审计豁免标记 → [$file][$line][$fn] = 理由 */
$exempt = [];
foreach (array_merge(glob($root . '/*.php') ?: [], glob($root . '/tools/*.php') ?: []) as $f) {
    $s = @file_get_contents($f);
    if ($s === false || $s === '' || strpos($s, $AUDIT_MARKER) === false) { continue; }
    foreach (@token_get_all($s) as $t) {
        if (!is_array($t) || ($t[0] !== T_COMMENT && $t[0] !== T_DOC_COMMENT)) { continue; }
        $p = strpos($t[1], $AUDIT_MARKER);
        if ($p === false) { continue; }
        // 格式：waf-audited:<fn>[,<fn>...]: <理由>   理由必须非空
        $spec = trim(substr($t[1], $p + strlen($AUDIT_MARKER)));
        if (!str_contains($spec, ':')) { continue; }
        [$fnList, $reason] = explode(':', $spec, 2);
        $reason = trim($reason);
        if ($reason === '') { continue; }
        foreach (explode(',', $fnList) as $fn) {
            $fn = strtolower(trim($fn));
            if (!in_array($fn, $EXEMPTABLE, true)) { continue; }
            // 标记写在行尾（同行）或上一行都生效
            foreach ([$t[2], $t[2] + 1] as $L) {
                $exempt[$f][$L][$fn] = $reason;
            }
        }
    }
}

$files = array_merge(glob($root . '/*.php') ?: [], glob($root . '/tools/*.php') ?: []);
$failCount = 0;
$warnCount = 0;
$auditCount = 0;

foreach ($files as $file) {
    $src = file_get_contents($file);
    if ($src === false || $src === '') {
        continue;
    }
    $tokens = @token_get_all($src);
    if ($tokens === []) {
        continue;
    }
    $n = count($tokens);
    $prevMeaningful = ''; // 上一个有意义的 token 文本（->, ::, function, new 等）
    $line = 1;

    for ($i = 0; $i < $n; $i++) {
        $tok = $tokens[$i];

        if (is_array($tok)) {
            $id = $tok[0];
            $text = $tok[1];
            if (isset($tok[2])) {
                $line = $tok[2];
            }
            if ($id === T_WHITESPACE || $id === T_COMMENT || $id === T_DOC_COMMENT) {
                continue;
            }

            // 识别「标识符 + 紧随 (」= 函数调用候选
            if ($id === T_STRING || $id === T_EVAL) {
                $j = $i + 1;
                while ($j < $n && is_array($tokens[$j])
                    && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $j++;
                }
                $next = $tokens[$j] ?? null;
                if ($next === '(') {
                    $fn = strtolower($text);
                    // 方法/静态调用、函数定义、new 不视为全局函数调用
                    $isMember = in_array($prevMeaningful, ['->', '::', 'function', 'new'], true);
                    if (!$isMember) {
                        if (isset($FAIL[$fn])) {
                            $reason = $exempt[$file][$line][$fn] ?? null;
                            if ($reason !== null) {
                                fwrite(STDERR, sprintf(
                                    "[AUDIT] %s:%d  %s() — 显式审计豁免：%s\n",
                                    $file, $line, $text, $reason
                                ));
                                $auditCount++;
                            } else {
                                fwrite(STDERR, sprintf(
                                    "[FAIL] %s:%d  %s() — %s\n", $file, $line, $text, $FAIL[$fn]
                                ));
                                $failCount++;
                            }
                        } elseif (isset($WARN[$fn])) {
                            fwrite(STDERR, sprintf(
                                "[WARN] %s:%d  %s() — %s\n", $file, $line, $text, $WARN[$fn]
                            ));
                            $warnCount++;
                        }
                    }
                }
            }
            $prevMeaningful = $text;
        } else {
            // 单字符 token（括号、运算符等）
            $prevMeaningful = $tok;
        }
    }
}

fwrite(STDERR, sprintf(
    "static_check 完成：%d 个文件，FAIL=%d，AUDIT=%d，WARN=%d\n",
    count($files), $failCount, $auditCount, $warnCount
));

exit($failCount > 0 ? 1 : 0);
