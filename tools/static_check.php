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

$files = array_merge(glob($root . '/*.php') ?: [], glob($root . '/tools/*.php') ?: []);
$failCount = 0;
$warnCount = 0;

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
                            fwrite(STDERR, sprintf(
                                "[FAIL] %s:%d  %s() — %s\n", $file, $line, $text, $FAIL[$fn]
                            ));
                            $failCount++;
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
    "static_check 完成：%d 个文件，FAIL=%d，WARN=%d\n", count($files), $failCount, $warnCount
));

exit($failCount > 0 ? 1 : 0);
