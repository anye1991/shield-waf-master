<?php
$file = '/workspace/shield-waf-master/src/Semantic/AdversarialDefense.php';
$content = file_get_contents($file);

// 第一步：把normalizeHomoglyphs和normalizeMathChar函数删掉（用strtr方式更好）
$funcStart = strpos($content, '    /**
     * 同形字归一化：静态映射 + 数学字母动态计算 + 全角半角转换
     */');
$funcEnd = strpos($content, '    /** 解码UTF-8超集编码（2字节序列表示的ASCII字符，路径遍历常用绕过） */');

if ($funcStart !== false && $funcEnd !== false) {
    $before = substr($content, 0, $funcStart);
    $after = substr($content, $funcEnd);
    $content = $before . $after;
    echo "删除normalizeHomoglyphs和normalizeMathChar成功\n";
}

// 第二步：生成数学字母映射的PHP代码，添加到$homoglyph_map里
// 找到 $homoglyph_map 的结束位置
$mapEndPos = strpos($content, '    ];', strpos($content, 'private static $homoglyph_map'));
if ($mapEndPos === false) {
    echo "找不到映射表结束位置\n";
    exit(1);
}

// 生成数学字母数字映射代码
$mathCode = "\n        // === 4. 数学字母数字符号（动态生成，约1000字符） ===\n";

// 4a. 数学粗体 A-Z, a-z (连续)
$mathCode .= "        // 粗体 Bold\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D400 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D41A + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4b. 数学斜体 (h缺)
$mathCode .= "        // 斜体 Italic (h缺)\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D434 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
// 小写斜体，h缺(U+1D455)，h之后偏移-1
for ($i = 0; $i < 26; $i++) {
    $letter = chr(ord('a') + $i);
    if ($i < 7) { // a-g
        $cp = 0x1D44E + $i;
    } elseif ($i === 7) { // h 缺失，跳过
        continue;
    } else { // i-z
        $cp = 0x1D44E + $i + 1; // +1跳过h的空缺
    }
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4c. 粗斜体 (连续)
$mathCode .= "        // 粗斜体 Bold Italic\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D468 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D482 + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4d. 手写体 Script (手写体大写很多空缺，小写连续)
$mathCode .= "        // 手写体 Script (大写有缺，小写连续)\n";
$scriptUpper = [
    0x1D49C => 'A', 0x1D49E => 'B', 0x1D4A0 => 'C', 0x1D4A2 => 'D',
    0x1D4A5 => 'E', 0x1D4A6 => 'F', 0x1D4A7 => 'G', 0x1D4A8 => 'H',
    0x1D4A9 => 'I', 0x1D4AA => 'J', 0x1D4AB => 'K', 0x1D4AC => 'L',
    0x1D4AE => 'M', 0x1D4AF => 'N', 0x1D4B0 => 'O', 0x1D4B1 => 'P',
    0x1D4B2 => 'Q', 0x1D4B3 => 'R', 0x1D4B4 => 'S', 0x1D4B5 => 'T',
    0x1D4B6 => 'U', 0x1D4B7 => 'V', 0x1D4B8 => 'W', 0x1D4B9 => 'X',
    0x1D4BA => 'Y', 0x1D4BB => 'Z',
];
$count = 0;
foreach ($scriptUpper as $cp => $letter) {
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    $count++;
    if ($count % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D4BC + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4e. 粗手写 Bold Script (h缺)
$mathCode .= "        // 粗手写 Bold Script (h缺)\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D4D6 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $letter = chr(ord('a') + $i);
    if ($i < 7) {
        $cp = 0x1D4F0 + $i;
    } elseif ($i === 7) continue;
    else {
        $cp = 0x1D4F0 + $i + 1;
    }
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4f. Fraktur (大写有缺，小写连续)
$mathCode .= "        // Fraktur 双线体 (大写有缺，小写连续)\n";
$frakturUpper = [
    0x1D504 => 'A', 0x1D505 => 'B', 0x1D507 => 'D',
    0x1D508 => 'E', 0x1D509 => 'F', 0x1D50A => 'G', 0x1D50B => 'H',
    0x1D50C => 'I', 0x1D50D => 'J', 0x1D50E => 'K', 0x1D50F => 'L',
    0x1D510 => 'M', 0x1D511 => 'N', 0x1D512 => 'O', 0x1D513 => 'P',
    0x1D514 => 'Q', 0x1D515 => 'R', 0x1D516 => 'S', 0x1D517 => 'T',
    0x1D518 => 'U', 0x1D519 => 'V', 0x1D51A => 'W', 0x1D51B => 'X',
    0x1D51C => 'Y', 0x1D51D => 'Z',
];
$count = 0;
foreach ($frakturUpper as $cp => $letter) {
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    $count++;
    if ($count % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D51E + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4g. 粗Fraktur (连续)
$mathCode .= "        // 粗双线体 Bold Fraktur\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D538 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D552 + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4h. 无衬线 Sans-serif (连续)
$mathCode .= "        // 无衬线 Sans-serif\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D56C + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D586 + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4i. 粗无衬线 Bold Sans (连续)
$mathCode .= "        // 粗无衬线 Bold Sans\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D5A0 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D5BA + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4j. 斜无衬线 Sans Italic (h缺)
$mathCode .= "        // 斜无衬线 Sans Italic (h缺)\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D5D4 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $letter = chr(ord('a') + $i);
    if ($i < 7) {
        $cp = 0x1D5EE + $i;
    } elseif ($i === 7) continue;
    else {
        $cp = 0x1D5EE + $i + 1;
    }
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4k. 粗斜无衬线 Bold Sans Italic (h缺)
$mathCode .= "        // 粗斜无衬线 Bold Sans Italic (h缺)\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D608 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $letter = chr(ord('a') + $i);
    if ($i < 7) {
        $cp = 0x1D622 + $i;
    } elseif ($i === 7) continue;
    else {
        $cp = 0x1D622 + $i + 1;
    }
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 4l. 等宽 Monospace (连续)
$mathCode .= "        // 等宽 Monospace\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D670 + $i;
    $letter = chr(ord('A') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";
for ($i = 0; $i < 26; $i++) {
    $cp = 0x1D68A + $i;
    $letter = chr(ord('a') + $i);
    $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $letter . '\',';
    if (($i + 1) % 4 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 数字：6种字体 × 10数字 = 60
$mathCode .= "        // 数学数字（6种字体×10个）\n";
$digitBlocks = [
    0x1D7CE, // 粗体数字
    0x1D7D8, // 双线体数字
    0x1D7E2, // 无衬线数字
    0x1D7EC, // 粗无衬线数字
    0x1D7F6, // 等宽数字
];
foreach ($digitBlocks as $start) {
    for ($i = 0; $i < 10; $i++) {
        $cp = $start + $i;
        $digit = chr(ord('0') + $i);
        $mathCode .= '        "\u{' . sprintf('%04X', $cp) . '}" => \'' . $digit . '\',';
        if (($i + 1) % 5 === 0) $mathCode .= "\n";
    }
}

// 全角字符
$mathCode .= "\n        // === 5. 全角字符 → 半角 (94个) ===\n";
for ($i = 0xFF01; $i <= 0xFF5E; $i++) {
    $ascii = chr($i - 0xFEE0);
    $mathCode .= '        "\u{' . sprintf('%04X', $i) . '}" => \'';
    if ($ascii === "'" || $ascii === '\\') {
        $mathCode .= '\\' . $ascii;
    } else {
        $mathCode .= $ascii;
    }
    $mathCode .= '\',';
    if (($i - 0xFF01 + 1) % 8 === 0) $mathCode .= "\n";
}
$mathCode .= "\n";

// 插入到映射表结束前
$newContent = substr($content, 0, $mapEndPos) . $mathCode . substr($content, $mapEndPos);

// 第三步：删除第11层（全角→半角，已经合并到第10层了）
$fwStart = strpos($newContent, '        // 11. 全角→半角转换');
if ($fwStart !== false) {
    $fwEnd = strpos($newContent, "\n        // 12.", $fwStart);
    if ($fwEnd !== false) {
        $newContent = substr($newContent, 0, $fwStart) . substr($newContent, $fwEnd + 1);
        echo "删除第11层（全角→半角）成功\n";
    }
}

file_put_contents($file, $newContent);
echo "完成！文件大小: " . strlen($newContent) . "\n";
