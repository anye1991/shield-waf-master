<?php
/**
 * 盾甲 WAF 文件上传检测 (upload.php)
 *
 * 顶级上传防护，集成：
 *   - L14 编码归一化 + 上下文记忆
 *   - 5 维语义分析引擎
 *   - 8 层编译引擎
 *   - 4 维智能评分
 *   - 精确恶意代码定位（行号+字符位置）
 *   - GD 库图像真实验证（识别图像马/图种）
 *   - SVG 专用检测（脚本注入/XXE）
 *   - 分阶段处置（低风险记录 / 中风险观察 / 高风险拦截）
 */
defined('ABSPATH') || exit;

/**
 * 上传检测主函数
 * 在文件上传时被调用，执行多层检测
 */
function waf_check_upload() {
    if (empty($_FILES)) return;
    if (defined('WAF_UPLOAD_DETECTION') && !WAF_UPLOAD_DETECTION) return;

    foreach ($_FILES as $file) {
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) continue;

        $filename = $file['name'] ?? '';
        $filesize = $file['size'] ?? 0;
        $tmpPath = $file['tmp_name'];

        // ========== 第1层：扩展名白名单 ==========
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $allowedExt = defined('WAF_UPLOAD_ALLOWED_EXT')
            ? unserialize(WAF_UPLOAD_ALLOWED_EXT)
            : ['jpg','jpeg','png','gif','webp','bmp','ico','svg'];

        if (!in_array($ext, $allowedExt)) {
            waf_upload_block($file, "禁止上传的文件类型: .$ext", 'extension_denied');
            return;
        }

        // SVG 单独处理
        if ($ext === 'svg' && defined('WAF_UPLOAD_ALLOW_SVG') && !WAF_UPLOAD_ALLOW_SVG) {
            waf_upload_block($file, 'SVG 上传已被禁用', 'svg_disabled');
            return;
        }

        // ========== 第2层：MIME 类型检测 ==========
        $allowedMime = defined('WAF_UPLOAD_ALLOWED_MIME')
            ? unserialize(WAF_UPLOAD_ALLOWED_MIME)
            : ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/x-icon', 'image/svg+xml'];

        $actualMime = '';
        if (class_exists('finfo')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $actualMime = finfo_file($finfo, $tmpPath);
            finfo_close($finfo);
        }

        if (!empty($actualMime) && !in_array($actualMime, $allowedMime)) {
            waf_upload_block($file, "文件真实类型不符: $actualMime", 'mime_mismatch');
            return;
        }

        // ========== 第3层：GD 库图像真实验证（图像马/图种检测） ==========
        $imageExts = ['jpg','jpeg','png','gif','webp','bmp'];
        if (in_array($ext, $imageExts) && defined('WAF_UPLOAD_GD_VERIFY') && WAF_UPLOAD_GD_VERIFY && function_exists('getimagesize')) {
            $imgInfo = @getimagesize($tmpPath);
            if ($imgInfo === false) {
                // getimagesize 无法解析 → 不是真图片 → 可能是图种
                waf_upload_block($file, '文件不是有效的图像文件（可能为图像马）', 'invalid_image');
                return;
            }
        }

        // ========== 第4层：读取文件内容 ==========
        $maxScanSize = defined('WAF_UPLOAD_SCAN_MAX_SIZE') ? WAF_UPLOAD_SCAN_MAX_SIZE : 5 * 1024 * 1024;
        $content = waf_upload_read_content($tmpPath, $filesize, $maxScanSize);
        if ($content === false || $content === '') continue;

        // ========== 第5层：SVG 专用检测 ==========
        if ($ext === 'svg') {
            $svgResult = waf_upload_svg_check($content);
            if ($svgResult['block']) {
                waf_upload_block($file, "SVG 文件包含恶意内容: {$svgResult['reason']}", 'svg_malicious', $svgResult);
                return;
            }
        }

        // ========== 第6层：多引擎深度分析（归一化 + 语义 + 编译 + 评分） ==========
        $analysis = waf_upload_deep_analyze($content, $ext);

        $blockThreshold = defined('WAF_UPLOAD_BLOCK_THRESHOLD') ? WAF_UPLOAD_BLOCK_THRESHOLD : 60;
        $logThreshold = defined('WAF_UPLOAD_LOG_THRESHOLD') ? WAF_UPLOAD_LOG_THRESHOLD : 30;

        // ========== 第7层：分阶段处置 ==========
        if ($analysis['score'] >= $blockThreshold) {
            waf_upload_block($file, "文件包含恶意代码 (评分: {$analysis['score']})", 'malicious_content', $analysis);
            return;
        } elseif ($analysis['score'] >= $logThreshold) {
            waf_upload_log($file, "文件内容可疑 (评分: {$analysis['score']})", $analysis);
        }

        // 低风险或干净 → 放行
    }
}

/**
 * 多引擎深度分析
 *
 * @param string $content 文件内容
 * @param string $ext 文件扩展名
 * @return array 分析结果
 */
function waf_upload_deep_analyze($content, $ext = '') {
    $score = 0;
    $engines = [];
    $locations = [];
    $attackType = 'unknown';
    $actualMime = '';

    // 图像文件：在二进制内容中搜索嵌入的代码特征
    $isImage = in_array($ext, ['jpg','jpeg','png','gif','webp','bmp','ico']);

    // ---------- 1. 归一化 + 编码复杂度（AdversarialDefense 14层解码） ----------
    $normContext = null;
    $normalized = $content;
    if (class_exists('AdversarialDefense')) {
        $normContext = AdversarialDefense::normalizeWithContext($content);
        $normalized = $normContext['output'] ?? $content;

        $encodingComplexity = $normContext['encoding_complexity'] ?? 0;
        $encodingDepth = $normContext['encoding_depth'] ?? 0;
        $semanticScore = $normContext['semantic_score'] ?? 0;
        $doubleEnc = !empty($normContext['double_encoding_detected']);

        if ($encodingComplexity > 50) {
            $score += 15;
            $engines[] = ['engine' => 'normalizer', 'score' => 15, 'desc' => "编码复杂度极高 ($encodingComplexity)"];
        } elseif ($encodingComplexity > 30) {
            $score += 8;
            $engines[] = ['engine' => 'normalizer', 'score' => 8, 'desc' => "编码复杂度偏高 ($encodingComplexity)"];
        }

        if ($encodingDepth >= 4) {
            $score += 15;
            $engines[] = ['engine' => 'normalizer', 'score' => 15, 'desc' => "多重编码绕过（深度 $encodingDepth 层）"];
        } elseif ($encodingDepth >= 2) {
            $score += 8;
            $engines[] = ['engine' => 'normalizer', 'score' => 8, 'desc' => "编码深度 $encodingDepth 层"];
        }

        if ($semanticScore >= 50) {
            $score += 10;
            $engines[] = ['engine' => 'normalizer', 'score' => 10, 'desc' => "语义异常分高 ($semanticScore)"];
        }

        if ($doubleEnc) {
            $score += 10;
            $engines[] = ['engine' => 'normalizer', 'score' => 10, 'desc' => '检测到双重编码'];
        }

        // 归一化后与原始内容差异大 → 混淆
        if (strlen($normalized) > 0 && strlen($content) > 0) {
            $diffRatio = abs(strlen($normalized) - strlen($content)) / strlen($content);
            if ($diffRatio > 0.3) {
                $score += 8;
                $engines[] = ['engine' => 'normalizer', 'score' => 8, 'desc' => '归一化后长度变化显著（混淆）'];
            }
        }
    }

    // ---------- 2. 规则检测（归一化后的内容） ----------
    if (function_exists('waf_analyze_attack') && $normContext) {
        $attackResult = waf_analyze_attack($normalized, $normContext);
        if ($attackResult['is_attack']) {
            $attackScore = min($attackResult['total_score'] * 0.5, 50);
            $score += $attackScore;
            $engines[] = [
                'engine' => 'detector',
                'score'  => round($attackScore, 1),
                'desc'   => "规则检测: {$attackResult['risk_level']} ({$attackResult['total_score']}%) hits={$attackResult['hit_count']}",
            ];
            if (!empty($attackResult['attack_type_scores'])) {
                arsort($attackResult['attack_type_scores']);
                $attackType = array_key_first($attackResult['attack_type_scores']);
            }
        }
    }

    // ---------- 3. 语义分析引擎 ----------
    if (class_exists('SemanticEngine')) {
        $semResult = SemanticEngine::analyze($normalized);
        $semScore = $semResult['total_score'] ?? 0;
        if ($semScore > 30) {
            $adjScore = min($semScore * 0.35, 30);
            $score += $adjScore;
            $engines[] = [
                'engine' => 'semantic',
                'score'  => round($adjScore, 1),
                'desc'   => "语义分析: " . ($semResult['risk_level'] ?? 'unknown') . " ($semScore)",
            ];
        }
    }

    // ---------- 4. 编译引擎 ----------
    if (class_exists('CompilerEngine')) {
        $compResult = CompilerEngine::compile($normalized);
        $compScore = $compResult['score'] ?? 0;
        if ($compScore > 40) {
            $adjScore = min($compScore * 0.25, 25);
            $score += $adjScore;
            $engines[] = [
                'engine' => 'compiler',
                'score'  => round($adjScore, 1),
                'desc'   => "编译引擎: score=$compScore" . (!empty($compResult['attack_type']) ? ", type={$compResult['attack_type']}" : ''),
            ];
            if (!empty($compResult['attack_type']) && $compResult['attack_type'] !== 'clean') {
                $attackType = $compResult['attack_type'];
            }
        }
    }

    // ---------- 5. 图像马特征检测 ----------
    if ($isImage) {
        $imgScore = waf_upload_imagemalware_check($content);
        if ($imgScore > 0) {
            $score += $imgScore;
            $engines[] = ['engine' => 'image_malware', 'score' => $imgScore, 'desc' => '图像中检测到代码特征'];
        }
    }

    // ---------- 6. 启发式检测 ----------
    $heurScore = waf_upload_heuristic($normalized, $ext);
    if ($heurScore > 0) {
        $score += $heurScore;
        $engines[] = ['engine' => 'heuristic', 'score' => $heurScore, 'desc' => '启发式分析命中'];
    }

    // ---------- 7. 精确定位恶意代码位置 ----------
    $locations = waf_upload_locate_malware($normalized, $content);

    $score = min(round($score, 1), 100);
    $level = $score >= 60 ? 'high' : ($score >= 30 ? 'medium' : 'low');

    return [
        'score'        => $score,
        'risk_level'   => $level,
        'attack_type'  => $attackType,
        'engines'      => $engines,
        'locations'    => $locations,
        'mime_type'    => $actualMime ?? '',
        'content_size' => strlen($content),
    ];
}

/**
 * 图像马检测 — 在二进制图像内容中搜索嵌入的代码
 */
function waf_upload_imagemalware_check($content) {
    $score = 0;

    // 在整个文件内容中搜索 PHP 标签（不区分大小写）
    $patterns = [
        '/<\?php/i'         => 30,  // PHP 开始标签
        '/<\?=/i'           => 25,  // PHP 短输出标签
        '/<%\s*=/i'         => 20,  // ASP 标签
        '/<script[^>]*>/i'  => 20,  // 脚本标签
        '/eval\s*\(/i'      => 20,  // eval 调用
        '/assert\s*\(/i'    => 20,  // assert 调用
        '/system\s*\(/i'    => 15,  // system 调用
        '/base64_decode\s*\(/i' => 15, // base64_decode
        '/gzinflate\s*\(/i' => 15,  // gzinflate
    ];

    foreach ($patterns as $pattern => $weight) {
        if (preg_match($pattern, $content)) {
            $score += $weight;
        }
    }

    return min($score, 60);
}

/**
 * SVG 专用检测
 */
function waf_upload_svg_check($content) {
    $result = ['block' => false, 'reason' => '', 'score' => 0, 'details' => []];
    $score = 0;

    // 1. XXE 检测（外部实体引用）
    if (preg_match('/<!ENTITY[^>]*SYSTEM[^>]*>/i', $content) ||
        preg_match('/<!DOCTYPE[^>]*\[/i', $content)) {
        $score += 40;
        $result['details'][] = '检测到 XML 外部实体定义（XXE 风险）';
    }

    // 2. 脚本检测
    if (preg_match('/<script[^>]*>([\s\S]*?)<\/script>/i', $content, $m)) {
        $scriptContent = $m[1] ?? '';
        if (trim($scriptContent) !== '') {
            $score += 25;
            $result['details'][] = 'SVG 中包含脚本标签';

            // 进一步检查是否是攻击脚本
            if (preg_match('/(alert|eval|fetch|XMLHttpRequest|document\.cookie|window\.location|onload|onerror|onclick)/i', $scriptContent)) {
                $score += 20;
                $result['details'][] = '脚本中包含危险函数（XSS 风险）';
            }
        }
    }

    // 3. 内联事件处理器
    $inlineEvents = preg_match_all('/\s+on\w+\s*=/i', $content);
    if ($inlineEvents > 2) {
        $score += 15;
        $result['details'][] = "包含多个内联事件处理器 ($inlineEvents 个)";
    }

    // 4. javascript: URI
    if (preg_match('/javascript\s*:/i', $content)) {
        $score += 20;
        $result['details'][] = '包含 javascript: URI';
    }

    // 5. data: URI 中的 payload
    if (preg_match('/data:text\/html/i', $content) || preg_match('/data:application\/x-php/i', $content)) {
        $score += 20;
        $result['details'][] = '包含危险的 data: URI';
    }

    // 6. 外部资源引用（可能用于 SSRF）
    $externalRefs = preg_match_all('/(href|xlink:href|src)\s*=\s*["\']https?:\/\//i', $content);
    if ($externalRefs > 3) {
        $score += 10;
        $result['details'][] = "包含多个外部资源引用 ($externalRefs 个)";
    }

    $result['score'] = $score;
    if ($score >= 50) {
        $result['block'] = true;
        $result['reason'] = implode('; ', $result['details']);
    }

    return $result;
}

/**
 * 启发式检测
 */
function waf_upload_heuristic($content, $ext = '') {
    $score = 0;

    // base64_decode 出现次数
    $b64count = preg_match_all('/base64_decode\s*\(/i', $content);
    if ($b64count > 2) {
        $score += min($b64count * 4, 15);
    }

    // 长 base64 字符串
    if (preg_match_all('/[A-Za-z0-9+\/]{80,}={0,2}/', $content)) {
        $score += 10;
    }

    // 大量 chr() 调用
    $chrCount = preg_match_all('/chr\s*\(\s*\d+\s*\)/i', $content);
    if ($chrCount > 5) {
        $score += min($chrCount * 2, 12);
    }

    // goto 混淆
    $gotoCount = preg_match_all('/goto\s+\w+\s*;/i', $content);
    if ($gotoCount > 3) {
        $score += 10;
    }

    // 超长单行
    $lines = explode("\n", $content);
    foreach ($lines as $line) {
        if (strlen($line) > 2000) {
            $score += 10;
            break;
        }
    }

    // 混淆变量名
    if (preg_match_all('/\$[O0lI]{4,}/', $content) > 3) {
        $score += 8;
    }

    return min($score, 40);
}

/**
 * 精确定位恶意代码位置（行号+字符位置）
 * 用于：日志记录、仪表盘展示、管理员审核
 * 兼容二进制文件：在整个内容中搜索，不依赖换行符
 */
function waf_upload_locate_malware($normalized, $original) {
    $locations = [];

    $malwarePatterns = [
        // PHP 标签
        ['pattern' => '/<\?php[^>]*>/i', 'type' => 'php_tag', 'score' => 25],
        ['pattern' => '/<\?=/i', 'type' => 'php_short_tag', 'score' => 20],
        // 危险函数
        ['pattern' => '/eval\s*\([^)]*\)/i', 'type' => 'eval_injection', 'score' => 25],
        ['pattern' => '/assert\s*\([^)]*\)/i', 'type' => 'assert_injection', 'score' => 25],
        ['pattern' => '/system\s*\([^)]*\)/i', 'type' => 'command_exec', 'score' => 20],
        ['pattern' => '/exec\s*\([^)]*\)/i', 'type' => 'command_exec', 'score' => 20],
        ['pattern' => '/shell_exec\s*\([^)]*\)/i', 'type' => 'command_exec', 'score' => 20],
        ['pattern' => '/base64_decode\s*\([^)]*\)/i', 'type' => 'obfuscation', 'score' => 15],
        ['pattern' => '/gzinflate\s*\([^)]*\)/i', 'type' => 'obfuscation', 'score' => 15],
        // SQL 注入
        ["pattern" => "/'\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+/i", 'type' => 'sqli', 'score' => 25],
        // XSS
        ['pattern' => '/<script[^>]*>[\s\S]*?<\/script>/i', 'type' => 'xss', 'score' => 25],
        ['pattern' => '/javascript\s*:\s*\w+/i', 'type' => 'xss', 'score' => 20],
        // XXE
        ['pattern' => '/<!ENTITY[^>]*SYSTEM[^>]*>/i', 'type' => 'xxe', 'score' => 30],
    ];

    // 在原始内容和归一化内容中都搜索（二进制文件主要靠原始内容）
    $searchTargets = [
        ['content' => $normalized, 'prefix' => 'norm_'],
        ['content' => $original,   'prefix' => 'orig_'],
    ];

    foreach ($searchTargets as $target) {
        $text = $target['content'];
        if (empty($text)) continue;

        foreach ($malwarePatterns as $mp) {
            if (preg_match_all($mp['pattern'], $text, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    if (!is_array($match)) continue;
                    $offset = $match[1];
                    $matchStr = $match[0];

                    // 计算行号和列号
                    $beforeMatch = substr($text, 0, $offset);
                    $lineNum = substr_count($beforeMatch, "\n") + 1;
                    $lastNewline = strrpos($beforeMatch, "\n");
                    $startChar = $lastNewline === false ? $offset + 1 : $offset - $lastNewline;
                    $endChar = $startChar + strlen($matchStr) - 1;

                    // 提取上下文片段
                    $snippetStart = max(0, $offset - 10);
                    $snippetLen = min(strlen($matchStr) + 20, strlen($text) - $snippetStart);
                    $snippet = substr($text, $snippetStart, $snippetLen);
                    // 清理不可打印字符
                    $snippet = preg_replace('/[\x00-\x1F\x7F]/', '.', $snippet);

                    $locations[] = [
                        'line'       => $lineNum,
                        'start_char' => $startChar,
                        'end_char'   => $endChar,
                        'offset'     => $offset,
                        'source'     => $target['prefix'] === 'orig_' ? 'original' : 'normalized',
                        'snippet'    => trim($snippet),
                        'type'       => $mp['type'],
                        'score'      => $mp['score'],
                    ];
                }
            }
        }
    }

    // 去重（同一位置可能被多个模式匹配）
    $seen = [];
    $unique = [];
    foreach ($locations as $loc) {
        $key = $loc['line'] . ':' . $loc['start_char'] . ':' . $loc['end_char'];
        if (!isset($seen[$key])) {
            $seen[$key] = true;
            $unique[] = $loc;
        }
    }

    // 只保留前 20 个
    return array_slice($unique, 0, 20);
}

/**
 * 读取文件内容（处理大文件）
 */
function waf_upload_read_content($tmpPath, $filesize, $maxSize) {
    if ($filesize <= $maxSize) {
        return @file_get_contents($tmpPath);
    }

    // 大文件：读头部 + 尾部 + 中间
    $head = @file_get_contents($tmpPath, false, null, 0, 102400);       // 前 100KB
    $tail = @file_get_contents($tmpPath, false, null, max(0, $filesize - 102400), 102400); // 后 100KB
    $mid  = @file_get_contents($tmpPath, false, null, intval($filesize * 0.4), 51200);     // 中间 50KB

    return $head . "\n---[MIDDLE]---\n" . $mid . "\n---[TAIL]---\n" . $tail;
}

/**
 * 拦截上传
 */
function waf_upload_block($file, $reason, $code = '', $detail = []) {
    $filename = $file['name'] ?? 'unknown';

    // 记录上传拦截日志
    $logDir = WAF_LOG_PATH;
    $logFile = $logDir . 'upload_block_' . date('Y-m-d') . '.log';
    $logLine = date('Y-m-d H:i:s') . ' | ' . waf_get_real_ip() . ' | ' . $code . ' | ' . $filename . ' | ' . $reason . "\n";
    if (!empty($detail)) {
        $logLine .= '  detail: ' . json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    }
    @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);

    // 累进封禁
    if (defined('WAF_UPLOAD_BAN_ON_BLOCK') && WAF_UPLOAD_BAN_ON_BLOCK) {
        waf_smart_ban(waf_get_real_ip());
    }

    // Webhook 告警
    if (function_exists('waf_webhook_notify') && defined('WAF_WEBHOOK_URL') && WAF_WEBHOOK_URL) {
        $msg = "盾甲WAF上传拦截: $code\n";
        $msg .= "文件: $filename\n";
        $msg .= "原因: $reason\n";
        $msg .= "IP: " . waf_get_real_ip() . "\n";
        if (!empty($detail['score'])) $msg .= "评分: {$detail['score']}\n";
        $msg .= "时间: " . date('Y-m-d H:i:s');
        waf_webhook_notify($msg);
    }

    waf_block('文件上传被拦截：' . $reason);
}

/**
 * 记录可疑上传日志（不拦截）
 */
function waf_upload_log($file, $reason, $detail = []) {
    $filename = $file['name'] ?? 'unknown';
    $logDir = WAF_LOG_PATH;
    $logFile = $logDir . 'upload_suspicious_' . date('Y-m-d') . '.log';
    $logLine = date('Y-m-d H:i:s') . ' | ' . waf_get_real_ip() . ' | ' . $filename . ' | ' . $reason . "\n";
    if (!empty($detail)) {
        $logLine .= '  detail: ' . json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    }
    @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
}
