<?php
/**
 * 文件上传检测（含累进惩罚）
 */
defined('ABSPATH') || exit;

function waf_check_upload() {
    if (empty($_FILES)) return;

    $dangerous = [
        'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru',
        'popen', 'proc_open', 'create_function', 'call_user_func',
        'base64_decode', 'gzinflate', 'str_rot13', 'move_uploaded_file',
        '<?php', '<?=', '<?', '<%', 'php://input', 'php://filter',
        'curl_exec', 'fsockopen', 'file_get_contents', 'file_put_contents',
        'mysql_query', 'mysqli_query'
    ];

    foreach ($_FILES as $file) {
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) continue;

        // 扩展名白名单
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ['jpg','jpeg','png','gif','webp','bmp','ico','svg'])) {
            waf_smart_ban(waf_get_real_ip());   // 累进封禁
            waf_block('禁止上传此类型文件');
        }

        // 真实 MIME 校验
        if (class_exists('finfo')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $file['tmp_name']);
            finfo_close($finfo);
            $allowed_mime = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/svg+xml'];
            if (!in_array($mime, $allowed_mime)) {
                waf_smart_ban(waf_get_real_ip());   // 累进封禁
                waf_block('文件真实类型不符，禁止上传');
            }
        }

        // 文件内容扫描
        $size = filesize($file['tmp_name']);
        $content = '';
        if ($size <= 307200) {
            $content = @file_get_contents($file['tmp_name']);
        } else {
            $tail = @file_get_contents($file['tmp_name'], false, null, max(0, $size - 102400), 102400);
            $head = @file_get_contents($file['tmp_name'], false, null, 0, 10240);
            $mid  = @file_get_contents($file['tmp_name'], false, null, intval($size * 0.4), 40960);
            $content = $head . $tail . $mid;
        }
        if ($content === false) continue;

        $cleaned = WafNormalizer::normalize($content);
        foreach ($dangerous as $pattern) {
            if (strpos($cleaned, $pattern) !== false) {
                waf_smart_ban(waf_get_real_ip());   // 累进封禁
                waf_block('文件包含恶意代码特征：' . $pattern);
            }
        }
    }
}