<?php
defined('ABSPATH') || exit;

function waf_decode_chunked_body($reset = false) {
    static $decoded = null;
    if ($reset) {
        $decoded = null;
        return null;
    }
    if ($decoded !== null) return $decoded;
    $te = $_SERVER['HTTP_TRANSFER_ENCODING'] ?? '';
    $raw = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
    if (stripos($te, 'chunked') === false) {
        $decoded = $raw;
        return $decoded;
    }
    $result = '';
    $offset = 0;
    $len = strlen($raw);
    $maxSize = defined('WAF_MAX_BODY_SIZE') ? WAF_MAX_BODY_SIZE : 1048576;
    $maxChunks = 10000;
    $chunksProcessed = 0;
    while ($offset < $len) {
        if ($chunksProcessed >= $maxChunks) break;
        $chunksProcessed++;
        $crlf = strpos($raw, "\r\n", $offset);
        $newlineOnly = false;
        if ($crlf === false) {
            // 兼容只有 \n 的非标准输入
            $crlf = strpos($raw, "\n", $offset);
            $newlineOnly = ($crlf !== false);
        }
        if ($crlf === false) break;
        $sizeStr = substr($raw, $offset, $crlf - $offset);
        $sizeStr = trim($sizeStr);
        if (($semi = strpos($sizeStr, ';')) !== false) $sizeStr = substr($sizeStr, 0, $semi);
        // 校验 chunk size 是合法的十六进制（防止 hexdec 对任意字符串返回值）
        if (!preg_match('/^[0-9a-fA-F]{1,8}$/', $sizeStr)) break;
        $chunkSize = hexdec($sizeStr);
        // 限制最大 chunk size（16MB）
        if ($chunkSize > 16777216) break;
        $offset = $newlineOnly ? $crlf + 1 : $crlf + 2;
        if ($chunkSize === 0) break;
        if (strlen($result) + $chunkSize > $maxSize) {
            $result .= substr($raw, $offset, $maxSize - strlen($result));
            break;
        }
        $result .= substr($raw, $offset, $chunkSize);
        $offset += $chunkSize;
        // 显式校验并跳过分隔符（可能是 \r\n、\n 或无分隔）
        if (substr($raw, $offset, 2) === "\r\n") {
            $offset += 2;
        } elseif (substr($raw, $offset, 1) === "\n") {
            $offset += 1;
        } else {
            break; // 格式错误
        }
    }
    $decoded = $result;
    return $result;
}
