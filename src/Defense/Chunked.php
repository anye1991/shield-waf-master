<?php
defined('ABSPATH') || exit;

function waf_decode_chunked_body() {
    static $decoded = null;
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
    while ($offset < $len) {
        $crlf = strpos($raw, "\r\n", $offset);
        if ($crlf === false) break;
        $sizeStr = substr($raw, $offset, $crlf - $offset);
        $sizeStr = trim($sizeStr);
        if (($semi = strpos($sizeStr, ';')) !== false) $sizeStr = substr($sizeStr, 0, $semi);
        $chunkSize = hexdec($sizeStr);
        $offset = $crlf + 2;
        if ($chunkSize === 0) break;
        if (strlen($result) + $chunkSize > $maxSize) {
            $result .= substr($raw, $offset, $maxSize - strlen($result));
            break;
        }
        $result .= substr($raw, $offset, $chunkSize);
        $offset += $chunkSize + 2;
    }
    $decoded = $result;
    return $result;
}