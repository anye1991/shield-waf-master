<?php
defined('ABSPATH') || exit;

function waf_decode_chunked_body() {
    static $decoded = null;
    if ($decoded !== null) return $decoded;
    $te = $_SERVER['HTTP_TRANSFER_ENCODING'] ?? '';
    if (stripos($te, 'chunked') === false) {
        $decoded = file_get_contents('php://input');
        return $decoded;
    }
    $raw = file_get_contents('php://input');
    $result = '';
    $offset = 0;
    $len = strlen($raw);
    while ($offset < $len) {
        $crlf = strpos($raw, "\r\n", $offset);
        if ($crlf === false) break;
        $sizeStr = substr($raw, $offset, $crlf - $offset);
        $sizeStr = trim($sizeStr);
        if (($semi = strpos($sizeStr, ';')) !== false) $sizeStr = substr($sizeStr, 0, $semi);
        $chunkSize = hexdec($sizeStr);
        $offset = $crlf + 2;
        if ($chunkSize === 0) break;
        $result .= substr($raw, $offset, $chunkSize);
        $offset += $chunkSize + 2;
    }
    $decoded = $result;
    return $result;
}