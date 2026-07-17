<?php
defined('ABSPATH') || exit;

function waf_output_filter_start() {
    ob_start(function($buffer) {
        $dangerous = [
            'mysql_fetch_array()',
            'mysql_num_rows()',
            'mysql_error()',
            'You have an error in your SQL syntax',
            'Warning: ',
            'Fatal error: ',
            'PDOException',
            'Stack trace:',
            'on line <b>',
        ];
        foreach ($dangerous as $err) {
            if (stripos($buffer, $err) !== false) {
                http_response_code(500);
                return '<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body><h1>内部服务器错误</h1><p>请稍后重试或联系管理员。</p></body></html>';
            }
        }
        return $buffer;
    });
}