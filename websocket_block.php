<?php
defined('ABSPATH') || exit;
class WebSocketBlock {
    public static function deny() {
        $upgrade = $_SERVER['HTTP_UPGRADE'] ?? '';
        if (strtolower($upgrade) === 'websocket') {
            http_response_code(426);
            header('Content-Type: text/plain');
            die('WebSocket connections are not allowed.');
        }
    }
}