<?php
defined('ABSPATH') || exit;

class ApiSecurity {
    private static $dangerApiPatterns = [
        ['pattern' => '/\.env$/i', 'name' => 'Environment file access'],
        ['pattern' => '/\.git/i', 'name' => 'Git repository access'],
        ['pattern' => '/\.svn/i', 'name' => 'SVN repository access'],
        ['pattern' => '/\.htaccess/i', 'name' => 'Apache config access'],
        ['pattern' => '/\.htpasswd/i', 'name' => 'Apache password file'],
        ['pattern' => '/etc\/passwd/i', 'name' => 'Unix passwd file'],
        ['pattern' => '/etc\/shadow/i', 'name' => 'Unix shadow file'],
        ['pattern' => '/etc\/hosts/i', 'name' => 'Unix hosts file'],
        ['pattern' => '/etc\/group/i', 'name' => 'Unix group file'],
        ['pattern' => '/proc\/self\/environ/i', 'name' => 'Process environment'],
        ['pattern' => '/proc\/self\/cmdline/i', 'name' => 'Process command line'],
        ['pattern' => '/proc\/self\/fd/i', 'name' => 'Process file descriptors'],
        ['pattern' => '/proc\/self\/maps/i', 'name' => 'Process memory maps'],
        ['pattern' => '/proc\/version/i', 'name' => 'Kernel version'],
        ['pattern' => '/\/tmp\//i', 'name' => 'Temp directory'],
        ['pattern' => '/\/var\/log\//i', 'name' => 'Var log directory'],
        ['pattern' => '/\/home\//i', 'name' => 'Home directory'],
        ['pattern' => '/\/root\//i', 'name' => 'Root directory'],
        ['pattern' => '/\/etc\//i', 'name' => 'Etc directory'],
        ['pattern' => '/\/bin\//i', 'name' => 'Bin directory'],
        ['pattern' => '/\/sbin\//i', 'name' => 'Sbin directory'],
        ['pattern' => '/\/usr\/bin\//i', 'name' => 'Usr bin directory'],
        ['pattern' => '/\/usr\/sbin\//i', 'name' => 'Usr sbin directory'],
        ['pattern' => '/\/usr\/local\//i', 'name' => 'Usr local directory'],
        ['pattern' => '/\/opt\//i', 'name' => 'Opt directory'],
        ['pattern' => '/\/boot\//i', 'name' => 'Boot directory'],
        ['pattern' => '/\/lib/i', 'name' => 'Lib directory'],
        ['pattern' => '/\/var\/www\//i', 'name' => 'Var www directory'],
        ['pattern' => '/\/var\/cache\//i', 'name' => 'Var cache directory'],
        ['pattern' => '/\/var\/tmp\//i', 'name' => 'Var tmp directory'],
        ['pattern' => '/\/var\/lib\//i', 'name' => 'Var lib directory'],
    ];

    private static $apiEndpointPatterns = [
        ['pattern' => '/\.\.\//', 'name' => 'Path traversal in API path'],
        ['pattern' => '/\.\./', 'name' => 'Path traversal in API path'],
        ['pattern' => '/\/\.\./', 'name' => 'Parent directory traversal'],
        ['pattern' => '/\.\.\\/', 'name' => 'Windows path traversal'],
        ['pattern' => '/\\\\\.\./', 'name' => 'Windows path traversal'],
        ['pattern' => '/\\\\/', 'name' => 'Windows backslash path'],
        ['pattern' => '/\/\//', 'name' => 'Double slash path'],
        ['pattern' => '/\/~/', 'name' => 'Home directory tilde'],
        ['pattern' => '/\/\$HOME/', 'name' => 'Home directory variable'],
        ['pattern' => '/\/\$USER/', 'name' => 'User variable'],
        ['pattern' => '/\/\$PATH/', 'name' => 'Path variable'],
        ['pattern' => '/\/\$PWD/', 'name' => 'PWD variable'],
    ];

    private static $apiParamNames = [
        'api_key', 'api_secret', 'api_token', 'access_key',
        'secret_key', 'client_id', 'client_secret', 'auth_token',
        'token', 'jwt', 'bearer', 'session_token',
        'user_id', 'uid', 'id', 'account', 'username',
        'email', 'password', 'pass', 'secret',
        'signature', 'sign', 'hmac', 'nonce',
        'timestamp', 'ts', 'version', 'v',
        'action', 'method', 'endpoint', 'path',
        'data', 'payload', 'body', 'query',
        'filter', 'limit', 'offset', 'page',
        'sort', 'order', 'fields', 'expand',
        'include', 'exclude', 'embed',
    ];

    public static function check() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            $result = self::analyzeValue($key, $value);
            if ($result['is_attack']) {
                waf_block('API security violation - ' . $result['reason']);
            }
        }
    }

    private static function collectInputs() {
        $inputs = [];

        foreach ($_GET as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_POST as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }

        $body = file_get_contents('php://input');
        if (!empty($body)) {
            $inputs['body'] = $body;

            $json = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
                self::extractJsonValues($json, $inputs);
            }
        }

        return $inputs;
    }

    private static function extractJsonValues($data, &$inputs, $prefix = '') {
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                $key = $prefix . (empty($prefix) ? '' : '.') . $k;
                if (is_array($v) || is_object($v)) {
                    self::extractJsonValues($v, $inputs, $key);
                } else {
                    $inputs[strtolower($key)] = (string)$v;
                }
            }
        }
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);

        if (empty($value)) {
            return ['is_attack' => false, 'reason' => ''];
        }

        foreach (self::$dangerApiPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                return ['is_attack' => true, 'reason' => $pattern['name']];
            }
        }

        foreach (self::$apiEndpointPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                return ['is_attack' => true, 'reason' => $pattern['name']];
            }
        }

        if (in_array($key, self::$apiParamNames)) {
            if (preg_match('/\.\./', $value)) {
                return ['is_attack' => true, 'reason' => 'Path traversal in API parameter'];
            }

            if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
                return ['is_attack' => true, 'reason' => 'Control characters in API parameter'];
            }

            if (preg_match('/[\r\n]/', $value)) {
                return ['is_attack' => true, 'reason' => 'Newline characters in API parameter'];
            }

            if (strlen($value) > 8192) {
                return ['is_attack' => true, 'reason' => 'API parameter exceeds maximum allowed size'];
            }
        }

        return ['is_attack' => false, 'reason' => ''];
    }
}
