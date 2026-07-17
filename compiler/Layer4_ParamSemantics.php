<?php
defined('ABSPATH') || exit;

/**
 * Layer4：参数语义分析层
 *
 * 对单个参数进行类型推断、值-类型一致性检查和风险评估，
 * 判断该参数是否携带注入载荷或异常内容。
 */
class Layer4_ParamSemantics {

    /**
     * 已知数字型参数名后缀
     */
    private static $numericSuffixes = ['id', 'num', 'count', 'page', 'size', 'limit', 'offset', 'qty', 'amount', 'year', 'month', 'day', 'age', 'price', 'level'];

    /**
     * 已知 ID 类参数名
     */
    private static $idParams = ['id', 'uid', 'gid', 'pid', 'cid', 'oid', 'sid', 'tid', 'nid', 'aid', 'mid', 'kid'];

    /**
     * 文件路径类参数名
     */
    private static $pathParams = ['file', 'path', 'url', 'src', 'href', 'page', 'template', 'include', 'dir', 'folder', 'name'];

    /**
     * 分析参数语义
     *
     * @param string $key   参数名
     * @param string $value 参数值
     * @return array ['score'=>0-100, 'risk'=>'high|medium|low|clean', ...]
     */
    public static function analyze(string $key, string $value): array {
        $result = [
            'score'   => 0,
            'risk'    => 'clean',
            'param'   => $key,
            'value'   => $value,
            'type'    => 'unknown',
            'expected'=> 'unknown',
            'mismatch'=> false,
            'findings'=> [],
        ];

        if ($value === '') {
            return $result;
        }

        $lowerKey = strtolower($key);
        $score = 0;

        // 1. 参数类型推断
        $expectedType = self::inferParamType($lowerKey);
        $result['expected'] = $expectedType;

        // 2. 值类型识别
        $actualType = self::detectValueType($value);
        $result['type'] = $actualType;

        // 3. 值-类型一致性检查
        if ($expectedType !== 'unknown' && $actualType !== $expectedType && $actualType !== 'mixed') {
            $result['mismatch'] = true;
            // 数字型参数却出现复杂字符串
            if ($expectedType === 'number' && $actualType === 'string') {
                $score += 25;
                $result['findings'][] = ['type' => 'type_mismatch', 'desc' => "数字型参数 '{$key}' 接收到非数字值"];
            } elseif ($expectedType === 'identifier' && $actualType === 'string') {
                $score += 15;
                $result['findings'][] = ['type' => 'type_mismatch', 'desc' => "标识符参数 '{$key}' 接收到复杂字符串"];
            } elseif ($expectedType === 'boolean' && $actualType === 'string') {
                $score += 20;
                $result['findings'][] = ['type' => 'type_mismatch', 'desc' => "布尔型参数 '{$key}' 接收到复杂字符串"];
            }
        }

        // 4. 风险载荷检测
        $lowerVal = strtolower($value);

        // SQL 注入特征
        $sqlPatterns = [
            '/union\s+(?:all\s+)?select/i' => 30,
            '/\bor\s+\d+\s*=\s*\d+/i'       => 25,
            '/\band\s+\d+\s*=\s*\d+/i'      => 22,
            '/\bselect\b.*\bfrom\b/is'      => 25,
            '/\b(?:sleep|benchmark)\s*\(/i' => 28,
            '/\b(?:drop|alter|insert|delete|update)\s+/i' => 25,
            '/information_schema/i'         => 22,
            '/into\s+outfile/i'             => 28,
            '/load_file\s*\(/i'             => 25,
            '/--|#/'                         => 12,
        ];
        foreach ($sqlPatterns as $p => $w) {
            if (preg_match($p, $value)) {
                $score += $w;
                $result['findings'][] = ['type' => 'sqli', 'pattern' => $p, 'desc' => '检测到 SQL 注入特征'];
            }
        }

        // XSS 特征
        $xssPatterns = [
            '/<script\b/i'                 => 28,
            '/<\/script>/i'                => 20,
            '/on\w+\s*=/i'                 => 22,
            '/javascript:/i'               => 22,
            '/vbscript:/i'                 => 20,
            '/data:text\/html/i'           => 22,
            '/<iframe\b/i'                 => 20,
            '/<svg\b/i'                    => 18,
            '/<img\b[^>]*onerror/i'        => 25,
        ];
        foreach ($xssPatterns as $p => $w) {
            if (preg_match($p, $value)) {
                $score += $w;
                $result['findings'][] = ['type' => 'xss', 'pattern' => $p, 'desc' => '检测到 XSS 特征'];
            }
        }

        // 路径遍历特征
        if (preg_match('/\.\.[\/\\\\]/', $value)) {
            $score += 22;
            $result['findings'][] = ['type' => 'path_traversal', 'desc' => '检测到路径遍历特征'];
        }
        if (preg_match('/(?:\/etc\/passwd|\/etc\/shadow|boot\.ini|win\.ini)/i', $value)) {
            $score += 28;
            $result['findings'][] = ['type' => 'path_traversal', 'desc' => '检测到敏感文件读取尝试'];
        }

        // 文件包含 / 协议特征
        if (preg_match('/(?:php|data|zip|phar|expect|glob)\s*:\s*\/\//i', $value)) {
            $score += 28;
            $result['findings'][] = ['type' => 'file_inclusion', 'desc' => '检测到封装协议'];
        }
        if (preg_match('/\.\.[\/\\\\]\.\.[\/\\\\]\.\./', $value)) {
            $score += 15;
            $result['findings'][] = ['type' => 'deep_traversal', 'desc' => '检测到深度路径遍历'];
        }

        // RCE 特征
        if (preg_match('/\b(?:eval|system|exec|shell_exec|passthru|assert|popen|proc_open)\s*\(/i', $value)) {
            $score += 30;
            $result['findings'][] = ['type' => 'rce', 'desc' => '检测到命令执行函数'];
        }

        // 5. 文件路径参数的额外检查
        if (in_array($expectedType, ['path', 'filename']) || in_array($lowerKey, self::$pathParams)) {
            // 路径参数中包含代码特征则更加可疑
            if (preg_match('/<\?(?:php|=)?/i', $value)) {
                $score += 25;
                $result['findings'][] = ['type' => 'webshell_in_path', 'desc' => '路径参数中包含 PHP 标签'];
            }
        }

        // 6. 编码/混淆特征
        if (preg_match('/0x[0-9a-f]{6,}/i', $value)) {
            $score += 15;
            $result['findings'][] = ['type' => 'hex_encoding', 'desc' => '检测到长十六进制编码'];
        }
        if (preg_match('/(?:%[0-9a-f]{2}){4,}/i', $value)) {
            $score += 12;
            $result['findings'][] = ['type' => 'url_encoding', 'desc' => '检测到密集 URL 编码'];
        }
        $base64Hit = preg_match('/^[A-Za-z0-9+\/]{20,}={0,2}$/', $value);
        if ($base64Hit && strlen($value) % 4 === 0) {
            $decoded = base64_decode($value, true);
            if ($decoded !== false && preg_match('/(?:select|union|script|eval|system|<)/i', $decoded)) {
                $score += 25;
                $result['findings'][] = ['type' => 'base64_payload', 'desc' => 'Base64 解码后包含攻击载荷'];
            }
        }

        $score = max(0, min(100, $score));
        $result['score'] = $score;

        if ($score >= 60) {
            $result['risk'] = 'high';
        } elseif ($score >= 35) {
            $result['risk'] = 'medium';
        } elseif ($score >= 15) {
            $result['risk'] = 'low';
        } else {
            $result['risk'] = 'clean';
        }

        return $result;
    }

    /**
     * 推断参数的预期类型
     */
    private static function inferParamType(string $key): string {
        // 完全匹配 ID 类
        if (in_array($key, self::$idParams)) {
            return 'identifier';
        }
        // 后缀匹配数字类
        foreach (self::$numericSuffixes as $suffix) {
            if (substr($key, -strlen($suffix)) === $suffix) {
                return 'number';
            }
        }
        // 布尔型
        if (preg_match('/^(?:is|has|can|enable|disable|allow|deny)[_a-z]/', $key)) {
            return 'boolean';
        }
        // 路径型
        if (in_array($key, self::$pathParams)) {
            return 'path';
        }
        // 邮箱、URL、Token
        if ($key === 'email' || $key === 'mail') {
            return 'email';
        }
        if ($key === 'url' || $key === 'redirect' || $key === 'callback') {
            return 'url';
        }
        if ($key === 'token' || $key === 'csrf_token' || $key === '_token') {
            return 'token';
        }
        // 搜索/查询
        if ($key === 'q' || $key === 'query' || $key === 'keyword' || $key === 'search') {
            return 'search';
        }
        return 'unknown';
    }

    /**
     * 检测值的实际类型
     */
    private static function detectValueType(string $value): string {
        if ($value === '') {
            return 'empty';
        }
        // 纯数字
        if (preg_match('/^-?\d+(\.\d+)?$/', $value)) {
            return 'number';
        }
        // 布尔
        if (in_array(strtolower($value), ['0', '1', 'true', 'false', 'yes', 'no', 'on', 'off'], true)) {
            return 'boolean';
        }
        // 邮箱
        if (preg_match('/^[\w.+-]+@[\w.-]+\.[a-z]{2,}$/i', $value)) {
            return 'email';
        }
        // URL
        if (preg_match('/^[a-z]+:\/\//i', $value)) {
            return 'url';
        }
        // 包含代码特征则视为字符串（复杂）
        if (preg_match('/(?:select|union|<script|eval|system|\.\.[\/\\\\])/i', $value)) {
            return 'string';
        }
        // 标识符（仅字母数字下划线短横）
        if (preg_match('/^[a-zA-Z0-9_-]+$/', $value)) {
            return 'identifier';
        }
        return 'string';
    }
}
