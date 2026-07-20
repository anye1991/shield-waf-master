<?php
defined('ABSPATH') || exit;

class FileInclusion {
    private static $lfiPatterns = [
        ['pattern' => '/\.\.\/\.\.\/etc\/passwd/i', 'severity' => 95, 'name' => 'LFI /etc/passwd traversal', 'category' => 'lfi'],
        ['pattern' => '/\.\.\/\.\.\/\.\.\/\.\.\/windows/i', 'severity' => 90, 'name' => 'LFI Windows path traversal', 'category' => 'lfi'],
        ['pattern' => '/php:\/\/filter\/convert\.base64-encode/i', 'severity' => 95, 'name' => 'LFI php://filter base64 encode', 'category' => 'lfi'],
        ['pattern' => '/php:\/\/input/i', 'severity' => 90, 'name' => 'LFI php://input wrapper', 'category' => 'lfi'],
        ['pattern' => '/data:\/\//i', 'severity' => 85, 'name' => 'LFI data:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/expect:\/\//i', 'severity' => 95, 'name' => 'LFI expect:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/phar:\/\//i', 'severity' => 90, 'name' => 'LFI phar:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/zip:\/\//i', 'severity' => 80, 'name' => 'LFI zip:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/rar:\/\//i', 'severity' => 80, 'name' => 'LFI rar:// wrapper', 'category' => 'lfi'],
        ['pattern' => '/php:\/\/filter/i', 'severity' => 85, 'name' => 'LFI php://filter wrapper', 'category' => 'lfi'],
        ['pattern' => '/file:\/\//i', 'severity' => 80, 'name' => 'LFI file:// wrapper', 'category' => 'lfi'],
    ];

    private static $traversalPatterns = [
        ['pattern' => '/\.\.\.\.\/\//i', 'severity' => 80, 'name' => 'Path traversal variant ....//', 'category' => 'traversal'],
        ['pattern' => '/\.\.%2f/i', 'severity' => 75, 'name' => 'URL-encoded path traversal ..%2f', 'category' => 'traversal'],
        ['pattern' => '/%2e%2e%2f/i', 'severity' => 75, 'name' => 'Double URL-encoded traversal %2e%2e%2f', 'category' => 'traversal'],
        ['pattern' => '/\.\.\\\/', 'severity' => 70, 'name' => 'Windows path traversal ..\\', 'category' => 'traversal'],
        ['pattern' => '/\.\.\//', 'severity' => 60, 'name' => 'Standard path traversal ../', 'category' => 'traversal'],
        ['pattern' => '/%252e%252e%252f/i', 'severity' => 70, 'name' => 'Triple URL-encoded traversal', 'category' => 'traversal'],
        ['pattern' => '/\.\.%5c/i', 'severity' => 70, 'name' => 'URL-encoded backslash traversal', 'category' => 'traversal'],
        ['pattern' => '/%2e%2e%5c/i', 'severity' => 70, 'name' => 'URL-encoded backslash dot traversal', 'category' => 'traversal'],
        ['pattern' => '/\.\.\/{2,}/', 'severity' => 80, 'name' => 'Multiple path traversal sequences', 'category' => 'traversal'],
    ];

    private static $rfiPatterns = [
        ['pattern' => '/http:\/\//i', 'severity' => 85, 'name' => 'RFI HTTP URL in include param', 'category' => 'rfi'],
        ['pattern' => '/https:\/\//i', 'severity' => 80, 'name' => 'RFI HTTPS URL in include param', 'category' => 'rfi'],
        ['pattern' => '/ftp:\/\//i', 'severity' => 75, 'name' => 'RFI FTP URL in include param', 'category' => 'rfi'],
    ];

    private static $targetFilePatterns = [
        ['pattern' => '/\/etc\/passwd/i', 'severity' => 90, 'name' => 'Target: /etc/passwd', 'category' => 'target'],
        ['pattern' => '/\/etc\/shadow/i', 'severity' => 95, 'name' => 'Target: /etc/shadow', 'category' => 'target'],
        ['pattern' => '/\/proc\/self\/environ/i', 'severity' => 85, 'name' => 'Target: /proc/self/environ', 'category' => 'target'],
        ['pattern' => '/\.htaccess/i', 'severity' => 75, 'name' => 'Target: .htaccess', 'category' => 'target'],
        ['pattern' => '/config\.php/i', 'severity' => 80, 'name' => 'Target: config.php', 'category' => 'target'],
        ['pattern' => '/wp-config\.php/i', 'severity' => 85, 'name' => 'Target: wp-config.php', 'category' => 'target'],
        ['pattern' => '/\/etc\/hosts/i', 'severity' => 75, 'name' => 'Target: /etc/hosts', 'category' => 'target'],
        ['pattern' => '/\/etc\/group/i', 'severity' => 75, 'name' => 'Target: /etc/group', 'category' => 'target'],
        ['pattern' => '/\/proc\/self\/fd\//i', 'severity' => 80, 'name' => 'Target: /proc/self/fd/', 'category' => 'target'],
        ['pattern' => '/\/proc\/version/i', 'severity' => 70, 'name' => 'Target: /proc/version', 'category' => 'target'],
        ['pattern' => '/\/proc\/cpuinfo/i', 'severity' => 70, 'name' => 'Target: /proc/cpuinfo', 'category' => 'target'],
        ['pattern' => '/\/proc\/mounts/i', 'severity' => 70, 'name' => 'Target: /proc/mounts', 'category' => 'target'],
        ['pattern' => '/boot\.ini/i', 'severity' => 75, 'name' => 'Target: boot.ini', 'category' => 'target'],
        ['pattern' => '/win\.ini/i', 'severity' => 75, 'name' => 'Target: win.ini', 'category' => 'target'],
    ];

    private static $includeParamNames = [
        'file', 'path', 'filename', 'filepath', 'include', 'require',
        'page', 'template', 'view', 'layout', 'module', 'action',
        'lang', 'language', 'theme', 'style', 'css', 'js',
        'img', 'image', 'src', 'source', 'url', 'uri',
        'doc', 'document', 'content', 'data', 'load', 'open',
        'read', 'readfile', 'cat', 'dir', 'directory',
        'redirect', 'redirect_url', 'next', 'return', 'go',
        'link', 'target', 'dest', 'destination', 'forward',
    ];

    // RFI 强相关参数：仅这些参数启用 RFI 高分，避免对 URL 类参数（如 redirect_url）误报
    private static $rfiParamNames = [
        'file', 'include', 'require', 'page', 'template',
        'view', 'layout', 'module', 'doc', 'document',
        'load', 'open', 'read', 'readfile', 'path', 'filepath',
        'include_once', 'require_once',
    ];

    // 缓存的合并大正则（首次使用时构建），覆盖全部 LFI/traversal/RFI/target patterns
    private static $combinedLfiRfiPattern = null;

    /**
     * 把全部 4 类 patterns 合并为单个 alternation 大正则。
     * 原 traversalPatterns 中部分 patterns 不带 /i 但都不含字母（如 /..\//），
     * 统一加 /i 不改变大小写行为。
     */
    private static function getCombinedPattern() {
        if (self::$combinedLfiRfiPattern !== null) {
            return self::$combinedLfiRfiPattern;
        }
        $parts = [];
        foreach (self::$lfiPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$traversalPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$rfiPatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        foreach (self::$targetFilePatterns as $p) {
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        self::$combinedLfiRfiPattern = '/' . implode('|', $parts) . '/i';
        return self::$combinedLfiRfiPattern;
    }

    /**
     * 解析 /body/flags 形式的正则，仅取 body 部分。避免 trim($p, '/') 把
     * 带 /i 后缀的 pattern 末尾 'i' 残留进 body，导致合并大正则出现裸 '/'。
     */
    private static function patternBody($pattern) {
        $lastSlash = strrpos($pattern, '/');
        if ($lastSlash === false || $lastSlash === 0) {
            return substr($pattern, 1);
        }
        return substr($pattern, 1, $lastSlash - 1);
    }

    public static function detect($inputs) {
        $score = 0;
        $details = [];
        $detected = false;

        if (!is_array($inputs) || empty($inputs)) {
            return ['detected' => false, 'score' => 0, 'details' => []];
        }

        foreach ($inputs as $key => $value) {
            // 递归遍历任意深度的嵌套数组
            $result = self::analyzeValueRecursive((string)$key, $value);
            if ($result['score'] > 0) {
                $score = max($score, $result['score']);
                $details[] = $result;
                if (!empty($result['detected'])) {
                    $detected = true;
                }
            }
        }

        return [
            'detected' => $detected,
            'score' => min($score, 100),
            'details' => $details,
        ];
    }

    /**
     * 递归分析任意深度嵌套的数组结构
     */
    private static function analyzeValueRecursive($key, $value) {
        if (is_array($value)) {
            $score = 0;
            $findings = [];
            $detected = false;
            foreach ($value as $v) {
                $sub = self::analyzeValueRecursive($key, $v);
                if ($sub['score'] > 0) {
                    $score = max($score, $sub['score']);
                    $findings = array_merge($findings, $sub['findings'] ?? []);
                    if (!empty($sub['detected'])) $detected = true;
                }
            }
            return [
                'detected' => $detected,
                'score' => $score,
                'findings' => $findings,
                'key' => $key,
            ];
        }
        return self::analyzeValue($key, (string)$value);
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);
        $lowerKey = strtolower($key);
        $score = 0;
        $findings = [];

        if (empty($value)) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'key' => $key];
        }

        // 长度上限：超过 8KB 只扫前 8KB
        if (strlen($value) > 8192) {
            $value = substr($value, 0, 8192);
        }

        $isIncludeParam = in_array($lowerKey, self::$includeParamNames, true);
        $isRfiParam = in_array($lowerKey, self::$rfiParamNames, true);
        $paramMultiplier = $isIncludeParam ? 1.0 : 0.55;

        // 原始值扫描（全部 4 类模式）
        $score = self::scanWithPatterns($value, $isRfiParam, $paramMultiplier, 1.0, $findings, $score, false);

        // 多层 URL 解码（最多 3 次），使用 rawurldecode 避免 + 被错误转为空格
        $decoded = $value;
        for ($i = 0; $i < 3; $i++) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) break;
            $decoded = $next;
            // 每层解码后对全部 4 类模式重新扫描，按层降低权重避免无限放大
            $layerFactor = max(0.7, 0.85 - $i * 0.05);
            $score = self::scanWithPatterns($decoded, $isRfiParam, $paramMultiplier, $layerFactor, $findings, $score, true);
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'key' => $key,
            'is_include_param' => $isIncludeParam,
        ];
    }

    /**
     * 用全部 4 类模式（LFI/RFI/traversal/target）扫描给定内容
     * RFI 模式仅在 RFI 强相关参数中才给予高分，避免对 URL 类参数误报
     */
    private static function scanWithPatterns($value, $isRfiParam, $paramMultiplier, $layerFactor, &$findings, $score, $isDecoded) {
        $prefix = $isDecoded ? 'URL-decoded: ' : '';

        // 廉价预筛：所有 4 类 patterns 都至少需要以下字符之一才可能命中
        //   lfiPatterns:        ':' (协议 php://, data:// 等) 或 '/' 或 '.'
        //   traversalPatterns:  '.' 或 '%' 或 '\'
        //   rfiPatterns:         ':' (http://, https://, ftp://)
        //   targetFilePatterns:  '/' (路径) 或 '.' (.htaccess / .php 等)
        if (strpos($value, ':') === false
            && strpos($value, '/') === false
            && strpos($value, '.') === false
            && strpos($value, '%') === false
            && strpos($value, '\\') === false) {
            return $score;
        }

        // 合并大正则做一次廉价筛除：未命中则跳过 4 类逐条匹配
        if (!preg_match(self::getCombinedPattern(), $value)) {
            return $score;
        }

        foreach (self::$lfiPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier * $layerFactor);
                if ($score < $adjustedScore) $score = $adjustedScore;
                $findings[] = $prefix . $pattern['name'];
            }
        }

        foreach (self::$traversalPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier * $layerFactor);
                if ($score < $adjustedScore) $score = $adjustedScore;
                $findings[] = $prefix . $pattern['name'];
            }
        }

        // RFI 模式：仅 RFI 强相关参数启用高分，其他参数大幅降权
        foreach (self::$rfiPatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                if ($isRfiParam) {
                    $adjustedScore = (int)($pattern['severity'] * $paramMultiplier * $layerFactor);
                } else {
                    $adjustedScore = (int)($pattern['severity'] * 0.3 * $paramMultiplier * $layerFactor);
                }
                if ($score < $adjustedScore) $score = $adjustedScore;
                $findings[] = $prefix . $pattern['name'];
            }
        }

        foreach (self::$targetFilePatterns as $pattern) {
            if (preg_match($pattern['pattern'], $value)) {
                $adjustedScore = (int)($pattern['severity'] * $paramMultiplier * $layerFactor);
                if ($score < $adjustedScore) $score = $adjustedScore;
                $findings[] = $prefix . $pattern['name'];
            }
        }

        return $score;
    }
}
