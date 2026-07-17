<?php
defined('ABSPATH') || exit;

/**
 * 代码定位器
 *
 * 用于在原始输入中定位代码片段的精确位置与上下文边界。
 * 支持识别 PHP 标签、SQL 语句边界、HTML 标签边界等多种语义边界，
 * 为后续各分析层提供准确的代码片段定位信息。
 */
class CodeLocator {

    /**
     * PHP 标签边界正则：匹配 <?php ... ?> / <?= ... ?> / <% ... %> 等
     */
    const PHP_TAG_PATTERN = '/<\?(?:php|=)?|\?>/i';

    /**
     * SQL 语句边界正则：匹配以分号结尾或关键 DDL/DML 起始位置
     */
    const SQL_BOUNDARY_PATTERN = '/(?:;|\b(?:select|insert\s+into|update|delete\s+from|drop\s+table|alter\s+table|create\s+table|union\s+(?:all\s+)?select)\b)/iu';

    /**
     * HTML 标签边界正则：匹配 <tag ...> 与 </tag>
     */
    const HTML_TAG_PATTERN = '/<\/?[a-zA-Z][^>]*>/u';

    /**
     * 定位代码片段位置
     *
     * 扫描输入文本，识别出其中包含的可疑代码片段，
     * 返回每个片段的起止位置、类型与上下文。
     *
     * @param string $text 待检测文本
     * @return array 片段列表，每项含 [start, end, type, snippet]
     */
    public static function locate(string $text): array {
        $fragments = [];
        if ($text === '') {
            return $fragments;
        }

        // 收集各类边界匹配
        $matches = [];

        // PHP 标签边界
        if (preg_match_all(self::PHP_TAG_PATTERN, $text, $m, PREG_OFFSET_CAPTURE)) {
            foreach ($m[0] as $match) {
                $matches[] = ['pos' => $match[1], 'len' => strlen($match[0]), 'type' => 'php'];
            }
        }

        // SQL 语句边界
        if (preg_match_all(self::SQL_BOUNDARY_PATTERN, $text, $m, PREG_OFFSET_CAPTURE)) {
            foreach ($m[0] as $match) {
                $matches[] = ['pos' => $match[1], 'len' => strlen($match[0]), 'type' => 'sql'];
            }
        }

        // HTML 标签边界
        if (preg_match_all(self::HTML_TAG_PATTERN, $text, $m, PREG_OFFSET_CAPTURE)) {
            foreach ($m[0] as $match) {
                $matches[] = ['pos' => $match[1], 'len' => strlen($match[0]), 'type' => 'html'];
            }
        }

        // 按位置排序
        usort($matches, function ($a, $b) {
            return $a['pos'] <=> $b['pos'];
        });

        // 合并相邻同类型片段，构造代码片段记录
        $len = strlen($text);
        foreach ($matches as $idx => $match) {
            $start = $match['pos'];
            $end = $start + $match['len'];

            // 寻找该边界之后的下一个同类边界作为片段结束
            for ($j = $idx + 1; $j < count($matches); $j++) {
                if ($matches[$j]['type'] === $match['type'] && $matches[$j]['pos'] > $end) {
                    $end = $matches[$j]['pos'] + $matches[$j]['len'];
                    break;
                }
            }

            // 限制片段最大长度，避免吞掉过多上下文
            $maxSpan = 256;
            if ($end - $start > $maxSpan) {
                $end = $start + $maxSpan;
            }

            $snippet = substr($text, $start, $end - $start);
            $fragments[] = [
                'start'    => $start,
                'end'      => min($end, $len),
                'type'     => $match['type'],
                'snippet'  => $snippet,
            ];
        }

        // 去重：相同起始位置只保留一个
        $seen = [];
        $unique = [];
        foreach ($fragments as $f) {
            $key = $f['start'] . ':' . $f['type'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $f;
            }
        }

        return $unique;
    }

    /**
     * 提取上下文
     *
     * 以指定位置为中心，提取前后指定半径范围内的文本，
     * 用于在告警或日志中显示触发点的代码上下文。
     *
     * @param string $text   原始文本
     * @param int    $pos    中心位置（字节偏移）
     * @param int    $radius 上下文半径（字节）
     * @return string 上下文片段
     */
    public static function extractContext(string $text, int $pos, int $radius = 50): string {
        if ($text === '') {
            return '';
        }
        $len = strlen($text);
        if ($pos < 0) {
            $pos = 0;
        }
        if ($pos > $len) {
            $pos = $len;
        }

        $start = max(0, $pos - $radius);
        $end = min($len, $pos + $radius);

        $ctx = substr($text, $start, $end - $start);

        // 在首尾添加省略号以表示截断
        $prefix = $start > 0 ? '...' : '';
        $suffix = $end < $len ? '...' : '';

        return $prefix . $ctx . $suffix;
    }

    /**
     * 检测代码块边界
     *
     * 综合判断输入中是否存在跨语言的代码块边界，
     * 返回边界类型与位置列表。
     *
     * @param string $text 待检测文本
     * @return array 边界列表
     */
    public static function detectBoundaries(string $text): array {
        $boundaries = [];
        if ($text === '') {
            return $boundaries;
        }

        $patterns = [
            'php'     => self::PHP_TAG_PATTERN,
            'sql'     => self::SQL_BOUNDARY_PATTERN,
            'html'    => self::HTML_TAG_PATTERN,
        ];

        foreach ($patterns as $type => $pattern) {
            if (preg_match_all($pattern, $text, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $match) {
                    $boundaries[] = [
                        'type' => $type,
                        'pos'  => $match[1],
                        'text' => $match[0],
                    ];
                }
            }
        }

        usort($boundaries, function ($a, $b) {
            return $a['pos'] <=> $b['pos'];
        });

        return $boundaries;
    }
}
