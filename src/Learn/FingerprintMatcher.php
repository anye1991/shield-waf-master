<?php
/**
 * n-gram SimHash 指纹匹配器 (v5.4)
 *
 * 原理：
 *   - 用 SimHash 把 payload 转成 64 位指纹
 *   - SimHash 对"局部修改"不敏感（加空格、换编码、换大小写，指纹距离仍然近）
 *   - 与已确认攻击指纹库比对，Hamming 距离 <= 阈值即判定匹配
 *
 * 优势：
 *   - 对变形/混淆 payload 有效，补 n-gram 贝叶斯的盲区
 *   - 指纹库由 AutoLearn 在高置信度攻击确认后自动写入，无需人工维护
 *   - 纯 PHP，无外部依赖
 *
 * 用途：
 *   - 作为 WAF 多引擎融合的第三个信号源
 *   - 识别"已知攻击的变体"
 */
defined('ABSPATH') || exit;

class Learning_FingerprintMatcher {

    const SIMHASH_BITS = 64;
    const SIMILARITY_THRESHOLD = 0.85; // Hamming 相似度阈值，可调
    const MAX_LIBRARY_SIZE = 5000;     // 指纹库上限，防膨胀
    const MIN_PAYLOAD_LEN = 8;

    /**
     * 匹配入口
     * @param string $payload
     * @return array [
     *   'matched'    => bool 是否匹配到已知攻击,
     *   'similarity' => 0-1 最高相似度,
     *   'reference'  => 匹配到的指纹 hash（若匹配）,
     *   'reason'     => 'matched' / 'no_match' / 'empty_library' / 'payload_too_short',
     * ]
     */
    public static function match(string $payload): array {
        if (strlen($payload) < self::MIN_PAYLOAD_LEN) {
            return ['matched' => false, 'similarity' => 0.0, 'reference' => '', 'reason' => 'payload_too_short'];
        }

        $library = self::loadLibrary();
        if (empty($library['fingerprints'])) {
            return ['matched' => false, 'similarity' => 0.0, 'reference' => '', 'reason' => 'empty_library'];
        }

        $fp = self::simhash($payload);
        $best = 0.0;
        $bestHash = '';

        foreach ($library['fingerprints'] as $hash => $entry) {
            $sim = self::hammingSimilarity($fp, $entry['fingerprint'] ?? '');
            if ($sim > $best) {
                $best = $sim;
                $bestHash = $hash;
            }
        }

        return [
            'matched'    => $best >= self::SIMILARITY_THRESHOLD,
            'similarity' => round($best, 4),
            'reference'  => $best >= self::SIMILARITY_THRESHOLD ? $bestHash : '',
            'reason'     => $best >= self::SIMILARITY_THRESHOLD ? 'matched' : 'no_match',
        ];
    }

    /**
     * 高置信度攻击入库（由 AutoLearn 调用）
     * @param string $payload 归一化后的攻击 payload
     * @param array  $meta    元数据（attack_type, score 等）
     */
    public static function addFingerprint(string $payload, array $meta = []): bool {
        if (strlen($payload) < self::MIN_PAYLOAD_LEN) return false;

        $library = self::loadLibrary();
        $hash = md5($payload);

        // 已存在，只更新命中次数
        if (isset($library['fingerprints'][$hash])) {
            $library['fingerprints'][$hash]['hit_count']++;
            $library['fingerprints'][$hash]['last_seen'] = time();
            return self::saveLibrary($library);
        }

        // 新增
        $library['fingerprints'][$hash] = [
            'fingerprint' => self::simhash($payload),
            'sample'      => mb_substr($payload, 0, 200, 'UTF-8'),
            'attack_type' => $meta['attack_type'] ?? 'unknown',
            'score'       => $meta['score'] ?? 0,
            'hit_count'   => 1,
            'first_seen'  => time(),
            'last_seen'   => time(),
        ];

        // 上限裁剪：删最久未命中的
        if (count($library['fingerprints']) > self::MAX_LIBRARY_SIZE) {
            uasort($library['fingerprints'], function($a, $b) {
                return ($a['last_seen'] ?? 0) <=> ($b['last_seen'] ?? 0);
            });
            $library['fingerprints'] = array_slice(
                $library['fingerprints'],
                -((int)(self::MAX_LIBRARY_SIZE * 0.8)),
                null,
                true
            );
        }

        return self::saveLibrary($library);
    }

    /**
     * 生成 SimHash 指纹（64 位二进制字符串）
     */
    public static function simhash(string $payload): string {
        $tokens = class_exists('NaiveBayesClassifier')
            ? NaiveBayesClassifier::tokenize($payload)
            : preg_split('/\s+/', strtolower(trim($payload)));

        if (empty($tokens)) {
            return str_repeat('0', self::SIMHASH_BITS);
        }

        $vector = array_fill(0, self::SIMHASH_BITS, 0);
        foreach ($tokens as $token) {
            $h = crc32((string)$token);
            for ($i = 0; $i < self::SIMHASH_BITS; $i++) {
                $bit = ($h >> ($i % 32)) & 1;
                $vector[$i] += $bit ? 1 : -1;
            }
        }

        $fp = '';
        for ($i = 0; $i < self::SIMHASH_BITS; $i++) {
            $fp .= ($vector[$i] > 0) ? '1' : '0';
        }
        return $fp;
    }

    /**
     * Hamming 相似度 = 1 - (不同位数 / 总位数)
     */
    public static function hammingSimilarity(string $a, string $b): float {
        if (strlen($a) !== self::SIMHASH_BITS || strlen($b) !== self::SIMHASH_BITS) {
            return 0.0;
        }
        $diff = 0;
        for ($i = 0; $i < self::SIMHASH_BITS; $i++) {
            if ($a[$i] !== $b[$i]) $diff++;
        }
        return 1.0 - ($diff / self::SIMHASH_BITS);
    }

    /** 指纹库状态 */
    public static function stats(): array {
        $lib = self::loadLibrary();
        $types = [];
        foreach ($lib['fingerprints'] as $entry) {
            $t = $entry['attack_type'] ?? 'unknown';
            if (!isset($types[$t])) $types[$t] = 0;
            $types[$t]++;
        }
        return [
            'total'          => count($lib['fingerprints']),
            'types'          => $types,
            'threshold'      => self::SIMILARITY_THRESHOLD,
            'max_size'       => self::MAX_LIBRARY_SIZE,
        ];
    }

    // ====================== 内部 ======================

    private static function loadLibrary(): array {
        $file = self::getLibraryFile();
        if (class_exists('Learning_Storage')) {
            return Learning_Storage::read($file, ['fingerprints' => []]);
        }
        // 兜底
        if (!is_file($file)) return ['fingerprints' => []];
        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') return ['fingerprints' => []];
        $data = json_decode($raw, true);
        return is_array($data) && isset($data['fingerprints']) ? $data : ['fingerprints' => []];
    }

    private static function saveLibrary(array $library): bool {
        $file = self::getLibraryFile();
        if (class_exists('Learning_Storage')) {
            return Learning_Storage::write($file, $library);
        }
        $dir = dirname($file);
        if (!is_dir($dir)) @mkdir($dir, 0775, true);
        $tmp = $file . '.tmp.' . getmypid();
        if (@file_put_contents($tmp, json_encode($library, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX) === false) {
            return false;
        }
        return @rename($tmp, $file);
    }

    private static function getLibraryFile(): string {
        $log = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
        return $log . '/learning/fingerprints.json';
    }
}