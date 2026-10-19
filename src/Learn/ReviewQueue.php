<?php
/**
 * 审核队列
 * 职责：中风险样本进队、人工 approve/reject、TTL 清理、CLI 审核
 * 设计：纯数据接口，不依赖控制台；提供 CLI 兜底
 */
defined('ABSPATH') || exit;

class Learning_ReviewQueue {

    const MAX_ITEMS = 500;
    const TTL_DAYS  = 14;

    /** 入队 */
    public static function push(array $sample): bool {
        if (empty($sample['payload_md5'])) return false;
        $file = self::getFile();
        $queue = Learning_Storage::read($file, ['items' => []]);
        $hash = $sample['payload_md5'];

        if (isset($queue['items'][$hash])) {
            // 已存在：仅更新分数和次数
            $queue['items'][$hash]['score'] = $sample['score'] ?? 0;
            $queue['items'][$hash]['confidence'] = $sample['confidence'] ?? 0;
            $queue['items'][$hash]['hit_count'] = ($queue['items'][$hash]['hit_count'] ?? 1) + 1;
            $queue['items'][$hash]['last_seen'] = time();
        } else {
            $queue['items'][$hash] = [
                'payload'     => mb_substr((string)$sample['payload'], 0, 500, 'UTF-8'),
                'class'       => $sample['class'] ?? 'attack',
                'score'       => $sample['score'] ?? 0,
                'confidence'  => $sample['confidence'] ?? 0,
                'risk_level'  => $sample['risk_level'] ?? 'unknown',
                'status'      => 'pending',
                'hit_count'   => 1,
                'queued_at'   => time(),
                'last_seen'   => time(),
            ];
        }

        // 上限裁剪：保留最新
        if (count($queue['items']) > self::MAX_ITEMS) {
            uasort($queue['items'], function($a, $b) {
                return ($a['last_seen'] ?? 0) <=> ($b['last_seen'] ?? 0);
            });
            $queue['items'] = array_slice($queue['items'], -self::MAX_ITEMS, null, true);
        }

        return Learning_Storage::write($file, $queue);
    }

    /** 列表 */
    public static function list(int $limit = 50, string $status = 'pending'): array {
        $file = self::getFile();
        $queue = Learning_Storage::read($file, ['items' => []]);
        $result = [];
        foreach ($queue['items'] as $hash => $item) {
            if ($status !== '' && ($item['status'] ?? '') !== $status) continue;
            $result[$hash] = $item;
        }
        uasort($result, function($a, $b) {
            return ($b['last_seen'] ?? 0) <=> ($a['last_seen'] ?? 0);
        });
        return array_slice($result, 0, $limit, true);
    }

    /** 审核通过 → 投喂训练 */
    public static function approve(string $hash): bool {
        $file = self::getFile();
        $queue = Learning_Storage::read($file, ['items' => []]);
        if (!isset($queue['items'][$hash])) return false;
        if (($queue['items'][$hash]['status'] ?? '') !== 'pending') return false;

        $payload = $queue['items'][$hash]['payload'] ?? '';
        $class   = $queue['items'][$hash]['class'] ?? 'attack';
        if ($payload !== '' && class_exists('NaiveBayesClassifier')) {
            NaiveBayesClassifier::train($payload, $class);
            NaiveBayesClassifier::save();
        }
        $queue['items'][$hash]['status'] = 'approved';
        $queue['items'][$hash]['approved_at'] = time();
        return Learning_Storage::write($file, $queue);
    }

    /** 审核拒绝 → 丢弃 */
    public static function reject(string $hash): bool {
        $file = self::getFile();
        $queue = Learning_Storage::read($file, ['items' => []]);
        if (!isset($queue['items'][$hash])) return false;
        if (($queue['items'][$hash]['status'] ?? '') !== 'pending') return false;
        $queue['items'][$hash]['status'] = 'rejected';
        $queue['items'][$hash]['rejected_at'] = time();
        return Learning_Storage::write($file, $queue);
    }

    /** 统计 */
    public static function stats(): array {
        $queue = Learning_Storage::read(self::getFile(), ['items' => []]);
        $stats = ['pending' => 0, 'approved' => 0, 'rejected' => 0];
        foreach ($queue['items'] as $item) {
            $s = $item['status'] ?? 'pending';
            if (isset($stats[$s])) $stats[$s]++;
        }
        $stats['total'] = count($queue['items']);
        return $stats;
    }

    /** TTL 清理 */
    public static function cleanup(): int {
        $file = self::getFile();
        $queue = Learning_Storage::read($file, ['items' => []]);
        $cutoff = time() - self::TTL_DAYS * 86400;
        $removed = 0;
        foreach ($queue['items'] as $hash => $item) {
            $ts = $item['last_seen'] ?? $item['queued_at'] ?? 0;
            if ($ts < $cutoff) { unset($queue['items'][$hash]); $removed++; }
        }
        if ($removed > 0) Learning_Storage::write($file, $queue);
        return $removed;
    }

    /** CLI 审核入口 */
    public static function cli(): void {
        if (PHP_SAPI !== 'cli') { echo "CLI only\n"; return; }
        $cmd = $argv[1] ?? 'list';
        switch ($cmd) {
            case 'list':
                $items = self::list(50, 'pending');
                if (empty($items)) { echo "队列为空\n"; return; }
                foreach ($items as $hash => $item) {
                    printf("[%s] score=%.1f hit=%d %s\n  %s\n",
                        substr($hash, 0, 8), $item['score'] ?? 0,
                        $item['hit_count'] ?? 1, $item['risk_level'] ?? '',
                        mb_substr($item['payload'] ?? '', 0, 120, 'UTF-8'));
                }
                break;
            case 'approve':
            case 'reject':
                $hash = $argv[2] ?? '';
                if ($hash === '') { echo "用法: cli.php {$cmd} <hash>\n"; return; }
                $ok = $cmd === 'approve' ? self::approve($hash) : self::reject($hash);
                echo $ok ? "OK\n" : "FAIL（不存在或已处理）\n";
                break;
            case 'stats':
                print_r(self::stats());
                break;
            case 'cleanup':
                echo "清理 " . self::cleanup() . " 条\n";
                break;
            default:
                echo "用法: cli.php [list|approve <hash>|reject <hash>|stats|cleanup]\n";
        }
    }

    private static function getFile(): string {
        $log = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
        return $log . '/learning/review_queue.json';
    }
}