<?php
/**
 * 训练调度器
 * 职责：攒批 + 定时 + 异步落盘 + 失败重试
 * 设计：不再每次请求 train，攒够 BATCH_SIZE 或超时 FLUSH_INTERVAL 才训练
 */
defined('ABSPATH') || exit;

class Learning_TrainingScheduler {

    const BATCH_SIZE      = 20;     // 攒够多少条训练一次
    const FLUSH_INTERVAL  = 300;    // 最长等 5 分钟
    const MAX_QUEUE_SIZE  = 500;    // 队列上限
    const MAX_RETRY       = 3;

    /** 入队（不立即训练） */
    public static function enqueue(array $sample): bool {
        $file = self::getQueueFile();
        $queue = Learning_Storage::read($file, ['items' => [], 'last_flush' => time()]);
        $queue['items'][] = [
            'payload' => (string)$sample['payload'],
            'class'   => $sample['class'] ?? 'attack',
            'score'   => $sample['score'] ?? 0,
            'ts'      => time(),
            'retry'   => 0,
        ];
        // 上限裁剪：丢最旧
        if (count($queue['items']) > self::MAX_QUEUE_SIZE) {
            $queue['items'] = array_slice($queue['items'], -self::MAX_QUEUE_SIZE);
        }
        return Learning_Storage::write($file, $queue);
    }

    /** 尝试 flush（由请求末尾或定时任务调用） */
    public static function maybeFlush(): int {
        $file = self::getQueueFile();
        $queue = Learning_Storage::read($file, ['items' => [], 'last_flush' => time()]);
        $items = $queue['items'] ?? [];
        if (empty($items)) return 0;

        $shouldFlush = count($items) >= self::BATCH_SIZE
                    || (time() - ($queue['last_flush'] ?? 0)) >= self::FLUSH_INTERVAL;
        if (!$shouldFlush) return 0;

        if (!class_exists('NaiveBayesClassifier')) return 0;

        $trained = 0;
        $remain = [];
        foreach ($items as $item) {
            $payload = (string)($item['payload'] ?? '');
            $class   = in_array($item['class'] ?? '', ['attack', 'normal'], true) ? $item['class'] : 'attack';
            if ($payload === '') continue;

            try {
                NaiveBayesClassifier::train($payload, $class);
                $trained++;
            } catch (\Throwable $e) {
                $item['retry'] = ($item['retry'] ?? 0) + 1;
                if ($item['retry'] < self::MAX_RETRY) $remain[] = $item;
            }
        }
        if ($trained > 0) {
            try { NaiveBayesClassifier::save(); } catch (\Throwable $e) {}
        }

        $queue['items'] = $remain;
        $queue['last_flush'] = time();
        Learning_Storage::write($file, $queue);
        return $trained;
    }

    /** 强制 flush（CLI / 定时任务） */
    public static function flushNow(): int {
        $file = self::getQueueFile();
        $queue = Learning_Storage::read($file, ['items' => [], 'last_flush' => time()]);
        if (empty($queue['items'])) return 0;
        $queue['last_flush'] = 0; // 强制触发
        Learning_Storage::write($file, $queue);
        return self::maybeFlush();
    }

    /** 队列状态 */
    public static function stats(): array {
        $queue = Learning_Storage::read(self::getQueueFile(), ['items' => [], 'last_flush' => time()]);
        $byClass = ['attack' => 0, 'normal' => 0];
        foreach ($queue['items'] as $item) {
            $c = $item['class'] ?? 'attack';
            if (isset($byClass[$c])) $byClass[$c]++;
        }
        return [
            'queue_size'   => count($queue['items'] ?? []),
            'attack'       => $byClass['attack'],
            'normal'       => $byClass['normal'],
            'last_flush'   => $queue['last_flush'] ?? 0,
            'last_flush_str' => !empty($queue['last_flush']) ? date('Y-m-d H:i:s', $queue['last_flush']) : 'never',
            'batch_size'   => self::BATCH_SIZE,
            'flush_interval' => self::FLUSH_INTERVAL,
        ];
    }

    private static function getQueueFile(): string {
        $log = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
        return $log . '/learning/train_queue.json';
    }
}