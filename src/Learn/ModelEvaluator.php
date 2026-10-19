<?php
/**
 * 模型评估器
 * 职责：留出集评估（准确率/召回/F1）、版本快照、回滚、指标历史
 * 设计：评估用独立样本池，不污染训练；快照保留最近 N 个
 */
defined('ABSPATH') || exit;

class Learning_ModelEvaluator {

    const MAX_SNAPSHOTS = 5;
    const EVAL_SAMPLE_SIZE = 200;

    /** 添加评估样本（训练时不消费，仅评估用） */
    public static function addEvalSample(string $payload, string $class): bool {
        if ($payload === '' || !in_array($class, ['attack', 'normal'], true)) return false;
        $file = self::getEvalFile();
        $pool = Learning_Storage::read($file, ['attack' => [], 'normal' => []]);
        $hash = md5($payload);
        if (isset($pool[$class][$hash])) return false;
        if (count($pool[$class]) >= 2000) {
            // 滚动淘汰最旧
            $pool[$class] = array_slice($pool[$class], -1500, null, true);
        }
        $pool[$class][$hash] = ['payload' => mb_substr($payload, 0, 500, 'UTF-8'), 'ts' => time()];
        return Learning_Storage::write($file, $pool);
    }

    /** 运行评估，返回指标 */
    public static function evaluate(): array {
        $pool = Learning_Storage::read(self::getEvalFile(), ['attack' => [], 'normal' => []]);
        if (empty($pool['attack']) || empty($pool['normal'])) {
            return ['ok' => false, 'reason' => 'empty_eval_pool'];
        }
        if (!class_exists('NaiveBayesClassifier')) {
            return ['ok' => false, 'reason' => 'classifier_missing'];
        }

        $tp = $tn = $fp = $fn = 0;
        foreach ($pool['attack'] as $item) {
            $r = NaiveBayesClassifier::predict($item['payload']);
            $predicted = $r['class'] ?? 'normal';
            if ($predicted === 'attack') $tp++; else $fn++;
        }
        foreach ($pool['normal'] as $item) {
            $r = NaiveBayesClassifier::predict($item['payload']);
            $predicted = $r['class'] ?? 'normal';
            if ($predicted === 'normal') $tn++; else $fp++;
        }

        $total = $tp + $tn + $fp + $fn;
        $accuracy  = $total > 0 ? ($tp + $tn) / $total : 0;
        $precision = ($tp + $fp) > 0 ? $tp / ($tp + $fp) : 0;
        $recall    = ($tp + $fn) > 0 ? $tp / ($tp + $fn) : 0;
        $f1        = ($precision + $recall) > 0 ? 2 * $precision * $recall / ($precision + $recall) : 0;

        $metrics = [
            'ok'        => true,
            'accuracy'  => round($accuracy, 4),
            'precision' => round($precision, 4),
            'recall'    => round($recall, 4),
            'f1'        => round($f1, 4),
            'tp' => $tp, 'tn' => $tn, 'fp' => $fp, 'fn' => $fn,
            'evaluated_at' => time(),
        ];

        // 记录历史
        $histFile = self::getHistoryFile();
        $history = Learning_Storage::read($histFile, ['runs' => []]);
        $history['runs'][] = $metrics;
        if (count($history['runs']) > 100) $history['runs'] = array_slice($history['runs'], -100);
        Learning_Storage::write($histFile, $history);

        return $metrics;
    }

    /** 保存当前模型快照 */
    public static function snapshot(): bool {
        $modelFile = self::getModelFile();
        if (!is_file($modelFile)) return false;
        $dir = self::getSnapshotDir();
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) return false;

        $ts = date('Ymd_His');
        $dst = $dir . '/model_' . $ts . '.json';
        if (!@copy($modelFile, $dst)) return false;

        // 清理旧快照
        $files = glob($dir . '/model_*.json');
        if (is_array($files) && count($files) > self::MAX_SNAPSHOTS) {
            sort($files);
            $remove = count($files) - self::MAX_SNAPSHOTS;
            for ($i = 0; $i < $remove; $i++) @unlink($files[$i]);
        }
        return true;
    }

    /** 回滚到指定快照 */
    public static function rollback(string $snapshotFile): bool {
        $dir = self::getSnapshotDir();
        $path = $dir . '/' . basename($snapshotFile);
        if (!is_file($path)) return false;
        $modelFile = self::getModelFile();
        return @copy($path, $modelFile);
    }

    /** 列出快照 */
    public static function listSnapshots(): array {
        $dir = self::getSnapshotDir();
        $files = glob($dir . '/model_*.json');
        if (!is_array($files)) return [];
        sort($files);
        $result = [];
        foreach ($files as $f) {
            $result[] = ['file' => basename($f), 'size' => filesize($f), 'time' => filemtime($f)];
        }
        return $result;
    }

    /** 指标历史 */
    public static function history(int $limit = 20): array {
        $history = Learning_Storage::read(self::getHistoryFile(), ['runs' => []]);
        return array_slice($history['runs'], -$limit);
    }

    private static function getModelFile(): string {
        return self::logPath() . '/bayes_model.json';
    }
    private static function getEvalFile(): string {
        return self::logPath() . '/learning/eval_pool.json';
    }
    private static function getHistoryFile(): string {
        return self::logPath() . '/learning/eval_history.json';
    }
    private static function getSnapshotDir(): string {
        return self::logPath() . '/learning/snapshots';
    }
    private static function logPath(): string {
        return defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
    }
}