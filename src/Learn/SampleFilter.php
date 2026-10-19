<?php
/**
 * 样本过滤器
 * 职责：判断样本是否值得训练、是否重复、类别是否均衡
 * 设计：纯判断 + 无副作用；阈值全部常量可配
 */
defined('ABSPATH') || exit;

class Learning_SampleFilter {

    // 高置信度攻击样本门槛
    const ATTACK_MIN_SCORE      = 75.0;
    const ATTACK_MIN_CONFIDENCE = 0.80;

    // 中风险（进审核队列）
    const REVIEW_MIN_SCORE      = 40.0;

    // 载荷长度
    const MIN_PAYLOAD_LEN = 8;
    const MAX_PAYLOAD_LEN = 10000;

    // 去重窗口（秒）
    const DEDUP_WINDOW = 86400;

    // 正常/攻击样本比上限（超过则暂停正常样本训练，防偏斜）
    const NORMAL_ATTACK_RATIO_MAX = 3.0;

    // 冷启动总样本门槛
    const COLD_START_MIN_TOTAL = 30;
    const COLD_START_MIN_PER_CLASS = 10;

    /** 是否高置信度攻击样本（可直接训练） */
    public static function isHighConfidenceAttack(array $sample): bool {
        if (($sample['class'] ?? '') !== 'attack') return false;
        if (!self::isValidPayload($sample)) return false;
        if (($sample['score'] ?? 0) < self::ATTACK_MIN_SCORE) return false;
        if (($sample['confidence'] ?? 0) < self::ATTACK_MIN_CONFIDENCE) return false;
        if (self::isDuplicate($sample['payload_md5'] ?? '')) return false;
        return true;
    }

    /** 是否中风险（进审核队列） */
    public static function isMediumRisk(array $sample): bool {
        if (($sample['class'] ?? '') !== 'attack') return false;
        if (!self::isValidPayload($sample)) return false;
        $score = (float)($sample['score'] ?? 0);
        if ($score < self::REVIEW_MIN_SCORE) return false;
        if ($score >= self::ATTACK_MIN_SCORE
            && ($sample['confidence'] ?? 0) >= self::ATTACK_MIN_CONFIDENCE) {
            return false; // 高置信度走训练，不进审核
        }
        if (self::isDuplicate($sample['payload_md5'] ?? '')) return false;
        return true;
    }

    /** 正常样本是否可训练（受均衡约束） */
    public static function isTrainableNormal(array $sample): bool {
        if (($sample['class'] ?? '') !== 'normal') return false;
        if (!self::isValidPayload($sample)) return false;
        if (self::isDuplicate($sample['payload_md5'] ?? '')) return false;
        if (!self::isClassBalanced('normal')) return false;
        return true;
    }

    /** 载荷合法性 */
    public static function isValidPayload(array $sample): bool {
        $payload = (string)($sample['payload'] ?? '');
        $len = strlen($payload);
        if ($len < self::MIN_PAYLOAD_LEN || $len > self::MAX_PAYLOAD_LEN) return false;
        // 全空白/控制字符直接拒
        if (trim($payload) === '') return false;
        return true;
    }

    /** 去重检查（读写去重索引） */
    public static function isDuplicate(string $md5): bool {
        if ($md5 === '') return true;
        $file = self::getDedupFile();
        $index = Learning_Storage::read($file, ['items' => []]);
        $now = time();
        $cutoff = $now - self::DEDUP_WINDOW;

        // 清理过期
        if (!empty($index['items'])) {
            foreach ($index['items'] as $h => $ts) {
                if ($ts < $cutoff) unset($index['items'][$h]);
            }
        }
        if (isset($index['items'][$md5])) return true;

        // 登记
        $index['items'][$md5] = $now;
        // 上限防膨胀
        if (count($index['items']) > 50000) {
            asort($index['items']);
            $index['items'] = array_slice($index['items'], -40000, null, true);
        }
        Learning_Storage::write($file, $index);
        return false;
    }

    /** 类别均衡检查 */
    public static function isClassBalanced(string $class): bool {
        $info = self::getClassCounts();
        $attack = $info['attack'];
        $normal = $info['normal'];
        if ($class === 'normal') {
            if ($attack === 0) return false; // 没有攻击样本，正常样本训练无意义
            return ($normal + 1) / $attack <= self::NORMAL_ATTACK_RATIO_MAX;
        }
        if ($class === 'attack') {
            if ($normal === 0) return true; // 攻击样本始终可训练
            return $attack / $normal <= self::NORMAL_ATTACK_RATIO_MAX;
        }
        return true;
    }

    /** 是否处于冷启动（样本不足） */
    public static function isColdStart(): bool {
        $info = self::getClassCounts();
        if (($info['attack'] + $info['normal']) < self::COLD_START_MIN_TOTAL) return true;
        if ($info['attack'] < self::COLD_START_MIN_PER_CLASS) return true;
        if ($info['normal'] < self::COLD_START_MIN_PER_CLASS) return true;
        return false;
    }

    private static function getClassCounts(): array {
        $modelFile = self::getModelFile();
        $model = Learning_Storage::read($modelFile, []);
        return [
            'attack' => (int)($model['classes']['attack']['count'] ?? 0),
            'normal' => (int)($model['classes']['normal']['count'] ?? 0),
        ];
    }

    private static function getDedupFile(): string {
        return self::logPath() . '/learning/dedup_index.json';
    }

    private static function getModelFile(): string {
        return self::logPath() . '/bayes_model.json';
    }

    private static function logPath(): string {
        return defined('WAF_LOG_PATH') ? WAF_LOG_PATH : (dirname(__DIR__, 2) . '/logs');
    }
}