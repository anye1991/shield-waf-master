<?php
/**
 * 盾甲 WAF 双重密码哈希引擎
 *
 * 设计原则：
 *   1. 双层哈希：主层（Argon2id 系）+ 副层（bcrypt），两层都必须通过验证
 *   2. 算法自动降级：环境无 sodium/argon2 时降级为 bcrypt-12 + bcrypt-10
 *   3. 数据库永不落明文：存储格式为 dual$v1$<base64-json>
 *   4. 自动迁移：检测到明文密码时自动哈希化并写入 hash 文件
 *   5. 时序安全：所有验证用 sodium/password_verify（内部已含时序安全）
 *
 * 存储格式：
 *   dual$v1$<base64(json_payload)>
 *
 *   payload = {
 *     "v": 1,
 *     "primary":   { "algo": "argon2id-sodium", "hash": "$argon2id..." },
 *     "secondary": { "algo": "bcrypt",          "hash": "$2y$10$..." },
 *     "created_at": 1234567890,
 *     "meta": { "ops_limit": "...", "mem_limit": "..." }
 *   }
 *
 * 算法优先级（主层）：
 *   1. argon2id-sodium   — ext-sodium (PHP 7.2+ 默认捆绑，抗 GPU/ASIC 最强)
 *   2. argon2id          — PASSWORD_ARGON2ID (PHP 7.3+ 编译时启用 argon2)
 *   3. argon2i           — PASSWORD_ARGON2I  (PHP 7.2+ 编译时启用 argon2)
 *   4. bcrypt-12         — PASSWORD_BCRYPT cost=12 (兜底，所有 PHP 都有)
 *
 * 副层固定：bcrypt cost=10（兼容性最好，作为冗余/降级备份验证）
 */
defined('ABSPATH') || exit;

class WafPassword
{
    const FORMAT_PREFIX = 'dual$v1$';
    const FORMAT_VERSION = 1;

    // 主层 Argon2 参数（抗 GPU/ASIC 平衡值）
    const ARGON2_MEM_COST  = 65536;   // 64 MB
    const ARGON2_TIME_COST = 4;
    const ARGON2_THREADS   = 1;
    // sodium INTERACTIVE 档（与上面参数接近）
    const SODIUM_OPS  = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE ?? 2;
    const SODIUM_MEM = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE ?? 67108864;

    // ============== 哈希生成 ==============

    /**
     * 双重哈希：返回 dual$v1$<base64> 字符串
     *
     * @param string $plain 明文密码
     * @return string 双重哈希字符串
     */
    public static function hash(string $plain): string
    {
        if ($plain === '') {
            throw new InvalidArgumentException('密码不能为空');
        }

        $payload = [
            'v'         => self::FORMAT_VERSION,
            'primary'   => self::hashPrimary($plain),
            'secondary' => self::hashSecondary($plain),
            'created_at' => time(),
            'meta'      => [
                'php_version'  => PHP_VERSION,
                'best_primary' => self::detectBestPrimaryAlgo(),
            ],
        ];

        return self::FORMAT_PREFIX . base64_encode(json_encode($payload));
    }

    /**
     * 主层哈希：自动选择最强可用算法
     */
    private static function hashPrimary(string $plain): array
    {
        // 1. 优先：sodium argon2id（最安全，抗 GPU/ASIC）
        if (function_exists('sodium_crypto_pwhash_str')) {
            $hash = sodium_crypto_pwhash_str(
                $plain,
                self::SODIUM_OPS,
                self::SODIUM_MEM
            );
            return ['algo' => 'argon2id-sodium', 'hash' => $hash];
        }

        // 2. 次：password_hash 的 argon2id
        if (defined('PASSWORD_ARGON2ID')) {
            $hash = password_hash($plain, PASSWORD_ARGON2ID, [
                'memory_cost' => self::ARGON2_MEM_COST,
                'time_cost'   => self::ARGON2_TIME_COST,
                'threads'     => self::ARGON2_THREADS,
            ]);
            return ['algo' => 'argon2id', 'hash' => $hash];
        }

        // 3. 再次：password_hash 的 argon2i
        if (defined('PASSWORD_ARGON2I')) {
            $hash = password_hash($plain, PASSWORD_ARGON2I, [
                'memory_cost' => self::ARGON2_MEM_COST,
                'time_cost'   => self::ARGON2_TIME_COST,
                'threads'     => self::ARGON2_THREADS,
            ]);
            return ['algo' => 'argon2i', 'hash' => $hash];
        }

        // 4. 兜底：bcrypt 高 cost
        $hash = password_hash($plain, PASSWORD_BCRYPT, ['cost' => 12]);
        return ['algo' => 'bcrypt-12', 'hash' => $hash];
    }

    /**
     * 副层哈希：固定 bcrypt cost=10（保证兼容性，作为冗余验证）
     */
    private static function hashSecondary(string $plain): array
    {
        $hash = password_hash($plain, PASSWORD_BCRYPT, ['cost' => 10]);
        return ['algo' => 'bcrypt', 'hash' => $hash];
    }

    // ============== 验证 ==============

    /**
     * 双重验证：两层都必须通过（双重保险）
     *
     * @param string $plain  明文密码
     * @param string $stored 存储的双重哈希
     * @return bool 两层都通过才返回 true
     */
    public static function verify(string $plain, string $stored): bool
    {
        if ($plain === '' || $stored === '') return false;

        // 1. 兼容：旧明文密码（开发期/迁移期）—— 用时序安全比较
        if (strpos($stored, self::FORMAT_PREFIX) !== 0) {
            return hash_equals($stored, $plain);
        }

        // 2. 解析双重哈希
        $payload = self::parsePayload($stored);
        if ($payload === null) return false;

        // 3. 双层验证：两层都必须通过
        $primaryOk   = self::verifyHash($plain, $payload['primary']['algo'], $payload['primary']['hash']);
        $secondaryOk = self::verifyHash($plain, $payload['secondary']['algo'], $payload['secondary']['hash']);

        return $primaryOk && $secondaryOk;
    }

    /**
     * 单层验证：用指定算法和 hash 验证明文
     */
    private static function verifyHash(string $plain, string $algo, string $hash): bool
    {
        switch ($algo) {
            case 'argon2id-sodium':
                if (!function_exists('sodium_crypto_pwhash_str_verify')) return false;
                try {
                    return sodium_crypto_pwhash_str_verify($hash, $plain);
                } catch (\Throwable $e) {
                    return false;
                }

            case 'argon2id':
            case 'argon2i':
            case 'bcrypt':
            case 'bcrypt-12':
                return password_verify($plain, $hash);

            default:
                return false;
        }
    }

    // ============== 重哈希检测 ==============

    /**
     * 检查是否需要重哈希（算法升级、参数变更时）
     *
     * 触发条件：
     *   - 当前最优算法与主层算法不同（如服务器加装了 sodium）
     *   - 主层参数过时（cost 太低）
     *   - 副层 cost 过低
     */
    public static function needsRehash(string $stored): bool
    {
        // 兼容：明文密码必须迁移
        if (strpos($stored, self::FORMAT_PREFIX) !== 0) return true;

        $payload = self::parsePayload($stored);
        if ($payload === null) return true;

        $primaryAlgo = $payload['primary']['algo'] ?? '';
        $primaryHash = $payload['primary']['hash'] ?? '';
        $secondaryHash = $payload['secondary']['hash'] ?? '';

        // 检查 1：当前最优算法是否变了
        $bestAlgo = self::detectBestPrimaryAlgo();
        if ($primaryAlgo !== $bestAlgo) return true;

        // 检查 2：主层参数是否需要升级
        if ($primaryAlgo === 'argon2id-sodium' && function_exists('sodium_crypto_pwhash_str_needs_rehash')) {
            if (sodium_crypto_pwhash_str_needs_rehash($primaryHash, self::SODIUM_OPS, self::SODIUM_MEM)) {
                return true;
            }
        } elseif (in_array($primaryAlgo, ['argon2id', 'argon2i', 'bcrypt', 'bcrypt-12'], true)) {
            $algoConst = self::getAlgoConstant($primaryAlgo);
            $options = self::getAlgoOptions($primaryAlgo);
            if (password_needs_rehash($primaryHash, $algoConst, $options)) {
                return true;
            }
        }

        // 检查 3：副层 cost 是否低于 10
        if (password_needs_rehash($secondaryHash, PASSWORD_BCRYPT, ['cost' => 10])) {
            return true;
        }

        return false;
    }

    // ============== 信息查询 ==============

    /**
     * 解析 hash 返回信息
     */
    public static function info(string $stored): array
    {
        if (strpos($stored, self::FORMAT_PREFIX) !== 0) {
            return [
                'format'   => 'legacy-plaintext',
                'secure'   => false,
                'note'     => '明文存储（不安全，请立即迁移）',
            ];
        }

        $payload = self::parsePayload($stored);
        if ($payload === null) {
            return ['format' => 'invalid', 'secure' => false, 'note' => '解析失败'];
        }

        return [
            'format'    => 'dual-v1',
            'secure'     => true,
            'primary'    => $payload['primary']['algo'] ?? 'unknown',
            'secondary'  => $payload['secondary']['algo'] ?? 'unknown',
            'created_at' => $payload['created_at'] ?? null,
            'best_algo'  => self::detectBestPrimaryAlgo(),
            'needs_rehash' => self::needsRehash($stored),
        ];
    }

    /**
     * 当前环境支持的最强算法
     */
    public static function detectBestPrimaryAlgo(): string
    {
        if (function_exists('sodium_crypto_pwhash_str')) return 'argon2id-sodium';
        if (defined('PASSWORD_ARGON2ID')) return 'argon2id';
        if (defined('PASSWORD_ARGON2I')) return 'argon2i';
        return 'bcrypt-12';
    }

    /**
     * 当前环境所有可用算法
     */
    public static function getAvailableAlgos(): array
    {
        $algos = [];
        if (function_exists('sodium_crypto_pwhash_str')) {
            $algos[] = ['algo' => 'argon2id-sodium', 'desc' => 'libsodium Argon2id（最强，抗 GPU/ASIC）'];
        }
        if (defined('PASSWORD_ARGON2ID')) {
            $algos[] = ['algo' => 'argon2id', 'desc' => 'password_hash Argon2id'];
        }
        if (defined('PASSWORD_ARGON2I')) {
            $algos[] = ['algo' => 'argon2i', 'desc' => 'password_hash Argon2i'];
        }
        $algos[] = ['algo' => 'bcrypt-12', 'desc' => 'bcrypt cost=12（兜底）'];
        $algos[] = ['algo' => 'bcrypt', 'desc' => 'bcrypt cost=10（副层固定）'];
        return $algos;
    }

    /**
     * 性能测试：测试本机算法性能
     */
    public static function benchmark(string $plain = 'benchmark-test-password'): array
    {
        $result = [
            'php_version'  => PHP_VERSION,
            'best_algo'    => self::detectBestPrimaryAlgo(),
            'available'    => self::getAvailableAlgos(),
            'benchmarks'   => [],
        ];

        // 测试 bcrypt cost=10
        $t = microtime(true);
        $h = password_hash($plain, PASSWORD_BCRYPT, ['cost' => 10]);
        $result['benchmarks']['bcrypt-10'] = [
            'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
            'verify_time_ms' => (function() use ($plain, $h) {
                $t = microtime(true); password_verify($plain, $h); return round((microtime(true) - $t) * 1000, 2);
            })(),
        ];

        // 测试 bcrypt cost=12（如果可用）
        $t = microtime(true);
        $h2 = password_hash($plain, PASSWORD_BCRYPT, ['cost' => 12]);
        $result['benchmarks']['bcrypt-12'] = [
            'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
        ];

        // 测试 argon2id-sodium（如果可用）
        if (function_exists('sodium_crypto_pwhash_str')) {
            $t = microtime(true);
            $h3 = sodium_crypto_pwhash_str($plain, self::SODIUM_OPS, self::SODIUM_MEM);
            $result['benchmarks']['argon2id-sodium'] = [
                'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
            ];
        }

        // 测试完整双重哈希
        $t = microtime(true);
        $dual = self::hash($plain);
        $result['benchmarks']['dual-full'] = [
            'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
        ];

        // 验证双重哈希
        $t = microtime(true);
        self::verify($plain, $dual);
        $result['benchmarks']['dual-verify'] = [
            'verify_time_ms' => round((microtime(true) - $t) * 1000, 2),
        ];

        return $result;
    }

    // ============== 内部辅助 ==============

    private static function parsePayload(string $stored): ?array
    {
        $b64 = substr($stored, strlen(self::FORMAT_PREFIX));
        $json = base64_decode($b64, true);
        if ($json === false) return null;
        $payload = json_decode($json, true);
        if (!is_array($payload)) return null;
        if (!isset($payload['primary']['hash'], $payload['secondary']['hash'])) return null;
        return $payload;
    }

    private static function getAlgoConstant(string $algo)
    {
        switch ($algo) {
            case 'argon2id':  return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
            case 'argon2i':   return defined('PASSWORD_ARGON2I') ? PASSWORD_ARGON2I : PASSWORD_BCRYPT;
            case 'bcrypt-12': return PASSWORD_BCRYPT;
            case 'bcrypt':     return PASSWORD_BCRYPT;
            default:           return PASSWORD_BCRYPT;
        }
    }

    private static function getAlgoOptions(string $algo): array
    {
        switch ($algo) {
            case 'argon2id':
            case 'argon2i':
                return [
                    'memory_cost' => self::ARGON2_MEM_COST,
                    'time_cost'   => self::ARGON2_TIME_COST,
                    'threads'     => self::ARGON2_THREADS,
                ];
            case 'bcrypt-12':
                return ['cost' => 12];
            case 'bcrypt':
            default:
                return ['cost' => 10];
        }
    }
}
