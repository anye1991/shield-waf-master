<?php
/**
 * 盾甲 WAF — 通用双重密码加密库 (DualPassword)
 *
 * 目标：任何 PHP 网站都可直接引入使用，零外部依赖，兼容 PHP 5.6 到最新版
 *
 * 核心特性：
 *   1. 双层哈希：主层(Argon2id/bcrypt) + 副层(bcrypt)，两层都必须通过验证
 *   2. 算法自动降级：环境不支持强算法时自动降到可用的最强算法
 *   3. 向前兼容：支持验证旧密码（md5/sha1/sha256/bcrypt/wordpress phpass等），登录后自动升级
 *   4. 数据库无关：只负责 hash/verify，不依赖任何数据库
 *
 * 存储格式：
 *   dual$v1$<base64(json_payload)>
 *
 * 算法优先级（主层，从高到低）：
 *   1. argon2id-sodium   (PHP 7.2+ ext-sodium)
 *   2. argon2id          (PHP 7.3+ PASSWORD_ARGON2ID)
 *   3. argon2i           (PHP 7.2+ PASSWORD_ARGON2I)
 *   4. bcrypt-12         (PHP 5.5+ PASSWORD_BCRYPT cost=12)
 *   5. bcrypt-10         (PHP 5.5+ PASSWORD_BCRYPT cost=10)
 *
 * 副层固定：bcrypt cost=10（兼容性最好，所有 PHP 5.5+ 都有）
 *
 * 旧密码兼容格式（验证时自动识别，登录成功后自动升级）：
 *   - $2y$ / $2a$ / $2b$    bcrypt
 *   - $P$ / $H$              phpass (WordPress)
 *   - $argon2id$ / $argon2i$ argon2
 *   - 32 字符 hex             MD5
 *   - 40 字符 hex             SHA-1
 *   - 64 字符 hex             SHA-256
 *   - 128 字符 hex            SHA-512
 *
 * 用法：
 *   require '/path/to/shield-waf/src/Password/DualPassword.php';
 *   $hash = DualPassword::hash($plainPassword);
 *   $ok   = DualPassword::verify($plainPassword, $storedHash);
 *   $new  = DualPassword::needsRehash($storedHash); // 升级检测
 */

if (!class_exists('DualPassword', false)) {

    class DualPassword
    {
        const FORMAT_PREFIX = 'dual$v1$';
        const FORMAT_VERSION = 1;

        // 主层 Argon2 参数（抗 GPU/ASIC 平衡值）
        const ARGON2_MEM = 65536;   // 64 MB
        const ARGON2_TIME = 4;
        const ARGON2_THREADS = 1;

        // sodium 参数档
        const SODIUM_OPS  = 2;
        const SODIUM_MEM = 67108864;

        // bcrypt 成本
        const BCRYPT_COST_PRIMARY = 12;
        const BCRYPT_COST_SECONDARY = 10;

        // ============= 哈希生成 =============

        /**
         * 双重哈希：返回 dual$v1$<base64> 字符串
         *
         * @param string $plain 明文密码
         * @return string 双重哈希
         * @throws InvalidArgumentException 空密码
         */
        public static function hash($plain)
        {
            if ($plain === '' || $plain === null) {
                throw new InvalidArgumentException('密码不能为空');
            }

            $primary = self::hashPrimary($plain);
            $secondary = self::hashSecondary($plain);

            if ($primary === false) {
                throw new RuntimeException('主层哈希生成失败，无可用算法');
            }
            if ($secondary === false) {
                throw new RuntimeException('副层哈希生成失败，无可用算法');
            }

            $payload = array(
                'v'          => self::FORMAT_VERSION,
                'primary'    => $primary,
                'secondary'  => $secondary,
                'created_at' => time(),
                'meta'       => array(
                    'php_version'  => PHP_VERSION,
                    'best_primary' => self::detectBestPrimaryAlgo(),
                ),
            );

            return self::FORMAT_PREFIX . base64_encode(json_encode($payload));
        }

        /** 主层哈希：选最强可用算法 */
        private static function hashPrimary($plain)
        {
            // 1. sodium argon2id（最强）
            if (function_exists('sodium_crypto_pwhash_str')) {
                $hash = sodium_crypto_pwhash_str($plain, self::SODIUM_OPS, self::SODIUM_MEM);
                return array('algo' => 'argon2id-sodium', 'hash' => $hash);
            }

            // 2. password_hash argon2id
            if (defined('PASSWORD_ARGON2ID') && PASSWORD_ARGON2ID) {
                $hash = password_hash($plain, PASSWORD_ARGON2ID, array(
                    'memory_cost' => self::ARGON2_MEM,
                    'time_cost'   => self::ARGON2_TIME,
                    'threads'     => self::ARGON2_THREADS,
                ));
                return array('algo' => 'argon2id', 'hash' => $hash);
            }

            // 3. password_hash argon2i
            if (defined('PASSWORD_ARGON2I') && PASSWORD_ARGON2I) {
                $hash = password_hash($plain, PASSWORD_ARGON2I, array(
                    'memory_cost' => self::ARGON2_MEM,
                    'time_cost'   => self::ARGON2_TIME,
                    'threads'     => self::ARGON2_THREADS,
                ));
                return array('algo' => 'argon2i', 'hash' => $hash);
            }

            // 4. bcrypt cost=12（兜底）
            if (function_exists('password_hash') || function_exists('crypt')) {
                $hash = self::bcryptHash($plain, self::BCRYPT_COST_PRIMARY);
                return array('algo' => 'bcrypt-12', 'hash' => $hash);
            }

            return false;
        }

        /** 副层哈希：固定 bcrypt cost=10 */
        private static function hashSecondary($plain)
        {
            $hash = self::bcryptHash($plain, self::BCRYPT_COST_SECONDARY);
            return array('algo' => 'bcrypt', 'hash' => $hash);
        }

        // ============= 验证 =============

        /**
         * 双重验证：两层都通过才返回 true
         *
         * 兼容旧密码格式：
         *   bcrypt / phpass / argon2 / md5 / sha1 / sha256 / sha512
         *   验证通过后可调用 needsRehash() 检测是否需要升级
         *
         * @param string $plain 明文
         * @param string $stored 存储的 hash
         * @return bool
         */
        public static function verify($plain, $stored)
        {
            if ($plain === '' || $stored === '' || $stored === null) {
                return false;
            }

            // 1. 双重哈希格式
            if (strpos($stored, self::FORMAT_PREFIX) === 0) {
                $payload = self::parsePayload($stored);
                if ($payload === null) {
                    self::verifySingle($plain, 'bcrypt', '$2y$10$' . str_repeat('0', 53));
                    return false;
                }

                $primaryOk   = self::verifySingle($plain, $payload['primary']['algo'], $payload['primary']['hash']);
                $secondaryOk = self::verifySingle($plain, $payload['secondary']['algo'], $payload['secondary']['hash']);

                $trueStr  = '1';
                $falseStr = '0';
                $primaryStr   = $primaryOk   ? $trueStr : $falseStr;
                $secondaryStr = $secondaryOk ? $trueStr : $falseStr;

                return hash_equals($primaryStr . $secondaryStr, $trueStr . $trueStr);
            }

            // 2. 旧格式兼容（单 hash）
            return self::verifyLegacy($plain, $stored);
        }

        /** 单层验证 */
        private static function verifySingle($plain, $algo, $hash)
        {
            switch ($algo) {
                case 'argon2id-sodium':
                    if (!function_exists('sodium_crypto_pwhash_str_verify')) return false;
                    try {
                        return sodium_crypto_pwhash_str_verify($hash, $plain);
                    } catch (Exception $e) {
                        return false;
                    }

                case 'argon2id':
                case 'argon2i':
                case 'bcrypt':
                case 'bcrypt-12':
                    // 我们自己生成的 bcrypt 用了 preKey（超长密码 sha256 预处理）
                    $key = self::bcryptPreKey($plain);
                    if (function_exists('password_verify')) {
                        return password_verify($key, $hash);
                    }
                    // PHP < 5.5 兜底：crypt()
                    return self::cryptVerify($key, $hash);

                default:
                    return false;
            }
        }

        /** 旧密码格式兼容验证 */
        private static function verifyLegacy($plain, $stored)
        {
            // bcrypt ($2y$ / $2a$ / $2b$)
            if (preg_match('/^\$2[aby]\$\d{2}\$/', $stored)) {
                if (function_exists('password_verify')) {
                    return password_verify($plain, $stored);
                }
                return self::cryptVerify($plain, $stored);
            }

            // phpass (WordPress) $P$ / $H$
            if (preg_match('/^\$[PH]\$/', $stored)) {
                return self::verifyPhpass($plain, $stored);
            }

            // argon2id / argon2i
            if (strpos($stored, '$argon2') === 0) {
                if (function_exists('password_verify')) {
                    return password_verify($plain, $stored);
                }
                return false;
            }

            // 纯 hex 哈希：md5/sha1/sha256/sha512
            if (preg_match('/^[a-f0-9]{32,128}$/i', $stored)) {
                $len = strlen($stored);
                switch ($len) {
                    case 32:  // md5
                        return hash_equals(strtolower($stored), md5($plain));
                    case 40:  // sha1
                        return hash_equals(strtolower($stored), sha1($plain));
                    case 64:  // sha256
                        if (function_exists('hash')) {
                            return hash_equals(strtolower($stored), hash('sha256', $plain));
                        }
                        return false;
                    case 128: // sha512
                        if (function_exists('hash')) {
                            return hash_equals(strtolower($stored), hash('sha512', $plain));
                        }
                        return false;
                    default:
                        return false;
                }
            }

            return false;
        }

        // ============= 重哈希检测 =============

        /**
         * 是否需要升级到双重哈希
         * 触发条件：
         *   - 不是 dual-v1 格式（旧密码）
         *   - 主层算法不是当前最优
         *   - 主层/副层参数过低
         */
        public static function needsRehash($stored)
        {
            if ($stored === '' || $stored === null) return true;

            // 非双重格式 → 需要升级
            if (strpos($stored, self::FORMAT_PREFIX) !== 0) return true;

            $payload = self::parsePayload($stored);
            if ($payload === null) return true;

            $primaryAlgo = $payload['primary']['algo'];
            $primaryHash = $payload['primary']['hash'];
            $secondaryHash = $payload['secondary']['hash'];

            // 算法升级检测
            $best = self::detectBestPrimaryAlgo();
            if ($primaryAlgo !== $best) return true;

            // 参数升级检测
            if (in_array($primaryAlgo, array('argon2id', 'argon2i', 'bcrypt', 'bcrypt-12'), true)) {
                if (function_exists('password_needs_rehash')) {
                    $algoConst = self::getAlgoConst($primaryAlgo);
                    $options = self::getAlgoOptions($primaryAlgo);
                    if (password_needs_rehash($primaryHash, $algoConst, $options)) {
                        return true;
                    }
                }
            }

            // 副层 cost 过低
            if (function_exists('password_needs_rehash')) {
                if (password_needs_rehash($secondaryHash, PASSWORD_BCRYPT, array('cost' => self::BCRYPT_COST_SECONDARY))) {
                    return true;
                }
            }

            return false;
        }

        // ============= 信息查询 =============

        /** 返回 hash 详细信息 */
        public static function info($stored)
        {
            if ($stored === '' || $stored === null) {
                return array('format' => 'empty', 'secure' => false);
            }

            if (strpos($stored, self::FORMAT_PREFIX) === 0) {
                $payload = self::parsePayload($stored);
                if ($payload === null) {
                    return array('format' => 'invalid', 'secure' => false);
                }
                return array(
                    'format'         => 'dual-v1',
                    'secure'         => true,
                    'primary_algo'   => $payload['primary']['algo'],
                    'secondary_algo' => $payload['secondary']['algo'],
                    'primary'        => $payload['primary']['algo'],
                    'secondary'      => $payload['secondary']['algo'],
                    'created_at'     => $payload['created_at'],
                    'best_algo'      => self::detectBestPrimaryAlgo(),
                    'needs_rehash'   => self::needsRehash($stored),
                );
            }

            // 旧格式识别
            $fmt = self::detectLegacyFormat($stored);
            return array(
                'format'       => $fmt,
                'secure'       => false,
                'note'         => '旧格式，登录后自动升级为双重哈希',
                'needs_rehash' => true,
            );
        }

        /** 当前环境最强主层算法 */
        public static function detectBestPrimaryAlgo()
        {
            if (function_exists('sodium_crypto_pwhash_str')) return 'argon2id-sodium';
            if (defined('PASSWORD_ARGON2ID') && PASSWORD_ARGON2ID) return 'argon2id';
            if (defined('PASSWORD_ARGON2I') && PASSWORD_ARGON2I) return 'argon2i';
            return 'bcrypt-12';
        }

        /** 当前环境所有可用算法 */
        public static function getAvailableAlgos()
        {
            $algos = array();
            if (function_exists('sodium_crypto_pwhash_str')) {
                $algos[] = array('algo' => 'argon2id-sodium', 'desc' => 'libsodium Argon2id（最强，抗 GPU/ASIC）');
            }
            if (defined('PASSWORD_ARGON2ID') && PASSWORD_ARGON2ID) {
                $algos[] = array('algo' => 'argon2id', 'desc' => 'password_hash Argon2id');
            }
            if (defined('PASSWORD_ARGON2I') && PASSWORD_ARGON2I) {
                $algos[] = array('algo' => 'argon2i', 'desc' => 'password_hash Argon2i');
            }
            $algos[] = array('algo' => 'bcrypt-12', 'desc' => 'bcrypt cost=12（主层兜底）');
            $algos[] = array('algo' => 'bcrypt', 'desc' => 'bcrypt cost=10（副层固定）');
            return $algos;
        }

        /** 性能基准测试 */
        public static function benchmark($plain = 'benchmark-test-password')
        {
            $result = array(
                'php_version' => PHP_VERSION,
                'best_algo'   => self::detectBestPrimaryAlgo(),
                'available'   => self::getAvailableAlgos(),
                'benchmarks'  => array(),
            );

            // bcrypt cost=10
            $t = microtime(true);
            $h = self::bcryptHash($plain, 10);
            $result['benchmarks']['bcrypt-10'] = array(
                'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
            );

            // bcrypt cost=12
            $t = microtime(true);
            self::bcryptHash($plain, 12);
            $result['benchmarks']['bcrypt-12'] = array(
                'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
            );

            // sodium argon2id
            if (function_exists('sodium_crypto_pwhash_str')) {
                $t = microtime(true);
                sodium_crypto_pwhash_str($plain, self::SODIUM_OPS, self::SODIUM_MEM);
                $result['benchmarks']['argon2id-sodium'] = array(
                    'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
                );
            }

            // 完整双重哈希
            $t = microtime(true);
            $dual = self::hash($plain);
            $result['benchmarks']['dual-full'] = array(
                'hash_time_ms' => round((microtime(true) - $t) * 1000, 2),
            );

            // 双重验证
            $t = microtime(true);
            self::verify($plain, $dual);
            $result['benchmarks']['dual-verify'] = array(
                'verify_time_ms' => round((microtime(true) - $t) * 1000, 2),
            );

            return $result;
        }

        // ============= 辅助内部方法 =============

        private static function parsePayload($stored)
        {
            $b64 = substr($stored, strlen(self::FORMAT_PREFIX));
            $json = base64_decode($b64, true);
            if ($json === false) return null;
            $payload = json_decode($json, true);
            if (!is_array($payload)) return null;
            if (!isset($payload['primary']['hash'], $payload['secondary']['hash'])) return null;
            return $payload;
        }

        private static function detectLegacyFormat($stored)
        {
            if (preg_match('/^\$2[aby]\$\d{2}\$/', $stored)) return 'bcrypt';
            if (preg_match('/^\$[PH]\$/', $stored)) return 'phpass';
            if (strpos($stored, '$argon2id$') === 0) return 'argon2id';
            if (strpos($stored, '$argon2i$') === 0) return 'argon2i';
            if (preg_match('/^[a-f0-9]{32}$/i', $stored)) return 'md5';
            if (preg_match('/^[a-f0-9]{40}$/i', $stored)) return 'sha1';
            if (preg_match('/^[a-f0-9]{64}$/i', $stored)) return 'sha256';
            if (preg_match('/^[a-f0-9]{128}$/i', $stored)) return 'sha512';
            return 'unknown';
        }

        private static function getAlgoConst($algo)
        {
            switch ($algo) {
                case 'argon2id':  return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
                case 'argon2i':   return defined('PASSWORD_ARGON2I') ? PASSWORD_ARGON2I : PASSWORD_BCRYPT;
                case 'bcrypt-12': return PASSWORD_BCRYPT;
                case 'bcrypt':    return PASSWORD_BCRYPT;
                default:          return PASSWORD_BCRYPT;
            }
        }

        private static function getAlgoOptions($algo)
        {
            switch ($algo) {
                case 'argon2id':
                case 'argon2i':
                    return array(
                        'memory_cost' => self::ARGON2_MEM,
                        'time_cost'   => self::ARGON2_TIME,
                        'threads'     => self::ARGON2_THREADS,
                    );
                case 'bcrypt-12':
                    return array('cost' => self::BCRYPT_COST_PRIMARY);
                case 'bcrypt':
                default:
                    return array('cost' => self::BCRYPT_COST_SECONDARY);
            }
        }

        private static function bcryptHash($plain, $cost)
        {
            // bcrypt 只处理前 72 字节，超长密码先 sha256 预哈希
            // 注意：所有 bcrypt 调用都走此函数，确保 hash 和 verify 用相同的预处理
            $key = self::bcryptPreKey($plain);

            if (function_exists('password_hash')) {
                return password_hash($key, PASSWORD_BCRYPT, array('cost' => $cost));
            }
            $salt = self::genBcryptSalt();
            return crypt($key, '$2a$' . $cost . '$' . $salt);
        }

        /** bcrypt 预哈希：>72 字节的密码先 sha256（十六进制）再 bcrypt，确保完整参与运算 */
        private static function bcryptPreKey($plain)
        {
            if (function_exists('mb_strlen')) {
                $len = mb_strlen($plain, '8bit');
            } else {
                $len = strlen($plain);
            }
            if ($len <= 72) return $plain;
            // sha256 十六进制输出 64 字符，在 bcrypt 72 字节限制内
            // 用 hex 而非二进制，避免某些 bcrypt 实现对二进制字符串处理异常
            return hash('sha256', $plain);
        }

        /** PHP < 5.5 兜底：生成 bcrypt 盐（22 字符） */
        private static function genBcryptSalt()
        {
            if (function_exists('random_bytes')) {
                return substr(strtr(base64_encode(random_bytes(16)), '+', '.'), 0, 22);
            }
            if (function_exists('openssl_random_pseudo_bytes')) {
                return substr(strtr(base64_encode(openssl_random_pseudo_bytes(16)), '+', '.'), 0, 22);
            }
            // 极端兜底：用 mt_rand（不安全但可用）
            $salt = '';
            for ($i = 0; $i < 22; $i++) {
                $salt .= substr('./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', mt_rand(0, 63), 1);
            }
            return $salt;
        }

        /** PHP < 5.5 兜底：用 crypt 验证 */
        private static function cryptVerify($plain, $hash)
        {
            if (!function_exists('crypt')) return false;
            $test = crypt($plain, $hash);
            if (!is_string($test) || strlen($test) < 13) return false;
            if (function_exists('hash_equals')) {
                return hash_equals($hash, $test);
            }
            return $test === $hash;
        }

        /** phpass (WordPress $P$/$H$) 验证 */
        private static function verifyPhpass($plain, $stored)
        {
            // phpass 编码字母表
            $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

            // 解析：$P$ + 1 字符迭代次数 + 8 字符盐 + 22 字符 hash
            if (strlen($stored) < 34) return false;

            $countLog2 = strpos($itoa64, $stored[3]);
            if ($countLog2 < 7 || $countLog2 > 30) return false;
            $count = 1 << $countLog2;

            $salt = substr($stored, 4, 8);
            if (strlen($salt) != 8) return false;

            $hash = md5($salt . $plain, true);
            do {
                $hash = md5($hash . $plain, true);
            } while (--$count);

            $expected = substr($stored, 12);
            $actual = self::encode64Phpass($hash, 16);

            if (function_exists('hash_equals')) {
                return hash_equals($expected, $actual);
            }
            return $expected === $actual;
        }

        /** phpass base64 编码 */
        private static function encode64Phpass($input, $count)
        {
            $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
            $output = '';
            $i = 0;
            do {
                $value = ord($input[$i++]);
                $output .= $itoa64[$value & 0x3f];
                if ($i < $count)
                    $value |= ord($input[$i]) << 8;
                $output .= $itoa64[($value >> 6) & 0x3f];
                if ($i++ >= $count)
                    break;
                if ($i < $count)
                    $value |= ord($input[$i]) << 16;
                $output .= $itoa64[($value >> 12) & 0x3f];
                if ($i++ >= $count)
                    break;
                $output .= $itoa64[($value >> 18) & 0x3f];
            } while ($i < $count);

            return $output;
        }
    }
}
