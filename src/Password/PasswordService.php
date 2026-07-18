<?php
/**
 * 盾甲 WAF — 网站密码双重加密服务 (PasswordService)
 *
 * 任何 PHP 网站都可引入使用，零侵入，自动兼容旧密码。
 *
 * 功能：
 *   1. register($username, $password)        - 用户注册，存双重哈希
 *   2. login($username, $password)           - 登录验证，旧密码自动升级为双重哈希
 *   3. changePassword($userId, $oldPass, $newPass) - 修改密码
 *   4. migrate($batchSize = 100)             - 批量迁移旧密码到双重哈希
 *   5. getStats()                            - 统计（总用户数、已升级数、未升级数）
 *   6. verifyPassword($password, $hash)      - 单次验密（静态方法）
 *   7. hashPassword($password)               - 单次哈希（静态方法）
 *
 * 数据库兼容性：
 *   - MySQL / MariaDB (mysqli / pdo_mysql)
 *   - PostgreSQL (pdo_pgsql / pgsql)
 *   - SQLite (pdo_sqlite / sqlite3)
 *   - MSSQL / SQL Server (pdo_sqlsrv)
 *
 * 旧密码格式兼容（自动识别，登录后自动升级）：
 *   - bcrypt ($2y$ $2a$ $2b$)
 *   - phpass WordPress ($P$ $H$)
 *   - argon2id / argon2i
 *   - md5 / sha1 / sha256 / sha512
 *
 * 用法示例：
 *   require '/path/to/shield-waf/src/Password/PasswordService.php';
 *
 *   $svc = ShieldPasswordService::init(array(
 *       'driver'   => 'pdo_mysql',
 *       'host'     => 'localhost',
 *       'dbname'   => 'mydb',
 *       'username' => 'root',
 *       'password' => 'secret',
 *       'table'    => 'users',
 *       'id_col'   => 'id',
 *       'name_col' => 'username',
 *       'pass_col' => 'password',
 *   ));
 *
 *   // 注册
 *   $userId = $svc->register('user1', 'my-password');
 *
 *   // 登录（自动升级旧密码）
 *   $user = $svc->login('user1', 'my-password');
 *
 *   // 批量迁移旧密码
 *   $result = $svc->migrate(100);
 */

if (!class_exists('ShieldPasswordService', false)) {

    if (!class_exists('DualPassword', false)) {
        require_once __DIR__ . '/DualPassword.php';
    }
    if (!class_exists('ShieldDbAdapter', false)) {
        require_once __DIR__ . '/DbAdapter.php';
    }

    class ShieldPasswordService
    {
        private $db;
        private $config;
        private $enabled = true;

        /**
         * 验证标识符格式（表名、列名等）
         *
         * @param string $name 标识符
         * @return void
         * @throws InvalidArgumentException 格式不合法
         */
        private function validateIdentifier($name)
        {
            if (!is_string($name) || !preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $name)) {
                throw new InvalidArgumentException('非法标识符: ' . $name);
            }
        }

        /**
         * 初始化密码服务
         *
         * @param array $config 配置
         * @return ShieldPasswordService
         */
        public static function init($config)
        {
            $svc = new self();
            $svc->config = $config;
            $svc->enabled = !isset($config['enabled']) || $config['enabled'];

            if (isset($config['table'])) {
                $svc->validateIdentifier($config['table']);
            }
            if (isset($config['id_col'])) {
                $svc->validateIdentifier($config['id_col']);
            }
            if (isset($config['name_col'])) {
                $svc->validateIdentifier($config['name_col']);
            }
            if (isset($config['pass_col'])) {
                $svc->validateIdentifier($config['pass_col']);
            }

            $svc->db = ShieldDbAdapter::connect($config);
            return $svc;
        }

        /** 获取数据库适配器 */
        public function getDb() { return $this->db; }

        /** 是否启用双重加密 */
        public function isEnabled() { return $this->enabled; }

        // ================= 注册 =================

        /**
         * 用户注册：密码存为双重哈希
         *
         * @param string $username 用户名
         * @param string $password 明文密码
         * @param array $extraData 额外字段
         * @return int|false 新用户 ID
         */
        public function register($username, $password, $extraData = array())
        {
            $table = $this->config['table'];
            $nameCol = $this->config['name_col'];
            $passCol = $this->config['pass_col'];

            foreach (array_keys($extraData) as $key) {
                $this->validateIdentifier($key);
            }

            if (!$this->enabled) {
                $hash = $password;
            } else {
                $hash = DualPassword::hash($password);
            }

            // 组装字段和值
            $fields = array_merge(array($nameCol => $username, $passCol => $hash), $extraData);
            $cols = array_keys($fields);
            $placeholders = array_fill(0, count($cols), '?');
            $values = array_values($fields);

            $sql = 'INSERT INTO ' . $table . ' (' . implode(',', $cols) . ') VALUES (' . implode(',', $placeholders) . ')';
            $this->db->execute($sql, $values);

            return $this->db->lastInsertId();
        }

        // ================= 登录 =================

        /**
         * 登录验证
         *
         * @param string $username 用户名
         * @param string $password 明文密码
         * @return array|false 用户数据（验证通过）或 false
         */
        public function login($username, $password)
        {
            $table = $this->config['table'];
            $nameCol = $this->config['name_col'];
            $passCol = $this->config['pass_col'];
            $idCol = $this->config['id_col'];

            $sql = 'SELECT * FROM ' . $table . ' WHERE ' . $nameCol . ' = ? LIMIT 1';
            $user = $this->db->queryOne($sql, array($username));
            if (!$user) return false;

            $storedHash = isset($user[$passCol]) ? $user[$passCol] : '';

            // 验证
            $ok = DualPassword::verify($password, $storedHash);
            if (!$ok) return false;

            // 自动升级：如果需要重哈希，登录成功后自动替换为双重哈希
            if ($this->enabled && DualPassword::needsRehash($storedHash)) {
                try {
                    $newHash = DualPassword::hash($password);
                    $updSql = 'UPDATE ' . $table . ' SET ' . $passCol . ' = ? WHERE ' . $idCol . ' = ?';
                    $this->db->execute($updSql, array($newHash, $user[$idCol]));
                    $user[$passCol] = $newHash;
                    $user['_upgraded'] = true;
                } catch (Exception $e) {
                    // 升级失败不影响登录
                }
            }

            return $user;
        }

        // ================= 修改密码 =================

        /**
         * 修改密码
         *
         * @param int|string $userId 用户ID
         * @param string $oldPassword 旧密码
         * @param string $newPassword 新密码
         * @return bool
         */
        public function changePassword($userId, $oldPassword, $newPassword)
        {
            $table = $this->config['table'];
            $idCol = $this->config['id_col'];
            $passCol = $this->config['pass_col'];

            // 读取当前
            $sql = 'SELECT * FROM ' . $table . ' WHERE ' . $idCol . ' = ? LIMIT 1';
            $user = $this->db->queryOne($sql, array($userId));
            if (!$user) return false;

            $stored = isset($user[$passCol]) ? $user[$passCol] : '';

            // 验旧密码
            if (!DualPassword::verify($oldPassword, $stored)) return false;

            // 更新
            $newHash = $this->enabled ? DualPassword::hash($newPassword) : $newPassword;
            $upd = 'UPDATE ' . $table . ' SET ' . $passCol . ' = ? WHERE ' . $idCol . ' = ?';
            $this->db->execute($upd, array($newHash, $userId));

            return true;
        }

        /** 强制重置密码（管理员） */
        public function resetPassword($userId, $newPassword)
        {
            $table = $this->config['table'];
            $idCol = $this->config['id_col'];
            $passCol = $this->config['pass_col'];

            $newHash = $this->enabled ? DualPassword::hash($newPassword) : $newPassword;
            $upd = 'UPDATE ' . $table . ' SET ' . $passCol . ' = ? WHERE ' . $idCol . ' = ?';
            $this->db->execute($upd, array($newHash, $userId));
            return true;
        }

        // ================= 批量迁移 =================

        /**
         * 批量迁移旧密码到双重哈希
         *
         * 注意：批量迁移只能"标记待迁移"，因为哈希无法反向解密。
         * 实际升级发生在用户下次登录时（login 方法自动处理）。
         *
         * 本方法返回统计信息，并可选地：
         *   - 生成迁移报告
         *   - 识别弱密码（纯 md5/sha1 等）
         *
         * @param int $batchSize 每批处理数量
         * @param int $offset 偏移
         * @return array
         */
        public function migrate($batchSize = 100, $offset = 0)
        {
            $table = $this->config['table'];
            $idCol = $this->config['id_col'];
            $passCol = $this->config['pass_col'];

            $sql = 'SELECT ' . $idCol . ', ' . $passCol . ' FROM ' . $table . ' LIMIT ? OFFSET ?';
            $rows = $this->db->query($sql, array($batchSize, $offset));

            $upgraded = 0;   // 已是双重哈希
            $legacy = 0;     // 旧格式（待下次登录升级）
            $formats = array(); // 各格式数量

            foreach ($rows as $row) {
                $hash = isset($row[$passCol]) ? $row[$passCol] : '';
                $info = DualPassword::info($hash);
                $fmt = $info['format'];

                if (!isset($formats[$fmt])) $formats[$fmt] = 0;
                $formats[$fmt]++;

                if ($fmt === 'dual-v1') $upgraded++;
                else $legacy++;
            }

            return array(
                'processed' => count($rows),
                'upgraded'  => $upgraded,
                'legacy'    => $legacy,
                'formats'   => $formats,
                'note'      => '旧密码格式将在用户下次登录时自动升级为双重哈希',
                'offset'    => $offset,
                'batch_size' => $batchSize,
            );
        }

        // ================= 统计 =================

        /** 获取用户密码格式统计 */
        public function getStats()
        {
            $table = $this->config['table'];
            $passCol = $this->config['pass_col'];

            // 先取总数
            $countRow = $this->db->queryOne('SELECT COUNT(*) AS cnt FROM ' . $table);
            $total = isset($countRow['cnt']) ? (int)$countRow['cnt'] : 0;

            // 抽样 1000 条估计各格式比例
            $sample = 1000;
            $rows = $this->db->query('SELECT ' . $passCol . ' FROM ' . $table . ' LIMIT ?', array($sample));

            $formats = array();
            $upgraded = 0;
            $legacyWeak = 0; // 弱加密（md5/sha1 等）
            $legacyStrong = 0; // 强加密（bcrypt/argon2）

            foreach ($rows as $row) {
                $hash = isset($row[$passCol]) ? $row[$passCol] : '';
                $info = DualPassword::info($hash);
                $fmt = $info['format'];
                if (!isset($formats[$fmt])) $formats[$fmt] = 0;
                $formats[$fmt]++;

                if ($fmt === 'dual-v1') $upgraded++;
                elseif (in_array($fmt, array('bcrypt', 'argon2id', 'argon2i'), true)) $legacyStrong++;
                elseif ($fmt !== 'empty' && $fmt !== 'unknown') $legacyWeak++;
            }

            $sampleCount = count($rows);
            $scale = $sampleCount > 0 ? $total / $sampleCount : 1;

            return array(
                'total_users'      => $total,
                'sampled'          => $sampleCount,
                'upgraded_est'     => (int)($upgraded * $scale),
                'legacy_weak_est'  => (int)($legacyWeak * $scale),
                'legacy_strong_est' => (int)($legacyStrong * $scale),
                'formats_est'      => array_map(function($v) use ($scale) { return (int)($v * $scale); }, $formats),
                'enabled'          => $this->enabled,
                'best_primary_algo' => DualPassword::detectBestPrimaryAlgo(),
            );
        }

        // ================= 静态便捷方法 =================

        /** 静态：生成双重哈希 */
        public static function hashPassword($password)
        {
            return DualPassword::hash($password);
        }

        /** 静态：验证密码 */
        public static function verifyPassword($password, $hash)
        {
            return DualPassword::verify($password, $hash);
        }

        /** 静态：是否需要升级 */
        public static function needsUpgrade($hash)
        {
            return DualPassword::needsRehash($hash);
        }

        /** 静态：获取 hash 信息 */
        public static function passwordInfo($hash)
        {
            return DualPassword::info($hash);
        }
    }
}
