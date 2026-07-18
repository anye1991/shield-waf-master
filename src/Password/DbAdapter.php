<?php
/**
 * 盾甲 WAF — 通用数据库适配器 (DbAdapter)
 *
 * 支持：MySQL/MariaDB (mysqli/pdo_mysql), PostgreSQL (pdo_pgsql/pgsql),
 *       SQLite (pdo_sqlite/sqlite3), MSSQL (pdo_sqlsrv)
 *
 * 统一接口：query / queryOne / execute / lastInsertId
 */
if (!class_exists('ShieldDbAdapter', false)) {

    class ShieldDbAdapter
    {
        private $connection;
        private $driver;

        private static function handleDbError($message)
        {
            $debug = defined('WAF_DB_DEBUG') && WAF_DB_DEBUG;
            if (!$debug) {
                $logDir = defined('WAF_LOG_PATH') ? WAF_LOG_PATH : __DIR__ . '/../../logs/';
                if (!is_dir($logDir)) {
                    @mkdir($logDir, 0700, true);
                }
                $ip = '0.0.0.0';
                if (function_exists('waf_get_real_ip')) {
                    $ip = waf_get_real_ip();
                } elseif (isset($_SERVER['REMOTE_ADDR'])) {
                    $ip = $_SERVER['REMOTE_ADDR'];
                }
                $logMsg = '[' . date('Y-m-d H:i:s') . '] [' . $ip . '] ' . $message . "\n";
                @file_put_contents($logDir . 'db_error.log', $logMsg, FILE_APPEND);
                return 'Database error';
            }
            return $message;
        }

        /**
         * 验证 host 格式（域名、IP 或 localhost）
         *
         * @param string $host
         * @return void
         * @throws InvalidArgumentException
         */
        private static function validateHost($host)
        {
            if (!is_string($host) || $host === '') {
                throw new InvalidArgumentException('host 不能为空');
            }
            if ($host === 'localhost') {
                return;
            }
            $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;
            $isDomain = preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $host);
            if (!$isIp && !$isDomain) {
                throw new InvalidArgumentException('非法 host 格式: ' . $host);
            }
        }

        /**
         * 验证端口号（1-65535）
         *
         * @param int|string $port
         * @return int
         * @throws InvalidArgumentException
         */
        private static function validatePort($port)
        {
            if (!is_numeric($port)) {
                throw new InvalidArgumentException('port 必须是整数');
            }
            $port = (int)$port;
            if ($port < 1 || $port > 65535) {
                throw new InvalidArgumentException('port 必须在 1-65535 范围内');
            }
            return $port;
        }

        /**
         * 验证 dbname 格式
         *
         * @param string $dbname
         * @return void
         * @throws InvalidArgumentException
         */
        private static function validateDbname($dbname)
        {
            if (!is_string($dbname) || !preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $dbname)) {
                throw new InvalidArgumentException('非法 dbname 格式: ' . $dbname);
            }
        }

        /**
         * 转义 PostgreSQL 连接字符串中的值
         *
         * @param string $value
         * @return string
         */
        private static function escapePgConnValue($value)
        {
            return "'" . str_replace(array('\\', "'"), array('\\\\', "\\'"), $value) . "'";
        }

        public static function connect($config)
        {
            $a = new self();
            $driver = isset($config['driver']) ? $config['driver'] : 'auto';

            switch ($driver) {
                case 'mysqli':
                    $a->connection = self::connMysqli($config);
                    break;
                case 'pdo_mysql':
                case 'mysql':
                    $a->connection = self::connPdo('mysql', $config);
                    break;
                case 'pdo_pgsql':
                case 'pgsql':
                    $a->connection = self::connPdo('pgsql', $config);
                    break;
                case 'pdo_sqlite':
                case 'sqlite':
                    $a->connection = self::connPdo('sqlite', $config);
                    break;
                case 'pdo_sqlsrv':
                case 'sqlsrv':
                case 'mssql':
                    $a->connection = self::connPdo('sqlsrv', $config);
                    break;
                case 'pg':
                case 'postgres':
                    $a->connection = self::connPgsql($config);
                    break;
                case 'sqlite3':
                    $a->connection = self::connSqlite3($config);
                    break;
                default:
                    list($conn, $detected) = self::autoConnect($config);
                    $a->connection = $conn;
                    $driver = $detected;
                    break;
            }

            $a->driver = $driver;
            return $a;
        }

        private static function autoConnect($config)
        {
            $cands = array();
            if (extension_loaded('pdo_mysql'))  $cands[] = 'pdo_mysql';
            if (extension_loaded('mysqli'))     $cands[] = 'mysqli';
            if (extension_loaded('pdo_pgsql'))  $cands[] = 'pdo_pgsql';
            if (extension_loaded('pgsql'))      $cands[] = 'pg';
            if (extension_loaded('pdo_sqlite')) $cands[] = 'pdo_sqlite';
            if (extension_loaded('sqlite3'))    $cands[] = 'sqlite3';
            if (extension_loaded('pdo_sqlsrv')) $cands[] = 'pdo_sqlsrv';

            if (empty($cands)) {
                throw new Exception('无可用数据库扩展');
            }

            $last = '';
            foreach ($cands as $c) {
                try {
                    switch ($c) {
                        case 'pdo_mysql':  return array(self::connPdo('mysql', $config), 'pdo_mysql');
                        case 'mysqli':    return array(self::connMysqli($config), 'mysqli');
                        case 'pdo_pgsql': return array(self::connPdo('pgsql', $config), 'pdo_pgsql');
                        case 'pg':         return array(self::connPgsql($config), 'pg');
                        case 'pdo_sqlite': return array(self::connPdo('sqlite', $config), 'pdo_sqlite');
                        case 'sqlite3':    return array(self::connSqlite3($config), 'sqlite3');
                        case 'pdo_sqlsrv': return array(self::connPdo('sqlsrv', $config), 'pdo_sqlsrv');
                    }
                } catch (Exception $e) {
                    $last = $e->getMessage();
                }
            }
            throw new Exception(self::handleDbError('所有数据库扩展连接失败: ' . $last));
        }

        // --- 连接 ---

        private static function connMysqli($c)
        {
            if (!extension_loaded('mysqli')) throw new Exception('mysqli 扩展未加载');
            $host = $c['host'] ?? 'localhost';
            $port = $c['port'] ?? 3306;
            $u = $c['username'] ?? '';
            $p = $c['password'] ?? '';
            $db = $c['dbname'] ?? '';
            $cs = $c['charset'] ?? 'utf8mb4';

            self::validateHost($host);
            $port = self::validatePort($port);
            self::validateDbname($db);

            $conn = @new mysqli($host, $u, $p, $db, $port);
            if ($conn->connect_error) throw new Exception(self::handleDbError('mysqli 连接失败: ' . $conn->connect_error));
            $conn->set_charset($cs);
            return $conn;
        }

        private static function connPdo($d, $c)
        {
            if ($d === 'sqlite') {
                $path = isset($c['dbpath']) ? $c['dbpath'] : ':memory:';
                $conn = new PDO("sqlite:$path");
                $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
                return $conn;
            }
            if (!extension_loaded('pdo_' . $d)) throw new Exception("pdo_$d 扩展未加载");
            $host = $c['host'] ?? 'localhost';
            $port = $c['port'] ?? null;
            $db = $c['dbname'] ?? '';
            $cs = $c['charset'] ?? 'utf8mb4';
            $u = $c['username'] ?? '';
            $p = $c['password'] ?? '';

            self::validateHost($host);
            if ($port !== null) {
                $port = self::validatePort($port);
            }
            self::validateDbname($db);

            $parts = array("host=$host");
            if ($port) $parts[] = "port=$port";
            $parts[] = "dbname=$db";
            if ($d === 'mysql') $parts[] = "charset=$cs";
            $dsn = "$d:" . implode(';', $parts);

            $conn = new PDO($dsn, $u, $p, array(
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ));
            return $conn;
        }

        private static function connPgsql($c)
        {
            if (!extension_loaded('pgsql')) throw new Exception('pgsql 扩展未加载');
            $h = $c['host'] ?? 'localhost';
            $port = $c['port'] ?? 5432;
            $u = $c['username'] ?? '';
            $p = $c['password'] ?? '';
            $db = $c['dbname'] ?? '';

            self::validateHost($h);
            $port = self::validatePort($port);
            self::validateDbname($db);

            $s = "host=" . self::escapePgConnValue($h) . " port=$port dbname=" . self::escapePgConnValue($db) . " user=" . self::escapePgConnValue($u) . " password=" . self::escapePgConnValue($p);
            $conn = @pg_connect($s);
            if (!$conn) throw new Exception(self::handleDbError('pgsql 连接失败'));
            return $conn;
        }

        private static function connSqlite3($c)
        {
            if (!extension_loaded('sqlite3')) throw new Exception('sqlite3 扩展未加载');
            return new SQLite3(isset($c['dbpath']) ? $c['dbpath'] : ':memory:');
        }

        // --- 统一接口 ---

        public function query($sql, $params = array())
        {
            $conn = $this->connection;
            if ($conn instanceof PDO) {
                try {
                    $st = $conn->prepare($sql);
                    $st->execute($params);
                    return $st->fetchAll(PDO::FETCH_ASSOC);
                } catch (PDOException $e) {
                    throw new Exception(self::handleDbError('PDO query 失败: ' . $e->getMessage()));
                }
            }
            if ($conn instanceof mysqli) {
                return $this->mysqliQuery($sql, $params);
            }
            if (is_resource($conn) && get_resource_type($conn) === 'pgsql link') {
                return $this->pgQuery($sql, $params);
            }
            if ($conn instanceof SQLite3) {
                return $this->sqlite3Query($sql, $params);
            }
            throw new Exception(self::handleDbError('不支持的数据库类型: ' . $this->driver));
        }

        public function queryOne($sql, $params = array())
        {
            $rows = $this->query($sql, $params);
            return $rows ? reset($rows) : null;
        }

        public function execute($sql, $params = array())
        {
            $conn = $this->connection;
            if ($conn instanceof PDO) {
                try {
                    $st = $conn->prepare($sql);
                    $st->execute($params);
                    return $st->rowCount();
                } catch (PDOException $e) {
                    throw new Exception(self::handleDbError('PDO execute 失败: ' . $e->getMessage()));
                }
            }
            if ($conn instanceof mysqli) {
                $st = $this->mysqliPrepare($sql, $params);
                $st->execute();
                return $st->affected_rows;
            }
            if (is_resource($conn) && get_resource_type($conn) === 'pgsql link') {
                $this->pgQuery($sql, $params);
                return pg_affected_rows($conn);
            }
            if ($conn instanceof SQLite3) {
                $this->sqlite3Exec($sql, $params);
                return $conn->changes();
            }
            throw new Exception(self::handleDbError('不支持的数据库类型: ' . $this->driver));
        }

        public function lastInsertId()
        {
            $conn = $this->connection;
            if ($conn instanceof PDO)    return $conn->lastInsertId();
            if ($conn instanceof mysqli) return $conn->insert_id;
            if ($conn instanceof SQLite3) return $conn->lastInsertRowID();
            if (is_resource($conn)) {
                $r = @pg_query($conn, 'SELECT LASTVAL()');
                if ($r) { $row = pg_fetch_row($r); return isset($row[0]) ? $row[0] : null; }
            }
            return null;
        }

        public function getConnection() { return $this->connection; }
        public function getDriver()     { return $this->driver; }

        // --- 各驱动实现 ---

        private function mysqliQuery($sql, $params)
        {
            $st = $this->mysqliPrepare($sql, $params);
            $st->execute();
            $res = $st->get_result();
            $rows = array();
            while ($row = $res->fetch_assoc()) $rows[] = $row;
            $res->free();
            return $rows;
        }

        private function mysqliPrepare($sql, $params)
        {
            $conn = $this->connection;
            $st = $conn->prepare($sql);
            if (!$st) throw new Exception(self::handleDbError('mysqli prepare 失败: ' . $conn->error));
            if (!empty($params)) {
                $types = '';
                $refs = array();
                foreach ($params as $k => $v) {
                    if (is_int($v)) $types .= 'i';
                    elseif (is_float($v)) $types .= 'd';
                    else $types .= 's';
                    $refs[$k] = &$params[$k];
                }
                array_unshift($refs, $types);
                call_user_func_array(array($st, 'bind_param'), $refs);
            }
            return $st;
        }

        private function pgQuery($sql, $params)
        {
            $conn = $this->connection;
            if (!empty($params)) {
                $i = 1;
                $pgSql = preg_replace_callback('/\?/', function() use (&$i) { return '$'.$i++; }, $sql);
                $result = @pg_query_params($conn, $pgSql, array_values($params));
            } else {
                $result = @pg_query($conn, $sql);
            }
            if (!$result) throw new Exception(self::handleDbError('pgsql 失败: ' . pg_last_error($conn)));
            $rows = array();
            while ($row = pg_fetch_assoc($result)) $rows[] = $row;
            return $rows;
        }

        private function sqlite3Query($sql, $params)
        {
            $conn = $this->connection;
            $st = $conn->prepare($sql);
            if (!$st) throw new Exception(self::handleDbError('sqlite3 prepare: ' . $conn->lastErrorMsg()));
            $i = 1;
            foreach ($params as $v) { $st->bindValue($i, $v); $i++; }
            $res = $st->execute();
            $rows = array();
            while ($row = $res->fetchArray(SQLITE3_ASSOC)) $rows[] = $row;
            $res->finalize();
            $st->close();
            return $rows;
        }

        private function sqlite3Exec($sql, $params)
        {
            $conn = $this->connection;
            $st = $conn->prepare($sql);
            if (!$st) throw new Exception(self::handleDbError('sqlite3 prepare: ' . $conn->lastErrorMsg()));
            $i = 1;
            foreach ($params as $v) { $st->bindValue($i, $v); $i++; }
            $st->execute();
            $st->close();
        }
    }
}
