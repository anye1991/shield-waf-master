<?php
defined('ABSPATH') || exit;

class RaceCondition {
    private static $thresholdConfig = [
        'same_url_per_second' => 5,
        'same_url_per_100ms' => 3,
        'idempotent_post_threshold' => 3,
        'window_seconds' => 1,
        'sensitive_window_seconds' => 5,
    ];

    private static $sensitiveKeywords = [
        'pay', 'payment', 'withdraw', 'withdrawal', 'transfer',
        'coupon', 'voucher', 'redeem', 'points', 'credit',
        'debit', 'charge', 'refund', 'reward', 'bonus',
        'lottery', 'draw', 'claim', 'submit', 'order',
        'purchase', 'buy', 'checkout', 'confirm', 'verify',
        'register', 'signup', 'invite', 'referral',
        'vote', 'like', 'follow', 'unfollow',
    ];

    private static $idempotentMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];

    private static $storageDir;

    public static function detect() {
        $score = 0;
        $details = [];
        $detected = false;

        self::initStorage();

        $currentRequest = self::getRequestFingerprint();
        $requestHistory = self::getRequestHistory();
        $history = self::pruneHistory($requestHistory);

        $rateResult = self::checkRequestRate($currentRequest, $history);
        if ($rateResult['score'] > 0) {
            $score = max($score, $rateResult['score']);
            $details[] = $rateResult;
            if ($rateResult['detected']) {
                $detected = true;
            }
        }

        $idempotentResult = self::checkIdempotentPost($currentRequest, $history);
        if ($idempotentResult['score'] > 0) {
            $score = max($score, $idempotentResult['score']);
            $details[] = $idempotentResult;
            if ($idempotentResult['detected']) {
                $detected = true;
            }
        }

        $sensitiveResult = self::checkSensitiveOperations($currentRequest, $history);
        if ($sensitiveResult['score'] > 0) {
            $score = max($score, $sensitiveResult['score']);
            $details[] = $sensitiveResult;
            if ($sensitiveResult['detected']) {
                $detected = true;
            }
        }

        self::saveRequest($currentRequest, $history);

        return [
            'detected' => $detected,
            'score' => min($score, 100),
            'details' => $details,
        ];
    }

    private static function initStorage() {
        $baseDir = defined('WAF_STORAGE_DIR') ? WAF_STORAGE_DIR : (sys_get_temp_dir() . '/shield-waf');
        self::$storageDir = $baseDir . '/race_condition';

        if (!is_dir(self::$storageDir)) {
            @mkdir(self::$storageDir, 0755, true);
        }
    }

    private static function getClientIp() {
        $ip = '';
        $headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                break;
            }
        }
        return $ip ?: '0.0.0.0';
    }

    private static function getRequestFingerprint() {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH) ?? $uri;
        $ip = self::getClientIp();

        $params = [];
        if (!empty($_GET)) {
            ksort($_GET);
            $params['get'] = $_GET;
        }
        if (!empty($_POST)) {
            ksort($_POST);
            $params['post'] = $_POST;
        }

        $paramsHash = md5(serialize($params));

        return [
            'timestamp' => microtime(true),
            'ip' => $ip,
            'method' => $method,
            'path' => $path,
            'uri' => $uri,
            'params_hash' => $paramsHash,
            'is_idempotent' => in_array(strtoupper($method), self::$idempotentMethods),
            'is_sensitive' => self::isSensitivePath($path),
        ];
    }

    private static function getStorageFile() {
        $ip = self::getClientIp();
        $safeIp = str_replace([':', '.'], '_', $ip);
        return self::$storageDir . '/rc_' . $safeIp . '.json';
    }

    private static function getRequestHistory() {
        $file = self::getStorageFile();
        if (file_exists($file)) {
            $content = @file_get_contents($file);
            if ($content !== false) {
                $data = json_decode($content, true);
                if (is_array($data)) {
                    return $data;
                }
            }
        }
        return [];
    }

    private static function pruneHistory($history) {
        $now = microtime(true);
        $maxAge = 60;
        $pruned = [];

        foreach ($history as $entry) {
            if (isset($entry['timestamp']) && ($now - $entry['timestamp']) <= $maxAge) {
                $pruned[] = $entry;
            }
        }

        return $pruned;
    }

    private static function saveRequest($request, $history) {
        $history[] = $request;
        $history = self::pruneHistory($history);

        if (count($history) > 500) {
            $history = array_slice($history, -500);
        }

        $file = self::getStorageFile();
        @file_put_contents($file, json_encode($history), LOCK_EX);
    }

    private static function checkRequestRate($currentRequest, $history) {
        $findings = [];
        $score = 0;
        $now = $currentRequest['timestamp'];
        $path = $currentRequest['path'];
        $paramsHash = $currentRequest['params_hash'];

        $sameUrlOneSec = 0;
        $sameUrl100ms = 0;
        $sameUrlWithParams = 0;

        foreach ($history as $entry) {
            if ($entry['path'] !== $path) continue;

            $age = $now - $entry['timestamp'];

            if ($age <= self::$thresholdConfig['window_seconds']) {
                $sameUrlOneSec++;
            }

            if ($age <= 0.1) {
                $sameUrl100ms++;
            }

            if ($entry['params_hash'] === $paramsHash && $age <= self::$thresholdConfig['window_seconds']) {
                $sameUrlWithParams++;
            }
        }

        if ($sameUrlOneSec >= self::$thresholdConfig['same_url_per_second']) {
            $score = 65;
            $findings[] = "High request rate: $sameUrlOneSec requests in 1s for same URL";
        }

        if ($sameUrl100ms >= self::$thresholdConfig['same_url_per_100ms']) {
            $score = max($score, 75);
            $findings[] = "Very high request rate: $sameUrl100ms requests in 100ms";
        }

        if ($sameUrlWithParams >= self::$thresholdConfig['same_url_per_second']) {
            $score = max($score, 80);
            $findings[] = "Identical parameter requests: $sameUrlWithParams in 1s";
        }

        if ($sameUrlOneSec >= 10) {
            $score = max($score, 90);
            $findings[] = "Extremely high request rate: $sameUrlOneSec/sec";
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'request_rate',
            'same_url_count_1s' => $sameUrlOneSec,
            'same_url_count_100ms' => $sameUrl100ms,
            'same_params_count' => $sameUrlWithParams,
        ];
    }

    private static function checkIdempotentPost($currentRequest, $history) {
        $findings = [];
        $score = 0;

        if (!$currentRequest['is_idempotent']) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'check' => 'idempotent_post'];
        }

        $now = $currentRequest['timestamp'];
        $path = $currentRequest['path'];
        $paramsHash = $currentRequest['params_hash'];
        $window = self::$thresholdConfig['window_seconds'];
        $count = 0;

        foreach ($history as $entry) {
            if ($entry['path'] !== $path) continue;
            if (!$entry['is_idempotent']) continue;

            $age = $now - $entry['timestamp'];
            if ($age <= $window) {
                $count++;
            }
        }

        if ($count >= self::$thresholdConfig['idempotent_post_threshold']) {
            $score = 70;
            $findings[] = "Multiple idempotent requests: $count POST/PUT in $window s";
        }

        $sameParamsCount = 0;
        foreach ($history as $entry) {
            if ($entry['path'] !== $path) continue;
            if ($entry['params_hash'] !== $paramsHash) continue;
            if (!$entry['is_idempotent']) continue;

            $age = $now - $entry['timestamp'];
            if ($age <= $window) {
                $sameParamsCount++;
            }
        }

        if ($sameParamsCount >= 2) {
            $score = max($score, 85);
            $findings[] = "Duplicate idempotent requests: $sameParamsCount identical POST/PUT";
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'idempotent_post',
            'idempotent_count' => $count,
            'same_params_count' => $sameParamsCount,
        ];
    }

    private static function checkSensitiveOperations($currentRequest, $history) {
        $findings = [];
        $score = 0;

        if (!$currentRequest['is_sensitive']) {
            return ['detected' => false, 'score' => 0, 'findings' => [], 'check' => 'sensitive_operations'];
        }

        $now = $currentRequest['timestamp'];
        $path = $currentRequest['path'];
        $paramsHash = $currentRequest['params_hash'];
        $window = self::$thresholdConfig['sensitive_window_seconds'];
        $sensitiveCount = 0;
        $sameSensitiveCount = 0;

        foreach ($history as $entry) {
            if (!$entry['is_sensitive']) continue;

            $age = $now - $entry['timestamp'];
            if ($age <= $window) {
                $sensitiveCount++;

                if ($entry['path'] === $path && $entry['params_hash'] === $paramsHash) {
                    $sameSensitiveCount++;
                }
            }
        }

        if ($sensitiveCount >= 3) {
            $score = 60;
            $findings[] = "Multiple sensitive operations: $sensitiveCount in ${window}s";
        }

        if ($sameSensitiveCount >= 2) {
            $score = max($score, 85);
            $findings[] = "Duplicate sensitive operation: $sameSensitiveCount identical requests";
        }

        if ($sameSensitiveCount >= 5) {
            $score = max($score, 95);
            $findings[] = "Mass duplicate sensitive operations: $sameSensitiveCount";
        }

        return [
            'detected' => $score >= 50,
            'score' => $score,
            'findings' => $findings,
            'check' => 'sensitive_operations',
            'sensitive_count' => $sensitiveCount,
            'same_sensitive_count' => $sameSensitiveCount,
            'path' => $path,
        ];
    }

    private static function isSensitivePath($path) {
        $lowerPath = strtolower($path);
        foreach (self::$sensitiveKeywords as $keyword) {
            if (strpos($lowerPath, $keyword) !== false) {
                return true;
            }
        }
        return false;
    }
}
