<?php
defined('ABSPATH') || exit;

class JwtSecurity {
    private static $jwtHeaderPatterns = [
        ['pattern' => '/eyJ[A-Za-z0-9_-]{10,}\./', 'name' => 'JWT header detected'],
        ['pattern' => '/\.[A-Za-z0-9_-]{10,}\./', 'name' => 'JWT payload detected'],
        ['pattern' => '/\.[A-Za-z0-9_-]{10,}$/', 'name' => 'JWT signature detected'],
    ];

    private static $jwtParamNames = [
        'token', 'jwt', 'access_token', 'refresh_token',
        'auth_token', 'bearer', 'id_token',
        'session_token', 'api_token', 'oauth_token',
    ];

    private static $dangerAlgorithms = [
        'none', 'noneNone', 'None', 'NONE',
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'ES256', 'ES384', 'ES512',
        'PS256', 'PS384', 'PS512',
        'EdDSA', 'Ed25519', 'Ed448',
        'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384',
        'RSA-PSS', 'RSA-PSS-256', 'RSA-PSS-384',
    ];

    private static $jwtClaims = [
        'iss', 'sub', 'aud', 'exp', 'nbf',
        'iat', 'jti', 'alg', 'typ', 'cty',
        'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256',
    ];

    public static function check() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            $result = self::analyzeValue($key, $value);
            if ($result['is_attack']) {
                waf_block('JWT security violation - ' . $result['reason']);
            }
        }
    }

    private static function collectInputs() {
        $inputs = [];

        foreach ($_GET as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_POST as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }

        $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!empty($authorization)) {
            $inputs['authorization'] = $authorization;
        }

        $cookie = $_SERVER['HTTP_COOKIE'] ?? '';
        if (!empty($cookie)) {
            $inputs['cookie'] = $cookie;
        }

        $body = file_get_contents('php://input');
        if (!empty($body)) {
            $inputs['body'] = $body;

            $json = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
                self::extractJsonValues($json, $inputs);
            }
        }

        return $inputs;
    }

    private static function extractJsonValues($data, &$inputs, $prefix = '') {
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                $key = $prefix . (empty($prefix) ? '' : '.') . $k;
                if (is_array($v) || is_object($v)) {
                    self::extractJsonValues($v, $inputs, $key);
                } else {
                    $inputs[strtolower($key)] = (string)$v;
                }
            }
        }
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);
        $lowerValue = strtolower($value);

        if (empty($value)) {
            return ['is_attack' => false, 'reason' => ''];
        }

        if (in_array($key, self::$jwtParamNames) || $key === 'authorization' || $key === 'cookie') {
            if (strpos($lowerValue, 'bearer ') === 0) {
                $token = substr($value, 7);
            } else {
                $token = $value;
            }

            $parts = explode('.', $token);
            if (count($parts) === 3) {
                $header = $parts[0];
                $payload = $parts[1];
                $signature = $parts[2];

                if (strlen($signature) === 0) {
                    return ['is_attack' => true, 'reason' => 'JWT with empty signature (alg=none attack)'];
                }

                $decodedHeader = self::base64UrlDecode($header);
                if (!empty($decodedHeader)) {
                    $headerJson = json_decode($decodedHeader, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($headerJson)) {
                        if (isset($headerJson['alg']) && strtolower($headerJson['alg']) === 'none') {
                            return ['is_attack' => true, 'reason' => 'JWT alg=none algorithm confusion attack'];
                        }

                        if (isset($headerJson['typ']) && strtolower($headerJson['typ']) !== 'jwt') {
                            return ['is_attack' => true, 'reason' => 'JWT typ header not set to JWT'];
                        }

                        if (isset($headerJson['kid']) && strlen($headerJson['kid']) > 255) {
                            return ['is_attack' => true, 'reason' => 'JWT kid header too long'];
                        }
                    }
                }

                $decodedPayload = self::base64UrlDecode($payload);
                if (!empty($decodedPayload)) {
                    $payloadJson = json_decode($decodedPayload, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($payloadJson)) {
                        if (isset($payloadJson['exp'])) {
                            if (!is_numeric($payloadJson['exp'])) {
                                return ['is_attack' => true, 'reason' => 'JWT exp claim is not numeric'];
                            }

                            if ($payloadJson['exp'] < time()) {
                                return ['is_attack' => true, 'reason' => 'JWT token expired'];
                            }
                        }

                        if (isset($payloadJson['nbf'])) {
                            if (!is_numeric($payloadJson['nbf'])) {
                                return ['is_attack' => true, 'reason' => 'JWT nbf claim is not numeric'];
                            }

                            if ($payloadJson['nbf'] > time()) {
                                return ['is_attack' => true, 'reason' => 'JWT token not yet valid'];
                            }
                        }

                        if (isset($payloadJson['iat'])) {
                            if (!is_numeric($payloadJson['iat'])) {
                                return ['is_attack' => true, 'reason' => 'JWT iat claim is not numeric'];
                            }
                        }

                        if (isset($payloadJson['sub'])) {
                            if (is_array($payloadJson['sub'])) {
                                return ['is_attack' => true, 'reason' => 'JWT sub claim is an array'];
                            }
                        }

                        if (isset($payloadJson['aud'])) {
                            if (!is_string($payloadJson['aud']) && !is_array($payloadJson['aud'])) {
                                return ['is_attack' => true, 'reason' => 'JWT aud claim is invalid type'];
                            }
                        }

                        if (isset($payloadJson['iss'])) {
                            if (!is_string($payloadJson['iss'])) {
                                return ['is_attack' => true, 'reason' => 'JWT iss claim is not a string'];
                            }
                        }

                        foreach ($payloadJson as $claim => $claimValue) {
                            if (!in_array($claim, self::$jwtClaims) && strpos($claim, '_') !== 0) {
                                if (is_array($claimValue) && count($claimValue) > 100) {
                                    return ['is_attack' => true, 'reason' => 'JWT payload contains oversized custom claim'];
                                }
                            }
                        }
                    }
                }

                if (!self::isValidBase64Url($header)) {
                    return ['is_attack' => true, 'reason' => 'JWT header is not valid base64url'];
                }

                if (!self::isValidBase64Url($payload)) {
                    return ['is_attack' => true, 'reason' => 'JWT payload is not valid base64url'];
                }

                if (strlen($token) > 8192) {
                    return ['is_attack' => true, 'reason' => 'JWT token exceeds maximum allowed size'];
                }
            }
        }

        return ['is_attack' => false, 'reason' => ''];
    }

    private static function base64UrlDecode($data) {
        $data = str_replace(['-', '_'], ['+', '/'], $data);
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }
        return base64_decode($data);
    }

    private static function isValidBase64Url($data) {
        return preg_match('/^[A-Za-z0-9_-]+$/', $data) === 1;
    }
}
