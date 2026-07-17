<?php
/**
 * CRLF 注入语义解析器
 * 职责：HTTP协议级CRLF注入检测，包括响应头注入、响应拆分、多层编码检测。
 */
defined('ABSPATH') || exit;

class CrlfInjectionSemanticParser {

    private static $headerInjectionPatterns = [
        'set_cookie'       => ['pattern' => '/Set-Cookie\s*:/i', 'level' => 4, 'desc' => 'Set-Cookie头注入'],
        'location'         => ['pattern' => '/Location\s*:/i', 'level' => 4, 'desc' => 'Location头注入'],
        'content_type'     => ['pattern' => '/Content-Type\s*:/i', 'level' => 3, 'desc' => 'Content-Type头注入'],
        'refresh'          => ['pattern' => '/Refresh\s*:/i', 'level' => 3, 'desc' => 'Refresh头注入'],
        'x_forwarded'      => ['pattern' => '/X-Forwarded-[A-Za-z-]+\s*:/i', 'level' => 2, 'desc' => 'X-Forwarded头注入'],
        'x_forwarded_for'  => ['pattern' => '/X-Forwarded-For\s*:/i', 'level' => 3, 'desc' => 'X-Forwarded-For头注入'],
        'set_cookie_evil'  => ['pattern' => '/Set-Cookie\s*:.*[=;]/i', 'level' => 5, 'desc' => '恶意Set-Cookie注入'],
    ];

    private static $crlfPatterns = [
        'raw_rn'    => ["\r\n", '原始CRLF'],
        'raw_nr'    => ["\n\r", '原始LFCR'],
        'raw_r'     => ["\r", '原始CR'],
        'raw_n'     => ["\n", '原始LF'],
        'url_rn'    => ['%0d%0a', 'URL编码CRLF'],
        'url_nr'    => ['%0a%0d', 'URL编码LFCR'],
        'url_r'     => ['%0d', 'URL编码CR'],
        'url_n'     => ['%0a', 'URL编码LF'],
        'url_upper_rn' => ['%0D%0A', 'URL编码CRLF(大写)'],
        'url_upper_nr' => ['%0A%0D', 'URL编码LFCR(大写)'],
        'url_mixed1' => ['%0d%0A', 'URL编码CRLF(混合)'],
        'url_mixed2' => ['%0D%0a', 'URL编码CRLF(混合)'],
        'double_rn' => ['%250d%250a', '双层URL编码CRLF'],
        'double_nr' => ['%250a%250d', '双层URL编码LFCR'],
        'unicode_r' => ['\u000d', 'Unicode编码CR'],
        'unicode_n' => ['\u000a', 'Unicode编码LF'],
        'hex_r'     => ['\\x0d', '十六进制CR'],
        'hex_n'     => ['\\x0a', '十六进制LF'],
        'html_r'    => ['&#13;', 'HTML实体CR'],
        'html_n'    => ['&#10;', 'HTML实体LF'],
    ];

    public static function analyze(string $input): array {
        $result = self::defaultResult();
        if ($input === '') return $result;

        $originalInput = $input;

        $decodeResult = self::multiLayerDecode($input);
        $decodedInput = $decodeResult['decoded'];
        $decodeDepth = $decodeResult['depth'];
        $encodeTypes = $decodeResult['encode_types'];

        $crlfResult = self::detectCrlfSequences($decodedInput, $originalInput);
        $crlfCount = $crlfResult['count'];
        $crlfTypes = $crlfResult['types'];

        $headerInjectionHits = self::detectHeaderInjections($decodedInput);
        $responseSplitting = self::detectResponseSplitting($decodedInput, $originalInput);

        $headerNameInjection = self::detectHeaderNameInjection($decodedInput);

        $score = 0;
        $indicators = [];

        if ($crlfCount >= 4) { $score += 30; $indicators[] = 'multiple_crlf'; }
        elseif ($crlfCount >= 2) { $score += 20; $indicators[] = 'double_crlf'; }
        elseif ($crlfCount >= 1) { $score += 10; $indicators[] = 'single_crlf'; }

        $maxHeaderLevel = 0;
        foreach ($headerInjectionHits as $hit) {
            if ($hit['level'] > $maxHeaderLevel) $maxHeaderLevel = $hit['level'];
        }
        if ($maxHeaderLevel >= 5) { $score += 30; $indicators[] = 'critical_header_injection'; }
        elseif ($maxHeaderLevel >= 4) { $score += 22; $indicators[] = 'high_header_injection'; }
        elseif ($maxHeaderLevel >= 3) { $score += 15; $indicators[] = 'medium_header_injection'; }
        elseif ($maxHeaderLevel >= 2) { $score += 8; $indicators[] = 'low_header_injection'; }

        if ($responseSplitting) {
            $score += 35;
            $indicators[] = 'response_splitting';
        }

        if ($headerNameInjection) {
            $score += 15;
            $indicators[] = 'header_name_injection';
        }

        if ($decodeDepth >= 3) { $score += 18; $indicators[] = 'multi_layer_encoding'; }
        elseif ($decodeDepth >= 2) { $score += 12; $indicators[] = 'double_encoding'; }
        elseif ($decodeDepth >= 1) { $score += 6; $indicators[] = 'single_encoding'; }

        if ($crlfCount > 0 && !empty($headerInjectionHits)) {
            $score += 15;
            $indicators[] = 'crlf_plus_header_combo';
        }

        if ($responseSplitting && !empty($headerInjectionHits)) {
            $score += 10;
            $indicators[] = 'splitting_plus_header_combo';
        }

        $riskLevel = 'low';
        if ($score >= 70) $riskLevel = 'critical';
        elseif ($score >= 50) $riskLevel = 'high';
        elseif ($score >= 30) $riskLevel = 'medium';

        return [
            'score'                 => min(100, $score),
            'risk_level'            => $riskLevel,
            'is_crlf'               => $score >= 15,
            'crlf_count'            => $crlfCount,
            'crlf_types'            => $crlfTypes,
            'header_injection_hits' => $headerInjectionHits,
            'response_splitting'    => $responseSplitting,
            'header_name_injection' => $headerNameInjection,
            'decode_depth'          => $decodeDepth,
            'encode_types'          => $encodeTypes,
            'indicators'            => $indicators,
        ];
    }

    private static function defaultResult(): array {
        return [
            'score'                 => 0,
            'risk_level'            => 'clean',
            'is_crlf'               => false,
            'crlf_count'            => 0,
            'crlf_types'            => [],
            'header_injection_hits' => [],
            'response_splitting'    => false,
            'header_name_injection' => false,
            'decode_depth'          => 0,
            'encode_types'          => [],
            'indicators'            => [],
        ];
    }

    private static function multiLayerDecode(string $input): array {
        $depth = 0;
        $encodeTypes = [];
        $current = $input;

        for ($i = 0; $i < 5; $i++) {
            $decoded = $current;
            $changed = false;

            if (preg_match('/%[0-9a-fA-F]{2}/', $decoded)) {
                $newDecoded = urldecode($decoded);
                if ($newDecoded !== $decoded) {
                    $decoded = $newDecoded;
                    $encodeTypes[] = 'url';
                    $changed = true;
                }
            }

            if (preg_match('/&#\d+;/', $decoded)) {
                $newDecoded = html_entity_decode($decoded, ENT_HTML5);
                if ($newDecoded !== $decoded) {
                    $decoded = $newDecoded;
                    $encodeTypes[] = 'html_entity';
                    $changed = true;
                }
            }

            if (!$changed) break;
            $depth++;
            $current = $decoded;
        }

        return [
            'decoded'      => $current,
            'depth'        => $depth,
            'encode_types' => array_values(array_unique($encodeTypes)),
        ];
    }

    private static function detectCrlfSequences(string $decodedInput, string $originalInput): array {
        $count = 0;
        $types = [];

        foreach (self::$crlfPatterns as $key => $info) {
            list($pattern, $desc) = $info;
            $foundInDecoded = substr_count($decodedInput, $pattern);
            $foundInOriginal = substr_count($originalInput, $pattern);

            if ($foundInDecoded > 0 || $foundInOriginal > 0) {
                $total = max($foundInDecoded, $foundInOriginal);
                $count += $total;
                $types[] = [
                    'type'  => $key,
                    'desc'  => $desc,
                    'count' => $total,
                ];
            }
        }

        $rnCount = substr_count($decodedInput, "\r\n");
        $nrCount = substr_count($decodedInput, "\n\r");
        $rawR = substr_count($decodedInput, "\r");
        $rawN = substr_count($decodedInput, "\n");

        if ($rnCount > 0) {
            $count += $rnCount;
        }
        if ($nrCount > 0) {
            $count += $nrCount;
        }

        return [
            'count' => $count,
            'types' => $types,
        ];
    }

    private static function detectHeaderInjections(string $input): array {
        $hits = [];

        foreach (self::$headerInjectionPatterns as $key => $info) {
            if (preg_match($info['pattern'], $input)) {
                $hits[] = [
                    'header' => $key,
                    'level'  => $info['level'],
                    'desc'   => $info['desc'],
                ];
            }
        }

        if (preg_match('/[A-Za-z][A-Za-z0-9-]*\s*:/', $input, $matches)) {
            $headerName = $matches[0];
            $standardHeaders = [
                'Content-Type:', 'Content-Length:', 'Set-Cookie:', 'Location:',
                'Refresh:', 'X-Forwarded-For:', 'X-Forwarded-Host:',
                'X-Forwarded-Proto:', 'X-Real-IP:', 'Host:', 'User-Agent:',
                'Accept:', 'Accept-Language:', 'Accept-Encoding:',
                'Connection:', 'Cache-Control:', 'Pragma:',
            ];
            $isStandard = false;
            foreach ($standardHeaders as $sh) {
                if (strcasecmp(trim($headerName), $sh) === 0) {
                    $isStandard = true;
                    break;
                }
            }
            if (!$isStandard && self::hasCrlfBefore($input, $matches[0])) {
                $hits[] = [
                    'header' => 'custom_header',
                    'level'  => 2,
                    'desc'   => '自定义HTTP头注入',
                ];
            }
        }

        usort($hits, function($a, $b) { return $b['level'] - $a['level']; });
        return $hits;
    }

    private static function hasCrlfBefore(string $input, string $headerStr): bool {
        $pos = strpos($input, $headerStr);
        if ($pos === false) return false;
        $before = substr($input, 0, $pos);
        return strpos($before, "\r") !== false || strpos($before, "\n") !== false;
    }

    private static function detectResponseSplitting(string $decodedInput, string $originalInput): bool {
        $doubleCrlfPatterns = [
            "\r\n\r\n",
            "\n\r\n\r",
            "\n\n",
            "\r\r",
            '%0d%0a%0d%0a',
            '%0D%0A%0D%0A',
            '%0a%0d%0a%0d',
            '%0A%0D%0A%0D',
            '%0a%0a',
            '%0A%0A',
            '%0d%0d',
            '%0D%0D',
        ];

        foreach ($doubleCrlfPatterns as $pattern) {
            if (stripos($decodedInput, $pattern) !== false) {
                return true;
            }
            if (stripos($originalInput, $pattern) !== false) {
                return true;
            }
        }

        if (preg_match('/(\r\n|\n\r|\n|\r).*?(\r\n|\n\r|\n|\r).*?HTTP\/\d\.\d/i', $decodedInput)) {
            return true;
        }

        if (preg_match('/(\r\n|\n\r|\n|\r).*?(\r\n|\n\r|\n|\r).*?Content-Type:/i', $decodedInput)) {
            return true;
        }

        return false;
    }

    private static function detectHeaderNameInjection(string $input): bool {
        if (preg_match('/[\r\n][A-Za-z][A-Za-z0-9-]*\s*:/', $input)) {
            return true;
        }
        if (preg_match('/%0[dD]%0[aA][A-Za-z]/', $input)) {
            return true;
        }
        if (preg_match('/%0[aA]%0[dD][A-Za-z]/', $input)) {
            return true;
        }
        return false;
    }
}
