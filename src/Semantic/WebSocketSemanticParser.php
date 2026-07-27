<?php
/**
 * WebSocket 语义解析器
 * 职责：通过解析 RFC 6455 WebSocket 帧格式构建帧结构 AST，
 *       进行协议级语义分析和攻击检测，包括掩码绕过、超大帧、
 *       分片注入、控制帧异常、保留位滥用、Ping Flood 等。
 */
defined('ABSPATH') || exit;

class WebSocketSemanticParser {

    const OPCODE_CONTINUATION = 0x0;
    const OPCODE_TEXT         = 0x1;
    const OPCODE_BINARY       = 0x2;
    const OPCODE_CLOSE        = 0x8;
    const OPCODE_PING         = 0x9;
    const OPCODE_PONG         = 0xA;

    const FRAME_TYPE_CONTROL  = 'control';
    const FRAME_TYPE_DATA     = 'data';

    const RISK_CLEAN     = 'clean';
    const RISK_LOW       = 'low';
    const RISK_MEDIUM    = 'medium';
    const RISK_HIGH      = 'high';
    const RISK_CRITICAL  = 'critical';

    const MAX_PAYLOAD_SOFT = 1048576;
    const MAX_PAYLOAD_HARD = 10485760;

    const MAX_CONTROL_PAYLOAD = 125;

    const PING_FLOOD_THRESHOLD = 10;

    private static $opcodeNames = [
        0x0 => 'continuation',
        0x1 => 'text',
        0x2 => 'binary',
        0x3 => 'reserved_3',
        0x4 => 'reserved_4',
        0x5 => 'reserved_5',
        0x6 => 'reserved_6',
        0x7 => 'reserved_7',
        0x8 => 'close',
        0x9 => 'ping',
        0xA => 'pong',
        0xB => 'reserved_B',
        0xC => 'reserved_C',
        0xD => 'reserved_D',
        0xE => 'reserved_E',
        0xF => 'reserved_F',
    ];

    private static $closeStatusCodes = [
        1000 => '正常关闭',
        1001 => '端点离开',
        1002 => '协议错误',
        1003 => '不支持的数据类型',
        1004 => '保留',
        1005 => '无状态码',
        1006 => '异常关闭',
        1007 => '数据不一致',
        1008 => '策略违规',
        1009 => '消息过大',
        1010 => '扩展协商失败',
        1011 => '服务器内部错误',
        1015 => 'TLS握手失败',
    ];

    private static $sqlInjectionPatterns = [
        '/\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set)\b/i',
        '/\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1|--\s|#|\/\*|\*\/)\b/i',
        "/\b(sleep\s*\(|benchmark\s*\(|load_file\s*\(|outfile\s*\()/i",
        "/\b(information_schema|sysobjects|syscolumns)\b/i",
    ];

    private static $xssPatterns = [
        '/<script\b[^>]*>/i',
        '/javascript\s*:/i',
        '/on\w+\s*=/i',
        '/<iframe\b/i',
        '/<img\b[^>]*onerror/i',
        '/document\.cookie/i',
    ];

    private static $commandInjectionPatterns = [
        '/[;&|`]\s*(rm|wget|curl|nc|bash|sh|cat|ls|id|whoami|uname|pwd)\b/i',
        '/\$\{[^}]+\}/',
        '/\$\([^)]+\)/',
        '/`[^`]+`/',
    ];

    public static function analyze(string $input): array {
        $result = self::buildDefaultResult();

        if ($input === '') {
            return $result;
        }

        $binaryResult = self::analyzeFrames($input);
        if ($binaryResult['is_websocket']) {
            return $binaryResult;
        }

        $result = self::analyzeAsTextPayload($input, $result);
        return $result;
    }

    public static function analyzeFrames(string $binaryData): array {
        $result = self::buildDefaultResult();

        if ($binaryData === '') {
            return $result;
        }

        $frames = [];
        $offset = 0;
        $length = strlen($binaryData);

        while ($offset < $length) {
            $frame = self::parseFrame($binaryData, $offset);
            if ($frame === null) {
                break;
            }
            $frames[] = $frame;
            $offset = $frame['end_offset'];
        }

        if (empty($frames)) {
            $result = self::analyzeAsTextPayload($binaryData, $result);
            return $result;
        }

        $result['is_websocket'] = true;
        $result['frame_count'] = count($frames);
        $result['frame_summaries'] = array_map([self::class, 'summarizeFrame'], $frames);

        $ast = self::buildFrameSequenceAst($frames);
        $result['ast_summary'] = self::summarizeFrameAst($ast);

        $result['has_fragmented'] = $ast['has_fragmented'];
        $result['fragment_count'] = $ast['fragment_count'];
        $result['max_frame_size'] = $ast['max_frame_size'];
        $result['opcode_distribution'] = $ast['opcode_distribution'];

        $semanticResult = self::performSemanticAnalysis($frames, $ast, $binaryData);

        $result = array_merge($result, $semanticResult);
        $result['score'] = self::calculateScore($result);
        $result['risk_level'] = self::determineRiskLevel($result['score']);

        return $result;
    }

    private static function buildDefaultResult(): array {
        return [
            'score'                       => 0,
            'risk_level'                  => self::RISK_CLEAN,
            'is_websocket'                => false,
            'frame_count'                 => 0,
            'has_fragmented'              => false,
            'fragment_count'              => 0,
            'max_frame_size'              => 0,
            'has_mask_issue'              => false,
            'opcode_distribution'         => [],
            'has_rsv_abuse'               => false,
            'has_control_frame_violation' => false,
            'has_large_payload'           => false,
            'injection_detected'          => [],
            'frame_summaries'             => [],
            'ast_summary'                 => [],
            'indicators'                  => [],
        ];
    }

    private static function parseFrame(string $data, int $offset): ?array {
        $length = strlen($data);
        if ($length - $offset < 2) {
            return null;
        }

        $byte1 = ord($data[$offset]);
        $byte2 = ord($data[$offset + 1]);

        $fin = ($byte1 & 0x80) !== 0;
        $rsv1 = ($byte1 & 0x40) !== 0;
        $rsv2 = ($byte1 & 0x20) !== 0;
        $rsv3 = ($byte1 & 0x10) !== 0;
        $opcode = $byte1 & 0x0F;

        $mask = ($byte2 & 0x80) !== 0;
        $payloadLen7 = $byte2 & 0x7F;

        $pos = $offset + 2;

        $payloadLength = 0;
        if ($payloadLen7 < 126) {
            $payloadLength = $payloadLen7;
        } elseif ($payloadLen7 === 126) {
            if ($length - $pos < 2) {
                return null;
            }
            $payloadLength = (ord($data[$pos]) << 8) | ord($data[$pos + 1]);
            $pos += 2;
        } elseif ($payloadLen7 === 127) {
            if ($length - $pos < 8) {
                return null;
            }
            $high = (ord($data[$pos]) << 24) | (ord($data[$pos + 1]) << 16) | (ord($data[$pos + 2]) << 8) | ord($data[$pos + 3]);
            $low = (ord($data[$pos + 4]) << 24) | (ord($data[$pos + 5]) << 16) | (ord($data[$pos + 6]) << 8) | ord($data[$pos + 7]);
            $payloadLength = ($high * 4294967296) + $low;
            $pos += 8;
        }

        $maskingKey = null;
        if ($mask) {
            if ($length - $pos < 4) {
                return null;
            }
            $maskingKey = substr($data, $pos, 4);
            $pos += 4;
        }

        if ($length - $pos < $payloadLength) {
            return null;
        }

        $payloadData = substr($data, $pos, $payloadLength);
        $pos += $payloadLength;

        $unmaskedPayload = $payloadData;
        if ($mask && $maskingKey !== null && $payloadLength > 0) {
            $unmaskedPayload = self::unmaskPayload($payloadData, $maskingKey);
        }

        $isControl = $opcode >= 0x8;

        return [
            'fin'               => $fin,
            'rsv1'              => $rsv1,
            'rsv2'              => $rsv2,
            'rsv3'              => $rsv3,
            'opcode'            => $opcode,
            'opcode_name'       => self::$opcodeNames[$opcode] ?? 'unknown',
            'masked'            => $mask,
            'masking_key'       => $maskingKey ? bin2hex($maskingKey) : null,
            'payload_length'    => $payloadLength,
            'payload_length_field' => $payloadLen7,
            'is_control'        => $isControl,
            'frame_type'        => $isControl ? self::FRAME_TYPE_CONTROL : self::FRAME_TYPE_DATA,
            'payload_data'      => $payloadData,
            'unmasked_payload'  => $unmaskedPayload,
            'start_offset'      => $offset,
            'end_offset'        => $pos,
            'header_size'       => $pos - $offset - $payloadLength,
            'total_size'        => $pos - $offset,
        ];
    }

    private static function unmaskPayload(string $payload, string $maskingKey): string {
        $length = strlen($payload);
        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $result .= chr(ord($payload[$i]) ^ ord($maskingKey[$i % 4]));
        }
        return $result;
    }

    private static function summarizeFrame(array $frame): array {
        $summary = [
            'fin'            => $frame['fin'],
            'opcode'         => $frame['opcode'],
            'opcode_name'    => $frame['opcode_name'],
            'frame_type'     => $frame['frame_type'],
            'masked'         => $frame['masked'],
            'payload_length' => $frame['payload_length'],
        ];

        if ($frame['opcode'] === self::OPCODE_CLOSE && $frame['payload_length'] >= 2) {
            $statusCode = (ord($frame['unmasked_payload'][0]) << 8) | ord($frame['unmasked_payload'][1]);
            $reason = $frame['payload_length'] > 2 ? substr($frame['unmasked_payload'], 2) : '';
            $summary['close_status'] = $statusCode;
            $summary['close_reason'] = $reason;
            $summary['close_reason_length'] = strlen($reason);
        }

        return $summary;
    }

    private static function buildFrameSequenceAst(array $frames): array {
        $ast = [
            'frames'               => [],
            'messages'             => [],
            'has_fragmented'       => false,
            'fragment_count'       => 0,
            'max_frame_size'       => 0,
            'opcode_distribution'  => [],
            'ping_count'           => 0,
            'pong_count'           => 0,
            'close_count'          => 0,
            'text_count'           => 0,
            'binary_count'         => 0,
            'continuation_count'   => 0,
        ];

        $currentMessage = null;
        $fragmentedMessages = 0;

        foreach ($frames as $idx => $frame) {
            $frameNode = [
                'index'           => $idx,
                'opcode'          => $frame['opcode'],
                'opcode_name'     => $frame['opcode_name'],
                'fin'             => $frame['fin'],
                'is_control'      => $frame['is_control'],
                'frame_type'      => $frame['frame_type'],
                'payload_length'  => $frame['payload_length'],
                'masked'          => $frame['masked'],
                'rsv1'            => $frame['rsv1'],
                'rsv2'            => $frame['rsv2'],
                'rsv3'            => $frame['rsv3'],
            ];

            $ast['frames'][] = $frameNode;

            if ($frame['payload_length'] > $ast['max_frame_size']) {
                $ast['max_frame_size'] = $frame['payload_length'];
            }

            $opcode = $frame['opcode'];
            if (!isset($ast['opcode_distribution'][$opcode])) {
                $ast['opcode_distribution'][$opcode] = 0;
            }
            $ast['opcode_distribution'][$opcode]++;

            switch ($opcode) {
                case self::OPCODE_PING:
                    $ast['ping_count']++;
                    break;
                case self::OPCODE_PONG:
                    $ast['pong_count']++;
                    break;
                case self::OPCODE_CLOSE:
                    $ast['close_count']++;
                    break;
                case self::OPCODE_TEXT:
                    $ast['text_count']++;
                    break;
                case self::OPCODE_BINARY:
                    $ast['binary_count']++;
                    break;
                case self::OPCODE_CONTINUATION:
                    $ast['continuation_count']++;
                    break;
            }

            if ($frame['is_control']) {
                continue;
            }

            if ($frame['opcode'] !== self::OPCODE_CONTINUATION) {
                if ($currentMessage !== null) {
                    $ast['messages'][] = $currentMessage;
                }
                $currentMessage = [
                    'type'           => $frame['opcode_name'],
                    'opcode'         => $frame['opcode'],
                    'fragmented'     => !$frame['fin'],
                    'fragment_count' => 1,
                    'total_length'   => $frame['payload_length'],
                    'frames'         => [$idx],
                    'payload'        => $frame['unmasked_payload'],
                ];
                if (!$frame['fin']) {
                    $fragmentedMessages++;
                }
            } else {
                if ($currentMessage !== null) {
                    $currentMessage['fragment_count']++;
                    $currentMessage['total_length'] += $frame['payload_length'];
                    $currentMessage['frames'][] = $idx;
                    $currentMessage['payload'] .= $frame['unmasked_payload'];
                    if ($frame['fin']) {
                        $currentMessage['fragmented'] = true;
                        $ast['messages'][] = $currentMessage;
                        $currentMessage = null;
                    }
                }
            }
        }

        if ($currentMessage !== null) {
            $ast['messages'][] = $currentMessage;
        }

        $ast['has_fragmented'] = $fragmentedMessages > 0 || $ast['continuation_count'] > 0;
        $ast['fragment_count'] = $ast['continuation_count'];

        return $ast;
    }

    private static function summarizeFrameAst(array $ast): array {
        return [
            'total_frames'      => count($ast['frames']),
            'total_messages'    => count($ast['messages']),
            'has_fragmented'    => $ast['has_fragmented'],
            'fragment_count'    => $ast['fragment_count'],
            'max_frame_size'    => $ast['max_frame_size'],
            'opcode_distribution' => $ast['opcode_distribution'],
            'ping_count'        => $ast['ping_count'],
            'pong_count'        => $ast['pong_count'],
            'close_count'       => $ast['close_count'],
            'text_count'        => $ast['text_count'],
            'binary_count'      => $ast['binary_count'],
            'message_count'     => count($ast['messages']),
        ];
    }

    private static function performSemanticAnalysis(array $frames, array $ast, string $rawData): array {
        $result = [
            'has_mask_issue'              => false,
            'has_rsv_abuse'               => false,
            'has_control_frame_violation' => false,
            'has_large_payload'           => false,
            'large_payload_count'         => 0,
            'ping_flood_detected'         => false,
            'injection_detected'          => [],
            'close_frame_anomalies'       => [],
            'indicators'                  => [],
        ];

        $maskedFrameCount = 0;
        $unmaskedClientFrames = 0;

        foreach ($frames as $frame) {
            if ($frame['masked']) {
                $maskedFrameCount++;
            } else {
                $unmaskedClientFrames++;
            }

            if ($frame['rsv1'] || $frame['rsv2'] || $frame['rsv3']) {
                $result['has_rsv_abuse'] = true;
                $result['indicators'][] = 'rsv_non_zero';
            }

            if ($frame['is_control']) {
                if (!$frame['fin']) {
                    $result['has_control_frame_violation'] = true;
                    $result['indicators'][] = 'control_frame_fragmented';
                }
                if ($frame['payload_length'] > self::MAX_CONTROL_PAYLOAD) {
                    $result['has_control_frame_violation'] = true;
                    $result['indicators'][] = 'control_frame_too_large';
                }
            }

            if ($frame['opcode'] === self::OPCODE_CLOSE) {
                $closeAnalysis = self::analyzeCloseFrame($frame);
                if (!empty($closeAnalysis['issues'])) {
                    $result['close_frame_anomalies'] = array_merge(
                        $result['close_frame_anomalies'],
                        $closeAnalysis['issues']
                    );
                    $result['indicators'] = array_merge($result['indicators'], $closeAnalysis['indicators']);
                }
            }

            if ($frame['payload_length'] > self::MAX_PAYLOAD_SOFT) {
                $result['has_large_payload'] = true;
                $result['large_payload_count']++;
                if ($frame['payload_length'] > self::MAX_PAYLOAD_HARD) {
                    $result['indicators'][] = 'extremely_large_payload';
                } else {
                    $result['indicators'][] = 'large_payload';
                }
            }

            $undefinedOpcodes = [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xD, 0xE, 0xF];
            if (in_array($frame['opcode'], $undefinedOpcodes)) {
                $result['indicators'][] = 'undefined_opcode_0x' . dechex($frame['opcode']);
            }
        }

        if ($unmaskedClientFrames > 0 && $maskedFrameCount === 0) {
            $result['has_mask_issue'] = true;
            $result['indicators'][] = 'no_masked_frames';
        } elseif ($unmaskedClientFrames > 0 && $maskedFrameCount > 0) {
            $result['has_mask_issue'] = true;
            $result['indicators'][] = 'mixed_masked_frames';
        }

        if ($ast['ping_count'] >= self::PING_FLOOD_THRESHOLD) {
            $result['ping_flood_detected'] = true;
            $result['indicators'][] = 'ping_flood';
        }

        foreach ($ast['messages'] as $message) {
            if ($message['opcode'] === self::OPCODE_TEXT || $message['opcode'] === self::OPCODE_BINARY) {
                $payload = $message['payload'];
                $injectionResult = self::detectInjections($payload);
                if (!empty($injectionResult)) {
                    $result['injection_detected'] = array_merge(
                        $result['injection_detected'],
                        $injectionResult
                    );
                }
                if ($message['fragmented']) {
                    $result['indicators'][] = 'fragmented_message_injection_check';
                }
            }
        }

        $result['injection_detected'] = array_values(array_unique($result['injection_detected']));
        if (!empty($result['injection_detected'])) {
            $result['indicators'][] = 'payload_injection:' . implode(',', $result['injection_detected']);
        }

        return $result;
    }

    private static function analyzeCloseFrame(array $frame): array {
        $issues = [];
        $indicators = [];

        if ($frame['payload_length'] === 0) {
            return ['issues' => $issues, 'indicators' => $indicators];
        }

        if ($frame['payload_length'] < 2) {
            $issues[] = 'close_frame_invalid_length';
            $indicators[] = 'close_frame_invalid_length';
            return ['issues' => $issues, 'indicators' => $indicators];
        }

        $payload = $frame['unmasked_payload'];
        $statusCode = (ord($payload[0]) << 8) | ord($payload[1]);

        if ($statusCode < 1000 || $statusCode > 4999) {
            $issues[] = 'close_status_out_of_range:' . $statusCode;
            $indicators[] = 'close_status_out_of_range';
        }

        if ($statusCode >= 1016 && $statusCode <= 2999) {
            $issues[] = 'close_status_reserved:' . $statusCode;
            $indicators[] = 'close_status_reserved';
        }

        if ($frame['payload_length'] > 125) {
            $issues[] = 'close_frame_too_large';
            $indicators[] = 'close_frame_too_large';
        }

        $reasonLength = $frame['payload_length'] - 2;
        if ($reasonLength > 100) {
            $issues[] = 'close_reason_too_long:' . $reasonLength;
            $indicators[] = 'close_reason_too_long';
        }

        return ['issues' => $issues, 'indicators' => $indicators];
    }

    private static function detectInjections(string $payload): array {
        $detected = [];

        foreach (self::$sqlInjectionPatterns as $pattern) {
            if (preg_match($pattern, $payload)) {
                $detected[] = 'sql_injection';
                break;
            }
        }

        foreach (self::$xssPatterns as $pattern) {
            if (preg_match($pattern, $payload)) {
                $detected[] = 'xss';
                break;
            }
        }

        foreach (self::$commandInjectionPatterns as $pattern) {
            if (preg_match($pattern, $payload)) {
                $detected[] = 'command_injection';
                break;
            }
        }

        return $detected;
    }

    private static function analyzeAsTextPayload(string $input, array $result): array {
        $injectionResult = self::detectInjections($input);
        if (!empty($injectionResult)) {
            $result['injection_detected'] = $injectionResult;
            $result['indicators'][] = 'text_payload_injection:' . implode(',', $injectionResult);
            $result['score'] = self::calculateScore($result);
            $result['risk_level'] = self::determineRiskLevel($result['score']);
        }

        return $result;
    }

    private static function calculateScore(array $result): int {
        $score = 0;

        if ($result['has_mask_issue']) {
            $score += 15;
        }

        if ($result['has_rsv_abuse']) {
            $score += 10;
        }

        if ($result['has_control_frame_violation']) {
            $score += 20;
        }

        if ($result['has_large_payload']) {
            $score += 15;
            if (!empty($result['indicators']) && in_array('extremely_large_payload', $result['indicators'])) {
                $score += 25;
            }
        }

        if (!empty($result['ping_flood_detected'] ?? false)) {
            $score += 25;
        }

        if (!empty($result['close_frame_anomalies'])) {
            $score += count($result['close_frame_anomalies']) * 5;
        }

        if (!empty($result['injection_detected'])) {
            foreach ($result['injection_detected'] as $injection) {
                switch ($injection) {
                    case 'sql_injection':
                        $score += 30;
                        break;
                    case 'xss':
                        $score += 25;
                        break;
                    case 'command_injection':
                        $score += 35;
                        break;
                    default:
                        $score += 15;
                        break;
                }
            }
        }

        $undefinedOpcodeIndicators = array_filter($result['indicators'], function($ind) {
            return strpos($ind, 'undefined_opcode_') === 0;
        });
        if (!empty($undefinedOpcodeIndicators)) {
            $score += count($undefinedOpcodeIndicators) * 10;
        }

        if ($result['has_fragmented'] && !empty($result['injection_detected'])) {
            $score += 10;
        }

        return min($score, 100);
    }

    private static function determineRiskLevel(int $score): string {
        if ($score === 0) {
            return self::RISK_CLEAN;
        }
        if ($score < 20) {
            return self::RISK_LOW;
        }
        if ($score < 40) {
            return self::RISK_MEDIUM;
        }
        if ($score < 70) {
            return self::RISK_HIGH;
        }
        return self::RISK_CRITICAL;
    }
}
