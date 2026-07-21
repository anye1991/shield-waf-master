<?php
defined('ABSPATH') || exit;

class WafNormalizer {
    private static $homoglyph_map = [];
    private static $fullwidth_map = [];
    private static $base64_max_len = 2000;
    private static $homoglyph_file = 'homoglyph_map.json';
    private static $initialized = false;
    public static $double_encoding_detected = false;

    public static function init() {
        if (self::$initialized) return;
        self::$initialized = true;
        self::$fullwidth_map = [
            '０' => '0','１' => '1','２' => '2','３' => '3','４' => '4',
            '５' => '5','６' => '6','７' => '7','８' => '8','９' => '9',
            'ａ' => 'a','ｂ' => 'b','ｃ' => 'c','ｄ' => 'd','ｅ' => 'e',
            'ｆ' => 'f','ｇ' => 'g','ｈ' => 'h','ｉ' => 'i','ｊ' => 'j',
            'ｋ' => 'k','ｌ' => 'l','ｍ' => 'm','ｎ' => 'n','ｏ' => 'o',
            'ｐ' => 'p','ｑ' => 'q','ｒ' => 'r','ｓ' => 's','ｔ' => 't',
            'ｕ' => 'u','ｖ' => 'v','ｗ' => 'w','ｘ' => 'x','ｙ' => 'y',
            'ｚ' => 'z',
            'Ａ' => 'A','Ｂ' => 'B','Ｃ' => 'C','Ｄ' => 'D','Ｅ' => 'E',
            'Ｆ' => 'F','Ｇ' => 'G','Ｈ' => 'H','Ｉ' => 'I','Ｊ' => 'J',
            'Ｋ' => 'K','Ｌ' => 'L','Ｍ' => 'M','Ｎ' => 'N','Ｏ' => 'O',
            'Ｐ' => 'P','Ｑ' => 'Q','Ｒ' => 'R','Ｓ' => 'S','Ｔ' => 'T',
            'Ｕ' => 'U','Ｖ' => 'V','Ｗ' => 'W','Ｘ' => 'X','Ｙ' => 'Y',
            'Ｚ' => 'Z',
            '／' => '/','：' => ':','；' => ';','？' => '?',
            '＜' => '<','＞' => '>','＝' => '=',
            '（' => '(','）' => ')','＇' => "'",'＂' => '"','＼' => '\\',
            '＠' => '@','＃' => '#','＄' => '$','％' => '%','＆' => '&',
            '＊' => '*','＋' => '+','，' => ',','．' => '.','！' => '!',
        ];
        self::$homoglyph_map = self::getBuiltInHomoglyphs();
        $extFile = __DIR__ . '/' . self::$homoglyph_file;
        if (is_file($extFile)) {
            $ext = json_decode(file_get_contents($extFile), true);
            if (is_array($ext)) {
                self::$homoglyph_map = array_merge(self::$homoglyph_map, $ext);
            }
        }
    }

    private static function getBuiltInHomoglyphs() {
        return [
            'а' => 'a','е' => 'e','о' => 'o','с' => 'c','р' => 'p','у' => 'y','х' => 'x','і' => 'i','ј' => 'j','ѕ' => 's',
            'ԛ' => 'q','ԝ' => 'w','ҽ' => 'e','ҿ' => 'c','ӷ' => 'g','ӏ' => 'i','һ' => 'h',
            'α' => 'a','β' => 'b','γ' => 'g','δ' => 'd','ε' => 'e','ζ' => 'z','η' => 'h','ι' => 'i','κ' => 'k','λ' => 'l',
            'μ' => 'm','ν' => 'v','ξ' => 'x','π' => 'p','ρ' => 'r','σ' => 's','τ' => 't','υ' => 'u','φ' => 'f','χ' => 'x',
            'ψ' => 'y','ω' => 'w','ο' => 'o',
            'ա' => 'w','բ' => 'b','գ' => 'q','դ' => 'd','ե' => 'e','զ' => 'q','է' => 'e','ը' => 'e','թ' => 't','ժ' => 'z',
            'ի' => 'i','լ' => 'l','խ' => 'x','ծ' => 'c','կ' => 'k','հ' => 'h','ձ' => 'j','ղ' => 'q','ճ' => 'c','մ' => 'm',
            'յ' => 'y','ն' => 'n','շ' => 's','ո' => 'o','չ' => 'c','պ' => 'p','ջ' => 'j','ռ' => 'r','ս' => 's','վ' => 'v',
            'տ' => 't','ր' => 'r','ց' => 'c','ու' => 'u','փ' => 'p','ք' => 'q','օ' => 'o','ֆ' => 'f',
            'ä' => 'a','ö' => 'o','ü' => 'u','ñ' => 'n','é' => 'e','è' => 'e','ê' => 'e','ë' => 'e',
            'í' => 'i','ì' => 'i','î' => 'i','ï' => 'i','ó' => 'o','ò' => 'o','ô' => 'o','õ' => 'o',
            'ú' => 'u','ù' => 'u','û' => 'u','ý' => 'y','ÿ' => 'y','ç' => 'c','ş' => 's','ğ' => 'g',
            'ß' => 'ss','æ' => 'ae','œ' => 'oe',
            'ى' => 'y','ه' => 'o','ا' => 'a','ل' => 'l','ك' => 'k','م' => 'm','ن' => 'n','ع' => 'e',
            'א' => 'x','ו' => 'i','י' => 'i','כ' => 'k','מ' => 'm','ס' => 's','ע' => 'e','צ' => 'c',
            'า' => 'a','ห' => 'n','ม' => 'm','อ' => 'o','ย' => 'y','ร' => 'r','ล' => 'l','ว' => 'w',
            'ค' => 'c','ต' => 't','น' => 'n','บ' => 'b','ป' => 'p','ส' => 's','ง' => 'g',
            'ល' => 'n','ស' => 's','អ' => 'a','ក' => 'k','ត' => 't','ន' => 'n','ប' => 'b','ម' => 'm',
            'ဝ' => 'o','မ' => 'm','တ' => 't','န' => 'n','ပ' => 'p','က' => 'k','သ' => 's',
            'र' => 'd','न' => 'n','ल' => 'l','त' => 't','क' => 'k','म' => 'm','स' => 's',
            '₿' => 'B','€' => 'E','₹' => 'R','₽' => 'P','₩' => 'W','₪' => 'S',
            'ℕ' => 'N','ℤ' => 'Z','ℚ' => 'Q','ℝ' => 'R','ℂ' => 'C',
            ' ' => ' ',' ' => ' ',' ' => ' ',
        ];
    }

    public static function normalize($input) {
        if (empty($input)) return '';
        $result = self::normalizeWithContext($input);
        return $result['output'];
    }

    public static function normalizeWithContext($input) {
        if (empty($input)) {
            return [
                'output' => '',
                'layers' => [],
                'encoding_depth' => 0,
                'encoding_complexity' => 0,
                'transform_count' => 0,
                'semantic_score' => 0,
            ];
        }
        self::init();
        self::$double_encoding_detected = false;

        $working = $input;
        $layers = [];
        $totalTransforms = 0;
        $encodingDepth = 0;
        $encodingTypes = [];

        $layerDefs = [
            1  => ['name' => 'URL递归解码', 'method' => 'layerUrlDecode'],
            2  => ['name' => 'HTML实体解码', 'method' => 'layerHtmlEntity'],
            3  => ['name' => 'Unicode转义解码', 'method' => 'layerUnicode'],
            4  => ['name' => 'UTF-7解码', 'method' => 'layerUtf7'],
            5  => ['name' => 'Base64智能解码', 'method' => 'layerBase64'],
            6  => ['name' => 'NFKC规范化', 'method' => 'layerNfkc'],
            7  => ['name' => '全角半角转换', 'method' => 'layerFullwidth'],
            8  => ['name' => '同形字符映射', 'method' => 'layerHomoglyph'],
            9  => ['name' => '零宽控制字符清除', 'method' => 'layerZeroWidth'],
            10 => ['name' => 'SQL注释移除', 'method' => 'layerSqlComments'],
            11 => ['name' => '空格压缩规范化', 'method' => 'layerWhitespace'],
            12 => ['name' => '大小写统一', 'method' => 'layerLowercase'],
            13 => ['name' => '语义上下文归一化', 'method' => 'layerSemantic'],
            14 => ['name' => '双重编码检测与深度解码', 'method' => 'layerDoubleEncoding'],
        ];

        $maxPasses = 12;
        $urlChanged = false;
        $htmlChanged = false;
        for ($pass = 0; $pass < $maxPasses; $pass++) {
            $prevLen = strlen($working);
            $passChanged = false;

            for ($l = 1; $l <= 5; $l++) {
                $method = $layerDefs[$l]['method'];
                $before = $working;
                $working = self::$method($working);
                $changed = $before !== $working;
                if ($changed) {
                    $passChanged = true;
                    $encodingTypes[] = "L{$l}";
                    $totalTransforms++;
                    if ($l === 1) $urlChanged = true;
                    if ($l === 2) $htmlChanged = true;
                }
                // 首次pass记录L1-L5层信息
                if ($pass === 0) {
                    $layers[$l] = [
                        'name' => $layerDefs[$l]['name'],
                        'changed' => $changed,
                        'input_len' => strlen($before),
                        'output_len' => strlen($working),
                    ];
                }
            }

            if (!$passChanged && $pass > 0) break;
            if ($passChanged) $encodingDepth++;
        }

        // 检测双重编码：URL编码和HTML实体在同一输入中共存
        if ($urlChanged && $htmlChanged) {
            self::$double_encoding_detected = true;
        }

        for ($l = 6; $l <= 14; $l++) {
            $method = $layerDefs[$l]['method'];
            $before = $working;
            $working = self::$method($working);
            $changed = $before !== $working;
            if ($changed) {
                $encodingTypes[] = "L{$l}";
                $totalTransforms++;
            }
            $layers[$l] = [
                'name' => $layerDefs[$l]['name'],
                'changed' => $changed,
                'input_len' => strlen($before),
                'output_len' => strlen($working),
            ];
        }

        $complexity = self::calcEncodingComplexity($encodingDepth, $totalTransforms, $encodingTypes);
        $semanticScore = self::calcSemanticScore($working, $encodingTypes, $encodingDepth);

        return [
            'output' => trim($working),
            'layers' => $layers,
            'encoding_depth' => $encodingDepth,
            'encoding_complexity' => $complexity,
            'transform_count' => $totalTransforms,
            'encoding_types' => array_unique($encodingTypes),
            'semantic_score' => $semanticScore,
            'double_encoding_detected' => self::$double_encoding_detected,
        ];
    }

    private static function calcEncodingComplexity($depth, $transforms, $types) {
        $score = 0;
        $score += $depth * 8;
        $score += $transforms * 2;
        $uniqueTypes = count(array_unique($types));
        $score += $uniqueTypes * 5;
        $highRiskTypes = ['L5', 'L4', 'L3'];
        foreach ($highRiskTypes as $t) {
            if (in_array($t, $types)) $score += 10;
        }
        return min($score, 100);
    }

    private static function calcSemanticScore($text, $encodingTypes, $depth) {
        $score = 0;
        if ($depth >= 4) $score += 25;
        elseif ($depth >= 2) $score += 10;
        $mixedScripts = self::countMixedScripts($text);
        if ($mixedScripts >= 3) $score += 20;
        elseif ($mixedScripts >= 2) $score += 8;
        $printableRatio = self::printableRatio($text);
        if ($printableRatio < 0.5) $score += 15;
        elseif ($printableRatio < 0.7) $score += 5;
        if (preg_match('/[a-zA-Z].*[\x{0400}-\x{04FF}].*[a-zA-Z]/u', $text)) $score += 15;
        if (preg_match('/[a-zA-Z].*[\x{0370}-\x{03FF}].*[a-zA-Z]/u', $text)) $score += 12;
        return min($score, 100);
    }

    private static function countMixedScripts($text) {
        $scripts = 0;
        if (preg_match('/[a-zA-Z]/', $text)) $scripts++;
        if (preg_match('/[\x{0400}-\x{04FF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0370}-\x{03FF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0530}-\x{058F}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0600}-\x{06FF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0E00}-\x{0E7F}]/u', $text)) $scripts++;
        if (preg_match('/[\x{0E80}-\x{0EFF}]/u', $text)) $scripts++;
        if (preg_match('/[\x{1000}-\x{109F}]/u', $text)) $scripts++;
        return $scripts;
    }

    private static function printableRatio($str) {
        $len = strlen($str);
        if ($len === 0) return 1;
        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $ord = ord($str[$i]);
            if (($ord >= 32 && $ord <= 126) || $ord === 9 || $ord === 10 || $ord === 13 || $ord > 127) {
                $printable++;
            }
        }
        return $printable / $len;
    }

    private static function layerUrlDecode($s) {
        return self::recursiveUrlDecode($s);
    }

    private static function layerHtmlEntity($s) {
        return html_entity_decode($s, ENT_QUOTES, 'UTF-8');
    }

    private static function layerUnicode($s) {
        return self::unescapeUnicode($s);
    }

    private static function layerUtf7($s) {
        return self::utf7Decode($s);
    }

    private static function layerBase64($s) {
        // 跳过Hex编码字符串（0x前缀），交给L14处理
        if (preg_match('/^0x[0-9a-f]+$/i', $s)) return $s;
        if (strlen($s) <= self::$base64_max_len && strlen($s) > 8 && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $s)) {
            $decoded = base64_decode($s, true);
            if ($decoded !== false && self::isLikelyText($decoded)) {
                return $decoded;
            }
        }
        return $s;
    }

    private static function layerNfkc($s) {
        if (class_exists('Normalizer')) {
            return \Normalizer::normalize($s, \Normalizer::NFKC);
        }
        return $s;
    }

    private static function layerFullwidth($s) {
        return strtr($s, self::$fullwidth_map);
    }

    private static function layerHomoglyph($s) {
        return strtr($s, self::$homoglyph_map);
    }

    private static function layerZeroWidth($s) {
        return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x{200B}-\x{200F}\x{202A}-\x{202E}\x{FEFF}\x{2060}-\x{2064}]/u', '', $s);
    }

    private static function layerSqlComments($s) {
        if (!defined('WAF_NORMALIZE_SQL_COMMENTS') || WAF_NORMALIZE_SQL_COMMENTS) {
            // 移除 MySQL 内联注释 /*!50000UNION*/ → UNION（保留注释内容，两侧加空格防止关键字粘连）
            // 加空格是为了避免 /*!50000UNION*//*!50000SELECT*/ 被提取成 UNIONSELECT 导致签名漏匹配
            $s = preg_replace('/\/\*!\d+\s*([^*]*)\*\//i', ' $1 ', $s);
            // 移除普通注释 /**/、--、#（替换为空格，同样防止关键字粘连）
            $s = preg_replace('/\/\*.*?\*\/|--[^\n]*|#.*/is', ' ', $s);
            return $s;
        }
        return $s;
    }

    private static function layerWhitespace($s) {
        return preg_replace('/\s+/u', ' ', $s);
    }

    private static function layerLowercase($s) {
        if (function_exists('mb_strtolower')) {
            return mb_strtolower($s, 'UTF-8');
        }
        return strtolower($s);
    }

    private static function layerSemantic($s) {
        // Hex解码：0x73656c656374 → "select"
        $s = preg_replace_callback('/\b0x([0-9a-f]+)\b/i', function($m) {
            $hex = $m[1];
            if (strlen($hex) % 2 !== 0) $hex = '0' . $hex;
            $decoded = @hex2bin($hex);
            return ($decoded !== false && self::isLikelyText($decoded)) ? $decoded : $m[0];
        }, $s);
        // 八进制解码：\163\171\163\164\145\155 → "system"
        $s = preg_replace_callback('/((?:\\\\[0-7]{1,3}){2,})/', function($m) {
            $octals = $m[1];
            $decoded = '';
            if (preg_match_all('/\\\\([0-7]{1,3})/', $octals, $matches)) {
                foreach ($matches[1] as $oct) {
                    $val = octdec($oct);
                    if ($val > 0 && $val < 256) {
                        $decoded .= chr($val);
                    }
                }
            }
            return ($decoded !== '' && self::isLikelyText($decoded)) ? $decoded : $m[0];
        }, $s);
        // 移除 SQL 函数混淆：unhex()/char()/ascii()/ord()
        $s = preg_replace('/\b(?:unhex|hex|char|ascii|ord)\s*\(/i', '', $s);
        $s = preg_replace('/\bconcat\s*\(/i', 'concat(', $s);
        return $s;
    }

    /**
     * L14: 双重编码检测与深度解码
     * 检测并解码混合编码载荷（如URL编码嵌套HTML实体、Hex编码+Base64叠加等）
     * 同时标记双重编码绕过行为，为评分系统提供额外信号
     */
    private static function layerDoubleEncoding($s) {
        // 检测Hex字符串编码（如 0x73656c656374 → select）
        $s = preg_replace_callback('/0x([0-9a-f]{6,})/i', function($m) {
            $hex = $m[1];
            $decoded = @hex2bin($hex);
            if ($decoded !== false && self::isLikelyText($decoded)) {
                return $decoded;
            }
            return $m[0];
        }, $s);

        // 检测连续转义序列（如 \x27\x3c\x73 ）
        // 注意：正则中需要匹配字面的反斜杠+x，需用 \\\\ 在PHP单引号字符串中
        $s = preg_replace_callback('/((?:\\\\x[0-9a-fA-F]{2}){3,})/', function($m) {
            $hexStr = $m[1];
            $decoded = '';
            if (preg_match_all('/\\\\x([0-9a-fA-F]{2})/', $hexStr, $hexMatches)) {
                foreach ($hexMatches[1] as $hex) {
                    $decoded .= chr(hexdec($hex));
                }
            }
            return ($decoded !== '' && self::isLikelyText($decoded)) ? $decoded : $m[0];
        }, $s);

        // 检测八进制编码（如 \104\105\114）
        $s = preg_replace_callback('/((?:\\\\[0-7]{3}){3,})/', function($m) {
            $octStr = $m[1];
            $decoded = '';
            if (preg_match_all('/\\\\([0-7]{3})/', $octStr, $octMatches)) {
                foreach ($octMatches[1] as $oct) {
                    $decoded .= chr(octdec($oct));
                }
            }
            return ($decoded !== '' && self::isLikelyText($decoded)) ? $decoded : $m[0];
        }, $s);

        return $s;
    }

    private static function recursiveUrlDecode($s) {
        $prev = '';
        while ($s !== $prev) {
            $prev = $s;
            $decoded = rawurldecode($s);
            if ($decoded !== $s) { $s = $decoded; continue; }
            $decoded2 = urldecode($s);
            if ($decoded2 !== $s) { $s = $decoded2; continue; }
            break;
        }
        return $s;
    }

    private static function unescapeUnicode($s) {
        return preg_replace_callback('/\\\\u([0-9a-fA-F]{4})|\\\\U([0-9a-fA-F]{8})/', function($m) {
            $code = hexdec($m[1] ?: $m[2]);
            return mb_chr($code, 'UTF-8') ?? $m[0];
        }, $s);
    }

    private static function utf7Decode($s) {
        if (strpos($s, '+') === false || strpos($s, '-') === false) return $s;
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            if ($s[$i] === '+') {
                $end = strpos($s, '-', $i);
                if ($end === false) { $out .= '+'; continue; }
                $segment = substr($s, $i + 1, $end - $i - 1);
                $i = $end;
                if ($segment === '') { $out .= '+'; continue; }
                $modified = strtr($segment, ['+' => '+', '/' => '/', ',' => '/', '-' => '=']);
                $mod = strlen($modified) % 4;
                if ($mod) $modified .= str_repeat('=', 4 - $mod);
                $decoded = base64_decode($modified, true);
                if ($decoded === false || strlen($decoded) % 2 !== 0) {
                    $out .= '+' . $segment . '-'; continue;
                }
                $utf16 = '';
                for ($j = 0; $j < strlen($decoded); $j += 2) {
                    $code = (ord($decoded[$j]) << 8) | ord($decoded[$j + 1]);
                    $utf16 .= mb_chr($code, 'UTF-8');
                }
                $out .= $utf16;
            } else {
                $out .= $s[$i];
            }
        }
        return $out;
    }

    private static function isLikelyText($str) {
        $len = strlen($str);
        if ($len === 0) return false;
        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $ord = ord($str[$i]);
            if (($ord >= 32 && $ord <= 126) || $ord === 9 || $ord === 10 || $ord === 13 || $ord > 127) {
                $printable++;
            }
        }
        return ($printable / $len) > 0.8;
    }

    public static function normalizeJson($rawJson) {
        $data = json_decode($rawJson, true);
        if ($data === null) return self::normalize($rawJson);
        $normalized = self::_normalizeJsonRecursive($data);
        return json_encode($normalized, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private static function _normalizeJsonRecursive($data) {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $data[$key] = self::_normalizeJsonRecursive($value);
            }
            return $data;
        } elseif (is_string($data)) {
            return self::normalize($data);
        }
        return $data;
    }

    public static function normalizeXml($rawXml) {
        if (!class_exists('DOMDocument')) return self::normalize($rawXml);
        $dom = new \DOMDocument();
        libxml_use_internal_errors(true);
        libxml_disable_entity_loader(true);
        if (!$dom->loadXML($rawXml, LIBXML_NONET)) {
            libxml_disable_entity_loader(false);
            return self::normalize($rawXml);
        }
        libxml_disable_entity_loader(false);
        libxml_clear_errors();
        self::_normalizeXmlNode($dom->documentElement);
        return $dom->saveXML($dom->documentElement);
    }

    private static function _normalizeXmlNode($node) {
        if ($node->nodeType === XML_TEXT_NODE || $node->nodeType === XML_CDATA_SECTION_NODE) {
            $node->nodeValue = self::normalize($node->nodeValue);
        }
        if ($node->hasChildNodes()) {
            foreach ($node->childNodes as $child) {
                self::_normalizeXmlNode($child);
            }
        }
    }
}
