<?php
defined('ABSPATH') || exit;

class WafNormalizer {
    private static $homoglyph_map = [];
    private static $fullwidth_map = [];
    private static $base64_max_len = 2000;
    private static $homoglyph_file = 'homoglyph_map.json';

    public static function init() {
        if (!empty(self::$fullwidth_map)) return;
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
            ' ' => ' ',' ' => ' ',' ' => ' ',
        ];
    }

    public static function normalize($input) {
        if (empty($input)) return '';
        self::init();
        $working = $input;
        $maxPasses = 8;
        $lastLen = 0;
        for ($pass = 0; $pass < $maxPasses; $pass++) {
            $working = self::recursiveUrlDecode($working);
            $working = html_entity_decode($working, ENT_QUOTES, 'UTF-8');
            $working = self::unescapeUnicode($working);
            $working = self::utf7Decode($working);
            if (strlen($working) <= self::$base64_max_len && strlen($working) > 8 && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $working)) {
                $decoded = base64_decode($working, true);
                if ($decoded !== false && self::isLikelyText($decoded)) {
                    $working = $decoded;
                }
            }
            if (strlen($working) === $lastLen && $pass > 0) break;
            $lastLen = strlen($working);
        }
        if (class_exists('Normalizer')) {
            $working = \Normalizer::normalize($working, \Normalizer::NFKC);
        }
        $working = strtr($working, self::$fullwidth_map);
        if (function_exists('mb_strtolower')) {
            $working = mb_strtolower($working, 'UTF-8');
        } else {
            $working = strtolower($working);
        }
        $working = strtr($working, self::$homoglyph_map);
        $working = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x{200B}-\x{200F}\x{202A}-\x{202E}\x{FEFF}\x{2060}-\x{2064}]/u', '', $working);
        if (defined('WAF_NORMALIZE_SQL_COMMENTS') && WAF_NORMALIZE_SQL_COMMENTS) {
            $working = preg_replace('/\/\*.*?\*\/|--[^\n]*|#.*/i', ' ', $working);
        }
        $working = preg_replace('/\s+/u', ' ', $working);
        return trim($working);
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

    /**
     * 对 XML 字符串进行上下文归一化（已修复 XXE 漏洞）
     */
    public static function normalizeXml($rawXml) {
        if (!class_exists('DOMDocument')) return self::normalize($rawXml);
        $dom = new \DOMDocument();
        libxml_use_internal_errors(true);
        // 禁用外部实体加载，防止 XXE
        libxml_disable_entity_loader(true);
        if (!$dom->loadXML($rawXml, LIBXML_NOENT | LIBXML_NONET)) {
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