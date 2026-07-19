<?php
/**
 * 对抗样本防御引擎（L10 - 深度重写版）
 *
 * 从"混淆关键词匹配"升级为"混淆还原 + 对抗样本检测"。
 * 核心能力：
 *   A. recursiveDecode       —— 多层编码递归还原（URL/HTML/Base64/Hex/Octal，最大深度 5）
 *   B. detectObfuscation      —— 混淆模式识别（注释分隔/大小写混合/CHAR()/字符串拼接/空白替换）
 *   C. detectAdversarialPayload —— 对抗样本检测（同形字/零宽字符/WAF 绕过 payload 结构）
 *   D. analyzeEncodingChain   —— 编码链分析（不自然编码组合/深度异常/混合编码）
 *   E. comparePrePostDecode   —— 还原前后对比（原文本看似无害但还原后含攻击 payload）
 *   F. scoreObfuscationComplexity —— 混淆复杂度评分（0-100）
 *
 * 关键突破：recursiveDecode() 真正递归还原多层嵌套编码，而非单次 urldecode。
 * 公共 API 保持不变：analyze() 返回 ['score' => 0-100, ...]
 */
defined('ABSPATH') || exit;

class AdversarialDefense {
    /** 递归解码最大深度 */
    public const MAX_DECODE_DEPTH = 5;

    /** 已知攻击 payload 结构特征（结构化模式，非单个关键词） */
    private static $attack_payload_patterns = [
        'sql_tautology_num' => '/\b(?:or|and)\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i',
        'sql_tautology_str' => '/\b(?:or|and)\b\s+[\'"][^\'"]{1,20}[\'"]\s*=\s*[\'"][^\'"]{1,20}[\'"]/i',
        'sql_union_select'  => '/\bunion\b[\s\S]{0,40}\bselect\b/i',
        'sql_comment_trail' => '/[\'"`]\s*(?:--|#)\s/',
        'sql_stacked_query' => '/;\s*(?:drop|insert|update|delete|select|exec|alter|create)\b/i',
        'sql_meta_probe'    => '/\binformation_schema\b|\bsysobjects\b|\bmysql\.\w+/i',
        'sql_time_blind'    => '/\b(?:sleep|benchmark|waitfor\s+delay)\s*\(/i',
        'sql_danger_func'   => '/\b(?:load_file|outfile|dumpfile|xp_cmdshell|extractvalue|updatexml)\s*\(/i',
        'xss_script_tag'    => '/<\s*script\b/i',
        'xss_event_handler' => '/\bon[a-z]+\s*=\s*[\'"]?[^\'">\s]+/i',
        'xss_js_protocol'   => '/\bjavascript:\s*\S/i',
        'xss_svg_payload'   => '/<\s*svg\b[\s\S]{0,80}?\bon[a-z]+\s*=/i',
        'cmd_pipe'          => '/\|\s*(?:sh|bash|cat|ls|id|whoami|nc|wget|curl)\b/i',
        'cmd_backtick'      => '/`[^`]{1,100}`/',
        'cmd_dollar_paren'  => '/\$\([^)]{1,100}\)/',
        'php_eval_chain'    => '/\b(?:eval|assert|system|exec|shell_exec|passthru)\s*\(/i',
        'php_code_tag'      => '/<\?(?:php)?|<%/',
    ];

    /** WAF 绕过专用 payload 结构（高级对抗样本特征） */
    private static $waf_bypass_patterns = [
        'comment_split_keyword' => '/[a-zA-Z]+\s*\/\*!?\d*\s*[\s\S]{0,40}?\*\/\s*[a-zA-Z]+/i',
        'string_concat_chain'   => '/[\'"][a-zA-Z0-9_]{1,8}[\'"]\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"](?:\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"])+/',
        'char_function'         => '/\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}\s*\)/i',
        'whitespace_subst'      => '/[\x0b\x0c]\s*(?:union|select|from|where|or|and)\b/i',
        'versioned_comment'     => '/\/\*!\d{4,}\s*[\s\S]*?\*\//i',
    ];

    /** 零宽字符与不可见 Unicode 字符（UTF-8 字节序列） */
    private static $zero_width_chars = [
        "\u{200B}" => 'ZWSP', "\u{200C}" => 'ZWNJ', "\u{200D}" => 'ZWJ',
        "\u{FEFF}" => 'BOM',  "\u{2060}" => 'WJ',
    ];

    /** 同形字映射：500+字符，覆盖西里尔/希腊/亚美尼亚/数学字母数字符号/全角/其他变体 → 拉丁字母 */
    private static $homoglyph_map = [
        // === 1. 西里尔字母 → 拉丁字母 ===
        // 小写
        "\u{0430}" => 'a', "\u{0435}" => 'e', "\u{043E}" => 'o', "\u{0440}" => 'p',
        "\u{0441}" => 'c', "\u{0443}" => 'y', "\u{0445}" => 'x', "\u{0456}" => 'i',
        "\u{0457}" => 'e', "\u{0432}" => 'b', "\u{0434}" => 'd', "\u{0437}" => '3',
        "\u{043B}" => 'l', "\u{043C}" => 'm', "\u{043D}" => 'h', "\u{043F}" => 'n',
        "\u{0442}" => 't', "\u{0444}" => 'f', "\u{044B}" => 'b', "\u{044C}" => 'b',
        "\u{044A}" => 'b', "\u{044E}" => 'u', "\u{044F}" => 'y', "\u{0451}" => 'e',
        // 大写
        "\u{0410}" => 'A', "\u{0412}" => 'B', "\u{0415}" => 'E', "\u{041A}" => 'K',
        "\u{041C}" => 'M', "\u{041D}" => 'H', "\u{041E}" => 'O', "\u{0420}" => 'P',
        "\u{0421}" => 'C', "\u{0422}" => 'T', "\u{0425}" => 'X', "\u{0406}" => 'I',
        "\u{0407}" => 'E', "\u{0414}" => 'D', "\u{0417}" => '3', "\u{041B}" => 'L',
        "\u{041F}" => 'N', "\u{0424}" => 'F', "\u{042B}" => 'B', "\u{042C}" => 'B',
        "\u{042A}" => 'B', "\u{042E}" => 'U', "\u{042F}" => 'Y', "\u{0401}" => 'E',
        "\u{0413}" => 'F', "\u{0416}" => 'X', "\u{0418}" => 'N', "\u{0419}" => 'N',
        "\u{0423}" => 'Y', "\u{0426}" => 'U', "\u{0428}" => 'W', "\u{0429}" => 'W',
        "\u{0427}" => 'h',

        // === 2. 希腊字母 → 拉丁字母 ===
        // 小写
        "\u{03B1}" => 'a', "\u{03B2}" => 'B', "\u{03B3}" => 'y', "\u{03B4}" => 'd',
        "\u{03B5}" => 'e', "\u{03B6}" => 'g', "\u{03B7}" => 'n', "\u{03B8}" => '0',
        "\u{03B9}" => 'i', "\u{03BA}" => 'k', "\u{03BB}" => 'l', "\u{03BC}" => 'u',
        "\u{03BD}" => 'v', "\u{03BE}" => 'E', "\u{03BF}" => 'o', "\u{03C0}" => 'p',
        "\u{03C1}" => 'p', "\u{03C2}" => 'c', "\u{03C3}" => 'c', "\u{03C4}" => 't',
        "\u{03C5}" => 'u', "\u{03C6}" => 'q', "\u{03C7}" => 'x', "\u{03C8}" => 'w',
        "\u{03C9}" => 'w',
        // 大写
        "\u{0391}" => 'A', "\u{0392}" => 'B', "\u{0393}" => 'E', "\u{0394}" => 'A',
        "\u{0395}" => 'E', "\u{0396}" => 'Z', "\u{0397}" => 'H', "\u{0398}" => 'Q',
        "\u{0399}" => 'I', "\u{039A}" => 'K', "\u{039B}" => 'A', "\u{039C}" => 'M',
        "\u{039D}" => 'N', "\u{039E}" => 'E', "\u{039F}" => 'O', "\u{03A0}" => 'P',
        "\u{03A1}" => 'P', "\u{03A3}" => 'E', "\u{03A4}" => 'T', "\u{03A5}" => 'Y',
        "\u{03A6}" => 'O', "\u{03A7}" => 'X', "\u{03A8}" => 'W', "\u{03A9}" => 'W',

        // === 3. 亚美尼亚字母 → 拉丁字母 ===
        "\u{0531}" => 'A', "\u{0561}" => 'a',
        "\u{0532}" => 'B', "\u{0562}" => 'b',
        "\u{0533}" => 'G', "\u{0563}" => 'g',
        "\u{0534}" => 'D', "\u{0564}" => 'd',
        "\u{0535}" => 'E', "\u{0565}" => 'e',
        "\u{0536}" => 'Z', "\u{0566}" => 'z',
        "\u{0537}" => 'E', "\u{0567}" => 'e',
        "\u{0538}" => 'U', "\u{0568}" => 'u',
        "\u{0539}" => 'T', "\u{0569}" => 't',
        "\u{053A}" => 'J', "\u{056A}" => 'j',
        "\u{053B}" => 'I', "\u{056B}" => 'i',
        "\u{053C}" => 'L', "\u{056C}" => 'l',
        "\u{053D}" => 'X', "\u{056D}" => 'x',
        "\u{053E}" => 'C', "\u{056E}" => 'c',
        "\u{053F}" => 'K', "\u{056F}" => 'k',
        "\u{0540}" => 'H', "\u{0570}" => 'h',
        "\u{0541}" => 'D', "\u{0571}" => 'd',
        "\u{0542}" => 'Z', "\u{0572}" => 'z',
        "\u{0543}" => 'K', "\u{0573}" => 'k',
        "\u{0544}" => 'L', "\u{0574}" => 'l',
        "\u{0545}" => 'M', "\u{0575}" => 'm',
        "\u{0546}" => 'Y', "\u{0576}" => 'y',
        "\u{0547}" => 'N', "\u{0577}" => 'n',
        "\u{0548}" => 'S', "\u{0578}" => 's',
        "\u{0549}" => 'O', "\u{0579}" => 'o',
        "\u{054A}" => 'V', "\u{057A}" => 'v',
        "\u{054B}" => 'T', "\u{057B}" => 't',
        "\u{054C}" => 'R', "\u{057C}" => 'r',
        "\u{054D}" => 'K', "\u{057D}" => 'k',
        "\u{054E}" => 'E', "\u{057E}" => 'e',
        "\u{054F}" => 'P', "\u{057F}" => 'p',
        "\u{0550}" => 'U', "\u{0580}" => 'u',
        "\u{0551}" => 'K', "\u{0581}" => 'k',
        "\u{0552}" => 'O', "\u{0582}" => 'o',
        "\u{0553}" => 'F', "\u{0583}" => 'f',
        "\u{0554}" => 'A', "\u{0584}" => 'a',
        "\u{0555}" => 'U', "\u{0585}" => 'u',
        "\u{0556}" => 'B', "\u{0586}" => 'b',
        "\u{0557}" => 'X', "\u{0587}" => 'y',
        "\u{0558}" => 'Q',
        "\u{0559}" => 'M',
        "\u{055A}" => 'H',
        "\u{055B}" => 'N',
        "\u{055C}" => 'S',
        "\u{055D}" => 'V',
        "\u{055E}" => 'T',
        "\u{055F}" => 'I',

                // === 4. 数学字母数字符号区 (U+1D400-U+1D7FF) ===
        //    由 normalizeMathAlphanumeric() 动态计算，覆盖约1000字符

        // === 5. 全角字符 (U+FF01-U+FF5E) ===
        //    由 normalizeFullwidth() 动态计算，94个全角→半角


        // === 4. 数学字母数字符号（动态生成，约1000字符） ===
        // 粗体 Bold
        // Bold (连续 52字符)
        // Bold 粗体 大写 (26)
        "\u{1D400}" => 'A', "\u{1D401}" => 'B', "\u{1D402}" => 'C', "\u{1D403}" => 'D', "\u{1D404}" => 'E', "\u{1D405}" => 'F',
        "\u{1D406}" => 'G', "\u{1D407}" => 'H', "\u{1D408}" => 'I', "\u{1D409}" => 'J', "\u{1D40A}" => 'K', "\u{1D40B}" => 'L',
        "\u{1D40C}" => 'M', "\u{1D40D}" => 'N', "\u{1D40E}" => 'O', "\u{1D40F}" => 'P', "\u{1D410}" => 'Q', "\u{1D411}" => 'R',
        "\u{1D412}" => 'S', "\u{1D413}" => 'T', "\u{1D414}" => 'U', "\u{1D415}" => 'V', "\u{1D416}" => 'W', "\u{1D417}" => 'X',
        "\u{1D418}" => 'Y', "\u{1D419}" => 'Z',
        // Bold 粗体 小写 (26)
        "\u{1D41A}" => 'a', "\u{1D41B}" => 'b', "\u{1D41C}" => 'c', "\u{1D41D}" => 'd', "\u{1D41E}" => 'e', "\u{1D41F}" => 'f',
        "\u{1D420}" => 'g', "\u{1D421}" => 'h', "\u{1D422}" => 'i', "\u{1D423}" => 'j', "\u{1D424}" => 'k', "\u{1D425}" => 'l',
        "\u{1D426}" => 'm', "\u{1D427}" => 'n', "\u{1D428}" => 'o', "\u{1D429}" => 'p', "\u{1D42A}" => 'q', "\u{1D42B}" => 'r',
        "\u{1D42C}" => 's', "\u{1D42D}" => 't', "\u{1D42E}" => 'u', "\u{1D42F}" => 'v', "\u{1D430}" => 'w', "\u{1D431}" => 'x',
        "\u{1D432}" => 'y', "\u{1D433}" => 'z',

        // Bold Italic 粗斜体 大写 (26)
        "\u{1D468}" => 'A', "\u{1D469}" => 'B', "\u{1D46A}" => 'C', "\u{1D46B}" => 'D', "\u{1D46C}" => 'E', "\u{1D46D}" => 'F',
        "\u{1D46E}" => 'G', "\u{1D46F}" => 'H', "\u{1D470}" => 'I', "\u{1D471}" => 'J', "\u{1D472}" => 'K', "\u{1D473}" => 'L',
        "\u{1D474}" => 'M', "\u{1D475}" => 'N', "\u{1D476}" => 'O', "\u{1D477}" => 'P', "\u{1D478}" => 'Q', "\u{1D479}" => 'R',
        "\u{1D47A}" => 'S', "\u{1D47B}" => 'T', "\u{1D47C}" => 'U', "\u{1D47D}" => 'V', "\u{1D47E}" => 'W', "\u{1D47F}" => 'X',
        "\u{1D480}" => 'Y', "\u{1D481}" => 'Z',
        // Bold Italic 粗斜体 小写 (26)
        "\u{1D482}" => 'a', "\u{1D483}" => 'b', "\u{1D484}" => 'c', "\u{1D485}" => 'd', "\u{1D486}" => 'e', "\u{1D487}" => 'f',
        "\u{1D488}" => 'g', "\u{1D489}" => 'h', "\u{1D48A}" => 'i', "\u{1D48B}" => 'j', "\u{1D48C}" => 'k', "\u{1D48D}" => 'l',
        "\u{1D48E}" => 'm', "\u{1D48F}" => 'n', "\u{1D490}" => 'o', "\u{1D491}" => 'p', "\u{1D492}" => 'q', "\u{1D493}" => 'r',
        "\u{1D494}" => 's', "\u{1D495}" => 't', "\u{1D496}" => 'u', "\u{1D497}" => 'v', "\u{1D498}" => 'w', "\u{1D499}" => 'x',
        "\u{1D49A}" => 'y', "\u{1D49B}" => 'z',

        // Sans-serif 无衬线 大写 (26)
        "\u{1D5A0}" => 'A', "\u{1D5A1}" => 'B', "\u{1D5A2}" => 'C', "\u{1D5A3}" => 'D', "\u{1D5A4}" => 'E', "\u{1D5A5}" => 'F',
        "\u{1D5A6}" => 'G', "\u{1D5A7}" => 'H', "\u{1D5A8}" => 'I', "\u{1D5A9}" => 'J', "\u{1D5AA}" => 'K', "\u{1D5AB}" => 'L',
        "\u{1D5AC}" => 'M', "\u{1D5AD}" => 'N', "\u{1D5AE}" => 'O', "\u{1D5AF}" => 'P', "\u{1D5B0}" => 'Q', "\u{1D5B1}" => 'R',
        "\u{1D5B2}" => 'S', "\u{1D5B3}" => 'T', "\u{1D5B4}" => 'U', "\u{1D5B5}" => 'V', "\u{1D5B6}" => 'W', "\u{1D5B7}" => 'X',
        "\u{1D5B8}" => 'Y', "\u{1D5B9}" => 'Z',
        // Sans-serif 无衬线 小写 (26)
        "\u{1D5BA}" => 'a', "\u{1D5BB}" => 'b', "\u{1D5BC}" => 'c', "\u{1D5BD}" => 'd', "\u{1D5BE}" => 'e', "\u{1D5BF}" => 'f',
        "\u{1D5C0}" => 'g', "\u{1D5C1}" => 'h', "\u{1D5C2}" => 'i', "\u{1D5C3}" => 'j', "\u{1D5C4}" => 'k', "\u{1D5C5}" => 'l',
        "\u{1D5C6}" => 'm', "\u{1D5C7}" => 'n', "\u{1D5C8}" => 'o', "\u{1D5C9}" => 'p', "\u{1D5CA}" => 'q', "\u{1D5CB}" => 'r',
        "\u{1D5CC}" => 's', "\u{1D5CD}" => 't', "\u{1D5CE}" => 'u', "\u{1D5CF}" => 'v', "\u{1D5D0}" => 'w', "\u{1D5D1}" => 'x',
        "\u{1D5D2}" => 'y', "\u{1D5D3}" => 'z',

        // Sans Bold 粗无衬线 大写 (26)
        "\u{1D5D4}" => 'A', "\u{1D5D5}" => 'B', "\u{1D5D6}" => 'C', "\u{1D5D7}" => 'D', "\u{1D5D8}" => 'E', "\u{1D5D9}" => 'F',
        "\u{1D5DA}" => 'G', "\u{1D5DB}" => 'H', "\u{1D5DC}" => 'I', "\u{1D5DD}" => 'J', "\u{1D5DE}" => 'K', "\u{1D5DF}" => 'L',
        "\u{1D5E0}" => 'M', "\u{1D5E1}" => 'N', "\u{1D5E2}" => 'O', "\u{1D5E3}" => 'P', "\u{1D5E4}" => 'Q', "\u{1D5E5}" => 'R',
        "\u{1D5E6}" => 'S', "\u{1D5E7}" => 'T', "\u{1D5E8}" => 'U', "\u{1D5E9}" => 'V', "\u{1D5EA}" => 'W', "\u{1D5EB}" => 'X',
        "\u{1D5EC}" => 'Y', "\u{1D5ED}" => 'Z',
        // Sans Bold 粗无衬线 小写 (26)
        "\u{1D5EE}" => 'a', "\u{1D5EF}" => 'b', "\u{1D5F0}" => 'c', "\u{1D5F1}" => 'd', "\u{1D5F2}" => 'e', "\u{1D5F3}" => 'f',
        "\u{1D5F4}" => 'g', "\u{1D5F5}" => 'h', "\u{1D5F6}" => 'i', "\u{1D5F7}" => 'j', "\u{1D5F8}" => 'k', "\u{1D5F9}" => 'l',
        "\u{1D5FA}" => 'm', "\u{1D5FB}" => 'n', "\u{1D5FC}" => 'o', "\u{1D5FD}" => 'p', "\u{1D5FE}" => 'q', "\u{1D5FF}" => 'r',
        "\u{1D600}" => 's', "\u{1D601}" => 't', "\u{1D602}" => 'u', "\u{1D603}" => 'v', "\u{1D604}" => 'w', "\u{1D605}" => 'x',
        "\u{1D606}" => 'y', "\u{1D607}" => 'z',

        // Sans Bold Italic 粗斜无衬线 大写 (26)
        "\u{1D63C}" => 'A', "\u{1D63D}" => 'B', "\u{1D63E}" => 'C', "\u{1D63F}" => 'D', "\u{1D640}" => 'E', "\u{1D641}" => 'F',
        "\u{1D642}" => 'G', "\u{1D643}" => 'H', "\u{1D644}" => 'I', "\u{1D645}" => 'J', "\u{1D646}" => 'K', "\u{1D647}" => 'L',
        "\u{1D648}" => 'M', "\u{1D649}" => 'N', "\u{1D64A}" => 'O', "\u{1D64B}" => 'P', "\u{1D64C}" => 'Q', "\u{1D64D}" => 'R',
        "\u{1D64E}" => 'S', "\u{1D64F}" => 'T', "\u{1D650}" => 'U', "\u{1D651}" => 'V', "\u{1D652}" => 'W', "\u{1D653}" => 'X',
        "\u{1D654}" => 'Y', "\u{1D655}" => 'Z',
        // Sans Bold Italic 粗斜无衬线 小写 (26)
        "\u{1D656}" => 'a', "\u{1D657}" => 'b', "\u{1D658}" => 'c', "\u{1D659}" => 'd', "\u{1D65A}" => 'e', "\u{1D65B}" => 'f',
        "\u{1D65C}" => 'g', "\u{1D65D}" => 'h', "\u{1D65E}" => 'i', "\u{1D65F}" => 'j', "\u{1D660}" => 'k', "\u{1D661}" => 'l',
        "\u{1D662}" => 'm', "\u{1D663}" => 'n', "\u{1D664}" => 'o', "\u{1D665}" => 'p', "\u{1D666}" => 'q', "\u{1D667}" => 'r',
        "\u{1D668}" => 's', "\u{1D669}" => 't', "\u{1D66A}" => 'u', "\u{1D66B}" => 'v', "\u{1D66C}" => 'w', "\u{1D66D}" => 'x',
        "\u{1D66E}" => 'y', "\u{1D66F}" => 'z',

        // Monospace 等宽 大写 (26)
        "\u{1D670}" => 'A', "\u{1D671}" => 'B', "\u{1D672}" => 'C', "\u{1D673}" => 'D', "\u{1D674}" => 'E', "\u{1D675}" => 'F',
        "\u{1D676}" => 'G', "\u{1D677}" => 'H', "\u{1D678}" => 'I', "\u{1D679}" => 'J', "\u{1D67A}" => 'K', "\u{1D67B}" => 'L',
        "\u{1D67C}" => 'M', "\u{1D67D}" => 'N', "\u{1D67E}" => 'O', "\u{1D67F}" => 'P', "\u{1D680}" => 'Q', "\u{1D681}" => 'R',
        "\u{1D682}" => 'S', "\u{1D683}" => 'T', "\u{1D684}" => 'U', "\u{1D685}" => 'V', "\u{1D686}" => 'W', "\u{1D687}" => 'X',
        "\u{1D688}" => 'Y', "\u{1D689}" => 'Z',
        // Monospace 等宽 小写 (26)
        "\u{1D68A}" => 'a', "\u{1D68B}" => 'b', "\u{1D68C}" => 'c', "\u{1D68D}" => 'd', "\u{1D68E}" => 'e', "\u{1D68F}" => 'f',
        "\u{1D690}" => 'g', "\u{1D691}" => 'h', "\u{1D692}" => 'i', "\u{1D693}" => 'j', "\u{1D694}" => 'k', "\u{1D695}" => 'l',
        "\u{1D696}" => 'm', "\u{1D697}" => 'n', "\u{1D698}" => 'o', "\u{1D699}" => 'p', "\u{1D69A}" => 'q', "\u{1D69B}" => 'r',
        "\u{1D69C}" => 's', "\u{1D69D}" => 't', "\u{1D69E}" => 'u', "\u{1D69F}" => 'v', "\u{1D6A0}" => 'w', "\u{1D6A1}" => 'x',
        "\u{1D6A2}" => 'y', "\u{1D6A3}" => 'z',

        // Italic 斜体 大写 (26)
        "\u{1D434}" => 'A', "\u{1D435}" => 'B', "\u{1D436}" => 'C', "\u{1D437}" => 'D', "\u{1D438}" => 'E', "\u{1D439}" => 'F',
        "\u{1D43A}" => 'G', "\u{1D43B}" => 'H', "\u{1D43C}" => 'I', "\u{1D43D}" => 'J', "\u{1D43E}" => 'K', "\u{1D43F}" => 'L',
        "\u{1D440}" => 'M', "\u{1D441}" => 'N', "\u{1D442}" => 'O', "\u{1D443}" => 'P', "\u{1D444}" => 'Q', "\u{1D445}" => 'R',
        "\u{1D446}" => 'S', "\u{1D447}" => 'T', "\u{1D448}" => 'U', "\u{1D449}" => 'V', "\u{1D44A}" => 'W', "\u{1D44B}" => 'X',
        "\u{1D44C}" => 'Y', "\u{1D44D}" => 'Z',
        // Italic 斜体 小写 (h空缺, 25)
        "\u{1D44E}" => 'a', "\u{1D44F}" => 'b', "\u{1D450}" => 'c', "\u{1D451}" => 'd', "\u{1D452}" => 'e', "\u{1D453}" => 'f',
        "\u{1D454}" => 'g', "\u{1D456}" => 'i', "\u{1D457}" => 'j', "\u{1D458}" => 'k', "\u{1D459}" => 'l', "\u{1D45A}" => 'm',
        "\u{1D45B}" => 'n', "\u{1D45C}" => 'o', "\u{1D45D}" => 'p', "\u{1D45E}" => 'q', "\u{1D45F}" => 'r', "\u{1D460}" => 's',
        "\u{1D461}" => 't', "\u{1D462}" => 'u', "\u{1D463}" => 'v', "\u{1D464}" => 'w', "\u{1D465}" => 'x', "\u{1D466}" => 'y',
        "\u{1D467}" => 'z',

        // 数学数字 (5种×10 = 50)
        "\u{1D7CE}" => '0', "\u{1D7CF}" => '1', "\u{1D7D0}" => '2', "\u{1D7D1}" => '3', "\u{1D7D2}" => '4', "\u{1D7D3}" => '5', "\u{1D7D4}" => '6', "\u{1D7D5}" => '7', "\u{1D7D6}" => '8', "\u{1D7D7}" => '9',
        "\u{1D7D8}" => '0', "\u{1D7D9}" => '1', "\u{1D7DA}" => '2', "\u{1D7DB}" => '3', "\u{1D7DC}" => '4', "\u{1D7DD}" => '5', "\u{1D7DE}" => '6', "\u{1D7DF}" => '7', "\u{1D7E0}" => '8', "\u{1D7E1}" => '9',
        "\u{1D7E2}" => '0', "\u{1D7E3}" => '1', "\u{1D7E4}" => '2', "\u{1D7E5}" => '3', "\u{1D7E6}" => '4', "\u{1D7E7}" => '5', "\u{1D7E8}" => '6', "\u{1D7E9}" => '7', "\u{1D7EA}" => '8', "\u{1D7EB}" => '9',
        "\u{1D7EC}" => '0', "\u{1D7ED}" => '1', "\u{1D7EE}" => '2', "\u{1D7EF}" => '3', "\u{1D7F0}" => '4', "\u{1D7F1}" => '5', "\u{1D7F2}" => '6', "\u{1D7F3}" => '7', "\u{1D7F4}" => '8', "\u{1D7F5}" => '9',
        "\u{1D7F6}" => '0', "\u{1D7F7}" => '1', "\u{1D7F8}" => '2', "\u{1D7F9}" => '3', "\u{1D7FA}" => '4', "\u{1D7FB}" => '5', "\u{1D7FC}" => '6', "\u{1D7FD}" => '7', "\u{1D7FE}" => '8', "\u{1D7FF}" => '9',

        // 全角字符 → 半角 (94)
        "\u{FF01}" => '!', "\u{FF02}" => '"', "\u{FF03}" => '#', "\u{FF04}" => '$', "\u{FF05}" => '%', "\u{FF06}" => '&', "\u{FF07}" => '\'', "\u{FF08}" => '(',
        "\u{FF09}" => ')', "\u{FF0A}" => '*', "\u{FF0B}" => '+', "\u{FF0C}" => ',', "\u{FF0D}" => '-', "\u{FF0E}" => '.', "\u{FF0F}" => '/', "\u{FF10}" => '0',
        "\u{FF11}" => '1', "\u{FF12}" => '2', "\u{FF13}" => '3', "\u{FF14}" => '4', "\u{FF15}" => '5', "\u{FF16}" => '6', "\u{FF17}" => '7', "\u{FF18}" => '8',
        "\u{FF19}" => '9', "\u{FF1A}" => ':', "\u{FF1B}" => ';', "\u{FF1C}" => '<', "\u{FF1D}" => '=', "\u{FF1E}" => '>', "\u{FF1F}" => '?', "\u{FF20}" => '@',
        "\u{FF21}" => 'A', "\u{FF22}" => 'B', "\u{FF23}" => 'C', "\u{FF24}" => 'D', "\u{FF25}" => 'E', "\u{FF26}" => 'F', "\u{FF27}" => 'G', "\u{FF28}" => 'H',
        "\u{FF29}" => 'I', "\u{FF2A}" => 'J', "\u{FF2B}" => 'K', "\u{FF2C}" => 'L', "\u{FF2D}" => 'M', "\u{FF2E}" => 'N', "\u{FF2F}" => 'O', "\u{FF30}" => 'P',
        "\u{FF31}" => 'Q', "\u{FF32}" => 'R', "\u{FF33}" => 'S', "\u{FF34}" => 'T', "\u{FF35}" => 'U', "\u{FF36}" => 'V', "\u{FF37}" => 'W', "\u{FF38}" => 'X',
        "\u{FF39}" => 'Y', "\u{FF3A}" => 'Z', "\u{FF3B}" => '[', "\u{FF3C}" => '\\', "\u{FF3D}" => ']', "\u{FF3E}" => '^', "\u{FF3F}" => '_', "\u{FF40}" => '`',
        "\u{FF41}" => 'a', "\u{FF42}" => 'b', "\u{FF43}" => 'c', "\u{FF44}" => 'd', "\u{FF45}" => 'e', "\u{FF46}" => 'f', "\u{FF47}" => 'g', "\u{FF48}" => 'h',
        "\u{FF49}" => 'i', "\u{FF4A}" => 'j', "\u{FF4B}" => 'k', "\u{FF4C}" => 'l', "\u{FF4D}" => 'm', "\u{FF4E}" => 'n', "\u{FF4F}" => 'o', "\u{FF50}" => 'p',
        "\u{FF51}" => 'q', "\u{FF52}" => 'r', "\u{FF53}" => 's', "\u{FF54}" => 't', "\u{FF55}" => 'u', "\u{FF56}" => 'v', "\u{FF57}" => 'w', "\u{FF58}" => 'x',
        "\u{FF59}" => 'y', "\u{FF5A}" => 'z', "\u{FF5B}" => '{', "\u{FF5C}" => '|', "\u{FF5D}" => '}', "\u{FF5E}" => '~',


    ];

    /**
     * 对抗样本检测分析入口。
     *
     * @param string $text              归一化后的文本
     * @param string $rawText           原始未归一化文本
     * @param array  $normalizerContext 归一化引擎上下文
     * @param array  $multiVectorResult 多向量融合结果
     * @return array{score:int, threats:array, threat_names:array, patterns:array, decoded:string, decode_depth:int, decode_path:array, is_adversarial:bool, risk_level:string, recommendation:string}
     */
    public static function analyze(
        string $text,
        string $rawText = '',
        array $normalizerContext = [],
        array $multiVectorResult = []
    ): array {
        $inputForDecode = $rawText !== '' ? $rawText : $text;

        // A. 多层编码递归还原
        $decodeResult = self::recursiveDecode($inputForDecode, 0);
        // B. 混淆模式识别
        $obfResult = self::detectObfuscation($inputForDecode);
        // C. 对抗样本检测
        $advResult = self::detectAdversarialPayload($inputForDecode);
        // D. 编码链分析
        $chainResult = self::analyzeEncodingChain($inputForDecode, $decodeResult);
        // E. 还原前后对比
        $compareBefore = $text !== '' ? $text : $inputForDecode;
        $compareResult = self::comparePrePostDecode($compareBefore, $decodeResult['decoded']);

        $features = [
            'decode_depth'        => $decodeResult['depth'],
            'decode_path'         => $decodeResult['path'],
            'obfuscation_count'   => count($obfResult['techniques']),
            'adversarial_count'   => count($advResult['features']),
            'chain_anomaly'       => $chainResult['anomaly'],
            'decoded_has_payload' => $compareResult['has_payload'],
        ];

        // F. 混淆复杂度评分
        $score = self::scoreObfuscationComplexity($features);

        // 组装 threats
        $threats = [];
        if ($decodeResult['depth'] >= 2) {
            $threats[] = ['type' => 'recursive_encoding', 'name' => '多层嵌套编码还原',
                'score' => $decodeResult['depth'] * 10,
                'matched' => ['depth:' . $decodeResult['depth'], 'path:' . implode('->', $decodeResult['path'])]];
        }
        foreach ($obfResult['techniques'] as $tech) {
            $threats[] = ['type' => 'obfuscation', 'name' => '混淆模式: ' . $tech, 'score' => 8, 'matched' => [$tech]];
        }
        foreach ($advResult['features'] as $feat) {
            $threats[] = ['type' => 'adversarial', 'name' => '对抗样本特征: ' . $feat, 'score' => 15, 'matched' => [$feat]];
        }
        if (!empty($chainResult['anomaly'])) {
            $threats[] = ['type' => 'encoding_chain', 'name' => '编码链异常: ' . implode(',', $chainResult['types']),
                'score' => $chainResult['score'], 'matched' => $chainResult['types']];
        }
        if ($compareResult['has_payload']) {
            $threats[] = ['type' => 'decoded_payload', 'name' => '还原后检出攻击 payload',
                'score' => 30, 'matched' => $compareResult['payload_types']];
        }

        $patterns = array_merge($obfResult['techniques'], $advResult['features'], $chainResult['types'], $compareResult['payload_types']);

        return [
            'score'          => $score,
            'threats'        => $threats,
            'threat_names'   => array_column($threats, 'name'),
            'patterns'       => array_values(array_unique($patterns)),
            'decoded'        => $decodeResult['decoded'],
            'decode_depth'   => $decodeResult['depth'],
            'decode_path'    => $decodeResult['path'],
            'is_adversarial' => $score >= 30,
            'risk_level'     => $score >= 60 ? 'high' : ($score >= 30 ? 'medium' : 'low'),
            'recommendation' => self::generateRecommendation($threats, $score),
        ];
    }

    // === A. 多层编码递归还原 ===

    /**
     * 逐层尝试 URL / HTML / Base64 / Hex escape / Octal escape / 0x hex literal
     * 解码，直至稳定或达到最大深度（5）。返回还原后文本 + 还原路径 + 编码层数。
     */
    private static function recursiveDecode(string $text, int $depth = 0): array {
        $path = [];
        $current = $text;
        $totalDepth = 0;
        while ($totalDepth < self::MAX_DECODE_DEPTH) {
            $step = self::applyDecodeLayer($current);
            if (!$step['changed']) break;
            $current = $step['text'];
            $path = array_merge($path, $step['applied']);
            $totalDepth++;
        }
        return ['decoded' => $current, 'depth' => $totalDepth, 'path' => $path];
    }

    /**
     * 单层解码尝试：依次应用 URL / HTML / Base64 / \xHH / \NNN / 0xNN 解码。
     * 同一层可应用多种解码，统一记录到 applied。
     */
    private static function applyDecodeLayer(string $text): array {
        $applied = [];
        $changed = false;

        // 1. URL 编码：rawurldecode 还原 %XX
        if (preg_match('#%[0-9a-fA-F]{2}#', $text)) {
            $decoded = rawurldecode($text);
            if ($decoded !== $text && $decoded !== '' && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'urldecode'; $changed = true;
            }
        }
        // 2. HTML 数字实体解码（&#xXX; / &#DDD;）
        if (preg_match('/&#[xX]?[0-9a-fA-F]+;/', $text)) {
            $before = $text;
            $text = self::decodeHtmlNumericEntities($text);
            if ($text !== $before) { $applied[] = 'html_numeric_entity'; $changed = true; }
        }
        // 3. Base64：仅当文本整体是合法 Base64 时尝试
        $b64 = self::tryBase64Decode($text);
        if ($b64 !== null) { $text = $b64; $applied[] = 'base64'; $changed = true; }
        // 4. \xHH 十六进制转义
        if (preg_match('/\\\\x[0-9a-fA-F]{2}/', $text)) {
            $decoded = preg_replace_callback('/\\\\x([0-9a-fA-F]{2})/', function ($m) {
                return chr(hexdec($m[1]));
            }, $text);
            if ($decoded !== null && $decoded !== $text) { $text = $decoded; $applied[] = 'hex_escape'; $changed = true; }
        }
        // 5. \NNN 八进制转义（仅 0-3 起始，避免误伤普通文本）
        if (preg_match('/\\\\[0-3][0-7]{2}/', $text)) {
            $decoded = preg_replace_callback('/\\\\([0-3][0-7]{2})/', function ($m) {
                return chr(octdec($m[1]));
            }, $text);
            if ($decoded !== null && $decoded !== $text) { $text = $decoded; $applied[] = 'octal_escape'; $changed = true; }
        }
        // 6. 0xNN 十六进制字面量（SQL/代码上下文，要求至少 4 位以减少误判）
        if (preg_match('/\b0x[0-9a-fA-F]{4,}\b/', $text)) {
            $decoded = preg_replace_callback('/\b0x([0-9a-fA-F]{4,})\b/', function ($m) {
                $hex = $m[1];
                if (strlen($hex) % 2 !== 0) return $m[0];
                $str = '';
                for ($i = 0; $i < strlen($hex); $i += 2) {
                    $str .= chr(hexdec(substr($hex, $i, 2)));
                }
                return $str;
            }, $text);
            if ($decoded !== null && $decoded !== $text) { $text = $decoded; $applied[] = 'hex_literal'; $changed = true; }
        }
        // 7. Unicode %uXXXX 编码（IIS经典）
        if (preg_match('/%u[0-9a-fA-F]{4}/', $text)) {
            $decoded = preg_replace_callback('/%u([0-9a-fA-F]{4})/', function ($m) {
                $cp = hexdec($m[1]);
                if ($cp < 0x80) return chr($cp);
                if ($cp < 0x800) return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
                return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
            }, $text);
            if ($decoded !== null && $decoded !== $text && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'unicode_percent_u'; $changed = true;
            }
        }
        // 8. UTF-8超集编码（2字节表示ASCII字符，路径遍历常用绕过）
        //    注意：检查已经URL解码后的二进制字节（[\xC0-\xE0][\x80-\xBF]模式）
        if (preg_match('/[\xC0-\xE0][\x80-\xBF]/', $text)) {
            $before = $text;
            $decoded = self::decodeOverlongUtf8($text);
            if ($decoded !== $before && $decoded !== '' && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'utf8_overlong'; $changed = true;
            }
        }
        // 9. 零宽字符移除
        $zeroWidthPattern = '/[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{2060}\x{200E}\x{200F}\x{202A}\x{202B}\x{202C}\x{202D}\x{202E}\x{2061}\x{2062}\x{2063}\x{2064}\x{2065}\x{2066}\x{2067}\x{2068}\x{2069}\x{180B}\x{180C}\x{180D}\x{180E}\x{FE00}\x{FE01}\x{FE02}\x{FE03}\x{FE04}\x{FE05}\x{FE06}\x{FE07}\x{FE08}\x{FE09}\x{FE0A}\x{FE0B}\x{FE0C}\x{FE0D}\x{FE0E}\x{FE0F}]/u';
        if (preg_match($zeroWidthPattern, $text)) {
            $before = $text;
            $text = preg_replace($zeroWidthPattern, '', $text);
            if ($text !== $before) { $applied[] = 'zero_width_remove'; $changed = true; }
        }
        // 10. 全角→半角转换（基础字符归一化，94字符）
        if (preg_match('/[\x{FF01}-\x{FF5E}]/u', $text)) {
            $before = $text;
            $text = preg_replace_callback('/[\x{FF01}-\x{FF5E}]/u', function ($m) {
                $cp = mb_ord($m[0], 'UTF-8');
                return chr($cp - 0xFEE0);
            }, $text);
            if ($text !== $before) { $applied[] = 'fullwidth_normalize'; $changed = true; }
        }
        // 11. 同形字还原（647字符映射，含数学字母/西里尔/希腊/亚美尼亚）
        $before = $text;
        $text = strtr($text, self::$homoglyph_map);
        if ($text !== $before) { $applied[] = 'homoglyph_normalize'; $changed = true; }
        // 12. Unicode转义解码（\uXXXX格式）
        if (preg_match('/\\\\u[0-9a-fA-F]{4}/', $text)) {
            $before = $text;
            $decoded = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($m) {
                return self::cpToUtf8(hexdec($m[1]));
            }, $text);
            if ($decoded !== null && $decoded !== $text && self::isPrintableEnough($decoded)) {
                $text = $decoded; $applied[] = 'unicode_escape'; $changed = true;
            }
        }
        // 13. HTML特殊字符名（扩展命名实体）
        if (preg_match('/&[a-zA-Z]+;/', $text)) {
            $before = $text;
            $text = self::decodeExtendedHtmlEntities($text);
            if ($text !== $before) { $applied[] = 'html_named_entity'; $changed = true; }
        }
        // 14. 大小写归一化（仅常见攻击关键词）
        $attackKeywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'from', 'where', 'or', 'and', 'script', 'javascript', 'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru', 'load_file', 'outfile', 'dumpfile', 'xp_cmdshell', 'extractvalue', 'updatexml', 'sleep', 'benchmark', 'information_schema', 'sysobjects'];
        $before = $text;
        foreach ($attackKeywords as $kw) {
            $text = preg_replace('/\b' . preg_quote($kw, '/') . '\b/i', $kw, $text);
        }
        if ($text !== $before) { $applied[] = 'case_normalize_keywords'; $changed = true; }
        return ['text' => $text, 'applied' => $applied, 'changed' => $changed];
    }

    /**
     * HTML 数字实体解码：&#xNN; / &#DDD;（不含命名实体）
     */
    private static function decodeHtmlNumericEntities(string $text): string {
        $text = preg_replace_callback('/&#[xX]([0-9a-fA-F]+);/', function ($m) {
            return self::cpToUtf8(hexdec($m[1]));
        }, $text);
        $text = preg_replace_callback('/&#(\d+);/', function ($m) {
            return self::cpToUtf8((int)$m[1]);
        }, $text);
        return $text;
    }

    /**
     * 自定义 HTML 实体解码：处理 &#xNN; &#NN; 命名实体（含 &amp; 双重编码场景）。
     * 注：&amp; 必须最先解，以便 &amp;#x27; 在 strtr 后变成 &#x27; 再被 hex 解码。
     */
    private static function decodeHtmlEntities(string $text): string {
        $named = ['&amp;' => '&', '&apos;' => "'", '&quot;' => '"', '&lt;' => '<', '&gt;' => '>'];
        $text = strtr($text, $named);
        $text = preg_replace_callback('/&#[xX]([0-9a-fA-F]+);/', function ($m) {
            return self::cpToUtf8(hexdec($m[1]));
        }, $text);
        $text = preg_replace_callback('/&#(\d+);/', function ($m) {
            return self::cpToUtf8((int)$m[1]);
        }, $text);
        return $text;
    }

    /**
     * 扩展HTML命名实体解码：除了基础的5个之外，再处理常见的命名实体。
     */
    private static function decodeExtendedHtmlEntities(string $text): string {
        $extendedNamed = [
            '&amp;' => '&', '&apos;' => "'", '&quot;' => '"', '&lt;' => '<', '&gt;' => '>',
            '&nbsp;' => ' ', '&iexcl;' => '¡', '&cent;' => '¢', '&pound;' => '£',
            '&curren;' => '¤', '&yen;' => '¥', '&brvbar;' => '¦', '&sect;' => '§',
            '&uml;' => '¨', '&copy;' => '©', '&ordf;' => 'ª', '&laquo;' => '«',
            '&not;' => '¬', '&shy;' => '', '&reg;' => '®', '&macr;' => '¯',
            '&deg;' => '°', '&plusmn;' => '±', '&sup2;' => '²', '&sup3;' => '³',
            '&acute;' => '´', '&micro;' => 'µ', '&para;' => '¶', '&middot;' => '·',
            '&cedil;' => '¸', '&sup1;' => '¹', '&ordm;' => 'º', '&raquo;' => '»',
            '&frac14;' => '¼', '&frac12;' => '½', '&frac34;' => '¾', '&iquest;' => '¿',
            '&times;' => '×', '&divide;' => '÷',
            '&Agrave;' => 'À', '&Aacute;' => 'Á', '&Acirc;' => 'Â', '&Atilde;' => 'Ã',
            '&Auml;' => 'Ä', '&Aring;' => 'Å', '&AElig;' => 'Æ', '&Ccedil;' => 'Ç',
            '&Egrave;' => 'È', '&Eacute;' => 'É', '&Ecirc;' => 'Ê', '&Euml;' => 'Ë',
            '&Igrave;' => 'Ì', '&Iacute;' => 'Í', '&Icirc;' => 'Î', '&Iuml;' => 'Ï',
            '&ETH;' => 'Ð', '&Ntilde;' => 'Ñ', '&Ograve;' => 'Ò', '&Oacute;' => 'Ó',
            '&Ocirc;' => 'Ô', '&Otilde;' => 'Õ', '&Ouml;' => 'Ö', '&Oslash;' => 'Ø',
            '&Ugrave;' => 'Ù', '&Uacute;' => 'Ú', '&Ucirc;' => 'Û', '&Uuml;' => 'Ü',
            '&Yacute;' => 'Ý', '&THORN;' => 'Þ', '&szlig;' => 'ß',
            '&agrave;' => 'à', '&aacute;' => 'á', '&acirc;' => 'â', '&atilde;' => 'ã',
            '&auml;' => 'ä', '&aring;' => 'å', '&aelig;' => 'æ', '&ccedil;' => 'ç',
            '&egrave;' => 'è', '&eacute;' => 'é', '&ecirc;' => 'ê', '&euml;' => 'ë',
            '&igrave;' => 'ì', '&iacute;' => 'í', '&icirc;' => 'î', '&iuml;' => 'ï',
            '&eth;' => 'ð', '&ntilde;' => 'ñ', '&ograve;' => 'ò', '&oacute;' => 'ó',
            '&ocirc;' => 'ô', '&otilde;' => 'õ', '&ouml;' => 'ö', '&oslash;' => 'ø',
            '&ugrave;' => 'ù', '&uacute;' => 'ú', '&ucirc;' => 'û', '&uuml;' => 'ü',
            '&yacute;' => 'ý', '&thorn;' => 'þ', '&yuml;' => 'ÿ',
            '&OElig;' => 'Œ', '&oelig;' => 'œ', '&Scaron;' => 'Š', '&scaron;' => 'š',
            '&Yuml;' => 'Ÿ', '&fnof;' => 'ƒ',
            '&Alpha;' => 'Α', '&Beta;' => 'Β', '&Gamma;' => 'Γ', '&Delta;' => 'Δ',
            '&Epsilon;' => 'Ε', '&Zeta;' => 'Ζ', '&Eta;' => 'Η', '&Theta;' => 'Θ',
            '&Iota;' => 'Ι', '&Kappa;' => 'Κ', '&Lambda;' => 'Λ', '&Mu;' => 'Μ',
            '&Nu;' => 'Ν', '&Xi;' => 'Ξ', '&Omicron;' => 'Ο', '&Pi;' => 'Π',
            '&Rho;' => 'Ρ', '&Sigma;' => 'Σ', '&Tau;' => 'Τ', '&Upsilon;' => 'Υ',
            '&Phi;' => 'Φ', '&Chi;' => 'Χ', '&Psi;' => 'Ψ', '&Omega;' => 'Ω',
            '&alpha;' => 'α', '&beta;' => 'β', '&gamma;' => 'γ', '&delta;' => 'δ',
            '&epsilon;' => 'ε', '&zeta;' => 'ζ', '&eta;' => 'η', '&theta;' => 'θ',
            '&iota;' => 'ι', '&kappa;' => 'κ', '&lambda;' => 'λ', '&mu;' => 'μ',
            '&nu;' => 'ν', '&xi;' => 'ξ', '&omicron;' => 'ο', '&pi;' => 'π',
            '&rho;' => 'ρ', '&sigmaf;' => 'ς', '&sigma;' => 'σ', '&tau;' => 'τ',
            '&upsilon;' => 'υ', '&phi;' => 'φ', '&chi;' => 'χ', '&psi;' => 'ψ',
            '&omega;' => 'ω', '&thetasym;' => 'ϑ', '&upsih;' => 'ϒ', '&piv;' => 'ϖ',
            '&bull;' => '•', '&hellip;' => '…', '&prime;' => '′', '&Prime;' => '″',
            '&oline;' => '‾', '&frasl;' => '⁄',
            '&weierp;' => '℘', '&image;' => 'ℑ', '&real;' => 'ℜ', '&trade;' => '™',
            '&alefsym;' => 'ℵ',
            '&larr;' => '←', '&uarr;' => '↑', '&rarr;' => '→', '&darr;' => '↓',
            '&harr;' => '↔', '&crarr;' => '↵', '&lArr;' => '⇐', '&uArr;' => '⇑',
            '&rArr;' => '⇒', '&dArr;' => '⇓', '&hArr;' => '⇔',
            '&forall;' => '∀', '&part;' => '∂', '&exist;' => '∃', '&empty;' => '∅',
            '&nabla;' => '∇', '&isin;' => '∈', '&notin;' => '∉', '&ni;' => '∋',
            '&prod;' => '∏', '&sum;' => '∑', '&minus;' => '−', '&lowast;' => '∗',
            '&radic;' => '√', '&prop;' => '∝', '&infin;' => '∞', '&ang;' => '∠',
            '&and;' => '∧', '&or;' => '∨', '&cap;' => '∩', '&cup;' => '∪',
            '&int;' => '∫', '&there4;' => '∴', '&sim;' => '∼', '&cong;' => '≅',
            '&asymp;' => '≈', '&ne;' => '≠', '&equiv;' => '≡', '&le;' => '≤',
            '&ge;' => '≥', '&sub;' => '⊂', '&sup;' => '⊃', '&nsub;' => '⊄',
            '&sube;' => '⊆', '&supe;' => '⊇', '&oplus;' => '⊕', '&otimes;' => '⊗',
            '&perp;' => '⊥', '&sdot;' => '⋅',
            '&lceil;' => '⌈', '&rceil;' => '⌉', '&lfloor;' => '⌊', '&rfloor;' => '⌋',
            '&lang;' => '〈', '&rang;' => '〉', '&loz;' => '◊',
            '&spades;' => '♠', '&clubs;' => '♣', '&hearts;' => '♥', '&diams;' => '♦',
        ];
        return strtr($text, $extendedNamed);
    }

    /** 码点转 UTF-8（PHP 7.0 兼容，不依赖 mbstring） */
    private static function cpToUtf8(int $cp): string {
        if ($cp < 0x80) return chr($cp);
        if ($cp < 0x800) return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x110000) {
            return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F))
                . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return '';
    }

    /** 解码UTF-8超集编码（2字节序列表示的ASCII字符，路径遍历常用绕过） */
    private static function decodeOverlongUtf8(string $text): string {
        $result = '';
        $len = strlen($text);
        $i = 0;
        while ($i < $len) {
            $byte = ord($text[$i]);
            if ($byte < 0x80) {
                $result .= chr($byte);
                $i++;
            } elseif (($byte & 0xE0) === 0xC0 && $i + 1 < $len) {
                $byte2 = ord($text[$i + 1]);
                if (($byte2 & 0xC0) === 0x80) {
                    $cp = (($byte & 0x1F) << 6) | ($byte2 & 0x3F);
                    if ($cp < 0x80) {
                        $result .= chr($cp);
                    } else {
                        $result .= chr($byte) . chr($byte2);
                    }
                    $i += 2;
                } else {
                    $result .= chr($byte);
                    $i++;
                }
            } elseif (($byte & 0xF0) === 0xE0 && $i + 2 < $len) {
                $byte2 = ord($text[$i + 1]);
                $byte3 = ord($text[$i + 2]);
                if (($byte2 & 0xC0) === 0x80 && ($byte3 & 0xC0) === 0x80) {
                    $cp = (($byte & 0x0F) << 12) | (($byte2 & 0x3F) << 6) | ($byte3 & 0x3F);
                    if ($cp < 0x800) {
                        if ($cp < 0x80) {
                            $result .= chr($cp);
                        } else {
                            $result .= chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
                        }
                    } else {
                        $result .= chr($byte) . chr($byte2) . chr($byte3);
                    }
                    $i += 3;
                } else {
                    $result .= chr($byte);
                    $i++;
                }
            } else {
                $result .= chr($byte);
                $i++;
            }
        }
        return $result;
    }

    /** 尝试 Base64 解码：仅当整体文本是合法 Base64 且解码后可读 */
    private static function tryBase64Decode(string $text): ?string {
        $trimmed = trim($text);
        $len = strlen($trimmed);
        if ($len < 8 || $len % 4 !== 0) return null;
        if (!preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $trimmed)) return null;
        $decoded = base64_decode($trimmed, true);
        if ($decoded === false || $decoded === '' || strlen($decoded) < 3) return null;
        if (!self::isPrintableEnough($decoded)) return null;
        return $decoded;
    }

    /** 判断文本是否"足够可打印"——避免对乱码循环解码 */
    private static function isPrintableEnough(string $text): bool {
        $len = strlen($text);
        if ($len === 0) return false;
        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $o = ord($text[$i]);
            if ($o === 9 || $o === 10 || $o === 13 || ($o >= 32 && $o <= 126) || $o >= 0x80) $printable++;
        }
        return ($printable / $len) >= 0.6;
    }

    // === B. 混淆模式识别（结构模式，非关键词匹配） ===

    private static function detectObfuscation(string $text): array {
        $techniques = [];
        // 1. 注释分隔：UNION/**/SELECT
        if (preg_match('/[a-zA-Z]+\s*\/\*[\s\S]{0,40}?\*\/\s*[a-zA-Z]+/', $text)) $techniques[] = 'comment_separator';
        // 2. 关键词拆分：UN/**/ION
        if (preg_match('/\bUN\s*\/\*[\s\S]{0,20}?\*\/\s*ION\b/i', $text)
            || preg_match('/\bSEL\s*\/\*[\s\S]{0,20}?\*\/\s*ECT\b/i', $text)
            || preg_match('/\bINS\s*\/\*[\s\S]{0,20}?\*\/\s*ERT\b/i', $text)
            || preg_match('/\bUPD\s*\/\*[\s\S]{0,20}?\*\/\s*ATE\b/i', $text)) {
            $techniques[] = 'keyword_split';
        }
        // 3. MySQL 版本注释：/*!50000UNION*/
        if (preg_match('/\/\*!\d{4,}\s*[\s\S]*?\*\//i', $text)) $techniques[] = 'versioned_comment';
        // 4. 大小写混合：UnIoN sElEcT
        if (self::hasMixedCaseKeyword($text)) $techniques[] = 'case_mixing';
        // 5. 字符串拼接：'a'+'d'+'m'+'i'+'n'
        if (preg_match('/[\'"][a-zA-Z0-9_]{1,8}[\'"]\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"]\s*\+\s*[\'"][a-zA-Z0-9_]{1,8}[\'"]/', $text)) {
            $techniques[] = 'string_concat';
        }
        // 6. CHAR() 函数构造字符串
        if (preg_match('/\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*){2,}\s*\)/i', $text)) $techniques[] = 'char_function';
        // 7. 空白字符替换：垂直制表符/换页符代替空格出现在关键词周围
        if (preg_match('/[\x0b\x0c][\s\S]{0,5}?(?:union|select|from|where|or|and|insert|update|delete|drop)\b/i', $text)
            || preg_match('/\b(?:union|select|from|where|or|and|insert|update|delete|drop)[\x0b\x0c]/i', $text)) {
            $techniques[] = 'whitespace_substitution';
        }
        // 8. SQL 注释截断：'-- 或 '#
        if (preg_match('/[\'"`]\s*--\s/', $text) || preg_match('/[\'"`]\s*#/', $text)) $techniques[] = 'comment_truncate';
        // 9. URL 双重编码
        if (preg_match('#%25[0-9a-fA-F]{2}#', $text)) $techniques[] = 'double_url_encoding';
        // 10. HTML 实体编码序列
        if (preg_match_all('/&#[xX][0-9a-fA-F]{2,4};/', $text) >= 2) $techniques[] = 'html_entity_encoding';
        return ['techniques' => array_values(array_unique($techniques))];
    }

    /** 检测攻击关键词内部是否混用大小写（如 UnIoN, sElEcT） */
    private static function hasMixedCaseKeyword(string $text): bool {
        $keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'from', 'where'];
        foreach ($keywords as $kw) {
            if (preg_match_all('/' . $kw . '/i', $text, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $hit) {
                    if (self::hasInternalMixedCase($hit[0])) return true;
                }
            }
        }
        return false;
    }

    /** 判断单词内部是否有大小写交替（排除 UNION / union 这种纯大小写） */
    private static function hasInternalMixedCase(string $word): bool {
        if (!preg_match('/[a-z]/', $word) || !preg_match('/[A-Z]/', $word)) return false;
        $inner = substr($word, 1);
        if (!preg_match('/[A-Z]/', $inner) || !preg_match('/[a-z]/', $inner)) return false;
        $transitions = 0;
        $prevUpper = null;
        $len = strlen($word);
        for ($i = 0; $i < $len; $i++) {
            $o = ord($word[$i]);
            $isUpper = ($o >= 0x41 && $o <= 0x5A);
            if ($prevUpper !== null && $isUpper !== $prevUpper) $transitions++;
            $prevUpper = $isUpper;
        }
        return $transitions >= 2;
    }

    // === C. 对抗样本检测（专门针对 WAF 绕过设计的 payload） ===

    private static function detectAdversarialPayload(string $text): array {
        $features = [];
        // 1. 已知 WAF 绕过 payload 结构
        foreach (self::$waf_bypass_patterns as $name => $pattern) {
            if (@preg_match($pattern, $text)) $features[] = 'waf_bypass:' . $name;
        }
        // 2. 零宽字符插入
        $zwHits = [];
        foreach (self::$zero_width_chars as $seq => $name) {
            $c = substr_count($text, $seq);
            if ($c > 0) $zwHits[$name] = $c;
        }
        if (!empty($zwHits)) $features[] = 'zero_width:' . implode(',', array_keys($zwHits));
        // 3. 同形字攻击
        $homoglyphHits = self::detectHomoglyphs($text);
        if (!empty($homoglyphHits)) $features[] = 'homoglyph:' . count($homoglyphHits);
        // 4. 字符集异常
        $anomalyCount = self::detectCharsetAnomaly($text);
        if ($anomalyCount > 0) $features[] = 'charset_anomaly:' . $anomalyCount;
        // 5. 多变体检测（自动化绕过工具特征）
        $variantCount = self::countPayloadVariants($text);
        if ($variantCount >= 2) $features[] = 'multi_variant:' . $variantCount;
        // 6. 极端编码深度（3+ 层 URL 编码）
        $encDepth = self::countUrlEncodingDepth($text);
        if ($encDepth >= 3) $features[] = 'deep_encoding:' . $encDepth;
        return ['features' => $features];
    }

    /** 同形字检测：在拉丁文本中发现西里尔/希腊字母 */
    private static function detectHomoglyphs(string $text): array {
        if (!preg_match('/[a-zA-Z]/', $text)) return []; // 避免误判纯西里尔文本
        $hits = [];
        foreach (self::$homoglyph_map as $cyr => $lat) {
            if (strpos($text, $cyr) !== false) $hits[] = $cyr . '->' . $lat;
        }
        return $hits;
    }

    /** 字符集异常检测：非常规 Unicode 字符（私用区/数学符号/全角等）出现频度 */
    private static function detectCharsetAnomaly(string $text): int {
        $len = strlen($text);
        if ($len < 4) return 0;
        $bytes = unpack('C*', $text);
        if (!$bytes) return 0;
        $anomaly = 0;
        $i = 1;
        $n = count($bytes);
        while ($i <= $n) {
            $b = $bytes[$i];
            if ($b < 0x80) { $i++; continue; }
            $cp = 0;
            if (($b & 0xE0) === 0xC0) {
                $cp = ($b & 0x1F) << 6;
                if (isset($bytes[$i + 1])) $cp |= ($bytes[$i + 1] & 0x3F);
                $i += 2;
            } elseif (($b & 0xF0) === 0xE0) {
                $cp = ($b & 0x0F) << 12;
                if (isset($bytes[$i + 1])) $cp |= ($bytes[$i + 1] & 0x3F) << 6;
                if (isset($bytes[$i + 2])) $cp |= ($bytes[$i + 2] & 0x3F);
                $i += 3;
            } elseif (($b & 0xF8) === 0xF0) {
                $i += 4; continue;
            } else {
                $i++; continue;
            }
            // 异常区域：通用标点 / 字母式符号 / 数学运算符 / 制表符几何形状 / 全角半角 / 私用区
            if (($cp >= 0x2000 && $cp <= 0x206F) || ($cp >= 0x2100 && $cp <= 0x214F)
                || ($cp >= 0x2200 && $cp <= 0x22FF) || ($cp >= 0x2500 && $cp <= 0x27BF)
                || ($cp >= 0xFF00 && $cp <= 0xFFEF) || ($cp >= 0xE000 && $cp <= 0xF8FF)) {
                $anomaly++;
            }
        }
        return $anomaly;
    }

    /** 多变体计数：检测同一攻击关键词的多种大小写形态 */
    private static function countPayloadVariants(string $text): int {
        $variants = 0;
        foreach (['union', 'select', 'or', 'and', 'script'] as $kw) {
            $forms = [];
            if (preg_match_all('/' . $kw . '/i', $text, $m)) {
                foreach ($m[0] as $w) $forms[$w] = true;
                if (count($forms) >= 2) $variants++;
            }
        }
        return $variants;
    }

    /** 独立计算 URL 编码深度（用于检测 3+ 层 URL 编码） */
    private static function countUrlEncodingDepth(string $text): int {
        $depth = 0;
        $t = $text;
        while ($depth < 6 && preg_match('#%[0-9a-fA-F]{2}#', $t)) {
            $decoded = rawurldecode($t);
            if ($decoded === $t || $decoded === '' || !self::isPrintableEnough($decoded)) break;
            $t = $decoded;
            $depth++;
        }
        return $depth;
    }

    // === D. 编码链分析（检测不自然的编码组合） ===

    private static function analyzeEncodingChain(string $text, array $decodeResult): array {
        $types = [];
        $anomaly = false;
        $score = 0;
        // 检测出现的编码类型
        if (preg_match('#%[0-9a-fA-F]{2}#', $text))       $types[] = 'url';
        if (preg_match('/&#|&[a-zA-Z]+;/', $text))          $types[] = 'html_entity';
        if (preg_match('/\\\\x[0-9a-fA-F]{2}/', $text))     $types[] = 'hex_escape';
        if (preg_match('/\b0x[0-9a-fA-F]{4,}\b/', $text))   $types[] = 'hex_literal';
        if (preg_match('/\\\\[0-3][0-7]{2}/', $text))       $types[] = 'octal_escape';
        if (preg_match('/\\\\u[0-9a-fA-F]{4}/', $text))     $types[] = 'unicode_escape';
        if (self::tryBase64Decode($text) !== null)          $types[] = 'base64';
        // URL 多重编码（2 层以上即异常）
        $urlDepth = self::countUrlEncodingDepth($text);
        if ($urlDepth >= 2) {
            $types[] = 'url_multi:' . $urlDepth;
            $anomaly = true; $score += 15;
        }
        // 混合编码：3 种以上不同编码同时出现
        $uniqueCount = count(array_unique($types));
        if ($uniqueCount >= 3) { $anomaly = true; $score += 20; }
        elseif ($uniqueCount === 2) { $score += 8; }
        // 递归还原深度异常（≥3 层）
        if ($decodeResult['depth'] >= 3) { $anomaly = true; $score += 15; }
        // 编码后内容包含攻击结构（高度可疑）
        $decoded = $decodeResult['decoded'];
        if ($decoded !== $text) {
            foreach (self::$attack_payload_patterns as $name => $pattern) {
                if (@preg_match($pattern, $decoded)) {
                    $types[] = 'decoded_contains:' . $name;
                    $anomaly = true; $score += 10;
                    break;
                }
            }
        }
        return ['types' => array_values(array_unique($types)), 'anomaly' => $anomaly, 'score' => min(40, $score)];
    }

    // === E. 还原前后对比分析 ===

    /**
     * 还原前：text（可能已部分解码）；还原后：rawText 的递归还原结果。
     * 若还原后内容包含攻击 payload 而原文本看似无害 → 强证据。
     */
    private static function comparePrePostDecode(string $before, string $after): array {
        $payloadTypes = [];
        $changed = ($before !== $after);
        if (!$changed) {
            // 未变化：直接检查原文本是否含 payload
            foreach (self::$attack_payload_patterns as $name => $pattern) {
                if (@preg_match($pattern, $before)) $payloadTypes[] = $name;
            }
            return ['has_payload' => !empty($payloadTypes), 'payload_types' => $payloadTypes, 'changed' => false];
        }
        // 还原后文本中检测攻击 payload
        foreach (self::$attack_payload_patterns as $name => $pattern) {
            if (@preg_match($pattern, $after)) $payloadTypes[] = $name;
        }
        // 强证据：原文本看似无害但还原后含攻击 payload
        if (!empty($payloadTypes) && !self::looksLikeAttack($before)) {
            $payloadTypes[] = 'hidden_payload_strong';
        }
        return ['has_payload' => !empty($payloadTypes), 'payload_types' => $payloadTypes, 'changed' => true];
    }

    /** 粗判文本是否看起来像攻击（用于"原文本看似无害"的对比） */
    private static function looksLikeAttack(string $text): bool {
        foreach (self::$attack_payload_patterns as $pattern) {
            if (@preg_match($pattern, $text)) return true;
        }
        return false;
    }

    // === F. 混淆复杂度评分 ===

    /**
     * 规则：编码层数 +10/层；混淆技术 +8/种；对抗样本特征 +15/种；
     *       编码链异常 +10；还原后含攻击 payload +30；多维交叉加成（2维+10/3维+20/4+维+30）。
     */
    private static function scoreObfuscationComplexity(array $features): int {
        $score = 0;
        $score += ($features['decode_depth'] ?? 0) * 10;
        $score += ($features['obfuscation_count'] ?? 0) * 8;
        $score += ($features['adversarial_count'] ?? 0) * 15;
        if (!empty($features['chain_anomaly']))       $score += 10;
        if (!empty($features['decoded_has_payload'])) $score += 30;
        // 多维混淆交叉加成
        $dimCount = 0;
        if (!empty($features['decode_depth']))         $dimCount++;
        if (!empty($features['obfuscation_count']))    $dimCount++;
        if (!empty($features['adversarial_count']))    $dimCount++;
        if (!empty($features['chain_anomaly']))        $dimCount++;
        if (!empty($features['decoded_has_payload']))  $dimCount++;
        if ($dimCount >= 4)      $score += 30;
        elseif ($dimCount === 3) $score += 20;
        elseif ($dimCount === 2) $score += 10;
        return min(100, max(0, $score));
    }

    // === 兼容层：WafNormalizer 接口适配 ===

    /**
     * 兼容 WafNormalizer::normalizeWithContext() 的返回格式
     * 用于平滑迁移，逐步替换旧归一化引擎
     */
    public static function normalizeWithContext(string $input): array {
        if (empty($input)) {
            return [
                'output' => '',
                'layers' => [],
                'encoding_depth' => 0,
                'encoding_complexity' => 0,
                'transform_count' => 0,
                'semantic_score' => 0,
                'double_encoding_detected' => false,
                'encoding_types' => [],
            ];
        }

        $advResult = self::analyze($input);

        $decoded = $advResult['decoded'] ?? $input;
        $depth = $advResult['decode_depth'] ?? 0;
        $path = $advResult['decode_path'] ?? [];
        $score = $advResult['score'] ?? 0;

        $complexity = self::calcComplexityFromAdv($depth, $path, $score);

        $doubleEncoding = in_array('double_url_encoding', $advResult['patterns'] ?? [])
            || in_array('html_entity_encoding', $advResult['patterns'] ?? [])
            || ($depth >= 2 && count($path) >= 2);

        return [
            'output' => trim($decoded),
            'layers' => self::buildLayerInfo($path, $input, $decoded),
            'encoding_depth' => $depth,
            'encoding_complexity' => $complexity,
            'transform_count' => count($path),
            'semantic_score' => $score,
            'double_encoding_detected' => $doubleEncoding,
            'encoding_types' => $path,
        ];
    }

    /**
     * 兼容 WafNormalizer::normalize()
     */
    public static function normalize(string $input): string {
        $result = self::normalizeWithContext($input);
        return $result['output'];
    }

    /**
     * 兼容 WafNormalizer::normalizeJson()
     */
    public static function normalizeJson(string $rawJson): string {
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
     * 兼容 WafNormalizer::normalizeXml()
     */
    public static function normalizeXml(string $rawXml): string {
        if (!class_exists('DOMDocument')) return self::normalize($rawXml);
        $dom = new \DOMDocument();
        libxml_use_internal_errors(true);
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

    /**
     * 从对抗防御结果计算编码复杂度（兼容 WafNormalizer 格式）
     */
    private static function calcComplexityFromAdv(int $depth, array $path, int $advScore): int {
        $score = 0;
        $score += $depth * 8;
        $score += count($path) * 2;
        $uniqueTypes = count(array_unique($path));
        $score += $uniqueTypes * 5;

        $highRiskTypes = ['base64', 'utf8_overlong', 'unicode_percent_u', 'homoglyph_normalize'];
        foreach ($highRiskTypes as $t) {
            if (in_array($t, $path)) $score += 10;
        }

        $score += $advScore * 0.3;

        return min((int)$score, 100);
    }

    /**
     * 构建层信息（兼容 WafNormalizer 格式）
     */
    private static function buildLayerInfo(array $path, string $input, string $decoded): array {
        $layers = [];
        $layerMap = [
            'urldecode' => 'URL递归解码',
            'html_numeric_entity' => 'HTML实体解码',
            'html_named_entity' => 'HTML命名实体解码',
            'base64' => 'Base64智能解码',
            'hex_escape' => 'Hex转义解码',
            'octal_escape' => '八进制转义解码',
            'hex_literal' => '十六进制字面量解码',
            'unicode_percent_u' => 'Unicode %u编码解码',
            'utf8_overlong' => 'UTF-8超集编码解码',
            'zero_width_remove' => '零宽控制字符清除',
            'fullwidth_normalize' => '全角半角转换',
            'homoglyph_normalize' => '同形字符映射',
            'unicode_escape' => 'Unicode转义解码',
            'case_normalize_keywords' => '关键词大小写归一化',
        ];

        $layerNum = 1;
        foreach ($path as $tech) {
            $layers[$layerNum] = [
                'name' => $layerMap[$tech] ?? $tech,
                'changed' => true,
                'input_len' => strlen($input),
                'output_len' => strlen($decoded),
            ];
            $layerNum++;
        }

        return $layers;
    }

    // === 防御建议生成 ===

    private static function generateRecommendation(array $threats, int $score): string {
        if (empty($threats)) return '无对抗攻击特征';
        $types = array_column($threats, 'type');
        if (in_array('decoded_payload', $types, true))     return '还原后检出攻击 payload，强烈建议拦截并告警';
        if (in_array('recursive_encoding', $types, true))  return '检测到多层嵌套编码，建议启用深度递归还原并重新评估';
        if (in_array('adversarial', $types, true))         return '检测到对抗样本特征（同形字/零宽字符/WAF 绕过结构），建议拦截并告警';
        if (in_array('encoding_chain', $types, true))      return '检测到不自然编码链，建议加强编码一致性校验';
        if (in_array('obfuscation', $types, true))         return '检测到混淆模式，建议启用混淆归一化后重新评估';
        if ($score >= 50) return '高置信度对抗攻击，建议立即拦截并告警';
        return '检测到疑似对抗攻击特征，建议加强观察';
    }
}
