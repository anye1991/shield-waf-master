<?php
/**
 * CSV/Excel 公式注入语义解析器
 * 职责：通过构建 Excel 公式 AST（抽象语法树）真正理解 CSV/Excel 公式结构，
 *       包括词法分析(Tokenizer)、语法分析(Parser)、语义分析(AST Walker)，
 *       识别 CSV 注入、公式注入、DDE、动态数据交换等攻击向量，
 *       而非依赖简单正则匹配进行注入检测。
 */
defined('ABSPATH') || exit;

class CsvInjectionSemanticParser {

    // ==================== Token 类型常量 ====================
    const TOK_COMMA          = 'COMMA';
    const TOK_SEMICOLON      = 'SEMICOLON';
    const TOK_TAB            = 'TAB';
    const TOK_SQUOTE         = 'SQUOTE';
    const TOK_DQUOTE         = 'DQUOTE';
    const TOK_EQ             = 'EQ';
    const TOK_PLUS           = 'PLUS';
    const TOK_MINUS          = 'MINUS';
    const TOK_MULT           = 'MULT';
    const TOK_DIV            = 'DIV';
    const TOK_POWER          = 'POWER';
    const TOK_CELL_REF       = 'CELL_REF';
    const TOK_RANGE_REF      = 'RANGE_REF';
    const TOK_FUNC_NAME      = 'FUNC_NAME';
    const TOK_LPAREN         = 'LPAREN';
    const TOK_RPAREN         = 'RPAREN';
    const TOK_COLON          = 'COLON';
    const TOK_EXCLAMATION    = 'EXCLAMATION';
    const TOK_DOLLAR         = 'DOLLAR';
    const TOK_STRING         = 'STRING';
    const TOK_NUMBER         = 'NUMBER';
    const TOK_BOOL           = 'BOOL';
    const TOK_AT             = 'AT';
    const TOK_AMPERSAND      = 'AMPERSAND';
    const TOK_PIPE           = 'PIPE';
    const TOK_LBRACE         = 'LBRACE';
    const TOK_RBRACE         = 'RBRACE';
    const TOK_LBRACKET       = 'LBRACKET';
    const TOK_RBRACKET       = 'RBRACKET';
    const TOK_PERCENT        = 'PERCENT';
    const TOK_NEWLINE        = 'NEWLINE';
    const TOK_CR             = 'CR';
    const TOK_IDENT          = 'IDENT';
    const TOK_OPERATOR       = 'OPERATOR';
    const TOK_ERROR          = 'ERROR';
    const TOK_EOF            = 'EOF';

    // ==================== 危险函数分类 ====================
    private static $dangerousFunctions = [
        'CMD'         => ['level' => 5, 'category' => 'command_exec', 'desc' => 'DDE命令执行'],
        'EXEC'        => ['level' => 5, 'category' => 'command_exec', 'desc' => '执行外部命令'],
        'SYSTEM'      => ['level' => 5, 'category' => 'command_exec', 'desc' => '系统命令执行'],
        'SHELL'       => ['level' => 5, 'category' => 'command_exec', 'desc' => 'Shell执行'],
        'DDE'         => ['level' => 5, 'category' => 'dde',          'desc' => '动态数据交换'],
        'DDEINITIATE' => ['level' => 5, 'category' => 'dde',          'desc' => 'DDE初始化'],
        'DDETERM'     => ['level' => 5, 'category' => 'dde',          'desc' => 'DDE终止'],
        'DDEPOKE'     => ['level' => 5, 'category' => 'dde',          'desc' => 'DDE数据发送'],
        'DDEREQUEST'  => ['level' => 5, 'category' => 'dde',          'desc' => 'DDE数据请求'],
        'HYPERLINK'   => ['level' => 3, 'category' => 'hyperlink',    'desc' => '超链接跳转'],
        'WEBSERVICE'  => ['level' => 4, 'category' => 'external_data', 'desc' => 'Web服务请求'],
        'FILTERXML'   => ['level' => 4, 'category' => 'external_data', 'desc' => 'XML外部实体'],
        'IMPORTXML'   => ['level' => 4, 'category' => 'external_data', 'desc' => 'XML数据导入'],
        'IMPORTHTML'  => ['level' => 4, 'category' => 'external_data', 'desc' => 'HTML数据导入'],
        'IMPORTDATA'  => ['level' => 4, 'category' => 'external_data', 'desc' => '数据导入'],
        'IMPORTRANGE' => ['level' => 3, 'category' => 'external_data', 'desc' => '区域数据导入'],
        'GOOGLEFINANCE' => ['level' => 3, 'category' => 'external_data', 'desc' => '谷歌财经数据'],
        'DIRECTORY'   => ['level' => 4, 'category' => 'file_op',      'desc' => '目录列表'],
        'FILES'       => ['level' => 4, 'category' => 'file_op',      'desc' => '文件列表'],
        'GET.CELL'    => ['level' => 4, 'category' => 'file_op',      'desc' => '单元格信息获取'],
        'GET.WORKBOOK'=> ['level' => 4, 'category' => 'file_op',      'desc' => '工作簿信息获取'],
        'ALERT'       => ['level' => 2, 'category' => 'popup',        'desc' => '弹窗警告'],
        'MSGBOX'      => ['level' => 2, 'category' => 'popup',        'desc' => '消息框'],
        'INDIRECT'    => ['level' => 3, 'category' => 'dynamic_eval', 'desc' => '动态引用'],
        'EVALUATE'    => ['level' => 4, 'category' => 'dynamic_eval', 'desc' => '动态求值'],
        'EVAL'        => ['level' => 4, 'category' => 'dynamic_eval', 'desc' => '表达式求值'],
        'VBA'         => ['level' => 5, 'category' => 'vba',          'desc' => 'VBA宏'],
        'CALL'        => ['level' => 5, 'category' => 'vba',          'desc' => 'DLL调用'],
        'REGISTER'    => ['level' => 5, 'category' => 'vba',          'desc' => 'DLL注册'],
        'REGISTER.ID' => ['level' => 5, 'category' => 'vba',          'desc' => 'DLL注册ID'],
    ];

    private static $commonFunctions = [
        'SUM', 'IF', 'VLOOKUP', 'HLOOKUP', 'INDEX', 'MATCH', 'COUNT', 'COUNTA',
        'COUNTIF', 'SUMIF', 'AVERAGE', 'MAX', 'MIN', 'ROUND', 'CONCATENATE',
        'LEFT', 'RIGHT', 'MID', 'LEN', 'TRIM', 'UPPER', 'LOWER', 'PROPER',
        'DATE', 'NOW', 'TODAY', 'TIME', 'YEAR', 'MONTH', 'DAY',
        'ABS', 'INT', 'MOD', 'RAND', 'RANDBETWEEN', 'SQRT', 'POWER',
        'AND', 'OR', 'NOT', 'TRUE', 'FALSE', 'ISNUMBER', 'ISTEXT',
        'SUBTOTAL', 'OFFSET', 'ROW', 'COLUMN', 'CELL', 'INFO',
    ];

    // ==================== 主入口 ====================

    /**
     * 主入口：分析 CSV/Excel 公式注入语义
     *
     * @param string $input
     * @return array
     */
    public static function analyze(string $input): array {
        $result = [
            'score'                => 0,
            'risk_level'           => 'clean',
            'is_csv_injection'     => false,
            'is_formula'           => false,
            'formula_count'        => 0,
            'dangerous_functions'  => [],
            'formula_depth'        => 0,
            'has_dde'              => false,
            'has_hyperlink'        => false,
            'has_external_data'    => false,
            'field_count'          => 0,
            'has_quote_escape'     => false,
            'formula_types'        => [],
            'ast_summary'          => [],
            'indicators'           => [],
        ];

        if (trim($input) === '') {
            return $result;
        }

        try {
            $inputTrimmed = trim($input);
            $startsWithFormula = self::isFormulaPrefix($inputTrimmed);

            $isCsvData = self::isLikelyCsvData($input);
            $result['is_csv_data'] = $isCsvData;

            $formulaFields = [];
            $allAstSummaries = [];
            $allDangerousFuncs = [];
            $maxDepth = 0;
            $hasDde = false;
            $hasHyperlink = false;
            $hasExternalData = false;
            $formulaTypes = [];
            $fieldCount = 0;
            $hasQuoteEscape = false;

            if ($isCsvData) {
                $csvFields = self::parseCsvFields($input);
                $fieldCount = count($csvFields);
                $hasQuoteEscape = self::detectQuoteEscape($input);

                foreach ($csvFields as $fieldIdx => $field) {
                    $trimmed = trim($field);
                    if (self::isFormulaPrefix($trimmed)) {
                        $formulaFields[] = [
                            'index'   => $fieldIdx,
                            'content' => $trimmed,
                        ];

                        $fieldResult = self::analyzeSingleFormula($trimmed);
                        if (!empty($fieldResult['dangerous_functions'])) {
                            $allDangerousFuncs = array_merge($allDangerousFuncs, $fieldResult['dangerous_functions']);
                        }
                        if ($fieldResult['depth'] > $maxDepth) $maxDepth = $fieldResult['depth'];
                        if ($fieldResult['has_dde']) $hasDde = true;
                        if ($fieldResult['has_hyperlink']) $hasHyperlink = true;
                        if ($fieldResult['has_external_data']) $hasExternalData = true;
                        if (!empty($fieldResult['formula_type'])) {
                            $formulaTypes[] = $fieldResult['formula_type'];
                        }
                        if (!empty($fieldResult['ast_summary'])) {
                            $allAstSummaries[] = [
                                'field_index' => $fieldIdx,
                                'summary'     => $fieldResult['ast_summary'],
                            ];
                        }
                    }
                }
            } else {
                $fieldCount = 1;

                if ($startsWithFormula) {
                    $formulaFields[] = [
                        'index'   => 0,
                        'content' => $inputTrimmed,
                    ];

                    $fieldResult = self::analyzeSingleFormula($inputTrimmed);
                    if (!empty($fieldResult['dangerous_functions'])) {
                        $allDangerousFuncs = array_merge($allDangerousFuncs, $fieldResult['dangerous_functions']);
                    }
                    if ($fieldResult['depth'] > $maxDepth) $maxDepth = $fieldResult['depth'];
                    if ($fieldResult['has_dde']) $hasDde = true;
                    if ($fieldResult['has_hyperlink']) $hasHyperlink = true;
                    if ($fieldResult['has_external_data']) $hasExternalData = true;
                    if (!empty($fieldResult['formula_type'])) {
                        $formulaTypes[] = $fieldResult['formula_type'];
                    }
                    if (!empty($fieldResult['ast_summary'])) {
                        $allAstSummaries[] = [
                            'field_index' => 0,
                            'summary'     => $fieldResult['ast_summary'],
                        ];
                    }
                }
            }

            $ddeFromPattern = self::detectDdePattern($input);
            if ($ddeFromPattern && !$hasDde) {
                $hasDde = true;
                if (!in_array('CMD', $allDangerousFuncs)) {
                    $allDangerousFuncs[] = 'CMD';
                }
                $formulaTypes[] = 'dde_pattern';
            }

            $result['field_count'] = $fieldCount;
            $result['has_quote_escape'] = $hasQuoteEscape;
            $result['formula_count'] = count($formulaFields);
            $result['is_formula'] = $result['formula_count'] > 0 || $hasDde;
            $result['is_csv_injection'] = $isCsvData && $result['is_formula'];
            $result['dangerous_functions'] = array_values(array_unique($allDangerousFuncs));
            $result['formula_depth'] = $maxDepth;
            $result['has_dde'] = $hasDde;
            $result['has_hyperlink'] = $hasHyperlink;
            $result['has_external_data'] = $hasExternalData;
            $result['formula_types'] = array_values(array_unique($formulaTypes));
            $result['ast_summary'] = $allAstSummaries;

            $result['score'] = self::calculateScore($result);
            $result['risk_level'] = self::getRiskLevel($result['score']);

            if ($result['is_csv_injection']) {
                $result['indicators'][] = 'csv_formula_injection';
            }
            if ($result['has_dde']) {
                $result['indicators'][] = 'dde_attack';
            }
            if ($result['has_hyperlink']) {
                $result['indicators'][] = 'malicious_hyperlink';
            }
            if ($result['has_external_data']) {
                $result['indicators'][] = 'external_data_retrieval';
            }
            if ($result['has_quote_escape']) {
                $result['indicators'][] = 'quote_escape_field_injection';
            }
            if (!empty($result['dangerous_functions'])) {
                $result['indicators'][] = 'dangerous_functions:' . implode(',', $result['dangerous_functions']);
            }
            if ($result['formula_depth'] > 5) {
                $result['indicators'][] = 'deep_formula_nesting:' . $result['formula_depth'];
            }

        } catch (Exception $e) {
            $result['indicators'][] = 'parse_error';
            $fallbackResult = self::regexFallback($input);
            if ($fallbackResult['score'] > $result['score']) {
                $result = array_merge($result, $fallbackResult);
            }
        }

        return $result;
    }

    // ==================== CSV 字段解析 ====================

    /**
     * 解析 CSV 行，提取各字段
     */
    private static function parseCsvFields(string $input): array {
        $fields = [];
        $len = strlen($input);
        $pos = 0;
        $currentField = '';
        $inQuotes = false;

        while ($pos < $len) {
            $char = $input[$pos];

            if ($inQuotes) {
                if ($char === '"') {
                    if ($pos + 1 < $len && $input[$pos + 1] === '"') {
                        $currentField .= '"';
                        $pos += 2;
                    } else {
                        $inQuotes = false;
                        $pos++;
                    }
                } else {
                    $currentField .= $char;
                    $pos++;
                }
            } else {
                if ($char === '"') {
                    $inQuotes = true;
                    $pos++;
                } elseif ($char === ',' || $char === ';' || $char === "\t") {
                    $fields[] = $currentField;
                    $currentField = '';
                    $pos++;
                } elseif ($char === "\n" || $char === "\r") {
                    $fields[] = $currentField;
                    $currentField = '';
                    if ($char === "\r" && $pos + 1 < $len && $input[$pos + 1] === "\n") {
                        $pos += 2;
                    } else {
                        $pos++;
                    }
                } else {
                    $currentField .= $char;
                    $pos++;
                }
            }
        }

        if ($currentField !== '' || $len > 0) {
            $fields[] = $currentField;
        }

        return $fields;
    }

    /**
     * 检测引号闭合逃逸：闭合引号后紧跟非分隔符字符
     */
    private static function detectQuoteEscape(string $input): bool {
        $len = strlen($input);
        $inQuotes = false;
        $i = 0;

        while ($i < $len) {
            $char = $input[$i];

            if ($inQuotes) {
                if ($char === '"') {
                    if ($i + 1 < $len && $input[$i + 1] === '"') {
                        $i += 2;
                        continue;
                    }
                    $inQuotes = false;
                    $i++;
                    if ($i < $len) {
                        $nextChar = $input[$i];
                        if ($nextChar !== ',' && $nextChar !== ';' && $nextChar !== "\t" &&
                            $nextChar !== "\n" && $nextChar !== "\r" && $nextChar !== ' ') {
                            return true;
                        }
                    }
                } else {
                    $i++;
                }
            } else {
                if ($char === '"') {
                    $inQuotes = true;
                }
                $i++;
            }
        }

        return false;
    }

    /**
     * 判断是否为公式前缀
     */
    private static function isFormulaPrefix(string $input): bool {
        if ($input === '') return false;
        $firstChar = $input[0];
        return in_array($firstChar, ['=', '+', '-', '@']);
    }

    /**
     * 判断输入是否可能是 CSV 数据
     */
    private static function isLikelyCsvData(string $input): bool {
        $trimmed = trim($input);
        if ($trimmed === '') return false;

        $lines = preg_split('/\r\n|\n|\r/', $trimmed);
        if (count($lines) >= 2) {
            $firstLine = $lines[0];
            $commaCount = substr_count($firstLine, ',');
            $semiCount = substr_count($firstLine, ';');
            $tabCount = substr_count($firstLine, "\t");
            if ($commaCount >= 1 || $semiCount >= 1 || $tabCount >= 1) {
                return true;
            }
        }

        if (self::isFormulaPrefix($trimmed)) {
            return false;
        }

        $commaCount = substr_count($trimmed, ',');
        $semiCount = substr_count($trimmed, ';');
        $tabCount = substr_count($trimmed, "\t");

        $quoteCount = substr_count($trimmed, '"');
        $hasQuotedFields = $quoteCount >= 2 && $quoteCount % 2 === 0;

        if ($hasQuotedFields && ($commaCount >= 1 || $semiCount >= 1)) {
            return true;
        }

        if ($commaCount >= 2 || $semiCount >= 2 || $tabCount >= 2) {
            return true;
        }

        return false;
    }

    /**
     * 检测 DDE 模式：=cmd|' /c calc'!A1
     */
    private static function detectDdePattern(string $input): bool {
        $patterns = [
            '/^[=+\-@]\s*[A-Za-z]+\s*\|/s',
            '/^[=+\-@]\s*[\'"]?[^\'"]+[\'"]?\s*\|[^\'"]*[\'"]?[A-Za-z0-9]+[\'"]?\s*!/s',
            '/\bCMD\s*\|/i',
            '/\bDDE\s*\(/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 分析单个公式
     */
    private static function analyzeSingleFormula(string $formula): array {
        $result = [
            'dangerous_functions' => [],
            'depth'               => 0,
            'has_dde'             => false,
            'has_hyperlink'       => false,
            'has_external_data'   => false,
            'formula_type'        => '',
            'ast_summary'         => null,
        ];

        $tokens = self::tokenize($formula);
        $ast = self::parseFormula($tokens);

        if ($ast !== null) {
            $analysis = self::analyzeFormulaAst($ast);
            $result['dangerous_functions'] = $analysis['dangerous_functions'];
            $result['depth'] = $analysis['depth'];
            $result['has_dde'] = $analysis['has_dde'];
            $result['has_hyperlink'] = $analysis['has_hyperlink'];
            $result['has_external_data'] = $analysis['has_external_data'];
            $result['formula_type'] = $analysis['formula_type'];
            $result['ast_summary'] = self::summarizeAst($ast);
        } else {
            $prefixAnalysis = self::analyzeFormulaByPrefix($formula);
            if ($prefixAnalysis['is_formula']) {
                $result['dangerous_functions'] = $prefixAnalysis['dangerous_functions'];
                $result['has_dde'] = $prefixAnalysis['has_dde'];
                $result['has_hyperlink'] = $prefixAnalysis['has_hyperlink'];
                $result['has_external_data'] = $prefixAnalysis['has_external_data'];
                $result['formula_type'] = $prefixAnalysis['formula_type'];
            }
        }

        if (self::detectDdePattern($formula) && !$result['has_dde']) {
            $result['has_dde'] = true;
            if (!in_array('CMD', $result['dangerous_functions'])) {
                $result['dangerous_functions'][] = 'CMD';
            }
        }

        return $result;
    }

    // ==================== Tokenizer ====================

    /**
     * Excel 公式词法分析
     */
    private static function tokenize(string $formula): array {
        $tokens = [];
        $pos = 0;
        $len = strlen($formula);

        if ($len === 0) {
            $tokens[] = ['type' => self::TOK_EOF, 'value' => '', 'pos' => 0];
            return $tokens;
        }

        $firstChar = $formula[0];
        if (in_array($firstChar, ['=', '+', '-', '@'])) {
            $typeMap = [
                '=' => self::TOK_EQ,
                '+' => self::TOK_PLUS,
                '-' => self::TOK_MINUS,
                '@' => self::TOK_AT,
            ];
            $tokens[] = [
                'type'  => $typeMap[$firstChar],
                'value' => $firstChar,
                'pos'   => 0,
            ];
            $pos = 1;
        }

        while ($pos < $len) {
            $char = $formula[$pos];

            if ($char === ' ' || $char === "\t") {
                $pos++;
                continue;
            }

            if ($char === "\n") {
                $tokens[] = ['type' => self::TOK_NEWLINE, 'value' => "\n", 'pos' => $pos];
                $pos++;
                continue;
            }

            if ($char === "\r") {
                if ($pos + 1 < $len && $formula[$pos + 1] === "\n") {
                    $tokens[] = ['type' => self::TOK_NEWLINE, 'value' => "\r\n", 'pos' => $pos];
                    $pos += 2;
                } else {
                    $tokens[] = ['type' => self::TOK_CR, 'value' => "\r", 'pos' => $pos];
                    $pos++;
                }
                continue;
            }

            if ($char === '"') {
                $start = $pos;
                $pos++;
                $value = '';
                while ($pos < $len) {
                    if ($formula[$pos] === '"') {
                        if ($pos + 1 < $len && $formula[$pos + 1] === '"') {
                            $value .= '"';
                            $pos += 2;
                        } else {
                            $pos++;
                            break;
                        }
                    } else {
                        $value .= $formula[$pos];
                        $pos++;
                    }
                }
                $tokens[] = [
                    'type'  => self::TOK_STRING,
                    'value' => $value,
                    'raw'   => substr($formula, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if (is_numeric($char) || ($char === '.' && $pos + 1 < $len && is_numeric($formula[$pos + 1]))) {
                $start = $pos;
                $hasDot = false;
                while ($pos < $len && (is_numeric($formula[$pos]) || ($formula[$pos] === '.' && !$hasDot))) {
                    if ($formula[$pos] === '.') $hasDot = true;
                    $pos++;
                }
                if ($pos < $len && ($formula[$pos] === 'e' || $formula[$pos] === 'E')) {
                    $pos++;
                    if ($pos < $len && ($formula[$pos] === '+' || $formula[$pos] === '-')) $pos++;
                    while ($pos < $len && is_numeric($formula[$pos])) $pos++;
                }
                if ($pos < $len && $formula[$pos] === '%') {
                    $tokens[] = [
                        'type'  => self::TOK_NUMBER,
                        'value' => substr($formula, $start, $pos - $start) . '%',
                        'pos'   => $start,
                    ];
                    $pos++;
                    continue;
                }
                $tokens[] = [
                    'type'  => self::TOK_NUMBER,
                    'value' => substr($formula, $start, $pos - $start),
                    'pos'   => $start,
                ];
                continue;
            }

            if (ctype_alpha($char) || $char === '_') {
                $start = $pos;
                while ($pos < $len && (ctype_alnum($formula[$pos]) || $formula[$pos] === '_' || $formula[$pos] === '.')) {
                    $pos++;
                }
                $word = substr($formula, $start, $pos - $start);
                $upper = strtoupper($word);

                if ($upper === 'TRUE' || $upper === 'FALSE') {
                    $tokens[] = [
                        'type'  => self::TOK_BOOL,
                        'value' => $upper,
                        'raw'   => $word,
                        'pos'   => $start,
                    ];
                    continue;
                }

                if ($pos < $len && $formula[$pos] === '(') {
                    $tokens[] = [
                        'type'  => self::TOK_FUNC_NAME,
                        'value' => $upper,
                        'raw'   => $word,
                        'pos'   => $start,
                    ];
                    continue;
                }

                $cellRef = self::tryParseCellRef($formula, $start, $pos);
                if ($cellRef !== null) {
                    $tokens[] = $cellRef;
                    $pos = $cellRef['end_pos'];
                    continue;
                }

                $tokens[] = [
                    'type'  => self::TOK_IDENT,
                    'value' => $upper,
                    'raw'   => $word,
                    'pos'   => $start,
                ];
                continue;
            }

            if ($char === '$') {
                $cellRef = self::tryParseCellRef($formula, $pos, $pos);
                if ($cellRef !== null) {
                    $tokens[] = $cellRef;
                    $pos = $cellRef['end_pos'];
                    continue;
                }
                $tokens[] = ['type' => self::TOK_DOLLAR, 'value' => '$', 'pos' => $pos];
                $pos++;
                continue;
            }

            switch ($char) {
                case ',':
                    $tokens[] = ['type' => self::TOK_COMMA, 'value' => ',', 'pos' => $pos];
                    $pos++;
                    break;
                case ';':
                    $tokens[] = ['type' => self::TOK_SEMICOLON, 'value' => ';', 'pos' => $pos];
                    $pos++;
                    break;
                case '(':
                    $tokens[] = ['type' => self::TOK_LPAREN, 'value' => '(', 'pos' => $pos];
                    $pos++;
                    break;
                case ')':
                    $tokens[] = ['type' => self::TOK_RPAREN, 'value' => ')', 'pos' => $pos];
                    $pos++;
                    break;
                case ':':
                    $tokens[] = ['type' => self::TOK_COLON, 'value' => ':', 'pos' => $pos];
                    $pos++;
                    break;
                case '!':
                    $tokens[] = ['type' => self::TOK_EXCLAMATION, 'value' => '!', 'pos' => $pos];
                    $pos++;
                    break;
                case '+':
                    $tokens[] = ['type' => self::TOK_PLUS, 'value' => '+', 'pos' => $pos];
                    $pos++;
                    break;
                case '-':
                    $tokens[] = ['type' => self::TOK_MINUS, 'value' => '-', 'pos' => $pos];
                    $pos++;
                    break;
                case '*':
                    $tokens[] = ['type' => self::TOK_MULT, 'value' => '*', 'pos' => $pos];
                    $pos++;
                    break;
                case '/':
                    $tokens[] = ['type' => self::TOK_DIV, 'value' => '/', 'pos' => $pos];
                    $pos++;
                    break;
                case '^':
                    $tokens[] = ['type' => self::TOK_POWER, 'value' => '^', 'pos' => $pos];
                    $pos++;
                    break;
                case '=':
                    $tokens[] = ['type' => self::TOK_EQ, 'value' => '=', 'pos' => $pos];
                    $pos++;
                    break;
                case '<':
                case '>':
                    if ($pos + 1 < $len && $formula[$pos + 1] === '=') {
                        $tokens[] = ['type' => self::TOK_OPERATOR, 'value' => $char . '=', 'pos' => $pos];
                        $pos += 2;
                    } elseif ($char === '<' && $pos + 1 < $len && $formula[$pos + 1] === '>') {
                        $tokens[] = ['type' => self::TOK_OPERATOR, 'value' => '<>', 'pos' => $pos];
                        $pos += 2;
                    } else {
                        $tokens[] = ['type' => self::TOK_OPERATOR, 'value' => $char, 'pos' => $pos];
                        $pos++;
                    }
                    break;
                case '&':
                    $tokens[] = ['type' => self::TOK_AMPERSAND, 'value' => '&', 'pos' => $pos];
                    $pos++;
                    break;
                case '|':
                    $tokens[] = ['type' => self::TOK_PIPE, 'value' => '|', 'pos' => $pos];
                    $pos++;
                    break;
                case "'":
                    $tokens[] = ['type' => self::TOK_SQUOTE, 'value' => "'", 'pos' => $pos];
                    $pos++;
                    break;
                case '[':
                    $tokens[] = ['type' => self::TOK_LBRACKET, 'value' => '[', 'pos' => $pos];
                    $pos++;
                    break;
                case ']':
                    $tokens[] = ['type' => self::TOK_RBRACKET, 'value' => ']', 'pos' => $pos];
                    $pos++;
                    break;
                case '{':
                    $tokens[] = ['type' => self::TOK_LBRACE, 'value' => '{', 'pos' => $pos];
                    $pos++;
                    break;
                case '}':
                    $tokens[] = ['type' => self::TOK_RBRACE, 'value' => '}', 'pos' => $pos];
                    $pos++;
                    break;
                case '%':
                    $tokens[] = ['type' => self::TOK_PERCENT, 'value' => '%', 'pos' => $pos];
                    $pos++;
                    break;
                default:
                    $pos++;
            }
        }

        $tokens[] = ['type' => self::TOK_EOF, 'value' => '', 'pos' => $len];
        return $tokens;
    }

    /**
     * 尝试解析单元格引用
     */
    private static function tryParseCellRef(string $formula, int $start, int $currentPos): ?array {
        $pos = $currentPos;
        $len = strlen($formula);

        $colAbsolute = false;
        if ($pos < $len && $formula[$pos] === '$') {
            $colAbsolute = true;
            $pos++;
        }

        $colLetters = '';
        while ($pos < $len && ctype_alpha($formula[$pos])) {
            $colLetters .= strtoupper($formula[$pos]);
            $pos++;
        }

        if ($colLetters === '') {
            return null;
        }

        $rowAbsolute = false;
        if ($pos < $len && $formula[$pos] === '$') {
            $rowAbsolute = true;
            $pos++;
        }

        $rowDigits = '';
        while ($pos < $len && is_numeric($formula[$pos])) {
            $rowDigits .= $formula[$pos];
            $pos++;
        }

        if ($rowDigits === '') {
            return null;
        }

        return [
            'type'        => self::TOK_CELL_REF,
            'value'       => substr($formula, $start, $pos - $start),
            'pos'         => $start,
            'end_pos'     => $pos,
            'col'         => $colLetters,
            'row'         => (int)$rowDigits,
            'col_absolute' => $colAbsolute,
            'row_absolute' => $rowAbsolute,
        ];
    }

    // ==================== Parser ====================

    /**
     * 解析 Excel 公式，构建 AST
     */
    private static function parseFormula(array $tokens): ?array {
        if (empty($tokens)) return null;

        $state = [
            'tokens' => $tokens,
            'pos'    => 0,
            'dangerous_functions' => [],
            'max_depth' => 0,
        ];

        $firstToken = $tokens[0] ?? null;
        if ($firstToken && in_array($firstToken['type'], [
            self::TOK_EQ, self::TOK_PLUS, self::TOK_MINUS, self::TOK_AT,
        ])) {
            $state['pos'] = 1;
        }

        $expr = self::parseExpression($state, 0);
        if ($expr === null) {
            return null;
        }

        $ast = [
            'type'                => 'formula',
            'prefix'              => $firstToken['value'] ?? '=',
            'expression'          => $expr,
            'dangerous_functions' => array_values(array_unique($state['dangerous_functions'])),
            'max_depth'           => $state['max_depth'],
        ];

        return $ast;
    }

    private static function parseExpression(array &$state, int $depth): ?array {
        return self::parseComparisonExpr($state, $depth);
    }

    private static function parseComparisonExpr(array &$state, int $depth): ?array {
        $left = self::parseConcatExpr($state, $depth);
        if ($left === null) return null;

        while (true) {
            $tok = self::current($state);
            if ($tok['type'] === self::TOK_EOF) break;

            $op = null;
            if ($tok['type'] === self::TOK_EQ) {
                $op = '=';
            } elseif ($tok['type'] === self::TOK_OPERATOR && in_array($tok['value'], ['<', '>', '<=', '>=', '<>'])) {
                $op = $tok['value'];
            }

            if ($op === null) break;

            self::next($state);
            $right = self::parseConcatExpr($state, $depth);
            if ($right === null) break;

            $left = [
                'type'  => 'comparison',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }

        return $left;
    }

    private static function parseConcatExpr(array &$state, int $depth): ?array {
        $left = self::parseAdditiveExpr($state, $depth);
        if ($left === null) return null;

        while (true) {
            $tok = self::current($state);
            if ($tok['type'] !== self::TOK_AMPERSAND) break;

            self::next($state);
            $right = self::parseAdditiveExpr($state, $depth);
            if ($right === null) break;

            $left = [
                'type'  => 'concatenation',
                'left'  => $left,
                'right' => $right,
            ];
        }

        return $left;
    }

    private static function parseAdditiveExpr(array &$state, int $depth): ?array {
        $left = self::parseMultiplicativeExpr($state, $depth);
        if ($left === null) return null;

        while (true) {
            $tok = self::current($state);
            $op = null;

            if ($tok['type'] === self::TOK_PLUS) {
                $op = '+';
            } elseif ($tok['type'] === self::TOK_MINUS) {
                $op = '-';
            }

            if ($op === null) break;

            self::next($state);
            $right = self::parseMultiplicativeExpr($state, $depth);
            if ($right === null) break;

            $left = [
                'type'  => 'arithmetic',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }

        return $left;
    }

    private static function parseMultiplicativeExpr(array &$state, int $depth): ?array {
        $left = self::parsePowerExpr($state, $depth);
        if ($left === null) return null;

        while (true) {
            $tok = self::current($state);
            $op = null;

            if ($tok['type'] === self::TOK_MULT) {
                $op = '*';
            } elseif ($tok['type'] === self::TOK_DIV) {
                $op = '/';
            }

            if ($op === null) break;

            self::next($state);
            $right = self::parsePowerExpr($state, $depth);
            if ($right === null) break;

            $left = [
                'type'  => 'arithmetic',
                'op'    => $op,
                'left'  => $left,
                'right' => $right,
            ];
        }

        return $left;
    }

    private static function parsePowerExpr(array &$state, int $depth): ?array {
        $left = self::parseUnaryExpr($state, $depth);
        if ($left === null) return null;

        $tok = self::current($state);
        if ($tok['type'] === self::TOK_POWER) {
            self::next($state);
            $right = self::parsePowerExpr($state, $depth);
            if ($right !== null) {
                $left = [
                    'type'  => 'arithmetic',
                    'op'    => '^',
                    'left'  => $left,
                    'right' => $right,
                ];
            }
        }

        return $left;
    }

    private static function parseUnaryExpr(array &$state, int $depth): ?array {
        $tok = self::current($state);

        if ($tok['type'] === self::TOK_PLUS || $tok['type'] === self::TOK_MINUS) {
            $op = $tok['value'];
            self::next($state);
            $operand = self::parseUnaryExpr($state, $depth);
            if ($operand !== null) {
                return [
                    'type'    => 'unary',
                    'op'      => $op,
                    'operand' => $operand,
                ];
            }
            return null;
        }

        return self::parsePostfixExpr($state, $depth);
    }

    private static function parsePostfixExpr(array &$state, int $depth): ?array {
        $expr = self::parsePrimary($state, $depth);
        if ($expr === null) return null;

        $tok = self::current($state);
        if ($tok['type'] === self::TOK_PERCENT) {
            self::next($state);
            $expr = [
                'type'    => 'postfix',
                'op'      => '%',
                'operand' => $expr,
            ];
        }

        return $expr;
    }

    private static function parsePrimary(array &$state, int $depth): ?array {
        $tok = self::current($state);

        if ($depth + 1 > $state['max_depth']) {
            $state['max_depth'] = $depth + 1;
        }

        if ($tok['type'] === self::TOK_NUMBER) {
            self::next($state);
            return [
                'type'  => 'number',
                'value' => $tok['value'],
            ];
        }

        if ($tok['type'] === self::TOK_STRING) {
            self::next($state);
            return [
                'type'  => 'string',
                'value' => $tok['value'],
                'raw'   => $tok['raw'] ?? $tok['value'],
            ];
        }

        if ($tok['type'] === self::TOK_BOOL) {
            self::next($state);
            return [
                'type'  => 'boolean',
                'value' => $tok['value'],
            ];
        }

        if ($tok['type'] === self::TOK_LPAREN) {
            self::next($state);
            $expr = self::parseExpression($state, $depth + 1);
            if (self::current($state)['type'] === self::TOK_RPAREN) {
                self::next($state);
            }
            if ($expr !== null) {
                return [
                    'type'       => 'parenthesized',
                    'expression' => $expr,
                ];
            }
            return null;
        }

        if ($tok['type'] === self::TOK_LBRACE) {
            return self::parseArrayConstant($state, $depth);
        }

        if ($tok['type'] === self::TOK_FUNC_NAME) {
            return self::parseFunctionCall($state, $depth);
        }

        if ($tok['type'] === self::TOK_CELL_REF) {
            return self::parseCellOrRangeRef($state, $depth);
        }

        if ($tok['type'] === self::TOK_IDENT) {
            $sheetName = $tok['value'];
            $nextTok = self::peek($state, 1);
            if ($nextTok && $nextTok['type'] === self::TOK_EXCLAMATION) {
                self::next($state);
                self::next($state);
                $ref = self::parseCellOrRangeRef($state, $depth);
                if ($ref !== null) {
                    $ref['sheet'] = $sheetName;
                    return $ref;
                }
            }
            self::next($state);
            return [
                'type'  => 'identifier',
                'value' => $tok['value'],
            ];
        }

        if ($tok['type'] === self::TOK_SQUOTE) {
            return self::parseQuotedSheetRef($state, $depth);
        }

        return null;
    }

    private static function parseFunctionCall(array &$state, int $depth): ?array {
        $tok = self::current($state);
        $funcName = $tok['value'];
        self::next($state);

        if (isset(self::$dangerousFunctions[$funcName])) {
            $state['dangerous_functions'][] = $funcName;
        }

        if (!self::expect($state, self::TOK_LPAREN)) {
            return [
                'type' => 'function_call',
                'name' => $funcName,
                'args' => [],
            ];
        }

        $args = [];
        if (self::current($state)['type'] !== self::TOK_RPAREN) {
            $args = self::parseArgumentList($state, $depth + 1);
        }

        self::match($state, self::TOK_RPAREN);

        return [
            'type' => 'function_call',
            'name' => $funcName,
            'args' => $args,
        ];
    }

    private static function parseArgumentList(array &$state, int $depth): array {
        $args = [];

        while (true) {
            $current = self::current($state);
            if ($current['type'] === self::TOK_RPAREN || $current['type'] === self::TOK_EOF) {
                break;
            }

            if ($current['type'] === self::TOK_COMMA || $current['type'] === self::TOK_SEMICOLON) {
                $args[] = null;
                self::next($state);
                continue;
            }

            $expr = self::parseExpression($state, $depth + 1);
            if ($expr !== null) {
                $args[] = $expr;
            }

            $next = self::current($state);
            if ($next['type'] === self::TOK_COMMA || $next['type'] === self::TOK_SEMICOLON) {
                self::next($state);
                continue;
            }

            break;
        }

        return $args;
    }

    private static function parseCellOrRangeRef(array &$state, int $depth): ?array {
        $startRef = self::current($state);
        self::next($state);

        $startNode = [
            'type'         => 'cell_ref',
            'value'        => $startRef['value'],
            'col'          => $startRef['col'] ?? '',
            'row'          => $startRef['row'] ?? 0,
            'col_absolute' => $startRef['col_absolute'] ?? false,
            'row_absolute' => $startRef['row_absolute'] ?? false,
        ];

        $next = self::current($state);
        if ($next['type'] === self::TOK_COLON) {
            self::next($state);
            $endRef = self::current($state);
            if ($endRef['type'] === self::TOK_CELL_REF) {
                self::next($state);
                return [
                    'type' => 'range_ref',
                    'start' => $startNode,
                    'end' => [
                        'type'         => 'cell_ref',
                        'value'        => $endRef['value'],
                        'col'          => $endRef['col'] ?? '',
                        'row'          => $endRef['row'] ?? 0,
                        'col_absolute' => $endRef['col_absolute'] ?? false,
                        'row_absolute' => $endRef['row_absolute'] ?? false,
                    ],
                ];
            }
        }

        return $startNode;
    }

    private static function parseQuotedSheetRef(array &$state, int $depth): ?array {
        self::next($state);
        $sheetName = '';
        while (!self::isEof($state) && self::current($state)['type'] !== self::TOK_SQUOTE) {
            $sheetName .= self::current($state)['value'];
            self::next($state);
        }
        if (self::current($state)['type'] === self::TOK_SQUOTE) {
            self::next($state);
        }
        if (self::current($state)['type'] === self::TOK_EXCLAMATION) {
            self::next($state);
            $ref = self::parseCellOrRangeRef($state, $depth);
            if ($ref !== null) {
                $ref['sheet'] = $sheetName;
                return $ref;
            }
        }
        return [
            'type'  => 'quoted_string',
            'value' => $sheetName,
        ];
    }

    private static function parseArrayConstant(array &$state, int $depth): ?array {
        self::next($state);
        $rows = [];
        $currentRow = [];

        while (!self::isEof($state) && self::current($state)['type'] !== self::TOK_RBRACE) {
            $tok = self::current($state);

            if ($tok['type'] === self::TOK_SEMICOLON) {
                $rows[] = $currentRow;
                $currentRow = [];
                self::next($state);
                continue;
            }

            if ($tok['type'] === self::TOK_COMMA) {
                self::next($state);
                continue;
            }

            $expr = self::parseExpression($state, $depth + 1);
            if ($expr !== null) {
                $currentRow[] = $expr;
            } else {
                self::next($state);
            }
        }

        if (!empty($currentRow)) {
            $rows[] = $currentRow;
        }

        if (self::current($state)['type'] === self::TOK_RBRACE) {
            self::next($state);
        }

        return [
            'type'  => 'array_constant',
            'rows'  => $rows,
        ];
    }

    // ==================== Parser 辅助函数 ====================

    private static function current(array &$state): array {
        return $state['tokens'][$state['pos']] ?? end($state['tokens']);
    }

    private static function peek(array &$state, int $offset): ?array {
        $idx = $state['pos'] + $offset;
        return $state['tokens'][$idx] ?? null;
    }

    private static function next(array &$state): void {
        if ($state['pos'] < count($state['tokens']) - 1) {
            $state['pos']++;
        }
    }

    private static function isEof(array &$state): bool {
        $tok = self::current($state);
        return $tok['type'] === self::TOK_EOF;
    }

    private static function match(array &$state, string $type): bool {
        if (self::current($state)['type'] === $type) {
            self::next($state);
            return true;
        }
        return false;
    }

    private static function expect(array &$state, string $type): bool {
        if (self::current($state)['type'] === $type) {
            self::next($state);
            return true;
        }
        return false;
    }

    // ==================== AST 语义分析 ====================

    /**
     * 分析公式 AST，提取危险特征
     */
    private static function analyzeFormulaAst(array $ast): array {
        $result = [
            'dangerous_functions' => [],
            'depth'               => 0,
            'has_dde'             => false,
            'has_hyperlink'       => false,
            'has_external_data'   => false,
            'formula_type'        => '',
        ];

        $depth = 0;
        self::walkAst($ast, $result, $depth);

        $result['depth'] = $ast['max_depth'] ?? $depth;

        if (!empty($ast['expression'])) {
            $result['formula_type'] = self::classifyFormula($ast['expression']);
        }

        return $result;
    }

    /**
     * 递归遍历 AST 节点
     */
    private static function walkAst(?array $node, array &$result, int $depth): void {
        if ($node === null) return;

        if ($depth > $result['depth']) {
            $result['depth'] = $depth;
        }

        $type = $node['type'] ?? '';

        switch ($type) {
            case 'function_call':
                $funcName = $node['name'] ?? '';
                if (isset(self::$dangerousFunctions[$funcName])) {
                    $result['dangerous_functions'][] = $funcName;
                    $cat = self::$dangerousFunctions[$funcName]['category'] ?? '';
                    if ($cat === 'dde') $result['has_dde'] = true;
                    if ($cat === 'hyperlink') $result['has_hyperlink'] = true;
                    if ($cat === 'external_data') $result['has_external_data'] = true;
                    if ($cat === 'command_exec') $result['has_dde'] = true;
                }

                if (strtoupper($funcName) === 'CMD' || strtoupper($funcName) === 'DDE') {
                    $result['has_dde'] = true;
                }

                if (!empty($node['args'])) {
                    foreach ($node['args'] as $arg) {
                        self::walkAst($arg, $result, $depth + 1);
                    }
                }
                break;

            case 'formula':
                self::walkAst($node['expression'] ?? null, $result, $depth + 1);
                break;

            case 'arithmetic':
            case 'comparison':
            case 'concatenation':
                self::walkAst($node['left'] ?? null, $result, $depth + 1);
                self::walkAst($node['right'] ?? null, $result, $depth + 1);
                break;

            case 'unary':
            case 'postfix':
            case 'parenthesized':
                self::walkAst($node['operand'] ?? $node['expression'] ?? null, $result, $depth + 1);
                break;

            case 'array_constant':
                if (!empty($node['rows'])) {
                    foreach ($node['rows'] as $row) {
                        foreach ($row as $cell) {
                            self::walkAst($cell, $result, $depth + 1);
                        }
                    }
                }
                break;

            case 'cell_ref':
            case 'range_ref':
            case 'number':
            case 'string':
            case 'boolean':
            case 'identifier':
            default:
                break;
        }
    }

    /**
     * 分类公式类型
     */
    private static function classifyFormula(array $expr): string {
        $type = $expr['type'] ?? '';

        if ($type === 'function_call') {
            $name = $expr['name'] ?? '';
            if (isset(self::$dangerousFunctions[$name])) {
                return 'dangerous_' . (self::$dangerousFunctions[$name]['category'] ?? 'function');
            }
            return 'function_' . strtolower($name);
        }

        if ($type === 'cell_ref' || $type === 'range_ref') {
            return 'reference';
        }

        if ($type === 'arithmetic') {
            return 'arithmetic';
        }

        if ($type === 'comparison') {
            return 'comparison';
        }

        if ($type === 'concatenation') {
            return 'string_concat';
        }

        return $type;
    }

    // ==================== 前缀快速分析（Fallback） ====================

    /**
     * 通过前缀和关键词进行快速公式分析（解析失败时使用）
     */
    private static function analyzeFormulaByPrefix(string $formula): array {
        $result = [
            'is_formula'          => false,
            'dangerous_functions' => [],
            'has_dde'             => false,
            'has_hyperlink'       => false,
            'has_external_data'   => false,
            'formula_type'        => '',
        ];

        if (!self::isFormulaPrefix($formula)) {
            return $result;
        }

        $result['is_formula'] = true;
        $upper = strtoupper($formula);

        foreach (self::$dangerousFunctions as $funcName => $info) {
            $pattern = '/\b' . preg_quote($funcName, '/') . '\s*\(/i';
            if (preg_match($pattern, $formula)) {
                $result['dangerous_functions'][] = strtoupper($funcName);
                $cat = $info['category'] ?? '';
                if ($cat === 'dde' || $cat === 'command_exec') $result['has_dde'] = true;
                if ($cat === 'hyperlink') $result['has_hyperlink'] = true;
                if ($cat === 'external_data') $result['has_external_data'] = true;
            }
        }

        if (preg_match('/^[=+\-@]\s*CMD\|/i', $formula) ||
            preg_match('/^[=+\-@]\s*[\'"]?.*[\'"]?\|.*!/i', $formula)) {
            $result['has_dde'] = true;
            if (!in_array('CMD', $result['dangerous_functions'])) {
                $result['dangerous_functions'][] = 'CMD';
            }
        }

        if (stripos($upper, 'HYPERLINK') !== false) {
            $result['has_hyperlink'] = true;
        }

        if (!empty($result['dangerous_functions'])) {
            $firstFunc = $result['dangerous_functions'][0];
            $result['formula_type'] = 'dangerous_' . (self::$dangerousFunctions[$firstFunc]['category'] ?? 'function');
        } else {
            $result['formula_type'] = 'unknown_formula';
        }

        return $result;
    }

    // ==================== AST 摘要 ====================

    private static function summarizeAst(array $ast): array {
        $summary = [
            'type' => $ast['type'] ?? 'unknown',
        ];

        if (isset($ast['max_depth'])) {
            $summary['depth'] = $ast['max_depth'];
        }

        if (!empty($ast['dangerous_functions'])) {
            $summary['dangerous_functions'] = $ast['dangerous_functions'];
        }

        if (isset($ast['prefix'])) {
            $summary['prefix'] = $ast['prefix'];
        }

        if (!empty($ast['expression'])) {
            $expr = $ast['expression'];
            $exprType = $expr['type'] ?? '';
            if ($exprType === 'function_call') {
                $summary['root_function'] = $expr['name'] ?? '';
                $summary['arg_count'] = count($expr['args'] ?? []);
            } else {
                $summary['root_type'] = $exprType;
            }
        }

        return $summary;
    }

    // ==================== 分数计算 ====================

    private static function calculateScore(array $result): int {
        $score = 0;

        if (!$result['is_formula']) {
            return 0;
        }

        $score += 15;

        if ($result['is_csv_injection']) {
            $score += 20;
        }

        if (!empty($result['dangerous_functions'])) {
            $funcScore = 0;
            foreach ($result['dangerous_functions'] as $func) {
                $info = self::$dangerousFunctions[$func] ?? ['level' => 2];
                $level = $info['level'] ?? 2;

                switch ($level) {
                    case 5:
                        $funcScore += 50;
                        break;
                    case 4:
                        $funcScore += 35;
                        break;
                    case 3:
                        $funcScore += 20;
                        break;
                    case 2:
                        $funcScore += 10;
                        break;
                    default:
                        $funcScore += 5;
                }
            }
            $score += min($funcScore, 70);
        }

        if ($result['has_dde']) {
            $score += 40;
        }

        if ($result['has_hyperlink']) {
            $score += 15;
        }

        if ($result['has_external_data']) {
            $score += 25;
        }

        if ($result['has_quote_escape']) {
            $score += 20;
        }

        if ($result['formula_count'] > 3) {
            $score += min(($result['formula_count'] - 1) * 5, 20);
        }

        if ($result['formula_depth'] > 5) {
            $score += min(($result['formula_depth'] - 5) * 3, 15);
        }

        return min($score, 100);
    }

    private static function getRiskLevel(int $score): string {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 35) return 'medium';
        if ($score >= 15) return 'low';
        return 'clean';
    }

    // ==================== 正则 Fallback ====================

    /**
     * 正则表达式 Fallback 检测
     */
    private static function regexFallback(string $input): array {
        $result = [
            'score'                => 0,
            'risk_level'           => 'clean',
            'is_csv_injection'     => false,
            'is_formula'           => false,
            'formula_count'        => 0,
            'dangerous_functions'  => [],
            'formula_depth'        => 0,
            'has_dde'              => false,
            'has_hyperlink'        => false,
            'has_external_data'    => false,
            'field_count'          => 0,
            'has_quote_escape'     => false,
            'formula_types'        => [],
            'indicators'           => [],
        ];

        $lines = preg_split('/\r\n|\n|\r/', $input);
        $totalFields = 0;
        $formulaCount = 0;
        $dangerousFuncs = [];
        $hasDde = false;
        $hasHyperlink = false;
        $hasExternalData = false;

        foreach ($lines as $line) {
            if (trim($line) === '') continue;

            $fields = self::parseCsvFields($line);
            $totalFields += count($fields);

            foreach ($fields as $field) {
                $trimmed = trim($field);
                if (self::isFormulaPrefix($trimmed)) {
                    $formulaCount++;
                    $upper = strtoupper($trimmed);

                    foreach (self::$dangerousFunctions as $funcName => $info) {
                        if (stripos($trimmed, $funcName . '(') !== false) {
                            $dangerousFuncs[] = strtoupper($funcName);
                            $cat = $info['category'] ?? '';
                            if ($cat === 'dde' || $cat === 'command_exec') $hasDde = true;
                            if ($cat === 'hyperlink') $hasHyperlink = true;
                            if ($cat === 'external_data') $hasExternalData = true;
                        }
                    }

                    if (preg_match('/^[=+\-@]\s*CMD\|/i', $trimmed) ||
                        preg_match('/\bDDE\b/i', $upper)) {
                        $hasDde = true;
                    }
                }
            }
        }

        $result['field_count'] = $totalFields;
        $result['formula_count'] = $formulaCount;
        $result['is_formula'] = $formulaCount > 0;
        $result['is_csv_injection'] = $formulaCount > 0 && $totalFields > 1;
        $result['dangerous_functions'] = array_values(array_unique($dangerousFuncs));
        $result['has_dde'] = $hasDde;
        $result['has_hyperlink'] = $hasHyperlink;
        $result['has_external_data'] = $hasExternalData;
        $result['has_quote_escape'] = self::detectQuoteEscape($input);

        $result['score'] = self::calculateScore($result);
        $result['risk_level'] = self::getRiskLevel($result['score']);

        if ($result['is_csv_injection']) {
            $result['indicators'][] = 'csv_formula_injection';
        }
        if ($result['has_dde']) {
            $result['indicators'][] = 'dde_attack';
        }

        return $result;
    }
}
