<?php
/**
 * 盾甲 WAF 智能评分系统 (Scorer.php)
 *
 * WafScorer 类采用四维评分机制综合判断请求是否为攻击：
 *   - 熵值分析 (Entropy, 权重 15%): 计算 payload 的信息熵，高熵值通常表示编码或混淆内容
 *   - 语义分析 (Semantic, 权重 30%): 结合语义引擎判断请求是否符合正常业务逻辑
 *   - 编译偏差分析 (Compiler, 权重 25%): 检测代码结构、SQL 结构等异常模式
 *   - 偏离分析 (Deviation, 权重 30%): 与历史正常请求对比，检测异常偏离
 *
 * 评分阈值：
 *   0-30   → 通过
 *   30-50  → 记录日志
 *   50-70  → 观察
 *   80+    → 拦截
 */
defined('ABSPATH') || exit;

require_once __DIR__ . '/../Semantic/SemanticEngine.php';
require_once __DIR__ . '/../Learn/AutoLearn.php';

class WafScorer {
    private static $weights = [
        'entropy'   => 0.15,
        'semantic'  => 0.30,
        'compiler'  => 0.25,
        'deviation' => 0.30,
    ];

    private static $thresholds = [
        'pass'    => 30,
        'log'     => 50,
        'observe' => 70,
        'block'   => 80,
    ];

    /**
     * 对请求进行四维评分
     * @param string $payload 归一化后的请求载荷
     * @param string $uri     请求URI
     * @param array  $params  请求参数键值对
     * @param array $normalizerContext 归一化引擎返回的上下文数据
     * @param string $ip      请求IP地址（用于攻击链关联）
     * @return array 评分结果
     */
    public static function score($payload, $uri = '', $params = [], $normalizerContext = [], $ip = '') {
        $entropyScore   = self::calcEntropy($payload);
        $semanticResult  = self::calcSemantic($payload, $uri, $params, $normalizerContext, $ip);
        $semanticScore   = $semanticResult['total_score'] ?? 0;
        $compilerScore   = self::calcCompiler($payload, $uri, $params);
        $deviationScore  = self::calcDeviation($uri, $params, $normalizerContext);

        $totalScore = $entropyScore * self::$weights['entropy']
                    + $semanticScore * self::$weights['semantic']
                    + $compilerScore * self::$weights['compiler']
                    + $deviationScore * self::$weights['deviation'];

        $totalScore = min(round($totalScore, 1), 100);

        $action = self::decideAction($totalScore);

        return [
            'total_score'     => $totalScore,
            'entropy_score'   => $entropyScore,
            'semantic_score'  => $semanticScore,
            'compiler_score'  => $compilerScore,
            'deviation_score' => $deviationScore,
            'action'          => $action,
            'risk_level'      => self::getRiskLevel($totalScore),
            'is_attack'       => $totalScore >= self::$thresholds['block'],
            'semantic_detail' => $semanticResult,
            'components'      => [
                'entropy'   => ['score' => $entropyScore, 'weight' => self::$weights['entropy']],
                'semantic'  => ['score' => $semanticScore, 'weight' => self::$weights['semantic']],
                'compiler'  => ['score' => $compilerScore, 'weight' => self::$weights['compiler']],
                'deviation' => ['score' => $deviationScore, 'weight' => self::$weights['deviation']],
            ],
        ];
    }

    // ====================== 熵值分析 (15%) ======================

    /**
     * 计算信息熵分数
     * 高熵值通常表示编码或混淆内容
     */
    private static function calcEntropy($text) {
        if (empty($text)) return 0;

        $len = strlen($text);
        if ($len <= 1) return 0;

        // 计算字符频率
        $freq = [];
        for ($i = 0; $i < $len; $i++) {
            $char = $text[$i];
            $freq[$char] = ($freq[$char] ?? 0) + 1;
        }

        // Shannon 熵
        $entropy = 0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        // 归一化到 0-100（最大熵为8 bits/char）
        $normalizedEntropy = min($entropy / 8 * 100, 100);

        // 特殊字符比例
        $specialRatio = 0;
        $specialChars = '<>"\'%;|&`$(){}\\/*%#=*?!';
        for ($i = 0; $i < $len; $i++) {
            if (strpos($specialChars, $text[$i]) !== false) $specialRatio++;
        }
        $specialRatio = ($specialRatio / $len) * 100;

        // 综合分数
        $score = $normalizedEntropy * 0.5 + $specialRatio * 1.5;
        return min(round($score, 1), 100);
    }

    // ====================== 语义分析 (30%) ======================

    /**
     * 调用语义引擎分析
     */
    private static function calcSemantic($text, $uri, $params, $normalizerContext = [], $ip = '') {
        $result = SemanticEngine::analyze($text, $uri, $params, $normalizerContext, $ip);
        return $result;
    }

    // ====================== 编译偏差分析 (25%) ======================

    /**
     * 内置结构分析（原 CompilerEngine 整合）
     * 通过 URI 路径、参数键值对的结构特征评分。
     */
    private static function calcCompiler($text, $uri, $params) {
        $score = 0;

        // 1. URI 异常结构
        $uri = (string)$uri;
        if (strlen($uri) > 200)                       $score += 15;
        if (substr_count($uri, '/') > 8)              $score += 10;
        if (preg_match('/\.\.\//', $uri))             $score += 20;
        if (preg_match('/\.(php|asp|jsp|cgi|env|sql)$/i', $uri)) $score += 10;
        if (preg_match('/(?:union|select|concat|script|onerror|javascript:)/i', $uri)) $score += 25;

        // 2. 参数键名异常
        $suspiciousKeys = ['cmd', 'exec', 'command', 'shell', 'eval', 'code', 'file', 'path', 'url', 'redirect', 'return', 'jump', 'include', 'require'];
        foreach ($params as $k => $v) {
            $lk = strtolower((string)$k);
            foreach ($suspiciousKeys as $s) {
                if (strpos($lk, $s) !== false) { $score += 8; break; }
            }
        }

        // 3. 参数值结构异常
        $val = is_array($params) ? implode(' ', array_map('strval', $params)) : (string)$params;
        $len = strlen($val);
        if ($len > 0) {
            $upperRatio = strlen(preg_replace('/[^A-Z]/', '', $val)) / max($len, 1);
            $digitRatio = strlen(preg_replace('/[^0-9]/', '', $val)) / max($len, 1);
            $symRatio   = strlen(preg_replace('/[a-zA-Z0-9\s]/', '', $val)) / max($len, 1);
            if ($upperRatio > 0.5 && $digitRatio > 0.3) $score += 15;
            if ($symRatio > 0.4)                          $score += 15;
        }

        return min(round($score, 1), 100);
    }

    // ====================== 偏离分析 (30%) ======================

    /**
     * 与历史正常请求对比，检测异常偏离
     */
    private static function calcDeviation($uri, $params, $normalizerContext) {
        $score = 0;

        // 从 AutoLearn 获取偏离分数
        $paramKeys = array_keys($params);
        $deviation = AutoLearn::getDeviationScore($uri, $paramKeys);
        $score += $deviation * 60;

        // 编码复杂度偏离
        $encodingComplexity = $normalizerContext['encoding_complexity'] ?? 0;
        if ($encodingComplexity > 50) {
            $score += 25;
        } elseif ($encodingComplexity > 30) {
            $score += 15;
        } elseif ($encodingComplexity > 10) {
            $score += 5;
        }

        // 编码深度偏离
        $encodingDepth = $normalizerContext['encoding_depth'] ?? 0;
        if ($encodingDepth >= 4) {
            $score += 20;
        } elseif ($encodingDepth >= 2) {
            $score += 10;
        }

        // 双重编码偏离
        if (!empty($normalizerContext['double_encoding_detected'])) {
            $score += 15;
        }

        return min(round($score, 1), 100);
    }

    // ====================== 决策 ======================

    private static function decideAction($score) {
        if ($score >= self::$thresholds['block']) return 'block';
        if ($score >= self::$thresholds['observe']) return 'observe';
        if ($score >= self::$thresholds['log']) return 'log';
        return 'pass';
    }

    public static function getRiskLevel($score) {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 20) return 'low';
        return 'clean';
    }

    /**
     * 获取阈值配置
     */
    public static function getThresholds() {
        return self::$thresholds;
    }

    /**
     * 设置阈值（可从 config 覆盖）
     */
    public static function setThresholds($thresholds) {
        self::$thresholds = array_merge(self::$thresholds, $thresholds);
    }
}
