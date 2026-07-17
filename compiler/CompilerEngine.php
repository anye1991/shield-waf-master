<?php
defined('ABSPATH') || exit;

/**
 * 编译引擎主类
 *
 * 串联 Layer1-Layer8 共 8 个分析层，对输入文本进行多维度代码级分析，
 * 汇总各层评分与发现，输出综合风险评分、攻击链与攻击者意图。
 */
class CompilerEngine {

    /**
     * 各层权重配置（用于综合评分加权）
     */
    private static $layerWeights = [
        'layer1' => 0.10, // 字符语义
        'layer2' => 0.15, // 词汇语义
        'layer3' => 0.15, // 结构解析
        'layer4' => 0.10, // 参数语义（按命中最大值计入）
        'layer5' => 0.10, // 业务语义
        'layer6' => 0.15, // 逻辑推理
        'layer7' => 0.10, // 意图阶段
        'layer8' => 0.15, // 攻击链
    ];

    /**
     * 编译分析入口
     *
     * @param string $text 待分析文本（已规范化）
     * @return array ['score'=>0-100, 'layers'=>[...], 'attack_chain'=>..., 'intent'=>...]
     */
    public static function compile(string $text): array {
        // 自动加载各层分析器
        if (!class_exists('Layer1_CharSemantics')) {
            $dir = __DIR__;
            require_once $dir . '/Layer1_CharSemantics.php';
            require_once $dir . '/Layer2_WordSemantics.php';
            require_once $dir . '/Layer3_StructureParser.php';
            require_once $dir . '/Layer4_ParamSemantics.php';
            require_once $dir . '/Layer5_BusinessSemantics.php';
            require_once $dir . '/Layer6_LogicInference.php';
            require_once $dir . '/Layer7_IntentAnalyzer.php';
            require_once $dir . '/Layer8_AttackChain.php';
        }

        $result = [
            'score'        => 0,
            'layers'       => [],
            'attack_chain' => [],
            'attack_type'  => 'clean',
            'intent'       => 'benign',
            'block'        => false,
        ];

        if ($text === '') {
            return $result;
        }

        // 依次执行各层分析
        $l1 = Layer1_CharSemantics::analyze($text);
        $l2 = Layer2_WordSemantics::analyze($text);
        $l3 = Layer3_StructureParser::analyze($text);
        // Layer4 在 compile 主入口中按整体文本作为单值评估，参数级由调用方单独触发
        $l4 = Layer4_ParamSemantics::analyze('', $text);
        $l5 = Layer5_BusinessSemantics::analyze('', ['_text' => $text]);
        $l6 = Layer6_LogicInference::analyze($text);
        $l7 = Layer7_IntentAnalyzer::analyze($text);
        $l8 = Layer8_AttackChain::analyze($text);

        $result['layers'] = [
            'layer1' => $l1,
            'layer2' => $l2,
            'layer3' => $l3,
            'layer4' => $l4,
            'layer5' => $l5,
            'layer6' => $l6,
            'layer7' => $l7,
            'layer8' => $l8,
        ];

        // 综合评分：加权求和
        $weighted = 0;
        foreach (self::$layerWeights as $key => $weight) {
            $layerScore = $result['layers'][$key]['score'] ?? 0;
            $weighted += $layerScore * $weight;
        }

        // 取最大层分数作为下限，避免加权平均稀释强信号
        $maxLayer = 0;
        foreach ($result['layers'] as $layer) {
            if (isset($layer['score']) && $layer['score'] > $maxLayer) {
                $maxLayer = $layer['score'];
            }
        }

        $finalScore = max($weighted, $maxLayer * 0.7);

        // 多层共振加分：多个层都检测到风险时，置信度更高
        $riskLayerCount = 0;
        foreach ($result['layers'] as $layer) {
            if (isset($layer['score']) && $layer['score'] >= 40) {
                $riskLayerCount++;
            }
        }
        if ($riskLayerCount >= 5) {
            $finalScore += 15;
        } elseif ($riskLayerCount >= 3) {
            $finalScore += 8;
        } elseif ($riskLayerCount >= 2) {
            $finalScore += 4;
        }

        $finalScore = max(0, min(100, $finalScore));
        $result['score'] = (int) round($finalScore);

        // 攻击链：直接复用 Layer8 的链
        $result['attack_chain'] = $l8['chain'];
        $result['attack_type']  = $l8['attack_type'];
        $result['block']        = $l8['block'] || $finalScore >= 70;

        // 攻击者意图：综合 Layer6 推理与 Layer7 阶段
        $intents = [];
        if (!empty($l6['inferences'])) {
            foreach ($l6['inferences'] as $inf) {
                if (isset($inf['type']) && $inf['type'] === 'intent' && !empty($inf['intents'])) {
                    foreach ($inf['intents'] as $it) {
                        $intents[$it] = true;
                    }
                }
            }
        }
        if (!empty($l7['stage']) && $l7['stage'] !== 'benign') {
            $intents['stage:' . $l7['stage']] = true;
        }
        $result['intent'] = empty($intents) ? 'benign' : implode('|', array_keys($intents));

        return $result;
    }

    /**
     * 编译分析：基于 URI + 参数集合
     *
     * 与 compile(string) 不同，本方法接受完整的请求上下文，
     * 会对每个参数独立执行 Layer4 评估，再综合各层结果。
     *
     * @param string $uri    请求 URI
     * @param array  $params 参数键值对
     * @return array
     */
    public static function compileRequest(string $uri, array $params = []): array {
        // 拼接整体文本用于通用层分析
        $text = $uri;
        $paramResults = [];
        $maxParamScore = 0;
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_UNICODE);
            }
            $value = (string) $value;
            $text .= ' ' . $value;
            $pr = Layer4_ParamSemantics::analyze((string) $key, $value);
            $paramResults[$key] = $pr;
            if ($pr['score'] > $maxParamScore) {
                $maxParamScore = $pr['score'];
            }
        }

        $base = self::compile($text);

        // 用 Layer5 业务语义覆盖基础 Layer5（compile 内部用的是空 URI）
        $base['layers']['layer5'] = Layer5_BusinessSemantics::analyze($uri, $params);
        // 用 Layer4 参数级结果覆盖
        $base['layers']['layer4'] = [
            'score'   => $maxParamScore,
            'params'  => $paramResults,
        ];

        // 重算综合分
        $weighted = 0;
        foreach (self::$layerWeights as $key => $weight) {
            $layerScore = $base['layers'][$key]['score'] ?? 0;
            $weighted += $layerScore * $weight;
        }
        $maxLayer = 0;
        foreach ($base['layers'] as $layer) {
            if (isset($layer['score']) && $layer['score'] > $maxLayer) {
                $maxLayer = $layer['score'];
            }
        }
        $finalScore = max($weighted, $maxLayer * 0.7);
        $finalScore = max(0, min(100, $finalScore));
        $base['score'] = (int) round($finalScore);
        $base['block'] = $base['block'] || $finalScore >= 70;

        return $base;
    }
}
