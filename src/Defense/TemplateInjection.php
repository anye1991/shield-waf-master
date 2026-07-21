<?php
defined('ABSPATH') || exit;

class TemplateInjection {
    private static $templatePatterns = [
        // 注意：通用的 /\{\{.*?\}\}/ 不在此处，因为会与 Angular/Vue.js 冲突，
        // 通用 {{ }} 仅当内含 dunder 或 Python 内建时才在 analyzeValue 中单独判定
        ['pattern' => '/\{\%.*?\%\}/s', 'name' => 'Jinja2/Twig statement'],
        ['pattern' => '/\{\#.*?\#\}/s', 'name' => 'Jinja2/Twig comment'],
        ['pattern' => '/\{\$.*?\}/s', 'name' => 'Smarty variable'],
        ['pattern' => '/\{\*.*?\*\}/s', 'name' => 'Smarty comment'],
        ['pattern' => '/\{\$smarty\.\w+\}/s', 'name' => 'Smarty superglobal'],
        ['pattern' => '/\{\{.*?\.__class__.*?\}\}/s', 'name' => 'Template __class__ access'],
        ['pattern' => '/\{\{.*?\.__bases__.*?\}\}/s', 'name' => 'Template __bases__ access'],
        ['pattern' => '/\{\{.*?\.__subclasses__\(\).*?\}\}/s', 'name' => 'Template __subclasses__ call'],
        ['pattern' => '/\{\{.*?\.__globals__.*?\}\}/s', 'name' => 'Template __globals__ access'],
        ['pattern' => '/\{\{.*?\.__init__.*?\}\}/s', 'name' => 'Template __init__ access'],
        ['pattern' => '/\{\{.*?\.__dict__.*?\}\}/s', 'name' => 'Template __dict__ access'],
        ['pattern' => '/\{\{.*?\.__module__.*?\}\}/s', 'name' => 'Template __module__ access'],
        ['pattern' => '/\{\{.*?\.__name__.*?\}\}/s', 'name' => 'Template __name__ access'],
        ['pattern' => '/\{\{.*?\.__doc__.*?\}\}/s', 'name' => 'Template __doc__ access'],
        ['pattern' => '/\{\{.*?\.__repr__.*?\}\}/s', 'name' => 'Template __repr__ access'],
        ['pattern' => '/\{\{.*?\.__str__.*?\}\}/s', 'name' => 'Template __str__ access'],
        ['pattern' => '/\{\{.*?\.__hash__.*?\}\}/s', 'name' => 'Template __hash__ access'],
        ['pattern' => '/\{\{.*?\.__eq__.*?\}\}/s', 'name' => 'Template __eq__ access'],
        ['pattern' => '/\{\{.*?\.__ne__.*?\}\}/s', 'name' => 'Template __ne__ access'],
        ['pattern' => '/\{\{.*?\.__lt__.*?\}\}/s', 'name' => 'Template __lt__ access'],
        ['pattern' => '/\{\{.*?\.__le__.*?\}\}/s', 'name' => 'Template __le__ access'],
        ['pattern' => '/\{\{.*?\.__gt__.*?\}\}/s', 'name' => 'Template __gt__ access'],
        ['pattern' => '/\{\{.*?\.__ge__.*?\}\}/s', 'name' => 'Template __ge__ access'],
        ['pattern' => '/\{\{.*?\.__bool__.*?\}\}/s', 'name' => 'Template __bool__ access'],
        ['pattern' => '/\{\{.*?\.__len__.*?\}\}/s', 'name' => 'Template __len__ access'],
        ['pattern' => '/\{\{.*?\.__iter__.*?\}\}/s', 'name' => 'Template __iter__ access'],
        ['pattern' => '/\{\{.*?\.__next__.*?\}\}/s', 'name' => 'Template __next__ access'],
        ['pattern' => '/\{\{.*?\.__getitem__.*?\}\}/s', 'name' => 'Template __getitem__ access'],
        ['pattern' => '/\{\{.*?\.__setitem__.*?\}\}/s', 'name' => 'Template __setitem__ access'],
        ['pattern' => '/\{\{.*?\.__delitem__.*?\}\}/s', 'name' => 'Template __delitem__ access'],
        ['pattern' => '/\{\{.*?\.__contains__.*?\}\}/s', 'name' => 'Template __contains__ access'],
        ['pattern' => '/\{\{.*?\.__getattr__.*?\}\}/s', 'name' => 'Template __getattr__ access'],
        ['pattern' => '/\{\{.*?\.__setattr__.*?\}\}/s', 'name' => 'Template __setattr__ access'],
        ['pattern' => '/\{\{.*?\.__delattr__.*?\}\}/s', 'name' => 'Template __delattr__ access'],
        ['pattern' => '/\{\{.*?\.__call__.*?\}\}/s', 'name' => 'Template __call__ access'],
        ['pattern' => '/\{\{.*?\.__enter__.*?\}\}/s', 'name' => 'Template __enter__ access'],
        ['pattern' => '/\{\{.*?\.__exit__.*?\}\}/s', 'name' => 'Template __exit__ access'],
        ['pattern' => '/\{\{.*?\.__getstate__.*?\}\}/s', 'name' => 'Template __getstate__ access'],
        ['pattern' => '/\{\{.*?\.__setstate__.*?\}\}/s', 'name' => 'Template __setstate__ access'],
        ['pattern' => '/\{\{.*?\.__reduce__.*?\}\}/s', 'name' => 'Template __reduce__ access'],
        ['pattern' => '/\{\{.*?\.__reduce_ex__.*?\}\}/s', 'name' => 'Template __reduce_ex__ access'],
        ['pattern' => '/\{\{.*?\.__sizeof__.*?\}\}/s', 'name' => 'Template __sizeof__ access'],
        ['pattern' => '/\{\{.*?\.__dir__.*?\}\}/s', 'name' => 'Template __dir__ access'],
        ['pattern' => '/\{\{.*?\.__class_getitem__.*?\}\}/s', 'name' => 'Template __class_getitem__ access'],
        ['pattern' => '/\{\{.*?\.__match_args__.*?\}\}/s', 'name' => 'Template __match_args__ access'],
        ['pattern' => '/\{\{.*?\.__orig_bases__.*?\}\}/s', 'name' => 'Template __orig_bases__ access'],
        ['pattern' => '/\{\{.*?\.__parameters__.*?\}\}/s', 'name' => 'Template __parameters__ access'],
        ['pattern' => '/\{\{.*?\.__args__.*?\}\}/s', 'name' => 'Template __args__ access'],
        ['pattern' => '/\{\{.*?\.__origin__.*?\}\}/s', 'name' => 'Template __origin__ access'],
        ['pattern' => '/\{\{.*?\.__annotations__.*?\}\}/s', 'name' => 'Template __annotations__ access'],
        ['pattern' => '/\{\{.*?\.__wrapped__.*?\}\}/s', 'name' => 'Template __wrapped__ access'],
        ['pattern' => '/\{\{.*?\.__code__.*?\}\}/s', 'name' => 'Template __code__ access'],
        ['pattern' => '/\{\{.*?\.__func__.*?\}\}/s', 'name' => 'Template __func__ access'],
        ['pattern' => '/\{\{.*?\.__self__.*?\}\}/s', 'name' => 'Template __self__ access'],
        ['pattern' => '/\{\{.*?\.__closure__.*?\}\}/s', 'name' => 'Template __closure__ access'],
        ['pattern' => '/\{\{.*?\.__defaults__.*?\}\}/s', 'name' => 'Template __defaults__ access'],
        ['pattern' => '/\{\{.*?\.__kwdefaults__.*?\}\}/s', 'name' => 'Template __kwdefaults__ access'],
        ['pattern' => '/\{\{.*?\.__qualname__.*?\}\}/s', 'name' => 'Template __qualname__ access'],
        ['pattern' => '/\{\{.*?\.__import__.*?\}\}/s', 'name' => 'Template __import__ access'],
        ['pattern' => '/\{\{.*?\.__build_class__.*?\}\}/s', 'name' => 'Template __build_class__ access'],
        ['pattern' => '/\{\{.*?\.__package__.*?\}\}/s', 'name' => 'Template __package__ access'],
        ['pattern' => '/\{\{.*?\.__loader__.*?\}\}/s', 'name' => 'Template __loader__ access'],
        ['pattern' => '/\{\{.*?\.__spec__.*?\}\}/s', 'name' => 'Template __spec__ access'],
        ['pattern' => '/\{\{.*?\.__file__.*?\}\}/s', 'name' => 'Template __file__ access'],
        ['pattern' => '/\{\{.*?\.__cached__.*?\}\}/s', 'name' => 'Template __cached__ access'],
        ['pattern' => '/\{\{.*?\.__error__.*?\}\}/s', 'name' => 'Template __error__ access'],
        ['pattern' => '/\{\{.*?\.__traceback__.*?\}\}/s', 'name' => 'Template __traceback__ access'],
        ['pattern' => '/\{\{.*?\.__context__.*?\}\}/s', 'name' => 'Template __context__ access'],
        ['pattern' => '/\{\{.*?\.__cause__.*?\}\}/s', 'name' => 'Template __cause__ access'],
        ['pattern' => '/\{\{.*?\.__suppress_context__.*?\}\}/s', 'name' => 'Template __suppress_context__ access'],
        ['pattern' => '/\{\{.*?\.__traceback_hide__.*?\}\}/s', 'name' => 'Template __traceback_hide__ access'],
        ['pattern' => '/\{\{.*?\.__bytes__.*?\}\}/s', 'name' => 'Template __bytes__ access'],
        ['pattern' => '/\{\{.*?\.__format__.*?\}\}/s', 'name' => 'Template __format__ access'],
        ['pattern' => '/\{\{.*?\.__get__.*?\}\}/s', 'name' => 'Template __get__ access'],
        ['pattern' => '/\{\{.*?\.__set__.*?\}\}/s', 'name' => 'Template __set__ access'],
        ['pattern' => '/\{\{.*?\.__delete__.*?\}\}/s', 'name' => 'Template __delete__ access'],
        ['pattern' => '/\{\{.*?\.__instancecheck__.*?\}\}/s', 'name' => 'Template __instancecheck__ access'],
        ['pattern' => '/\{\{.*?\.__subclasscheck__.*?\}\}/s', 'name' => 'Template __subclasscheck__ access'],
        ['pattern' => '/\{\{.*?\.__subclasshook__.*?\}\}/s', 'name' => 'Template __subclasshook__ access'],
        ['pattern' => '/\{\{.*?\.__prepare__.*?\}\}/s', 'name' => 'Template __prepare__ access'],
        ['pattern' => '/\{\{.*?\.__init_subclass__.*?\}\}/s', 'name' => 'Template __init_subclass__ access'],
        ['pattern' => '/\{\{.*?\.__abstractmethods__.*?\}\}/s', 'name' => 'Template __abstractmethods__ access'],
        ['pattern' => '/\{\{.*?\.__mro__.*?\}\}/s', 'name' => 'Template __mro__ access'],
        ['pattern' => '/\{\{.*?\.__base__.*?\}\}/s', 'name' => 'Template __base__ access'],
        ['pattern' => '/\{\{.*?\.__weakref__.*?\}\}/s', 'name' => 'Template __weakref__ access'],
        ['pattern' => '/\{\{.*?\.__slots__.*?\}\}/s', 'name' => 'Template __slots__ access'],
        ['pattern' => '/\{\{.*?\|\s*(safe|escape|trim|lower|upper|capitalize|title|replace|default|sort|unique|reverse|random|first|last|length|sum|min|max|round|int|float|string|list|dict|join|split|format|striptags|truncate|raw|e|nl2br|date|url_encode|url_decode|json_encode|json_decode)\s*\}\}/s', 'name' => 'Template filter injection'],
        ['pattern' => '/\{\{.*?\|\s*attr\(.*?\)\s*\}\}/s', 'name' => 'Template attr filter'],
        ['pattern' => '/\{\{.*?\|\s*method\(.*?\)\s*\}\}/s', 'name' => 'Template method filter'],
        ['pattern' => '/\{\{.*?\.__class__\.__bases__\[0\]\.__subclasses__\(\).*?\}\}/s', 'name' => 'Template class chain traversal'],
        ['pattern' => '/\{\{.*?\.__class__\.__mro__\[1\]\.__subclasses__\(\).*?\}\}/s', 'name' => 'Template mro chain traversal'],
        ['pattern' => '/\{\{.*?\.subclasses\(\).*?\}\}/s', 'name' => 'Template subclasses call'],
        ['pattern' => '/\{\{.*?\.__globals__\["__builtins__"\].*?\}\}/s', 'name' => 'Template builtins access'],
        ['pattern' => '/\{\{.*?\.__globals__\["os"\].*?\}\}/s', 'name' => 'Template os module access'],
        ['pattern' => '/\{\{.*?\.__globals__\["subprocess"\].*?\}\}/s', 'name' => 'Template subprocess access'],
        ['pattern' => '/\{\{.*?\.__globals__\["sys"\].*?\}\}/s', 'name' => 'Template sys module access'],
        ['pattern' => '/\{\{.*?\.__globals__\["importlib"\].*?\}\}/s', 'name' => 'Template importlib access'],
        ['pattern' => '/\{\{.*?\.read\(\).*?\}\}/s', 'name' => 'Template file read'],
        ['pattern' => '/\{\{.*?\.write\(.*?\).*?\}\}/s', 'name' => 'Template file write'],
        ['pattern' => '/\{\{.*?\.exec\(.*?\).*?\}\}/s', 'name' => 'Template exec call'],
        ['pattern' => '/\{\{.*?\.eval\(.*?\).*?\}\}/s', 'name' => 'Template eval call'],
        ['pattern' => '/\{\{.*?\.system\(.*?\).*?\}\}/s', 'name' => 'Template system call'],
        ['pattern' => '/\{\{.*?\.popen\(.*?\).*?\}\}/s', 'name' => 'Template popen call'],
        ['pattern' => '/\{\{.*?\.spawn\(.*?\).*?\}\}/s', 'name' => 'Template spawn call'],
        ['pattern' => '/\{\{.*?\.fork\(\).*?\}\}/s', 'name' => 'Template fork call'],
        ['pattern' => '/\{\{.*?\.pipe\(\).*?\}\}/s', 'name' => 'Template pipe call'],
        ['pattern' => '/\{\{.*?\.dup\(\).*?\}\}/s', 'name' => 'Template dup call'],
        ['pattern' => '/\{\{.*?\.dup2\(.*?\).*?\}\}/s', 'name' => 'Template dup2 call'],
        ['pattern' => '/\{\{.*?\.close\(\).*?\}\}/s', 'name' => 'Template close call'],
        ['pattern' => '/\{\{.*?\.open\(.*?\).*?\}\}/s', 'name' => 'Template open call'],
        ['pattern' => '/\{\{.*?\.chmod\(.*?\).*?\}\}/s', 'name' => 'Template chmod call'],
        ['pattern' => '/\{\{.*?\.chown\(.*?\).*?\}\}/s', 'name' => 'Template chown call'],
        ['pattern' => '/\{\{.*?\.stat\(.*?\).*?\}\}/s', 'name' => 'Template stat call'],
        ['pattern' => '/\{\{.*?\.lstat\(.*?\).*?\}\}/s', 'name' => 'Template lstat call'],
        ['pattern' => '/\{\{.*?\.fstat\(.*?\).*?\}\}/s', 'name' => 'Template fstat call'],
        ['pattern' => '/\{\{.*?\.access\(.*?\).*?\}\}/s', 'name' => 'Template access call'],
        ['pattern' => '/\{\{.*?\.listdir\(.*?\).*?\}\}/s', 'name' => 'Template listdir call'],
        ['pattern' => '/\{\{.*?\.mkdir\(.*?\).*?\}\}/s', 'name' => 'Template mkdir call'],
        ['pattern' => '/\{\{.*?\.rmdir\(.*?\).*?\}\}/s', 'name' => 'Template rmdir call'],
        ['pattern' => '/\{\{.*?\.remove\(.*?\).*?\}\}/s', 'name' => 'Template remove call'],
        ['pattern' => '/\{\{.*?\.rename\(.*?\).*?\}\}/s', 'name' => 'Template rename call'],
        ['pattern' => '/\{\{.*?\.symlink\(.*?\).*?\}\}/s', 'name' => 'Template symlink call'],
        ['pattern' => '/\{\{.*?\.link\(.*?\).*?\}\}/s', 'name' => 'Template link call'],
        ['pattern' => '/\{\{.*?\.unlink\(.*?\).*?\}\}/s', 'name' => 'Template unlink call'],
        ['pattern' => '/\{\{.*?\.readlink\(.*?\).*?\}\}/s', 'name' => 'Template readlink call'],
        ['pattern' => '/\{\{.*?\.realpath\(.*?\).*?\}\}/s', 'name' => 'Template realpath call'],
        ['pattern' => '/\{\{.*?\.abspath\(.*?\).*?\}\}/s', 'name' => 'Template abspath call'],
        ['pattern' => '/\{\{.*?\.path\.join\(.*?\).*?\}\}/s', 'name' => 'Template path.join'],
        ['pattern' => '/\{\{.*?\.path\.dirname\(.*?\).*?\}\}/s', 'name' => 'Template path.dirname'],
        ['pattern' => '/\{\{.*?\.path\.basename\(.*?\).*?\}\}/s', 'name' => 'Template path.basename'],
        ['pattern' => '/\{\{.*?\.path\.exists\(.*?\).*?\}\}/s', 'name' => 'Template path.exists'],
        ['pattern' => '/\{\{.*?\.path\.isfile\(.*?\).*?\}\}/s', 'name' => 'Template path.isfile'],
        ['pattern' => '/\{\{.*?\.path\.isdir\(.*?\).*?\}\}/s', 'name' => 'Template path.isdir'],
        ['pattern' => '/\{\{.*?\.path\.isabs\(.*?\).*?\}\}/s', 'name' => 'Template path.isabs'],
        ['pattern' => '/\{\{.*?\.path\.split\(.*?\).*?\}\}/s', 'name' => 'Template path.split'],
        ['pattern' => '/\{\{.*?\.path\.splitext\(.*?\).*?\}\}/s', 'name' => 'Template path.splitext'],
        ['pattern' => '/\{\{.*?\.path\.expanduser\(.*?\).*?\}\}/s', 'name' => 'Template path.expanduser'],
        ['pattern' => '/\{\{.*?\.path\.expandvars\(.*?\).*?\}\}/s', 'name' => 'Template path.expandvars'],
        ['pattern' => '/\{\{.*?\.path\.normpath\(.*?\).*?\}\}/s', 'name' => 'Template path.normpath'],
        ['pattern' => '/\{\{.*?\.path\.normcase\(.*?\).*?\}\}/s', 'name' => 'Template path.normcase'],
        ['pattern' => '/\{\{.*?\.path\.relpath\(.*?\).*?\}\}/s', 'name' => 'Template path.relpath'],
        ['pattern' => '/\{\{.*?\.path\.samefile\(.*?\).*?\}\}/s', 'name' => 'Template path.samefile'],
        ['pattern' => '/\{\{.*?\.path\.sameopenfile\(.*?\).*?\}\}/s', 'name' => 'Template path.sameopenfile'],
        ['pattern' => '/\{\{.*?\.path\.samestat\(.*?\).*?\}\}/s', 'name' => 'Template path.samestat'],
        ['pattern' => '/\{\{.*?\.path\.walk\(.*?\).*?\}\}/s', 'name' => 'Template path.walk'],
        ['pattern' => '/\{\{.*?\.path\.getsize\(.*?\).*?\}\}/s', 'name' => 'Template path.getsize'],
        ['pattern' => '/\{\{.*?\.path\.getmtime\(.*?\).*?\}\}/s', 'name' => 'Template path.getmtime'],
        ['pattern' => '/\{\{.*?\.path\.getctime\(.*?\).*?\}\}/s', 'name' => 'Template path.getctime'],
        ['pattern' => '/\{\{.*?\.path\.getatime\(.*?\).*?\}\}/s', 'name' => 'Template path.getatime'],
        ['pattern' => '/\{\{.*?\.path\.readlink\(.*?\).*?\}\}/s', 'name' => 'Template path.readlink'],
        ['pattern' => '/\{\{.*?\.path\.realpath\(.*?\).*?\}\}/s', 'name' => 'Template path.realpath'],
        ['pattern' => '/\{\{.*?\.path\.abspath\(.*?\).*?\}\}/s', 'name' => 'Template path.abspath'],
    ];

    private static $templateParamNames = [
        'template', 'tpl', 'view', 'layout', 'theme',
        'page', 'content', 'html', 'body', 'fragment',
        'partial', 'include', 'extend', 'block', 'macro',
    ];

    // 缓存的合并大正则（首次使用时构建），避免每条输入跑 ~150 条正则
    private static $combinedPattern = null;

    public static function check() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            $result = self::analyzeValue($key, $value);
            if ($result['is_attack']) {
                waf_block('Template injection detected - ' . $result['reason']);
            }
        }
    }

    /**
     * 构建并缓存合并后的 alternation 大正则，用于廉价快速筛除无命中输入。
     * 仅作"是否命中任一模式"的预筛；具体命中名称仍由逐条 preg_match 兜底返回。
     * 使用 patternBody 提取 body（剥离尾部 /flags），合并大正则统一加 /s
     * 修饰符以检测跨行 payload，规避以下 bypass：
     *   {%\n  set x = __class__\n%}
     *   {{\n  ''.__class__.__mro__[1].__subclasses__()\n}}
     */
    private static function getCombinedPattern() {
        if (self::$combinedPattern !== null) {
            return self::$combinedPattern;
        }
        $parts = [];
        foreach (self::$templatePatterns as $p) {
            // 每条单独包裹非捕获组，防止 pattern 内部有顶层 | 破坏整体 alternation 优先级
            $parts[] = '(?:' . self::patternBody($p['pattern']) . ')';
        }
        self::$combinedPattern = '/' . implode('|', $parts) . '/s';
        return self::$combinedPattern;
    }

    /**
     * 把 '/body/flags' 形式的 pattern 解析为 body 与 flags 两部分，
     * 去除尾部 modifiers，避免合并时把 /i /s /m 等修饰符错认作 body。
     * 返回数组 [body, flags]。
     */
    private static function patternSplit($pattern) {
        $lastSlash = strrpos($pattern, '/');
        if ($lastSlash === false || $lastSlash === 0) {
            return [substr($pattern, 1), ''];
        }
        $body = substr($pattern, 1, $lastSlash - 1);
        $flags = substr($pattern, $lastSlash + 1);
        return [$body, $flags];
    }

    /**
     * 仅返回 body（剥离 '/flags'），供合并大正则使用。
     */
    private static function patternBody($pattern) {
        return self::patternSplit($pattern)[0];
    }

    private static function collectInputs() {
        $inputs = [];

        foreach ($_GET as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_POST as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }

        $body = defined('WAF_RAW_BODY') ? WAF_RAW_BODY : file_get_contents('php://input');
        if (!empty($body)) {
            $inputs['body'] = $body;

            $json = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
                self::extractJsonValues($json, $inputs, '', 0);
            }
        }

        return $inputs;
    }

    private static function extractJsonValues($data, &$inputs, $prefix = '', $depth = 0) {
        // 限制递归深度，防止恶意嵌套 JSON 导致栈溢出
        if ($depth > 20) {
            return;
        }
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                // 不使用 empty($prefix) 防止 '0' 被误判
                $key = ($prefix === '' || $prefix === null) ? (string)$k : $prefix . '.' . $k;
                if (is_array($v) || is_object($v)) {
                    self::extractJsonValues($v, $inputs, $key, $depth + 1);
                } else {
                    $inputs[strtolower($key)] = (string)$v;
                }
            }
        }
    }

    private static function analyzeValue($key, $value) {
        $value = trim($value);

        if (empty($value)) {
            return ['is_attack' => false, 'reason' => ''];
        }

        // 长度上限：超过 8KB 只扫前 8KB，避免对超大输入做深度正则扫描
        if (strlen($value) > 8192) {
            $value = substr($value, 0, 8192);
        }

        if (in_array($key, self::$templateParamNames)) {
            // 廉价预筛：不含任何模板标签起始符则跳过整组正则
            // 模板起始符涵盖所有 templatePatterns：{{ {% {# {$ {* 以及 {!!（Laravel Blade，预留）
            if (strpos($value, '{{') === false
                && strpos($value, '{%') === false
                && strpos($value, '{#') === false
                && strpos($value, '{$') === false
                && strpos($value, '{*') === false
                && strpos($value, '{!!') === false) {
                // 无任何模板起始符，必定不命中 templatePatterns，跳过
                return ['is_attack' => false, 'reason' => ''];
            }

            // 合并大正则做一次廉价筛除：无任何命中则跳过逐条循环
            if (!preg_match(self::getCombinedPattern(), $value)) {
                // 大正则未命中，但通用 {{ }} 检测仍需走（templatePatterns 不含通用 {{...}}）
            } else {
                // 大正则命中，逐条匹配找出具体名称并返回
                foreach (self::$templatePatterns as $pattern) {
                    if (preg_match($pattern['pattern'], $value)) {
                        return ['is_attack' => true, 'reason' => $pattern['name']];
                    }
                }
            }

            // 通用 {{ }} 模式与 Angular/Vue.js 冲突，仅当内含 dunder 访问或 Python 内建时才判定
            if (preg_match('/\{\{.*?\}\}/s', $value)) {
                if (preg_match('/__\w+__/', $value)
                    || preg_match('/\b(os|subprocess|sys|importlib|builtins)\b/', $value)) {
                    return ['is_attack' => true, 'reason' => 'Template expression with dangerous attributes'];
                }
            }

            if (preg_match('/\{\%.*?\%\}/s', $value)) {
                return ['is_attack' => true, 'reason' => 'Template statement detected'];
            }

            if (preg_match('/\{\$.*?\}/s', $value)) {
                return ['is_attack' => true, 'reason' => 'Smarty variable detected'];
            }
        }

        return ['is_attack' => false, 'reason' => ''];
    }
}
