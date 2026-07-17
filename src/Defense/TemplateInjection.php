<?php
defined('ABSPATH') || exit;

class TemplateInjection {
    private static $templatePatterns = [
        ['pattern' => '/\{\{.*?\}\}/', 'name' => 'Jinja2/Twig expression'],
        ['pattern' => '/\{\%.*?\%\}/', 'name' => 'Jinja2/Twig statement'],
        ['pattern' => '/\{\#.*?\#\}/', 'name' => 'Jinja2/Twig comment'],
        ['pattern' => '/\{\$.*?\}/', 'name' => 'Smarty variable'],
        ['pattern' => '/\{\%.*?\%\}/', 'name' => 'Smarty block tag'],
        ['pattern' => '/\{\*.*?\*\}/', 'name' => 'Smarty comment'],
        ['pattern' => '/\{\$smarty\.\w+\}/', 'name' => 'Smarty superglobal'],
        ['pattern' => '/\{\{.*?\.__class__.*?\}\}/', 'name' => 'Template __class__ access'],
        ['pattern' => '/\{\{.*?\.__bases__.*?\}\}/', 'name' => 'Template __bases__ access'],
        ['pattern' => '/\{\{.*?\.__subclasses__\(\).*?\}\}/', 'name' => 'Template __subclasses__ call'],
        ['pattern' => '/\{\{.*?\.__globals__.*?\}\}/', 'name' => 'Template __globals__ access'],
        ['pattern' => '/\{\{.*?\.__init__.*?\}\}/', 'name' => 'Template __init__ access'],
        ['pattern' => '/\{\{.*?\.__dict__.*?\}\}/', 'name' => 'Template __dict__ access'],
        ['pattern' => '/\{\{.*?\.__module__.*?\}\}/', 'name' => 'Template __module__ access'],
        ['pattern' => '/\{\{.*?\.__name__.*?\}\}/', 'name' => 'Template __name__ access'],
        ['pattern' => '/\{\{.*?\.__doc__.*?\}\}/', 'name' => 'Template __doc__ access'],
        ['pattern' => '/\{\{.*?\.__repr__.*?\}\}/', 'name' => 'Template __repr__ access'],
        ['pattern' => '/\{\{.*?\.__str__.*?\}\}/', 'name' => 'Template __str__ access'],
        ['pattern' => '/\{\{.*?\.__hash__.*?\}\}/', 'name' => 'Template __hash__ access'],
        ['pattern' => '/\{\{.*?\.__eq__.*?\}\}/', 'name' => 'Template __eq__ access'],
        ['pattern' => '/\{\{.*?\.__ne__.*?\}\}/', 'name' => 'Template __ne__ access'],
        ['pattern' => '/\{\{.*?\.__lt__.*?\}\}/', 'name' => 'Template __lt__ access'],
        ['pattern' => '/\{\{.*?\.__le__.*?\}\}/', 'name' => 'Template __le__ access'],
        ['pattern' => '/\{\{.*?\.__gt__.*?\}\}/', 'name' => 'Template __gt__ access'],
        ['pattern' => '/\{\{.*?\.__ge__.*?\}\}/', 'name' => 'Template __ge__ access'],
        ['pattern' => '/\{\{.*?\.__bool__.*?\}\}/', 'name' => 'Template __bool__ access'],
        ['pattern' => '/\{\{.*?\.__len__.*?\}\}/', 'name' => 'Template __len__ access'],
        ['pattern' => '/\{\{.*?\.__iter__.*?\}\}/', 'name' => 'Template __iter__ access'],
        ['pattern' => '/\{\{.*?\.__next__.*?\}\}/', 'name' => 'Template __next__ access'],
        ['pattern' => '/\{\{.*?\.__getitem__.*?\}\}/', 'name' => 'Template __getitem__ access'],
        ['pattern' => '/\{\{.*?\.__setitem__.*?\}\}/', 'name' => 'Template __setitem__ access'],
        ['pattern' => '/\{\{.*?\.__delitem__.*?\}\}/', 'name' => 'Template __delitem__ access'],
        ['pattern' => '/\{\{.*?\.__contains__.*?\}\}/', 'name' => 'Template __contains__ access'],
        ['pattern' => '/\{\{.*?\.__getattr__.*?\}\}/', 'name' => 'Template __getattr__ access'],
        ['pattern' => '/\{\{.*?\.__setattr__.*?\}\}/', 'name' => 'Template __setattr__ access'],
        ['pattern' => '/\{\{.*?\.__delattr__.*?\}\}/', 'name' => 'Template __delattr__ access'],
        ['pattern' => '/\{\{.*?\.__call__.*?\}\}/', 'name' => 'Template __call__ access'],
        ['pattern' => '/\{\{.*?\.__enter__.*?\}\}/', 'name' => 'Template __enter__ access'],
        ['pattern' => '/\{\{.*?\.__exit__.*?\}\}/', 'name' => 'Template __exit__ access'],
        ['pattern' => '/\{\{.*?\.__getstate__.*?\}\}/', 'name' => 'Template __getstate__ access'],
        ['pattern' => '/\{\{.*?\.__setstate__.*?\}\}/', 'name' => 'Template __setstate__ access'],
        ['pattern' => '/\{\{.*?\.__reduce__.*?\}\}/', 'name' => 'Template __reduce__ access'],
        ['pattern' => '/\{\{.*?\.__reduce_ex__.*?\}\}/', 'name' => 'Template __reduce_ex__ access'],
        ['pattern' => '/\{\{.*?\.__sizeof__.*?\}\}/', 'name' => 'Template __sizeof__ access'],
        ['pattern' => '/\{\{.*?\.__dir__.*?\}\}/', 'name' => 'Template __dir__ access'],
        ['pattern' => '/\{\{.*?\.__class_getitem__.*?\}\}/', 'name' => 'Template __class_getitem__ access'],
        ['pattern' => '/\{\{.*?\.__match_args__.*?\}\}/', 'name' => 'Template __match_args__ access'],
        ['pattern' => '/\{\{.*?\.__orig_bases__.*?\}\}/', 'name' => 'Template __orig_bases__ access'],
        ['pattern' => '/\{\{.*?\.__parameters__.*?\}\}/', 'name' => 'Template __parameters__ access'],
        ['pattern' => '/\{\{.*?\.__args__.*?\}\}/', 'name' => 'Template __args__ access'],
        ['pattern' => '/\{\{.*?\.__origin__.*?\}\}/', 'name' => 'Template __origin__ access'],
        ['pattern' => '/\{\{.*?\.__annotations__.*?\}\}/', 'name' => 'Template __annotations__ access'],
        ['pattern' => '/\{\{.*?\.__wrapped__.*?\}\}/', 'name' => 'Template __wrapped__ access'],
        ['pattern' => '/\{\{.*?\.__code__.*?\}\}/', 'name' => 'Template __code__ access'],
        ['pattern' => '/\{\{.*?\.__func__.*?\}\}/', 'name' => 'Template __func__ access'],
        ['pattern' => '/\{\{.*?\.__self__.*?\}\}/', 'name' => 'Template __self__ access'],
        ['pattern' => '/\{\{.*?\.__closure__.*?\}\}/', 'name' => 'Template __closure__ access'],
        ['pattern' => '/\{\{.*?\.__defaults__.*?\}\}/', 'name' => 'Template __defaults__ access'],
        ['pattern' => '/\{\{.*?\.__kwdefaults__.*?\}\}/', 'name' => 'Template __kwdefaults__ access'],
        ['pattern' => '/\{\{.*?\.__qualname__.*?\}\}/', 'name' => 'Template __qualname__ access'],
        ['pattern' => '/\{\{.*?\.__import__.*?\}\}/', 'name' => 'Template __import__ access'],
        ['pattern' => '/\{\{.*?\.__build_class__.*?\}\}/', 'name' => 'Template __build_class__ access'],
        ['pattern' => '/\{\{.*?\.__package__.*?\}\}/', 'name' => 'Template __package__ access'],
        ['pattern' => '/\{\{.*?\.__loader__.*?\}\}/', 'name' => 'Template __loader__ access'],
        ['pattern' => '/\{\{.*?\.__spec__.*?\}\}/', 'name' => 'Template __spec__ access'],
        ['pattern' => '/\{\{.*?\.__file__.*?\}\}/', 'name' => 'Template __file__ access'],
        ['pattern' => '/\{\{.*?\.__cached__.*?\}\}/', 'name' => 'Template __cached__ access'],
        ['pattern' => '/\{\{.*?\.__error__.*?\}\}/', 'name' => 'Template __error__ access'],
        ['pattern' => '/\{\{.*?\.__traceback__.*?\}\}/', 'name' => 'Template __traceback__ access'],
        ['pattern' => '/\{\{.*?\.__context__.*?\}\}/', 'name' => 'Template __context__ access'],
        ['pattern' => '/\{\{.*?\.__cause__.*?\}\}/', 'name' => 'Template __cause__ access'],
        ['pattern' => '/\{\{.*?\.__suppress_context__.*?\}\}/', 'name' => 'Template __suppress_context__ access'],
        ['pattern' => '/\{\{.*?\.__traceback_hide__.*?\}\}/', 'name' => 'Template __traceback_hide__ access'],
        ['pattern' => '/\{\{.*?\.__bytes__.*?\}\}/', 'name' => 'Template __bytes__ access'],
        ['pattern' => '/\{\{.*?\.__format__.*?\}\}/', 'name' => 'Template __format__ access'],
        ['pattern' => '/\{\{.*?\.__get__.*?\}\}/', 'name' => 'Template __get__ access'],
        ['pattern' => '/\{\{.*?\.__set__.*?\}\}/', 'name' => 'Template __set__ access'],
        ['pattern' => '/\{\{.*?\.__delete__.*?\}\}/', 'name' => 'Template __delete__ access'],
        ['pattern' => '/\{\{.*?\.__instancecheck__.*?\}\}/', 'name' => 'Template __instancecheck__ access'],
        ['pattern' => '/\{\{.*?\.__subclasscheck__.*?\}\}/', 'name' => 'Template __subclasscheck__ access'],
        ['pattern' => '/\{\{.*?\.__subclasshook__.*?\}\}/', 'name' => 'Template __subclasshook__ access'],
        ['pattern' => '/\{\{.*?\.__prepare__.*?\}\}/', 'name' => 'Template __prepare__ access'],
        ['pattern' => '/\{\{.*?\.__init_subclass__.*?\}\}/', 'name' => 'Template __init_subclass__ access'],
        ['pattern' => '/\{\{.*?\.__abstractmethods__.*?\}\}/', 'name' => 'Template __abstractmethods__ access'],
        ['pattern' => '/\{\{.*?\.__mro__.*?\}\}/', 'name' => 'Template __mro__ access'],
        ['pattern' => '/\{\{.*?\.__base__.*?\}\}/', 'name' => 'Template __base__ access'],
        ['pattern' => '/\{\{.*?\.__weakref__.*?\}\}/', 'name' => 'Template __weakref__ access'],
        ['pattern' => '/\{\{.*?\.__slots__.*?\}\}/', 'name' => 'Template __slots__ access'],
        ['pattern' => '/\{\{.*?\|\s*(safe|escape|trim|lower|upper|capitalize|title|replace|default|sort|unique|reverse|random|first|last|length|sum|min|max|round|int|float|string|list|dict|join|split|format|striptags|truncate|raw|e|nl2br|date|url_encode|url_decode|json_encode|json_decode)\s*\|\s*\}\}/', 'name' => 'Template filter injection'],
        ['pattern' => '/\{\{.*?\|\s*attr\(.*?\)\s*\|\s*\}\}/', 'name' => 'Template attr filter'],
        ['pattern' => '/\{\{.*?\|\s*method\(.*?\)\s*\|\s*\}\}/', 'name' => 'Template method filter'],
        ['pattern' => '/\{\{.*?\.__class__\.__bases__\[0\].__subclasses__\(\).*?\}\}/', 'name' => 'Template class chain traversal'],
        ['pattern' => '/\{\{.*?\.__class__\.__mro__\[1\].__subclasses__\(\).*?\}\}/', 'name' => 'Template mro chain traversal'],
        ['pattern' => '/\{\{.*?\.subclasses\(\).*?\}\}/', 'name' => 'Template subclasses call'],
        ['pattern' => '/\{\{.*?\.__globals__\["__builtins__"\].*?\}\}/', 'name' => 'Template builtins access'],
        ['pattern' => '/\{\{.*?\.__globals__\["os"\].*?\}\}/', 'name' => 'Template os module access'],
        ['pattern' => '/\{\{.*?\.__globals__\["subprocess"\].*?\}\}/', 'name' => 'Template subprocess access'],
        ['pattern' => '/\{\{.*?\.__globals__\["sys"\].*?\}\}/', 'name' => 'Template sys module access'],
        ['pattern' => '/\{\{.*?\.__globals__\["importlib"\].*?\}\}/', 'name' => 'Template importlib access'],
        ['pattern' => '/\{\{.*?\.read\(\).*?\}\}/', 'name' => 'Template file read'],
        ['pattern' => '/\{\{.*?\.write\(.*?\).*?\}\}/', 'name' => 'Template file write'],
        ['pattern' => '/\{\{.*?\.exec\(.*?\).*?\}\}/', 'name' => 'Template exec call'],
        ['pattern' => '/\{\{.*?\.eval\(.*?\).*?\}\}/', 'name' => 'Template eval call'],
        ['pattern' => '/\{\{.*?\.system\(.*?\).*?\}\}/', 'name' => 'Template system call'],
        ['pattern' => '/\{\{.*?\.popen\(.*?\).*?\}\}/', 'name' => 'Template popen call'],
        ['pattern' => '/\{\{.*?\.spawn\(.*?\).*?\}\}/', 'name' => 'Template spawn call'],
        ['pattern' => '/\{\{.*?\.fork\(\).*?\}\}/', 'name' => 'Template fork call'],
        ['pattern' => '/\{\{.*?\.pipe\(\).*?\}\}/', 'name' => 'Template pipe call'],
        ['pattern' => '/\{\{.*?\.dup\(\).*?\}\}/', 'name' => 'Template dup call'],
        ['pattern' => '/\{\{.*?\.dup2\(.*?\).*?\}\}/', 'name' => 'Template dup2 call'],
        ['pattern' => '/\{\{.*?\.close\(\).*?\}\}/', 'name' => 'Template close call'],
        ['pattern' => '/\{\{.*?\.open\(.*?\).*?\}\}/', 'name' => 'Template open call'],
        ['pattern' => '/\{\{.*?\.chmod\(.*?\).*?\}\}/', 'name' => 'Template chmod call'],
        ['pattern' => '/\{\{.*?\.chown\(.*?\).*?\}\}/', 'name' => 'Template chown call'],
        ['pattern' => '/\{\{.*?\.stat\(.*?\).*?\}\}/', 'name' => 'Template stat call'],
        ['pattern' => '/\{\{.*?\.lstat\(.*?\).*?\}\}/', 'name' => 'Template lstat call'],
        ['pattern' => '/\{\{.*?\.fstat\(.*?\).*?\}\}/', 'name' => 'Template fstat call'],
        ['pattern' => '/\{\{.*?\.access\(.*?\).*?\}\}/', 'name' => 'Template access call'],
        ['pattern' => '/\{\{.*?\.listdir\(.*?\).*?\}\}/', 'name' => 'Template listdir call'],
        ['pattern' => '/\{\{.*?\.mkdir\(.*?\).*?\}\}/', 'name' => 'Template mkdir call'],
        ['pattern' => '/\{\{.*?\.rmdir\(.*?\).*?\}\}/', 'name' => 'Template rmdir call'],
        ['pattern' => '/\{\{.*?\.remove\(.*?\).*?\}\}/', 'name' => 'Template remove call'],
        ['pattern' => '/\{\{.*?\.rename\(.*?\).*?\}\}/', 'name' => 'Template rename call'],
        ['pattern' => '/\{\{.*?\.symlink\(.*?\).*?\}\}/', 'name' => 'Template symlink call'],
        ['pattern' => '/\{\{.*?\.link\(.*?\).*?\}\}/', 'name' => 'Template link call'],
        ['pattern' => '/\{\{.*?\.unlink\(.*?\).*?\}\}/', 'name' => 'Template unlink call'],
        ['pattern' => '/\{\{.*?\.readlink\(.*?\).*?\}\}/', 'name' => 'Template readlink call'],
        ['pattern' => '/\{\{.*?\.realpath\(.*?\).*?\}\}/', 'name' => 'Template realpath call'],
        ['pattern' => '/\{\{.*?\.abspath\(.*?\).*?\}\}/', 'name' => 'Template abspath call'],
        ['pattern' => '/\{\{.*?\.path\.join\(.*?\).*?\}\}/', 'name' => 'Template path.join'],
        ['pattern' => '/\{\{.*?\.path\.dirname\(.*?\).*?\}\}/', 'name' => 'Template path.dirname'],
        ['pattern' => '/\{\{.*?\.path\.basename\(.*?\).*?\}\}/', 'name' => 'Template path.basename'],
        ['pattern' => '/\{\{.*?\.path\.exists\(.*?\).*?\}\}/', 'name' => 'Template path.exists'],
        ['pattern' => '/\{\{.*?\.path\.isfile\(.*?\).*?\}\}/', 'name' => 'Template path.isfile'],
        ['pattern' => '/\{\{.*?\.path\.isdir\(.*?\).*?\}\}/', 'name' => 'Template path.isdir'],
        ['pattern' => '/\{\{.*?\.path\.isabs\(.*?\).*?\}\}/', 'name' => 'Template path.isabs'],
        ['pattern' => '/\{\{.*?\.path\.split\(.*?\).*?\}\}/', 'name' => 'Template path.split'],
        ['pattern' => '/\{\{.*?\.path\.splitext\(.*?\).*?\}\}/', 'name' => 'Template path.splitext'],
        ['pattern' => '/\{\{.*?\.path\.expanduser\(.*?\).*?\}\}/', 'name' => 'Template path.expanduser'],
        ['pattern' => '/\{\{.*?\.path\.expandvars\(.*?\).*?\}\}/', 'name' => 'Template path.expandvars'],
        ['pattern' => '/\{\{.*?\.path\.normpath\(.*?\).*?\}\}/', 'name' => 'Template path.normpath'],
        ['pattern' => '/\{\{.*?\.path\.normcase\(.*?\).*?\}\}/', 'name' => 'Template path.normcase'],
        ['pattern' => '/\{\{.*?\.path\.relpath\(.*?\).*?\}\}/', 'name' => 'Template path.relpath'],
        ['pattern' => '/\{\{.*?\.path\.samefile\(.*?\).*?\}\}/', 'name' => 'Template path.samefile'],
        ['pattern' => '/\{\{.*?\.path\.sameopenfile\(.*?\).*?\}\}/', 'name' => 'Template path.sameopenfile'],
        ['pattern' => '/\{\{.*?\.path\.samestat\(.*?\).*?\}\}/', 'name' => 'Template path.samestat'],
        ['pattern' => '/\{\{.*?\.path\.walk\(.*?\).*?\}\}/', 'name' => 'Template path.walk'],
        ['pattern' => '/\{\{.*?\.path\.getsize\(.*?\).*?\}\}/', 'name' => 'Template path.getsize'],
        ['pattern' => '/\{\{.*?\.path\.getmtime\(.*?\).*?\}\}/', 'name' => 'Template path.getmtime'],
        ['pattern' => '/\{\{.*?\.path\.getctime\(.*?\).*?\}\}/', 'name' => 'Template path.getctime'],
        ['pattern' => '/\{\{.*?\.path\.getatime\(.*?\).*?\}\}/', 'name' => 'Template path.getatime'],
        ['pattern' => '/\{\{.*?\.path\.getuid\(.*?\).*?\}\}/', 'name' => 'Template path.getuid'],
        ['pattern' => '/\{\{.*?\.path\.getgid\(.*?\).*?\}\}/', 'name' => 'Template path.getgid'],
        ['pattern' => '/\{\{.*?\.path\.getpwuid\(.*?\).*?\}\}/', 'name' => 'Template path.getpwuid'],
        ['pattern' => '/\{\{.*?\.path\.getgrgid\(.*?\).*?\}\}/', 'name' => 'Template path.getgrgid'],
        ['pattern' => '/\{\{.*?\.path\.readlink\(.*?\).*?\}\}/', 'name' => 'Template path.readlink'],
        ['pattern' => '/\{\{.*?\.path\.realpath\(.*?\).*?\}\}/', 'name' => 'Template path.realpath'],
        ['pattern' => '/\{\{.*?\.path\.abspath\(.*?\).*?\}\}/', 'name' => 'Template path.abspath'],
        ['pattern' => '/\{\{.*?\.path\.normpath\(.*?\).*?\}\}/', 'name' => 'Template path.normpath'],
        ['pattern' => '/\{\{.*?\.path\.normcase\(.*?\).*?\}\}/', 'name' => 'Template path.normcase'],
        ['pattern' => '/\{\{.*?\.path\.relpath\(.*?\).*?\}\}/', 'name' => 'Template path.relpath'],
        ['pattern' => '/\{\{.*?\.path\.samefile\(.*?\).*?\}\}/', 'name' => 'Template path.samefile'],
        ['pattern' => '/\{\{.*?\.path\.sameopenfile\(.*?\).*?\}\}/', 'name' => 'Template path.sameopenfile'],
        ['pattern' => '/\{\{.*?\.path\.samestat\(.*?\).*?\}\}/', 'name' => 'Template path.samestat'],
        ['pattern' => '/\{\{.*?\.path\.walk\(.*?\).*?\}\}/', 'name' => 'Template path.walk'],
        ['pattern' => '/\{\{.*?\.path\.getsize\(.*?\).*?\}\}/', 'name' => 'Template path.getsize'],
        ['pattern' => '/\{\{.*?\.path\.getmtime\(.*?\).*?\}\}/', 'name' => 'Template path.getmtime'],
        ['pattern' => '/\{\{.*?\.path\.getctime\(.*?\).*?\}\}/', 'name' => 'Template path.getctime'],
        ['pattern' => '/\{\{.*?\.path\.getatime\(.*?\).*?\}\}/', 'name' => 'Template path.getatime'],
        ['pattern' => '/\{\{.*?\.path\.getuid\(.*?\).*?\}\}/', 'name' => 'Template path.getuid'],
        ['pattern' => '/\{\{.*?\.path\.getgid\(.*?\).*?\}\}/', 'name' => 'Template path.getgid'],
        ['pattern' => '/\{\{.*?\.path\.getpwuid\(.*?\).*?\}\}/', 'name' => 'Template path.getpwuid'],
        ['pattern' => '/\{\{.*?\.path\.getgrgid\(.*?\).*?\}\}/', 'name' => 'Template path.getgrgid'],
        ['pattern' => '/\{\{.*?\.path\.readlink\(.*?\).*?\}\}/', 'name' => 'Template path.readlink'],
        ['pattern' => '/\{\{.*?\.path\.realpath\(.*?\).*?\}\}/', 'name' => 'Template path.realpath'],
        ['pattern' => '/\{\{.*?\.path\.abspath\(.*?\).*?\}\}/', 'name' => 'Template path.abspath'],
        ['pattern' => '/\{\{.*?\.path\.normpath\(.*?\).*?\}\}/', 'name' => 'Template path.normpath'],
        ['pattern' => '/\{\{.*?\.path\.normcase\(.*?\).*?\}\}/', 'name' => 'Template path.normcase'],
        ['pattern' => '/\{\{.*?\.path\.relpath\(.*?\).*?\}\}/', 'name' => 'Template path.relpath'],
        ['pattern' => '/\{\{.*?\.path\.samefile\(.*?\).*?\}\}/', 'name' => 'Template path.samefile'],
        ['pattern' => '/\{\{.*?\.path\.sameopenfile\(.*?\).*?\}\}/', 'name' => 'Template path.sameopenfile'],
        ['pattern' => '/\{\{.*?\.path\.samestat\(.*?\).*?\}\}/', 'name' => 'Template path.samestat'],
        ['pattern' => '/\{\{.*?\.path\.walk\(.*?\).*?\}\}/', 'name' => 'Template path.walk'],
        ['pattern' => '/\{\{.*?\.path\.getsize\(.*?\).*?\}\}/', 'name' => 'Template path.getsize'],
        ['pattern' => '/\{\{.*?\.path\.getmtime\(.*?\).*?\}\}/', 'name' => 'Template path.getmtime'],
        ['pattern' => '/\{\{.*?\.path\.getctime\(.*?\).*?\}\}/', 'name' => 'Template path.getctime'],
        ['pattern' => '/\{\{.*?\.path\.getatime\(.*?\).*?\}\}/', 'name' => 'Template path.getatime'],
        ['pattern' => '/\{\{.*?\.path\.getuid\(.*?\).*?\}\}/', 'name' => 'Template path.getuid'],
        ['pattern' => '/\{\{.*?\.path\.getgid\(.*?\).*?\}\}/', 'name' => 'Template path.getgid'],
        ['pattern' => '/\{\{.*?\.path\.getpwuid\(.*?\).*?\}\}/', 'name' => 'Template path.getpwuid'],
        ['pattern' => '/\{\{.*?\.path\.getgrgid\(.*?\).*?\}\}/', 'name' => 'Template path.getgrgid'],
    ];

    private static $templateParamNames = [
        'template', 'tpl', 'view', 'layout', 'theme',
        'page', 'content', 'html', 'body', 'fragment',
        'partial', 'include', 'extend', 'block', 'macro',
    ];

    public static function check() {
        $inputs = self::collectInputs();
        foreach ($inputs as $key => $value) {
            $result = self::analyzeValue($key, $value);
            if ($result['is_attack']) {
                waf_block('Template injection detected - ' . $result['reason']);
            }
        }
    }

    private static function collectInputs() {
        $inputs = [];

        foreach ($_GET as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }
        foreach ($_POST as $k => $v) {
            $inputs[strtolower($k)] = (string)$v;
        }

        $body = file_get_contents('php://input');
        if (!empty($body)) {
            $inputs['body'] = $body;

            $json = json_decode($body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
                self::extractJsonValues($json, $inputs);
            }
        }

        return $inputs;
    }

    private static function extractJsonValues($data, &$inputs, $prefix = '') {
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                $key = $prefix . (empty($prefix) ? '' : '.') . $k;
                if (is_array($v) || is_object($v)) {
                    self::extractJsonValues($v, $inputs, $key);
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

        if (in_array($key, self::$templateParamNames)) {
            foreach (self::$templatePatterns as $pattern) {
                if (preg_match($pattern['pattern'], $value)) {
                    return ['is_attack' => true, 'reason' => $pattern['name']];
                }
            }

            if (preg_match('/\{\{.*?\}\}/', $value)) {
                return ['is_attack' => true, 'reason' => 'Template expression detected'];
            }

            if (preg_match('/\{\%.*?\%\}/', $value)) {
                return ['is_attack' => true, 'reason' => 'Template statement detected'];
            }

            if (preg_match('/\{\$.*?\}/', $value)) {
                return ['is_attack' => true, 'reason' => 'Smarty variable detected'];
            }
        }

        return ['is_attack' => false, 'reason' => ''];
    }
}
