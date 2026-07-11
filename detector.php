<?php
defined('ABSPATH') || exit;

function waf_is_attack($clean) {
    $static_rules = [
        'union select', 'or 1=1', 'and 1=1', 'or 1=2', 'and 1=2',
        'insert into', 'drop table', 'alter table', 'delete from',
        'sleep(', 'benchmark(', 'waitfor delay',
        '../', '..\\',
        'onerror=', 'onload=', 'onclick=', '<script', 'javascript:',
        'eval(', 'system(', 'exec(', 'shell_exec', 'passthru',
        'popen', 'proc_open', '<?php', '<?=', '<?=',
    ];
    foreach ($static_rules as $rule) {
        if (strpos($clean, $rule) !== false) return true;
    }
    $patterns = [
        '/\b(?:union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|alter\s+table|delete\s+from)\b/iu',
        '/\b(?:or|and)\s+[\d\w]+\s*=\s*[\d\w]+/iu',
        '/\b(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b/iu',
        '/\/\*.*?\*\//iu',
        '/\.{2,}[\/\\\\]/',
        '/\b(?:onerror|onload|onclick|script|javascript|eval|expression)\b/iu',
        '/\b(?:eval\s*\(|system\s*\(|exec\s*\(|shell_exec|passthru|popen|proc_open)\b/iu',
        '/<\?php|<\?=/iu',
        '/<!ENTITY\s+[^>]+SYSTEM/iu',
        '/<\?xml[^>]+encoding/iu',
    ];
    foreach ($patterns as $p) {
        if (preg_match($p, $clean)) return true;
    }
    return false;
}