<?php
/**
 * L6 逻辑推理引擎（真值表推演 + 表达式求值版）
 *
 * 核心能力：A.Tokenizer+Parser B.真值表推演 C.表达式求值
 *           D.LIKE恒真推理 E.攻击模式检测 F.复杂度评估
 */
defined('ABSPATH') || exit;

class LogicInference {
    const T_EOF='EOF'; const T_ID='ID'; const T_INT='INT'; const T_FLT='FLT';
    const T_STR='STR'; const T_BOOL='BOOL'; const T_NULL='NULL';
    const T_OR='OR'; const T_AND='AND'; const T_NOT='NOT'; const T_LIKE='LIKE';
    const T_EQ='EQ'; const T_NE='NE'; const T_LT='LT'; const T_GT='GT';
    const T_LE='LE'; const T_GE='GE';
    const T_LP='('; const T_RP=')'; const T_SC=';';

    private static $tks = [], $pos = 0;

    /**
     * @param string $text
     * @return array{score:int, details:array, logic_type:string, ...}
     */
    public static function analyze(string $text): array {
        if ($text === '') return self::emptyRes();
        $score = 0; $details = []; $logicType = 'none';
        $findings = array_fill_keys(['tautology','partial_tautology','contradiction',
            'partial_contradiction','eval_true','like_tautology','multi_statement',
            'time_blind','boolean_blind','error_based','comment_truncation'], false);
        $low = function_exists('mb_strtolower') ? mb_strtolower($text,'UTF-8') : strtolower($text);

        $er = self::analyzeExprs($text);
        foreach ($er['f'] as $f) $findings[$f] = true;
        foreach ($er['d'] as $d) $details[] = $d;

        $ar = self::detectAttacks($text);
        foreach ($ar['f'] as $f => $v) if ($v) $findings[$f] = true;
        foreach ($ar['d'] as $d) $details[] = $d;

        $cx = self::complexity($text);
        $score += $cx['score'];
        foreach ($cx['details'] as $d) $details[] = $d;

        $scoreMap = [
            'tautology'=>[50,'恒真式(tautology)','tautology'],
            'partial_tautology'=>[35,'部分恒真(partial_tautology)','partial_tautology'],
            'contradiction'=>[30,'恒假式(contradiction)','contradiction'],
            'partial_contradiction'=>[20,'部分恒假(partial_contradiction)','partial_contradiction'],
            'eval_true'=>[40,'求值为真(eval_true)','eval_true'],
            'like_tautology'=>[35,'LIKE恒真(like_tautology)','like_tautology'],
            'multi_statement'=>[45,'多语句(multi_statement)','multi_statement'],
            'time_blind'=>[40,'时间盲注(time_blind)','time_blind'],
            'error_based'=>[35,'报错注入(error_based)','error_based'],
            'boolean_blind'=>[25,'布尔盲注(boolean_blind)','boolean_blind'],
            'comment_truncation'=>[20,'注释截断',null],
        ];
        foreach ($scoreMap as $k=>$info) {
            if ($findings[$k]) {
                $score += $info[0];
                $details[] = $info[1];
                if ($info[2] !== null && $logicType === 'none') $logicType = $info[2];
            }
        }
        if ($findings['tautology'] && $findings['eval_true']) $score -= 40;

        $fc = count(array_filter($findings));
        if ($fc >= 4) { $score += 20; $details[] = '多模式组合(+20)'; }
        elseif ($fc >= 3) { $score += 12; $details[] = '多模式组合(+12)'; }
        elseif ($fc >= 2) { $score += 6; }

        $score = max(0, min(100, (int)round($score)));
        if ($score === 0 && empty($details)) $details[] = '无逻辑攻击特征';

        return [
            'score'=>$score, 'logic_type'=>$logicType,
            'logic_type_label'=>self::typeLabel($logicType),
            'details'=>$details, 'findings'=>$findings,
            'complexity'=>$cx['metrics'],
            'tautology_count'=>$findings['tautology']?1:0,
            'contradiction_count'=>$findings['contradiction']?1:0,
            'time_blind_count'=>$findings['time_blind']?1:0,
            'error_based_count'=>$findings['error_based']?1:0,
            'boolean_blind_count'=>$findings['boolean_blind']?1:0,
            'total_patterns'=>$fc,
        ];
    }

    /* ===== A. Tokenizer + Parser ===== */
    private static function tokenize(string $s): array {
        $tks = []; $len = strlen($s); $i = 0;
        $kw = ['or'=>self::T_OR,'and'=>self::T_AND,'not'=>self::T_NOT,
            'like'=>self::T_LIKE,'true'=>self::T_BOOL,'false'=>self::T_BOOL,'null'=>self::T_NULL];
        while ($i < $len) {
            $c = $s[$i];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") { $i++; continue; }
            // 注释
            if ($c === '-' && $i+1<$len && $s[$i+1] === '-') {
                $st=$i; while($i<$len && $s[$i]!=="\n") $i++;
                $tks[]=['t'=>'CMT','v'=>substr($s,$st,$i-$st)]; continue;
            }
            if ($c === '/' && $i+1<$len && $s[$i+1] === '*') {
                $st=$i; $i+=2; while($i<$len-1 && !($s[$i]==='*'&&$s[$i+1]==='/')) $i++;
                if ($i<$len-1) $i+=2; $tks[]=['t'=>'CMT','v'=>substr($s,$st,$i-$st)]; continue;
            }
            if ($c === '#') { $st=$i; while($i<$len && $s[$i]!=="\n") $i++;
                $tks[]=['t'=>'CMT','v'=>substr($s,$st,$i-$st)]; continue; }
            // 字符串
            if ($c === "'" || $c === '"') {
                $q = $c; $st = $i; $i++; $v = '';
                while ($i<$len && $s[$i]!==$q) {
                    if ($s[$i]==='\\' && $i+1<$len) { $v.=$s[$i].$s[$i+1]; $i+=2; }
                    else { $v.=$s[$i]; $i++; }
                }
                if ($i<$len) $i++;
                $tks[]=['t'=>self::T_STR,'v'=>$v]; continue;
            }
            // 数字
            if (ctype_digit($c) || ($c==='.' && $i+1<$len && ctype_digit($s[$i+1]))) {
                $st=$i; $dot=false;
                while($i<$len && (ctype_digit($s[$i]) || ($s[$i]==='.' && !$dot))) {
                    if ($s[$i]==='.') $dot=true; $i++;
                }
                $tks[]=['t'=>$dot?self::T_FLT:self::T_INT,'v'=>substr($s,$st,$i-$st)];
                continue;
            }
            // 标识符
            if (ctype_alpha($c) || $c==='_' || $c==='@') {
                $st=$i; while($i<$len && (ctype_alnum($s[$i]) || $s[$i]==='_' || $s[$i]==='@' || $s[$i]==='.')) $i++;
                $w = substr($s,$st,$i-$st); $lw = strtolower($w);
                $tks[]=['t'=>isset($kw[$lw])?$kw[$lw]:self::T_ID,'v'=>$w]; continue;
            }
            // 双字符运算符
            $tc = $i+1<$len ? $c.$s[$i+1] : '';
            $tm = ['=='=>self::T_EQ,'!='=>self::T_NE,'<='=>self::T_LE,'>='=>self::T_GE,'<>'=>self::T_NE];
            if (isset($tm[$tc])) { $tks[]=['t'=>$tm[$tc],'v'=>$tc]; $i+=2; continue; }
            // 单字符
            $sm = ['='=>self::T_EQ,'<'=>self::T_LT,'>'=>self::T_GT,
                '+'=>'+','-'=>'-','*'=>'*','/'=>'/','%'=>'%',
                '('=>self::T_LP,')'=>self::T_RP,';'=>self::T_SC,','=>','];
            if (isset($sm[$c])) { $tks[]=['t'=>$sm[$c],'v'=>$c]; $i++; continue; }
            $i++;
        }
        $tks[]=['t'=>self::T_EOF,'v'=>''];
        return $tks;
    }

    private static function extractCandidates(string $s): array {
        $cands = [];
        foreach (preg_split('/;/', $s) as $stmt) {
            $stmt = trim($stmt); if ($stmt === '') continue;
            if (preg_match('/\b(?:where|having|and|or)\b\s+(.+?)(?:\s+(?:order|group|limit|union|--|#|\/\*|$))/is',
                    ' '.$stmt.' ', $m)) $cands[] = trim($m[1]);
            $cands[] = $stmt;
            if (preg_match_all('/\(((?:[^()]|\([^()]*\))+)\)/', $stmt, $pm))
                foreach ($pm[1] as $pe) $cands[] = trim($pe);
        }
        if (preg_match_all('/([^\s;()]+\s*(?:=|!=|<>|<=?|>=?|like)\s*[^\s;()]+)/i', $s, $cm))
            foreach ($cm[1] as $ce) $cands[] = trim($ce);
        return array_values(array_unique(array_filter($cands, fn($c)=>strlen(trim($c))>=3)));
    }

    private static function analyzeExprs(string $s): array {
        $findings = $details = [];
        foreach (self::extractCandidates($s) as $cand) {
            $r = self::analyzeOne($cand);
            foreach ($r['f'] as $f) $findings[$f] = $f;
            foreach ($r['d'] as $d) $details[] = $d;
        }
        return ['f'=>array_values(array_unique($findings)),
                'd'=>array_values(array_unique($details))];
    }

    private static function analyzeOne(string $expr): array {
        $tks = self::tokenize($expr);
        if (count($tks) <= 2) return ['f'=>[],'d'=>[]];
        self::$tks = $tks; self::$pos = 0;
        $ast = null;
        try { $ast = self::pExpr(); } catch (\Exception $e) { return ['f'=>[],'d'=>[]]; }
        if ($ast === null) return ['f'=>[],'d'=>[]];

        $f = $d = [];
        $hasV = self::hasVar($ast);
        if (!$hasV) {
            $v = self::evalAst($ast);
            if ($v === true) { $f[]='tautology'; $f[]='eval_true'; $d[]='恒真式(求值): '.trim($expr); }
            elseif ($v === false) { $f[]='contradiction'; $d[]='恒假式(求值): '.trim($expr); }
        } else {
            $tr = self::truthTable($ast);
            if ($tr['t']) { $f[]='tautology'; $d[]='恒真式(真值表): '.trim($expr); }
            elseif ($tr['c']) { $f[]='contradiction'; $d[]='恒假式(真值表): '.trim($expr); }
            elseif ($tr['pt']) { $f[]='partial_tautology'; $d[]='部分恒真: '.trim($expr); }
            elseif ($tr['pc']) { $f[]='partial_contradiction'; $d[]='部分恒假: '.trim($expr); }
        }
        if (self::detectLike($ast)) { $f[]='like_tautology'; $d[]='LIKE恒真: '.trim($expr); }
        if (self::detectTypeMis($ast)) { $f[]='partial_tautology'; $d[]='类型不匹配恒真: '.trim($expr); }
        return ['f'=>$f,'d'=>$d];
    }

    /* ----- 递归下降 Parser ----- */
    private static function pExpr() { return self::pOr(); }
    private static function pOr() {
        $l = self::pAnd();
        while (self::peek()['t'] === self::T_OR) {
            self::consume(self::T_OR);
            $l = ['t'=>'bin','op'=>'OR','l'=>$l,'r'=>self::pAnd()];
        }
        return $l;
    }
    private static function pAnd() {
        $l = self::pNot();
        while (self::peek()['t'] === self::T_AND) {
            self::consume(self::T_AND);
            $l = ['t'=>'bin','op'=>'AND','l'=>$l,'r'=>self::pNot()];
        }
        return $l;
    }
    private static function pNot() {
        if (self::peek()['t'] === self::T_NOT) {
            self::consume(self::T_NOT);
            return ['t'=>'un','op'=>'NOT','e'=>self::pNot()];
        }
        return self::pCmp();
    }
    private static function pCmp() {
        $l = self::pArith();
        $cmps = [self::T_EQ,self::T_NE,self::T_LT,self::T_GT,self::T_LE,self::T_GE,self::T_LIKE];
        while (in_array(self::peek()['t'], $cmps, true)) {
            $op = self::peek(); self::consume($op['t']);
            $l = ['t'=>'cmp','op'=>$op['t'],'l'=>$l,'r'=>self::pArith()];
        }
        return $l;
    }
    private static function pArith() {
        $l = self::pTerm();
        while (self::peek()['t']==='+' || self::peek()['t']==='-') {
            $op = self::peek(); self::consume($op['t']);
            $l = ['t'=>'ari','op'=>$op['v'],'l'=>$l,'r'=>self::pTerm()];
        }
        return $l;
    }
    private static function pTerm() {
        $l = self::pUn();
        while (in_array(self::peek()['t'], ['*','/','%'], true)) {
            $op = self::peek(); self::consume($op['t']);
            $l = ['t'=>'ari','op'=>$op['v'],'l'=>$l,'r'=>self::pUn()];
        }
        return $l;
    }
    private static function pUn() {
        if (self::peek()['t'] === '-') {
            self::consume('-');
            return ['t'=>'un','op'=>'-','e'=>self::pUn()];
        }
        if (self::peek()['t'] === '+') { self::consume('+'); return self::pUn(); }
        return self::pPrim();
    }
    private static function pPrim() {
        $tk = self::peek(); $t = $tk['t'];
        if ($t===self::T_INT || $t===self::T_FLT) {
            self::consume($t);
            return ['t'=>'lit','k'=>$t===self::T_INT?'int':'float','v'=>$tk['v']];
        }
        if ($t===self::T_STR) { self::consume($t); return ['t'=>'lit','k'=>'string','v'=>$tk['v']]; }
        if ($t===self::T_BOOL) { self::consume($t);
            return ['t'=>'lit','k'=>'bool','v'=>strtolower($tk['v'])==='true']; }
        if ($t===self::T_NULL) { self::consume($t); return ['t'=>'lit','k'=>'null','v'=>null]; }
        if ($t===self::T_ID) {
            self::consume(self::T_ID); $nm = $tk['v'];
            if (self::peek()['t'] === self::T_LP) {
                self::consume(self::T_LP); $args = [];
                if (self::peek()['t'] !== self::T_RP) {
                    $args[] = self::pExpr();
                    while (self::peek()['t'] === ',') { self::consume(','); $args[] = self::pExpr(); }
                }
                if (self::peek()['t']===self::T_RP) self::consume(self::T_RP);
                return ['t'=>'func','n'=>$nm,'a'=>$args];
            }
            return ['t'=>'id','n'=>$nm];
        }
        if ($t===self::T_LP) {
            self::consume(self::T_LP); $e = self::pExpr();
            if (self::peek()['t']===self::T_RP) self::consume(self::T_RP);
            return $e;
        }
        throw new \Exception('Unexpected token');
    }
    private static function peek() {
        return self::$tks[self::$pos] ?? ['t'=>self::T_EOF,'v'=>''];
    }
    private static function consume($exp) {
        if (self::peek()['t'] !== $exp) throw new \Exception('Expected '.$exp);
        self::$pos++;
    }

    /* ===== C. 表达式求值 ===== */
    private static function evalAst(array $e, array $env = null) {
        $t = $e['t'] ?? '';
        if ($t==='lit') return self::litVal($e);
        if ($t==='id') return $env !== null ? ($env[strtolower($e['n'])] ?? null) : null;
        if ($t==='func') return null;
        if ($t==='un') {
            $v = self::evalAst($e['e'], $env);
            if ($e['op']==='NOT') return $v===null ? null : !$v;
            if ($e['op']==='-') { $n=self::toNum($v); return $n===null?null:-$n; }
            return $v;
        }
        if ($t==='bin') {
            $l = self::evalAst($e['l'], $env); $r = self::evalAst($e['r'], $env);
            if ($e['op']==='AND') return ($l===null||$r===null) ? null : $l&&$r;
            if ($e['op']==='OR') {
                if ($l===true || $r===true) return true;
                if ($l===null || $r===null) return null;
                return $l||$r;
            }
            return null;
        }
        if ($t==='cmp') {
            $l = self::evalAst($e['l'], $env); $r = self::evalAst($e['r'], $env);
            if ($l===null || $r===null) return null;
            return self::doCmp($l, $r, $e['op']);
        }
        if ($t==='ari') return self::evalAri($e, $env);
        return null;
    }

    /** 求值算术表达式（关键突破：5-5=0 → true） */
    private static function evalAri(array $e, array $env = null) {
        $l = self::evalAst($e['l'], $env); $r = self::evalAst($e['r'], $env);
        if ($l===null || $r===null) return null;
        $ln = self::toNum($l); $rn = self::toNum($r);
        if ($ln===null || $rn===null) return null;
        switch ($e['op']) {
            case '+': return $ln+$rn; case '-': return $ln-$rn;
            case '*': return $ln*$rn; case '/': return $rn!=0?$ln/$rn:null;
            case '%': return $rn!=0?fmod($ln,$rn):null;
        }
        return null;
    }

    private static function doCmp($l, $r, string $op) {
        $bn = self::isNum($l) && self::isNum($r);
        $ln = $bn ? self::toNum($l) : null; $rn = $bn ? self::toNum($r) : null;
        if ($op === self::T_LIKE) return self::doLike((string)$l, (string)$r);
        switch ($op) {
            case self::T_EQ: return $bn&&$ln!==null&&$rn!==null ? $ln==$rn : (string)$l===(string)$r;
            case self::T_NE: return $bn&&$ln!==null&&$rn!==null ? $ln!=$rn : (string)$l!==(string)$r;
            case self::T_LT: return $bn&&$ln!==null&&$rn!==null ? $ln<$rn  : (string)$l<(string)$r;
            case self::T_GT: return $bn&&$ln!==null&&$rn!==null ? $ln>$rn  : (string)$l>(string)$r;
            case self::T_LE: return $bn&&$ln!==null&&$rn!==null ? $ln<=$rn : (string)$l<=(string)$r;
            case self::T_GE: return $bn&&$ln!==null&&$rn!==null ? $ln>=$rn : (string)$l>=(string)$r;
        }
        return null;
    }
    private static function doLike(string $v, string $p): bool {
        return (bool)preg_match('#^'.str_replace(['%','_'],['.*','.'],preg_quote($p,'#')).'$#is', $v);
    }
    private static function litVal(array $e) {
        switch ($e['k']??'') {
            case 'int': return (int)$e['v']; case 'float': return (float)$e['v'];
            case 'string': return (string)$e['v']; case 'bool': return (bool)$e['v'];
            case 'null': return null;
        }
        return $e['v'] ?? null;
    }
    private static function isNum($v): bool {
        if (is_int($v)||is_float($v)||is_bool($v)) return true;
        return is_string($v) && is_numeric($v);
    }
    private static function toNum($v) {
        if (is_int($v)||is_float($v)) return $v;
        if (is_bool($v)) return $v?1:0;
        if (is_string($v)&&is_numeric($v)) {
            return (strpos($v,'.')!==false||stripos($v,'e')!==false) ? (float)$v : (int)$v;
        }
        return null;
    }

    /* ===== B. 真值表推演 ===== */
    private static function hasVar(array $e): bool {
        $t = $e['t'] ?? '';
        if ($t==='id') return true;
        if ($t==='func') { foreach($e['a'] as $a) if(self::hasVar($a)) return true; return false; }
        if (isset($e['l']) && self::hasVar($e['l'])) return true;
        if (isset($e['r']) && self::hasVar($e['r'])) return true;
        if (isset($e['e']) && self::hasVar($e['e'])) return true;
        return false;
    }
    private static function truthTable(array $ast): array {
        $vars = self::getVars($ast); $n = count($vars);
        if ($n===0) { $v=self::evalAst($ast); return ['t'=>$v===true,'c'=>$v===false,'pt'=>false,'pc'=>false]; }
        if ($n>5) return self::subClause($ast);
        $isT=true; $isC=true; $total=1<<$n;
        for ($m=0; $m<$total; $m++) {
            $env=[]; for($i=0;$i<$n;$i++) $env[$vars[$i]]=(bool)(($m>>$i)&1);
            $val = self::evalAst($ast, $env);
            if ($val!==true) $isT=false; if ($val!==false) $isC=false;
            if (!$isT && !$isC) break;
        }
        $sc = self::subClause($ast);
        return ['t'=>$isT,'c'=>$isC,'pt'=>$sc['pt'],'pc'=>$sc['pc']];
    }
    private static function getVars(array $ast): array {
        $v=[]; self::getVarsR($ast, $v); return array_values(array_unique($v));
    }
    private static function getVarsR(array $e, array &$v) {
        $t=$e['t']??'';
        if ($t==='id') { $v[]=strtolower($e['n']); return; }
        if ($t==='func') { foreach($e['a'] as $a) self::getVarsR($a,$v); return; }
        if (isset($e['l'])) self::getVarsR($e['l'],$v);
        if (isset($e['r'])) self::getVarsR($e['r'],$v);
        if (isset($e['e'])) self::getVarsR($e['e'],$v);
    }
    private static function subClause(array $ast): array {
        $r = ['pt'=>false,'pc'=>false];
        foreach (self::clauses($ast,'OR') as $c)
            if (!self::hasVar($c) && self::evalAst($c)===true) $r['pt']=true;
        foreach (self::clauses($ast,'AND') as $c)
            if (!self::hasVar($c) && self::evalAst($c)===false) $r['pc']=true;
        return $r;
    }
    private static function clauses(array $e, string $op): array {
        $c=[];
        if (($e['t']??'')==='bin' && ($e['op']??'')===$op) {
            foreach (self::clauses($e['l'],$op) as $x) $c[]=$x;
            foreach (self::clauses($e['r'],$op) as $x) $c[]=$x;
        } else $c[]=$e;
        return $c;
    }

    /* ===== D. LIKE恒真 + 类型不匹配 ===== */
    private static function detectLike(array $e): bool {
        $t=$e['t']??'';
        if ($t==='cmp' && ($e['op']??'')===self::T_LIKE) {
            $l=$e['l']; $r=$e['r'];
            $lv = (($l['t']??'')==='lit') ? self::litVal($l) : null;
            $rv = (($r['t']??'')==='lit') ? self::litVal($r) : null;
            if ($rv!==null && (string)$rv==='%') return true;
            if ($lv!==null && $rv!==null) {
                $ls=(string)$lv; $rs=(string)$rv;
                if ($ls===$rs && strpos($rs,'%')===false && strpos($rs,'_')===false) return true;
                if (self::doLike($ls,$rs)) return true;
            }
        }
        return self::walkAst($e, __FUNCTION__);
    }
    private static function detectTypeMis(array $e): bool {
        $t=$e['t']??'';
        if ($t==='cmp' && ($e['op']??'')===self::T_EQ) {
            $l=$e['l']; $r=$e['r'];
            $lt=$l['t']??''; $rt=$r['t']??'';
            $lN = $lt==='lit' && in_array(($l['k']??''),['int','float'],true);
            $rN = $rt==='lit' && in_array(($r['k']??''),['int','float'],true);
            $lS = $lt==='lit' && ($l['k']??'')==='string';
            $rS = $rt==='lit' && ($r['k']??'')==='string';
            if (($lN&&$rS) || ($rN&&$lS)) {
                $nv = $lN ? self::litVal($l) : self::litVal($r);
                $sv = $lS ? self::litVal($l) : self::litVal($r);
                $sn = self::toNum($sv);
                if ($sn!==null && $nv==$sn) return true;
            }
        }
        return self::walkAst($e, __FUNCTION__);
    }
    private static function walkAst(array $e, string $fn): bool {
        if (isset($e['l']) && self::$fn($e['l'])) return true;
        if (isset($e['r']) && self::$fn($e['r'])) return true;
        if (isset($e['e']) && self::$fn($e['e'])) return true;
        if (isset($e['a'])) foreach($e['a'] as $a) if (self::$fn($a)) return true;
        return false;
    }

    /* ===== E. 攻击模式检测 ===== */
    private static function detectAttacks(string $text): array {
        $f = ['multi_statement'=>false,'time_blind'=>false,'boolean_blind'=>false,
              'error_based'=>false,'comment_truncation'=>false];
        $d = []; $tks = self::tokenize($text); $n = count($tks);

        // 多语句
        $sc=0; $hasAfter=false;
        foreach ($tks as $tk) {
            if ($tk['t']==='CMT') continue;
            if ($tk['t']===self::T_SC) $sc++;
            elseif ($sc>0 && $tk['t']===self::T_ID) {
                if (in_array(strtolower($tk['v']), ['select','insert','update','delete',
                    'drop','alter','create','truncate','exec','execute','declare',
                    'union','waitfor','sleep','benchmark'], true)) { $hasAfter=true; break; }
            }
        }
        if ($sc>=1 && $hasAfter) { $f['multi_statement']=true; $d[]='多语句(堆叠查询)'; }

        // 注释截断
        foreach (array_reverse($tks) as $tk) {
            if ($tk['t']===self::T_EOF) continue;
            if ($tk['t']==='CMT') { $f['comment_truncation']=true; break; }
            if (trim($tk['v'])!=='') break;
        }

        // 时间盲注
        $tfs = ['sleep','benchmark','waitfor','pg_sleep'];
        for ($i=0;$i<$n;$i++) {
            if ($tks[$i]['t']===self::T_ID && in_array(strtolower($tks[$i]['v']),$tfs,true)) {
                for ($j=$i+1;$j<$n;$j++) {
                    if ($tks[$j]['t']===self::T_LP) {
                        $f['time_blind']=true; $d[]='时间盲注: '.strtolower($tks[$i]['v']);
                        break 2;
                    }
                    if ($tks[$j]['t']!=='CMT') break;
                }
            }
        }

        // 报错注入
        $efs = ['extractvalue','updatexml','exp','floor','geometrycollection',
            'multipoint','polygon','st_linefromtext','st_polyfromtext'];
        for ($i=0;$i<$n;$i++) {
            if ($tks[$i]['t']===self::T_ID && in_array(strtolower($tks[$i]['v']),$efs,true)) {
                for ($j=$i+1;$j<$n;$j++) {
                    if ($tks[$j]['t']===self::T_LP) {
                        $f['error_based']=true; $d[]='报错注入: '.strtolower($tks[$i]['v']);
                        break 2;
                    }
                    if ($tks[$j]['t']!=='CMT') break;
                }
            }
        }

        // 布尔盲注
        $ifN=$caseN=$blindN=0;
        $bfs = ['ascii','substring','substr','mid','char_length','length','ord'];
        foreach ($tks as $tk) {
            if ($tk['t']===self::T_ID) {
                $v=strtolower($tk['v']);
                if ($v==='if') $ifN++;
                if ($v==='case') $caseN++;
                if (in_array($v,$bfs,true)) $blindN++;
            }
        }
        if (($ifN||$caseN) && $f['time_blind']) { $f['boolean_blind']=true; $d[]='条件时间盲注(IF/CASE+SLEEP)'; }
        elseif ($blindN>=2) { $f['boolean_blind']=true; $d[]='布尔盲注函数组合'; }

        return ['f'=>$f,'d'=>$d];
    }

    /* ===== F. 复杂度评估 ===== */
    private static function complexity(string $text): array {
        $score=0; $details=[]; $tks=self::tokenize($text);
        $total=count($tks)-1;
        if ($total<5) return ['score'=>0,'details'=>[],
            'metrics'=>['depth'=>0,'op_density'=>0.0,'literal_ratio'=>0.0]];

        // 括号深度
        $d=0; $maxD=0;
        foreach ($tks as $t) {
            if ($t['t']===self::T_LP) { $d++; $maxD=max($maxD,$d); }
            elseif ($t['t']===self::T_RP) $d--;
        }
        if ($maxD>=4) { $score+=8; $details[]='深度嵌套:'.$maxD.'层'; }
        elseif ($maxD>=3) $score+=5; elseif ($maxD>=2) $score+=2;

        // 操作符密度
        $allOps = [self::T_OR,self::T_AND,self::T_NOT,self::T_EQ,self::T_NE,
            self::T_LT,self::T_GT,self::T_LE,self::T_GE,self::T_LIKE,
            '+','-','*','/','%'];
        $opN=0; foreach ($tks as $t) if (in_array($t['t'],$allOps,true)) $opN++;
        $opD = $total>0 ? $opN/$total : 0.0;
        if ($opD>0.30 && $opN>=2) { $score+=6; $details[]='高操作符密度:'.round($opD,2); }
        elseif ($opD>0.20 && $opN>=2) $score+=3;

        // 字面量比例
        $litN=0; foreach ($tks as $t)
            if (in_array($t['t'],[self::T_INT,self::T_FLT,self::T_STR,self::T_BOOL,self::T_NULL],true)) $litN++;
        $litR = $total>0 ? $litN/$total : 0.0;
        if ($litR>0.40 && $opN>=2) { $score+=5; $details[]='高字面量比例:'.round($litR,2); }

        // 逻辑操作符
        $logN=0; foreach ($tks as $t)
            if ($t['t']===self::T_OR || $t['t']===self::T_AND) $logN++;
        if ($logN>=4) { $score+=6; $details[]='多逻辑操作符:'.$logN.'个'; }
        elseif ($logN>=2) $score+=3;

        return ['score'=>min(20,$score),'details'=>$details,
            'metrics'=>['depth'=>$maxD,'op_density'=>round($opD,3),
                'literal_ratio'=>round($litR,3),'op_count'=>$opN,'logic_op_count'=>$logN]];
    }

    /* ===== 辅助 ===== */
    private static function emptyRes(): array {
        return ['score'=>0,'logic_type'=>'none','logic_type_label'=>'无逻辑攻击',
            'details'=>['无逻辑攻击特征'],
            'findings'=>['tautology'=>false,'partial_tautology'=>false,
                'contradiction'=>false,'partial_contradiction'=>false,
                'eval_true'=>false,'like_tautology'=>false,
                'multi_statement'=>false,'time_blind'=>false,
                'boolean_blind'=>false,'error_based'=>false,
                'comment_truncation'=>false],
            'complexity'=>['depth'=>0,'op_density'=>0.0,'literal_ratio'=>0.0],
            'tautology_count'=>0,'contradiction_count'=>0,
            'time_blind_count'=>0,'error_based_count'=>0,
            'boolean_blind_count'=>0,'total_patterns'=>0];
    }
    private static function typeLabel(string $t): string {
        $m = ['none'=>'无逻辑攻击','tautology'=>'恒真式注入','partial_tautology'=>'部分恒真式',
            'contradiction'=>'恒假式注入','partial_contradiction'=>'部分恒假式',
            'eval_true'=>'表达式求值恒真','like_tautology'=>'LIKE恒真注入',
            'multi_statement'=>'多语句注入','time_blind'=>'时间盲注',
            'error_based'=>'报错注入','boolean_blind'=>'布尔盲注'];
        return $m[$t] ?? $t;
    }
}
