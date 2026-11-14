<?php
/**
 * YSL语枢-盾甲WAF
 * 作者  : 暗夜铭少
 * 邮箱  : azgq@foxmail.com
 * 网站  : https://waf.duduziy.com
 * 版权  : (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
 * 许可  : MIT -- SPDX-License-Identifier: MIT
 */

/**
 * YSL语枢-盾甲WAF · 中文展示层（v6.5.1）
 *
 * 原则：状态文件、runtime.json、控制端点 JSON 契约里的枚举值一律保留英文原值，
 * 因为状态机判断、外部对接与回归测试都依赖它们；只有「给人看」的页面才做中文映射。
 * 所有映射集中在此文件，避免各页面各写一套导致口径不一致。
 *
 * 刻意不翻译的技术名词：WAF / QPS / IP / AI / DNA / PHP 等用户与运维通用缩写，
 * 以及 attack.log、runtime.json 等真实文件名。要翻译的是 closed / open /
 * enforce / observe / plan / scan 这类「普通用户看不懂」的状态与命令枚举。
 */
declare(strict_types=1);

/** 熔断 / 电路状态枚举 */
function wafCnStateMap(): array {
    return [
        'closed'    => '正常放行',
        'open'      => '熔断中',
        'half_open' => '半开试探',
        'normal'    => '正常运行',
        'degrade'   => '降级运行',
        'emergency' => '紧急降级',
        'circuit'   => '熔断保护',
        'alert'     => '告警中',
        'info'      => '待初始化',
        ''          => '暂无记录',
    ];
}
function wafCnState(string $s): string {
    $m = wafCnStateMap();
    return $m[strtolower(trim($s))] ?? '其他状态';
}

/** 运行模式 */
function wafCnModeMap(): array {
    return ['enforce' => '强制拦截', 'observe' => '观察模式'];
}
function wafCnMode(string $m): string {
    $a = wafCnModeMap();
    return $a[strtolower(trim($m))] ?? '其他模式';
}

/** 防护开关内部名 */
function wafCnGuard(string $g): string {
    $m = [
        'ai'        => 'AI 自学习',
        'fp'        => '叙述性误报复核',
        'tautology' => '布尔恒真加固',
        'bypass'    => '绕过结构加固',
        'errors'    => '错误输出',
    ];
    return $m[$g] ?? '其他开关';
}

/** QPS 配置参数名 */
function wafCnQpsParam(string $p): string {
    $m = [
        'soft'     => '全局软阈值', 'hard'     => '全局硬阈值',
        'ip_soft'  => '单 IP 软阈值', 'ip_hard'  => '单 IP 硬阈值',
        'cooldown' => '熔断冷却秒数', 'enabled' => '保护开关',
    ];
    return $m[$p] ?? '其他参数';
}

/** 触发 / 拦截原因码：与响应页、大屏、控制台共用同一张表 */
function wafCnReasonMap(): array {
    return [
        'sql_boolean_tautology'      => 'SQL 布尔恒真注入',
        'bypass_structure_block'     => '编码 / 混淆绕过结构',
        'taint_tracking_confirmed'   => '污点追踪确认的注入路径',
        'core_evidence_taint'        => '核心证据链污点命中',
        'arbiter_critical'           => '仲裁器判定为危急',
        'arbiter_high'               => '仲裁器判定为高危',
        'malicious_upload'           => '恶意文件上传',
        'payload_too_large'          => '请求体超过上限',
        'magic_gate_blocked'         => '蜜罐入口阻断',
        'circuit_breaker_unavailable'=> '熔断模块异常（故障关闭）',
        'circuit_breaker_open'       => '内核熔断开启',
        'circuit_breaker_qps_exceeded_circuit' => '内核 QPS 熔断',
        'global_qps_soft'            => '全局请求速率超过限流阈值',
        'global_qps_hard'            => '全局请求速率触发保护性熔断',
        'ip_qps_soft'                => '单 IP 请求速率超过限流阈值',
        'ip_qps_hard'                => '单 IP 请求速率触发保护性熔断',
        'circuit_open'               => '节点处于熔断保护期',
        'half_open_failed'           => '半开试探失败，重新熔断',
        'manual_drill'               => '控制台演练触发',
        'kernel_exception'           => '安全内核异常',
        'kernel_missing'             => '安全内核文件缺失',
        'beast_missing'              => '运行环境缺少解密扩展（php-beast）',
        'fp_narrative_override'      => '叙述性文本误报复核放行',
    ];
}
function wafCnReason(string $r): string {
    if ($r === '') { return '—'; }
    $m = wafCnReasonMap();
    return $m[$r] ?? '其他原因';
}

/** 文件 DNA 子命令 */
function wafCnDnaCmd(string $c): string {
    $m = [
        'plan'       => '试算巡检范围',
        'baseline'   => '建立基线',
        'scan'       => '只读巡检',
        'audit'      => '完整性审计',
        'rebaseline' => '重建基线',
        'status'     => '查看状态',
        'selftest'   => '能力自检',
        'restore'    => '从备份还原',
        'watch'      => '守护进程',
    ];
    return $m[$c] ?? '其他命令';
}

/** 控制端点动作名：用于操作审计回显 */
function wafCnAction(string $a): string {
    $m = [
        'state.get' => '读取运行状态', 'control.audit' => '查看控制审计',
        'mode.set' => '切换运行模式', 'guard.set' => '切换防护开关',
        'runtime.reset' => '恢复出厂配置', 'config.body_max' => '调整请求体上限',
        'whitelist.add' => '新增白名单', 'whitelist.del' => '移除白名单',
        'whitelist.clear' => '清空白名单',
        'circuit.reset' => '熔断复位', 'circuit.open' => '熔断演练',
        'circuit.close' => '关闭熔断',
        'qps.config' => '调整限流阈值', 'qps.reset' => '复位限流计数',
        'qps.open' => '演练熔断', 'qps.close' => '强制恢复', 'qps.state' => '读取限流状态',
        'windows.clear' => '清理时间窗口', 'chains.clear' => '清理攻击链会话',
        'honeypot.clear' => '清理蜜罐索引', 'locks.clear' => '清理临时锁',
        'honeypot.enable' => '启用蜜罐（高危）', 'honeypot.disable' => '立即停用蜜罐',
        'honeypot.state' => '读取蜜罐状态',
        'ai.model.reset' => '重置贝叶斯模型', 'ai.queues.clear' => '清空训练队列',
        'ai.fingerprints.clear' => '清空指纹库',
        'logs.rotate' => '归档审计日志', 'logs.export' => '导出审计日志',
        'logs.purge' => '清空审计日志',
        'dna.plan' => '试算巡检范围', 'dna.baseline' => '建立 DNA 基线',
        'dna.scan' => 'DNA 只读巡检', 'dna.audit' => 'DNA 完整性审计',
        'dna.apply' => '处置高置信篡改', 'dna.rebaseline' => '重建 DNA 基线',
        'dna.status' => '查看 DNA 状态', 'dna.selftest' => 'DNA 能力自检',
        'dna.restore' => '从备份还原文件',
        'dna.watch.start' => '启动 DNA 守护', 'dna.watch.stop' => '停止 DNA 守护',
        'key.rotate' => '轮换控制台密钥',
    ];
    return $m[$a] ?? '其他操作';
}

/** 内核审计决策 action → 中文 */
function wafCnDecision(string $a): string {
    $m = [
        'block'      => '拦截', 'challenge' => '挑战验证', 'monitor' => '观察',
        'pass'       => '放行', 'allow'     => '放行', 'log' => '仅记录',
        'not_found'  => '未找到', 'unauthorized' => '未授权',
    ];
    return $m[strtolower($a)] ?? (($a === '') ? '未标注' : '其他决策');
}

/** 蜜罐展示层：默认停用是安全侧，启用中必须带倒计时，绝不裸露英文枚举 */
function wafCnHoneypot(array $h): array {
    $on = !empty($h['enabled']);
    $left = (int)($h['left'] ?? 0);
    return [
        'state' => $on ? 'on' : 'off',
        'label' => $on ? '启用中（高危）' : '已停用（默认）',
        'note'  => $on ? (($h['timed'] ?? false) ? ('剩余 ' . ceil($left / 60) . ' 分钟') : '长期启用') : '不诱捕',
        'lamp'  => $on ? 'danger' : 'off',
    ];
}

/** 蜜罐快照 → 中文键值行（零 JS 控制台用） */
function wafCnHoneypotRows(array $h): array {
    $on = !empty($h['enabled']);
    return [
        ['当前状态',   $on ? '启用中（高危）' : '已停用（默认，安全侧）'],
        ['有效期',     $on ? (($h['timed'] ?? false)
                              ? ((int)($h['left'] ?? 0) . ' 秒后自动停用')
                              : '长期启用（不建议）') : '不适用'],
        ['启用时间',   wafCnTime((int)($h['enabled_at'] ?? 0))],
        ['用途留痕',   (string)($h['reason'] ?? '') !== '' ? (string)$h['reason'] : '暂无'],
        ['审批指纹',   (string)($h['by'] ?? '') !== '' ? (string)$h['by'] : '暂无'],
        ['触碰次数',   (int)($h['hits'] ?? 0) . ' 次（蜜罐命中日志统计）'],
    ];
}

/** 布尔状态 */
function wafCnBool($v, string $on = '已启用', string $off = '已停用'): string {
    if (is_string($v)) { return in_array(strtolower($v), ['0', 'false', 'off', 'no', ''], true) ? $off : $on; }
    return $v ? $on : $off;
}

/** 时间戳 → 北京时间可读文本 */
function wafCnTime(int $ts): string {
    return $ts > 0 ? date('Y-m-d H:i:s', $ts + 8 * 3600) . '（北京时间）' : '暂无';
}

/**
 * 历史操作审计详情的展示归一化。
 * control.log 是只追加的真实记录，中文化之前写入的英文 detail 不能改写文件内容，
 * 但展示时可以把里面的英文状态枚举换成中文，保证用户看到的始终是中文。
 * 只做词级替换，不改动时间、路径、数字与原文语义。
 */
function wafCnAuditDetail(string $s): string {
    $map = [
        'half_open' => '半开试探', 'closed' => '正常放行', 'open' => '熔断中',
        'enforce'   => '强制拦截', 'observe' => '观察模式',
        'degrade'   => '降级运行', 'emergency' => '紧急降级', 'circuit' => '熔断保护',
        'half_open_failed' => '半开试探失败',
    ];
    // 长词先替换，避免 half_open 被 open 抢先切开；动作名里的点号也算词内字符，不能误伤
    $s = strtr($s, ['half_open_failed' => '半开试探失败', 'half_open' => '半开试探']);
    foreach (['closed', 'open', 'enforce', 'observe', 'degrade', 'emergency', 'circuit'] as $k) {
        $s = preg_replace('/(?<![A-Za-z0-9_.])' . preg_quote($k, '/') . '(?![A-Za-z0-9_.])/u', $map[$k], $s) ?? $s;
    }
    // 老记录里的 OK / FAIL 结果标记
    $s = strtr($s, [' OK ' => ' 成功 ', ' FAIL ' => ' 失败 ']);
    return $s;
}

/** 内核熔断快照 JSON → 中文键值行；原始英文键不再直接展示 */
function wafCnCircuitRows(array $j): array {
    $t  = is_array($j['thresholds'] ?? null) ? $j['thresholds'] : [];
    $th = [];
    foreach (['normal', 'degrade', 'emergency', 'circuit'] as $k) {
        if (isset($t[$k])) { $th[] = wafCnState($k) . ' ' . (int)$t[$k] . ' QPS'; }
    }
    $rows = [
        ['熔断状态',   wafCnState((string)($j['state'] ?? ''))],
        ['运行级别',   wafCnState((string)($j['mode'] ?? ''))],
        ['当前请求速率', (int)($j['qps'] ?? 0) . ' 次 / 秒'],
        ['每分钟请求',  number_format((int)($j['rpm'] ?? 0)) . ' 次'],
        ['平均响应耗时', number_format((float)($j['avg_latency_ms'] ?? 0), 1) . ' 毫秒'],
        ['连续失败 / 成功', (int)($j['consecutive_failures'] ?? 0) . ' / '
                            . (int)($j['consecutive_successes'] ?? 0) . ' 次'],
        ['累计请求 / 拒绝', number_format((int)($j['total_requests'] ?? 0)) . ' / '
                            . number_format((int)($j['rejected_requests'] ?? 0)) . ' 次'],
    ];
    if ($th !== []) { $rows[] = ['等级切换阈值', implode(' · ', $th)]; }
    $opened = (int)($j['opened_at'] ?? 0);
    if ($opened > 0) { $rows[] = ['熔断开始时间', wafCnTime($opened)]; }
    $upd = (int)($j['updated_at'] ?? 0);
    if ($upd > 0) { $rows[] = ['快照更新时间', wafCnTime($upd)]; }
    return $rows;
}

/** 接入层 QPS 快照 → 中文键值行 */
function wafCnQpsRows(array $q): array {
    $scope = (string)($q['scope'] ?? '');
    $scopeCn = ['global' => '全局', 'ip' => '单个 IP', '' => '本轮无触发'][$scope] ?? '其他范围';
    $reason = (string)($q['reason'] ?? '');
    return [
        ['保护开关',       wafCnBool($q['enabled'] ?? true)],
        ['熔断状态',       wafCnState((string)($q['state'] ?? 'closed'))],
        ['最近触发原因',   $reason === '' ? '本轮无触发' : wafCnReason($reason)],
        ['触发范围',       $scopeCn],
        ['当前请求速率',   (int)($q['qps'] ?? 0) . ' 次 / 秒'],
        ['窗口峰值',       (int)($q['peak'] ?? 0) . ' 次 / 秒'],
        ['累计请求',       number_format((int)($q['total'] ?? 0)) . ' 次'],
        ['累计拒绝',       number_format((int)($q['rejects'] ?? 0)) . ' 次'],
        ['追踪来源',       (int)($q['ip_tracked'] ?? 0) . ' 个'],
        ['全局阈值（软 / 硬）',  (int)($q['soft'] ?? 0) . ' / ' . (int)($q['hard'] ?? 0) . ' 次 / 秒'],
        ['单 IP 阈值（软 / 硬）', (int)($q['ip_soft'] ?? 0) . ' / ' . (int)($q['ip_hard'] ?? 0) . ' 次 / 秒'],
        ['熔断冷却时长',   (int)($q['cooldown'] ?? 0) . ' 秒'],
        ['剩余冷却',       (int)($q['retry_left'] ?? 0) . ' 秒'],
        ['最近一次限流',   wafCnTime((int)($q['last_429'] ?? 0))],
        ['最近一次熔断',   wafCnTime((int)($q['last_502'] ?? 0))],
    ];
}
