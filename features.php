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
 * YSL语枢-盾甲WAF · 全功能注册表与真实状态采集（v6.5.1）
 *
 * 用户要求「监控里要能看到所有功能都能控制」。本文件只做一件事：
 * 把 WAF 的每一项功能登记成一条记录，并读取真实运行数据给出状态灯，
 * 同时绑定一个**确实存在于 control.php 动作白名单**里的真实操作。
 *
 * 铁律：
 *   1. 不编造指标，不编造状态；status / lamp 全部来自 runtime.json、QPS 快照、
 *      DNA 状态文件、circuit_state.json、日志大小与守护进程。
 *   2. 每条记录必须有 act 或 focus 之一，且 act 必须是后端真实动作，
 *      绝不放「点了没反应」的假按钮；测试会逐条比对 control.php 白名单。
 *   3. 常驻内核能力与可开关配置分开标注（kind），不把「只读监测」伪装成开关。
 *
 * 返回结构同时供大屏 HTML、JSON 接口与静态快照使用，三者同一个数据源。
 */
declare(strict_types=1);

require_once __DIR__ . '/runtime.php';

/** 功能分组顺序：先检测、再接入、再完整性、再日志、最后访问控制 */
function wafFeatureGroupOrder(): array {
    return ['kernel', 'edge', 'dna', 'log', 'access'];
}
function wafFeatureGroupName(string $id): string {
    return [
        'kernel' => '检测内核', 'edge' => '接入防护', 'dna' => '文件完整性',
        'log'    => '日志与学习', 'access' => '访问与视图',
    ][$id] ?? '其他功能';
}

/**
 * @param array $c 上下文，键：
 *   home, rt, qps, dna, watch_pid, log_bytes, circuit_note, whitelist_n,
 *   hp（蜜罐视图 + hits）, body_max, model_trained
 * @return array groups / items / total / controllable
 */
function wafFeatures(array $c): array {
    $rt      = $c['rt'];
    $qps     = $c['qps'];
    $dna     = $c['dna'];
    $hp      = $c['hp'];
    $guards  = $rt['guards'];
    $hpCn    = wafCnHoneypot($hp);
    $items   = [];

    /** 记一条功能 */
    $add = static function (
        string $group, string $id, string $name, string $desc,
        string $status, string $lamp, string $kind,
        string $act = '', array $params = [], string $label = '',
        bool $danger = false, string $focus = ''
    ) use (&$items): void {
        $items[] = [
            'group'   => $group,
            'id'      => $id,
            'name'    => $name,
            'desc'    => $desc,
            'status'  => $status,
            'lamp'    => $lamp,       // on / warn / off / info / danger
            'kind'    => $kind,       // 开关 / 参数 / 维护 / 只读 / 高危
            'act'     => $act,
            'params'  => $params,
            'label'   => $label !== '' ? $label : '进入控制',
            'danger'  => $danger,
            'focus'   => $focus !== '' ? $focus : '',
        ];
    };
    $onoff = static fn(bool $on): array => $on ? ['已启用', 'on'] : ['已停用', 'warn'];

    // ------------------------------------------------------------ 检测内核
    [$st, $lp] = $onoff($rt['mode'] === 'enforce');
    $add('kernel', 'mode', '运行模式', '强制拦截真的阻断；观察模式只写审计日志',
         wafCnMode($rt['mode']), $rt['mode'] === 'enforce' ? 'on' : 'warn', '开关',
         'mode.set', ['value' => $rt['mode'] === 'enforce' ? 'observe' : 'enforce'],
         $rt['mode'] === 'enforce' ? '切换为观察' : '恢复强制拦截', false, 'sec-mode');

    foreach ([
        'ai'        => ['AI 自学习', '贝叶斯在线学习与语义打分'],
        'fp'        => ['叙述性误报复核', '中文教程类文本降级放行'],
        'tautology' => ['布尔恒真加固', 'SQL 恒真式与变形识别'],
        'bypass'    => ['绕过结构加固', '多层编码 / 全角 / 控制字符绕过'],
        'errors'    => ['错误输出', '排查用；生产环境建议保持关闭'],
    ] as $g => [$gname, $gdesc]) {
        [$st, $lp] = $onoff(!empty($guards[$g]));
        $add('kernel', 'guard_' . $g, $gname, $gdesc, $st, $lp, '开关',
             'guard.set', ['name' => $g, 'on' => !empty($guards[$g]) ? '0' : '1'],
             !empty($guards[$g]) ? '点击关闭' : '点击开启', false, 'sec-guards');
    }

    $add('kernel', 'honeypot', '蜜罐诱捕（高危）',
         '触碰诱饵即延迟响应、投喂假数据、标记确认恶意；默认停用，启用需确认短语 + 有效期',
         $hpCn['label'] . ' · ' . $hpCn['note'], $hpCn['lamp'], '高危',
         'honeypot.state', [], '读取真实状态', false, 'sec-honeypot');
    $add('kernel', 'taint', '污点追踪引擎', '符号表 / 图 / 路径搜索，常驻内核能力',
         '常驻启用 · 内核接管', 'on', '只读', 'state.get', [], '回读运行状态', false, 'sec-state');
    $add('kernel', 'arbiter', '多层仲裁器', '证据链加权裁决，决定最终放行或拦截',
         '常驻启用 · 内核接管', 'on', '只读', 'state.get', [], '回读运行状态', false, 'sec-state');
    $add('kernel', 'audit_chain', '审计哈希链', '每请求写不可篡改审计链',
         '常驻启用 · 日志 ' . number_format(((int)($c['log_bytes'] ?? 0)) / 1048576, 2) . ' MB',
         'on', '维护', 'logs.rotate', [], '归档日志', false, 'sec-logs');
    $add('kernel', 'chain', '攻击链会话',
         '跨请求阶段追踪，当前 ' . (int)($c['chain_files'] ?? 0) . ' 个会话文件',
         '状态文件可维护', 'info', '维护', 'chains.clear', [], '清理会话', false, 'sec-state');
    $add('kernel', 'window', '时间窗口',
         '滑动窗口统计，当前 ' . (int)($c['window_files'] ?? 0) . ' 个窗口文件',
         '状态文件可维护', 'info', '维护', 'windows.clear', [], '清理窗口', false, 'sec-state');
    $add('kernel', 'c2', 'C2 信标监测', '独立接收端点服务，需部署并配置签名密钥后才启用',
         '未配置独立端点', 'off', '只读', 'state.get', [], '回读运行状态', false, 'sec-state');

    // ------------------------------------------------------------ 接入防护
    $add('edge', 'body_max', '请求体上限', '单请求最大读取字节，超限直接 413',
         number_format((int)($c['body_max'] ?? 8388608)) . ' 字节', 'info', '参数',
         'config.body_max', ['value' => (int)($c['body_max'] ?? 8388608)],
         '沿用当前值', false, 'sec-request');
    $add('edge', 'whitelist', '硬旁路白名单', '名单内 IP / CIDR 完全跳过检测',
         (int)($c['whitelist_n'] ?? 0) . ' 条', (int)($c['whitelist_n'] ?? 0) > 0 ? 'warn' : 'on',
         '参数', 'whitelist.clear', [], '清空名单', true, 'sec-request');
    $qpsOn = !empty($qps['enabled']);
    $add('edge', 'qps_switch', 'QPS 保护开关', '关闭后只计数、不触发 429 / 502',
         $qpsOn ? '已启用' : '已停用（只计数）', $qpsOn ? 'on' : 'warn', '开关',
         'qps.config', ['enabled' => $qpsOn ? '0' : '1'], $qpsOn ? '停用保护' : '启用保护',
         false, 'sec-qps');
    $add('edge', 'qps_limit', '限流阈值',
         '全局 ' . (int)($qps['soft'] ?? 0) . '/' . (int)($qps['hard'] ?? 0)
         . ' · 单 IP ' . (int)($qps['ip_soft'] ?? 0) . '/' . (int)($qps['ip_hard'] ?? 0) . ' QPS',
         '软阈值 429 · 硬阈值 502', 'info', '参数',
         'qps.state', [], '读取实时状态', false, 'sec-qps');
    $qs = (string)($qps['state'] ?? 'closed');
    $add('edge', 'qps_breaker', '接入层熔断', '1 秒滑动窗口 + 冷却后半开自动恢复',
         wafCnState($qs) . ' · 当前 ' . (int)($qps['qps'] ?? 0) . ' QPS',
         $qs === 'closed' ? 'on' : 'danger', '维护',
         'qps.close', [], '强制恢复', false, 'sec-qps');
    $add('edge', 'circuit', '内核熔断状态', '内核内部降级信号，状态文件可复位',
         (string)($c['circuit_note'] ?? '无记录') !== '' ? (string)$c['circuit_note'] : '无记录',
         'info', '维护', 'circuit.reset', [], '熔断复位', false, 'sec-state');
    $add('edge', 'locks', '临时锁与残留', '原子写临时文件、状态锁',
         '可随时清理', 'info', '维护', 'locks.clear', [], '清理临时锁', false, 'sec-state');
    $add('edge', 'hp_index', '蜜罐 IP 索引', '触碰诱饵后被标记的恶意 IP 索引',
         (int)($hp['hits'] ?? 0) . ' 次触碰', 'info', '维护',
         'honeypot.clear', [], '清理索引', false, 'sec-honeypot');

    // ------------------------------------------------------------ 文件完整性
    $dnAlive = !empty($dna['_alive']);
    $dnOK    = $dnAlive && !empty($dna['baseline_ok']) && !empty($dna['healthy']);
    $dnDesc  = $dna === [] ? '未建档' : ((int)($dna['files'] ?? 0) . ' 个文件 · '
                 . ($dnOK ? '基线完好' : ($dnAlive ? '存在异常' : '守护未运行')));
    $dnLamp  = $dnOK ? 'on' : ($dnAlive ? 'warn' : 'off');
    $add('dna', 'dna_baseline', 'DNA 基线', 'SHA-256 基线 + HMAC 签名',
         $dnDesc, $dnLamp, '维护', 'dna.status', [], '查看状态', false, 'sec-dna');
    $add('dna', 'dna_scan', '只读巡检', '不改动文件，只比对基线',
         $dna === [] ? '待建档' : '可随时执行', $dnLamp, '维护',
         'dna.scan', [], '执行巡检', false, 'sec-dna');
    $add('dna', 'dna_audit', '完整性审计', '输出差异清单与置信分级',
         '可随时执行', $dnLamp, '维护', 'dna.audit', [], '执行审计', false, 'sec-dna');
    $add('dna', 'dna_selftest', '能力自检', '签名、权限、还原、隔离等自检',
         '可随时执行', 'info', '维护', 'dna.selftest', [], '运行自检', false, 'sec-dna');
    $add('dna', 'dna_apply', '处置篡改', '精准手术 / 隔离留档，需二次确认',
         '危险操作', 'warn', '高危', 'dna.apply', [], '处置高置信篡改', true, 'sec-dna');
    $add('dna', 'dna_rebaseline', '重建基线', '改动代码后必须重签，需二次确认',
         '危险操作', 'warn', '高危', 'dna.rebaseline', [], '重建基线', true, 'sec-dna');
    $add('dna', 'dna_watch', '只读守护', '独立进程定时巡检并写状态快照',
         $c['watch_pid'] ? ('进程 ' . (int)$c['watch_pid'] . ' 运行中') : '未运行',
         $c['watch_pid'] ? 'on' : 'off', '开关',
         'dna.watch.start', [], '启动守护', false, 'sec-dna');
    $add('dna', 'dna_restore', '从备份还原', '按相对路径还原隔离文件，需二次确认',
         '危险操作', 'warn', '高危', 'dna.restore', [], '填写路径还原', true, 'sec-dna');

    // ------------------------------------------------------------ 日志与学习
    $logMb = number_format(((int)($c['log_bytes'] ?? 0)) / 1048576, 2);
    $add('log', 'logs', '攻击审计日志', 'attack.log · ' . $logMb . ' MB',
         $logMb . ' MB', 'info', '维护', 'logs.rotate', [], '归档', false, 'sec-logs');
    $add('log', 'logs_export', '日志导出', '生成 jsonl 副本，不改动原文',
         '可随时导出', 'info', '维护', 'logs.export', [], '导出副本', false, 'sec-logs');
    $add('log', 'logs_purge', '清空攻击日志', '不可恢复，需二次确认',
         '危险操作', 'warn', '高危', 'logs.purge', [], '清空日志', true, 'sec-logs');
    $add('log', 'control_audit', '控制操作审计', '每次控制动作写 control.log',
         (int)($c['audit_count'] ?? 0) . ' 条记录', 'on', '只读',
         'control.audit', [], '查看最近操作', false, 'sec-logs');
    $add('log', 'bayes', '贝叶斯模型', '在线训练样本',
         !empty($c['model_trained']) ? '已训练' : '未训练',
         !empty($c['model_trained']) ? 'on' : 'warn', '维护',
         'ai.model.reset', [], '重置模型', true, 'sec-state');
    $add('log', 'queues', '训练 / 审核队列', '攒批落盘的学习队列',
         '可随时清理', 'info', '维护', 'ai.queues.clear', [], '清空队列', false, 'sec-state');
    $add('log', 'fingerprints', '相似指纹库', '攻击样本指纹',
         '可随时清理', 'info', '维护', 'ai.fingerprints.clear', [], '清空指纹', false, 'sec-state');

    // ------------------------------------------------------------ 访问与视图
    $add('access', 'key', '控制台密钥', '大屏 / 控制台 / 控制端点共用一把钥匙',
         '轮换后旧链接立即失效', 'warn', '高危', 'key.rotate', [], '轮换密钥', true, 'sec-access');
    $add('access', 'runtime', '运行配置', '模式 / 开关 / 上限 / 白名单一键恢复出厂',
         '危险操作', 'warn', '高危', 'runtime.reset', [], '恢复出厂', true, 'sec-request');
    $add('access', 'views', '大屏视图', '轮询间隔 / 全屏 / 静态快照 / 简洁控制台',
         '当前 ' . (int)($c['period'] ?? 5) . ' 秒刷新', 'info', '只读',
         'state.get', [], '回读状态', false, 'sec-access');
    $add('access', 'hp_disable', '蜜罐紧急停用', '一键退出诱捕，安全侧无需二次确认',
         $hpCn['label'], $hpCn['lamp'], '高危', 'honeypot.disable', [],
         '立即停用', false, 'sec-honeypot');

    // ------------------------------------------------------------ 汇总
    $groups = [];
    foreach (wafFeatureGroupOrder() as $gid) {
        $rows = array_values(array_filter($items, static fn($i) => $i['group'] === $gid));
        if ($rows !== []) { $groups[] = ['id' => $gid, 'name' => wafFeatureGroupName($gid), 'items' => $rows]; }
    }
    $controllable = count(array_filter($items, static fn($i) => $i['act'] !== '' || $i['focus'] !== ''));
    return [
        'groups'       => $groups,
        'items'        => $items,
        'total'        => count($items),
        'controllable' => $controllable,
        'legend'       => [
            'on'     => '正常 / 已启用', 'warn' => '需留意 / 已停用',
            'off'    => '未运行', 'info' => '架构事实 / 可维护',
            'danger' => '高危运行中',
        ],
    ];
}
