#!/bin/bash
# ============================================
# 盾甲 WAF 沙箱管理脚本 (sandbox-manager.sh)
# 用法: ./sandbox-manager.sh <command> [args]
#
# 命令:
#   list           查看隔离文件列表
#   stats          查看隔离统计 + 自动扫描状态
#   scan           手动触发全量扫描
#   analyze <path> 分析指定文件（不隔离）
#   locate <path>  精确定位恶意代码位置
#   restore <id>   恢复指定隔离文件（原路返回）
#   restore-all    恢复所有隔离文件
#   review <id> <action>  人工审核 (approve|false_positive|delete|keep)
#   history        查看扫描历史
#   log            查看沙箱日志
#   help           显示帮助
# ============================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WAF_LOGS="${SCRIPT_DIR}/waf_logs"
SANDBOX_DIR="${WAF_LOGS}/sandbox"
QUARANTINE_DIR="${WAF_LOGS}/quarantine"
SNAPSHOT_FILE="${SANDBOX_DIR}/snapshot.json"
STATS_FILE="${SANDBOX_DIR}/scan_result.json"
HISTORY_FILE="${SANDBOX_DIR}/scan_history.json"
LOCATIONS_FILE="${SANDBOX_DIR}/malicious_locations.json"
MANIFEST_FILE="${QUARANTINE_DIR}/manifest.json"
LOG_FILE="${SANDBOX_DIR}/sandbox.log"

show_help() {
    echo "盾甲 WAF 沙箱管理工具"
    echo ""
    echo "用法: $0 <command> [args]"
    echo ""
    echo "命令:"
    echo "  list                    查看隔离文件列表"
    echo "  stats                   查看隔离统计 + 自动扫描状态"
    echo "  scan                    手动触发全量扫描（通过API）"
    echo "  analyze <path>          分析指定文件（不隔离）"
    echo "  locate <path>           精确定位恶意代码（行号+字符位置）"
    echo "  restore <id>            恢复指定隔离文件（原路返回）"
    echo "  restore-all             恢复所有隔离文件"
    echo "  review <id> <action>    人工审核 (approve|false_positive|delete|keep)"
    echo "  history                 查看扫描历史（最近20次）"
    echo "  log                     查看沙箱日志"
    echo "  snapshot                查看文件快照状态"
    echo "  help                    显示帮助信息"
}

cmd_list() {
    if [ ! -f "$MANIFEST_FILE" ]; then
        echo "暂无隔离文件"
        return 0
    fi
    echo "=========================================="
    echo "  隔离文件列表"
    echo "=========================================="
    python3 -c "
import json, sys
try:
    with open('$MANIFEST_FILE') as f:
        manifest = json.load(f)
    if not manifest:
        print('  暂无隔离文件')
        sys.exit(0)
    for idx, (qid, entry) in enumerate(manifest.items(), 1):
        status_icon = {'pending_review':'[待审核]', 'approved':'[已确认]', 'restored':'[已恢复]', 'false_positive':'[误报]', 'deleted':'[已删除]'}.get(entry.get('status',''), '[?]')
        score = entry.get('analysis',{}).get('score', 0)
        mtype = entry.get('analysis',{}).get('type','unknown')
        print(f'  [{idx}] {status_icon} {qid}')
        print(f'      路径: {entry.get(\"original_path\",\"-\")}')
        print(f'      评分: {score}  类型: {mtype}')
        print(f'      原因: {entry.get(\"reason\",\"-\")}')
        print(f'      时间: {__import__(\"datetime\").datetime.fromtimestamp(entry.get(\"quarantined_at\",0)).strftime(\"%Y-%m-%d %H:%M:%S\")}')
        print()
except Exception as e:
    print(f'  读取失败: {e}')
" 2>/dev/null || cat "$MANIFEST_FILE" | python3 -m json.tool 2>/dev/null || echo "  解析失败，原始内容:" && cat "$MANIFEST_FILE"
    echo "=========================================="
}

cmd_stats() {
    echo "=========================================="
    echo "  沙箱统计"
    echo "=========================================="
    python3 -c "
import json, os, time
# 统计隔离
manifest = {}
if os.path.isfile('$MANIFEST_FILE'):
    with open('$MANIFEST_FILE') as f:
        manifest = json.load(f)
stats = {'total':0, 'pending_review':0, 'approved':0, 'restored':0, 'false_positive':0, 'deleted':0}
for entry in manifest.values():
    stats['total'] += 1
    s = entry.get('status','')
    if s in stats: stats[s] += 1
print(f'  隔离文件总数: {stats[\"total\"]}')
print(f'  待审核: {stats[\"pending_review\"]}  已确认: {stats[\"approved\"]}  已恢复: {stats[\"restored\"]}  误报: {stats[\"false_positive\"]}  已删除: {stats[\"deleted\"]}')

# 扫描结果
if os.path.isfile('$STATS_FILE'):
    with open('$STATS_FILE') as f:
        scan = json.load(f)
    scan_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan.get('scan_time',0)))
    print(f'')
    print(f'  最近扫描: {scan_time}')
    print(f'  扫描文件: {scan.get(\"scanned\",0)}')
    print(f'  恶意文件: {scan.get(\"malicious_count\",0)}')
    print(f'  已隔离: {scan.get(\"quarantined_count\",0)}')
    print(f'  定位数: {scan.get(\"location_count\",0)}')
    print(f'  扫描耗时: {scan.get(\"scan_duration\",0)}s')

# 恶意代码定位
if os.path.isfile('$LOCATIONS_FILE'):
    with open('$LOCATIONS_FILE') as f:
        locs = json.load(f)
    print(f'')
    print(f'  恶意代码定位记录: {len(locs)} 个文件')
    for path, info in locs.items():
        loc_count = len(info.get('locations',[]))
        print(f'    {path} ({loc_count} 处)')

# 快照状态
if os.path.isfile('$SNAPSHOT_FILE'):
    with open('$SNAPSHOT_FILE') as f:
        snap = json.load(f)
    print(f'')
    print(f'  文件快照: {len(snap)} 个文件')
    snap_age = int(time.time() - os.path.getmtime('$SNAPSHOT_FILE'))
    print(f'  快照年龄: {snap_age}秒前')
" 2>/dev/null || echo "  统计解析失败"
    echo "=========================================="
}

cmd_scan() {
    echo "触发全量扫描（通过 API）..."
    echo ""
    echo "方式1 - 通过 Web API:"
    echo "  curl -X POST 'https://your-domain.com/waf-sandbox-api.php?action=scan'"
    echo ""
    echo "方式2 - 通过 PHP CLI:"
    echo "  php -r \"require '$SCRIPT_DIR/../Admin/Sandbox.php'; WafSandbox::init(); print_r(WafSandbox::scanAll());\""
    echo ""
    echo "扫描结果将保存到: $STATS_FILE"
}

cmd_analyze() {
    local path=$1
    if [ -z "$path" ]; then
        echo "错误: 请指定文件路径"
        echo "用法: $0 analyze <path>"
        return 1
    fi
    echo "分析文件: $path"
    echo ""
    echo "通过 PHP CLI 分析:"
    php -r "
        define('ABSPATH', '$SCRIPT_DIR');
        define('WAF_LOG_PATH', '$WAF_LOGS/');
        require '$SCRIPT_DIR/config.php';
        require '$SCRIPT_DIR/../Support/Functions.php';
        require '$SCRIPT_DIR/../Core/Normalizer.php';
        require '$SCRIPT_DIR/../Core/Detector.php';
        require '$SCRIPT_DIR/../Semantic/SemanticEngine.php';
        require '$SCRIPT_DIR/../Admin/Sandbox.php';
        WafNormalizer::init();
        \$result = WafSandbox::analyzeFile('$path');
        echo json_encode(\$result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . PHP_EOL;
    " 2>/dev/null || echo "  PHP CLI 分析失败"
}

cmd_locate() {
    local path=$1
    if [ -z "$path" ]; then
        echo "错误: 请指定文件路径"
        echo "用法: $0 locate <path>"
        return 1
    fi
    echo "精确定位恶意代码: $path"
    echo ""
    php -r "
        define('ABSPATH', '$SCRIPT_DIR');
        define('WAF_LOG_PATH', '$WAF_LOGS/');
        require '$SCRIPT_DIR/config.php';
        require '$SCRIPT_DIR/../Support/Functions.php';
        require '$SCRIPT_DIR/../Core/Normalizer.php';
        require '$SCRIPT_DIR/../Core/Detector.php';
        require '$SCRIPT_DIR/../Semantic/SemanticEngine.php';
        require '$SCRIPT_DIR/../Admin/Sandbox.php';
        WafNormalizer::init();
        \$locations = WafSandbox::locateMaliciousCode('$path');
        if (empty(\$locations)) {
            echo '  未发现恶意代码' . PHP_EOL;
        } else {
            echo '  发现 ' . count(\$locations) . ' 处恶意代码:' . PHP_EOL;
            echo str_repeat('=', 60) . PHP_EOL;
            foreach (\$locations as \$i => \$loc) {
                \$n = \$i + 1;
                echo sprintf('  [%d] 第%d行 第%d-%d字符', \$n, \$loc['line'], \$loc['start_char'], \$loc['end_char']) . PHP_EOL;
                echo sprintf('      规则: %s', \$loc['rule']) . PHP_EOL;
                echo sprintf('      类型: %s  评分: %d', \$loc['attack_type'], \$loc['score']) . PHP_EOL;
                echo sprintf('      代码: %s', \$loc['snippet']) . PHP_EOL;
                echo '' . PHP_EOL;
            }
        }
    " 2>/dev/null || echo "  PHP CLI 定位失败"
}

cmd_restore() {
    local id=$1
    if [ -z "$id" ]; then
        echo "错误: 请指定要恢复的文件ID"
        echo "用法: $0 restore <id>"
        echo "使用 '$0 list' 查看可用文件列表"
        return 1
    fi
    echo "恢复隔离文件: $id"
    echo ""
    php -r "
        define('ABSPATH', '$SCRIPT_DIR');
        define('WAF_LOG_PATH', '$WAF_LOGS/');
        require '$SCRIPT_DIR/config.php';
        require '$SCRIPT_DIR/../Support/Functions.php';
        require '$SCRIPT_DIR/../Admin/Sandbox.php';
        WafSandbox::init();
        \$result = WafSandbox::restoreFile('$id');
        echo \$result ? '  恢复成功' : '  恢复失败' . PHP_EOL;
    " 2>/dev/null || echo "  PHP CLI 执行失败"
}

cmd_restore_all() {
    echo "恢复所有隔离文件..."
    php -r "
        define('ABSPATH', '$SCRIPT_DIR');
        define('WAF_LOG_PATH', '$WAF_LOGS/');
        require '$SCRIPT_DIR/config.php';
        require '$SCRIPT_DIR/../Support/Functions.php';
        require '$SCRIPT_DIR/../Admin/Sandbox.php';
        WafSandbox::init();
        \$count = WafSandbox::restoreAllFiles();
        echo \"  恢复了 {\$count} 个文件\" . PHP_EOL;
    " 2>/dev/null || echo "  PHP CLI 执行失败"
}

cmd_review() {
    local id=$1
    local action=$2
    if [ -z "$id" ] || [ -z "$action" ]; then
        echo "错误: 请指定文件ID和审核动作"
        echo "用法: $0 review <id> <approve|false_positive|delete|keep>"
        return 1
    fi
    local desc=""
    case "$action" in
        approve)        desc="确认恶意，永久删除" ;;
        false_positive) desc="误报，恢复文件" ;;
        delete)         desc="永久删除备份" ;;
        keep)           desc="保留隔离" ;;
        *) echo "错误: 无效动作 $action"; echo "可选: approve | false_positive | delete | keep"; return 1 ;;
    esac
    echo "审核: $id → $action ($desc)"
    php -r "
        define('ABSPATH', '$SCRIPT_DIR');
        define('WAF_LOG_PATH', '$WAF_LOGS/');
        require '$SCRIPT_DIR/config.php';
        require '$SCRIPT_DIR/../Support/Functions.php';
        require '$SCRIPT_DIR/../Admin/Sandbox.php';
        WafSandbox::init();
        \$result = WafSandbox::reviewFile('$id', '$action');
        echo \$result ? '  审核完成' : '  审核失败' . PHP_EOL;
    " 2>/dev/null || echo "  PHP CLI 执行失败"
}

cmd_history() {
    if [ ! -f "$HISTORY_FILE" ]; then
        echo "暂无扫描历史"
        return 0
    fi
    echo "=========================================="
    echo "  扫描历史（最近20次）"
    echo "=========================================="
    python3 -c "
import json, time
with open('$HISTORY_FILE') as f:
    history = json.load(f)
for h in history:
    t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(h.get('scan_time',0)))
    print(f'  {t} | 扫描:{h.get(\"scanned\",0)} 恶意:{h.get(\"malicious_count\",0)} 隔离:{h.get(\"quarantined\",0)} 耗时:{h.get(\"scan_duration\",0)}s')
" 2>/dev/null || cat "$HISTORY_FILE" | python3 -m json.tool
    echo "=========================================="
}

cmd_log() {
    if [ ! -f "$LOG_FILE" ]; then
        echo "暂无沙箱日志"
        return 0
    fi
    echo "=========================================="
    echo "  沙箱日志（最近50条）"
    echo "=========================================="
    tail -50 "$LOG_FILE"
    echo "=========================================="
}

cmd_snapshot() {
    if [ ! -f "$SNAPSHOT_FILE" ]; then
        echo "暂无快照文件"
        return 0
    fi
    python3 -c "
import json, os, time
with open('$SNAPSHOT_FILE') as f:
    snap = json.load(f)
print(f'  快照文件数: {len(snap)}')
snap_age = int(time.time() - os.path.getmtime('$SNAPSHOT_FILE'))
print(f'  快照年龄: {snap_age}秒前 ({snap_age // 60}分钟前)')
print()
# 显示最近修改的5个文件
sorted_files = sorted(snap.items(), key=lambda x: x[1].get('mtime',0), reverse=True)
print('  最近修改的5个文件:')
for path, info in sorted_files[:5]:
    mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.get('mtime',0)))
    print(f'    {mtime} {path}')
" 2>/dev/null || echo "  解析失败"
}

# 主逻辑
case "${1:-help}" in
    list)         cmd_list ;;
    stats)        cmd_stats ;;
    scan)         cmd_scan ;;
    analyze)      cmd_analyze "$2" ;;
    locate)       cmd_locate "$2" ;;
    restore)      cmd_restore "$2" ;;
    restore-all)  cmd_restore_all ;;
    review)       cmd_review "$2" "$3" ;;
    history)      cmd_history ;;
    log)          cmd_log ;;
    snapshot)     cmd_snapshot ;;
    help|--help|-h) show_help ;;
    *) echo "未知命令: $1"; show_help; exit 1 ;;
esac
