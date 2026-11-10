#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 暗夜铭少 and the YSL语枢-盾甲WAF contributors
# YSL语枢-盾甲WAF · 误报治理回归（HTTP 端到端）
#
# 前置：先启动带 auto_prepend_file 的服务，例如
#   WAF_HOME=/app php -d auto_prepend_file=/app/shield-waf.php -S 0.0.0.0:8080 -t /app/demo
# 用法：
#   WAF_URL=http://127.0.0.1:8080 bash tests/fp_regression.sh
#
# 期望：完整 AI 模式下 9 条误报/正常文本 200，28 条真实攻击 403（共 37 条断言）。
# 若设置 WAF_FP_GUARD=0 或 WAF_AI_ENABLED=0，前 6 条误报应回到 403（补丁可回退）。
# 布尔恒真式加固由 WAF_TAUTOLOGY_GUARD=0 单独回退，
# 绕过结构加固由 WAF_BYPASS_GUARD=0 单独回退，均不依赖 AI/语义层。
# v6.0.2 新增：中文叙述性误报（arbiter 分支复核）+ 9 类 Docker 压测暴露的漏放结构。
set -u

BASE="${WAF_URL:-http://127.0.0.1:8080}"
FP_EXPECT="${FP_EXPECT:-200}"

cases=(
"$FP_EXPECT|误报1 union 数学叙述|/?q=The%20union%20of%20two%20sets%20A%20and%20B"
"$FP_EXPECT|误报2 script 文档说明|/?doc=The%20tag%20%3Cscript%3E%20is%20used%20to%20embed%20JavaScript%20in%20HTML"
"$FP_EXPECT|说明文字变体|/?q=%3Cscript%3E%20is%20a%20tag%20used%20in%20HTML%20documents"
"$FP_EXPECT|普通英文长句|/?q=Please%20select%20a%20shipping%20address%20for%20your%20order%20today"
"$FP_EXPECT|文档含 documents 单词|/?q=HTML%20documents%20describe%20how%20to%20use%20the%20script%20element"
"200|正常首页|/"
"200|正常参数|/?id=12"
"403|真 SQLi|/?id=1%27%20OR%201%3D1--"
"403|真 XSS script 执行|/?x=%3Cscript%3Ealert(1)%3C/script%3E"
"403|document.cookie 执行|/?x=%3Cscript%3Edocument.cookie%3C/script%3E"
"403|window.location 执行|/?x=%3Cscript%3Ewindow.location%3D%27x%27%3C/script%3E"
"403|真 UNION SELECT|/?q=UNION%20SELECT%20password%20FROM%20users"
"403|真 路径穿越|/?p=..%2F..%2Fetc%2Fpasswd"
"403|真 img onerror|/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
"403|真 命令注入|/?cmd=%3Bcat%20%2Fetc%2Fshadow"
"403|叙述包裹真攻击|/?q=The%20union%20of%20two%20sets%20%27%20OR%201%3D1--"
"403|script 说明+执行|/?q=The%20tag%20%3Cscript%3Ealert(1)%3C/script%3E%20is%20used%20in%20HTML"
"403|真 编码路径穿越|/?p=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
"403|XSS 事件属性|/?q=%3Cdiv%20onmouseover%3Dalert(1)%3Ehi%3C/div%3E"
"403|无引号布尔注入（加固）|/?id=1%20OR%201%3D1"
"403|无引号布尔注入变体|/?id=1%20and%202%3E1"
"403|引号恒真式|/?id=x%27%20OR%20%271%27%3D%271"
"403|布尔注入带注释|/?id=1%20OR%201%3D1--"
"403|SQL 注释拆分绕过|/?q=UN%2F%2A%2A%2FION%20SEL%2F%2A%2A%2FECT%20password%20FROM%20users"
"403|JNDI 表达式注入|/?q=%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D"
"403|PHP 流包装器包含|/?f=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php"
"200|超长正常文本|/?q=This%20is%20a%20perfectly%20normal%20paragraph%20about%20web%20application%20firewalls%20and%20how%20they%20inspect%20incoming%20HTTP%20requests%20for%20suspicious%20patterns%20in%20order%20to%20protect%20the%20underlying%20application"
"$FP_EXPECT|中文 SQL 教程叙述（arbiter 复核）|/?q=%E6%9C%AC%E6%AE%B5%E6%96%87%E5%AD%97%E5%8C%85%E5%90%AB%20select%E3%80%81from%E3%80%81where%20%E7%AD%89%20SQL%20%E6%95%99%E7%A8%8B%E8%AF%8D%E6%B1%87%EF%BC%8C%E4%BD%86%E6%B2%A1%E6%9C%89%E6%94%BB%E5%87%BB%E7%BB%93%E6%9E%84"
"403|metadata SSRF|/?u=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
"403|gopher 协议|/?u=gopher%3A%2F%2F127.0.0.1%3A6379%2F_INFO"
"403|dict 协议|/?u=dict%3A%2F%2F127.0.0.1%3A11211%2Fstats"
"403|Java 序列化 magic|/?d=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ%3D%3D"
"403|pickle 反序列化骨架|/?d=cos%5Cnsystem%5Cn%28S%22id%22%5CntR."
"403|CRLF 头注入|/?q=abc%0D%0ALocation%3A%20http%3A%2F%2Fevil"
"403|LDAP 注入骨架|/?q=%27%29%28cn%3D%2A%29%28%7C%28objectClass%3D%2A"
"403|HTTP 参数污染 HPP|/?q=id%3D1%26id%3D2%26id%3D3"
"403|CRLF + 参数污染|/?q=%3Fa%3D1%26b%3D2%0D%0AX-Injected%3A1"
)

pass=0
fail=0
for t in "${cases[@]}"; do
  exp="${t%%|*}"
  rest="${t#*|}"
  label="${rest%%|*}"
  url="${rest#*|}"
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE$url")"
  if [ "$code" = "$exp" ]; then
    printf '[ OK ] 期望 %s 实际 %s  %s\n' "$exp" "$code" "$label"
    pass=$((pass + 1))
  else
    printf '[FAIL] 期望 %s 实际 %s  %s\n' "$exp" "$code" "$label"
    fail=$((fail + 1))
  fi
done

printf '\n合计：%d 通过 / %d 失败（FP_EXPECT=%s）\n' "$pass" "$fail" "$FP_EXPECT"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
