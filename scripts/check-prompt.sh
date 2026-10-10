#!/usr/bin/env bash
# check-prompt.sh —— 发送给 AI 前扫描身份泄漏（只检查，不修改）
#
# 用法:
#   cat app.log | ./check-prompt.sh
#   ./check-prompt.sh --file app.log
#   ./check-prompt.sh --text "帮我看看 13800138000 这条日志"
#
# 退出码:
#   0 = 通过（未发现规则覆盖的字段）
#   1 = 发现问题
#   2 = 用法错误
set -u

FILE=""
TEXT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -f|--file) FILE="${2:-}"; shift 2 ;;
    -t|--text) TEXT="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -n "$TEXT" ]; then
  CONTENT="$TEXT"
elif [ -n "$FILE" ]; then
  [ -f "$FILE" ] || { echo "文件不存在: $FILE" >&2; exit 2; }
  CONTENT="$(cat "$FILE")"
else
  if [ -t 0 ]; then
    echo "从 stdin 读取。Ctrl-D 结束。" >&2
  fi
  CONTENT="$(cat)"
fi

# 检查表：名称<TAB>严重度<TAB>ERE   （用 TAB 分隔，避免正则里的 | 干扰）
CHECKS="$(cat <<'TABLE'
中国大陆手机号	HIGH	(^|[^0-9])1[3-9][0-9]{9}([^0-9]|$)
邮箱	MED	[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
身份证号	HIGH	[1-9][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]
明文 API key	HIGH	(sk-ant-|sk-|ghp_|gho_|ghu_|ghs_|github_pat_|AKIA|AIza|xox[baprs]-|glpat-|hf_)[A-Za-z0-9_-]{8,}
密码/令牌字段	HIGH	(Bearer|password|passwd|secret|api_?key)["'=: ]+[A-Za-z0-9_.-]{6,}
私钥块	HIGH	-----BEGIN [A-Z ]*PRIVATE KEY-----
内网 IP	MED	(^|[^0-9])(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)
本机用户名路径	MED	(/home/|/Users/|C:\\Users\\|C:/Users/)[a-zA-Z0-9_.-]+
内部主机名	MED	[a-z0-9-]+\.(internal|local|corp|lan)
Telegram 账号	MED	(^|[^A-Za-z0-9_@])@[A-Za-z][A-Za-z0-9_]{4,31}
身份证字面提及	MED	身份证
精确住址	MED	(省|市|区|县|镇|街道|路|号)
IP:端口直连	MED	([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}
TABLE
)"

HITS=0
REPORT=""

while IFS=$'\t' read -r name sev re; do
  [ -z "${name:-}" ] && continue
  matches="$(printf '%s' "$CONTENT" | grep -oE "$re" 2>/dev/null \
    | sed 's/^[^A-Za-z0-9]*//; s/[^A-Za-z0-9]*$//' \
    | grep -vE '^(10\.0\.0\.0|127\.0\.0\.1|0\.0\.0\.0)$' \
    | sort -u | head -5)"
  [ -z "$matches" ] && continue
  HITS=$((HITS+1))
  REPORT="${REPORT}[${sev}] ${name}"$'\n'
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    len=${#m}
    if [ "$len" -le 6 ]; then shown="***"
    else shown="${m:0:3}***${m: -2}"; fi
    REPORT="${REPORT}       命中: ${shown}  (长度 ${len})"$'\n'
  done <<< "$matches"
done <<< "$CHECKS"

echo "=== AI 提示词身份泄漏检查 ==="
echo "输入长度: ${#CONTENT} 字符"
echo

if [ "$HITS" -eq 0 ]; then
  echo "结果: 通过 —— 未发现规则覆盖的身份字段"
  echo
  echo "注意: 启发式规则，不覆盖以下内容，仍需人工过一遍:"
  echo "  · 真实姓名 / 昵称 / 拼音 / 首字母缩写"
  echo "  · 年龄段 / 生日 / 学校 / 公司 / 部门 / 职级"
  echo "  · 唯一措辞习惯 / 口头禅 / 特殊错别字模式"
  echo "  · 第三方个人信息（法律风险最大）"
  echo "  · 内部项目代号 / 未公开产品名"
  exit 0
fi

echo "结果: 发现 ${HITS} 类问题"
echo "----------------------------------------------"
printf '%s' "$REPORT"
echo "----------------------------------------------"
echo
echo "处置建议:"
echo "  bash scripts/redact.sh --file <文件>     # 自动剥离"
echo "  或人工删除后重发"
exit 1
