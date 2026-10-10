#!/usr/bin/env bash
# redact.sh —— 剥离文本中的身份字段，供发送给 AI 前使用
#
# 用法:
#   cat app.log | ./redact.sh
#   ./redact.sh --file app.log > clean.log
#   ./redact.sh --stdin < input.txt
#
# 注意: 是启发式规则，不保证 100% 覆盖。发送前仍应人工过一遍检查表。
set -u

usage() { sed -n '2,12p' "$0"; exit 0; }

INPUT_MODE=stdin
FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -f|--file) FILE="${2:-}"; INPUT_MODE=file; shift 2 ;;
    -s|--stdin) INPUT_MODE=stdin; shift ;;
    *) shift ;;
  esac
done

REDACT_RE='s#(/home/|/Users/|C:\\Users\\|C:/Users/)[^/\\]+#\1USER#g'
REDACT_RE="$REDACT_RE"'
s/\b(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b/10.0.0.0/g
s/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/EMAIL@REDACTED/g
s/\b1[3-9][0-9]{9}\b/PHONE_REDACTED/g
s/\b[1-9][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]\b/IDNUM_REDACTED/g
s/(sk-ant-|sk-|ghp_|gho_|ghu_|ghs_|github_pat_|AKIA|AIza|xox[baprs]-|glpat-|hf_)[A-Za-z0-9_\-]{8,}/TOKEN_REDACTED/g
s/(Bearer|token|secret|password|passwd|pwd|apikey|api_key)([":= ]+)[A-Za-z0-9_\-\.]{6,}/\1\2SECRET_REDACTED/Ig
s/\b[a-z0-9-]+\.(internal|local|corp|lan|intra|intranet)\b/HOST.internal/g
s/\b[A-Za-z0-9-]{2,}\.(internal|local|corp)\b/HOST.internal/g
s/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----/g'

case "$INPUT_MODE" in
  file)
    [ -f "$FILE" ] || { echo "文件不存在: $FILE" >&2; exit 1; }
    sed -E "$REDACT_RE" "$FILE"
    ;;
  stdin)
    if [ -t 0 ]; then
      echo "从 stdin 读取。Ctrl-D 结束。示例: cat app.log | ./redact.sh" >&2
    fi
    sed -E "$REDACT_RE"
    ;;
esac
