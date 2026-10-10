#!/usr/bin/env bash
# scan.sh —— 测绘 AI 客户端在本机的落盘取证面
# 用法: ./scan.sh [--json]
set -u

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

TARGETS=(
  # CLI / IDE agent
  "$HOME/.claude"
  "$HOME/.codex"
  "$HOME/.cursor"
  "$HOME/.continue"
  "$HOME/.aider"
  "$HOME/.config/gh"
  "$HOME/.config/Code"
  "$HOME/.config/Cursor"
  "$HOME/.config/Claude"
  "$HOME/.config/opencode"
  # 本地模型
  "$HOME/.ollama"
  "$HOME/.cache/huggingface"
  "$HOME/.cache/lm-studio"
  "$HOME/.lmstudio"
  # macOS
  "$HOME/Library/Application Support/Claude"
  "$HOME/Library/Application Support/Cursor"
  "$HOME/Library/Application Support/Code"
  "$HOME/Library/Caches/com.anthropic.claudefordesktop"
  # 浏览器 profile（仅列出，映射可能不准）
  "$HOME/.config/google-chrome/Default"
  "$HOME/.config/chromium/Default"
  "$HOME/Library/Application Support/Google/Chrome/Default"
)

# 高价值文件名特征 —— 命中即说明有明文会话
HOT_PATTERNS='(^|/)(history\.jsonl|.*\.jsonl|memory|sessions?|projects?|transcripts?|todos|shell-snapshots|conversations?)(/|$)'

emit_row() {
  local path="$1" size="$2" hot="$3"
  if [ "$JSON" -eq 1 ]; then
    printf '{"path":"%s","bytes":%s,"sensitive":%s}\n' "$path" "${size:-0}" "${hot:-false}"
  else
    local flag=""
    [ "$hot" = "true" ] && flag="  <== 敏感落盘"
    printf '%14s  %s%s\n' "$(human "${size:-0}")" "$path" "$flag"
  fi
}

human() {
  local b="${1:-0}"
  if   [ "$b" -ge 1073741824 ]; then awk -v b="$b" 'BEGIN{printf "%.2f GB", b/1073741824}'
  elif [ "$b" -ge 1048576 ];    then awk -v b="$b" 'BEGIN{printf "%.2f MB", b/1048576}'
  elif [ "$b" -ge 1024 ];       then awk -v b="$b" 'BEGIN{printf "%.1f KB", b/1024}'
  else printf '%d B' "$b"; fi
}

[ "$JSON" -eq 0 ] && {
  echo "=== AI 客户端落盘测绘 ==="
  echo "主机: $(hostname)  用户: $(whoami)  时间: $(date -Iseconds)"
  echo
  printf '%14s  %s\n' "大小" "路径"
  echo "--------------------------------------------------------------"
}

total=0
found=0
for t in "${TARGETS[@]}"; do
  [ -e "$t" ] || continue
  found=$((found+1))
  sz=$(du -sb "$t" 2>/dev/null | cut -f1)
  [ -z "$sz" ] && sz=$(du -sk "$t" 2>/dev/null | awk '{print $1*1024}')
  sz=${sz:-0}
  total=$((total + sz))

  hot=false
  if find "$t" -maxdepth 4 -type f 2>/dev/null | grep -Eq "$HOT_PATTERNS"; then
    hot=true
  fi
  emit_row "$t" "$sz" "$hot"
done

if [ "$JSON" -eq 0 ]; then
  echo "--------------------------------------------------------------"
  echo "命中目录: $found    合计: $(human "$total")"
  echo
  echo "=== 高价值文件（明文会话/memory/snapshot）==="
  for t in "${TARGETS[@]}"; do
    [ -d "$t" ] || continue
    find "$t" -maxdepth 5 -type f 2>/dev/null \
      | grep -E "$HOT_PATTERNS" \
      | head -25
  done
  echo
  echo "下一步:"
  echo "  1) 关遥测/memory: 见 docs/forensics-surface.md"
  echo "  2) 会话目录挂 tmpfs，或改用加密容器"
  echo "  3) 清痕: ./scripts/shred.sh"
fi
