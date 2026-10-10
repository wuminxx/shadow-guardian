#!/usr/bin/env bash
# shred.sh —— 清除 AI 客户端在本机的会话痕迹
#
# 用法:
#   ./shred.sh --dry-run      # 先看会动哪些文件（默认行为）
#   ./shred.sh --force        # 真删
#   ./shred.sh --force --keep-config   # 保留 settings/credentials
#
# 警告: SSD + TRIM + 写时复制文件系统（btrfs/ZFS/APFS）下，
#       原地覆写不保证擦除旧块。真需要彻底时上全盘加密 + 一次性 VM。
set -u

DRY=1
KEEP_CONFIG=1
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --force)   DRY=0 ;;
    --no-keep-config) KEEP_CONFIG=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
  esac
done

# 要清的路径（会话/历史/memory/snapshot），保持 config 与凭据不动
SESSION_TARGETS=(
  "$HOME/.claude/projects"
  "$HOME/.claude/todos"
  "$HOME/.claude/shell-snapshots"
  "$HOME/.claude/statsig"
  "$HOME/.codex/sessions"
  "$HOME/.codex/history.jsonl"
  "$HOME/.cursor/logs"
  "$HOME/.cursor/User/History"
  "$HOME/.continue/sessions"
  "$HOME/.aider/analytics.jsonl"
  "$HOME/.ollama/logs"
)

# 单文件目标（追加内容清空而非删目录）
FILE_TARGETS=(
  "$HOME/.claude/history.jsonl"
)

# 可选的深度清理（--no-keep-config 时才动）
CONFIG_TARGETS=(
  "$HOME/.claude/settings.json"
  "$HOME/.codex/config.toml"
)

have_shred=0
command -v shred >/dev/null 2>&1 && have_shred=1

do_shred_file() {
  local f="$1"
  if [ "$have_shred" -eq 1 ]; then
    shred -u -n 3 "$f" 2>/dev/null || rm -f "$f"
  else
    # 无 shred 时的退化：覆写后删
    local sz; sz=$(wc -c < "$f" 2>/dev/null || echo 0)
    if [ "${sz:-0}" -gt 0 ]; then
      dd if=/dev/urandom of="$f" bs=1M count=$(( sz/1048576 + 1 )) conv=notrunc status=none 2>/dev/null || true
    fi
    rm -f "$f"
  fi
}

echo "=== AI 会话痕迹清理 ==="
echo "模式: $([ "$DRY" -eq 1 ] && echo 'DRY-RUN（只列出）' || echo 'FORCE（真删）')"
echo "保留配置: $([ "$KEEP_CONFIG" -eq 1 ] && echo '是' || echo '否')"
echo "shred 可用: $([ "$have_shred" -eq 1 ] && echo '是' || echo '否（退化到 dd 覆写）')"
echo

nfiles=0
nbytes=0

wipe_path() {
  local p="$1"
  [ -e "$p" ] || return 0
  if [ -d "$p" ]; then
    local cnt sz
    cnt=$(find "$p" -type f 2>/dev/null | wc -l)
    sz=$(du -sb "$p" 2>/dev/null | cut -f1); sz=${sz:-0}
    printf '%8s files  %12s  %s\n' "$cnt" "$(awk -v b="$sz" 'BEGIN{printf "%.2f MB", b/1048576}')" "$p"
    nfiles=$((nfiles+cnt)); nbytes=$((nbytes+sz))
    if [ "$DRY" -eq 0 ]; then
      find "$p" -type f -exec sh -c 'for f; do
        if command -v shred >/dev/null 2>&1; then shred -u -n 3 "$f" 2>/dev/null || rm -f "$f"
        else rm -f "$f"; fi
      done' sh {} + 2>/dev/null
      find "$p" -type d -empty -delete 2>/dev/null || true
    fi
  else
    local sz; sz=$(wc -c < "$p" 2>/dev/null || echo 0)
    printf '%8s        %12s  %s\n' 1 "$sz B" "$p"
    nfiles=$((nfiles+1)); nbytes=$((nbytes+sz))
    [ "$DRY" -eq 0 ] && do_shred_file "$p"
  fi
}

for t in "${SESSION_TARGETS[@]}"; do wipe_path "$t"; done

# 单文件：清空内容但保留文件（某些客户端要求文件存在）
for f in "${FILE_TARGETS[@]}"; do
  [ -e "$f" ] || continue
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  printf '%8s        %12s  %s\n' "清空" "$sz B" "$f"
  nfiles=$((nfiles+1)); nbytes=$((nbytes+sz))
  if [ "$DRY" -eq 0 ]; then
    : > "$f"
    # 再覆写一遍并 truncate
    [ "$have_shred" -eq 1 ] && { : > "$f"; }
  fi
done

if [ "$KEEP_CONFIG" -eq 0 ]; then
  echo
  echo "--- 配置（--no-keep-config 生效）---"
  for t in "${CONFIG_TARGETS[@]}"; do wipe_path "$t"; done
fi

echo
echo "------------------------------"
printf '合计: %d 项  %.2f MB\n' "$nfiles" "$(awk -v b="$nbytes" 'BEGIN{print b/1048576}')"

if [ "$DRY" -eq 1 ]; then
  echo
  echo "这是 DRY-RUN。要真删跑: ./shred.sh --force"
else
  echo
  echo "已清理。注意: SSD/CoW 下覆写不保证擦除旧块。"
  echo "彻底方案: 全盘加密 + 一次性 VM。"
fi
