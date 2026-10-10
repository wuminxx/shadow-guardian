#!/usr/bin/env bash
# install-hooks.sh —— 把 prompt-guard 装成 Claude Code hook
#
# 用法:
#   ./install-hooks.sh              # 装到 ~/.claude/settings.json
#   ./install-hooks.sh --uninstall  # 移除
#   ./install-hooks.sh --print      # 只打印要合并的 JSON
#
# 会先备份原 settings.json 为 settings.json.bak.<时间戳>
set -u

MODE=install
for a in "$@"; do
  case "$a" in
    --uninstall) MODE=uninstall ;;
    --print)     MODE=print ;;
    -h|--help)   sed -n '2,9p' "$0"; exit 0 ;;
  esac
done

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SELF_DIR")"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SETTINGS="$CLAUDE_DIR/settings.json"
GUARD="$REPO_DIR/hooks/prompt-guard.py"
BANNER="$REPO_DIR/hooks/session-banner.py"

command -v python3 >/dev/null 2>&1 || { echo "需要 python3" >&2; exit 1; }

read -r -d '' SNIPPET <<JSON
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "python3 \"$GUARD\"", "timeout": 5 }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "python3 \"$BANNER\"", "timeout": 5 }
        ]
      }
    ]
  }
}
JSON

if [ "$MODE" = "print" ]; then
  echo "$SNIPPET"
  exit 0
fi

mkdir -p "$CLAUDE_DIR"

# 合并脚本：读现有 settings，插入/移除 hook，写回
merge_py='
import json, sys, os, shutil, time

mode, settings_path, snippet = sys.argv[1], sys.argv[2], sys.argv[3]
new = json.loads(snippet)

if not os.path.exists(settings_path):
    cur = {}
else:
    with open(settings_path, encoding="utf-8") as f:
        try:
            cur = json.load(f)
        except json.JSONDecodeError:
            print("settings.json 不是合法 JSON，先手工确认。", file=sys.stderr)
            sys.exit(1)
    # 备份
    bak = settings_path + ".bak." + time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(settings_path, bak)
    print("备份:", bak, file=sys.stderr)

MARK = "ai-opsec-privacy"
hooks = cur.setdefault("hooks", {})

def is_ours(cmd): return MARK in cmd

if mode == "install":
    for evt, entries in new["hooks"].items():
        bucket = hooks.setdefault(evt, [])
        # 去掉已存在的同名 hook，避免重复
        for e in bucket:
            e["hooks"] = [h for h in e.get("hooks", []) if not is_ours(h.get("command",""))]
        bucket[:] = [e for e in bucket if e.get("hooks")]
        bucket.extend(entries)
    # 清理空的
    cur["hooks"] = {k: v for k, v in hooks.items() if v}
    if not cur["hooks"]:
        cur.pop("hooks")
else:
    for evt in list(hooks.keys()):
        hooks[evt] = [e for e in hooks[evt]
                      if not any(is_ours(h.get("command","")) for h in e.get("hooks",[]))]
        hooks[evt] = [e for e in hooks[evt] if e.get("hooks")]
        if not hooks[evt]:
            hooks.pop(evt)
    if not hooks:
        cur.pop("hooks", None)

with open(settings_path, "w", encoding="utf-8") as f:
    json.dump(cur, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("已写入:", settings_path, file=sys.stderr)
'

python3 -c "$merge_py" "$MODE" "$SETTINGS" "$SNIPPET"

if [ "$MODE" = "install" ]; then
  echo
  echo "已安装。验证:"
  echo "  1) 重启 Claude Code（hook 在启动时加载）"
  echo "  2) 发一条含手机号的 prompt，应被拦截"
  echo "  3) 卸载: $0 --uninstall"
fi
