#!/usr/bin/env python3
"""session-banner.py —— Claude Code SessionStart hook

会话开始时提示当前 OPSEC 档位与可用的清理命令。
不改行为，只提示（SessionStart 输出会作为 additionalContext 注入）。
"""

import os
import sys
from pathlib import Path

def find_install() -> Path:
    # 优先 $CLAUDE_CONFIG_DIR，其次 ~/.claude
    for cand in (
        os.environ.get("CLAUDE_CONFIG_DIR"),
        os.path.expanduser("~/.claude"),
    ):
        if not cand:
            continue
        p = Path(cand) / "skills" / "ai-opsec-privacy"
        if p.is_dir():
            return p
    return Path(os.path.expanduser("~/.claude/skills/ai-opsec-privacy"))


def main():
    root = find_install()
    home = Path(os.path.expanduser("~"))

    # 找会话落盘点
    session_dirs = [
        home / ".claude" / "projects",
        home / ".claude" / "history.jsonl",
        home / ".claude" / "todos",
        home / ".claude" / "shell-snapshots",
    ]
    existing = [p for p in session_dirs if p.exists()]

    lines = ["[ai-opsec-privacy] 本会话的安全基线提示："]
    lines.append("")
    lines.append("落盘面（会话结束时建议清理）：")
    for p in existing:
        lines.append(f"  · {p}")

    if not existing:
        lines.append("  · 未发现常见落盘点 —— 已配置好，或尚未使用过 AI 客户端")

    lines.append("")
    lines.append("命令：")
    lines.append(f"  测绘   bash {root}/scripts/scan.sh")
    lines.append(f"  脱敏   cat file | bash {root}/scripts/redact.sh")
    lines.append(f"  检查   bash {root}/scripts/check-prompt.sh --file <f>")
    lines.append(f"  清理   bash {root}/scripts/shred.sh            # 先 DRY-RUN")
    lines.append(f"  真删   bash {root}/scripts/shred.sh --force")
    lines.append("")
    lines.append("提醒：送进模型的一切文本视为永久留存；")
    lines.append("      本会话的每条 prompt 都会写入 history.jsonl。")

    print("\n".join(lines))
    sys.exit(0)


if __name__ == "__main__":
    main()
