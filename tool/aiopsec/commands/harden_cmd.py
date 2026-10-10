"""aiopsec harden —— 生成/应用加固配置。"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path

from ..core import output as O

HOME = Path.home()


def _claude_settings() -> Path:
    d = Path(os.environ.get("CLAUDE_CONFIG_DIR", HOME / ".claude"))
    return d / "settings.json"


def _codex_config() -> Path:
    return HOME / ".codex" / "config.toml"


def _vscode_settings() -> Path:
    if platform.system() == "Windows":
        return Path(os.environ.get("APPDATA", "")) / "Code" / "User" / "settings.json"
    if platform.system() == "Darwin":
        return HOME / "Library/Application Support/Code/User/settings.json"
    return HOME / ".config/Code/User/settings.json"


def _proposed() -> dict:
    return {
        "claude": {
            "path": str(_claude_settings()),
            "merge": {
                "includeCoAuthoredBy": False,
                "env": {
                    "DISABLE_TELEMETRY": "1",
                    "DISABLE_ERROR_REPORTING": "1",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                },
            },
        },
        "vscode": {
            "path": str(_vscode_settings()),
            "merge": {
                "telemetry.telemetryLevel": "off",
                "github.copilot.chat.telemetry.enabled": False,
                "github.copilot.enable": {
                    "*": True,
                    "plaintext": False,
                    "markdown": False,
                    "scminput": False,
                },
                "git.enableSmartCommit": False,
            },
        },
        "gitignore_block": (
            "# --- AI agent config (aiopsec) ---\n"
            ".claude/\n.cursor/\n.continue/\n.aider*\n"
            ".codex/\nAGENTS.md\nCLAUDE.md\n.windsurf/\n"
            "# --- end ---\n"
        ),
    }


def add_parser(sub):
    p = sub.add_parser("harden", help="生成/应用加固配置")
    p.add_argument("--apply", action="store_true",
                   help="真的写入（默认只打印）")
    p.add_argument("--target", action="append", default=[],
                   choices=["claude", "vscode", "gitignore"],
                   help="只处理指定目标")
    p.add_argument("--gitignore-dir", default=".",
                   help="--target gitignore 时写入哪个目录")
    p.set_defaults(func=run)
    return p


def _merge_json(path: Path, patch: dict, apply: bool) -> str:
    """浅合并顶层 key；env 这类子字典做二次合并。返回说明。"""
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return f"{O.red('✗')} {path} 不是合法 JSON，跳过"

    changed = {}
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(existing.get(k), dict):
            sub = dict(existing[k])
            before = dict(sub)
            sub.update(v)
            if sub != before:
                existing[k] = sub
                changed[k] = v
        elif existing.get(k) != v:
            existing[k] = v
            changed[k] = v

    if not changed:
        return f"{O.ok(str(path))} 已是加固状态，无需改动"

    if not apply:
        return (f"{O.yellow(str(path))} 将写入:\n" +
                json.dumps(changed, ensure_ascii=False, indent=2))

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        bak = path.with_name(path.name + ".bak." + time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, bak)
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    return f"{O.ok(str(path))} 已写入（备份 {path.name}.bak.*）"


def run(args) -> int:
    targets = set(args.target) if args.target else {"claude", "vscode", "gitignore"}
    prop = _proposed()
    lines: list[str] = []

    if "claude" in targets:
        lines.append(O.header("Claude Code"))
        lines.append(_merge_json(_claude_settings(), prop["claude"]["merge"], args.apply))

    if "vscode" in targets:
        lines.append(O.header("VS Code / Copilot"))
        lines.append(_merge_json(_vscode_settings(), prop["vscode"]["merge"], args.apply))

    if "gitignore" in targets:
        lines.append(O.header(".gitignore"))
        gi = Path(args.gitignore_dir) / ".gitignore"
        block = prop["gitignore_block"]
        if gi.exists() and "aiopsec" in gi.read_text(encoding="utf-8", errors="replace"):
            lines.append(f"{O.ok(str(gi))} 已包含 AI 配置忽略规则")
        elif args.apply:
            with open(gi, "a", encoding="utf-8") as f:
                f.write("\n" + block)
            lines.append(f"{O.ok(str(gi))} 已追加忽略块")
        else:
            lines.append(f"{O.yellow(str(gi))} 将追加:\n{block}")

    print("\n".join(lines))
    print()
    if args.apply:
        print(O.ok("加固已应用。重启客户端后生效。"))
        print(O.info("提示：hook 安装见 aiopsec hook --install"))
    else:
        print(O.warn("这是预演。真要写：aiopsec harden --apply"))
    return 0
