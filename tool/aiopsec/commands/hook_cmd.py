"""aiopsec hook —— 安装/卸载 Claude Code hook，以及 hook 自身的入口。"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from ..core import engine, output as O, rules as R

MARK = "aiopsec"


def _claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))


def _pkg_dir() -> Path:
    """找到 aiopsec 包所在的父目录（即 sys.path 上能 import 到它的那层）。"""
    return Path(__file__).resolve().parents[2]


def _hook_script(sub: str) -> Path:
    """生成一个自带路径的 launcher 脚本，不依赖 pip install -e。"""
    d = _claude_dir() / "aiopsec"
    d.mkdir(parents=True, exist_ok=True)
    script = d / f"hook-{sub}.py"
    pkg = _pkg_dir()
    body = (
        "#!/usr/bin/env python3\n"
        '"""aiopsec hook launcher —— 由 aiopsec hook --install 生成，可删。"""\n'
        "import sys\n"
        f"sys.path.insert(0, {str(pkg)!r})\n"
        "from aiopsec.commands.hook_cmd import main_entry\n"
        f"sys.exit(main_entry({sub!r}))\n"
    )
    script.write_text(body, encoding="utf-8")
    return script


def _self_cmd(sub: str) -> str:
    """生成调用本工具的 hook 命令。"""
    py = sys.executable or sys.executable or "python3"
    return f'"{py}" "{_hook_script(sub)}"'


def _guarded_cmd() -> str:
    return _self_cmd("guard")


# ------------------------------------------------------------------ guard
def guard() -> int:
    """UserPromptSubmit hook 入口：从 stdin 读事件，命中则 exit 2 阻断。"""
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        event = {"prompt": raw}

    text = ""
    for k in ("prompt", "user_prompt", "text", "content", "message"):
        v = event.get(k)
        if isinstance(v, str) and v:
            text = v
            break
    if not text:
        return 0

    findings = engine.scan_text(text, min_severity=R.MED)
    block_on = os.environ.get("AIOP_SEC_BLOCK", "HIGH").upper()
    if block_on == "NONE":
        return 0

    threshold = {"HIGH": 3, "MED": 2, "LOW": 1}.get(block_on, 3)
    hits = [f for f in findings if R.severity_rank(f.severity) >= threshold]
    if not hits:
        return 0

    seen = set()
    lines = [f"[aiopsec] 提示词身份泄漏检查未通过（阈值 {block_on}）", ""]
    for f in hits:
        if f.rule in seen:
            continue
        seen.add(f.rule)
        lines.append(f"  [{f.severity}] {f.rule}: {f.masked}  ({f.line}:{f.col})")
    lines += [
        "",
        "处置:",
        "  · 删除上述字段后重发；",
        "  · 或先跑 aiopsec redact 脱敏；",
        "  · 误报可设 AIOP_SEC_BLOCK=MED|LOW|NONE 调整阈值。",
    ]
    print("\n".join(lines), file=sys.stderr)
    return 2


# ------------------------------------------------------------------ banner
def banner() -> int:
    """SessionStart hook 入口：提示落盘点。"""
    from ..core import surface
    hits = [h for h in surface.probe() if h.sensitive]
    if not hits:
        return 0
    lines = ["[aiopsec] 本会话安全基线提示：", ""]
    lines.append(f"检测到 {len(hits)} 个敏感落盘点（会话结束时建议清理）：")
    for h in hits[:6]:
        lines.append(f"  · {h.path}  ({h.desc})")
    lines += [
        "",
        "命令：",
        "  aiopsec scan            测绘",
        "  aiopsec check -f <f>    检查泄漏",
        "  aiopsec redact < <f>    脱敏",
        "  aiopsec shred --force   清理",
    ]
    print("\n".join(lines))
    return 0


# ------------------------------------------------------------------ install
def _snippet() -> dict:
    return {
        "hooks": {
            "UserPromptSubmit": [{
                "hooks": [{"type": "command", "command": _guarded_cmd(), "timeout": 5}]
            }],
            "SessionStart": [{
                "hooks": [{"type": "command",
                           "command": _self_cmd("banner"), "timeout": 5}]
            }],
        }
    }


def _is_ours(cmd: str) -> bool:
    return "aiopsec" in cmd and "hook" in cmd


def _install(apply: bool) -> int:
    settings = _claude_dir() / "settings.json"
    snippet = _snippet()

    cur = {}
    if settings.exists():
        try:
            cur = json.loads(settings.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(O.err(f"{settings} 不是合法 JSON，先手工确认"))
            return 2
    else:
        cur = {}

    hooks = cur.setdefault("hooks", {})
    for evt, entries in snippet["hooks"].items():
        bucket = hooks.setdefault(evt, [])
        for e in bucket:
            e["hooks"] = [h for h in e.get("hooks", [])
                          if not _is_ours(h.get("command", ""))]
        bucket[:] = [e for e in bucket if e.get("hooks")]
        bucket.extend(entries)
    cur["hooks"] = {k: v for k, v in hooks.items() if v}

    print(O.header("安装 aiopsec hook"))
    print(O.kv("配置文件", str(settings)))
    print(O.kv("UserPromptSubmit", "拦截含身份字段的输入"))
    print(O.kv("SessionStart", "提示落盘点"))

    if not apply:
        print()
        print(O.warn("这是预演。要真装：aiopsec hook --install --apply"))
        print(O.dim(json.dumps(snippet, ensure_ascii=False, indent=2)))
        return 0

    if settings.exists():
        bak = settings.with_name(settings.name + ".bak." + time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(settings, bak)
        print(O.ok(f"备份: {bak}"))
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    print(O.ok("已安装。重启 Claude Code 后生效。"))
    return 0


def _uninstall(apply: bool) -> int:
    settings = _claude_dir() / "settings.json"
    if not settings.exists():
        print(O.warn("没有 settings.json"))
        return 0
    try:
        cur = json.loads(settings.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(O.err("settings.json 不是合法 JSON"))
        return 2

    hooks = cur.get("hooks", {})
    removed = 0
    for evt in list(hooks.keys()):
        before = len(hooks[evt])
        hooks[evt] = [e for e in hooks[evt]
                      if not any(_is_ours(h.get("command", ""))
                                 for h in e.get("hooks", []))]
        hooks[evt] = [e for e in hooks[evt] if e.get("hooks")]
        removed += before - len(hooks[evt])
        if not hooks[evt]:
            hooks.pop(evt)
    if not hooks:
        cur.pop("hooks", None)

    print(O.header("卸载 aiopsec hook"))
    print(O.kv("移除条目", str(removed)))
    if not apply:
        print(O.warn("这是预演。要真卸：aiopsec hook --uninstall --apply"))
        return 0
    if settings.exists():
        bak = settings.with_name(settings.name + ".bak." + time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(settings, bak)
    settings.write_text(json.dumps(cur, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    print(O.ok("已卸载"))
    return 0


def _status() -> int:
    settings = _claude_dir() / "settings.json"
    print(O.header("hook 状态"))
    print(O.kv("配置文件", str(settings)))
    if not settings.exists():
        print(O.warn("不存在"))
        return 0
    try:
        cur = json.loads(settings.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(O.err("不是合法 JSON"))
        return 2
    hooks = cur.get("hooks", {})
    found = False
    for evt, entries in hooks.items():
        for e in entries:
            for h in e.get("hooks", []):
                if _is_ours(h.get("command", "")):
                    print(O.kv(evt, O.green(h["command"])))
                    found = True
    if not found:
        print(O.kv("状态", O.yellow("未安装")))
    return 0


def main_entry(which: str) -> int:
    """给生成的 launcher 脚本用的入口。"""
    if which == "guard":
        return guard()
    if which == "banner":
        return banner()
    return 0


def add_parser(sub):
    p = sub.add_parser("hook", help="安装/卸载 Claude Code hook")
    p.add_argument("--install", action="store_true", help="安装")
    p.add_argument("--uninstall", action="store_true", help="卸载")
    p.add_argument("--status", action="store_true", help="查看状态")
    p.add_argument("--apply", action="store_true",
                   help="实际写入（不加则只是预演）")
    p.add_argument("sub", nargs="?", choices=["guard", "banner"],
                   help="(内部) hook 入口")
    p.set_defaults(func=run)
    return p


def run(args) -> int:
    sub = getattr(args, "sub", None)
    if sub == "guard":
        return guard()
    if sub == "banner":
        return banner()
    if args.uninstall:
        return _uninstall(args.apply)
    if args.install:
        return _install(args.apply)
    return _status()
