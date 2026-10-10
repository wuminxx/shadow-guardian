"""aiopsec shred —— 清除 AI 会话痕迹（默认 DRY-RUN）。"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ..core import output as O
from ..core.surface import default_targets

# 只清会话/历史/memory/snapshot；配置与凭据默认保留
SHRED_SUFFIXES = (
    "projects", "history.jsonl", "memory", "todos", "shell-snapshots",
    "statsig", "sessions", "log", "logs", "History", "globalStorage",
    "analytics.jsonl", "User/History",
)

# 单文件：清空内容但保留文件（某些客户端要求存在）
CLEAR_ONLY = ("history.jsonl", "analytics.jsonl")


def _is_clear_only(path: Path) -> bool:
    return path.name in CLEAR_ONLY


def _overwrite(path: Path, passes: int = 3) -> bool:
    """覆写并删除单文件。返回是否成功。"""
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size > 0:
        try:
            with open(path, "r+b", buffering=0) as f:
                chunk = os.urandom(1 << 20)
                for _ in range(passes):
                    f.seek(0)
                    written = 0
                    while written < size:
                        n = min(len(chunk), size - written)
                        f.write(chunk[:n])
                        written += n
                    f.flush()
                    os.fsync(f.fileno())
        except OSError:
            pass
    try:
        path.unlink()
        return True
    except OSError:
        return False


def add_parser(sub):
    p = sub.add_parser("shred", help="清除 AI 会话痕迹（默认 DRY-RUN）")
    p.add_argument("--force", action="store_true",
                   help="真的删（不加就是预演）")
    p.add_argument("--app", action="append", default=[],
                   help="只清指定客户端")
    p.add_argument("--include-config", action="store_true",
                   help="连配置和凭据一起清（危险）")
    p.add_argument("--passes", type=int, default=3, help="覆写遍数")
    p.add_argument("--no-overwrite", action="store_true",
                   help="只删除不覆写（快，但 SSD 上不彻底）")
    p.set_defaults(func=run)
    return p


# 配置与凭据类路径 —— 只有 --include-config 时才加入
CONFIG_TARGETS = [
    "~/.claude/settings.json",
    "~/.claude/credentials.json",
    "~/.claude.json",
    "~/.codex/config.toml",
    "~/.codex/auth.json",
    "~/.cursor/mcp.json",
    "~/.continue/config.json",
    "~/.aider.conf.yml",
]


def run(args) -> int:
    want = {a.lower() for a in args.app} if args.app else None

    targets = []
    for t in default_targets():
        if want and t.app.lower() not in want:
            continue
        rel = str(t.path).replace("\\", "/")
        if not args.include_config:
            # 配置类不清
            if rel.endswith("/settings.json") or rel.endswith("credentials.json"):
                continue
            if any(rel.endswith(s) or f"/{s}" in rel for s in SHRED_SUFFIXES):
                targets.append(t)
        else:
            targets.append(t)

    # --include-config：显式加入配置与凭据路径
    if args.include_config:
        from ..core.surface import Target
        for spec in CONFIG_TARGETS:
            p = Path(os.path.expandvars(spec)).expanduser()
            if want and not any(w in str(p).lower() for w in want):
                continue
            targets.append(Target(p, "config", "配置/凭据", True))

    # 去重
    seen = set()
    uniq = []
    for t in targets:
        k = str(t.path)
        if k not in seen and t.path.exists():
            seen.add(k)
            uniq.append(t)
    targets = uniq

    print(O.header("AI 会话痕迹清理"))
    print(O.kv("模式", O.green("FORCE（真删）") if args.force else O.yellow("DRY-RUN")))
    print(O.kv("覆写", f"{args.passes} 遍" if not args.no_overwrite else "不覆写"))
    print(O.kv("配置", "一起清" if args.include_config else "保留"))

    if not targets:
        print()
        print(O.ok("未发现需要清理的路径"))
        return 0

    rows = []
    total_files = 0
    total_bytes = 0
    cleared = 0
    errors = 0

    for t in targets:
        p = t.path
        if p.is_file():
            try:
                sz = p.stat().st_size
                n = 1
            except OSError:
                continue
            rows.append([t.app, str(n), O.human_bytes(sz), str(p)])
            total_files += n
            total_bytes += sz
            if args.force:
                if _is_clear_only(p):
                    # history.jsonl 这类：清空内容但保留文件
                    try:
                        p.write_text("")
                        cleared += 1
                    except OSError:
                        errors += 1
                else:
                    if args.no_overwrite:
                        try:
                            p.unlink()
                            cleared += 1
                        except OSError:
                            errors += 1
                    elif _overwrite(p, args.passes):
                        cleared += 1
                    else:
                        errors += 1
        else:
            n = 0
            sz = 0
            for dp, dn, fn in os.walk(p):
                for f in fn:
                    fp = Path(dp) / f
                    try:
                        st = fp.lstat()
                    except OSError:
                        continue
                    n += 1
                    sz += st.st_size
                    if args.force:
                        if args.no_overwrite:
                            try:
                                fp.unlink()
                                cleared += 1
                            except OSError:
                                errors += 1
                        elif _overwrite(fp, args.passes):
                            cleared += 1
                        else:
                            errors += 1
            if args.force:
                shutil.rmtree(p, ignore_errors=True)
            rows.append([t.app, f"{n:,}", O.human_bytes(sz), str(p)])
            total_files += n
            total_bytes += sz

    print(O.header("明细"))
    print(O.table(["客户端", "文件", "大小", "路径"], rows))

    print(O.header("合计"))
    print(O.kv("路径", str(len(targets))))
    print(O.kv("文件", f"{total_files:,}"))
    print(O.kv("大小", O.human_bytes(total_bytes)))
    if args.force:
        print(O.kv("已处理", O.green(f"{cleared:,}") + (O.red(f"  失败 {errors}") if errors else "")))

    print()
    if args.force:
        print(O.ok("已清理"))
        print(O.warn("SSD/CoW 文件系统下覆写不保证擦除旧块"))
        print(O.info("彻底方案：全盘加密 + 一次性 VM"))
    else:
        print(O.warn("这是预演。真要清：aiopsec shred --force"))
        print(O.info("清理前建议先跑 aiopsec scan 确认范围"))
    return 0
