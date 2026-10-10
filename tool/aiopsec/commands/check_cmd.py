"""aiopsec check —— 扫描文本/文件里的身份泄漏。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..core import engine, output as O, rules as R


def add_parser(sub):
    p = sub.add_parser("check", help="扫描文本或文件中的身份泄漏（只检查）")
    src = p.add_mutually_exclusive_group()
    src.add_argument("-f", "--file", help="输入文件（- 表示 stdin）")
    src.add_argument("-t", "--text", help="直接给文本")
    src.add_argument("-d", "--dir", help="递归扫描目录")
    p.add_argument("--kind", action="append", default=[],
                   choices=["secret", "pii", "infra", "path"],
                   help="只查指定类别（可重复）")
    p.add_argument("--min-severity", default="LOW",
                   choices=["HIGH", "MED", "LOW"], help="最低严重度")
    p.add_argument("--show-raw", action="store_true",
                   help="输出原始命中值（危险：会打印敏感数据）")
    p.add_argument("--json", action="store_true")
    p.add_argument("--quiet", action="store_true", help="只输出结论")
    p.add_argument("--max-files", type=int, default=5000)
    p.set_defaults(func=run)
    return p


def _read(args) -> tuple[str, str]:
    if args.text is not None:
        return args.text, "<text>"
    if args.file:
        if args.file == "-":
            return sys.stdin.read(), "<stdin>"
        p = Path(args.file)
        if not p.exists():
            raise FileNotFoundError(args.file)
        return p.read_text(encoding="utf-8", errors="replace"), str(p)
    if sys.stdin.isatty():
        return "", "<stdin>"
    return sys.stdin.read(), "<stdin>"


def _iter_dir(root: Path, max_files: int):
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv",
            ".mypy_cache", ".pytest_cache", "dist", "build"}
    count = 0
    for p in sorted(root.rglob("*")):
        if count >= max_files:
            return
        if any(part in skip for part in p.parts):
            continue
        if not p.is_file():
            continue
        if p.stat().st_size > 8 * 1024 * 1024:
            continue
        count += 1
        yield p


def _report_one(name: str, text: str, findings, args) -> bool:
    """返回是否有命中。"""
    if args.json:
        return bool(findings)
    if not findings:
        if not args.quiet:
            print(f"{O.ok(name)} 无命中")
        return False

    if args.quiet:
        worst = max((f.severity for f in findings), key=R.severity_rank)
        print(f"{O.err(name)} {len(findings)} 处命中（最高 {O.sev(worst)}）")
        return True

    print(f"\n{O.bold(name)}  {O.red(str(len(findings)))} 处命中")
    for f in findings[:40]:
        loc = f"{f.line}:{f.col}"
        raw = f"  {O.dim(f.raw)}" if args.show_raw and f.raw else ""
        print(f"  {O.sev(f.severity):<10} {f.rule:<26} {O.dim(loc):<12} {f.masked}{raw}")
    if len(findings) > 40:
        print(f"  {O.dim(f'… 还有 {len(findings) - 40} 处')}")
    return True


def run(args) -> int:
    kinds = args.kind or None
    total_findings = []
    any_hit = False

    if args.dir:
        root = Path(args.dir)
        if not root.is_dir():
            print(O.err(f"不是目录: {root}"))
            return 2
        json_out = []
        for p in _iter_dir(root, args.max_files):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings = engine.scan_text(text, kinds, args.min_severity, args.show_raw)
            if findings:
                any_hit = True
                total_findings.extend(findings)
                if args.json:
                    json_out.append({
                        "file": str(p),
                        "findings": [f.to_dict(args.show_raw) for f in findings],
                    })
                else:
                    _report_one(str(p), text, findings, args)
        if args.json:
            print(json.dumps({
                "tool": "aiopsec", "command": "check",
                "root": str(root),
                "summary": engine.summarize(total_findings),
                "files": json_out,
            }, ensure_ascii=False, indent=2))
        elif not any_hit:
            print(O.ok(f"{root} 下未发现泄漏"))
    else:
        text, name = _read(args)
        findings = engine.scan_text(text, kinds, args.min_severity, args.show_raw)
        any_hit = bool(findings)
        total_findings = findings
        if args.json:
            print(json.dumps({
                "tool": "aiopsec", "command": "check",
                "source": name,
                "summary": engine.summarize(findings),
                "findings": [f.to_dict(args.show_raw) for f in findings],
            }, ensure_ascii=False, indent=2))
        else:
            print(O.header("身份泄漏检查"))
            print(O.kv("来源", name))
            print(O.kv("长度", f"{len(text)} 字符"))
            _report_one(name, text, findings, args)

    if not args.json and not args.quiet:
        if any_hit:
            s = engine.summarize(total_findings)
            print(O.header("汇总"))
            for sev in ("HIGH", "MED", "LOW"):
                n = s["by_severity"].get(sev, 0)
                if n:
                    print(O.kv(sev, str(n)))
            print()
            print(O.warn("提示：正则规则不覆盖姓名/学校/公司/措辞习惯，仍需人工过一遍"))
            print(f"  {O.cyan('aiopsec redact')} 可自动剥离")

    return 1 if any_hit else 0
