"""aiopsec redact —— 剥离身份字段。"""

from __future__ import annotations

import sys
from pathlib import Path

from ..core import engine, output as O


def add_parser(sub):
    p = sub.add_parser("redact", help="剥离文本/文件中的身份字段")
    src = p.add_mutually_exclusive_group()
    src.add_argument("-f", "--file", help="输入文件（- 表示 stdin）")
    src.add_argument("-t", "--text", help="直接给文本")
    p.add_argument("-o", "--out", help="输出文件（默认 stdout）")
    p.add_argument("--in-place", action="store_true",
                   help="就地覆盖输入文件（会先生成 .bak）")
    p.add_argument("--kind", action="append", default=[],
                   choices=["secret", "pii", "infra", "path"],
                   help="只处理指定类别")
    p.add_argument("--dry-run", action="store_true",
                   help="只报会替换多少处，不输出内容")
    p.set_defaults(func=run)
    return p


def run(args) -> int:
    kinds = args.kind or None

    if args.text is not None:
        text, name = args.text, "<text>"
    elif args.file:
        if args.file == "-":
            text, name = sys.stdin.read(), "<stdin>"
        else:
            p = Path(args.file)
            if not p.exists():
                print(O.err(f"文件不存在: {p}"))
                return 2
            text = p.read_text(encoding="utf-8", errors="replace")
            name = str(p)
    else:
        if sys.stdin.isatty():
            print(O.err("需要输入：用 -f / -t，或从管道传入"))
            return 2
        text, name = sys.stdin.read(), "<stdin>"

    cleaned, count = engine.redact_text(text, kinds)

    if args.dry_run:
        findings = engine.scan_text(text, kinds)
        s = engine.summarize(findings)
        print(O.header("脱敏预演"))
        print(O.kv("来源", name))
        print(O.kv("会替换", f"{count} 处"))
        for sev in ("HIGH", "MED", "LOW"):
            n = s["by_severity"].get(sev, 0)
            if n:
                print(O.kv(f"  {sev}", str(n)))
        return 0

    if args.in_place:
        if not args.file or args.file == "-":
            print(O.err("--in-place 需要具体文件"))
            return 2
        p = Path(args.file)
        bak = p.with_suffix(p.suffix + ".bak")
        bak.write_bytes(p.read_bytes())
        p.write_text(cleaned, encoding="utf-8")
        print(O.ok(f"已就地脱敏 {name}（{count} 处），备份: {bak}"), file=sys.stderr)
        return 0

    if args.out:
        Path(args.out).write_text(cleaned, encoding="utf-8")
        print(O.ok(f"已写入 {args.out}（{count} 处替换）"), file=sys.stderr)
        return 0

    sys.stdout.write(cleaned)
    if not cleaned.endswith("\n"):
        sys.stdout.write("\n")
    print(O.dim(f"[aiopsec] {count} 处替换"), file=sys.stderr)
    return 0
