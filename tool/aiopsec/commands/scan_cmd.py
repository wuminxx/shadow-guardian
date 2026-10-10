"""aiopsec scan —— 测绘落盘取证面。"""

from __future__ import annotations

import json
import time

from ..core import output as O
from ..core import surface


def add_parser(sub):
    p = sub.add_parser("scan", help="测绘 AI 客户端在本机的落盘取证面")
    p.add_argument("--json", action="store_true", help="输出 JSON")
    p.add_argument("--app", action="append", default=[],
                   help="只看指定客户端（可重复）")
    p.add_argument("--sensitive-only", action="store_true",
                   help="只列敏感落盘点")
    p.add_argument("--max-files", type=int, default=200_000,
                   help="单目录扫描文件上限（默认 200000）")
    p.set_defaults(func=run)


def run(args) -> int:
    hits = surface.probe()
    if args.app:
        want = {a.lower() for a in args.app}
        hits = [h for h in hits if h.app.lower() in want]
    if args.sensitive_only:
        hits = [h for h in hits if h.sensitive]

    t = surface.totals(hits)

    if args.json:
        payload = {
            "tool": "aiopsec",
            "command": "scan",
            "timestamp": time.time(),
            "totals": t,
            "hits": [
                {
                    "path": h.path, "app": h.app, "desc": h.desc,
                    "bytes": h.bytes, "files": h.files,
                    "sensitive": h.sensitive,
                    "newest": h.newest, "samples": h.samples,
                } for h in hits
            ],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print(O.header("AI 客户端落盘取证面"))
    print(O.kv("主机", __import__("socket").gethostname()))
    print(O.kv("发现路径", f"{t['paths']}"))
    print(O.kv("敏感路径", O.yellow(str(t["sensitive"])) if t["sensitive"] else "0"))
    print(O.kv("合计文件", f"{t['files']:,}"))
    print(O.kv("合计大小", O.human_bytes(t["bytes"])))

    if not hits:
        print()
        print(O.ok("未发现 AI 客户端落盘面 —— 干净，或尚未使用过 AI 客户端"))
        return 0

    print(O.header("明细"))
    rows = []
    for h in hits:
        flag = O.red("敏感") if h.sensitive else O.dim("—")
        rows.append([
            h.app,
            flag,
            h.files.__str__(),
            O.human_bytes(h.bytes),
            h.path,
        ])
    print(O.table(["客户端", "标记", "文件", "大小", "路径"], rows))

    sensitive = [h for h in hits if h.sensitive]
    if sensitive:
        print(O.header("高危落盘点（含明文会话 / 凭据 / snapshot）"))
        for h in sensitive:
            print(f"  {O.red('▸')} {O.bold(h.path)}")
            print(f"      {O.dim(h.desc)}")
            for s in h.samples[:4]:
                print(f"      · {O.dim(s)}")

    print(O.header("下一步"))
    print(f"  {O.cyan('aiopsec shred --dry-run')}        查看会清理什么")
    print(f"  {O.cyan('aiopsec shred --force')}          执行清理")
    print(f"  {O.cyan('aiopsec harden')}                 生成加固配置")
    return 0
