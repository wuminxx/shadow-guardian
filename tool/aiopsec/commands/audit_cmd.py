"""aiopsec audit —— 一次性全量体检，输出评分与整改清单。"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..core import engine, environment, output as O, surface


def add_parser(sub):
    p = sub.add_parser("audit", help="全量体检：落盘面 + 环境指纹 + 配置 + 凭据")
    p.add_argument("--json", action="store_true")
    p.add_argument("--offline", action="store_true", help="不联网")
    p.add_argument("--deep", action="store_true",
                   help="扫描已知风险路径里的实际内容（慢）")
    p.set_defaults(func=run)
    return p


# 配置加固检查项
CONFIG_CHECKS = [
    ("Claude Code 遥测关闭", "claude_telemetry"),
    ("VS Code 遥测关闭", "vscode_telemetry"),
    ("Copilot 不读纯文本/文档", "copilot_plaintext"),
    ("已知落盘点已清理或隔离", "surface"),
    ("时区/语言/出口IP 一致", "env_consistency"),
    ("检测到代理", "proxy"),
    ("gitignore 含 AI 配置", "gitignore"),
]


def _check_claude() -> tuple[bool, str]:
    import os
    d = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
    s = d / "settings.json"
    if not s.exists():
        return False, "无 settings.json"
    try:
        cfg = json.loads(s.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, "settings.json 非法"
    env = cfg.get("env", {})
    if env.get("DISABLE_TELEMETRY") == "1" and \
       env.get("DISABLE_ERROR_REPORTING") == "1":
        return True, "已关"
    return False, "未关（aiopsec harden --apply）"


def _check_vscode() -> tuple[bool, str]:
    import platform
    import os
    if platform.system() == "Windows":
        p = Path(os.environ.get("APPDATA", "")) / "Code/User/settings.json"
    elif platform.system() == "Darwin":
        p = Path.home() / "Library/Application Support/Code/User/settings.json"
    else:
        p = Path.home() / ".config/Code/User/settings.json"
    if not p.exists():
        return False, "无 settings.json"
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, "非法 JSON"
    return cfg.get("telemetry.telemetryLevel") == "off", \
        "已关" if cfg.get("telemetry.telemetryLevel") == "off" else "未关"


def _check_copilot() -> tuple[bool, str]:
    import platform
    import os
    if platform.system() == "Windows":
        p = Path(os.environ.get("APPDATA", "")) / "Code/User/settings.json"
    elif platform.system() == "Darwin":
        p = Path.home() / "Library/Application Support/Code/User/settings.json"
    else:
        p = Path.home() / ".config/Code/User/settings.json"
    if not p.exists():
        return False, "无 settings.json"
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, "非法 JSON"
    en = cfg.get("github.copilot.enable", {})
    ok = en.get("plaintext") is False and en.get("markdown") is False
    return ok, "已限制" if ok else "Copilot 会读你的笔记/文档"


def _check_gitignore() -> tuple[bool, str]:
    gi = Path.cwd() / ".gitignore"
    if not gi.exists():
        return False, f"{gi} 不存在"
    txt = gi.read_text(encoding="utf-8", errors="replace")
    ok = ".claude/" in txt or ".claude" in txt
    return ok, "含 AI 配置" if ok else "未忽略 .claude/"


def run(args) -> int:
    results: dict[str, dict] = {}

    # ---- 1. 落盘面 ----
    hits = surface.probe()
    sens = [h for h in hits if h.sensitive]
    results["surface"] = {
        "paths": len(hits),
        "sensitive_paths": len(sens),
        "bytes": sum(h.bytes for h in hits),
        "files": sum(h.files for h in hits),
        "top": [{"path": h.path, "app": h.app, "desc": h.desc,
                 "bytes": h.bytes, "sensitive": h.sensitive} for h in hits[:12]],
    }

    # ---- 2. 环境指纹 ----
    rep = environment.collect(check_network=not args.offline)
    results["environment"] = environment.to_dict(rep)

    # ---- 3. 配置加固 ----
    claude_ok, claude_msg = _check_claude()
    vscode_ok, vscode_msg = _check_vscode()
    copilot_ok, copilot_msg = _check_copilot()
    gi_ok, gi_msg = _check_gitignore()
    results["config"] = {
        "claude_telemetry": {"ok": claude_ok, "detail": claude_msg},
        "vscode_telemetry": {"ok": vscode_ok, "detail": vscode_msg},
        "copilot_plaintext": {"ok": copilot_ok, "detail": copilot_msg},
        "gitignore": {"ok": gi_ok, "detail": gi_msg},
    }

    # ---- 4. 深度内容扫描 ----
    if args.deep:
        deep_hits = []
        # 扫已知高危：shell-snapshots / 配置 / env 备份
        import os
        candidates = []
        for h in hits:
            p = Path(h.path)
            if p.is_dir() and p.name in ("shell-snapshots", "history.jsonl"):
                candidates.append(p)
            elif p.is_file() and p.name in ("history.jsonl", "settings.json"):
                candidates.append(p)
        for p in candidates:
            files = [p] if p.is_file() else list(p.rglob("*"))
            for f in files[:200]:
                if not f.is_file() or f.stat().st_size > 4 * 1024 * 1024:
                    continue
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                fs = engine.scan_text(text, min_severity="HIGH")
                if fs:
                    deep_hits.append({
                        "file": str(f),
                        "count": len(fs),
                        "rules": sorted({x.rule for x in fs}),
                    })
        results["deep"] = {"scanned_paths": len(candidates), "hits": deep_hits}

    # ---- 5. 评分 ----
    score = 100
    deductions: list[tuple[str, int]] = []

    if sens:
        d = min(30, len(sens) * 6)
        score -= d
        deductions.append((f"{len(sens)} 个敏感落盘点未隔离/清理", d))
    if rep.issues:
        d = min(20, len(rep.issues) * 10)
        score -= d
        deductions.append((f"{len(rep.issues)} 处环境指纹矛盾", d))
    if not claude_ok:
        score -= 8
        deductions.append(("Claude Code 遥测未关", 8))
    if not vscode_ok:
        score -= 6
        deductions.append(("VS Code 遥测未关", 6))
    if not copilot_ok:
        score -= 8
        deductions.append(("Copilot 会读纯文本/文档", 8))
    if not rep.proxy_env and rep.public_ip:
        score -= 10
        deductions.append(("未检测到代理，流量可能直连", 10))
    if not gi_ok:
        score -= 5
        deductions.append(("项目未忽略 .claude/", 5))
    if args.deep and results.get("deep", {}).get("hits"):
        d = min(25, len(results["deep"]["hits"]) * 8)
        score -= d
        deductions.append((f"{len(results['deep']['hits'])} 个文件含明文凭据", d))

    score = max(0, score)
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 55 else "D" if score >= 35 else "F")
    results["score"] = {"value": score, "grade": grade,
                        "deductions": [{"reason": r, "points": p} for r, p in deductions]}

    # ---- 输出 ----
    if args.json:
        print(json.dumps({"tool": "aiopsec", "command": "audit",
                          "timestamp": time.time(), **results},
                         ensure_ascii=False, indent=2))
        return 1 if score < 75 else 0

    print(O.header("AI OPSEC 体检报告"))
    print(O.kv("时间", time.strftime("%Y-%m-%d %H:%M:%S")))

    grade_color = {"A": O.green, "B": O.green, "C": O.yellow,
                   "D": O.red, "F": O.red}.get(grade, str)
    print(O.kv("评分", grade_color(f"{score}/100  ({grade})")))
    print()

    # 落盘面
    print(O.bold("落盘面"))
    s = results["surface"]
    print(O.kv("  发现路径", str(s["paths"])))
    print(O.kv("  敏感路径", O.yellow(str(s["sensitive_paths"]))
               if s["sensitive_paths"] else "0"))
    print(O.kv("  合计", f"{s['files']:,} 文件 / {O.human_bytes(s['bytes'])}"))
    if sens:
        print()
        for h in sens[:8]:
            print(f"  {O.red('▸')} {h.path}")
            print(f"      {O.dim(h.desc)}")

    # 环境
    print()
    print(O.bold("环境指纹"))
    print(O.kv("  时区", f"{rep.tz} ({rep.tz_offset})"))
    print(O.kv("  语言", rep.lang or "?"))
    if rep.public_ip:
        print(O.kv("  出口 IP", f"{rep.public_ip}  "
                   f"{rep.ip_city}/{rep.ip_region}/{rep.ip_country}"))
        print(O.kv("  IP 时区", rep.ip_timezone or "?"))
    print(O.kv("  代理", ", ".join(rep.proxy_env) if rep.proxy_env else O.yellow("无")))
    for i in rep.issues:
        print(f"  {O.red('✗')} {i}")
    for n in rep.notes:
        print(f"  {O.blue('·')} {n}")

    # 配置
    print()
    print(O.bold("配置加固"))
    for name, key in (("Claude Code 遥测", "claude_telemetry"),
                      ("VS Code 遥测", "vscode_telemetry"),
                      ("Copilot 文本读取", "copilot_plaintext"),
                      ("gitignore", "gitignore")):
        c = results["config"][key]
        icon = O.green("✓") if c["ok"] else O.red("✗")
        print(f"  {icon} {name:<20} {c['detail']}")

    # 深度
    if args.deep:
        print()
        print(O.bold("深度内容扫描"))
        deep = results.get("deep", {})
        hits_d = deep.get("hits", [])
        print(O.kv("  扫描路径", str(deep.get("scanned_paths", 0))))
        if hits_d:
            for h in hits_d[:10]:
                print(f"  {O.red('▸')} {h['file']}  ({h['count']} 处: "
                      f"{', '.join(h['rules'][:3])})")
        else:
            print(O.ok("  未发现明文凭据"))

    # 扣分
    if deductions:
        print()
        print(O.bold("扣分项"))
        for r, p in deductions:
            print(f"  {O.yellow(f'-{p}')} {r}")

    # 整改
    print()
    print(O.bold("整改建议"))
    tips = []
    if sens:
        tips.append("aiopsec shred --force          # 清理会话痕迹")
    if rep.issues:
        tips.append("# 修正时区/语言与出口 IP 的一致性")
    if not claude_ok or not vscode_ok or not copilot_ok:
        tips.append("aiopsec harden --apply         # 关闭遥测 + 限制 Copilot")
    if not rep.proxy_env and rep.public_ip:
        tips.append("# 配置自建代理（见 docs/network.md）")
    if not gi_ok:
        tips.append("aiopsec harden --apply --target gitignore")
    if not tips:
        tips.append("基线良好。高敏场景见 docs/local-models.md 的 C 档")
    for t in tips:
        print(f"  {O.cyan('→')} {t}")

    return 1 if score < 75 else 0
