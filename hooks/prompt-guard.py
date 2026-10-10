#!/usr/bin/env python3
"""prompt-guard.py —— Claude Code UserPromptSubmit hook

在用户提交 prompt 时扫描身份泄漏字段。命中则阻断并提示。

Claude Code hook 协议:
  读 stdin JSON → 写 stdout JSON
  退出码 0 + 无输出        = 放行
  退出码 0 + decision:block = 阻断（stdout JSON）
  退出码 2                 = 阻断（stderr 回显给用户）

本 hook 默认用 exit 2（简单、无需构造完整 JSON）。

配置见 hooks/settings.snippet.json。
"""

import json
import os
import re
import sys

# (名称, 正则, 严重度)
CHECKS = [
    ("中国大陆手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "HIGH"),
    ("邮箱", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "MED"),
    ("身份证号", re.compile(r"(?<!\d)[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"), "HIGH"),
    ("明文 API key", re.compile(r"(sk-ant-|sk-|ghp_|gho_|ghu_|ghs_|github_pat_|AKIA|AIza|xox[baprs]-|glpat-|hf_)[A-Za-z0-9_\-]{8,}"), "HIGH"),
    ("Bearer/密码赋值", re.compile(r"(?i)(Bearer|password|passwd|secret|api_?key)[\"':= ]+[A-Za-z0-9_.\-]{8,}"), "HIGH"),
    ("私钥块", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "HIGH"),
    ("内网 IP", re.compile(r"\b(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"), "MED"),
    ("本机用户名路径", re.compile(r"(/home/|/Users/|C:\\Users\\|C:/Users/)[a-zA-Z0-9_.\-]+"), "MED"),
    ("内部主机名", re.compile(r"\b[a-z0-9-]+\.(internal|local|corp|lan|intra)\b"), "MED"),
    ("Telegram 账号", re.compile(r"(?<![\w@])@[A-Za-z][A-Za-z0-9_]{4,31}\b"), "MED"),
    ("中国大陆身份证提及", re.compile(r"身份证号?"), "MED"),
    ("IP:端口 直连地址", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"), "MED"),
]

# 允许列表（示例：本地回环不算泄漏）
ALLOW = [
    re.compile(r"\b(127\.0\.0\.1|0\.0\.0\.0|localhost)\b"),
    re.compile(r"\b10\.0\.0\.0\b"),          # redact.sh 的占位符
    re.compile(r"EMAIL@REDACTED|PHONE_REDACTED|TOKEN_REDACTED|SECRET_REDACTED|IDNUM_REDACTED"),
    re.compile(r"HOST\.internal"),
    re.compile(r"USER\b"),                    # 路径占位符
    re.compile(r"@(REDACTED|example|test)\b"),
]


def mask(s: str) -> str:
    if len(s) <= 6:
        return "*" * len(s)
    return f"{s[:3]}***{s[-2:]}"


def scan(text: str):
    hits = []
    for name, rx, sev in CHECKS:
        for m in rx.finditer(text):
            frag = m.group(0)
            # 允许列表过滤
            if any(a.search(frag) for a in ALLOW):
                continue
            hits.append((sev, name, mask(frag)))
    return hits


def load_text(event: dict) -> str:
    # UserPromptSubmit 事件里 prompt 字段名可能变化，逐个试
    for key in ("prompt", "user_prompt", "text", "content", "message"):
        v = event.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


def main():
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # 不是 JSON，当作纯文本处理
        event = {"prompt": raw}

    text = load_text(event)
    if not text:
        sys.exit(0)

    hits = scan(text)
    if not hits:
        sys.exit(0)

    # 同一类只报第一条
    seen = set()
    lines = []
    for sev, name, masked in hits:
        if name in seen:
            continue
        seen.add(name)
        lines.append(f"  [{sev}] {name}: {masked}")

    msg = [
        "== AI OPSEC: 提示词身份泄漏检查未通过 ==",
        *lines,
        "",
        "处置:",
        "  · 删除上述字段后重发；",
        "  · 或先跑 ./scripts/redact.sh 脱敏；",
        "  · 若为误报，在 hooks/prompt-guard.py 的 ALLOW 里加规则。",
        "",
        "（这是启发式检查，通过不代表无泄漏。）",
    ]
    # exit 2 = 阻断，stderr 内容回显给用户
    print("\n".join(msg), file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
