"""检测与脱敏引擎 —— 规则表的执行层。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from . import rules as R


@dataclass
class Finding:
    rule: str
    severity: str
    kind: str
    masked: str
    line: int
    col: int
    length: int
    raw: str = ""            # 仅在显式要求时填充（--show-raw）

    def to_dict(self, show_raw: bool = False) -> dict:
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "kind": self.kind,
            "masked": self.masked,
            "line": self.line,
            "col": self.col,
            "length": self.length,
        }
        if show_raw:
            d["raw"] = self.raw
        return d


def mask_value(fragment: str) -> str:
    """在报告里展示的掩码形式：保留首尾少量字符。"""
    s = fragment.strip()
    if len(s) <= 6:
        return "*" * len(s)
    return f"{s[:3]}{'*' * min(len(s) - 5, 12)}{s[-2:]}"


def _validate(rule: R.Rule, match: re.Match) -> bool:
    """有 validator 的规则在这里二次校验，降低误报。"""
    if not rule.validator:
        return True
    fn = R.VALIDATORS.get(rule.validator)
    if fn is None:
        return True
    # 优先用第一个捕获组，没有就用整个匹配
    candidate = match.group(1) if match.groups() else match.group(0)
    return fn(candidate)


def scan_text(text: str, kinds: Iterable[str] | None = None,
              min_severity: str = R.LOW, show_raw: bool = False) -> list[Finding]:
    """扫描文本，返回全部命中。"""
    kinds = set(kinds) if kinds else None
    floor = R.severity_rank(min_severity)
    out: list[Finding] = []

    # 预先算每行起始偏移，供 line/col 换算
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def locate(off: int) -> tuple[int, int]:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, off - line_starts[lo] + 1

    for rule in R.ALL_RULES:
        if kinds and rule.kind not in kinds:
            continue
        if R.severity_rank(rule.severity) < floor:
            continue
        for m in rule.compile().finditer(text):
            frag = m.group(0)
            if R.is_allowlisted(frag):
                continue
            if not _validate(rule, m):
                continue
            ln, col = locate(m.start())
            out.append(Finding(
                rule=rule.name,
                severity=rule.severity,
                kind=rule.kind,
                masked=mask_value(frag),
                line=ln,
                col=col,
                length=len(frag),
                raw=frag if show_raw else "",
            ))

    out.sort(key=lambda f: (f.line, f.col))
    # 同一位置被多条规则命中时，只保留严重度最高、名最长的那条
    deduped: list[Finding] = []
    seen_span: dict[tuple[int, int], Finding] = {}
    for f in out:
        key = (f.line, f.col)
        prev = seen_span.get(key)
        if prev is None:
            seen_span[key] = f
            deduped.append(f)
        else:
            # 同起点保留更严重/更具体的那条
            if (R.severity_rank(f.severity), f.length) > \
               (R.severity_rank(prev.severity), prev.length):
                deduped[deduped.index(prev)] = f
                seen_span[key] = f
    return deduped


def redact_text(text: str, kinds: Iterable[str] | None = None) -> tuple[str, int]:
    """返回 (脱敏后的文本, 替换次数)。

    替换顺序按 kind 优先级：secret > pii > infra > path。
    高优先级先替换，避免被低优先级规则的替换结果再次误伤。
    """
    kinds = set(kinds) if kinds else None
    order = {"secret": 0, "pii": 1, "infra": 2, "path": 3}
    rules = sorted(R.ALL_RULES, key=lambda r: order.get(r.kind, 9))

    total = 0
    result = text
    for rule in rules:
        if kinds and rule.kind not in kinds:
            continue
        rx = rule.compile()
        count = 0

        def _sub(m: re.Match) -> str:
            nonlocal count
            frag = m.group(0)
            if R.is_allowlisted(frag) or not _validate(rule, m):
                return frag
            count += 1
            # mask 里含 \1 时按模板展开，否则整体替换
            if "\\" in rule.mask or "$" in rule.mask:
                try:
                    return m.expand(rule.mask)
                except (re.error, IndexError):
                    return rule.mask
            return rule.mask

        result = rx.sub(_sub, result)
        total += count

    return result, total


def summarize(findings: list[Finding]) -> dict:
    by_sev: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    return {"total": len(findings), "by_severity": by_sev,
            "by_kind": by_kind, "by_rule": by_rule}
