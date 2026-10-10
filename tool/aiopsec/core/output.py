"""终端输出 —— 颜色、表格、进度。无第三方依赖。"""

from __future__ import annotations

import os
import sys

_NO_COLOR = bool(os.environ.get("NO_COLOR"))
_IS_TTY = sys.stdout.isatty()


def _supports_color() -> bool:
    if _NO_COLOR or not _IS_TTY:
        return False
    if os.name == "nt":
        # Windows 10+ 终端支持 ANSI；确保 VT 开启
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


COLOR = _supports_color()


def c(text: str, code: str) -> str:
    if not COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(s):    return c(s, "1")
def dim(s):     return c(s, "2")
def red(s):     return c(s, "31")
def green(s):   return c(s, "32")
def yellow(s):  return c(s, "33")
def blue(s):    return c(s, "34")
def magenta(s): return c(s, "35")
def cyan(s):    return c(s, "36")


SEV_COLOR = {"HIGH": red, "MED": yellow, "LOW": cyan}


def sev(s: str) -> str:
    return SEV_COLOR.get(s, str)(s)


def human_bytes(n: int) -> str:
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= div:
            return f"{n / div:.2f} {unit}"
    return f"{n} B"


def header(title: str) -> str:
    line = "─" * max(8, min(len(title) + 4, 60))
    return f"\n{bold(title)}\n{dim(line)}"


def kv(key: str, value: str, width: int = 18) -> str:
    return f"  {key:<{width}} {value}"


def table(headers: list[str], rows: list[list[str]], indent: int = 2) -> str:
    if not rows:
        return dim("  (无数据)")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            # 去掉 ANSI 再算宽度
            plain = _strip_ansi(cell)
            widths[i] = max(widths[i], len(plain))
    pad = " " * indent
    out = [pad + "  ".join(bold(h.ljust(widths[i])) for i, h in enumerate(headers))]
    out.append(pad + "  ".join("─" * w for w in widths))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            plain_len = len(_strip_ansi(cell))
            cells.append(cell + " " * max(0, widths[i] - plain_len))
        out.append(pad + "  ".join(cells))
    return "\n".join(out)


def _strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def ok(msg):   return f"{green('✓')} {msg}"
def warn(msg): return f"{yellow('!')} {msg}"
def err(msg):  return f"{red('✗')} {msg}"
def info(msg): return f"{blue('·')} {msg}"
