"""落盘取证面测绘 —— 找 AI 客户端在本机留下的东西。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

HOME = Path.home()


@dataclass
class Target:
    path: Path
    app: str
    desc: str
    sensitive: bool = False
    # 只统计顶层文件，不递归（用于含大量下载缓存的目录，如插件目录）
    shallow: bool = False


@dataclass
class SurfaceHit:
    path: str
    app: str
    desc: str
    bytes: int
    files: int
    sensitive: bool
    newest: float = 0.0
    samples: list[str] = field(default_factory=list)

    @property
    def human_bytes(self) -> str:
        b = self.bytes
        for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
            if b >= div:
                return f"{b / div:.2f} {unit}"
        return f"{b} B"


def _t(p: str, app: str, desc: str, sensitive: bool = False,
       shallow: bool = False) -> Target:
    return Target(Path(os.path.expandvars(p)).expanduser(), app, desc,
                  sensitive, shallow)


def default_targets() -> list[Target]:
    return [
        # ---- Claude Code ----
        _t("~/.claude/projects", "claude-code", "会话 transcript（明文 JSONL）", True),
        _t("~/.claude/history.jsonl", "claude-code", "输入过的每条 prompt", True),
        _t("~/.claude/memory", "claude-code", "跨会话 memory", True),
        _t("~/.claude/todos", "claude-code", "任务清单", False),
        _t("~/.claude/shell-snapshots", "claude-code", "shell 快照（含 env）", True),
        _t("~/.claude/statsig", "claude-code", "遥测 ID", False),
        _t("~/.claude/plugins", "claude-code",
           "插件目录（只查顶层：installed/marketplaces 元数据）", False,
           shallow=True),
        # ---- Codex ----
        _t("~/.codex/sessions", "codex", "会话记录", True),
        _t("~/.codex/history.jsonl", "codex", "输入历史", True),
        _t("~/.codex/log", "codex", "日志", True),
        # ---- Cursor ----
        _t("~/.cursor/logs", "cursor", "日志", False),
        _t("~/.cursor/User/History", "cursor", "文件编辑历史", True),
        _t("~/.cursor/User/globalStorage", "cursor", "AI 对话存储", True),
        _t("~/AppData/Roaming/Cursor/User/History", "cursor", "文件编辑历史", True),
        _t("~/AppData/Roaming/Cursor/User/globalStorage", "cursor", "AI 对话存储", True),
        _t("~/Library/Application Support/Cursor/User/History", "cursor", "文件编辑历史", True),
        _t("~/Library/Application Support/Cursor/User/globalStorage", "cursor", "AI 对话存储", True),
        # ---- Continue ----
        _t("~/.continue/sessions", "continue", "会话", True),
        _t("~/.continue", "continue", "配置与会话", True),
        # ---- Aider ----
        _t("~/.aider/analytics.jsonl", "aider", "使用分析", False),
        _t("~/.aider", "aider", "配置", False),
        # ---- VS Code / Copilot ----
        _t("~/AppData/Roaming/Code/User/globalStorage/github.copilot-chat",
           "vscode-copilot", "Copilot 对话存储", True),
        _t("~/.config/Code/User/globalStorage/github.copilot-chat",
           "vscode-copilot", "Copilot 对话存储", True),
        _t("~/Library/Application Support/Code/User/globalStorage/github.copilot-chat",
           "vscode-copilot", "Copilot 对话存储", True),
        # ---- 本地模型 ----
        _t("~/.ollama/models", "ollama", "模型文件", False),
        _t("~/.ollama/logs", "ollama", "日志", True),
        _t("~/.cache/huggingface", "huggingface", "模型缓存", False),
        _t("~/.lmstudio", "lmstudio", "模型与日志", True),
        # ---- 浏览器 ----
        _t("~/.config/google-chrome/Default", "chrome", "浏览器 profile（含 Web 存储）", True),
        _t("~/.config/chromium/Default", "chromium", "浏览器 profile", True),
        _t("~/AppData/Local/Google/Chrome/User Data/Default", "chrome", "浏览器 profile", True),
        _t("~/AppData/Local/Microsoft/Edge/User Data/Default", "edge", "浏览器 profile", True),
        _t("~/Library/Application Support/Google/Chrome/Default", "chrome", "浏览器 profile", True),
        # ---- 其他 agent ----
        _t("~/.opencode", "opencode", "会话与配置", True),
        _t("~/.windsurf", "windsurf", "会话与配置", True),
        _t("~/.config/opencode", "opencode", "配置", False),
    ]


# 会话/历史类文件名特征 —— 命中即高危
SENSITIVE_NAME_HINTS = (
    "history", "session", "transcript", "memory", "conversation",
    "chat", "todos", "projects", "snapshot", "log",
)


# 遍历时跳过的纯缓存目录（不含任何一个存储会话/历史数据的位置）
SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".tox",
    # 浏览器纯缓存（无对话内容）
    "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache",
    "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache",
    "Cache_Data", "CacheStorage", "Service Worker",
    # 保留：Local Storage / IndexedDB / Session Storage
    #       —— 浏览器版 AI 的会话就存在这里，不能跳
})


def _walk_stats(root: Path, max_files: int = 200_000,
                max_seconds: float = 20.0, shallow: bool = False
                ) -> tuple[int, int, float, list[str]]:
    """用 os.scandir 统计目录（比 os.walk + lstat 快数倍）。

    shallow=True 时只统计顶层文件，不进子目录。
    带时间上限，避免超大目录拖死整个扫描。
    """
    import time as _t
    total = 0
    count = 0
    newest = 0.0
    samples: list[str] = []
    deadline = _t.monotonic() + max_seconds
    stack: list[str] = [str(root)]

    while stack:
        if count >= max_files or _t.monotonic() > deadline:
            break
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not shallow and entry.name not in SKIP_DIRS:
                                stack.append(entry.path)
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total += st.st_size
                    count += 1
                    if st.st_mtime > newest:
                        newest = st.st_mtime
                    if len(samples) < 8:
                        low = entry.name.lower()
                        if any(h in low for h in SENSITIVE_NAME_HINTS):
                            samples.append(entry.path)
                    if count >= max_files:
                        break
        except OSError:
            continue

    return total, count, newest, samples


def _probe_one(t: Target) -> SurfaceHit | None:
    p = t.path
    try:
        if not p.exists():
            return None
        if p.is_file():
            st = p.stat()
            return SurfaceHit(
                path=str(p), app=t.app, desc=t.desc,
                bytes=st.st_size, files=1,
                sensitive=t.sensitive, newest=st.st_mtime,
                samples=[str(p)] if t.sensitive else [],
            )
        if p.is_dir():
            total, count, newest, samples = _walk_stats(p, shallow=t.shallow)
            return SurfaceHit(
                path=str(p), app=t.app, desc=t.desc,
                bytes=total, files=count,
                sensitive=t.sensitive or bool(samples),
                newest=newest, samples=samples,
            )
    except OSError:
        return None
    return None


def probe(targets: list[Target] | None = None) -> list[SurfaceHit]:
    targets = targets or default_targets()

    # 去重（避免 symlink / 重复路径重复遍历）
    seen: set[str] = set()
    uniq: list[Target] = []
    for t in targets:
        try:
            key = str(t.path.resolve())
        except OSError:
            key = str(t.path)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(t)

    hits: list[SurfaceHit] = []
    # 并发遍历：各目标互相独立，IO bound
    try:
        from concurrent.futures import ThreadPoolExecutor
        workers = min(8, max(2, (os.cpu_count() or 4)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for h in ex.map(_probe_one, uniq):
                if h is not None:
                    hits.append(h)
    except Exception:
        # 并发不可用时退回串行
        for t in uniq:
            h = _probe_one(t)
            if h is not None:
                hits.append(h)

    hits.sort(key=lambda h: (-h.sensitive, -h.bytes))
    return hits


def totals(hits: list[SurfaceHit]) -> dict:
    return {
        "paths": len(hits),
        "bytes": sum(h.bytes for h in hits),
        "files": sum(h.files for h in hits),
        "sensitive": sum(1 for h in hits if h.sensitive),
    }
