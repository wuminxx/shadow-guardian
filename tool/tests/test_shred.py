"""shred 命令的行为测试 —— 用临时 HOME 做沙箱，不碰真实数据。"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiopsec.commands import shred_cmd


class _Args:
    def __init__(self, **kw):
        self.force = kw.get("force", False)
        self.app = kw.get("app", [])
        self.include_config = kw.get("include_config", False)
        self.passes = kw.get("passes", 1)
        self.no_overwrite = kw.get("no_overwrite", False)


class ShredSandbox(unittest.TestCase):
    """把 HOME / USERPROFILE 指向临时目录再跑。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._old = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE")}
        os.environ["HOME"] = str(self.root)
        os.environ["USERPROFILE"] = str(self.root)

        c = self.root / ".claude"
        (c / "projects" / "x").mkdir(parents=True)
        (c / "todos").mkdir()
        (c / "shell-snapshots").mkdir()
        for i in (1, 2, 3):
            (c / "projects" / "x" / f"sess{i}.jsonl").write_text(
                f"secret transcript {i} 13800138000\n", encoding="utf-8")
        (c / "shell-snapshots" / "snap.sh").write_text("env dump\n", encoding="utf-8")
        (c / "todos" / "t.jsonl").write_text("task\n", encoding="utf-8")
        (c / "history.jsonl").write_text("prompt 1\nprompt 2\n", encoding="utf-8")
        (c / "settings.json").write_text('{"keep": true}\n', encoding="utf-8")

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def _c(self) -> Path:
        return self.root / ".claude"

    def test_dry_run_deletes_nothing(self):
        shred_cmd.run(_Args(force=False))
        self.assertTrue((self._c() / "projects" / "x" / "sess1.jsonl").exists())
        self.assertTrue((self._c() / "history.jsonl").exists())
        self.assertEqual((self._c() / "history.jsonl").stat().st_size > 0, True)

    def test_force_removes_session_dirs(self):
        shred_cmd.run(_Args(force=True))
        self.assertFalse((self._c() / "projects").exists())
        self.assertFalse((self._c() / "todos").exists())
        self.assertFalse((self._c() / "shell-snapshots").exists())

    def test_history_cleared_not_deleted(self):
        """history.jsonl 应被清空成 0 字节，文件保留（客户端要求存在）。"""
        shred_cmd.run(_Args(force=True))
        h = self._c() / "history.jsonl"
        self.assertTrue(h.exists(), "history.jsonl 应保留")
        self.assertEqual(h.stat().st_size, 0, "history.jsonl 应清空")

    def test_settings_untouched_by_default(self):
        shred_cmd.run(_Args(force=True))
        s = self._c() / "settings.json"
        self.assertTrue(s.exists())
        self.assertEqual(json.loads(s.read_text(encoding="utf-8")), {"keep": True})

    def test_include_config_removes_settings(self):
        shred_cmd.run(_Args(force=True, include_config=True))
        self.assertFalse((self._c() / "settings.json").exists())

    def test_app_filter(self):
        """--app 只清指定客户端。"""
        (self.root / ".codex" / "sessions").mkdir(parents=True)
        (self.root / ".codex" / "sessions" / "s.jsonl").write_text("x", encoding="utf-8")
        shred_cmd.run(_Args(force=True, app=["codex"]))
        self.assertFalse((self.root / ".codex" / "sessions").exists(),
                         "codex 应被清")
        self.assertTrue((self._c() / "projects" / "x" / "sess1.jsonl").exists(),
                        "claude-code 不应被碰")

    def test_no_overwrite_still_deletes(self):
        shred_cmd.run(_Args(force=True, no_overwrite=True))
        self.assertFalse((self._c() / "projects").exists())
        self.assertEqual((self._c() / "history.jsonl").stat().st_size, 0)

    def test_no_data_left_behind(self):
        """清理后，临时 HOME 下不应有含敏感串的文件。"""
        shred_cmd.run(_Args(force=True))
        leftovers = []
        for p in self.root.rglob("*"):
            if p.is_file():
                try:
                    if "13800138000" in p.read_text(encoding="utf-8", errors="ignore"):
                        leftovers.append(str(p))
                except OSError:
                    pass
        self.assertEqual(leftovers, [], f"残留敏感文件: {leftovers}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
