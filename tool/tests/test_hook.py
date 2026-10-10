"""hook 命令的测试 —— 重点是生成的 launcher 脚本可独立运行。"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiopsec.commands import hook_cmd


class TestGuard(unittest.TestCase):
    def _run_guard(self, payload: str) -> int:
        old = sys.stdin
        sys.stdin = io.StringIO(payload)
        try:
            return hook_cmd.guard()
        finally:
            sys.stdin = old

    def test_dirty_blocks(self):
        rc = self._run_guard(json.dumps({"prompt": "我的手机 13800138000"}))
        self.assertEqual(rc, 2)

    def test_clean_passes(self):
        rc = self._run_guard(json.dumps({"prompt": "写个快速排序"}))
        self.assertEqual(rc, 0)

    def test_empty_prompt(self):
        rc = self._run_guard("")
        self.assertEqual(rc, 0)

    def test_threshold_med(self):
        """MED 阈值下，仅 MED 命中也要阻断。"""
        old = os.environ.get("AIOP_SEC_BLOCK")
        os.environ["AIOP_SEC_BLOCK"] = "MED"
        try:
            rc = self._run_guard(json.dumps({"prompt": "内网 192.168.1.1"}))
            self.assertEqual(rc, 2)
        finally:
            if old is None:
                os.environ.pop("AIOP_SEC_BLOCK", None)
            else:
                os.environ["AIOP_SEC_BLOCK"] = old

    def test_threshold_none_never_blocks(self):
        old = os.environ.get("AIOP_SEC_BLOCK")
        os.environ["AIOP_SEC_BLOCK"] = "NONE"
        try:
            rc = self._run_guard(json.dumps({"prompt": "我的手机 13800138000"}))
            self.assertEqual(rc, 0)
        finally:
            if old is None:
                os.environ.pop("AIOP_SEC_BLOCK", None)
            else:
                os.environ["AIOP_SEC_BLOCK"] = old

    def test_non_json_input(self):
        """非 JSON 输入应当不崩。"""
        rc = self._run_guard("plain text 13800138000")
        self.assertIn(rc, (0, 2))


class TestLauncher(unittest.TestCase):
    """生成的 launcher 必须能脱离 pip install -e 独立跑。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_cfg = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = self.tmp.name

    def tearDown(self):
        if self.old_cfg is None:
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
        else:
            os.environ["CLAUDE_CONFIG_DIR"] = self.old_cfg
        self.tmp.cleanup()

    def test_launcher_created(self):
        p = hook_cmd._hook_script("guard")
        self.assertTrue(p.exists())
        body = p.read_text(encoding="utf-8")
        self.assertIn("sys.path.insert", body)
        self.assertIn("main_entry", body)
        self.assertIn("'guard'", body)

    def test_launcher_no_double_backslash(self):
        """Windows 路径不应出现 \\\\ （repr 与 raw string 叠加的 bug）。"""
        p = hook_cmd._hook_script("guard")
        body = p.read_text(encoding="utf-8")
        self.assertNotIn("\\\\\\\\", body)

    def test_launcher_is_runnable(self):
        """真的用 subprocess 跑一遍 launcher。"""
        p = hook_cmd._hook_script("guard")
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(
            [sys.executable, str(p)],
            input=json.dumps({"prompt": "手机 13800138000"}),
            capture_output=True, text=True, timeout=30, env=env,
        )
        self.assertEqual(r.returncode, 2, f"stderr={r.stderr}")

    def test_launcher_clean_exit_zero(self):
        p = hook_cmd._hook_script("guard")
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(
            [sys.executable, str(p)],
            input=json.dumps({"prompt": "hello"}),
            capture_output=True, text=True, timeout=30, env=env,
        )
        self.assertEqual(r.returncode, 0, f"stderr={r.stderr}")


class TestSettingsMerge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_cfg = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = self.tmp.name
        self.settings = Path(self.tmp.name) / "settings.json"

    def tearDown(self):
        if self.old_cfg is None:
            os.environ.pop("CLAUDE_CONFIG_DIR", None)
        else:
            os.environ["CLAUDE_CONFIG_DIR"] = self.old_cfg
        self.tmp.cleanup()

    def test_install_creates_settings(self):
        class A:
            install, uninstall, apply, status, sub = True, False, True, False, None
        hook_cmd.run(A())
        cfg = json.loads(self.settings.read_text(encoding="utf-8"))
        cmds = [h.get("command", "")
                for evt in cfg.get("hooks", {}).values()
                for e in evt for h in e.get("hooks", [])]
        self.assertTrue(any("aiopsec" in c or "hook-guard" in c for c in cmds))

    def test_install_preserves_existing(self):
        self.settings.parent.mkdir(parents=True, exist_ok=True)
        self.settings.write_text(json.dumps({
            "enabledPlugins": {"a@b": True},
            "env": {"MY_VAR": "keep-me"},
        }), encoding="utf-8")

        class A:
            install, uninstall, apply, status, sub = True, False, True, False, None
        hook_cmd.run(A())

        cfg = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertEqual(cfg["enabledPlugins"], {"a@b": True})
        self.assertEqual(cfg["env"]["MY_VAR"], "keep-me")

    def test_uninstall_removes_only_ours(self):
        self.settings.parent.mkdir(parents=True, exist_ok=True)
        self.settings.write_text(json.dumps({
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"type": "command", "command": "other-tool"}]},
                ]
            }
        }), encoding="utf-8")

        class A:
            install, uninstall, apply, status, sub = True, False, True, False, None
        hook_cmd.run(A())

        class B:
            install, uninstall, apply, status, sub = False, True, True, False, None
        hook_cmd.run(B())

        cfg = json.loads(self.settings.read_text(encoding="utf-8"))
        cmds = [h.get("command", "")
                for evt in cfg.get("hooks", {}).values()
                for e in evt for h in e.get("hooks", [])]
        self.assertNotIn("other-tool", cmds) if False else None
        self.assertTrue(any(c == "other-tool" for c in cmds), "别人的 hook 应保留")
        self.assertFalse(any("aiopsec" in c or "hook-guard" in c for c in cmds))


if __name__ == "__main__":
    unittest.main(verbosity=2)
