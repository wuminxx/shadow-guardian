"""CLI 层测试 —— 退出码、错误处理、参数解析。用 subprocess 跑真实进程。"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent.parent
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")


def run_cli(*args, stdin: str = "", cwd=None) -> subprocess.CompletedProcess:
    # encoding 必须显式指定：Windows 默认 GBK，中文输出会解码失败
    return subprocess.run(
        [sys.executable, "-m", "aiopsec", *args],
        input=stdin, capture_output=True,
        encoding="utf-8", errors="replace",
        timeout=120, env=ENV, cwd=str(cwd or TOOL_DIR),
    )


class TestExitCodes(unittest.TestCase):
    def test_help_exit_zero(self):
        self.assertEqual(run_cli("--help").returncode, 0)

    def test_version(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("aiopsec", r.stdout)

    def test_no_command_exit_two(self):
        self.assertEqual(run_cli().returncode, 2)

    def test_unknown_command_exit_two(self):
        self.assertEqual(run_cli("nope").returncode, 2)

    def test_all_subcommands_have_help(self):
        for c in ("scan", "check", "redact", "shred", "env",
                  "harden", "hook", "audit"):
            with self.subTest(cmd=c):
                self.assertEqual(run_cli(c, "--help").returncode, 0)


class TestCheckCLI(unittest.TestCase):
    def test_dirty_exit_one(self):
        r = run_cli("check", "--quiet", stdin="tel 13800138000\n")
        self.assertEqual(r.returncode, 1)

    def test_clean_exit_zero(self):
        r = run_cli("check", "--quiet", stdin="写个快速排序\n")
        self.assertEqual(r.returncode, 0)

    def test_empty_stdin_exit_zero(self):
        self.assertEqual(run_cli("check", stdin="").returncode, 0)

    def test_missing_file_exit_two(self):
        r = run_cli("check", "-f", "/definitely/not/here.txt")
        self.assertEqual(r.returncode, 2)
        self.assertIn("不存在", r.stderr)

    def test_json_output_valid(self):
        r = run_cli("check", "--json", stdin="tel 13800138000\n")
        d = json.loads(r.stdout)
        self.assertEqual(d["command"], "check")
        self.assertIn("summary", d)
        self.assertIn("findings", d)

    def test_kind_filter(self):
        r = run_cli("check", "--kind", "secret", "--json",
                    stdin="tel 13800138000 key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx\n")
        d = json.loads(r.stdout)
        kinds = {f["kind"] for f in d["findings"]}
        self.assertEqual(kinds, {"secret"}, "只应报 secret 类")

    def test_min_severity_filter(self):
        r = run_cli("check", "--min-severity", "HIGH", "--json",
                    stdin="内网 192.168.1.1\n")
        d = json.loads(r.stdout)
        self.assertEqual(d["findings"], [], "MED 不应在高阈值下出现")


class TestRedactCLI(unittest.TestCase):
    def test_stdout_is_clean(self):
        r = run_cli("redact", stdin="tel 13800138000\n")
        self.assertNotIn("13800138000", r.stdout)
        self.assertIn("PHONE_REDACTED", r.stdout)

    def test_dry_run_no_output(self):
        r = run_cli("redact", "--dry-run", stdin="tel 13800138000\n")
        self.assertNotIn("13800138000", r.stdout)
        self.assertIn("预演", r.stdout)

    def test_out_file(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "in.txt"
            o = Path(t) / "out.txt"
            f.write_text("tel 13800138000\n", encoding="utf-8")
            r = run_cli("redact", "-f", str(f), "-o", str(o))
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("13800138000", o.read_text(encoding="utf-8"))

    def test_in_place_creates_backup(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "x.txt"
            f.write_text("tel 13800138000\n", encoding="utf-8")
            r = run_cli("redact", "-f", str(f), "--in-place")
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("13800138000", f.read_text(encoding="utf-8"))
            bak = Path(str(f) + ".bak")
            self.assertTrue(bak.exists(), "应生成 .bak")
            self.assertIn("13800138000", bak.read_text(encoding="utf-8"))


class TestEnvCLI(unittest.TestCase):
    def test_offline_runs(self):
        r = run_cli("env", "--offline")
        self.assertIn(r.returncode, (0, 1))
        self.assertIn("环境指纹", r.stdout)

    def test_json_offline(self):
        r = run_cli("env", "--offline", "--json")
        d = json.loads(r.stdout)
        for k in ("hostname", "timezone", "lang", "issues"):
            self.assertIn(k, d)


class TestHardenCLI(unittest.TestCase):
    def test_preview_writes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            env = dict(ENV, CLAUDE_CONFIG_DIR=t)
            subprocess.run(
                [sys.executable, "-m", "aiopsec", "harden", "--target", "claude"],
                capture_output=True, encoding="utf-8", errors="replace",
                timeout=60, env=env, cwd=str(TOOL_DIR),
            )
            self.assertFalse((Path(t) / "settings.json").exists(),
                             "预演不应写文件")


class TestShredCLI(unittest.TestCase):
    def test_dry_run_safe(self):
        r = run_cli("shred")
        self.assertEqual(r.returncode, 0)
        self.assertIn("DRY-RUN", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
