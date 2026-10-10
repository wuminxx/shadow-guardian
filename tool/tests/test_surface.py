"""surface 遍历的性能与正确性测试。"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiopsec.core import surface


class TestWalkStats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _mk(self, rel: str, content: str = "x"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_counts_files_and_bytes(self):
        self._mk("a.txt", "12345")
        self._mk("sub/b.txt", "123")
        total, count, _, _ = surface._walk_stats(self.root)
        self.assertEqual(count, 2)
        self.assertEqual(total, 8)

    def test_skips_noise_dirs(self):
        self._mk("keep.txt")
        self._mk("node_modules/big.js", "x" * 1000)
        self._mk("__pycache__/c.pyc", "x" * 1000)
        _, count, _, _ = surface._walk_stats(self.root)
        self.assertEqual(count, 1, "噪声目录应被跳过")

    def test_keeps_browser_storage(self):
        """浏览器 Local Storage / IndexedDB 必须保留（会话数据在这里）。"""
        self._mk("Local Storage/leveldb/000003.log")
        self._mk("IndexedDB/https_x.indexeddb.leveldb/000001.log")
        _, count, _, _ = surface._walk_stats(self.root)
        self.assertEqual(count, 2, "浏览器存储目录不能被跳过")

    def test_shallow_mode(self):
        self._mk("top.txt")
        self._mk("cache/deep/big.bin", "x" * 5000)
        total, count, _, _ = surface._walk_stats(self.root, shallow=True)
        self.assertEqual(count, 1, "shallow 只统计顶层")
        self.assertEqual(total, 1)

    def test_time_limit(self):
        """时间上限应生效，不无限跑。"""
        # 造很多目录
        for i in range(200):
            self._mk(f"d{i}/f.txt")
        t0 = time.monotonic()
        surface._walk_stats(self.root, max_seconds=0.05)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 5.0, "时间上限应生效")

    def test_max_files(self):
        for i in range(50):
            self._mk(f"f{i}.txt")
        _, count, _, _ = surface._walk_stats(self.root, max_files=10)
        self.assertLessEqual(count, 10)

    def test_samples_only_sensitive_names(self):
        self._mk("history.jsonl")
        self._mk("normal.txt")
        _, _, _, samples = surface._walk_stats(self.root)
        self.assertTrue(any("history" in s for s in samples))
        self.assertFalse(any("normal" in s for s in samples))

    def test_missing_dir_returns_zero(self):
        total, count, newest, samples = surface._walk_stats(self.root / "nope")
        self.assertEqual((total, count, newest), (0, 0, 0.0))
        self.assertEqual(samples, [])


class TestProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_probe_dedupes_and_handles_missing(self):
        d = self.root / "d"
        d.mkdir()
        (d / "f.txt").write_text("x", encoding="utf-8")
        targets = [
            surface.Target(d, "a", "desc1"),
            surface.Target(d, "a", "desc2"),          # 重复
            surface.Target(self.root / "gone", "b", "missing"),
        ]
        hits = surface.probe(targets)
        self.assertEqual(len(hits), 1, "重复路径应去重，缺失路径应跳过")

    def test_probe_file_target(self):
        f = self.root / "history.jsonl"
        f.write_text("12345", encoding="utf-8")
        hits = surface.probe([surface.Target(f, "a", "d", sensitive=True)])
        self.assertEqual(hits[0].files, 1)
        self.assertEqual(hits[0].bytes, 5)
        self.assertTrue(hits[0].sensitive)

    def test_probe_sorted_sensitive_first(self):
        big = self.root / "big"
        big.mkdir()
        (big / "x.bin").write_text("y" * 100, encoding="utf-8")
        small_sens = self.root / "hist"
        small_sens.mkdir()
        (small_sens / "history.jsonl").write_text("z", encoding="utf-8")
        hits = surface.probe([
            surface.Target(big, "a", "big", sensitive=False),
            surface.Target(small_sens, "b", "sens", sensitive=True),
        ])
        self.assertTrue(hits[0].sensitive, "敏感项应排前面")

    def test_totals(self):
        d = self.root / "d"
        d.mkdir()
        (d / "f").write_text("xx", encoding="utf-8")
        hits = surface.probe([surface.Target(d, "a", "d", sensitive=True)])
        t = surface.totals(hits)
        self.assertEqual(t["paths"], 1)
        self.assertEqual(t["files"], 1)
        self.assertEqual(t["sensitive"], 1)
        self.assertEqual(t["bytes"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
