"""引擎与规则表的单元测试。零依赖，用 unittest。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiopsec.core import engine, rules as R


class TestSecrets(unittest.TestCase):
    def test_anthropic_key(self):
        t = "key=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"
        f = engine.scan_text(t)
        self.assertTrue(any(x.rule == "Anthropic API key" for x in f))

    def test_openai_not_double_match(self):
        """sk-ant- 不应同时命中 OpenAI 规则。"""
        t = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"
        f = engine.scan_text(t)
        names = {x.rule for x in f}
        self.assertIn("Anthropic API key", names)
        self.assertNotIn("OpenAI API key", names)

    def test_github_token(self):
        t = "ghp_" + "a" * 40
        f = engine.scan_text(t)
        self.assertTrue(any("GitHub" in x.rule for x in f))

    def test_aws_key(self):
        t = "AKIAIOSFODNN7EXAMPLE"
        f = engine.scan_text(t)
        self.assertTrue(any("AWS" in x.rule for x in f))

    def test_jwt(self):
        t = ("eyJhbGciOiJIUzI1NiJ9."
             "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
             "dQw4w9WgXcQabcd1234")
        f = engine.scan_text(t)
        self.assertTrue(any(x.rule == "JWT" for x in f))

    def test_generic_assigned_secret(self):
        t = 'password = "hunter2hunter2"'
        f = engine.scan_text(t)
        self.assertTrue(any(x.kind == "secret" for x in f))

    def test_connection_string(self):
        t = "postgresql://admin:s3cr3tp4ss@db.internal:5432/app"
        f = engine.scan_text(t)
        self.assertTrue(any(x.kind == "secret" for x in f))


class TestPII(unittest.TestCase):
    def test_cn_mobile(self):
        f = engine.scan_text("电话 13800138000。")
        self.assertTrue(any(x.rule == "中国大陆手机号" for x in f))

    def test_cn_mobile_negatives(self):
        """长度不对的不算。"""
        f = engine.scan_text("编号 1380013800 and 138001380000")
        self.assertFalse(any(x.rule == "中国大陆手机号" for x in f))

    def test_cn_id_valid(self):
        # 11010519491231002X 是公开的合法测试号
        f = engine.scan_text("身份证 11010519491231002X")
        self.assertTrue(any(x.rule == "中国大陆身份证号" for x in f))

    def test_cn_id_invalid_checksum(self):
        """校验位错的应当被 validator 拦掉。"""
        f = engine.scan_text("号码 110105194912310021")
        self.assertFalse(any(x.rule == "中国大陆身份证号" for x in f))

    def test_email(self):
        f = engine.scan_text("联系 zhang.wei@corp.example.com")
        self.assertTrue(any(x.rule == "电子邮箱" for x in f))

    def test_email_rfc2606_allowlisted(self):
        f = engine.scan_text("联系 test@example.com")
        self.assertFalse(any(x.rule == "电子邮箱" for x in f))

    def test_card_luhn_valid(self):
        f = engine.scan_text("卡号 4539578763621486")
        self.assertTrue(any(x.rule == "银行卡号" for x in f))

    def test_card_luhn_invalid(self):
        f = engine.scan_text("编号 1234567890123456")
        self.assertFalse(any(x.rule == "银行卡号" for x in f))


class TestInfra(unittest.TestCase):
    def test_private_ip(self):
        f = engine.scan_text("内网 192.168.1.100")
        self.assertTrue(any("私有 IPv4" in x.rule for x in f))

    def test_public_ip_not_flagged_as_private(self):
        f = engine.scan_text("8.8.8.8")
        self.assertFalse(any("私有 IPv4" in x.rule for x in f))

    def test_ip_port(self):
        f = engine.scan_text("连 203.0.113.5:8443")
        self.assertTrue(any("IPv4 + 端口" in x.rule for x in f))

    def test_internal_host(self):
        f = engine.scan_text("db.corp.internal")
        self.assertTrue(any("内部主机名" in x.rule for x in f))

    def test_metadata_endpoint(self):
        f = engine.scan_text("http://169.254.169.254/latest/meta-data/")
        self.assertTrue(any("元数据" in x.rule for x in f))


class TestPaths(unittest.TestCase):
    def test_windows_user_path(self):
        f = engine.scan_text(r"C:\Users\zhangwei\app\log.txt")
        self.assertTrue(any(x.kind == "path" for x in f))

    def test_unix_user_path(self):
        f = engine.scan_text("/home/zhangwei/app/service.py")
        self.assertTrue(any(x.kind == "path" for x in f))


class TestRedact(unittest.TestCase):
    def test_roundtrip(self):
        t = ("13800138000 zhang@corp.com 10.1.2.3 "
             "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx")
        cleaned, n = engine.redact_text(t)
        self.assertEqual(n, 4)
        self.assertNotIn("13800138000", cleaned)
        self.assertNotIn("zhang@corp.com", cleaned)
        self.assertNotIn("sk-ant-api03", cleaned)
        self.assertIn("PHONE_REDACTED", cleaned)

    def test_idempotent(self):
        """已脱敏的文本再脱敏不应再变。"""
        t = "PHONE_REDACTED EMAIL_REDACTED"
        cleaned, n = engine.redact_text(t)
        self.assertEqual(n, 0)
        self.assertEqual(cleaned, t)

    def test_kind_filter(self):
        t = "13800138000 sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"
        cleaned, n = engine.redact_text(t, kinds=["pii"])
        self.assertEqual(n, 1)
        self.assertIn("sk-ant-api03", cleaned)


class TestScanMeta(unittest.TestCase):
    def test_clean_text_no_findings(self):
        f = engine.scan_text("写一个 python 快速排序函数")
        self.assertEqual(f, [])

    def test_line_col(self):
        f = engine.scan_text("line1\nline2 13800138000\n")
        self.assertTrue(f)
        self.assertEqual(f[0].line, 2)

    def test_min_severity(self):
        t = "192.168.1.1"           # MED
        self.assertTrue(engine.scan_text(t, min_severity="LOW"))
        self.assertFalse(engine.scan_text(t, min_severity="HIGH"))

    def test_show_raw(self):
        f = engine.scan_text("13800138000", show_raw=True)
        self.assertEqual(f[0].raw, "13800138000")
        f2 = engine.scan_text("13800138000", show_raw=False)
        self.assertEqual(f2[0].raw, "")

    def test_dedup_same_offset(self):
        """同位置的重复命中应合并。"""
        t = "10.1.2.3:8080"
        f = engine.scan_text(t)
        positions = [(x.line, x.col) for x in f]
        self.assertEqual(len(positions), len(set(positions)))


class TestRulesTable(unittest.TestCase):
    def test_all_rules_compile(self):
        for r in R.ALL_RULES:
            r.compile()      # 不抛异常即通过

    def test_validators_exist(self):
        for r in R.ALL_RULES:
            if r.validator:
                self.assertIn(r.validator, R.VALIDATORS)

    def test_luhn(self):
        self.assertTrue(R.VALIDATORS["luhn"]("4539578763621486"))
        self.assertFalse(R.VALIDATORS["luhn"]("1234567890123456"))

    def test_cn_id(self):
        self.assertTrue(R.VALIDATORS["cn_id"]("11010519491231002X"))
        self.assertFalse(R.VALIDATORS["cn_id"]("110105194912310021"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
