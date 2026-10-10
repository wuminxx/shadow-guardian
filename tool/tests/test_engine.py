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
    def test_email(self):
        f = engine.scan_text("联系 zhang.wei@corp.example.com")
        self.assertTrue(any(x.rule == "电子邮箱" for x in f))

    def test_email_rfc2606_allowlisted(self):
        f = engine.scan_text("联系 test@example.com")
        self.assertFalse(any(x.rule == "电子邮箱" for x in f))

    def test_card_number_not_flagged(self):
        """位置类 PII 已砍 —— 订单号/测试数据误报太高。"""
        f = engine.scan_text("编号 4539578763621486")
        self.assertFalse(f)

    def test_cn_mobile_not_flagged(self):
        f = engine.scan_text("电话 13800138000")
        self.assertFalse(f, "手机号规则已砍")



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


class TestPaths(unittest.TestCase):
    def test_windows_user_path(self):
        f = engine.scan_text(r"C:\Users\zhangwei\app\log.txt")
        self.assertTrue(any(x.kind == "path" for x in f))

    def test_unix_user_path(self):
        f = engine.scan_text("/home/zhangwei/app/service.py")
        self.assertTrue(any(x.kind == "path" for x in f))


class TestRedact(unittest.TestCase):
    def test_roundtrip(self):
        t = ("zhang@corp.com 10.1.2.3 "
             "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx")
        cleaned, n = engine.redact_text(t)
        self.assertEqual(n, 3)
        self.assertNotIn("zhang@corp.com", cleaned)
        self.assertNotIn("sk-ant-api03", cleaned)
        self.assertIn("EMAIL_REDACTED", cleaned)

    def test_idempotent(self):
        """已脱敏的文本再脱敏不应再变。"""
        t = "PHONE_REDACTED EMAIL_REDACTED"
        cleaned, n = engine.redact_text(t)
        self.assertEqual(n, 0)
        self.assertEqual(cleaned, t)

    def test_kind_filter(self):
        t = "zhang@corp.com sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"
        cleaned, n = engine.redact_text(t, kinds=["secret"])
        self.assertEqual(n, 1)
        self.assertIn("zhang@corp.com", cleaned)


class TestScanMeta(unittest.TestCase):
    def test_clean_text_no_findings(self):
        f = engine.scan_text("写一个 python 快速排序函数")
        self.assertEqual(f, [])

    def test_line_col(self):
        f = engine.scan_text("line1\nline2 10.1.2.3\n")
        self.assertTrue(f)
        self.assertEqual(f[0].line, 2)

    def test_min_severity(self):
        t = "10.0.0.1"            # MED
        self.assertTrue(engine.scan_text(t, min_severity="LOW"))
        self.assertFalse(engine.scan_text(t, min_severity="HIGH"))

    def test_show_raw(self):
        f = engine.scan_text("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx",
                             show_raw=True)
        self.assertTrue(f[0].raw.startswith("sk-ant-"))
        f2 = engine.scan_text("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx",
                              show_raw=False)
        self.assertEqual(f2[0].raw, "")

    def test_dedup_same_offset(self):
        t = "10.1.2.3:8080"
        f = engine.scan_text(t)
        positions = [(x.line, x.col) for x in f]
        self.assertEqual(len(positions), len(set(positions)))


class TestRulesTable(unittest.TestCase):
    def test_all_rules_compile(self):
        for r in R.ALL_RULES:
            r.compile()      # 不抛异常即通过


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestFalsePositives(unittest.TestCase):
    """真实代码/文档里的常见串不该被报。"""

    def test_normal_python_code_clean(self):
        code = '''
import os
from dataclasses import dataclass
DEFAULT = 30

class Svc:
    """服务。@author: team"""
    @property
    def x(self):
        # TODO: cache
        return os.getenv("X")
'''
        self.assertEqual(engine.scan_text(code), [], "正常代码应零命中")

    def test_version_number_not_tg(self):
        self.assertFalse(engine.scan_text("version @1.2.3"))
