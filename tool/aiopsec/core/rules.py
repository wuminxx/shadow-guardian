"""检测规则表 —— 单一数据源，redact / scan / hook / audit 共用。

每条规则:
    name        显示名
    severity    HIGH | MED | LOW
    pattern     正则（re 模块语法）
    mask        脱敏时替换成什么
    kind        "secret" | "pii" | "infra" | "path"
    flags       可选 re 标志
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

HIGH = "HIGH"
MED = "MED"
LOW = "LOW"


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: str
    mask: str
    kind: str
    flags: int = 0
    # 编译后可选的"必须满足"回调名（见 validators）
    validator: str = ""

    def compile(self) -> Pattern[str]:
        return re.compile(self.pattern, self.flags)


# ---------------------------------------------------------------- 校验器
VALIDATORS = {}

# ---------------------------------------------------------------- 密钥类
SECRET_RULES = [
    Rule("Anthropic API key", HIGH,
         r"sk-ant-[A-Za-z0-9_\-]{20,}", "ANTHROPIC_KEY_REDACTED", "secret"),
    Rule("OpenAI API key", HIGH,
         r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}", "OPENAI_KEY_REDACTED", "secret"),
    Rule("GitHub token", HIGH,
         r"gh[pousr]_[A-Za-z0-9]{36,}", "GITHUB_TOKEN_REDACTED", "secret"),
    Rule("GitHub PAT (fine-grained)", HIGH,
         r"github_pat_[A-Za-z0-9_]{22,}", "GITHUB_PAT_REDACTED", "secret"),
    Rule("AWS access key ID", HIGH,
         r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", "AWS_AKID_REDACTED", "secret"),
    Rule("AWS secret access key", HIGH,
         r"(?i)aws[_\- ]?(?:secret[_\- ]?)?access[_\- ]?key[\"'\s:=]+([A-Za-z0-9/+=]{40})",
         r"aws_secret=\1\2AWS_SECRET_REDACTED", "secret"),
    Rule("Google API key", HIGH,
         r"AIza[0-9A-Za-z_\-]{35}", "GOOGLE_KEY_REDACTED", "secret"),
    Rule("Slack token", HIGH,
         r"xox[baprs]-[0-9A-Za-z\-]{10,}", "SLACK_TOKEN_REDACTED", "secret"),
    Rule("GitLab PAT", HIGH,
         r"glpat-[A-Za-z0-9_\-]{20,}", "GITLAB_PAT_REDACTED", "secret"),
    Rule("HuggingFace token", HIGH,
         r"hf_[A-Za-z0-9]{30,}", "HF_TOKEN_REDACTED", "secret"),
    Rule("Stripe key", HIGH,
         r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}", "STRIPE_KEY_REDACTED", "secret"),
    Rule("JWT", MED,
         r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
         "JWT_REDACTED", "secret"),
    Rule("PEM private key", HIGH,
         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,4000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
         "-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----", "secret"),
    Rule("age / SSH key marker", MED,
         r"-----BEGIN (?:AGE-SECRET-KEY|OPENSSH PRIVATE KEY)-----",
         "PRIVATE_KEY_REDACTED", "secret"),
    Rule("generic assigned secret", HIGH,
         r"(?i)\b(api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|"
         r"client[_\-]?secret|private[_\-]?key|password|passwd|pwd)\b[\"'\s]*[:=][\"'\s]*"
         r"([A-Za-z0-9_\-./+=]{12,})",
         r"\1=SECRET_REDACTED", "secret"),
    Rule("Bearer token", HIGH,
         r"(?i)\bbearer\s+([A-Za-z0-9_\-./+=]{20,})", "Bearer TOKEN_REDACTED", "secret"),
    Rule("connection string w/ password", HIGH,
         r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
         r"([^:@/\s]+):([^@/\s]+)@",
         r"DBURL_REDACTED\1:\2@", "secret"),
]

# ---------------------------------------------------------------- 个人信息
PII_RULES = [
    # 只保留邮箱。位置类 PII（中国手机号/身份证/银行卡/车牌/座机）已砍：
    #   1) 真实泄漏里极少以明文形态出现在给 AI 的文本中
    #   2) 误报率高（订单号、日志、测试数据都像）
    #   3) 攻击者不会用这些格式投递
    Rule("电子邮箱", MED,
         r"(?<![\w.\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?![\w.\-])",
         "EMAIL_REDACTED", "pii"),
]

# ---------------------------------------------------------------- 基础设施
INFRA_RULES = [
    Rule("私有 IPv4 (RFC1918)", MED,
         r"(?<![0-9])(?:10\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9])",
         "PRIVATE_IP_REDACTED", "infra"),
    Rule("IPv4 + 端口", MED,
         r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}(?![0-9])",
         "IPPORT_REDACTED", "infra"),
    Rule("内部主机名", MED,
         r"(?:[a-z0-9][a-z0-9\-]*\.)+(?:internal|local|corp|lan|intra|intranet|home\.arpa)(?![A-Za-z0-9.\-])",
         "INTERNAL_HOST_REDACTED", "infra"),
]

# ---------------------------------------------------------------- 路径
PATH_RULES = [
    Rule("Windows 用户路径", MED,
         r"[A-Za-z]:[\\/]Users[\\/]([^\\/\s\"'<>|]{1,64})",
         r"C:\\Users\\USER", "path"),
    Rule("Unix 用户路径", MED,
         r"/(?:home|Users)/([^/\s\"'<>|]{1,64})",
         r"/home/USER", "path"),
]

ALL_RULES: list[Rule] = SECRET_RULES + PII_RULES + INFRA_RULES + PATH_RULES


# ---------------------------------------------------------------- 白名单
# 命中这些值的片段不视为泄漏（占位符 / 回环 / 示例值）
ALLOWLIST = [
    re.compile(r"^(?:127\.0\.0\.1|0\.0\.0\.0|::1|localhost)$", re.I),
    re.compile(r"^10\.0\.0\.0$"),
    re.compile(r"(?:PHONE|EMAIL|TOKEN|SECRET|ID|CARD|PLATE|IPV6|JWT|HANDLE|PRIVATE|AWS|"
               r"OPENAI|ANTHROPIC|GITHUB|GITLAB|GOOGLE|SLACK|HF|STRIPE|DBURL|LANDLINE|"
               r"INTERNAL|IPPORT)_(?:REDACTED|HOST|SVC)", re.I),
    re.compile(r"@(?:REDACTED|test|localhost)\b", re.I),
    # 只放行 RFC2606 保留域的完整邮箱
    re.compile(r"^[A-Za-z0-9._%+\-]+@(?:example\.(?:com|org|net)|test|localhost)$", re.I),
    re.compile(r"^USER$|USER$"),
    re.compile(r"^example\.(?:com|org|net)$", re.I),
]


def is_allowlisted(fragment: str) -> bool:
    return any(rx.search(fragment) for rx in ALLOWLIST)


def rules_by_kind(kind: str) -> list[Rule]:
    return [r for r in ALL_RULES if r.kind == kind]


def severity_rank(sev: str) -> int:
    return {HIGH: 3, MED: 2, LOW: 1}.get(sev, 0)
