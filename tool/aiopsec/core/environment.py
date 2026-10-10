"""环境指纹一致性检查 —— 时区 / 语言 / IP 地理位置 / 主机名 是否互相矛盾。

矛盾本身就是归因信号：声称在某地，但时区/语言/出口 IP 指向另一处。
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field

TIMEOUT = 6


@dataclass
class EnvReport:
    hostname: str = ""
    username: str = ""
    os_name: str = ""
    tz: str = ""
    tz_offset: str = ""
    lang: str = ""
    langs: list[str] = field(default_factory=list)
    public_ip: str = ""
    ip_country: str = ""
    ip_region: str = ""
    ip_city: str = ""
    ip_asn: str = ""
    ip_org: str = ""
    ip_timezone: str = ""
    proxy_env: dict = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _sh(cmd: list[str], timeout: int = TIMEOUT) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


_OFFSET_TO_IANA = {
    -12: "Etc/GMT+12", -11: "Pacific/Pago_Pago", -10: "Pacific/Honolulu",
    -9: "America/Anchorage", -8: "America/Los_Angeles", -7: "America/Denver",
    -6: "America/Chicago", -5: "America/New_York", -4: "America/Halifax",
    -3: "America/Sao_Paulo", -2: "Atlantic/South_Georgia",
    -1: "Atlantic/Azores", 0: "UTC", 1: "Europe/Paris",
    2: "Europe/Athens", 3: "Europe/Moscow", 4: "Asia/Dubai",
    5: "Asia/Karachi", 6: "Asia/Dhaka", 7: "Asia/Bangkok",
    8: "Asia/Shanghai", 9: "Asia/Tokyo", 10: "Australia/Sydney",
    11: "Pacific/Noumea", 12: "Pacific/Auckland",
}


def _tz_from_offset() -> str:
    try:
        import time
        off = -time.timezone
        return _OFFSET_TO_IANA.get(off // 3600, "")
    except Exception:
        return ""


def local_tz() -> tuple[str, str]:
    """返回 (时区名, UTC 偏移)。"""
    name = ""
    # 1) 环境变量
    name = os.environ.get("TZ", "")
    # 2) Linux timedatectl
    if not name and platform.system() == "Linux":
        out = _sh(["timedatectl", "show", "--property=Timezone", "--value"])
        name = out
    # 3) /etc/timezone
    if not name and os.path.exists("/etc/timezone"):
        try:
            name = open("/etc/timezone", encoding="utf-8").read().strip()
        except OSError:
            pass
    # 4) macOS
    if not name and platform.system() == "Darwin":
        out = _sh(["readlink", "/etc/localtime"])
        if "zoneinfo/" in out:
            name = out.split("zoneinfo/")[-1]
    # 5) Windows: 用注册表里的时区键名 + 从偏移反查 IANA
    if not name and platform.system() == "Windows":
        out = _sh(["powershell", "-NoProfile", "-Command",
                   "(Get-TimeZone).Id"], timeout=8)
        name = out
    # 6) 兜底：从 UTC 偏移猜一个常见 IANA 名
    if not name:
        name = _tz_from_offset()

    # 偏移
    offset = ""
    try:
        import time
        off = -time.timezone if not time.daylight else -time.altzone
        sign = "+" if off >= 0 else "-"
        off = abs(off)
        offset = f"UTC{sign}{off // 3600:02d}:{(off % 3600) // 60:02d}"
    except Exception:
        pass
    return name, offset


def local_lang() -> tuple[str, list[str]]:
    primary = (os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES")
               or os.environ.get("LANG") or "")
    if not primary and platform.system() == "Windows":
        out = _sh(["powershell", "-NoProfile", "-Command",
                   "(Get-Culture).Name"], timeout=8)
        primary = out
    others = [v for k, v in sorted(os.environ.items())
              if k.startswith("LANG") or k.startswith("LC_")]
    return primary, others


def proxy_env() -> dict:
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy")
    return {k: os.environ[k] for k in keys if os.environ.get(k)}


def lookup_ip(ip: str = "") -> dict:
    """查出口 IP 及其归属（走 ipinfo.io 的免费端点）。"""
    url = f"https://ipinfo.io/{ip}/json" if ip else "https://ipinfo.io/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aiopsec/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return {}


def _region_matches_tz(tz: str, ip_tz: str) -> bool | None:
    if not tz or not ip_tz:
        return None
    # 粗比对：都含同一大区关键词
    groups = [
        ("Asia/Shanghai", ("Asia/Shanghai", "Asia/Chongqing", "Asia/Urumqi")),
        ("America/New_York", ("America/New_York",)),
        ("Europe/London", ("Europe/London",)),
        ("Asia/Tokyo", ("Asia/Tokyo",)),
    ]
    for canon, members in groups:
        if tz in members:
            return ip_tz in members
    return tz.split("/")[0] == ip_tz.split("/")[0]


def _lang_matches_country(lang: str, country: str) -> bool | None:
    if not lang or not country:
        return None
    lang = lang.lower()
    mapping = {
        "CN": ("zh", "zh_cn", "zh-hans"),
        "TW": ("zh_tw", "zh-hant"),
        "HK": ("zh_hk", "zh-hant"),
        "JP": ("ja",),
        "KR": ("ko",),
        "US": ("en_us", "en-us", "c"),
        "GB": ("en_gb", "en-gb"),
        "DE": ("de",),
        "FR": ("fr",),
        "RU": ("ru",),
        "BR": ("pt",),
    }
    expect = mapping.get(country)
    if not expect:
        return None
    return any(e in lang for e in expect)


def collect(check_network: bool = True) -> EnvReport:
    rep = EnvReport()
    rep.hostname = socket.gethostname()
    try:
        rep.username = os.getlogin()
    except OSError:
        rep.username = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    rep.os_name = f"{platform.system()} {platform.release()}"

    rep.tz, rep.tz_offset = local_tz()
    rep.lang, rep.langs = local_lang()
    rep.proxy_env = proxy_env()

    if check_network:
        info = lookup_ip()
        if info:
            rep.public_ip = info.get("ip", "")
            rep.ip_country = info.get("country", "")
            rep.ip_region = info.get("region", "")
            rep.ip_city = info.get("city", "")
            rep.ip_timezone = info.get("timezone", "")
            org = info.get("org", "")
            if " " in org:
                asn, _, name = org.partition(" ")
                rep.ip_asn, rep.ip_org = asn, name
            else:
                rep.ip_org = org
        else:
            rep.notes.append("无法查询出口 IP（离线或网络受限）")

    # ---- 一致性判定 ----
    m = _region_matches_tz(rep.tz, rep.ip_timezone)
    if m is False:
        rep.issues.append(
            f"时区与出口 IP 地理位置矛盾：本地 {rep.tz}，出口 IP 在 {rep.ip_timezone}"
        )
    elif m is None and rep.tz and not rep.ip_timezone and check_network:
        rep.notes.append("出口 IP 未返回时区，无法比对")

    lm = _lang_matches_country(rep.lang, rep.ip_country)
    if lm is False:
        rep.issues.append(
            f"系统语言与出口 IP 国家矛盾：本地 {rep.lang}，出口 IP 在 {rep.ip_country}"
        )

    if not rep.proxy_env and check_network and rep.public_ip:
        rep.notes.append("未检测到代理环境变量，流量可能直连")

    # 主机名/用户名是否含真名线索
    for field_name, val in (("主机名", rep.hostname), ("用户名", rep.username)):
        if val and any(c.isalpha() for c in val) and len(val) <= 20:
            if val.lower() not in ("user", "admin", "root", "steam", "localhost"):
                rep.notes.append(
                    f"{field_name} '{val}' 是稳定标识符，可跨设备关联"
                )

    return rep


def to_dict(rep: EnvReport) -> dict:
    return {
        "hostname": rep.hostname,
        "username": rep.username,
        "os": rep.os_name,
        "timezone": rep.tz,
        "utc_offset": rep.tz_offset,
        "lang": rep.lang,
        "public_ip": rep.public_ip,
        "ip_country": rep.ip_country,
        "ip_region": rep.ip_region,
        "ip_city": rep.ip_city,
        "ip_asn": rep.ip_asn,
        "ip_org": rep.ip_org,
        "ip_timezone": rep.ip_timezone,
        "proxy": rep.proxy_env,
        "issues": rep.issues,
        "notes": rep.notes,
    }
