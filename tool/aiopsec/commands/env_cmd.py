"""aiopsec env —— 环境指纹一致性检查。"""

from __future__ import annotations

import json

from ..core import environment, output as O


def add_parser(sub):
    p = sub.add_parser("env", help="检查时区/语言/出口IP/主机名 是否互相矛盾")
    p.add_argument("--offline", action="store_true", help="不联网，只查本地")
    p.add_argument("--json", action="store_true")
    p.add_argument("--ip", help="查指定 IP 的归属（而非本机出口）")
    p.set_defaults(func=run)
    return p


def run(args) -> int:
    if args.ip:
        info = environment.lookup_ip(args.ip)
        if args.json:
            print(json.dumps(info, ensure_ascii=False, indent=2))
        else:
            print(O.header(f"IP 归属: {args.ip}"))
            for k, v in info.items():
                print(O.kv(k, str(v)))
        return 0

    rep = environment.collect(check_network=not args.offline)

    if args.json:
        print(json.dumps(environment.to_dict(rep), ensure_ascii=False, indent=2))
        return 1 if rep.issues else 0

    print(O.header("环境指纹"))
    print(O.kv("主机名", rep.hostname))
    print(O.kv("用户名", rep.username))
    print(O.kv("系统", rep.os_name))
    print(O.kv("时区", f"{rep.tz or '?'}  ({rep.tz_offset})"))
    print(O.kv("语言", rep.lang or "?"))

    if not args.offline:
        print(O.header("网络"))
        print(O.kv("出口 IP", rep.public_ip or "?"))
        print(O.kv("IP 位置", " ".join(filter(None, [
            rep.ip_city, rep.ip_region, rep.ip_country])) or "?"))
        print(O.kv("IP 时区", rep.ip_timezone or "?"))
        print(O.kv("ASN/组织", f"{rep.ip_asn} {rep.ip_org}".strip() or "?"))
        if rep.proxy_env:
            print(O.kv("代理变量", ", ".join(rep.proxy_env.keys())))
        else:
            print(O.kv("代理变量", O.yellow("未设置")))

    if rep.issues:
        print(O.header("发现矛盾"))
        for i in rep.issues:
            print(f"  {O.red('✗')} {i}")
    else:
        print()
        print(O.ok("未发现一致性矛盾"))

    if rep.notes:
        print(O.header("提示"))
        for n in rep.notes:
            print(f"  {O.blue('·')} {n}")

    return 1 if rep.issues else 0
