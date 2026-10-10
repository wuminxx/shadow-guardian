# 网络与元数据泄漏

即使内容加密，**元数据仍会泄漏**。本文档处理出网层。

---

## 1. 你无法隐藏的三件事

```
1) 你连接了 AI 服务商（除非用隧道）
2) 连接的时长、频率、数据量
3) 如果直接连：你的 IP → 你的 ISP → 你的大致位置
```

**能隐藏的**：内容（TLS 之内）、真实出口 IP（用代理/Tor）。
**难隐藏的**：流量模式（即使加密也能看出在跟谁通信，除非用 Tor/混淆）。

---

## 2. 泄漏面清单

```
□ 真实 IP（直连 AI 服务商）
□ DNS 查询（明文 DNS 泄漏你访问的域名）
□ WebRTC（浏览器版 AI，可能泄漏真实 IP）
□ 时区（浏览器报的时区）
□ 语言（Accept-Language）
□ 屏幕分辨率 / 字体（浏览器指纹）
□ 客户端版本（UA / API 客户端版本）
□ 账号关联（同 IP 登多个账号）
□ 支付方式（同卡绑多个账号）
□ 时间模式（你的活跃时段 = 时区）
```

---

## 3. 代理

**必须自建**。免费/公共代理本身就是采集点。

```bash
# SSH 隧道（最简，加密到你的服务器）
ssh -D 1080 -N -C user@your-server
export ALL_PROXY=socks5://127.0.0.1:1080

# 或用 Clash / sing-box / Xray 自建
# 关键：关掉服务端日志
```

**验证代理生效**
```bash
curl -s https://api.ipify.org; echo       # 应显示代理出口 IP
curl -s https://ipinfo.io/json | jq       # 看 IP、ASN、地理位置
```

**泄漏检测**
```bash
# DNS 泄漏（浏览器）
#   访问 dnsleaktest.com / browserleaks.com/dns
# WebRTC 泄漏
#   browserleaks.com/webrtc
# 综合
#   browserleaks.com / whoer.net
```

---

## 4. DNS 泄漏

即使流量走代理，DNS 查询可能走本地解析器 → 泄漏你访问的域名。

```bash
# 确认 DNS 也走隧道
# Clash / sing-box 一般默认接管 DNS；核对配置里的 DNS 段

# 测试
dig +short whoami.akamai.net      # 返回你的解析器 IP，应与代理出口一致
# 或访问 dnsleaktest.com

# 强制走隧道（Linux）
sudo resolvectl dns tun0 1.1.1.1
```

**DoH / DoT 不够** —— 加密了 DNS 内容，但解析器仍知道你查了什么。要么自建解析器，要么让 DNS 走代理。

---

## 5. 时区与语言

比 IP 更隐蔽的指纹。

```bash
# 时区
date +%Z                          # 系统时区
timedatectl                       # Linux
#   浏览器: Intl.DateTimeFormat().resolvedOptions().timeZone

# 语言
echo $LANG $LC_ALL                # 系统语言
#   浏览器: navigator.language / navigator.languages
```

**一致性问题**：声称在某地，但时区/语言不匹配 ⇒ 直接暴露。

```bash
# 临时改（Linux）
sudo timedatectl set-timezone America/New_York
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# 浏览器：用启用了时区伪装的 profile，或容器里设 TZ
docker run -e TZ=America/New_York ...
```

**检查一致性**
```
声称地点:  ____
IP 地理位置: ____        (ipinfo.io)
系统时区:  ____
浏览器时区: ____
系统语言:  ____
浏览器语言: ____
⇒ 全部应指向同一区域
```

---

## 6. 浏览器隔离

```bash
# 独立 profile
chromium --user-data-dir="$HOME/.ai-profile"

# 容器
firejail --private --net=none firefox    # 完全无网
firejail --private firefox               # 隔离文件系统

# Docker
docker run -d --rm \
  -e TZ=America/New_York \
  -v /tmp/ai-profile:/profile \
  --shm-size=2g \
  kasmweb/firefox:1.16.0
```

**必须关**
```
□ 浏览器同步（Chrome Sync 会把 Cookie 同步到所有设备）
□ 地理位置权限
□ 保存密码
□ 第三方 Cookie（减少跨站追踪）
□ 遥测 / 崩溃报告 / "帮助改进"
```

**必须检查**
```
□ WebRTC 是否泄漏真实 IP → about:config 里 media.peerconnection.enabled=false（Firefox）
□ 字体指纹
□ Canvas 指纹（可用 CanvasBlocker / Brave 的 farbling）
```

---

## 7. 流量模式

即使全加密，**流量特征仍可分析**：

```
· 连接的目标（SNI / 目标 IP，除非用 Tor 或 ECH）
· 时长、频率、数据量
· 包大小分布（可指纹客户端）
· 连接时段（作息 → 时区）
```

**对策**
```
□ 用 Tor（最强流量匿名，但慢）
□ 用 CDN 前置（流量混在其他用户里）
□ 用 ECH（Encrypted Client Hello）—— 隐藏 SNI，需服务端支持
□ 不要在固定时刻做敏感操作
□ 用填充/混淆（对高级对手才需要）
```

---

## 8. 客户端遥测

AI 客户端可能**绕过你的代理**向厂商发遥测。

```bash
# 抓包确认有无非预期外联
sudo tcpdump -i any -n 'not host 127.0.0.1' -w ai-traffic.pcap
# 用一会儿客户端，然后分析
tshark -r ai-traffic.pcap -T fields -e ip.dst -e tcp.dstport | sort -u
```

**已知遥测开关**
```jsonc
// Claude Code (~/.claude/settings.json)
{ "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
}}

// VS Code
{ "telemetry.telemetryLevel": "off" }
```

**注意**：有些客户端即使用 SDK 级别开关仍会发。**唯一可靠方法是网络层阻断**（防火墙规则 / 全局限流到已验证的端点）。

```bash
# Linux：只允许必要的出站
sudo iptables -A OUTPUT -d api.anthropic.com -j ACCEPT
sudo iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner $(id -u) -j DROP   # 其余全断
```

---

## 9. 账号与支付

```
□ 独立邮箱（一次性服务，与真身邮箱无关）
□ 独立支付方式（不与真身卡关联）
□ 不用同一手机号注册多个 AI 服务
□ 不用"用 Google 登录"（直接关联真身账号）
□ 不在同一网络下登真身账号和隔离账号
```

**关联判据**（对手会用的）：
```
同 IP / 同 IP 段 / 同 ASN
同支付方式（卡号、钱包地址）
同邮箱域名模式（如都是 gmail 且用户名相似）
同设备指纹
同活跃时段
```

---

## 10. 检查清单

```
□ 出网走自建代理，服务端日志已关
□ 不用任何免费/公共代理
□ DNS 也走隧道，已用 dnsleaktest 验证
□ 真实 IP 已用 ipify 验证不泄漏
□ WebRTC 已禁（浏览器版）
□ 时区 / 语言 / IP 地理位置三者一致
□ 浏览器用独立 profile，关闭同步
□ 客户端遥测已关，且抓包验证过无意外外联
□ 账号与真身零关联（邮箱、支付、手机号）
□ 不在同一网络下混用真身账号与隔离账号
□ 高敏用 Tor 或独立网络出口
□ 活跃时段不暴露真实作息
```
