---
name: shadow-guardian
description: "用 AI 时的 OPSEC 基线。三件机器事：AI 客户端把完整对话写盘（怎么查怎么清）、提交 prompt 前扫凭据、关遥测。含 aiopsec CLI 命令。Triggers: AI 隐私, AI 泄漏, OPSEC, 会话记录, 落盘, prompt 脱敏, 凭据泄漏, 关遥测, 本地模型, 离线 AI, 清理会话, .claude 目录, gitignore AI 配置。"
---

# AI 使用 OPSEC 基线

核心事实：**AI 客户端把每一轮对话、每次工具调用，明文写进固定路径。**
不是加密、不是临时文件。其余都是围绕这一件事。

完整版见 `docs/opsec-baseline.md`。

---

## 1. 查 + 清 + 加固

```bash
aiopsec scan                        # 看你机器上实际有什么
aiopsec harden --apply              # 关遥测 + 阻止 Copilot 读笔记/文档
aiopsec hook --install --apply      # 提交 prompt 时自动拦凭据
aiopsec shred                       # 预演
aiopsec shred --force               # 执行（urandom 覆写 + fsync）
```

`shred` 默认只清会话/历史/memory/snapshot，配置与凭据保留。
`--include-config` 才连配置一起清。

### 三个最容易漏

```
① ~/.claude/shell-snapshots/  存 shell 快照，含环境变量
   export 过的 API key 都在里面

② <project>/.claude/settings.json  会被 git commit 带走
   printf '.claude/\n.cursor/\n.codex/\nAGENTS.md\n' >> .gitignore
   已提交的：git rm -r --cached .claude + git filter-repo 清史

③ 改 base_url 不等于不外联  客户端可能仍向厂商发遥测
   抓包验证，不是看配置文件
```

### 清理做不到的

SSD/CoW 下覆写不保证擦除旧块；备份服务可能已同步；
剪贴板历史、shell history、崩溃转储、编辑器 swap 都不覆盖。
**唯一彻底方案：全盘加密 + 一次性 VM。**

---

## 2. 提交 prompt 前

**原则**：送进 LLM 的文本，按「永久留存 + 可能被调取 + 可能进训练」对待。

```bash
cat f | aiopsec check      # 只检查，exit 1 = 有问题
cat f | aiopsec redact     # 脱敏
aiopsec check -d ./src     # 递归扫目录
```

### 工具抓什么（23 条规则）

```
secret  API key（Anthropic/OpenAI/GitHub/AWS/Google/Slack/GitLab/HF/Stripe）
        私钥、Bearer、JWT、数据库连接串
pii     邮箱（公司邮箱直接暴露雇主）
infra   私有 IPv4、IP:端口、内部主机名
path    Windows/Unix 用户路径
```

### 工具不抓什么（误报率高，别指望它）

```
中国手机号 / 身份证 / 银行卡 / 车牌 / 座机 / Telegram 用户名
```

原因：这些几乎不会以明文形态出现在给 AI 的文本里，
但订单号、日志、测试数据都很像 → **误报淹没真信号**。
真要发，手工改。

（早期版本 33 条规则，砍掉 10 条。见 CHANGELOG。）

### 绝对不要在会话里做

```
问销赃 / 交易渠道              动机坐实 + 永久留存
贴真实凭据"帮我看看"          换成同结构的脱敏样本
让 AI 生成含真实身份的简历     真实案例里这就是破点
同一账号先聊身份再聊任务       上下文 + 账号双重关联
```

### 上下文污染

```
同一会话先聊私事再聊敏感任务 → 前者进后者上下文
memory 开着 → A 写的进 B 的上下文
服务端关了 memory 仍可能按账号聚合
```

敏感任务**开新会话**。不同项目**用不同账号**。

---

## 3. 环境一致性

对手不需要破解，只需要**对比**。

```
本地时区      vs  出口 IP 时区
系统语言      vs  出口 IP 国家
主机名/用户名  vs  是否可跨设备关联
```

```bash
aiopsec env                # 查这三项
aiopsec env --offline      # 不联网
```

这只是提醒。问题是"你为什么要让它们不一致"——大多数时候答案是"不需要"，那就统一。

---

## 4. 本地模型：什么时候真的需要

**默认不需要。** 零留存渠道 + 独立账号大多数场景够用。

**必须自托管**：数据涉及第三方个人信息（法律义务）/ 客户数据 / 生产凭据 /
需要"绝对不出本机"的保证 / 对手是国家级 / 你无法核实服务商政策是否被执行。

```bash
# Ollama（最简）
OLLAMA_HOST=127.0.0.1:11434 ollama run qwen2.5:14b
ss -tlnp | grep 11434        # 确认只绑本地

# vLLM（⚠️ 必须关请求日志，默认会把 prompt 打到日志）
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-14B --host 127.0.0.1 --disable-log-requests

# 断网（Linux，进程完全无网）
sudo unshare -n -- <cmd>
```

**硬边界**：本地部署 + 本地模型 ⇒ **厂商封号无效**。
真实案例：国家级监控平台完全本地部署，事后研究者写
"账号层面的执法措施不影响已部署的产品"。
⇒ 治理必须在能力固化前介入。

---

## 5. 判断框架：8 个可关联源

断一个不够，要断的是"这些源能否指向同一人"。

```
1 基础设施  IP/ASN/托管商/端口/证书    5 账号  邮箱/支付/昵称/跨服务复用
2 时间      时区/活跃时段/作息          6 客户端 落盘/telemetry ID/版本
3 语言      用词/拼写/措辞/code-switch  7 行为  并发模式/节奏/工具偏好
4 内容      身份字段/项目代号           8 关联  跨会话/跨账号/跨项目
```

2026 年公开案例里，攻击者技术层伪装都很好（12 国 IP、9 个代理、多模型栈），
栽的都是上面某一源：工作目录开成公网读、提示词写真实身份、账号跨案复用。

**技术层 AI 能补，人的 OPSEC 补不了。**

---

## 6. 八个误区

| 以为 | 实际 |
|---|---|
| 删了会话记录就没事 | SSD/CoW 下覆写不保证；备份可能已同步 |
| 无痕模式够用 | 只防本地历史，不防网络观测和服务端留存 |
| 关了 memory 就干净 | 服务端仍可能按账号聚合 |
| 用了代理就安全 | 免费代理本身就是采集点 |
| 脱敏了姓名就行 | 措辞/时区/语言组合仍可指纹 |
| 本地小模型就安全 | 模型文件、日志、缓存仍在磁盘 |
| key 放 env 里就行 | env 会进 shell snapshot 和进程列表 |
| 换个说法问同一件事没事 | 语义等价会被聚类 |

---

## 7. 法律边界

技术脱敏**不免除**法律义务。向境外模型转发**第三方个人信息**，
在《个人信息保护法》下是「向第三方提供」+「出境」：

```
第 23 条    单独同意 + 告知接收方名称/联系方式/目的/种类
第 38~39 条 出境须安全评估/认证/标准合同之一 + 另行单独同意
第 55 条    事前个人信息保护影响评估
第 57 条    泄露须通知个人并报告
```

脱敏后再发给境外模型，**法律上仍是同一件事**。
自托管解决"出不出网"，不解决"该不该处理"。

---

## 命令速查

```bash
aiopsec audit | scan | check | redact | shred | env | harden | hook
```

退出码：`0` 通过 · `1` 有问题 · `2` 用法错。

无 Python：`scripts/` 下有纯 shell 版。
Claude Code Skill：`cp -r . ~/.claude/skills/shadow-guardian/`

---

## 工具覆盖不到的

```
真实姓名/昵称/学校/公司/职级
语义关联（"我上周去的那家店"）
剪贴板历史/备份服务/浏览器 LocalStorage
磁盘物理擦除
法律判断
```

**工具降低机械失误，不替代判断。通过 `check` ≠ 安全。**