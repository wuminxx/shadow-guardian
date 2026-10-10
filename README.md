# Shadow Guardian

**用 AI 时零身份暴露、零隐私泄漏。**

一个零依赖的 CLI 工具（`aiopsec`）+ 一份 OPSEC 基线 + 可选的 Claude Code Skill。

```bash
pip install -e tool/

aiopsec audit          # 体检：0-100 评分 + 整改清单
aiopsec scan           # 查：你的机器上 AI 客户端留了什么
aiopsec shred --force  # 清：会话痕迹
aiopsec harden --apply # 加固：关遥测
aiopsec hook --install --apply   # 自动拦截
```

---

## 这个项目解决什么

**一个事实**：AI 客户端把每一轮对话、每次工具调用、每个工具结果，
**明文写进固定路径**。不是加密、不是临时文件。

```
~/.claude/projects/<cwd-slug>/*.jsonl    完整 transcript
~/.claude/history.jsonl                  输入过的每条 prompt
~/.claude/shell-snapshots/               shell 快照（含环境变量！）
<project>/.claude/settings.json           项目配置 —— 会被 git 提交
```

其余是围绕这一件事的检测、清理、加固。

**它不能解决的**：真实姓名/学校/公司/措辞习惯、语义关联、磁盘物理擦除、法律判断。
**通过检查 ≠ 安全。**

---

## 核心洞察：8 个可关联源

对手不需要破解什么，只需要**对比**。断掉一个源不够——
要断的是"这些源能否指向同一人"。

```
1 基础设施  IP / ASN / 托管商 / 端口 / 证书
2 时间      时区 / 活跃时段 / 作息
3 语言      用词 / 拼写 / 措辞习惯 / code-switch
4 内容      提示词里的身份字段 / 项目代号
5 账号      邮箱 / 支付 / 昵称 / 跨服务复用
6 客户端    落盘文件 / telemetry ID / 版本
7 行为      并发模式 / 节奏 / 工具偏好
8 关联      跨会话 / 跨账号 / 跨项目同一性
```

2026 年公开的真实案例里，攻击者的技术层伪装都做得很好
（12 国 IP、9 个代理、多模型栈），栽的都是上面某一源：
工作目录开成公网读、提示词里写真实身份、账号跨案复用。

**技术层 AI 能补，人的 OPSEC 补不了。**

---

## 工具

零依赖，Python 3.8+，纯标准库。

| 命令 | 作用 |
|---|---|
| `aiopsec audit` | 全量体检 → 0-100 评分 + 逐项扣分 + 整改命令 |
| `aiopsec scan` | 测绘 30+ 已知落盘路径，标记敏感项 |
| `aiopsec check` | 扫描凭据/邮箱/内网 IP（文本/文件/目录） |
| `aiopsec redact` | 脱敏（幂等，支持 `--in-place` / `--dry-run`） |
| `aiopsec shred` | 清理（默认 DRY-RUN，urandom 覆写 + fsync） |
| `aiopsec env` | 时区/语言/出口 IP/主机名 一致性 |
| `aiopsec harden` | 关遥测 + 限制 Copilot（浅合并 + 自动备份） |
| `aiopsec hook` | 装 Claude Code 拦截 hook |

退出码：`0` 通过 · `1` 发现问题 · `2` 用法错误。可直接接 CI。

### 检测范围（23 条规则，刻意收窄）

**会抓**（真的会贴在给 AI 的文本里）：

```
secret  17 条  API key（Anthropic/OpenAI/GitHub/AWS/Google/Slack/
                     GitLab/HF/Stripe）、私钥、Bearer、JWT、连接串
pii      1 条  邮箱（公司邮箱直接暴露雇主）
infra    3 条  私有 IPv4、IP:端口、内部主机名
path     2 条  Windows/Unix 用户路径
```

**刻意不抓**：

```
中国手机号 / 身份证 / 银行卡 / 车牌 / 座机 / Telegram 用户名
```

原因：这些几乎不会以明文形态出现在给 AI 的文本里，
但订单号、日志、测试数据都很像 → **误报淹没真信号**。
真要发这类信息，手工改。

（早期版本有 33 条规则，实测误报率高，已砍掉 10 条。见 CHANGELOG。）

---

## 文档

`docs/opsec-baseline.md` — 一篇，11 节。

包含：落盘面完整清单、提示词卫生、环境指纹、本地模型部署、
清理的真实局限、三个敏感度档位、8 个可关联源、8 个误区、法律边界。

---

## 作为 Claude Code Skill

```bash
cp -r . ~/.claude/skills/shadow-guardian/
```

之后 `/shadow-guardian`，或提到 AI 隐私 / OPSEC / 会话记录 / 清理时触发。

**Skill 与工具解耦** —— 工具升级不影响 Skill，反之亦然。

### 运行时拦截（可选）

```bash
aiopsec hook --install --apply
```

装两个 hook：
- **UserPromptSubmit** — 提交时扫凭据，命中则阻断
- **SessionStart** — 提示敏感落盘点

阈值可调：`AIOP_SEC_BLOCK=HIGH|MED|LOW|NONE`

安装时生成 `~/.claude/aiopsec/hook-*.py` launcher，
内嵌包路径 —— **不依赖 `pip install -e`**。

---

## 三档用法

```bash
# 只想要工具
git clone https://github.com/wuminxx/shadow-guardian
cd shadow-guardian && pip install -e tool/
aiopsec audit

# 无 Python 环境
./scripts/scan.sh
cat f | ./scripts/redact.sh
./scripts/check-prompt.sh --file f
./scripts/shred.sh --force

# 只想让 AI 遵守
cp -r . ~/.claude/skills/shadow-guardian/
```

---

## 真实局限

写在这里是因为不写就是骗人。

```
正则不覆盖   姓名/学校/公司/职级/措辞习惯/语义关联
清理不彻底   SSD+TRIM+CoW 下覆写不保证擦除旧块
不检测       剪贴板历史、备份服务、浏览器 LocalStorage 内容
本地模型     模型文件、日志、缓存仍在磁盘
env          联网部分依赖 ipinfo.io，离线时跳过
离线部署     本地部署 + 本地模型 ⇒ 厂商封号无效
```

**唯一彻底的方案**：全盘加密 + 一次性 VM。

---

## 法律边界

技术脱敏**不免除**法律义务。

向境外模型转发**第三方个人信息**，在《个人信息保护法》下是
「向第三方提供」+「出境」：

```
第 23 条    单独同意 + 告知接收方名称/联系方式/目的/种类
第 38~39 条 出境须安全评估 / 认证 / 标准合同之一 + 另行单独同意
第 55 条    事前个人信息保护影响评估
第 57 条    发生泄露须通知个人并报告
```

脱敏后再发给境外模型，**法律上仍是同一件事**。
自托管解决"出不出网"，不解决"该不该处理"。

---

## License

MIT