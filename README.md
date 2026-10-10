# AI OPSEC & Privacy

**用 AI 时零身份暴露、零隐私泄漏的工具 + 规程。**

一个零依赖的 Python CLI 工具（`aiopsec`）+ 一套可复用的 **Claude Code Skill**。

```bash
pip install -e tool/
aiopsec audit          # 体检：0-100 评分 + 整改清单
aiopsec scan           # 测绘：你的机器上 AI 留了什么
aiopsec check -f x.log # 检查：发送前扫身份泄漏
aiopsec redact < x.log # 脱敏
aiopsec shred --force  # 清理
aiopsec env            # 环境指纹一致性
aiopsec harden --apply # 加固配置
aiopsec hook --install --apply   # 自动拦截含身份字段的输入
```

覆盖三层：AI 客户端落盘取证面、提示词身份字段清洗、网络与提供商留存。

```
L1 会话层   AI 客户端在你机器上写什么、怎么清
L2 提示词层 你送进去的文本会留下什么
L3 网络层   出网时谁看得见、留存多久
```

任一层单独用都不够，三层叠加才够。

---

## 为什么需要这个

AI 客户端把**完整对话明文写到磁盘**。这不是猜测，是默认行为。

典型落盘面（Claude Code 为例）：

```
~/.claude/projects/<cwd-slug>/    每次会话完整 transcript（明文 JSONL）
~/.claude/history.jsonl           你输入过的每一条 prompt
~/.claude/memory/                 memory 文件（跨会话持久）
~/.claude/shell-snapshots/        shell 环境快照 —— 含 env 变量、API key！
~/.claude/todos/                  任务清单
<project>/.claude/settings.json   项目级配置 —— 会被 git 提交
```

而送进 LLM 的文本，按**永久留存 + 可能被调取 + 可能进入训练**对待。

真实案例（2026-10 韩国银行 AI 攻击案）中，攻击方的破点正是这一层：

- 把工作目录开成**公网可读**（`http://38.244.50.120:18899/.claude/CLAUDE.md`）
- 在 Claude Code 会话里让 AI 写「安全研究员简历」，**顺手写进真实姓名、手机、Telegram、年龄、学校、居住地**

技术层伪装做得很好（12 国 IP、9 个代理、多模型栈），死在最基础的 OPSEC。

---

## 快速开始

**方式一：Python 工具（推荐）**

```bash
git clone https://github.com/wuminxx/ai-opsec-privacy.git
cd ai-opsec-privacy
pip install -e tool/

aiopsec audit                        # 1. 全量体检，看评分和整改清单
aiopsec scan                         # 2. 看具体在哪些目录
cat app.log | aiopsec check          # 3. 发送前检查
cat app.log | aiopsec redact         #    脱敏
aiopsec env                          # 4. 环境指纹
aiopsec harden --apply               # 5. 关遥测 + 加固
aiopsec hook --install --apply       # 6. 装自动拦截
aiopsec shred --force                # 7. 清理
```

**方式二：纯 shell（无 Python）**

```bash
./scripts/scan.sh                        # Linux/macOS
.\scripts\scan.ps1                       # Windows
cat app.log | ./scripts/redact.sh        # 脱敏
./scripts/check-prompt.sh --file app.log # 检查
./scripts/install-hooks.sh               # 装 hook
./scripts/shred.sh                       # 清理（先 DRY-RUN）
```

**方式三：只给 AI 用**

```bash
cp -r . ~/.claude/skills/ai-opsec-privacy/
# 之后 /ai-opsec-privacy，或提到 AI 隐私/OPSEC/本地模型/会话清理 时自动触发
```

---

## 目录

```
ai-opsec-privacy/
├── README.md
├── SKILL.md                      Claude Code Skill（给 AI 读的规程）
├── LICENSE                       MIT
│
├── tool/                         ★ 主工具：aiopsec CLI
│   ├── README.md                 工具文档（完整命令参考）
│   ├── pyproject.toml            可 pip install
│   ├── aiopsec/
│   │   ├── __main__.py           CLI 入口
│   │   ├── core/
│   │   │   ├── rules.py          检测规则表（单一数据源）
│   │   │   ├── engine.py         检测 + 脱敏引擎
│   │   │   ├── surface.py        落盘取证面测绘
│   │   │   ├── environment.py    环境指纹一致性
│   │   │   └── output.py         终端输出
│   │   └── commands/             8 个子命令
│   └── tests/                    34 个单元测试（零依赖 unittest）
│
├── hooks/                        独立的 hook 脚本（不想装 pip 包时用）
│   ├── prompt-guard.py           UserPromptSubmit 拦截
│   ├── session-banner.py         SessionStart 提示
│   └── settings.snippet.json
│
├── scripts/                      纯 shell 版（无 Python 环境时用）
│   ├── scan.sh / scan.ps1
│   ├── redact.sh / redact.ps1
│   ├── check-prompt.sh
│   ├── shred.sh / shred.ps1
│   ├── local-model.sh
│   └── install-hooks.sh
│
├── docs/                         规程文档
│   ├── threat-model.md           先定清楚防谁
│   ├── forensics-surface.md      各客户端落盘点逐条
│   ├── prompt-hygiene.md         提示词卫生
│   ├── providers.md              厂商留存政策检查模板
│   ├── local-models.md           Ollama / llama.cpp / vLLM + 断网
│   ├── network.md                网络与元数据泄漏
│   └── checklist.md              上线前自查
│
├── examples/
│   ├── pseudo-identity.txt       假身份模板 + 一致性检查
│   └── gitignore.txt             AI 配置 .gitignore + 清史流程
│
└── .github/workflows/ci.yml      三平台 × 两 Python 版本 + 功能测试
```

**三种用法，按环境选一种：**

| 环境 | 用什么 |
|---|---|
| 有 Python | `tool/` — 功能最全（8 命令、JSON 输出、hook 安装） |
| 只有 shell | `scripts/` — 核心功能，无依赖 |
| 只想让 AI 自己遵守 | `SKILL.md` — 拷到 `~/.claude/skills/ai-opsec-privacy/` |

---

## 三层速览

### L1 会话层

```bash
aiopsec scan                    # 测绘：看看机器上留了什么
aiopsec harden --apply          # 关遥测
aiopsec shred                   # 预演清理
aiopsec shred --force           # 执行
```

```bash
# 会话目录挂 tmpfs（Linux）—— 重启即失
sudo mount -t tmpfs -o size=512m,mode=0700,uid=$(id -u) tmpfs ~/.claude/projects
```

> **警告**：SSD + TRIM + 写时复制文件系统（btrfs/ZFS/APFS）下，原地覆写**不保证**擦除旧块。
> 真正需要时上全盘加密 + 一次性 VM。

### L2 提示词层

```bash
cat app.log | aiopsec check      # 只检查，退出码 1 = 有泄漏
cat app.log | aiopsec redact     # 脱敏
aiopsec check -d ./src           # 递归扫目录
```

检测 40+ 规则：Anthropic/OpenAI/GitHub/AWS/Google/Slack key、PEM 私钥、JWT、连接串、
中国手机号/身份证（带校验位）/车牌、邮箱、银行卡（Luhn）、内网 IP、内部主机名、用户路径。

### L3 网络层

```bash
aiopsec env                      # 时区/语言/出口IP 是否互相矛盾
aiopsec env --ip 1.2.3.4         # 查指定 IP 归属

# 本地模型，只绑 127.0.0.1，不出网
./scripts/local-model.sh ollama qwen2.5:14b
```

```bash
# 验证不泄漏真实 IP
curl -s https://api.ipify.org; echo
```

---

## 三个敏感度档位

| 档位 | 目标 | 做什么 | 成本 |
|---|---|---|---|
| **A 日常** | 防本地取证 | 测绘 + 关遥测 + 脱敏 + 清理脚本 | 低 |
| **B 敏感** | 防提供商 + 防关联 | A + 零留存渠道 + 假身份 + tmpfs + 无日志代理 | 中 |
| **C 高敏** | 防国家级 + 断网 | B + 本地模型 + 断网 + 一次性 VM + 全盘加密 | 高 |

决策树：

```
要处理敏感数据？
├─ 否 → A：测绘 + 关遥测 + 脱敏 + 清理脚本
└─ 是 → 数据必须离开本机？
        ├─ 否 → C：本地模型 + 断网
        └─ 是 → 必须给第三方？
                ├─ 否 → C（自托管在你的云）
                └─ 是 → B：零留存 + 假身份 + 脱敏 + 无日志代理
```

---

## 八个常见误区

| 你以为 | 实际 |
|---|---|
| 我删了会话记录 | SSD/CoW 下覆写不保证擦除旧块 → 真需要时上全盘加密 |
| 我用无痕模式 | 无痕只防本地历史，不防网络观测和服务端留存 |
| 我关了 memory | 服务端仍可能按账号聚合 → 高敏换账号或自托管 |
| 我用了代理 | 免费代理本身就是采集点 → 自建无日志 |
| 我脱敏了姓名 | 措辞习惯/时区/语言组合仍可指纹 → 全维度对齐 locale |
| 小模型本地跑就安全 | 模型文件、日志、缓存仍在磁盘 → 配全盘加密 + 关请求日志 |
| API key 存 env 就行 | env 会进 shell snapshot 和进程列表 → 用密钥库 / tmpfs |
| 换个说法问同样的事就没事 | 语义等价会被聚类 → 事本身不能问时，换说法也不能问 |

---

## 作为 Claude Code Skill 使用

见上方"方式三"。Skill 内容在 `SKILL.md`，与工具解耦 —— 工具升级不影响 Skill，反之亦然。

`aiopsec hook --install --apply` 装的是运行时拦截；Skill 是让 AI 主动遵守规程。两者互补。

---

## 边界

- 本规程只处理**你自己**的隐私与你**有权处置**的数据。
- 涉及**第三方个人信息**时，向境外模型转发在《个人信息保护法》下属对外提供 + 出境行为，
  需单独同意 + 安全评估/认证/标准合同之一 + 事前影响评估。**技术脱敏不免除法律义务。**
- 本仓库不含任何绕过他人授权、伪造他人身份的内容 —— 目标是保护使用者自己。

---

## License

MIT
