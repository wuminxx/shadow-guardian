---
name: ai-opsec-privacy
description: "用 AI 时零身份暴露、零隐私泄漏的操作规程。覆盖 AI 客户端落盘取证面(会话历史/memory/telemetry)、提示词身份字段清洗、AI 提供商日志与训练留存、本地/自托管模型部署、网络与元数据泄漏、跨会话关联、团队与合规留痕。用于：不想让 AI 会话泄漏真实身份、不想被 AI 厂商留存或训练、想用本地模型彻底断网、需要一套能过审计的 AI 使用规范、评估 Claude/ChatGPT/Cursor/Copilot 等客户端会把什么写到磁盘。Triggers: AI 隐私, OPSEC, 不泄漏身份, 本地模型, 离线 AI, ollama, llama.cpp, vLLM, 会话历史清理, prompt 脱敏, AI 客户端取证, telemetry 关闭, 训练退出。也可直接当 AI 使用安全基线文档用。"
---

# AI 使用 OPSEC 与隐私保护规程

目的：让「用 AI」这件事在任何场景下都不产生可归因到真身的痕迹，也不把敏感数据交给第三方。

按三层给方案。任一层单独用都不够，三层叠加才是「任一场景都不被发现」。

- **L1 会话层**：AI 客户端在你机器上写什么、怎么清洗
- **L2 提示词层**：你送进去的文本会留下什么
- **L3 网络与提供商层**：出网时谁看得见、能留存多久

---

## 工具优先（有 `aiopsec` 就直接用，别手搓）

本仓库带一个 CLI，覆盖本文档的绝大多数机械性操作。**能跑工具就别背命令**。

```bash
pip install -e <repo>/tool/     # 或 cd tool && python -m aiopsec

aiopsec audit                   # 先跑这个：全量体检 + 0-100 评分 + 整改清单
aiopsec scan                    # 测绘落盘取证面（30+ 路径，含浅扫优化）
aiopsec check -f <file>         # 检查泄漏（退出码 0 通过 / 1 有问题 / 2 用法错）
aiopsec check -d <dir>          # 递归扫目录
aiopsec redact < in > out       # 脱敏（幂等）
aiopsec shred --force           # 清理会话痕迹
aiopsec env                     # 时区/语言/出口IP 一致性
aiopsec harden --apply          # 关遥测 + 限制 Copilot
aiopsec hook --install --apply  # 装运行时拦截
```

| 本文档章节 | 对应命令 |
|---|---|
| 1. L1 会话层 | `aiopsec scan` / `shred` / `harden` |
| 2. L2 提示词层 | `aiopsec check` / `redact` |
| 3. L3 网络层 | `aiopsec env` |
| 6. 上线前自查 | `aiopsec audit` |

无 Python 环境时，用仓库 `scripts/` 下的纯 shell 版本（`scan.sh` / `redact.sh` /
`check-prompt.sh` / `shred.sh`）。功能少一些，核心覆盖。

**工具覆盖不到的（仍需人工判断）**：姓名/学校/公司/职级/措辞习惯、语义关联、
法律义务、磁盘物理擦除。工具降低机械失误，不替代判断。

---

## 0. 威胁模型（先定清楚，否则做多或做少）

先回答这四问，再决定做到哪一层：

| 问题 | 决定什么 |
|---|---|
| **防谁？** 本地取证 / 网络中间人 / AI 厂商 / 未来法律调取 / 数据泄漏连带 | 决定要不要断网、要不要全盘加密 |
| **保什么？** 真实身份 / 商业秘密 / 第三方个人信息 / 只是不想被训练 | 决定脱敏力度 |
| **时间窗？** 长期潜伏 / 一次性任务 | 决定要不要一次性 VM |
| **对手能力？** 脚本小子 / 商业取证 / 国家级 | 决定要不要硬件隔离 |

**默认假设（没有更好信息时按这个走）**：
- 假设会话记录**永久留存**且**可能被调取**
- 假设网络链路**全程可观测**
- 假设 AI 厂商**默认留存**，除非明确关闭
- 假设你的措辞习惯、时区、语言组合**本身可指纹**

---

## 1. L1 会话层：AI 客户端落盘取证面

### 1.1 先测绘：AI 客户端会在哪落盘

各家客户端把对话、memory、索引写到固定路径。**先跑一遍，知道你的机器上有什么**。

**Windows**
```powershell
$targets = @(
  "$env:USERPROFILE\.claude",            # Claude Code: projects/ history.jsonl memory/
  "$env:USERPROFILE\.codex",             # Codex CLI
  "$env:USERPROFILE\.cursor",            # Cursor
  "$env:USERPROFILE\.continue",          # Continue
  "$env:USERPROFILE\.ollama",            # Ollama 模型 + 日志
  "$env:APPDATA\Code",                   # VS Code (Copilot 会话/settings)
  "$env:APPDATA\Claude",
  "$env:APPDATA\Cursor",
  "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",   # 浏览器版 AI 的 Web 存储
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
)
foreach ($t in $targets) {
  if (Test-Path $t) {
    $sz = (Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue |
           Measure-Object Length -Sum).Sum
    "{0,12:N0} B  {1}" -f $sz, $t
  }
}
```

**Linux / macOS**
```bash
for t in ~/.claude ~/.codex ~/.cursor ~/.continue ~/.ollama ~/.config/gh \
         ~/.config/Code ~/.config/Cursor \
         ~/Library/Application\ Support/Claude \
         ~/Library/Application\ Support/Cursor; do
  [ -e "$t" ] && printf '%12s  %s\n' "$(du -sh "$t" 2>/dev/null | cut -f1)" "$t"
done
```

**判据**：找到 `projects/`、`history.jsonl`、`*.jsonl`、`memory/`、`sessions/` 这些字样 ⇒ 明文会话存在。

### 1.2 Claude Code 具体落盘点（最常被忽略）

```
~/.claude/projects/<cwd-slug>/         每次会话的完整 transcript（明文 JSONL）
~/.claude/history.jsonl                你输入过的每条 prompt
~/.claude/memory/                      memory 文件（跨会话持久）
~/.claude/todos/                       任务清单
~/.claude/shell-snapshots/             shell 环境快照（可能含 env 变量！）
~/.claude/statsig/                     遥测 ID
~/.claude/plugins/                     插件（可能带自己的缓存）
<project>/.claude/                     项目级配置（会被 git 提交！见下）
```

**高危**：`shell-snapshots/` 和会话里执行过的命令会把 **环境变量、API key、路径**一起写进去。

### 1.3 关闭 / 最小化落盘

```jsonc
// ~/.claude/settings.json
{
  "includeCoAuthoredBy": false,
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1"
  }
}
```

```bash
# 会话目录挂 tmpfs（Linux）—— 重启即失
sudo mount -t tmpfs -o size=512m,mode=0700,uid=$(id -u) tmpfs ~/.claude/projects
# /etc/fstab 持久化：
# tmpfs /home/USER/.claude/projects tmpfs size=512m,mode=0700,uid=1000 0 0

# Windows：用 VeraCrypt 容器装会话目录，或 VHD + 每次登录重建
```

### 1.4 用完即焚（脚本）

**Linux / macOS**
```bash
#!/usr/bin/env bash
# ai-shred.sh —— 清 AI 客户端会话痕迹
set -u
shred_targets=(
  "$HOME/.claude/projects"
  "$HOME/.claude/history.jsonl"
  "$HOME/.claude/todos"
  "$HOME/.claude/shell-snapshots"
  "$HOME/.codex/sessions"
  "$HOME/.cursor/logs"
)
for t in "${shred_targets[@]}"; do
  [ -e "$t" ] || continue
  if [ -d "$t" ]; then
    find "$t" -type f -exec shred -u -n 3 {} + 2>/dev/null
    rmdir "$t" 2>/dev/null || true
  else
    shred -u -n 3 "$t" 2>/dev/null
  fi
  echo "shredded: $t"
done
# 不要碰 ~/.claude/settings.json 和 credentials，那是配置不是会话
```

**Windows（PowerShell，加密擦除单文件）**
```powershell
function Remove-Secure {
  param([string]$Path, [int]$Passes = 3)
  if (-not (Test-Path $Path)) { return }
  $fi = New-Object System.IO.FileInfo $Path
  $len = $fi.Length
  if ($len -gt 0) {
    $fs = [System.IO.File]::Open($Path, 'Open', 'ReadWrite')
    $buf = New-Object byte[] 1048576
    (New-Object Random).NextBytes($buf)
    for ($p = 0; $p -lt $Passes; $p++) {
      $fs.Position = 0
      for ($o = 0; $o -lt $len; $o += $buf.Length) {
        $fs.Write($buf, 0, [Math]::Min($buf.Length, $len - $o))
      }
      $fs.Flush($true)
    }
    $fs.Close()
  }
  Remove-Item $Path -Force
}
Get-ChildItem "$env:USERPROFILE\.claude\projects" -Recurse -File |
  ForEach-Object { Remove-Secure $_.FullName }
```

> **注意**：SSD + TRIM + 写时复制文件系统（btrfs/ZFS/APFS）下，原地覆写**不保证**擦除旧块。真正需要时上全盘加密 + 一次性 VM。

### 1.5 项目级 `.claude/` 会被 git 提交

```
.project/
  .claude/settings.json      ← 会进 git！可能含 hook 脚本、路径、token
  .claude/settings.local.json
```

```bash
# 每个仓库都加
printf '.claude/\n.cursor/\n.continue/\nAGENTS.md\n' >> .gitignore
# 已经提交过的要清史
git rm -r --cached .claude .cursor 2>/dev/null
git commit -m "chore: untrack AI agent config"
# 彻底清史用 git-filter-repo
```

### 1.6 浏览器版 AI（claude.ai / chatgpt.com 等）

```
1) 用独立浏览器 profile，不与日常浏览混用
   chromium --user-data-dir="$HOME/.ai-profile"
2) 更好：用容器/独立 VM 开，不用主 profile
3) 退出时清：Cookie + LocalStorage + IndexedDB + Service Worker
   注意：仅清 Cookie 不够，Web 存储里有会话缓存
4) 关闭「记住我」，每次登录
5) 不用浏览器同步（Chrome Sync 会把 AI 站 Cookie 同步到所有设备）
```

---

## 2. L2 提示词层：送进去的文本会留下什么

### 2.1 核心原则

> 任何送进 LLM 的文本，**当作会永久留存 + 可能被调取 + 可能进入训练**。

### 2.2 提示词脱敏检查表

发送前逐条过：

```
□ 真实姓名 / 昵称 / 拼音 / 首字母缩写
□ 年龄 / 生日 / 身份证号 / 护照号
□ 手机号 / 邮箱 / 微信 / QQ / Telegram / 其他 IM 账号
□ 家庭住址 / 公司地址 / 精确到市/区/街道的来源地
□ 学校 / 公司 / 部门 / 职级 / 工号
□ 车牌 / 设备序列号 / MAC / IMEI / 主机名
□ 银行/支付账号 / 钱包地址
□ 客户/同事/第三方的个人信息 ← 法律风险最大的一类
□ 内部项目代号 / 未公开产品名 / 服务器名 / 内网 IP
□ 唯一措辞习惯 / 口头禅 / 特殊错别字模式
```

### 2.3 假身份模板（需要人设时预造，不现场编）

```
预先生成一套与真身零关联的假身份，写死在模板文件里复用：

  PSEUDO_NAME       （与真名无任何字符/语义关联）
  PSEUDO_AGE
  PSEUDO_LOCATION   （用大区域，不精确到街道）
  PSEUDO_CONTACT    （一次性邮箱，见 3.4）
  PSEUDO_BIO

铁律：
  · 不在对话里即兴编 —— 即兴编的容易掺真信息
  · 每次用同一套（或按项目分套），别随机化到自相矛盾
  · 假身份的"教育/工作背景"也要预造，别留空白让模型追问
```

### 2.4 需要贴代码/日志时的脱敏

```bash
# 通用脱敏函数（粘进 AI 前先跑）
redact() {
  sed -E \
    -e 's#(/home/|/Users/|C:\\Users\\)[^/\\]+#\1USER#g' \
    -e 's/\b(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b/10.0.0.0/g' \
    -e 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/EMAIL@REDACTED/g' \
    -e 's/\b1[3-9][0-9]{9}\b/PHONE_REDACTED/g' \
    -e 's/(sk-|ghp_|gho_|AKIA|AIza|xox[baprs]-)[A-Za-z0-9_\-]{8,}/TOKEN_REDACTED/g' \
    -e 's/\b[a-z0-9-]+\.(internal|local|corp|lan)\b/HOST.internal/g'
}
# 用法：cat app.log | redact | pbcopy      （macOS）
#       cat app.log | redact | xclip -sel c （Linux）
```

### 2.5 绝不要在会话里做的事

```
× 问销赃/交易渠道（动机直接坐实，且会被记录）
× 把真实凭据贴进去"帮我看看"
× 描述只有你知道的、与真身强绑定的事件细节
× 用真名"扮演自己"做角色扮演
× 让 AI 生成含真实身份的简历/CV/档案
× 在同一会话里先聊私事再聊敏感任务（上下文关联）
```

---

## 3. L3 网络与提供商层

### 3.1 提供商留存政策（认准这三档）

| 档位 | 做法 | 适用 |
|---|---|---|
| **零留存** | 选明确承诺 zero-retention 的 API 渠道；企业版通常默认不训练 | 一般商业敏感 |
| **自托管** | 模型跑在自己机器/自己云上，数据不出网 | 高敏 / 需断网 |
| **断网** | 本地模型 + 物理断网（air-gap） | 最高敏 |

**必做**：去服务商隐私页确认三件事并写下来存档：
```
1) 数据留存多久？（有些默认 30 天，有些永久）
2) 是否用于训练？（默认开还是关，怎么关）
3) 是否人工审核？（有些标记后会人工看）
```

### 3.2 本地 / 自托管模型（彻底不出网）

**Ollama（最简）**
```bash
export OLLAMA_HOST=127.0.0.1:11434     # 只监听本地
ss -tlnp | grep 11434                  # Linux 确认没监听公网
netstat -ano | findstr 11434           # Windows
ollama run qwen2.5:14b
```

**llama.cpp（可控性最好）**
```bash
cmake -B build -DGGML_CUDA=ON && cmake --build build -j
./build/bin/llama-server -m model.gguf --host 127.0.0.1 --port 8080 -c 8192
# 网络命名空间隔离（Linux）
sudo unshare -n ./build/bin/llama-server -m model.gguf --host 127.0.0.1 --port 8080
```

**vLLM（有 GPU、要并发）**
```bash
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-14B-Instruct \
  --host 127.0.0.1 --port 8000 \
  --disable-log-requests          # 关键：默认会把 prompt 打到日志
```

**物理断网（air-gap）**
```bash
sudo ip link set eth0 down
sudo ip link set wlan0 down
# 或全程 unshare -n
sudo unshare -n -- bash -c './run-ai.sh'
```

### 3.3 必须联网时的网络卫生

```
□ 出网走代理，代理不记录（自建，日志关）
□ 不用免费公共代理（本身可能就是采集点）
□ DNS 也走同一隧道（防 DNS 泄漏）
□ 验证不泄漏真实 IP：curl -s https://api.ipify.org
□ 检查 WebRTC 泄漏（浏览器版 AI）
□ 关浏览器地理位置；语言+时区一致性=指纹，需与目标 locale 对齐
□ 一次性网络标识：新 MAC、新 hostname、新时区
```

### 3.4 账号与支付

```
□ AI 账号与真身零关联：独立邮箱（一次性服务）+ 独立支付方式
□ 不用同一手机号注册多个 AI 服务
□ 不用浏览器同步 / 不用"用 Google 登录"
□ API key 单独签发，不与其他服务共用
□ 每个项目一套 key（便于隔离与吊销）
```

### 3.5 AI API key 当生产凭据管

```
□ 不落客户端（不进 APK / 仓库 / 容器镜像 / 前端代码）
□ 统一网关代理出站调用
□ 最小权限签发
□ 用量 + 速率上限 + 告警（异常用量 = 入侵指标）
□ 轮换 + 吊销流程
□ 访问日志与生产系统同级留存审计
```

---

## 4. 跨会话关联防御

AI 服务商和取证方会做**跨会话关联**。切断它：

```
□ 关 memory / 持久记忆
□ 关"个性化" / "从历史学习"
□ 每次敏感任务开新会话，不复用上下文
□ 不用同一账号先聊身份相关再聊任务
□ 不同项目用不同账号（彻底隔离）
□ 注意：即使关了 memory，服务端仍可能按账号聚合 ← 高敏须换账号或自托管
```

---

## 5. 分层方案速查（按敏感度选）

### 档位 A — 日常（防本地取证 + 基本脱敏）
```
· 跑 1.1 测绘，知道落盘位置
· 关 telemetry + memory
· 提示词过 2.2 检查表
· 每次任务后跑 1.4 清理脚本
· 项目 .claude/ 加 .gitignore
```
成本低，防脚本级取证和意外泄漏。

### 档位 B — 敏感（防提供商 + 防关联）
```
A 全部 +
· 走零留存 API 渠道，或独立账号
· 假身份模板
· 代码/日志过 redact() 流水线
· 会话目录 tmpfs / VeraCrypt 容器
· 出网走自建无日志代理
· 跨会话不用同一账号
```

### 档位 C — 高敏（防国家级 + 需断网）
```
B 全部 +
· 本地模型（Ollama/llama.cpp/vLLM，绑 127.0.0.1 + 关请求日志）
· 物理断网或 unshare -n
· 一次性 VM，任务后销毁
· 全盘加密（LUKS / BitLocker / VeraCrypt）
· 与日常机零网络零文件往来
· 硬件隔离（独立机器）
```

---

## 6. 上线前自查清单

```
【会话层】
□ 已跑落盘测绘，知道所有 AI 痕迹位置
□ telemetry / error reporting 已关
□ memory 已关
□ 会话目录 tmpfs 或加密容器
□ 清理脚本已就位并测过
□ 项目 .claude/ .cursor/ 已 gitignore
□ shell-snapshots 无敏感 env（检查过）
□ 浏览器用独立 profile，关闭同步

【提示词层】
□ 脱敏检查表逐条过
□ 假身份模板已预造
□ 贴代码/日志前跑过 redact()
□ 没在会话里问销赃/贴凭据/生成真实身份文档
□ 没有先聊私事后聊敏感任务

【网络/提供商层】
□ 提供商留存政策已确认并存档
□ 出网代理自建、无日志
□ DNS 走同一隧道，无泄漏
□ 真实 IP 已用 ipify 类服务验证不泄漏
□ AI 账号与真身零关联
□ API key 按生产凭据管理

【跨会话】
□ 不同项目不同账号
□ 敏感任务开新会话
□ 未开个性化/历史学习

【兜底层】（高敏必做）
□ 全盘加密
□ 一次性 VM
□ 本地模型或断网
```

---

## 7. 一页决策树

```
要处理敏感数据？
├─ 否 → 档位 A：测绘 + 关遥测 + 脱敏 + 清理脚本
└─ 是 → 数据必须离开本机？
        ├─ 否 → 档位 C：本地模型 + 断网
        └─ 是 → 必须给第三方？
                ├─ 否 → 档位 C（自托管在你自己的云）
                └─ 是 → 档位 B：零留存渠道 + 假身份 + 脱敏 + 无日志代理
                        敏感度再高 → 叠加 C 的兜底（全盘加密 + 一次性 VM）
```

---

## 8. 常见误区（以为安全其实不安全）

```
✗ "我删了会话记录" —— SSD/CoW 文件系统下覆写不保证擦除旧块
   → 真需要时上全盘加密

✗ "我用无痕模式" —— 无痕只防本地历史，不防网络观测和服务端留存

✗ "我关了 memory" —— 服务端仍可能按账号聚合
   → 高敏换账号或自托管

✗ "我用了代理" —— 免费代理本身就是采集点
   → 自建无日志

✗ "我脱敏了姓名" —— 措辞习惯/时区/语言组合仍可指纹
   → 全维度对齐目标 locale

✗ "我用小模型本地跑就安全" —— 模型文件、日志、缓存仍在磁盘
   → 配合全盘加密 + 关请求日志

✗ "API key 存在 env 里就行" —— env 会进 shell snapshot 和进程列表
   → 用密钥库 / tmpfs

✗ "换个说法问同样的事就没事" —— 语义等价会被聚类
   → 如果事本身不能问，换说法也不能问
```

---

## 9. 快速命令卡

**有工具时（首选）**

```bash
aiopsec audit                    # 体检，看评分和整改清单
aiopsec scan                     # 测绘
cat f | aiopsec check            # 检查，退出码 1 = 有泄漏
cat f | aiopsec redact > clean   # 脱敏
aiopsec env                      # 环境指纹
aiopsec harden --apply           # 加固
aiopsec hook --install --apply   # 拦截
aiopsec shred --force            # 清理
```

**无工具时（纯 shell 兜底）**

```bash
# 测绘（Linux/macOS）
ls -la ~/.claude ~/.codex ~/.cursor ~/.ollama 2>/dev/null
du -sh ~/.claude/* 2>/dev/null | sort -h

# 立即清理 Claude Code 痕迹
rm -rf ~/.claude/projects/* ~/.claude/todos/* ~/.claude/shell-snapshots/*
shred -u -n 3 ~/.claude/history.jsonl 2>/dev/null || : > ~/.claude/history.jsonl

# 或改用仓库脚本
./scripts/scan.sh
cat f | ./scripts/redact.sh
./scripts/check-prompt.sh --file f
./scripts/shred.sh --force
```

**本地模型（不出网）**

```bash
# Ollama
OLLAMA_HOST=127.0.0.1:11434 ollama run qwen2.5:14b

# 仓库脚本（一步起好并验证只绑本地）
./scripts/local-model.sh ollama qwen2.5:14b
./scripts/local-model.sh check

# 网络命名空间隔离（Linux，进程完全无网）
sudo unshare -n -- bash -c 'OLLAMA_HOST=127.0.0.1:11434 ollama run qwen2.5:14b'
```

**验证不泄漏真实 IP**

```bash
curl -s https://api.ipify.org; echo
aiopsec env --offline     # 或只查本地，不触网
```

```powershell
# 测绘（Windows，无工具时）
Get-ChildItem "$env:USERPROFILE\.claude","$env:USERPROFILE\.codex",
  "$env:USERPROFILE\.cursor","$env:APPDATA\Claude" -ErrorAction SilentlyContinue |
  Select-Object FullName
# 清理
Get-ChildItem "$env:USERPROFILE\.claude\projects" -Recurse -File |
  Remove-Item -Force
Clear-Content "$env:USERPROFILE\.claude\history.jsonl"
# 或
.\scripts\scan.ps1
.\scripts\shred.ps1 -Force
```

---

## 10. 边界

- 本规程只处理**你自己**的隐私与自己有权处置的数据。
- 涉及**第三方个人信息**时，向境外模型转发在《个人信息保护法》下属对外提供 + 出境行为，需单独同意 + 安全评估/认证/标准合同之一 + 事前影响评估。技术脱敏不免除法律义务。
- 本规程不含任何绕过他人授权、伪造他人身份的内容 —— 目标是保护使用者自己。
