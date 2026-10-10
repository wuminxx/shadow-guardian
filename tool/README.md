# aiopsec

**AI 使用 OPSEC 命令行工具。** 落盘测绘 / 泄露检查 / 脱敏 / 清理 / 环境指纹 / 加固 / hook。

零第三方依赖，纯 Python 标准库。Python 3.8+。

---

## 安装

```bash
# 从仓库直接跑（无需安装）
cd tool
python -m aiopsec --help

# 或安装成命令
pip install -e .
aiopsec --help

# 或 pipx（隔离环境）
pipx install .
```

---

## 命令一览

| 命令 | 作用 |
|---|---|
| `aiopsec audit` | **先跑这个** — 全量体检，出评分与整改清单 |
| `aiopsec scan` | 测绘 AI 客户端在本机的落盘取证面 |
| `aiopsec check` | 扫描文本/文件/目录里的身份泄漏（只检查） |
| `aiopsec redact` | 剥离身份字段 |
| `aiopsec shred` | 清除会话痕迹（默认预演） |
| `aiopsec env` | 检查时区/语言/出口 IP/主机名 是否互相矛盾 |
| `aiopsec harden` | 生成/应用加固配置（关遥测、限制 Copilot） |
| `aiopsec hook` | 装 Claude Code 拦截 hook |

**退出码**：`0` 通过 · `1` 发现问题 · `2` 用法错误。可直接接 CI。

---

## 快速开始

```bash
# 1. 体检
aiopsec audit

# 2. 测绘看看具体在哪些目录
aiopsec scan

# 3. 发送前检查
cat app.log | aiopsec check          # 退出码 1 = 有泄漏
cat app.log | aiopsec redact > clean.log

# 4. 环境指纹
aiopsec env

# 5. 加固
aiopsec harden --apply

# 6. 装 hook（自动拦截含身份字段的输入）
aiopsec hook --install --apply

# 7. 清理
aiopsec shred              # 预演
aiopsec shred --force      # 执行
```

---

## 各命令详解

### `aiopsec audit` — 体检

```bash
aiopsec audit                   # 联网查出口 IP
aiopsec audit --offline         # 只查本地
aiopsec audit --deep            # 额外扫描已知风险路径的实际内容（慢）
aiopsec audit --json            # 机器可读
```

输出 0-100 评分 + 等级（A/B/C/D/F）+ 逐项扣分 + 整改命令。

评分构成：

```
-30  敏感落盘点未隔离/清理（每处 -6，上限 30）
-20  环境指纹矛盾（每处 -10，上限 20）
-25  明文凭据（--deep，每处 -8，上限 25）
-10  无代理，流量可能直连
 -8  Claude Code 遥测未关
 -8  Copilot 会读纯文本/文档
 -6  VS Code 遥测未关
 -5  项目未忽略 .claude/
```

### `aiopsec scan` — 落盘测绘

覆盖 30+ 已知路径：Claude Code / Codex / Cursor / Continue / Aider / VS Code+Copilot / Ollama / HuggingFace / LM Studio / Chrome / Edge / OpenCode / Windsurf。

```bash
aiopsec scan --sensitive-only        # 只看高危
aiopsec scan --app claude-code       # 只看某客户端（--app 可重复）
aiopsec scan --max-files 50000       # 单目录文件上限（默认 200000）
aiopsec scan --json
```

**性能**：`os.scandir` + 线程池并发 + 每目标 20s 时间上限 + 纯缓存目录跳过。
本机实测 120s+ → 3.8s（含浏览器 profile 1.35GB）。
插件目录（`~/.claude/plugins`，548MB 下载缓存）只查顶层元数据，不递归。

### `aiopsec check` — 泄露检查

```bash
aiopsec check -f app.log             # 单文件（- 表示 stdin）
aiopsec check -t "帮我看看 13800138000"   # 直接给文本
aiopsec check -d ./src               # 递归扫目录
aiopsec check -f x.log --min-severity HIGH
aiopsec check -d ./src --max-files 10000
aiopsec check -f x.log --show-raw    # 打印原始命中值（危险）
aiopsec check -f x.log --json
aiopsec check -f x.log --quiet       # 只输出结论，适合 CI
```

**检测类别**（`--kind`）：

| kind | 覆盖 |
|---|---|
| `secret` | Anthropic/OpenAI/GitHub/AWS/Google/Slack/GitLab/HF/Stripe key、JWT、PEM 私钥、Bearer、连接串、泛化的 `password=` |
| `pii` | 中国手机号/身份证（带校验位）/座机/车牌、邮箱、银行卡（Luhn 校验）、Telegram 用户名、IPv6 |
| `infra` | 私有 IPv4、IP:端口、内部主机名、云元数据端点 |
| `path` | Windows/Unix 用户路径、macOS 私密路径 |

**降误报**：身份证走校验位，银行卡走 Luhn，RFC2606 保留域放行，占位符放行。

### `aiopsec redact` — 脱敏

```bash
cat app.log | aiopsec redact                 # stdout
aiopsec redact -t "我的电话 13800138000"       # 直接给文本
aiopsec redact -f app.log -o clean.log       # 写文件
aiopsec redact -f app.log --in-place         # 就地改（自动生成 .bak）
aiopsec redact -f app.log --dry-run          # 只报会替换多少处
aiopsec redact -f app.log --kind secret --kind pii   # 只处理指定类别
```

替换顺序按 `secret > pii > infra > path`，避免高优先级被后处理误伤。**幂等**：已脱敏的文本再跑不会变。

### `aiopsec shred` — 清理

```bash
aiopsec shred                    # 预演（默认）
aiopsec shred --force            # 执行
aiopsec shred --force --passes 7 # 覆写 7 遍
aiopsec shred --force --no-overwrite      # 只删不覆写（快）
aiopsec shred --force --include-config    # 连配置和凭据一起清（危险）
aiopsec shred --app claude-code  # 只清某客户端
```

- 只清**会话/历史/memory/snapshot**，配置与凭据默认保留
- `history.jsonl` 这类文件是**清空内容**而非删除（某些客户端要求文件存在）
- 覆写用 `os.urandom` 逐块写 + `fsync`

**⚠ 局限**：SSD + TRIM + CoW 文件系统（btrfs/ZFS/APFS）下覆写**不保证**擦除旧块。彻底方案是全盘加密 + 一次性 VM。

### `aiopsec env` — 环境指纹

```bash
aiopsec env
aiopsec env --offline        # 不联网
aiopsec env --ip 1.2.3.4     # 查指定 IP 归属
```

检查三组一致性：

```
1. 本地时区      vs  出口 IP 时区
2. 系统语言      vs  出口 IP 国家
3. 主机名/用户名 是否是可跨设备关联的稳定标识符
```

矛盾即报。例：

```
✗ 时区与出口 IP 地理位置矛盾：本地 Asia/Shanghai，出口 IP 在 America/New_York
✗ 系统语言与出口 IP 国家矛盾：本地 zh_CN，出口 IP 在 US
· 主机名 'zhangwei-laptop' 是稳定标识符，可跨设备关联
```

### `aiopsec harden` — 加固

```bash
aiopsec harden                          # 预演
aiopsec harden --apply                  # 写入
aiopsec harden --target claude          # 只改 Claude Code
aiopsec harden --apply --target gitignore --gitignore-dir ~/proj
```

写入项：

```jsonc
// ~/.claude/settings.json
{ "includeCoAuthoredBy": false,
  "env": { "DISABLE_TELEMETRY": "1",
           "DISABLE_ERROR_REPORTING": "1",
           "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1" } }

// VS Code settings.json
{ "telemetry.telemetryLevel": "off",
  "github.copilot.chat.telemetry.enabled": false,
  "github.copilot.enable": { "*": true, "plaintext": false,
                              "markdown": false, "scminput": false } }
```

浅合并，保留现有配置，改动前自动备份为 `settings.json.bak.<时间戳>`。

### `aiopsec hook` — Claude Code 拦截

```bash
aiopsec hook                      # 查看状态
aiopsec hook --status             # 同上
aiopsec hook --install            # 预演
aiopsec hook --install --apply    # 安装
aiopsec hook --uninstall --apply  # 卸载
```

安装时会在 `~/.claude/aiopsec/` 生成 `hook-guard.py` / `hook-banner.py`
launcher 脚本，内嵌包路径 —— **不依赖 `pip install -e`**，clone 后直接可用。

装两个 hook：

- **UserPromptSubmit** — 提交 prompt 时扫描，命中则阻断（exit 2）

  ```
  [aiopsec] 提示词身份泄漏检查未通过（阈值 HIGH）
    [HIGH] 中国大陆手机号: 138******00  (1:6)
    [HIGH] Anthropic API key: sk-************AA  (1:20)
  ```

- **SessionStart** — 会话开始时提示敏感落盘点

**阈值可调**：

```bash
export AIOP_SEC_BLOCK=HIGH   # 默认，只有 HIGH 阻断
export AIOP_SEC_BLOCK=MED    # 更严
export AIOP_SEC_BLOCK=LOW    # 最严
export AIOP_SEC_BLOCK=NONE   # 只提示不阻断
```

---

## CI 集成

```yaml
# .github/workflows/opsec.yml
name: opsec
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install -e tool/
      # 仓库里不许有凭据
      - run: aiopsec check -d . --min-severity HIGH --quiet
```

退出码非零即失败。

---

## 局限（必读）

```
· 正则规则是启发式，不覆盖姓名/学校/公司/职级/措辞习惯
· 不覆盖语义关联（"我上周去的那家店" 这种）
· 脱敏不改变法律性质 —— 第三方向境外模型转发仍触《个保法》
· shred 在 SSD/CoW 上不彻底
· env 依赖 ipinfo.io，离线时跳过网络部分
· 不检测剪贴板历史、备份服务、浏览器 LocalStorage 内容
```

**通过检查 ≠ 安全。** 工具降低机械性失误，不替代判断。

---

## 测试

```bash
cd tool
python -m unittest discover -s tests -v     # 34 个用例
```

---

## 许可

MIT
