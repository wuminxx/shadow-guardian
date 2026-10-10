# 落盘取证面

AI 客户端把**完整对话明文写到磁盘**。这不是猜测，是默认行为。本文档逐客户端给落盘点与关闭方法。

配合脚本：`scripts/scan.sh`（测绘）、`scripts/shred.sh`（清理）。

---

## 1. Claude Code

### 落盘点

```
~/.claude/
├── projects/<cwd-slug>/*.jsonl     每次会话的完整 transcript（明文 JSONL）
│                                   —— 每一轮对话、每一次工具调用、每一个工具结果
├── history.jsonl                   你输入过的每一条 prompt
├── memory/                         memory 文件（跨会话持久，可能含个人偏好/事实）
├── todos/                          任务清单（会话恢复用）
├── shell-snapshots/                shell 环境快照
├── statsig/                        遥测 ID（稳定标识符，可跨设备关联）
├── plugins/                        插件（可能自带缓存）
├── ide/                            IDE 集成状态
├── settings.json                   配置
└── credentials.json                凭据

<project>/.claude/
├── settings.json                   项目级配置 —— 会被 git 提交 ⚠
├── settings.local.json
└── todos/
```

### 高危项

**`shell-snapshots/`** —— 会保存 shell 环境快照，包含：
- 环境变量（`ANTHROPIC_API_KEY`、`AWS_SECRET_ACCESS_KEY` 等）
- `PATH`、`HOME`、`PWD`
- 函数定义、别名

会话里执行过的命令也会进 transcript。所以**贴过的密钥、跑过的 curl、连过的内网地址**都在里面。

**`projects/*.jsonl`** —— 完整 transcript。包括你贴的每一份日志、代码、配置文件。

**`memory/`** —— 跨会话持久。写进去的东西会在未来所有会话里被加载。

### 关闭与最小化

**关遥测**
```jsonc
// ~/.claude/settings.json
{
  "includeCoAuthoredBy": false,
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  }
}
```

**关 memory**
```
会话内: /config  →  关闭 memory
或 settings.json 里对应字段
```

**会话目录挂 tmpfs（Linux）—— 重启即失**
```bash
# 一次性挂载
sudo mount -t tmpfs -o size=512m,mode=0700,uid=$(id -u) tmpfs ~/.claude/projects

# 持久化（/etc/fstab）
tmpfs /home/USER/.claude/projects tmpfs size=512m,mode=0700,uid=1000 0 0
```

**Windows：加密容器**
```
用 VeraCrypt 建一个容器，挂载到 ~/.claude/projects
或：把 USERPROFILE\.claude 整体做成 VHD + BitLocker
```

**项目级：gitignore**
```bash
printf '.claude/\n.cursor/\n.continue/\nAGENTS.md\nCLAUDE.md\n' >> .gitignore

# 已经提交过的要清史
git rm -r --cached .claude .cursor 2>/dev/null
git commit -m "chore: untrack AI agent config"

# 彻底清史
pip install git-filter-repo
git filter-repo --path .claude --path .cursor --invert-paths
```

---

## 2. Codex CLI

```
~/.codex/
├── sessions/         会话记录
├── history.jsonl     输入历史
├── config.toml       配置（可能含 API key）
└── log/              日志
```

```bash
# 清理
rm -rf ~/.codex/sessions/* ~/.codex/log/*
: > ~/.codex/history.jsonl
# config.toml 里不要把 key 明文写进去，用环境变量或密钥库
```

---

## 3. Cursor

```
Windows:  %APPDATA%\Cursor\
macOS:    ~/Library/Application Support/Cursor/
Linux:    ~/.config/Cursor/

├── User/
│   ├── History/          文件编辑历史（可恢复旧版本）
│   ├── globalStorage/    AI 对话存储（LevelDB / SQLite）
│   └── workspaceStorage/ 每工作区的 AI 状态
├── logs/
└── CachedData/
```

Cursor 会把代码库索引、AI 对话、编辑历史都存下来。`workspaceStorage` 里常有完整的代码片段。

```bash
# Linux
rm -rf ~/.config/Cursor/User/History ~/.config/Cursor/logs
# macOS
rm -rf ~/Library/Application\ Support/Cursor/User/History
```

---

## 4. VS Code + Copilot

```
配置:   %APPDATA%\Code\User\settings.json
        ~/.config/Code/User/settings.json
历史:   .../User/History/
对话:   .../User/globalStorage/github.copilot-chat/
遥测:   .../User/globalStorage/storage.json  (telemetry.*)
```

```jsonc
// settings.json
{
  "telemetry.telemetryLevel": "off",
  "github.copilot.chat.telemetry.enabled": false,
  "github.copilot.enable": { "*": true, "plaintext": false, "markdown": false }
  //   最后一项：避免 Copilot 读你的笔记/文档
}
```

**关键**：`"plaintext": false, "markdown": false` —— 否则 Copilot 会把你打开的笔记内容作为上下文。

---

## 5. Continue / Aider / 其他 CLI

```
~/.continue/          sessions/ config.json
~/.aider/             analytics.jsonl  .aider.chat.history.md
                      .aider.tags.cache.v3/  （代码库索引缓存）
```

```bash
# aider 的 chat history 是明文 markdown，在项目目录里
find . -name '.aider*' -o -name '.continue*'
```

---

## 6. 本地模型运行时

```
~/.ollama/
├── models/           模型文件（GB 级）
└── logs/             日志（可能含 prompt）
```

```
~/.cache/huggingface/   下载的模型
~/.lmstudio/            LM Studio 模型 + 日志
~/.cache/llama.cpp/     编译缓存
```

**注意**：vLLM 默认会把 prompt 打到日志。必须加 `--disable-log-requests`。

---

## 7. 浏览器版 AI（claude.ai / chatgpt.com / gemini 等）

落盘位置：
```
Chrome:   ~/.config/google-chrome/Default/
          %LOCALAPPDATA%\Google\Chrome\User Data\Default\
macOS:    ~/Library/Application Support/Google/Chrome/Default/

├── Cookies            （含 AI 站的会话 token）
├── Local Storage/     （leveldb，含 Web 应用状态）
├── IndexedDB/         （可能含会话缓存）
├── Service Worker/    （离线缓存）
├── History            （你的访问记录）
└── Login Data         （保存的密码）
```

**仅清 Cookie 不够** —— LocalStorage 和 IndexedDB 里有会话缓存。

**隔离方案**
```bash
# 独立 profile
chromium --user-data-dir="$HOME/.ai-profile"

# 或容器（Firefox）
firejail --private firefox

# 或独立 VM
```

**必须关掉**：
- 浏览器同步（Chrome Sync 会把 AI 站 Cookie 同步到所有登录设备）
- 地理位置权限
- 保存密码

---

## 8. 通用：进程与内存

即使清理了磁盘，**运行中的进程仍持有数据**：

```bash
# 进程列表会暴露命令行参数（含 key）
ps aux | grep -i 'api.key\|token'
# Linux: /proc/<pid>/environ 可读（同用户）
cat /proc/$(pgrep -f 'ai-client')/environ | tr '\0' '\n'
```

**对策**：
- 密钥不通过命令行参数传（用 env 或 stdin）
- 关掉进程后内存可能被换页到 swap → 加密 swap 或禁用 swap
- `mlock` 锁定敏感页（高级）

---

## 9. 时间线与残留

删了文件不等于没了：

```
1) 文件系统日志（ext4 journal / NTFS $LogFile）—— 记录元数据操作
2) SSD 磨损均衡 —— 旧块可能仍在物理介质
3) 写时复制（btrfs/ZFS/APFS）—— 快照里可能保留旧版本
4) 备份/同步 —— Time Machine、OneDrive、iCloud 可能已上传
5) 编辑器 swap/undo —— vim 的 .swp、VS Code 的 History
6) 剪贴板历史 —— Windows Win+V、macOS 第三方工具
7) 缩略图缓存 —— 看过的图片
8) 应用崩溃转储 —— core dump 可能含完整内存
```

**唯一可靠的方案**：全盘加密（LUKS / BitLocker / VeraCrypt）+ 密钥不落盘（启动时输入）+ 一次性 VM。

---

## 10. 检查清单

```
□ 已跑 scan.sh，知道所有落盘点
□ telemetry / error reporting 已关
□ memory 已关
□ 会话目录 tmpfs / 加密容器
□ shell-snapshots 检查过，无敏感 env
□ 项目 .claude/ .cursor/ 已 gitignore（含清史）
□ 浏览器用独立 profile，关闭同步
□ 剪贴板历史关闭或定期清
□ swap 加密或禁用
□ 备份/同步服务不包含 AI 目录
□ 清理脚本就位并测过
```
