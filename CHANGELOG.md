# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.0.0] — 2026-10-10

首版。工具 + Skill + 文档三层交付。

### Added

**工具（`tool/`，零依赖 Python 包）**

- `aiopsec audit` — 全量体检，0-100 评分 + 逐项扣分 + 整改命令
- `aiopsec scan` — 落盘取证面测绘，30+ 已知路径
- `aiopsec check` — 身份泄漏扫描（文本 / 文件 / 目录）
- `aiopsec redact` — 脱敏（幂等，支持 `--in-place` / `--dry-run`）
- `aiopsec shred` — 会话痕迹清理（默认 DRY-RUN，urandom 覆写 + fsync）
- `aiopsec env` — 时区 / 语言 / 出口 IP / 主机名 一致性检查
- `aiopsec harden` — 加固配置（关遥测、限制 Copilot，浅合并 + 自动备份）
- `aiopsec hook` — 安装 Claude Code UserPromptSubmit 拦截 + SessionStart 提示
- 规则表 40+ 条，覆盖 secret / pii / infra / path 四类
- 校验器：中国身份证校验位、银行卡 Luhn（降误报）
- 全部子命令支持 `--json`
- 退出码约定：`0` 通过 / `1` 发现问题 / `2` 用法错误

**Skill（`SKILL.md`）**

- 三层规程：会话层 / 提示词层 / 网络层
- 威胁模型四问 + 八归因源
- 分档位方案（A 日常 / B 敏感 / C 高敏）
- 上线前自查清单 + 决策树 + 八误区

**纯 shell 版（`scripts/`）**

- `scan.sh` / `scan.ps1`、`redact.sh` / `redact.ps1`
- `check-prompt.sh`、`shred.sh` / `shred.ps1`
- `local-model.sh`（Ollama / llama.cpp / vLLM / 离线模式）
- `install-hooks.sh`

**文档（`docs/`）**

- `threat-model.md`、`forensics-surface.md`、`prompt-hygiene.md`
- `providers.md`、`local-models.md`、`network.md`、`checklist.md`

**CI**

- GitHub Actions：3 平台（ubuntu / windows / macos）× 2 Python（3.8 / 3.12）
- 单元测试 + 子命令冒烟 + 功能测试

### Fixed

开发过程中实测并修掉的 10 个缺陷：

1. **Windows 中文输出** — stdout 默认 GBK，`--json` 输出到管道时
   UnicodeEncodeError，下游无法解析。改为强制 UTF-8。
2. **未知子命令 exit 0** — argparse 的 SystemExit 未接住。
3. **文件不存在抛 traceback** — 未捕获 `FileNotFoundError`，改为 exit 2。
4. **`--include-config` 无效** — `settings.json` 不在默认目标里，
   该选项从未生效。新增 `CONFIG_TARGETS`。
5. **`history.jsonl` 在 `--include-config` 下被误删** — 应清空而非删除。
6. **hook 依赖 pip 安装** — 未 `pip install -e` 时重启客户端会静默失效。
   改为生成内嵌路径的 launcher 脚本。
7. **launcher 路径双反斜杠** — `repr()` 与 raw string 叠加。
8. **scan 超时** — `os.walk` + `lstat` 逐文件建对象，1.35GB 浏览器 profile
   场景超 120s。改 `os.scandir` + 线程池 + 时间上限 + 浅扫，降到 3.8s。
9. **浏览器存储被误跳** — 优化时把 `Local Storage` / `IndexedDB` 也放进
   跳过列表，而浏览器版 AI 的会话正存在那里。改为只跳纯缓存目录。
10. **规则误报** — 邮箱白名单放行 `@example.corp.com`；`sk-ant-` 同时命中
    OpenAI 规则；内部主机名 lookbehind 挡住多级子域；云元数据端点被
    白名单吞掉。全部修正。

### Security

- `shred` 明确文档化局限：SSD + TRIM + CoW 文件系统下原地覆写
  **不保证**擦除旧块，彻底方案是全盘加密 + 一次性 VM。
- 文档明确法律边界：向境外模型转发第三方个人信息在《个人信息保护法》下
  属对外提供 + 出境，技术脱敏不免除法律义务。
- 工具不含任何绕过他人授权、伪造他人身份的功能。

### Known Limitations

- 正则规则是启发式，不覆盖姓名 / 学校 / 公司 / 职级 / 措辞习惯 / 语义关联
- 不检测剪贴板历史、备份服务、浏览器 LocalStorage 内容
- `env` 联网部分依赖 `ipinfo.io`，离线时跳过
- 无 Python 环境时 shell 版功能较少

[Unreleased]: https://github.com/wuminxx/ai-opsec-privacy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/wuminxx/ai-opsec-privacy/releases/tag/v1.0.0
