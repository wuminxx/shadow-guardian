# 上线前自查清单

打印出来逐条打勾。**没打完不要开始敏感任务。**

---

## 阶段 0：威胁模型（先做这个）

```
□ 防谁？            _______________
□ 保什么？          _______________
□ 时间窗？          _______________
□ 对手能力？        _______________
□ 选定档位：        A / B / C
□ 我知道自己接受的风险是：_______________
```

---

## 阶段 1：会话层

```
【测绘】
□ 跑过 scan.sh / scan.ps1，知道所有 AI 落盘点
□ 检查过 shell-snapshots 里有没有敏感 env
□ 知道 history.jsonl 里存着我发过的每条 prompt

【关闭】
□ telemetry / error reporting 已关
□ memory 已关
□ 个性化 / 从历史学习 已关
□ 浏览器同步已关

【隔离】
□ 会话目录挂 tmpfs（或 VeraCrypt 容器）
□ 项目 .claude/ .cursor/ 已 gitignore
□ 已提交过的 AI 配置已清史（git filter-repo）
□ 浏览器用独立 profile
□ 剪贴板历史关闭或定期清
□ swap 加密或禁用
□ 备份/同步服务（OneDrive/iCloud/Time Machine）不包含 AI 目录

【清理】
□ shred 脚本就位并测过（先 DRY-RUN）
□ 知道 SSD/CoW 下覆写不保证彻底 ⇒ 高敏上全盘加密
```

---

## 阶段 2：提示词层

```
【检查】
□ 脱敏检查表逐条过
□ 假身份模板已预造（姓名/年龄/地点/职业/教育/时区）
□ 假身份的时区与声称地点一致
□ 贴代码/日志前跑过 redact.sh
□ 报错信息已去掉绝对路径、主机名、内网 IP

【禁忌】
□ 没在会话里问销赃 / 交易渠道
□ 没贴真实凭据
□ 没让 AI 生成含真实身份的简历/CV/档案
□ 没描述只有我知道的事件细节
□ 没先聊私事再聊敏感任务

【上下文】
□ 敏感任务开了新会话
□ 不同项目用不同账号
□ 知道关了 memory 服务端仍可能按账号聚合 ⇒ 高敏换账号

【语言】
□ 敏感任务提示词用英文
□ 没 code-switch
□ 语言/单位/日期格式与声称身份一致
```

---

## 阶段 3：网络与提供商层

```
【提供商】
□ 核对过留存时长（附日期）
□ 核对过是否用于训练（附日期）
□ 核对过是否人工审核
□ 关闭所有"改进服务/训练"开关
□ 企业场景已签 DPA
□ 没用任何来路不明的 API 中转

【网络】
□ 出网走自建代理，服务端无日志
□ 不用免费/公共代理
□ DNS 也走隧道，dnsleaktest 验证过
□ 真实 IP 用 ipify 验证不泄漏
□ WebRTC 已禁（浏览器版）
□ 时区/语言/IP 地理三者一致
□ 抓包验证过客户端无意外外联

【账号】
□ AI 账号与真身零关联（邮箱、支付、手机号）
□ 不用"用 Google 登录"
□ 每个项目独立 API key
□ 不在同一网络混用真身账号与隔离账号
```

---

## 阶段 4：兜底层（高敏必做）

```
□ 全盘加密（LUKS / BitLocker / VeraCrypt）
□ 模型文件/日志/缓存也在加密卷里
□ 本地模型只绑 127.0.0.1（已用 ss 验证）
□ 请求日志已关（vLLM 需 --disable-log-requests）
□ 不需要联网时用 unshare -n 或物理断网
□ 一次性 VM，任务后销毁
□ VM 无共享目录、无剪贴板共享
□ 与日常机零网络零文件往来
□ 硬件隔离（独立机器）
```

---

## 阶段 5：事后

```
□ 任务结束跑了 shred.sh --force
□ 检查过没有残留（history.jsonl 已清空）
□ 检查过浏览器 profile 已清（Cookie + LocalStorage + IndexedDB）
□ 撤销/轮换本次用过的 API key
□ 删掉一次性 VM / 卸载加密卷
□ 记录本次的异常（下次改进）
```

---

## 常见疏漏（重点检查）

```
□ shell-snapshots —— 最容易漏，含 env 变量
□ 项目 .claude/ 已提交到 git —— 忘了清史
□ 剪贴板历史 —— 复制过敏感内容
□ 备份服务 —— OneDrive/iCloud 已同步
□ 浏览器 LocalStorage —— 只清了 Cookie
□ 客户端遥测 —— 改了 base_url 仍外联
□ swap —— 内存换页到磁盘
□ 崩溃转储 —— core dump 含完整内存
□ shell history（bash/zsh）—— 命令行参数里的 key
□ 编辑器 swap / undo 历史 —— vim .swp
```

---

## 一行快速版

```bash
# 开始前
./scripts/scan.sh && ./scripts/check-prompt.sh --file <待发内容>

# 结束后
./scripts/shred.sh --force
```
