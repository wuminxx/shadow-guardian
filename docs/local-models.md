# 本地 / 自托管模型

数据不出本机的唯一可靠方案。配套脚本：`scripts/local-model.sh`

---

## 1. 为什么需要

```
第三方服务:  数据离开本机 → 依赖政策、依赖对手不查、依赖链路安全
自托管:      数据不出本机 → 你控制一切，但要自己负责加固
```

**关键点**：自托管不等于安全。默认配置常把服务绑到 `0.0.0.0`，且默认记日志。

---

## 2. 三方案对比

| | Ollama | llama.cpp | vLLM |
|---|---|---|---|
| 上手 | 最容易 | 中 | 中 |
| 依赖 | 无 | 需编译 | 需 GPU + Python |
| 并发 | 一般 | 一般 | 强 |
| 日志控制 | 少 | 少 | 需显式关 |
| 适合 | 日常单机 | 精细控制 | 生产/高并发 |

---

## 3. Ollama

```bash
# 安装: https://ollama.com/download

export OLLAMA_HOST=127.0.0.1:11434     # 只绑本地（关键）
ollama serve &
ollama run qwen2.5:14b
```

**验证只绑本地**
```bash
ss -tlnp | grep 11434        # Linux —— 应显示 127.0.0.1:11434
netstat -ano | findstr 11434 # Windows
```
出现 `0.0.0.0:11434` 或 `[::]:11434` ⇒ **暴露到局域网**，任何人同网段都能用。

**模型与日志位置**
```
~/.ollama/models/    模型文件（GB 级，需在加密卷里）
~/.ollama/logs/      日志（可能含 prompt）
```

---

## 4. llama.cpp（可控性最好）

```bash
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp
cmake -B build -DGGML_CUDA=ON      # 有 GPU；纯 CPU 去掉此项
cmake --build build -j

# 起服务，只绑本地
./build/bin/llama-server \
  -m ~/models/qwen2.5-14b-instruct-q4_k_m.gguf \
  --host 127.0.0.1 --port 8080 \
  -c 8192
```

**断网跑（网络命名空间）**
```bash
sudo unshare -n ./build/bin/llama-server -m model.gguf --host 127.0.0.1 --port 8080
# 该进程完全无网络，连本机其他服务也访问不到
```

---

## 5. vLLM（需 GPU）

```bash
pip install vllm

python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-14B-Instruct \
  --host 127.0.0.1 --port 8000 \
  --disable-log-requests          # ← 关键！默认会把 prompt 打到日志
```

**其它隐私相关参数**
```
--disable-log-requests     不记录请求体
--disable-log-stats        不记录统计
--max-log-len 0            限制日志长度
```

**模型缓存位置**（需在加密卷里）
```bash
export HF_HOME=/encrypted/hf          # HuggingFace 缓存
export VLLM_CACHE_ROOT=/encrypted/vllm
```

---

## 6. 网络隔离层级

从弱到强：

```bash
# 级别 1：只绑本地（必要但不充分）
--host 127.0.0.1

# 级别 2：防火墙阻断入站
sudo ufw deny 11434
# 或 Windows 防火墙规则

# 级别 3：网络命名空间（Linux，进程完全无网）
sudo unshare -n -- bash -c './run-ai.sh'

# 级别 4：物理断网（air-gap）
sudo ip link set eth0 down
sudo ip link set wlan0 down
#   或拔网线 / 关 WiFi

# 级别 5：独立机器，从不联网
```

**验证断网**
```bash
curl -s --max-time 3 https://api.ipify.org && echo "⚠ 仍有网" || echo "✓ 已断网"
```

---

## 7. 磁盘加密

模型、日志、缓存都在磁盘上。不加密，物理接触就能取。

**Linux（LUKS）**
```bash
# 新盘加密
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX aivault
sudo mkfs.ext4 /dev/mapper/aivault
sudo mount /dev/mapper/aivault /mnt/aivault
# 把 HF_HOME / OLLAMA_MODELS 指到这里
export OLLAMA_MODELS=/mnt/aivault/ollama
export HF_HOME=/mnt/aivault/hf
```

**Windows（BitLocker）**
```powershell
Enable-BitLocker -MountPoint "E:" -EncryptionMethod XtsAes256 `
  -UsedSpaceOnly -TpmProtector
```

**跨平台（VeraCrypt）**
```
建容器 → 挂载 → 把模型/日志/会话目录都放里面 → 用完卸载
```

---

## 8. 一次性 VM

最强隔离。任务后销毁，什么都不留。

```bash
# QEMU / libvirt：起一个 VM，跑完删盘
# 或 VirtualBox / VMware：
#   用 immutable disk（只读基础盘 + 临时增量盘）
#   VBoxManage modifyvm "ai-vm" --snapshotfolder /tmp --disk immutabledifferencing

# 关键：VM 内不挂载宿主机共享目录，网络用 NAT 或直接禁用
```

**要点**
```
□ VM 磁盘用临时增量盘（关闭即丢）
□ 不挂共享文件夹
□ 不挂剪贴板共享
□ 网络 NAT 或禁用
□ 宿主机的 AI 目录不暴露给 VM
```

---

## 9. API 兼容层

本地模型大多提供 OpenAI 兼容接口，可直接接现有客户端：

```bash
# Ollama
export OPENAI_BASE_URL=http://127.0.0.1:11434/v1
export OPENAI_API_KEY=ollama          # 占位，不真正校验

# vLLM
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY=EMPTY

# llama.cpp server
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
```

接到 Claude Code / Cursor / Continue 等客户端时，**确认客户端不会再向厂商端点发遥测**（有些客户端即使改 base_url 仍会外联）。

**验证**
```bash
# 跑起来后抓包确认无外联
sudo tcpdump -i any -n 'not host 127.0.0.1' &
# 用一会儿，看有没有非本地流量
```

---

## 10. 检查清单

```
□ 服务只绑 127.0.0.1（已用 ss/netstat 验证）
□ 防火墙阻断对外端口
□ 请求日志已关（vLLM 需显式 --disable-log-requests）
□ 模型/日志/缓存目录在加密卷里
□ 不需要联网时用 unshare -n 或物理断网
□ 用 tcpdump 验证过无外联
□ 高敏用一次性 VM，任务后销毁
□ VM 无共享目录、无剪贴板共享
□ 客户端改 base_url 后不再向厂商发遥测（抓包确认）
□ swap 加密或禁用（防内存换页泄漏）
□ 模型文件本身也在加密卷
```
