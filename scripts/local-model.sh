#!/usr/bin/env bash
# local-model.sh —— 起一个只绑本地、不出网的模型实例
#
# 用法:
#   ./local-model.sh ollama qwen2.5:14b         # Ollama（最简）
#   ./local-model.sh llama  ./models/x.gguf     # llama.cpp
#   ./local-model.sh vllm   Qwen/Qwen2.5-14B    # vLLM（需 GPU）
#   ./local-model.sh check                      # 检查当前监听是否只绑本地
#   ./local-model.sh offline <cmd...>           # 用网络命名空间跑任意命令（Linux）
set -u

BACKEND="${1:-}"
shift || true

bind_check() {
  echo "=== 检查 AI 服务监听地址 ==="
  local found=0
  for port in 11434 8080 8000 1234 5000; do
    if command -v ss >/dev/null 2>&1; then
      out=$(ss -tlnp 2>/dev/null | grep ":$port ")
    else
      out=$(netstat -tlnp 2>/dev/null | grep ":$port ")
    fi
    [ -z "$out" ] && continue
    found=1
    echo "端口 $port:"
    echo "$out" | sed 's/^/  /'
    if echo "$out" | grep -qE '0\.0\.0\.0:|\[::\]:|\*:'; then
      echo "  ⚠ 监听所有接口 —— 可能暴露到局域网/公网"
    else
      echo "  ✓ 只绑本地"
    fi
  done
  [ "$found" -eq 0 ] && echo "未发现常见 AI 服务端口在监听"
}

case "$BACKEND" in
  ollama)
    MODEL="${1:-qwen2.5:14b}"
    command -v ollama >/dev/null || { echo "未安装 ollama: https://ollama.com/download" >&2; exit 1; }
    export OLLAMA_HOST=127.0.0.1:11434
    echo "启动 ollama，模型 $MODEL，只绑 127.0.0.1"
    echo "验证: ss -tlnp | grep 11434  （应显示 127.0.0.1:11434）"
    ollama serve &
    OLLAMA_PID=$!
    sleep 2
    ollama run "$MODEL"
    kill "$OLLAMA_PID" 2>/dev/null || true
    ;;

  llama)
    MODEL="${1:-}"
    [ -n "$MODEL" ] || { echo "用法: ./local-model.sh llama <model.gguf>" >&2; exit 1; }
    BIN=""
    for c in ./build/bin/llama-server llama-server /usr/local/bin/llama-server; do
      [ -x "$c" ] && { BIN="$c"; break; }
    done
    [ -n "$BIN" ] || { echo "找不到 llama-server。编译: cmake -B build && cmake --build build -j" >&2; exit 1; }
    echo "启动 llama-server，只绑 127.0.0.1:8080"
    "$BIN" -m "$MODEL" --host 127.0.0.1 --port 8080 -c 8192
    ;;

  vllm)
    MODEL="${1:-Qwen/Qwen2.5-14B-Instruct}"
    python3 -c 'import vllm' 2>/dev/null || { echo "未安装 vLLM: pip install vllm" >&2; exit 1; }
    echo "启动 vLLM，只绑 127.0.0.1:8000，关闭请求日志"
    python3 -m vllm.entrypoints.openai.api_server \
      --model "$MODEL" \
      --host 127.0.0.1 --port 8000 \
      --disable-log-requests
    ;;

  check)
    bind_check
    ;;

  offline)
    # 用网络命名空间跑任意命令，进程完全无网络
    [ "$(uname -s)" = "Linux" ] || { echo "offline 模式仅 Linux（unshare -n）" >&2; exit 1; }
    [ $# -gt 0 ] || { echo "用法: ./local-model.sh offline <cmd...>" >&2; exit 1; }
    echo "在网络命名空间中运行（无任何网络访问）: $*"
    sudo unshare -n -- "$@"
    ;;

  ""|-h|--help)
    sed -n '2,12p' "$0"
    echo
    echo "推荐流程:"
    echo "  1) ./local-model.sh ollama qwen2.5:14b"
    echo "  2) ./local-model.sh check          # 确认只绑本地"
    echo "  3) curl -s https://api.ipify.org   # 断网后应失败"
    ;;

  *)
    echo "未知后端: $BACKEND（可选: ollama | llama | vllm | check | offline）" >&2
    exit 1
    ;;
esac
