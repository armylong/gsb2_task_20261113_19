#!/usr/bin/env bash
# 本地启动 HAR 脱敏工具(仅监听 127.0.0.1,不对外暴露)。
# 用法:./run.sh [端口号,默认 8000]
set -euo pipefail

cd "$(dirname "$0")"
PORT="${1:-8000}"

if [ ! -d ".venv" ]; then
  echo "未发现 .venv,正在创建虚拟环境并安装依赖..."
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

echo "启动中... 浏览器打开 http://127.0.0.1:${PORT}/ (Ctrl+C 停止)"
exec .venv/bin/python -I -m uvicorn app.main:app --host 127.0.0.1 --port "${PORT}"
