#!/usr/bin/env bash
# 在 server2 上研判一条告警(慢通道)。
# 用法: bash scripts/run_investigation.sh <alert_uid>
# 前提: .env 已填(NEO4J_* → server1 图;LLM_API_BASE → 本地 qwen :8000)。
# 首跑自动建 venv + 装依赖(neo4j/openai)。
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env —— 先 cp .env.example .env 并填端点"; exit 1; }

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "== 首跑:建 venv + 装依赖(neo4j/openai)=="
  python3 -m venv .venv
  ./.venv/bin/pip install -q -e .
fi

if [ $# -lt 1 ]; then
  echo "用法: bash scripts/run_investigation.sh <alert_uid>"
  echo "(先跑 python scripts/preflight.py 看有哪些可研判的 alert_uid)"
  exit 1
fi

echo "== 研判 alert_uid=$1 =="
PYTHONUTF8=1 "$PY" -m soc_agent.cli "$1"
