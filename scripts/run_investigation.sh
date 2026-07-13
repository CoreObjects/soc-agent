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

AUID="$1"
mkdir -p feedback
FB="feedback/inv-${AUID:0:12}.out"

# 研判 + tee 到 feedback(输出仅含 GOAD 公开靶场名,真实端点/口令只在 .env 不会打印)
{
  echo "=== investigate $AUID  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" -m soc_agent.cli "$@"
  echo "=== done $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
} 2>&1 | tee "$FB" || true      # 研判即使崩了也继续:保证 traceback 也被 ferry 回来

# 回推 feedback(ferry:我 pull 就能读)
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"   # 无身份则本地兜底,否则 commit 静默失败
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: investigate ${AUID:0:12} $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
if git push origin HEAD >/dev/null 2>&1 \
   || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD >/dev/null 2>&1; }; then
  echo "✅ 已推 $FB,Claude 可 pull"
else
  echo "!! push 失败,可手动: git push origin HEAD"
fi
