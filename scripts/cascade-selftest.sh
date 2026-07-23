#!/usr/bin/env bash
# server2 浅层 cascade selftest:每类抽样 → 只跑浅层(不写台账)→ 打印决策 + 量 deferral,ferry 回来。
# 前提: .env 填好(NEO4J_* → server1 图;LLM_API_BASE → 本地 qwen);先跑过 cascade-gate.sh(建 .venv312+装 openjiuwen)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#        bash scripts/cascade-selftest.sh [每类条数=1] [类数上限=12] [--order recent|severity|first]
set -uo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env —— 先 cp .env.example .env 并填端点"; exit 1; }
PY=".venv312/bin/python"
[ -x "$PY" ] || { echo "!! 缺 .venv312 —— 先跑 bash scripts/cascade-gate.sh(建 3.11+ venv + 装 openjiuwen)"; exit 1; }

mkdir -p feedback
TS="$(date -u '+%Y%m%d-%H%M%SZ' 2>/dev/null || echo run)"
FB="feedback/cascade-selftest-${TS}.out"
{
  echo "=== cascade-selftest $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/cascade_selftest.py "$@" 2>&1 | grep -vE "\| INFO \||Registered parser|event_id"
  echo "=== done $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
} 2>&1 | tee "$FB" || true

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: cascade-selftest ${TS}" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
