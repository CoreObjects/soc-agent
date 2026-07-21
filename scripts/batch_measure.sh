#!/usr/bin/env bash
# 真告警批量定量验:经验层"越用越省"(沉淀收敛 / AUTO 命中率 / LLM 节省)。结果 ferry 回来。
# 前置:先 bash scripts/reset_pristine.sh(干净态,量测才准)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/batch_measure.sh [条数=20] [--tech T1558.003]
set -uo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }
./.venv/bin/pip install -q "psycopg2-binary>=2.9" >/dev/null 2>&1 || true

mkdir -p feedback
FB="feedback/batch-measure.out"
{
  echo "=== batch-measure  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/batch_measure.py "$@"
  echo "=== done ==="
} 2>&1 | tee "$FB"

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: batch-measure $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
