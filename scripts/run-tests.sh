#!/usr/bin/env bash
# server2:跑与本轮改动相关的单测(.venv312 有 openjiuwen+psycopg2,能跑 cascade/决策A/poller)。结果 ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/run-tests.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PY=".venv312/bin/python"
[ -x "$PY" ] || { echo "!! 缺 .venv312 —— 先 bash scripts/cascade-gate.sh"; exit 1; }

mkdir -p feedback
FB="feedback/tests.out"
TESTS="tests/test_cascade_build.py tests/test_cascade_components.py tests/test_poller.py \
tests/test_runtime_service.py tests/test_response_auto.py tests/test_response_ledger.py \
tests/test_cascade_signature.py tests/test_cascade_dispatch.py tests/test_cascade_floor.py \
tests/test_config.py tests/test_respond_cli.py"
{
  echo "=== pytest (.venv312)  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  # shellcheck disable=SC2086
  PYTHONUTF8=1 "$PY" -m pytest $TESTS -q 2>&1 | tail -45
  echo "=== done ==="
} 2>&1 | tee "$FB" || true

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: tests $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
