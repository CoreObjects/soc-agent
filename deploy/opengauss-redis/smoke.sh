#!/usr/bin/env bash
# openGauss 规则库冒烟(server2)+ 自 ferry。用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash deploy/opengauss-redis/smoke.sh
set -u
cd "$(cd "$(dirname "$0")/../.." && pwd)" || exit 1
OUT="feedback/opengauss-smoke.out"; mkdir -p feedback
PY=".venv/bin/python"
{
  echo "=== openGauss 规则库冒烟 $(date -u '+%F %H:%MZ' 2>/dev/null) ==="
  "$PY" deploy/opengauss-redis/smoke_patterns.py 2>&1
  echo "=== done ==="
} 2>&1 | tee "$OUT"
git add "$OUT" >/dev/null 2>&1 || true
git commit -q -m "feedback: opengauss smoke $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" >/dev/null 2>&1 || true
git push origin HEAD >/dev/null 2>&1 || { git pull --rebase -q origin main >/dev/null 2>&1; git push origin HEAD 2>&1 | tail -2; }
echo "✅ 反馈已推 feedback/opengauss-smoke.out"
