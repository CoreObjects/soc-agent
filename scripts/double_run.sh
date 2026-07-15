#!/usr/bin/env bash
# P3' 首刀总验收(server2)+ 自 ferry。用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/double_run.sh
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
OUT="feedback/double-run.out"; mkdir -p feedback
{
  echo "=== P3' 换实例双跑总验收 $(date -u '+%F %H:%MZ' 2>/dev/null) ==="
  .venv/bin/python scripts/double_run.py --reset 2>&1
  echo "=== done ==="
} 2>&1 | tee "$OUT"
git add "$OUT" >/dev/null 2>&1 || true
git commit -q -m "feedback: double-run $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" >/dev/null 2>&1 || true
git push origin HEAD >/dev/null 2>&1 || { git pull --rebase -q origin main >/dev/null 2>&1; git push origin HEAD 2>&1 | tail -2; }
echo "✅ 反馈已推 feedback/double-run.out"
