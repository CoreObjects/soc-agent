#!/usr/bin/env bash
# server2:统计未研判告警分布(给"签名铺开"排优先级),结果 ferry 回来。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/alert_stats.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }

mkdir -p feedback
FB="feedback/alert-stats.out"
{
  echo "=== alert-stats  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/alert_stats.py
  echo "=== done ==="
} 2>&1 | tee "$FB" || true

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: alert-stats $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
