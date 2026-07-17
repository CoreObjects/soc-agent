#!/usr/bin/env bash
# server2:扒 T1105(ingress_tool_transfer)未研判告警数据实形(给 signature 定通用特征),结果 ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/inspect_t1105.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }

mkdir -p feedback
FB="feedback/inspect-t1105.out"
{
  echo "=== inspect-t1105  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/inspect_t1105.py
  echo "=== done ==="
} 2>&1 | tee "$FB" || true

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: inspect-t1105 $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
