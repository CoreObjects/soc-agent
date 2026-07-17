#!/usr/bin/env bash
# server2:验证某 technique 的快通道签名(换实例双跑式,报快/慢占比+verdict+收敛),结果 ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/verify_signature.sh T1003.001 [n]
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }

TECH="${1:-T1003.001}"
N="${2:-60}"
mkdir -p feedback
FB="feedback/verify-${TECH}.out"
{
  echo "=== verify-signature $TECH n=$N  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" scripts/verify_signature.py "$TECH" "$N"
  echo "=== done ==="
} 2>&1 | tee "$FB" || true

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: verify $TECH $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
