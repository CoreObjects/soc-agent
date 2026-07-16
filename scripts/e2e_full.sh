#!/usr/bin/env bash
# Phase 1 全闭环(经 HTTP appliance,全在 server2):找TP→组计划→approve→execute→验台账→rollback→验台账。
#   用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/e2e_full.sh
#   需 ~/soc-agent/.env 配 RESPONSE_URL/RESPONSE_TOKEN(靶场 62 脚本打印的)。DRY(appliance --dry-run)下零风险。
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
OUT="feedback/e2e-full.out"; mkdir -p feedback
{
  echo "=== e2e-full(找TP→approve→execute→rollback 全闭环)$(date -u '+%F %H:%MZ' 2>/dev/null) ==="
  .venv/bin/python scripts/e2e_full.py 2>&1
  echo "=== done ==="
} 2>&1 | tee "$OUT"
git add "$OUT" scripts/e2e_full.py scripts/e2e_full.sh >/dev/null 2>&1 || true
git commit -q -m "feedback: e2e-full $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" >/dev/null 2>&1 || true
git push origin HEAD >/dev/null 2>&1 || { git pull --rebase -q origin main >/dev/null 2>&1; git push origin HEAD 2>&1 | tail -2; }
echo "✅ 反馈已推 feedback/e2e-full.out"
