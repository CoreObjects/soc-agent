#!/usr/bin/env bash
# Phase 1 E2E(agent 侧)· 找 TP kerberoast → 研判(快慢通道+composer 组处置)→ 列台账待审计划 → push feedback。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/e2e_response.sh
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
OUT="feedback/e2e-response.out"; mkdir -p feedback
{
  echo "=== e2e-response(找TP→研判→组处置→列待审计划)$(date -u '+%F %H:%MZ' 2>/dev/null) ==="
  .venv/bin/python scripts/e2e_response.py 2>&1
  echo "=== done ==="
} 2>&1 | tee "$OUT"
git add "$OUT" scripts/e2e_response.py scripts/e2e_response.sh >/dev/null 2>&1 || true
git commit -q -m "feedback: e2e-response $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" >/dev/null 2>&1 || true
git push origin HEAD >/dev/null 2>&1 || { git pull --rebase -q origin main >/dev/null 2>&1; git push origin HEAD 2>&1 | tail -2; }
echo "✅ 反馈已推 feedback/e2e-response.out"
