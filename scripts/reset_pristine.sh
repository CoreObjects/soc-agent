#!/usr/bin/env bash
# 全量对称重置(图台账 + openGauss 规则双清回最初态)+ 自 ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/reset_pristine.sh
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)" || exit 1
OUT="feedback/reset-pristine.out"; mkdir -p feedback
{
  echo "=== reset-to-pristine(图台账+openGauss规则双清)$(date -u '+%F %H:%MZ' 2>/dev/null) ==="
  .venv/bin/python scripts/reset_pristine.py 2>&1
  echo "=== done ==="
} 2>&1 | tee "$OUT"
git add "$OUT" >/dev/null 2>&1 || true
git commit -q -m "feedback: reset-pristine $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" >/dev/null 2>&1 || true
git push origin HEAD >/dev/null 2>&1 || { git pull --rebase -q origin main >/dev/null 2>&1; git push origin HEAD 2>&1 | tail -2; }
echo "✅ 反馈已推 feedback/reset-pristine.out"
