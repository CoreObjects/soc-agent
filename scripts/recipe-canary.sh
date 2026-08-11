#!/usr/bin/env bash
# recipe 硬编码字面量哨兵(只读):扫 skills/**/recipe.py 里的 event_code/al.source 字面量,
# 逐个到图里数条数;任何一条 0 行 = 该 recipe 现在静默瞎着。结果 ferry 回来。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/recipe-canary.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }
mkdir -p feedback
FB="feedback/recipe-canary.out"

{
  echo "=== recipe 字面量哨兵(只读) $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" -X utf8 scripts/recipe_canary.py
  echo "[退出码] $?"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: recipe-canary $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
