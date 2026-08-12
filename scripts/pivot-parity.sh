#!/usr/bin/env bash
# WP7 真机闸门(★只读):pivot 化前后,三个 recipe 在真实告警上的取证产物逐条对比。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/pivot-parity.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv/bin/python"
[ -x "$PY" ] || { python3 -m venv .venv && ./.venv/bin/pip install -q -e .; }
mkdir -p feedback
FB="feedback/pivot-parity.out"

# 基线 = 引入 pivot.py 的那个提交的父提交。★不用 HEAD~1:本次可能推了不止一个提交,
#   写死 ~1 会把基线选成"已经改过一半"的版本,比出来的零差异是假的。
BASE_COMMIT="$(git log --diff-filter=A --format=%H -- soc_agent/graph/pivot.py | tail -1)"
if [ -z "$BASE_COMMIT" ]; then
  echo "!! 找不到引入 soc_agent/graph/pivot.py 的提交 —— 先 git fetch/reset 到含本次改动的 main"; exit 1
fi
REV="${BASE_COMMIT}^"

{
  echo "=== WP7 pivot 行为对等(只读) $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "基线 rev = $REV  (= 引入 pivot.py 的提交 $BASE_COMMIT 的父提交)"
  git --no-pager log -1 --format='  基线提交: %h %s' "$REV" 2>&1 || true
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/pivot_parity.py --rev "$REV" --limit "${LIMIT:-800}" \
      --random-limit "${RANDOM_LIMIT:-400}" --min-nonempty "${MIN_NONEMPTY:-500}"
  echo "[退出码] $?"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: pivot-parity $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
