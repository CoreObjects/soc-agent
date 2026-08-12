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
  # ★把"这份结果是哪个版本跑出来的"写进报告本身:没有它,拿到一份旧结果时
  #   分不清是"没跑"还是"跑了旧脚本"(实测吃过一次亏)。
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
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
git add -f "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: pivot-parity $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD 2>&1 | tail -3
if [ -n "$(git rev-parse HEAD 2>/dev/null)" ]; then
  git pull --rebase -q origin main 2>&1 | tail -2 || true
  git push origin HEAD 2>&1 | tail -3 || true
fi

# ★核实推送**真的**落地了,再说成功。此前这里无条件打印"已推" —— 推失败也照样显示成功。
git fetch -q origin 2>/dev/null || true
LOCAL="$(git rev-parse HEAD 2>/dev/null)"
REMOTE="$(git rev-parse origin/main 2>/dev/null)"
if [ -n "$LOCAL" ] && [ "$LOCAL" = "$REMOTE" ]; then
  echo "✅ 已推并核实落地:$FB  (origin/main = $(echo "$LOCAL" | cut -c1-8))"
else
  echo "❌ **没推上去**:本地 HEAD=$(echo "$LOCAL" | cut -c1-8) 远端 origin/main=$(echo "$REMOTE" | cut -c1-8)"
  echo "   结果只在本机 $FB —— 别当成跑完了,先解决推送(网络/代理/冲突)。"
  exit 3
fi
