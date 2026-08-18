#!/usr/bin/env bash
# 【Phase 0】路由记忆:逐键定性 + 估值。★只读 —— 不调 LLM、不写图、不写经验库。
#
# 它回答两个**不同**的问题:
#   ① 值不值得做:有多少告警能算出键(= 能被记住的路由调用上限)、要学多少个键。
#   ② 哪些键**天生有歧义**:这些必须永远走 LLM,用 --seed 预先播成负例。
#
# ★注意判据是**逐键**的,不是全局的。"能不能安全缓存"是每个键各自的属性 ——
#   把它平均成一个总数,会让"1 个歧义键恰好覆盖 30% 告警"这种情况看起来一切正常。
#
# 用法(server2 研判机,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/route-profile.sh
#
#   bash scripts/route-profile.sh --top 0          # 列出全部键,不截断
#   bash scripts/route-profile.sh --seed           # ★要等 Phase 1 的 route_memo 表建好才能用
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"

mkdir -p feedback
FB="feedback/route-profile.out"
ferry_guard "$FB" "feedback: route-profile $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== route-profile  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo
  PYTHONUTF8=1 "$PY" -X utf8 scripts/route_profile.py "$@"
  RC=$?
  echo
  echo "[退出码] $RC   (0=估值判据 PASS / 1=FAIL,别当报错 / 2=图里没告警)"
  if [ "$RC" -eq 0 ]; then
    echo "★PASS —— 可以进 Phase 1。若 [4] 列了 ambiguous 键,等表建好后跑一次:"
    echo "  bash scripts/route-profile.sh --seed"
  elif [ "$RC" -eq 1 ]; then
    echo "★FAIL —— 有键覆盖率不够,记忆层省不下多少。先看 [3] rule_id 的缺失情况。"
  fi
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
