#!/usr/bin/env bash
# 行集一致闸门(★只读):改动前后,改过的那些 recipe 在同一批真实告警上产出是否逐字相同。
#
# 与 replay-reuse.sh 的分工 —— **两道都要跑,谁也替不了谁**:
#   · replay-reuse  量「已沉淀经验还认不认得出来」,只护得住**有已研判语料**的 skill;
#     真机实测 16 个 skill 里 10 个一条语料都没有(c2_beacon/webshell/web_exploit/
#     suspicious_outbound 等,正是 WP10 要改的重点)⇒ 对它们那道闸门是全绿的空转。
#   · recipe-parity 不要求告警被判过,只要求「同一条告警,改前改后吐出的东西逐字相同」。
#
# 用法(soc 身份,在 server2 上):
#   REV=<改动前的提交> bash scripts/recipe-parity.sh
#   REV=abc1234 SKILLS=c2_beacon,webshell bash scripts/recipe-parity.sh    # 只测这几个
#   不给 SKILLS 就自动测 REV..HEAD 之间**改动过的** recipe。
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/recipe-parity.out"
ferry_guard "$FB" "feedback: recipe-parity $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

: "${REV:?必须给基线 rev,例:REV=\$(git rev-parse HEAD~1) bash scripts/recipe-parity.sh}"

{
  echo "=== 行集一致闸门 $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo
  # shellcheck disable=SC2086
  PYTHONUTF8=1 "$PY" -X utf8 scripts/recipe_parity.py \
      --rev "$REV" \
      ${SKILLS:+--skills "$SKILLS"} \
      --pool "${POOL:-1200}" \
      --min-nonempty "${MIN_NONEMPTY:-30}" \
      ${ALLOW_FINDINGS:+--allow-new-findings "$ALLOW_FINDINGS"} \
      ${ALLOW_CTX:+--allow-new-ctx "$ALLOW_CTX"} \
      ${ALLOW_BINDINGS:+--allow-new-bindings "$ALLOW_BINDINGS"}
  RC=$?
  echo "[退出码] $RC"
  echo
  case "$RC" in
    0) echo "✅ 通过:行集一致,且样本有区分力。" ;;
    1) echo "❌ 不通过:出现了**未声明**的差异。这正是本闸门要拦的东西 —— 别急着加白名单放行。" ;;
    3) echo "⚠ 证据不足:样本上旧版几乎没产出过东西,零差异不证明任何事。加大 POOL 再来。" ;;
    *) echo "⚠ 异常退出($RC),看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
