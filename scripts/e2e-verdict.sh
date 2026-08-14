#!/usr/bin/env bash
# 端到端验证【第 2 步 / 共 2 步】:对着**演练图**(第三张、用完即扔)把研判完整走一遍。
#
# 第 1 步(soc-graph-ingest/scripts/e2e-graph.sh)已经把三个新源真写进 bolt://<靶场机>:7689。
# 这一步验的是后半段:告警 → 取证(recipe)→ 浅层分诊 → 深度研判 → 结论 + 处置建议。
#
# ★复用 `demo_pipeline.py`,不另写一套:它包的是**生产真实函数**,
#   并且完整打印每一步的输入/动作/产出、以及送进大模型的完整提示词与完整返回、一个字不截断。
#   为这次验证另写一个"精简版流水线",验的就是一条生产不走的路。
#
# ★三道硬拒绝(照搬 kafka-consume 那几个脚本的纪律):
#   ①NEO4J_URI 必须指向 7689 —— 指向生产 7687 / 影子 7688 一律拒绝;
#   ②默认不写台账、不写经验库(演示口径,--write 才真写);
#   ③.env 里的 NEO4J_* 会被本脚本覆盖,跑完不残留(子进程 env,不改文件)。
#
# 用法(server2,soc 身份):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   E2E_NEO4J_URI=bolt://10.185.93.0:7689 E2E_NEO4J_PASSWORD=<第1步打印的密码> \
#   bash scripts/e2e-verdict.sh
#   # 只跑某一条:再加 E2E_ONLY=<alert_uid>
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env(要用里面的大模型配置)"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/e2e-verdict.out"
ferry_guard "$FB" "feedback: e2e-verdict $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

URI="${E2E_NEO4J_URI:-}"
case "$URI" in
  "")        echo "!! 必须给 E2E_NEO4J_URI(第 1 步的输出里有)"; exit 1;;
  *7687*)    echo "!! 指向生产图 7687,拒绝 —— 演练数据绝不进生产"; exit 1;;
  *7688*)    echo "!! 指向影子图 7688,拒绝 —— 那张图是等价性比对的基线"; exit 1;;
  *7689*)    :;;
  *)         echo "!! E2E_NEO4J_URI=$URI 不是演练图(应为 …:7689),拒绝"; exit 1;;
esac
export NEO4J_URI="$URI"
export NEO4J_USER="${E2E_NEO4J_USER:-neo4j}"
export NEO4J_PASSWORD="${E2E_NEO4J_PASSWORD:?必须给 E2E_NEO4J_PASSWORD}"

RUN=(env PYTHONUTF8=1 PYTHONPATH=. "$PY" -X utf8)

{
  echo "=== 端到端【第 2 步】对演练图跑完整研判 $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo "目标图  : $NEO4J_URI   ★已硬拒绝 7687/7688"
  echo "口径    : 不写台账/不写经验库(演示口径);蒸馏与考试真跑但落用完即弃的临时库"
  echo

  echo "########## [1] 演练图里有哪些告警,每条值得验什么 ##########"
  "${RUN[@]}" scripts/e2e_alerts.py
  RC=$?
  if [ "$RC" != "0" ]; then
    echo "!! 取不到告警(退出码 $RC)。图里没有 :Alert?先确认第 1 步跑完且图没被拆。"
    exit 1
  fi
  echo

  UIDS=$("${RUN[@]}" scripts/e2e_alerts.py --uids)
  if [ -n "${E2E_ONLY:-}" ]; then
    UIDS="$E2E_ONLY"
    echo "(只跑指定的一条:$E2E_ONLY)"
  fi
  N=$(echo "$UIDS" | grep -c .)
  echo "########## [2] 逐条走完整研判(共 $N 条,不截断)##########"
  echo

  i=0
  FAILED=0
  for uid in $UIDS; do
    i=$((i + 1))
    echo ""
    echo "################################################################################"
    echo "###  第 $i/$N 条   alert_uid=$uid"
    echo "################################################################################"
    "${RUN[@]}" scripts/demo_pipeline.py --alert-uid "$uid" --cascade on
    rc=$?
    echo "[本条退出码] $rc"
    [ "$rc" = "0" ] || FAILED=$((FAILED + 1))
  done

  echo
  echo "########## [3] 小结 ##########"
  echo "  共 $N 条,失败 $FAILED 条"
  if [ "$FAILED" = "0" ]; then
    echo "  ✅ 三个新源写进图之后,后半段(取证 → 浅层分诊 → 深度研判 → 结论/处置)全程跑通。"
    echo "     每一步都是生产真实执行的那一步(脚本包的是真实函数),"
    echo "     大模型每次调用的完整提示词与完整返回都在上面,可逐字核对。"
  else
    echo "  ⚠ 有失败的,看上面对应那条的报错。"
  fi
  echo
  echo "验完记得拆图(在靶场机上): bash scripts/e2e-graph.sh --down"
  echo "=== done ==="
} 2>&1 | tee "$FB"
