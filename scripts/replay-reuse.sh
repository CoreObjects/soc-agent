#!/usr/bin/env bash
# 语料保全闸门:重放已研判告警,量自动复用率(★只读:不调 LLM、不写台账、不沉淀经验)。
#
# 这是 WP10 的硬闸门。放宽 recipe 谓词、给 Finding.attrs 加字段这类改动,失败方式
# **不是报错**,而是指纹悄悄不再命中、系统默默退回全量 LLM 研判,唯一症状是成本漂移。
#
# 用法(在 **server2 研判机**上跑):
#   bash scripts/replay-reuse.sh                      # 出一份基线并存盘
#   bash scripts/replay-reuse.sh --compare            # 改完之后与基线对比;复用率下降即失败
#   PER_SKILL=20 bash scripts/replay-reuse.sh         # 想快点先小样本(每 skill 20 条)
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/replay-reuse.out"
BASE="feedback/replay-reuse.baseline.json"
export FERRY_EXTRA="$BASE"          # 基线要跟结果一起推回去,否则下次没法对比
ferry_guard "$FB" "feedback: replay-reuse $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

MODE="${1:-}"
{
  echo "=== 语料保全闸门:重放复用率 $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo "每 skill 抽: ${PER_SKILL:-60} 条(★分层抽样,不是总数封顶)"
  echo
  if [ "$MODE" = "--compare" ]; then
    if [ ! -f "$BASE" ]; then
      echo "❌ 没有基线 $BASE —— 先不带参数跑一次出基线,改完再 --compare。"
      echo "   ★注意:基线必须是**改动之前**跑的,改完再补的基线毫无意义。"
      exit 2
    fi
    PYTHONUTF8=1 "$PY" -X utf8 scripts/replay_reuse.py --per-skill "${PER_SKILL:-60}" --baseline "$BASE"
    echo "[退出码] $?"
  else
    PYTHONUTF8=1 "$PY" -X utf8 scripts/replay_reuse.py --per-skill "${PER_SKILL:-60}" --save "$BASE"
    RC=$?
    echo "[退出码] $RC"
    echo
    # ★首跑这里无条件打了"这一份是基线",而那次其实**失败了**(空经验库)——
    #   又一次"失败却报得像成功"。按退出码说话。
    if [ "$RC" -eq 0 ]; then
      echo "★这一份是**基线**。改动之后跑 \`bash scripts/replay-reuse.sh --compare\` 对比。"
    else
      echo "❌ 本次**没有产出基线**(退出码 $RC)。先按上面的提示修好再跑,别拿这次的输出当基线。"
    fi
  fi
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
