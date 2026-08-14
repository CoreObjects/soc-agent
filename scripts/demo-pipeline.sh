#!/usr/bin/env bash
# 端到端研判流程演示:挑一条可疑进程告警,把每一步的输入/动作/产出全打印出来。
#
# ★默认**演示模式**:不写图台账、不存回归语料、不沉淀经验 —— 只打印「本应写入什么」。
#   为做一次汇报而往生产台账和经验库里写东西,是那种当时没人注意、以后查不清的污染。
#   要真写:  WRITE=1 bash scripts/demo-pipeline.sh
#
# 用法(soc 身份,server2):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && \
#   bash scripts/demo-pipeline.sh
#   ALERT_UID=<uid> bash scripts/demo-pipeline.sh      # 指定某一条
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/_ferry.sh
source "$(dirname "$0")/_ferry.sh"
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
mkdir -p feedback
FB="feedback/demo-pipeline.out"
ferry_guard "$FB" "feedback: demo-pipeline $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)"

{
  echo "=== 研判流程演示 $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "主机    : $(hostname 2>/dev/null)   仓库 $(pwd)"
  echo "代码版本: $(git rev-parse --short HEAD 2>/dev/null) $(git log -1 --format=%s 2>/dev/null | cut -c1-60)"
  echo "解释器  : $PY -> $("$PY" -V 2>&1)"
  echo
  # shellcheck disable=SC2086
  PYTHONUTF8=1 "$PY" -X utf8 scripts/demo_pipeline.py \
      ${ALERT_UID:+--alert-uid "$ALERT_UID"} \
      ${MODE:+--mode "$MODE"} \
      ${WRITE:+--write}
  RC=$?
  echo
  echo "[退出码] $RC"
  case "$RC" in
    0) echo "✅ 演示跑通。上面每一步都是生产真实执行的那一步(脚本包的是真实函数,不是复制品)。" ;;
    2) echo "⚠ 指定的 alert_uid 在图里不存在。" ;;
    3) echo "⚠ 图里没有进程类告警,挑不出演示对象。" ;;
    *) echo "⚠ 异常退出($RC),看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
