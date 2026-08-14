#!/usr/bin/env bash
# 端到端研判流程演示:挑一条可疑进程告警,把每一步的输入/动作/产出全打印出来。
#
# ★默认口径(为了让汇报看到完整流程、且不污染生产):
#   · **不走经验复用** —— 把这条告警当成没见过的,完整走到大模型深度研判。
#     经验层照常比对并把**真实结论**打印出来,随后显式声明「演示强制转深度」,
#     所以既看得到经验层确实命中了什么(省算力的能力),也看得到完整流程。
#     要看生产实际的抄近路行为:REUSE=1
#   · **不写生产** —— 图台账/回归语料/经验库都只打印「本应写入什么」。
#     但**蒸馏与考试是真跑的**,只是落到一个用完即弃的临时经验库,
#     所以「自进化」那一环有实物可看,而生产经验库不被一次演示污染。要真写:WRITE=1
#   · **不截断** —— 告警原文、取证上下文、**送入大模型的完整提示词与完整返回**,
#     一字不省地打出来,可以逐字核对我们有没有把答案偷偷塞给模型。
#   · **打开浅层** —— 三级漏斗的第一级(签名库前置 → 硬底线 floor → 浅层 LLM 分诊)
#     由 SOC_CASCADE_ENABLED 控制、生产可能是关的。汇报要看完整流程就得展示,
#     所以演示默认打开,并**同时打印 .env 里的真实配置**,不一致时明确标注是演示口径。
#     要按 .env 实际配置跑:CASCADE=env   只走深度:CASCADE=off
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
      ${REUSE:+--reuse} \
      ${CASCADE:+--cascade "$CASCADE"} \
      ${WRITE:+--write}
  RC=$?
  echo
  echo "[退出码] $RC"
  case "$RC" in
    0) echo "✅ 演示跑通。每一步都是生产真实执行的那一步(脚本包的是真实函数,不是复制品);"
       echo "   大模型每次调用的完整提示词与完整返回都在上面,可逐字核对。" ;;
    2) echo "⚠ 指定的 alert_uid 在图里不存在。" ;;
    3) echo "⚠ 图里没有进程类告警,挑不出演示对象。" ;;
    *) echo "⚠ 异常退出($RC),看上面的报错。" ;;
  esac
  echo "=== done ==="
} 2>&1 | tee "$FB"
# 推送由 ferry_guard(EXIT 陷阱)负责。
