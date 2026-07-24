#!/usr/bin/env bash
# server2:启动告警轮询研判(存量按时间序消化 + 常驻轮询)。结果 ferry 回来。
# 前置:① cascade-gate.sh(建 .venv312 + 装 openjiuwen)② og_probe 通过 ③ .env 配好 NEO4J_*/LLM_*/OG_*。
# 用法(小样本先验一轮闭环,再放开):
#   cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller.sh --once --max 20
#   常驻(消化存量+轮询新告警,后台跑):nohup bash scripts/poller.sh >/dev/null 2>&1 &   # 见下方说明
# ★处置默认 manual(只生成待处置、不执行);要 auto 在 .env 设 SOC_RESPONSE_MODE=auto。
set -uo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env —— 先 cp .env.example .env 并填端点"; exit 1; }
PY=".venv312/bin/python"
[ -x "$PY" ] || { echo "!! 缺 .venv312 —— 先跑 bash scripts/cascade-gate.sh"; exit 1; }

mkdir -p feedback
TS="$(date -u '+%Y%m%d-%H%M%SZ' 2>/dev/null || echo run)"
FB="feedback/poller-${TS}.out"
{
  echo "=== poller  $(date -u '+%F %H:%MZ' 2>/dev/null || true)   args: $* ==="
  # SOC_CASCADE_ENABLED=1:poller 走浅层→深度 cascade(决策 A 要 cascade 开)
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" -m soc_agent.runtime "$@" 2>&1 \
    | grep -vE "\| INFO \||Registered parser|event_id"
  echo "=== done  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
} 2>&1 | tee "$FB" || true

# ferry(有限运行 --once/--max 跑完才 push;真常驻请用 nohup 直接跑 python -m,别经本 wrapper)
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller ${TS}" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
