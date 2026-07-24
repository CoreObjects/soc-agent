#!/usr/bin/env bash
# server2:放开全量 —— 后台常驻消化存量(arrival 序)+ 持续轮询新入图告警。日志落 logs/poller-full.log。
# 处置默认 manual(只生成待处置、不执行)。★长跑几天,幂等可随时停/续(CONCLUDED 作水位)。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-full.sh
#   看进度: tail -f logs/poller-full.log    |    台账快照(ferry): bash scripts/ledger-stats.sh
#   停:     pkill -f soc_agent.runtime      |    调并发: 启动前 export POLLER_CONCURRENCY=4
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"
[ -x "$PY" ] || { echo "!! 缺 .venv312 —— 先 bash scripts/cascade-gate.sh"; exit 1; }
mkdir -p logs

if pgrep -f "soc_agent.runtime" >/dev/null 2>&1; then
  echo "⚠️ 已有 poller 在跑(pgrep -f soc_agent.runtime)。要重启先:pkill -f soc_agent.runtime"
  exit 1
fi

nohup env SOC_CASCADE_ENABLED=1 "$PY" -m soc_agent.runtime > logs/poller-full.log 2>&1 &
PID=$!
sleep 3
echo "✅ poller 已后台启动  PID=$PID"
echo "   日志:   tail -f logs/poller-full.log"
echo "   进度:   bash scripts/ledger-stats.sh      # verdict/path 分布快照,ferry 回来"
echo "   停(可续):pkill -f soc_agent.runtime"
echo
echo "—— 启动头几行 ——"
head -4 logs/poller-full.log 2>/dev/null || true
