#!/usr/bin/env bash
# server2:深度研判换更大模型(领导:9b 上下文超了才慢,27B 上下文更大)。停 poller + 设 LLM_MODEL + 重启 + 验证。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/use-27b.sh [模型=qwen3.5-27b] [并发=16]
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
MODEL="${1:-qwen3.5-27b}"; CONC="${2:-16}"

echo "-- 停旧 poller --"
pkill -9 -f "soc_agent.runtime" 2>/dev/null && echo "  已停" || echo "  本没跑"
sleep 2
# 设 .env 的 LLM_MODEL(有则替换、无则追加)
if grep -q '^LLM_MODEL=' .env; then
  sed -i "s|^LLM_MODEL=.*|LLM_MODEL=${MODEL}|" .env
else
  echo "LLM_MODEL=${MODEL}" >> .env
fi
echo "-- LLM_MODEL 已设为 ${MODEL} --"
grep -E "^LLM_MODEL|^LLM_TIMEOUT|^POLLER_CONCURRENCY" .env || true
echo "-- 重启 poller(超时180/并发${CONC})+ 自检 + ferry --"
exec bash scripts/poller-fix-restart.sh 180 "$CONC"
