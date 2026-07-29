#!/usr/bin/env bash
# server2:恢复【双模型漏斗】—— 浅层分诊用小模型(9b,快、便宜、终局筛 FP)、升级后深度研判用大模型(27b)。
# 设 LLM_MODEL(深)+ SHALLOW_LLM_MODEL(浅)+ 探网关两模型都在 + 重启 poller + 180s 验证。
# 背景:use-27b.sh 把 LLM_MODEL 一刀切成 27b → 浅层+深度全 27b、9b 没用上。本脚本把浅层切回 9b。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/use-split.sh [深=qwen3.5-27b] [浅=qwen3.5-9b] [并发=16]
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
DEEP="${1:-qwen3.5-27b}"; SHALLOW="${2:-qwen3.5-9b}"; CONC="${3:-16}"

echo "-- 设 .env:深度 LLM_MODEL=$DEEP  浅层 SHALLOW_LLM_MODEL=$SHALLOW --"
for kv in "LLM_MODEL=$DEEP" "SHALLOW_LLM_MODEL=$SHALLOW"; do
  k="${kv%%=*}"
  if grep -q "^$k=" .env; then sed -i "s|^$k=.*|$kv|" .env; else echo "$kv" >> .env; fi
done
grep -E "^LLM_MODEL|^SHALLOW_LLM_MODEL" .env || true

echo "-- 探网关 /models(确认两模型都在,不在会研判即崩)--"
PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1 || echo "  (探测失败,不阻断重启)"
import os, sys, httpx
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
c = Config.from_env(dotenv_path=".env")
base = (c.llm_api_base or "").rstrip("/")
try:
    r = httpx.Client(trust_env=False, timeout=15).get(
        base + "/models", headers={"Authorization": f"Bearer {c.llm_api_key or 'EMPTY'}"})
    ids = [m.get("id") for m in (r.json().get("data") or [])]
    print("  网关模型:", ids)
    for tag, want in [("深度", c.llm_model), ("浅层", c.shallow_llm_model or c.llm_model)]:
        print(f"    {tag} {want}: {'✅在' if want in ids else '⚠不在网关!会崩,先让领导挂上'}")
except Exception as e:
    print("  探测异常:", type(e).__name__, str(e)[:120])
PYEOF

echo "-- 重启 poller(深度=$DEEP / 浅层=$SHALLOW / 超时180 / 并发=$CONC)+ 自检 + ferry --"
exec bash scripts/poller-fix-restart.sh 180 "$CONC"
