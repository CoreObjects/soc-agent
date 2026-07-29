#!/usr/bin/env bash
# server2:【唯一的 poller 重启脚本】降超时 + 设并发 +(可选)设深浅模型 + 重启 + 180s 验证进度。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-fix-restart.sh [超时=120] [并发=8] [深度模型] [浅层模型]
#   例:  poller-fix-restart.sh 180 16                             # 超时180/并发16,模型沿用 .env
#         poller-fix-restart.sh 180 16 qwen3.5-27b qwen3.5-9b     # 顺带设 深=27b/浅=9b(双模型漏斗)
#         poller-fix-restart.sh 180 16 qwen3.5-27b               # 只设深度、浅层沿用 .env
#   不传模型参数就不动 .env 里的 LLM_MODEL/SHALLOW_LLM_MODEL。
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
TMO="${1:-120}"; CONC="${2:-8}"; DEEP="${3:-}"; SHALLOW="${4:-}"

mkdir -p feedback logs
FB="feedback/poller-fix-restart.out"
{
  echo "=== poller-fix-restart  TMO=$TMO CONC=$CONC  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  # 写 .env(有则替换、无则追加);模型仅在传了参数时才改,不传沿用 .env
  KVS=("LLM_TIMEOUT=$TMO" "POLLER_CONCURRENCY=$CONC")
  [ -n "$DEEP" ]    && KVS+=("LLM_MODEL=$DEEP")
  [ -n "$SHALLOW" ] && KVS+=("SHALLOW_LLM_MODEL=$SHALLOW")
  for kv in "${KVS[@]}"; do
    k="${kv%%=*}"
    if grep -q "^$k=" .env; then sed -i "s|^$k=.*|$kv|" .env; else echo "$kv" >> .env; fi
  done
  echo "-- .env 现值(深/浅模型 + 超时 + 并发)--"
  grep -E "^LLM_MODEL|^SHALLOW_LLM_MODEL|^LLM_TIMEOUT|^POLLER_CONCURRENCY|^SOC_CASCADE" .env || true

  echo "-- 强杀旧 poller(清掉卡死的 worker)--"
  pkill -9 -f "soc_agent.runtime" 2>/dev/null || true; sleep 3
  echo "-- 起新 poller(新 QwenClient:每次新连接、读超时 ${TMO}s)--"
  nohup env SOC_CASCADE_ENABLED=1 "$PY" -m soc_agent.runtime > logs/poller-full.log 2>&1 &
  sleep 5
  echo "  PID=$!"

  echo "-- 180s 进度验证(深度研判是多轮 agent、每条几分钟,窗口必须够长才准)--"
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1 || echo "  (查询失败)"
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
c = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(c.neo4j_uri, c.neo4j_user, c.neo4j_password, c.neo4j_database)
def snap():
    t = g.run_cypher("MATCH (a:Alert)-[:CONCLUDED]->() RETURN count(DISTINCT a) AS n")[0]["n"]
    p = g.run_cypher("MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true RETURN count(a) AS n")[0]["n"]
    return t, p
t0, p0 = snap(); time.sleep(180); t1, p1 = snap()
g.close()
rate = (t1 - t0) / 3.0
print(f"  180s 内:新研判 {t1-t0} 条,新增毒告警 {p1-p0}  → 约 {rate:.1f}/分钟")
print(f"  ✅ 在动(数字在涨)" if t1 > t0 else "  ⚠ 还是0 —— 看日志末尾/og 是否又挂")
PYEOF
  echo "-- 日志末尾 --"; tail -10 logs/poller-full.log 2>/dev/null || true
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-fix-restart" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
