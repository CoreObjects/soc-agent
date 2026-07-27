#!/usr/bin/env bash
# server2:诊断 poller —— 在不在跑 / 台账进度 / 最近日志 / 当前并发。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-status.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/poller-status.out"
{
  echo "=== poller-status  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- poller 进程(soc_agent.runtime)--"
  if pgrep -af "soc_agent.runtime" 2>/dev/null; then
    echo "  ✅ 在跑"
  else
    echo "  ❌ 没在跑(已停)→ 没有新研判就是这个原因;续跑: bash scripts/poller-full.sh"
  fi
  echo "-- .env 相关配置 --"
  grep -E "^POLLER_CONCURRENCY|^SOC_RESPONSE_MODE|^SOC_CASCADE" .env 2>/dev/null || echo "  (用默认:并发2/manual)"
  echo "-- 台账进度(两次隔 5s,看数字动不动)--"
  for i in 1 2; do
    PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1 || echo "  (查询失败)"
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
c = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(c.neo4j_uri, c.neo4j_user, c.neo4j_password, c.neo4j_database)
tot = g.run_cypher("MATCH (a:Alert)-[:CONCLUDED]->() RETURN count(DISTINCT a) AS n")[0]["n"]
bl = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                  "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n")[0]["n"]
ps = g.run_cypher("MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true RETURN count(a) AS n")[0]["n"]
g.close(); d = tot + bl
print(f"  已研判 {tot} / 积压 {bl} / 毒告警 {ps}  —— 完成 {100*tot/(d or 1):.1f}%")
PYEOF
    [ "$i" = 1 ] && sleep 5
  done
  echo "  ↑ 两行数字一样 = 没在研判;不一样 = 在动"
  echo "-- poller 日志末尾 --"; tail -8 logs/poller-full.log 2>/dev/null || echo "  (无 logs/poller-full.log)"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-status" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
