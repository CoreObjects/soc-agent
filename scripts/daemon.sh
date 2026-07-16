#!/usr/bin/env bash
# 在 server2 上跑一趟 daemon(排空当前未研判告警后退出),并把结果 ferry 回来。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/daemon.sh
# 常驻请改用 --serve(见文末);本脚本是 --once 的 git-ferry 验收包装。
# 前提: .env 已填(NEO4J_* → 图库;LLM_API_BASE → 本地 qwen;OG_* → openGauss)。
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "!! 缺 .env —— 先 cp .env.example .env 并填端点"; exit 1; }

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "== 首跑:建 venv + 装依赖 =="
  python3 -m venv .venv
  ./.venv/bin/pip install -q -e .
fi

mkdir -p feedback
FB="feedback/daemon.out"

# 排空一趟 + tee 到 feedback(输出无真实端点/口令,只在 .env)
{
  echo "=== daemon --once  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- selftest(内存 fake,先证明逻辑没坏)--"
  PYTHONUTF8=1 "$PY" -m soc_agent.daemon --selftest
  echo "-- --once(真基建:排空未研判告警)--"
  PYTHONUTF8=1 "$PY" -m soc_agent.daemon --once
  echo "-- 剩余未研判计数(应随范围闸收敛)--"
  PYTHONUTF8=1 "$PY" - <<'PYEOF'
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
c = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(c.neo4j_uri, c.neo4j_user, c.neo4j_password, c.neo4j_database)
try:
    techs = c.daemon_techniques
    rows = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
        "AND ($techs=[] OR any(t IN coalesce(a.technique_ids,[]) WHERE t IN $techs)) "
        "RETURN count(a) AS n", techs=techs)
    print("范围闸内仍未研判:", rows[0]["n"], " (techs=", techs, ")")
    tot = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() RETURN count(a) AS n")[0]["n"]
    print("全库仍未研判(含范围闸外):", tot)
finally:
    g.close()
PYEOF
  echo "=== done $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
} 2>&1 | tee "$FB" || true      # 即使崩了也继续:保证 traceback 也被 ferry 回来

# 回推 feedback(ferry)
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: daemon $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
if git push origin HEAD >/dev/null 2>&1 \
   || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD >/dev/null 2>&1; }; then
  echo "✅ 已推 $FB,Claude 可 pull"
else
  echo "!! push 失败,可手动: git push origin HEAD"
fi

# 常驻(确认 --once 无误后再开):  nohup .venv/bin/python -m soc_agent.daemon >>daemon.log 2>&1 & echo $! > daemon.pid
