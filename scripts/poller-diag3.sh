#!/usr/bin/env bash
# server2:判"又卡死 vs 只是慢" —— py-spy 看 worker 当前卡点 + 采样 150s(超 120s 超时线,真卡会转毒告警)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-diag3.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/poller-diag3.out"
{
  echo "=== poller-diag3  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PID=$(pgrep -f "soc_agent.runtime" 2>/dev/null | head -1 || true)
  echo "-- poller PID=${PID:-无} --"
  PYSPY="$(dirname "$PY")/py-spy"
  [ -x "$PYSPY" ] || "$PY" -m pip install -q py-spy 2>&1 | tail -1 || true
  echo "-- py-spy 线程栈(worker 现在卡在哪一行)--"
  if [ -n "${PID:-}" ] && [ -x "$PYSPY" ]; then
    "$PYSPY" dump --pid "$PID" 2>&1 | grep -E "Thread |chat |investigate|run_pipeline|read |acquire|recv|create |completions|poller.py|consult|opengauss|_receive" | head -40 \
      || { echo "  py-spy 直接 dump 失败,试 sudo:"; sudo "$PYSPY" dump --pid "$PID" 2>&1 | grep -E "Thread |chat |read |investigate|completions|_receive" | head -40 || echo "  仍失败(权限)"; }
  fi
  echo "-- 采样 150s(超 120s 超时线)--"
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
t0, p0 = snap()
print(f"  T0: 已研判 {t0} / 毒 {p0}")
time.sleep(150)
t1, p1 = snap()
print(f"  T1(+150s): 已研判 {t1} / 毒 {p1}")
print(f"  → 150s 新研判 {t1-t0} 条,新增毒 {p1-p0}")
if t1 > t0:
    print("  ✅ 在动(只是慢,agent 多轮循环正常)")
elif p1 > p0:
    print("  ⚠ 没研判成但在冒毒 → 请求超时/失败,模型对这些 prompt 不响应")
else:
    print("  ❌ 零动零毒 → 彻底卡死(连 120s 超时都没触发?连接层挂死)")
g.close()
PYEOF
  echo "-- 日志末尾 --"; tail -12 logs/poller-full.log 2>/dev/null || true
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-diag3" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
