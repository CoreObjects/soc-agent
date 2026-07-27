#!/usr/bin/env bash
# server2:诊断 poller —— 在不在跑 / 采样 60s 算真实速率+ETA / 最近日志 / 并发。ferry。
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
    echo "  ❌ 没在跑(已停)→ 续跑: bash scripts/poller-full.sh"
  fi
  echo "-- .env 配置 --"
  grep -E "^POLLER_CONCURRENCY|^SOC_RESPONSE_MODE|^SOC_CASCADE" .env 2>/dev/null || echo "  (默认:并发2/manual)"
  echo "-- 采样 60s 算真实速率(深度研判每条几十秒,必须拉长窗口才准)--"
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1 || echo "  (查询失败——图不通?)"
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
c = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(c.neo4j_uri, c.neo4j_user, c.neo4j_password, c.neo4j_database)

def snap():
    tot = g.run_cypher("MATCH (a:Alert)-[:CONCLUDED]->() RETURN count(DISTINCT a) AS n")[0]["n"]
    bl = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                      "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n")[0]["n"]
    ps = g.run_cypher("MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true RETURN count(a) AS n")[0]["n"]
    return tot, bl, ps

t0, b0, p0 = snap()
print(f"  T0:       已研判 {t0} / 积压 {b0} / 毒告警 {p0}")
time.sleep(60)
t1, b1, p1 = snap()
print(f"  T1(+60s): 已研判 {t1} / 积压 {b1} / 毒告警 {p1}")
done, poison = t1 - t0, p1 - p0
print(f"  → 60s 内新研判 {done} 条(其中新增毒告警 {poison})≈ {done}/分钟")
if done > 0:
    eta_h = b1 / done / 60
    print(f"  → 按此速率清完 {b1} 积压 ≈ {eta_h:.1f} 小时;想更快就调大并发(poller-stop.sh N)")
else:
    print("  ⚠ 60s 一条没动 → 要么全卡在慢 LLM、要么 LLM/openGauss 不通(看下面日志末尾)")
g.close()
PYEOF
  echo "-- poller 日志末尾(已压掉 Neo4j 无害警告后应能看到真进度/报错)--"
  tail -12 logs/poller-full.log 2>/dev/null || echo "  (无 logs/poller-full.log)"
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-status" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
