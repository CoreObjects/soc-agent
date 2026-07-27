#!/usr/bin/env bash
# server2:摆渡所有"真实威胁(true_positive)"—— 按 technique 分组,列 规则/依据/处置目标/路径。
# 供核对:①是不是都是你打的那几个攻击 ②有没有漏检 ③有没有把良性误判成真实威胁。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/dump-tp.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/dump-tp.out"
{
  echo "=== dump-tp  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
cfg = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)

rows = g.run_cypher(
    "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict {verdict:'true_positive'}) "
    "OPTIONAL MATCH (v)-[:LED_TO]->(:ResponsePlan)-[:STEP]->(d:Disposition) "
    "WITH a, c, v, collect(DISTINCT {action:d.action, target:d.target}) AS disps "
    "RETURN a.alert_uid AS uid, a.rule_description AS rule, a.technique_ids AS tech, "
    "  a.source AS source, coalesce(c.path,v.path) AS path, coalesce(c.method,'llm') AS method, "
    "  c.rationale AS rationale, disps "
    "ORDER BY tech, a.rule_description")

print(f"真实威胁(true_positive)总数: {len(rows)}\n")

# 按 technique 分布
from collections import Counter
hist = Counter()
for r in rows:
    tech = (r.get("tech") or ["(无technique)"])
    hist[tech[0] if tech else "(无technique)"] += 1
print("按 technique 分布:")
for t, n in hist.most_common():
    print(f"   {t}: {n}")

# 复用 vs 真研判(复用的要留意源判例对不对)
mh = Counter(r.get("method") for r in rows)
print(f"\n研判方式: {dict(mh)}  (reuse=复用经验命中,llm=真研判)")

print("\n逐条:")
for r in rows:
    tech = ",".join(r.get("tech") or []) or "-"
    disps = [f"{d['action']}→{d.get('target')}" for d in (r.get("disps") or [])
             if d.get("action") and d["action"] != "none"]
    rat = (r.get("rationale") or "").replace("\n", " ")
    print(f"  ── [{tech}] {r['uid'][:16]}  path={r['path']}/{r['method']}  source={r.get('source')}")
    print(f"     规则: {r.get('rule')}")
    print(f"     依据: {rat[:300]}")
    print(f"     处置: {', '.join(disps) if disps else '(无/未组出)'}")
g.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: dump-tp" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
