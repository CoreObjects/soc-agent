#!/usr/bin/env bash
# server2:统计已研判台账(verdict×path 分布 / 处置状态 / TP 抽样),验 poller 产出。结果 ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/ledger-stats.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/ledger-stats.out"
{
  echo "=== ledger-stats  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline
pl = build_pipeline(Config.from_env(dotenv_path=".env"))
g = pl.graph
try:
    tot = g.run_cypher("MATCH (a:Alert)-[:CONCLUDED]->() RETURN count(*) AS n")[0]["n"]
    backlog = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                           "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n")[0]["n"]
    poison = g.run_cypher("MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true "
                          "RETURN count(a) AS n")[0]["n"]
    total = tot + backlog + poison
    pct = (100.0 * tot / total) if total else 0.0
    print(f"进度:已研判 {tot} / 未研判(积压){backlog} / 毒告警跳过 {poison}  —— 完成 {pct:.1f}%")
    print("★积压=0 即存量研判完(之后只随新入图告警慢慢涨)\n")
    # ★path=S 里其实是**两种**东西,成本差一个数量级,必须分开看:
    #     method=reuse → 签名库复用,**零 LLM**
    #     method=llm   → 浅层 9b 直判(新 payload 还要再花一次 27b 蒸签名,见 _sig_learn)
    #   只按 path 分组会把它们糊成一个数,而"到底省了多少"完全取决于这个比例。
    print("verdict × path × method(S=浅层 / A=经验复用 / B=深度LLM;reuse=零LLM复用):")
    for r in g.run_cypher("MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
                          "RETURN v.verdict AS verdict, coalesce(c.path,v.path) AS path, "
                          "coalesce(c.method,'?') AS method, count(*) AS n "
                          "ORDER BY n DESC"):
        print(f"  {str(r['verdict']):16} path={str(r['path']):3} "
              f"method={str(r['method']):6}  {r['n']}")
    print("\n处置 Disposition 状态(排除 __no_op__ 占位;★manual 应全 proposed=待处置):")
    rows = g.run_cypher("MATCH (d:Disposition) WHERE d.step_key<>'__no_op__' "
                        "RETURN d.status AS status, count(*) AS n ORDER BY n DESC")
    print("  (无真处置步骤)" if not rows else "")
    for r in rows:
        print(f"  {str(r['status']):12} {r['n']}")
    print("\nResponsePlan 状态:")
    for r in g.run_cypher("MATCH (p:ResponsePlan) RETURN p.status AS status, count(*) AS n ORDER BY n DESC"):
        print(f"  {str(r['status']):12} {r['n']}")
    print("\nTP 抽样(≤5 条,含处置步骤+状态):")
    tps = g.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict {verdict:'true_positive'}) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)-[:STEP]->(d:Disposition) "
        "RETURN a.alert_uid AS uid, p.status AS plan, "
        "collect({action:d.action, target:d.target, status:d.status}) AS steps LIMIT 5")
    print("  (本轮无 TP)" if not tps else "")
    for r in tps:
        print(f"  {str(r['uid'])[:16]}  plan={r['plan']}  steps={r['steps']}")
finally:
    pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: ledger-stats $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
