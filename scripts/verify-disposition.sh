#!/usr/bin/env bash
# server2:定向验"深度判 TP → 生成处置指令(待处置)"。抓一条 kerberoast(RC4)走 poller 同款研判路径
# (run_investigation, cascade on)→ 看是否组出处置、状态是否 proposed(=待处置,manual 只生成不执行)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/verify-disposition.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/verify-disposition.out"
{
  echo "=== verify-disposition  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation
pl = build_pipeline(Config.from_env(dotenv_path=".env"))
g = pl.graph
try:
    rows = g.run_cypher("MATCH (a:Alert) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
                        "AND NOT (a)-[:CONCLUDED]->() RETURN a.alert_uid AS uid LIMIT 1")
    if not rows:
        print("无未研判 kerberoast(T1558.003)告警 —— 换一条已知攻击类再试"); sys.exit(0)
    uid = rows[0]["uid"]
    print(f"研判 kerberoast 告警 {uid[:20]}(cascade on → run_cascade → 升级深度)…\n")
    result, report, picked = run_investigation(pl, uid, mode="recipe")
    v = result.verdict
    print(f"结论:verdict={v.verdict if v else None}  path={result.path}  decision={report.decision}  picked={picked}")
    dl = g.run_cypher(
        "MATCH (a:Alert {alert_uid:$u})-[:CONCLUDED]->(v:Verdict) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)-[:STEP]->(d:Disposition) "
        "RETURN p.status AS plan, "
        "collect({order:d.step_key, action:d.action, target:d.target, status:d.status}) AS steps", u=uid)
    for r in dl:
        print(f"ResponsePlan.status = {r['plan']}   (★manual 应为 proposed=待处置)")
        steps = [s for s in r["steps"] if s.get("action")]
        print("处置步骤:" + ("(无 —— 若判 TP 却无处置=组处置没触发,该查)" if not steps else ""))
        for s in steps:
            print(f"  - {s['action']} → {s['target']}   [status={s['status']}]")
finally:
    pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: verify-disposition $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
