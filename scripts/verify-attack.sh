#!/usr/bin/env bash
# server2:揪一条真·用户 kerberoast(用户账号取票+SPN扇出,非机器账号跨域)验 deep TP → 生成处置(待处置)。
# 先用确定性取证筛"requester_is_machine 缺失"(=用户取票)的候选、按扇出排序,再挑前几条走 run_investigation。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/verify-attack.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/verify-attack.out"
{
  echo "=== verify-attack  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, re, sys, json
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, collect_forensics, run_investigation
from soc_agent.models import Alert
_IP = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
def m(s): return _IP.sub(lambda x: f"x.x.x.{x.group(4)}", str(s))

pl = build_pipeline(Config.from_env(dotenv_path=".env"))
g = pl.graph
try:
    skill = pl.router.registry.by_name("kerberoast")
    rows = g.run_cypher("MATCH (a:Alert) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
                        "AND NOT (a)-[:CONCLUDED]->() RETURN a.alert_uid AS uid LIMIT 120")
    cands = []
    for r in rows:
        alert = Alert.from_node(g.get_alert(r["uid"]))
        seed = g.seed(alert)
        fx = collect_forensics(g, alert, seed, skill)
        fids = {f.finding_id for f in fx.findings}
        if "kerberoast.requester_is_machine" in fids:
            continue                                   # 机器账号跨域=良性,跳过
        req = (seed.get("subject") or {}).get("sam")
        fan = 0
        for f in fx.findings:
            if f.finding_id == "kerberoast.spn_fanout":
                fan = f.attrs.get("distinct_targets", 0) or 0
        cands.append((fan, r["uid"], req, sorted(fids)))
    cands.sort(reverse=True)                            # 扇出高的优先(真 kerberoast)
    print(f"用户账号 kerberoast 候选 {len(cands)} 条(扫 {len(rows)} 条 kerberoast;机器账号跨域已排除):")
    for fan, uid, req, fids in cands[:10]:
        print(f"  扇出={fan:<3} {uid[:16]} requester={req}  {fids}")

    tp = None
    for fan, uid, req, fids in cands[:5]:               # 前 5 高扇出跑研判,直到 TP
        result, report, picked = run_investigation(pl, uid, mode="recipe")
        v = result.verdict.verdict if result.verdict else None
        print(f"\n  研判 {uid[:16]}(requester={req}, 扇出={fan})→ verdict={v} path={result.path} decision={report.decision}")
        if v == "true_positive":
            tp = uid
            break
    if not tp:
        print("\n前 5 候选深度都没判 TP —— 贴上面各条 verdict,我看是深度判据保守还是这批确无真 kerberoast。")
        sys.exit(0)

    print(f"\n★深度判 TP:{tp[:20]} —— 处置台账:")
    for r in g.run_cypher(
        "MATCH (a:Alert {alert_uid:$u})-[:CONCLUDED]->(v:Verdict) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)-[:STEP]->(d:Disposition) "
        "RETURN p.status AS plan, collect({action:d.action,target:d.target,status:d.status}) AS steps", u=tp):
        print(f"  ResponsePlan.status = {r['plan']}   (★manual 应为 proposed=待处置)")
        steps = [s for s in r["steps"] if s.get("action")]
        print("  处置步骤:" + ("(无!判 TP 却没组处置,该查)" if not steps else ""))
        for s in steps:
            print(f"    - {s['action']} → {m(s['target'])}   [status={s['status']}]")
finally:
    pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: verify-attack $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
