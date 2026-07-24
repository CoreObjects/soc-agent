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
  SOC_VERIFY_UID="${1:-}" PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation
pl = build_pipeline(Config.from_env(dotenv_path=".env"))
g = pl.graph
# 攻击类技战术:逐条走 poller 同款研判(run_investigation, cascade on),直到深度判出一个 TP;预算 8 条。
TECHS = ["T1003.006", "T1649", "T1558.003", "T1003.001"]   # dcsync / ADCS-ESC / kerberoast / lsass-dump
BUDGET = 8
try:
    tp_uid = None
    target = os.environ.get("SOC_VERIFY_UID") or ""
    if target.strip():                       # 指定 uid:只研判这一条(拿已知真攻击验)
        uid = target.strip()
        result, report, picked = run_investigation(pl, uid, mode="recipe")
        v = result.verdict.verdict if result.verdict else None
        print(f"  [指定] {uid[:20]} → verdict={v}  path={result.path}  decision={report.decision}")
        if v == "true_positive":
            tp_uid = uid
        else:
            print(f"\n指定的 {uid[:16]} 深度判成 {v}(非 TP)—— 若你确信它是真攻击=深度召回该查。")
            sys.exit(0)
    for t in ([] if target.strip() else TECHS):
        rows = g.run_cypher("MATCH (a:Alert) WHERE $t IN coalesce(a.technique_ids,[]) "
                            "AND NOT (a)-[:CONCLUDED]->() RETURN a.alert_uid AS uid LIMIT 4", t=t)
        for r in rows:
            if BUDGET <= 0:
                break
            BUDGET -= 1
            uid = r["uid"]
            result, report, picked = run_investigation(pl, uid, mode="recipe")
            v = result.verdict.verdict if result.verdict else None
            print(f"  [{t:11}] {uid[:16]} → verdict={v}  path={result.path}")
            if v == "true_positive":
                tp_uid = uid
                break
        if tp_uid or BUDGET <= 0:
            break

    if not tp_uid:
        print("\n预算内没碰到深度判 TP 的攻击告警(这批多为良性/存疑)。处置组装另由 e2e-full 验过;"
              "或指定红队真实攻击 uid 再验。")
        sys.exit(0)

    print(f"\n★深度判 TP:{tp_uid[:20]} —— 查其处置台账:")
    dl = g.run_cypher(
        "MATCH (a:Alert {alert_uid:$u})-[:CONCLUDED]->(v:Verdict) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)-[:STEP]->(d:Disposition) "
        "RETURN p.status AS plan, "
        "collect({action:d.action, target:d.target, status:d.status}) AS steps", u=tp_uid)
    for r in dl:
        print(f"ResponsePlan.status = {r['plan']}   (★manual 应为 proposed=待处置)")
        steps = [s for s in r["steps"] if s.get("action")]
        print("处置步骤:" + ("(无 —— 判 TP 却无处置=组处置没触发,该查)" if not steps else ""))
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
