#!/usr/bin/env bash
# server2:研判一条未研判告警(cascade on),崩了就打**完整 traceback**,定位浅层 QwenClient 那条路的错。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/debug-one.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/debug-one.out"
{
  echo "=== debug-one  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, sys, traceback
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation
pl = build_pipeline(Config.from_env(dotenv_path=".env"))
g = pl.graph
print("pl.llm =", type(pl.llm).__name__, " cascade_enabled =", getattr(pl, "cascade_enabled", None))
try:
    rows = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                        "AND coalesce(a.poller_skip,false)=false RETURN a.alert_uid AS uid LIMIT 1")
    if not rows:
        print("无未研判告警(全清了?)"); sys.exit(0)
    uid = rows[0]["uid"]
    print("研判", uid[:16], "…\n")
    # 单独先探一下浅层 shallow_triage(直接调,和 poller 同款)
    try:
        from soc_agent.cascade.run import shallow_triage
        from soc_agent.models import Alert
        alert = Alert.from_node(g.get_alert(uid))
        sh = shallow_triage(pl.llm, alert)
        print("shallow_triage OK →", sh, "\n")
    except Exception:
        print("!! shallow_triage 崩:")
        traceback.print_exc()
        print()
    # 再跑完整 run_investigation
    try:
        result, report, picked = run_investigation(pl, uid, mode="recipe")
        print("run_investigation OK →", (result.verdict.verdict if result.verdict else None),
              "path=", result.path, "decision=", report.decision)
    except Exception:
        print("!! run_investigation 崩:")
        traceback.print_exc()
finally:
    pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: debug-one $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
