#!/usr/bin/env bash
# server2:停 poller + 一类一类跑通 —— 每个已迁移 skill 取 1 条真样本【单线程】研判,验:
#   ①recipe 在真数据上产不产 findings ②能否完成(不超时)③沉淀经验(给后续复用)。ferry。
# 单线程=不抢模型,能真跑完;跑完再开轮询,同型告警就能复用而非挨个研判。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/prime-skills.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/prime-skills.out"
{
  echo "=== prime-skills  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "-- 停 poller(单线程跑不抢模型)--"
  pkill -9 -f "soc_agent.runtime" 2>/dev/null && echo "  已停" || echo "  本就没在跑"
  sleep 2
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation
from soc_agent.skills_runtime import SkillRegistry
cfg = Config.from_env(dotenv_path=".env")
pl = build_pipeline(cfg)
g = pl.graph
reg = SkillRegistry(cfg.skills_dir)

MIGRATED = ["lateral_movement", "dcsync", "adcs", "c2_beacon", "suspicious_outbound",
            "registry_persistence", "suspicious_process", "ingress_tool_transfer",
            "web_exploit", "webshell", "kerberoast", "lsass_dump"]

print("逐 skill 单线程跑通(1 条/类;findings>0=recipe 在真数据上工作,decision=沉淀/复用情况):")
for name in MIGRATED:
    try:
        sk = reg.by_name(name)
    except Exception as e:
        print(f"  {name:22} 注册表无此 skill:{str(e)[:60]}"); continue
    techs = list(getattr(sk, "technique_ids", []) or [])
    rows = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND coalesce(a.poller_skip,false)=false "
        "AND any(t IN coalesce(a.technique_ids,[]) WHERE t IN $techs) "
        "RETURN a.alert_uid AS uid ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT 1", techs=techs)
    if not rows:
        print(f"  {name:22} 无待研判样本(technique={techs})"); continue
    uid = rows[0]["uid"]
    t = time.time()
    try:
        result, report, picked = run_investigation(pl, uid, mode="recipe")
        dt = time.time() - t
        nf = len(getattr(result, "findings", None) or [])
        vd = result.verdict.verdict if (result and result.verdict) else None
        flag = "" if nf > 0 or result.path == "S" else "  ⚠findings=0(recipe 没产 finding?)"
        print(f"  {name:22} {uid[:12]} {dt:5.0f}s  path={result.path} verdict={vd} "
              f"findings={nf} decision={report.decision}{flag}")
    except Exception as e:
        print(f"  {name:22} {uid[:12]} ❌ {time.time()-t:5.0f}s  {type(e).__name__}: {str(e)[:120]}")
pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: prime-skills" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
