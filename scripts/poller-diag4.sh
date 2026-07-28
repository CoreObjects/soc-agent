#!/usr/bin/env bash
# server2:量"每条投研判到底多贵" —— openGauss 单次耗时 + 单独跑3条投研判计时(总时/调模型次数/path)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/poller-diag4.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/poller-diag4.out"
{
  echo "=== poller-diag4  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  echo "★ 注:此脚本会单线程跑几条真投研判(与在跑的 poller 抢模型),计时含并发争用,属实况。"
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation
cfg = Config.from_env(dotenv_path=".env")
pl = build_pipeline(cfg)
g = pl.graph

# ① openGauss 单次读耗时(现在快不快)
try:
    t = time.time()
    n = len(pl.exp_store.active_for_skill("kerberoast"))
    print(f"① openGauss 读一次 active_for_skill: {time.time()-t:.2f}s (拿到 {n} 条经验)  <—— >1s 就是 og 慢")
except Exception as e:
    print(f"① openGauss 读失败: {type(e).__name__}: {str(e)[:120]}")

# ② 单独跑 3 条 backlog 投研判,各计时 + 数调模型次数
rows = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                    "AND coalesce(a.poller_skip,false)=false "
                    "RETURN a.alert_uid AS uid ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT 3")
print(f"② 单独跑 {len(rows)} 条投研判计时:")
for r in rows:
    uid = r["uid"]
    t = time.time()
    try:
        result, report, picked = run_investigation(pl, uid, mode="recipe")
        dt = time.time() - t
        tr = result.trace or []
        llm = sum(1 for s in tr if s.get("tool") == "llm_input")
        cyp = sum(1 for s in tr if s.get("tool") == "run_cypher")
        vd = result.verdict.verdict if result.verdict else None
        print(f"   {uid[:16]}  用时 {dt:5.1f}s  path={result.path} verdict={vd}  "
              f"调模型 {llm} 次 / cypher {cyp} 次  → 每次模型 ~{dt/max(llm,1):.1f}s")
    except Exception as e:
        print(f"   {uid[:16]}  ❌ {time.time()-t:.1f}s  {type(e).__name__}: {str(e)[:120]}")
pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: poller-diag4" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
