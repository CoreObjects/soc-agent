#!/usr/bin/env bash
# server2:放宽 LLM 超时到 400s(模型深度研判单线程要 200-320s)+ 连跑 5 条 robb.stark 登录(最大头 4373 条)。
# 看:①判 FP 还是 suspicious(FP 才沉淀→可复用;suspicious 不沉淀)②第1条沉淀后,第2条起能否 AUTO_FP 复用。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/prime-robbstark.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

# 放宽 .env 的 LLM 超时(下次 poller 也用)
if grep -q '^LLM_TIMEOUT=' .env; then sed -i 's/^LLM_TIMEOUT=.*/LLM_TIMEOUT=400/' .env; else echo "LLM_TIMEOUT=400" >> .env; fi

mkdir -p feedback
FB="feedback/prime-robbstark.out"
{
  echo "=== prime-robbstark  $(date -u '+%F %H:%MZ' 2>/dev/null || true)  LLM_TIMEOUT=400 ==="
  pkill -9 -f "soc_agent.runtime" 2>/dev/null && echo "-- 停了在跑的 poller --" || echo "-- poller 本没跑 --"
  sleep 2
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation
cfg = Config.from_env(dotenv_path=".env")
print("  LLM_TIMEOUT =", cfg.llm_timeout)
pl = build_pipeline(cfg)
g = pl.graph
rows = g.run_cypher(
    "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND coalesce(a.poller_skip,false)=false "
    "AND a.rule_description CONTAINS 'robb.stark' AND toLower(a.rule_description) CONTAINS 'logon type 3' "
    "RETURN a.alert_uid AS uid ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT 5")
print(f"抓到 {len(rows)} 条 robb.stark 登录,逐条单线程研判(看沉淀→复用):")
for i, r in enumerate(rows, 1):
    uid = r["uid"]; t = time.time()
    try:
        result, report, picked = run_investigation(pl, uid, mode="recipe")
        dt = time.time() - t
        vd = result.verdict.verdict if (result and result.verdict) else None
        nf = len(getattr(result, "findings", None) or [])
        note = ""
        if report.decision == "FALLTHROUGH" and vd in ("false_positive", "benign", "true_positive"):
            note = "  → 应已沉淀经验"
        elif report.decision in ("AUTO_FP", "AUTO_TP"):
            note = "  → ★复用命中(零 LLM)!"
        elif vd == "suspicious":
            note = "  → suspicious 不沉淀(复用解锁不了这条)"
        print(f"  [{i}] {uid[:12]} {dt:5.0f}s path={result.path} verdict={vd} findings={nf} decision={report.decision}{note}")
    except Exception as e:
        print(f"  [{i}] {uid[:12]} ❌ {time.time()-t:5.0f}s {type(e).__name__}: {str(e)[:120]}")
pl.close()
print("\n判读:若第1条 FALLTHROUGH+FP 沉淀、后面几条变 AUTO_FP → 4373 大户解锁,可低并发开轮询。")
print("     若全 suspicious → LLM 对横向登录太保守,需调提示词/让 suspicious 也沉淀(另议)。")
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: prime-robbstark" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
