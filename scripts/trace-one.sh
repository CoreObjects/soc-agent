#!/usr/bin/env bash
# server2:把一条深度研判的全过程录下来 —— 每次 LLM 调用的次数/耗时/prompt大小 + 逐步 trace。
# 看到底调几次、为啥慢(1次慢=prompt太大/生成慢;多次=agent 多轮循环)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/trace-one.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
# 放宽超时,别让 trace 中途被砍(看完整调用链)
if grep -q '^LLM_TIMEOUT=' .env; then sed -i 's/^LLM_TIMEOUT=.*/LLM_TIMEOUT=600/' .env; else echo "LLM_TIMEOUT=600" >> .env; fi

mkdir -p feedback
FB="feedback/trace-one.out"
{
  echo "=== trace-one  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  pkill -9 -f "soc_agent.runtime" 2>/dev/null && echo "-- 停了 poller --" || echo "-- poller 本没跑 --"
  sleep 2
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, time
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, run_investigation, render_trace
cfg = Config.from_env(dotenv_path=".env")
print("  LLM_TIMEOUT =", cfg.llm_timeout, " 端点 =", cfg.llm_api_base, " 模型 =", cfg.llm_model)
pl = build_pipeline(cfg)
g = pl.graph
# 挑一条会走深度的 robb.stark 登录;没有就退而求其次任一横向/kerberoast
rows = g.run_cypher(
    "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND coalesce(a.poller_skip,false)=false "
    "AND a.rule_description CONTAINS 'robb.stark' AND toLower(a.rule_description) CONTAINS 'logon type 3' "
    "RETURN a.alert_uid AS uid LIMIT 1")
if not rows:
    rows = g.run_cypher(
        "MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() AND coalesce(a.poller_skip,false)=false "
        "AND any(t IN coalesce(a.technique_ids,[]) WHERE t IN ['T1021.001','T1558.003','T1003.006']) "
        "RETURN a.alert_uid AS uid LIMIT 1")
if not rows:
    print("  无合适样本"); pl.close(); sys.exit(0)
uid = rows[0]["uid"]
print("研判样本:", uid[:16], "\n")

# 包裹 LLM.chat 计时(数每次调用)
calls = []
_orig = pl.llm.chat
def _timed(messages, tools=None, tool_choice=None):
    t = time.time()
    r = _orig(messages, tools=tools, tool_choice=tool_choice)
    dt = time.time() - t
    pc = sum(len(str(m.get("content") or "")) for m in messages)
    calls.append((dt, len(messages), pc, len(getattr(r, "tool_calls", None) or []),
                  len(getattr(r, "content", "") or "")))
    return r
pl.llm.chat = _timed

t0 = time.time()
try:
    result, report, picked = run_investigation(pl, uid, mode="recipe")
    tot = time.time() - t0
    llm_s = sum(c[0] for c in calls)
    vd = result.verdict.verdict if (result and result.verdict) else None
    print(f"总用时 {tot:.1f}s  path={result.path} verdict={vd} decision={report.decision} picked={picked}")
    print(f"LLM 调用 {len(calls)} 次,合计 {llm_s:.1f}s;非 LLM(取证/图查/组处置)约 {tot-llm_s:.1f}s\n")
    print("每次 LLM 调用:")
    for i, (dt, nm, pc, ntc, cl) in enumerate(calls, 1):
        print(f"  call#{i:2}: {dt:6.1f}s  上文{nm}条/{pc}字符  →  tool_calls={ntc} content={cl}字符")
    print("\n-- 逐步 trace(render_trace)--")
    print(render_trace(result))
except Exception as e:
    import traceback
    tot = time.time() - t0
    print(f"研判崩(总 {tot:.0f}s,已调 LLM {len(calls)} 次):")
    print(traceback.format_exc()[-1000:])
    for i, (dt, nm, pc, ntc, cl) in enumerate(calls, 1):
        print(f"  call#{i:2}: {dt:6.1f}s  上文{nm}条/{pc}字符 → tool_calls={ntc} content={cl}字符")
pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: trace-one" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
