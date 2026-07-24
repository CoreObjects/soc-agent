#!/usr/bin/env bash
# server2:诊断某告警为何 AUTO_FP —— dump 它的 findings + 跨域信任证据 + 命中的良性经验(指纹/规则/蒸自哪条)。
# 只读(forensics+consult,不写台账)。用法: bash scripts/dump-autofp.sh [alert_uid]
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
UID_ARG="${1:-8cb0e34cac59fa3a9c12cda0b8ec89716610f975b77dfb170342f52c079a66aa}"

mkdir -p feedback
FB="feedback/dump-autofp.out"
{
  echo "=== dump-autofp  $(date -u '+%F %H:%MZ' 2>/dev/null || true)  uid=${UID_ARG:0:16} ==="
  SOC_DUMP_UID="$UID_ARG" PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, re, sys, json
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, collect_forensics
from soc_agent.models import Alert
from soc_agent.experience.consult import consult
_IP = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
def m(s): return _IP.sub(lambda x: f"x.x.x.{x.group(4)}", str(s))
def j(o, n=400): return m(json.dumps(o, ensure_ascii=False, default=str))[:n]

uid = os.environ["SOC_DUMP_UID"]
pl = build_pipeline(Config.from_env(dotenv_path=".env"))
g = pl.graph
try:
    node = g.get_alert(uid)
    if node is None:
        print("图里无此 uid"); sys.exit(0)
    alert = Alert.from_node(node)
    print("rule_description:", alert.rule_description)
    print("raw:", j(alert.raw, 700), "\n")
    seed = g.seed(alert)
    print("seed(触发事件+实体):", j(seed, 900), "\n")
    skill = pl.router.route(alert, seed)
    print("路由 skill:", skill.name if skill else None, "\n")
    fx = collect_forensics(g, alert, seed, skill)
    print("=== findings(取证结果)===")
    for f in fx.findings:
        print("  -", f.finding_id, ":", j(f.attrs, 200))
    print("\n=== forensics 证据(★看有没有'跨域信任/TRUSTS')===")
    for k, v in (fx.context or {}).items():
        print(f"  [{k}] {j(v, 260)}")
    print("\n=== consult 决策 ===")
    rep = consult(skill.name if skill else None, fx.findings, pl.exp_store)
    print("decision:", rep.decision)
    print("benign_fp 命中:", [(e.fingerprint.get('finding_ids'), e.note) for e in rep.benign_fp_hits])
    print("threat_fp 命中:", [e.fingerprint.get('finding_ids') for e in rep.threat_fp_hits])
    print("threat_rule 命中:", [j(e.rule, 200) for e in rep.threat_rule_hits])
    ch = rep.chosen
    if ch:
        print("\n★被复用的经验(chosen):")
        print("  kind/verdict:", ch.kind, ch.verdict)
        print("  fingerprint(finding_ids):", ch.fingerprint.get("finding_ids"))
        print("  rule:", j(ch.rule, 300))
        print("  note:", ch.note)
        print("  蒸自告警 origin_case_id:", ch.origin_case_id)
        if ch.origin_case_id:
            on = g.get_alert(ch.origin_case_id)
            if on:
                oa = Alert.from_node(on)
                print("  ↳ 源告警 rule:", oa.rule_description)
                print("  ↳ 源告警 raw:", j(oa.raw, 400))
finally:
    pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: dump-autofp $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
