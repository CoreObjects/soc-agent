#!/usr/bin/env bash
# server2:挖 robb.stark 网络登录为啥每条都升级不复用 —— 3 条各自 台账verdict/取证findings/指纹canon/consult决策,
# 对比指纹是否一样,并对库里每条 benign 经验算命中分(score<0.8 就是没复用的原因)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/dig-robbstark.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/dig-robbstark.out"
{
  echo "=== dig-robbstark  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, json
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, collect_forensics
from soc_agent.models import Alert
from soc_agent.experience.fingerprint import build_fingerprint
from soc_agent.experience.consult import consult
from soc_agent.experience.matching import fingerprint_hit

cfg = Config.from_env(dotenv_path=".env")
pl = build_pipeline(cfg)
g = pl.graph

rows = g.run_cypher(
    "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
    "WHERE a.rule_description CONTAINS 'robb.stark' AND toLower(a.rule_description) CONTAINS 'logon type 3' "
    "RETURN a.alert_uid AS uid, v.verdict AS verdict, coalesce(c.path,v.path) AS path, "
    "  a.rule_description AS rule ORDER BY coalesce(a.arrival_ms,0) ASC LIMIT 3")
print(f"抓到 {len(rows)} 条 robb.stark 登录\n")

fps = []
skills = set()
for r in rows:
    uid = r["uid"]
    node = g.get_alert(uid); alert = Alert.from_node(node)
    seed = g.seed(alert)
    skill = pl.router.route(alert, seed)
    sname = skill.name if skill else None
    skills.add(sname)
    fo = collect_forensics(g, alert, seed, skill)
    fp = build_fingerprint(fo.findings, fo.bindings)
    fps.append(fp)
    rep = consult(sname, fo.findings, pl.exp_store)
    print(f"── {uid[:16]}  台账verdict={r['verdict']} path={r['path']}")
    print(f"   规则: {r['rule'][:70]}")
    print(f"   路由 skill = {sname}")
    print(f"   bindings(角色→值) = {json.dumps(fo.bindings, ensure_ascii=False, default=str)[:200]}")
    print(f"   findings 类型 = {fp['finding_ids']}")
    print(f"   指纹 canon = {json.dumps(fp['canon'], ensure_ascii=False, default=str)[:400]}")
    print(f"   consult 决策 = {rep.decision}  (benign命中 {len(rep.benign_fp_hits)} / 威胁指纹 {len(rep.threat_fp_hits)} / 威胁规则 {len(rep.threat_rule_hits)})")
    print()

# 3 条指纹是否一样
if len(fps) >= 2:
    same = all(f["finding_ids"] == fps[0]["finding_ids"] and f["canon"] == fps[0]["canon"] for f in fps)
    print(f"★这几条指纹是否完全一致: {'是(一样却不复用=没沉淀经验/被威胁否决)' if same else '否(canon 里有会变的字段→每条长得不一样→天然不复用)'}")
    if not same:
        for i, f in enumerate(fps):
            print(f"   [{i}] canon = {json.dumps(f['canon'], ensure_ascii=False, default=str)[:300]}")
print()

# 库里这个 skill 有哪些经验,对最后一条算命中分
print("库里该 skill 的经验:")
for sn in skills:
    exps = pl.exp_store.active_for_skill(sn)
    print(f"  skill={sn}: {len(exps)} 条")
    for e in exps:
        print(f"    - kind={e.kind} verdict={e.verdict} finding_ids={(e.fingerprint or {}).get('finding_ids')} note={e.note}")
        if rows:
            # 对第一条 alert 的 findings 算这条经验的命中分
            node = g.get_alert(rows[0]["uid"]); alert = Alert.from_node(node)
            fo = collect_forensics(g, alert, g.seed(alert), pl.router.route(alert, g.seed(alert)))
            hit, score, matched = fingerprint_hit(e, fo.findings)
            print(f"      对 robb.stark 首条:命中={hit} score={score:.2f} matched={matched}  (benign阈值0.8/威胁1.0)")
pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: dig-robbstark" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
