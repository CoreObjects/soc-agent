#!/usr/bin/env bash
# server2:纯取证探针 —— 精确测 12 个已迁移 recipe 本身。强制指定 skill、只调 collect()、【零 LLM】,
# 绕开 router/浅层签名/经验/concluded(prime-skills 走完整 run_investigation 会被这些挡在 recipe 之前)。
# 每类取任一真告警(判没判过都行),打 findings(id[极性]+决定性attrs)/bindings/blind_spots。快(只查图)。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/probe-recipes.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/probe-recipes.out"
{
  echo "=== probe-recipes  $(date -u '+%F %H:%MZ' 2>/dev/null || true)  【纯取证·零LLM】 ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1
import os, sys, time, json
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline, collect_forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry
cfg = Config.from_env(dotenv_path=".env")
pl = build_pipeline(cfg)
g = pl.graph
reg = SkillRegistry(cfg.skills_dir)

MIGRATED = ["lateral_movement", "dcsync", "adcs", "c2_beacon", "suspicious_outbound",
            "registry_persistence", "suspicious_process", "ingress_tool_transfer",
            "web_exploit", "webshell", "kerberoast", "lsass_dump"]

def _fid(f):  return getattr(f, "finding_id", None) or (f.get("finding_id") if isinstance(f, dict) else None) or "?"
def _pol(f):  return str(getattr(f, "polarity", None) or (f.get("polarity") if isinstance(f, dict) else None) or "?")[:1]
def _attrs(f):
    a = getattr(f, "attrs", None)
    if a is None and isinstance(f, dict): a = f.get("attrs")
    return a or {}

def fmt(fds):
    out = []
    for f in fds:
        a = _attrs(f)
        av = " ".join(f"{k}={v}" for k, v in list(a.items())[:4]) if a else ""
        out.append(f"      {_fid(f)}[{_pol(f)}] {{{av}}}")
    return "\n".join(out)

print("逐 recipe 纯取证(强制 skill、直调 collect、零 LLM;findings>0=recipe 在真数据上工作):\n")
for name in MIGRATED:
    try:
        sk = reg.by_name(name)
    except Exception as e:
        print(f"■ {name}: 注册表无此 skill:{str(e)[:60]}\n"); continue
    if sk is None or sk.recipe is None:
        print(f"■ {name}: 无 recipe(agent skill)\n"); continue
    techs = list(getattr(sk, "technique_ids", []) or [])
    rows = g.run_cypher(
        "MATCH (a:Alert) WHERE any(t IN coalesce(a.technique_ids,[]) WHERE t IN $techs) "
        "RETURN a.alert_uid AS uid, coalesce(a.rule_description,'') AS rd "
        "ORDER BY coalesce(a.arrival_ms,0) DESC LIMIT 5", techs=techs)
    if not rows:
        print(f"■ {name}: 库里无此类告警(technique={techs})\n"); continue
    picked = None
    for r in rows:
        uid = r["uid"]
        try:
            node = g.get_alert(uid)
            alert = Alert.from_node(node)
            seed = g.seed(alert)
            fx = collect_forensics(g, alert, seed, sk)
            fds = list(getattr(fx, "findings", None) or [])
            picked = (uid, r["rd"], fx, fds)
            if fds:  # 拿到有产出的就停
                break
        except Exception as e:
            picked = (uid, r["rd"], None, None)
            print(f"■ {name}: {uid[:12]} collect 崩 {type(e).__name__}: {str(e)[:120]}\n")
            picked = None
            continue
    if picked is None:
        print(f"■ {name}: 5 条样本 collect 全崩\n"); continue
    uid, rd, fx, fds = picked
    binds = dict(getattr(fx, "bindings", None) or {})
    bs = getattr(fx, "blind_spots", None) or ""
    flag = "" if fds else "  ⚠findings=0(recipe 在这条真告警上没产 finding —— 要查!)"
    print(f"■ {name}: {uid[:12]}  findings={len(fds)}{flag}")
    print(f"    rule: {rd[:90]}")
    if fds: print(fmt(fds))
    if binds: print(f"    bindings: {json.dumps(binds, ensure_ascii=False)[:200]}")
    if bs: print(f"    blind_spots: {str(bs)[:120]}")
    print()
pl.close()
print("判读:findings>0 且 id/极性/attrs 合理 = 该 recipe 迁移成功、真数据上可用。")
print("      findings=0 = recipe 在真样本上取不到证(cypher 匹配不上/字段名对不上),需单独查那类。")
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: probe-recipes" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
