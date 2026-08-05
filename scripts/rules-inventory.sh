#!/usr/bin/env bash
# server2:导出"沉淀的规则"总览(给领导汇报)——经验库规则清单 + 复用贡献。只读。
# 规则数 / 按 kind×verdict(误报白指纹·威胁红指纹·威胁DSL规则)/ 按攻击手法 / 复用命中 / 时间跨度 / 样例
#   + 经验复用对研判的贡献(path=A 占比)。结果 ferry 回 feedback,交给 Claude 排版成汇报页。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/rules-inventory.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/rules-inventory.out"
{
  echo "=== rules-inventory  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 SOC_CASCADE_ENABLED=1 "$PY" - <<'PYEOF'
import os, sys, json, collections
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.cli import build_pipeline
pl = build_pipeline(Config.from_env(dotenv_path=".env"))
try:
    exps = pl.exp_store.all()
    print(f"沉淀规则总数: {len(exps)}")
    if not exps:
        print("(经验库为空 —— 可能连的是 InMemory / 未蒸馏;检查 .env 的 openGauss 配置)")

    byk = collections.Counter((e.kind, e.verdict) for e in exps)
    print("\n按 kind × verdict(误报白指纹 / 威胁红指纹 / 威胁DSL规则):")
    for (k, v), n in sorted(byk.items(), key=lambda x: -x[1]):
        print(f"  {str(k):16} {str(v):16} {n}")

    print("\n按 skill(攻击手法覆盖):")
    for sk, n in collections.Counter(e.skill for e in exps).most_common():
        print(f"  {str(sk):26} {n}")

    tot_hit = sum(e.hit_count for e in exps)
    tot_ovr = sum(e.override_count for e in exps)
    active = sum(1 for e in exps if e.status == "active")
    print(f"\n复用:规则总命中(hit_count)={tot_hit}  ·  被人工纠正(override)={tot_ovr}  ·  active={active}/{len(exps)}")

    print("\nTop 复用规则(hit_count 降序 ≤12):")
    for e in sorted(exps, key=lambda e: -e.hit_count)[:12]:
        fids = (e.fingerprint or {}).get("finding_ids")
        print(f"  hit={e.hit_count:6} {str(e.kind):14}/{str(e.verdict):14} skill={e.skill:20} fids={fids} note={(e.note or '')[:50]}")

    cas = [e.created_at for e in exps if e.created_at]
    if cas:
        print(f"\n沉淀时间跨度: {min(cas)}  →  {max(cas)}")

    print("\n样例(各 kind 抽 1 条,看规则长啥样):")
    seen = set()
    for e in exps:
        if e.kind in seen:
            continue
        seen.add(e.kind)
        print(f"  [{e.kind}/{e.verdict}] skill={e.skill}")
        print(f"    fingerprint = {json.dumps(e.fingerprint, ensure_ascii=False)[:320]}")
        if e.rule:
            print(f"    rule(DSL)   = {json.dumps(e.rule, ensure_ascii=False)[:320]}")
        print(f"    note={e.note}  hit={e.hit_count}")

    g = pl.graph
    print("\n经验复用对研判的贡献(S=浅层终局 / A=经验复用 / B=深度LLM):")
    rows = g.run_cypher("MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
                        "RETURN coalesce(c.path,v.path) AS path, count(*) AS n ORDER BY n DESC")
    tot = sum(r["n"] for r in rows) or 1
    for r in rows:
        print(f"  path={str(r['path']):3} {r['n']:8}  ({100.0*r['n']/tot:.1f}%)")
    a = sum(r["n"] for r in rows if r["path"] == "A")
    print(f"  → 经验规则直接复用完成的研判占比 = {100.0*a/tot:.1f}%(其余才落深度 LLM)")
finally:
    pl.close()
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: rules-inventory $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
