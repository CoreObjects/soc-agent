#!/usr/bin/env bash
# server2:诚实复用率 —— 按 rule_description 拆,量头部重复任务占比,算"去掉它之后"的真复用率/升级率。ferry。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/reuse-breakdown.sh
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"

mkdir -p feedback
FB="feedback/reuse-breakdown.out"
{
  echo "=== reuse-breakdown  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>&1
import os, sys
from collections import defaultdict
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
cfg = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)

rows = g.run_cypher(
    "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
    "RETURN a.rule_description AS rule, coalesce(c.path,v.path) AS path, "
    "  coalesce(c.method,'llm') AS method, count(*) AS n")
g.close()

total = sum(r["n"] for r in rows)
by_path = defaultdict(int); by_method = defaultdict(int)
rule_tot = defaultdict(int)
for r in rows:
    by_path[r["path"]] += r["n"]
    by_method[r["method"]] += r["n"]
    rule_tot[r["rule"] or "(空)"] += r["n"]

def rate(x): return f"{100*x/(total or 1):.1f}%"

print(f"总已研判 {total}")
print(f"按 path : S(浅层)={by_path.get('S',0)}  A(深度复用)={by_path.get('A',0)}  B(深度LLM)={by_path.get('B',0)}")
print(f"按 method: reuse(真复用)={by_method.get('reuse',0)}  llm(真调模型)={by_method.get('llm',0)}")
print()

top = sorted(rule_tot.items(), key=lambda kv: -kv[1])
print(f"规则种类共 {len(rule_tot)} 种。Top 12(按量):")
for rule, n in top[:12]:
    # 该规则的主要处置方式
    sub = [(r["path"], r["method"], r["n"]) for r in rows if (r["rule"] or "(空)") == rule]
    dom = max(sub, key=lambda x: x[2])
    print(f"  {n:6d} ({rate(n):>5})  {dom[0]}/{dom[1]:5}  {(rule or '')[:64]}")

# —— 去掉头部重复任务,看多样告警的真相 ——
def metrics(subrows):
    t = sum(r["n"] for r in subrows) or 1
    reuse = sum(r["n"] for r in subrows if r["method"] == "reuse")
    sh_llm = sum(r["n"] for r in subrows if r["method"] == "llm" and r["path"] == "S")
    deepB = sum(r["n"] for r in subrows if r["path"] == "B")
    return t, reuse, sh_llm, deepB

print()
top1_rule = top[0][0]
tail1 = [r for r in rows if (r["rule"] or "(空)") != top1_rule]
t, reuse, sh, deep = metrics(tail1)
print(f"★去掉 Top1「{(top1_rule or '')[:40]}」({top[0][1]} 条,占 {rate(top[0][1])})后 —— 剩 {t} 条多样告警:")
print(f"    真复用率={100*reuse/t:.1f}%   浅层LLM直判={100*sh/t:.1f}%   升级深度LLM={100*deep/t:.1f}%")

# 去掉所有"高频规则(单规则 >1000 条)"
big = {r for r, n in rule_tot.items() if n > 1000}
tail2 = [r for r in rows if (r["rule"] or "(空)") not in big]
t2, reuse2, sh2, deep2 = metrics(tail2)
print(f"★去掉所有高频规则(单规则>1000条,共 {len(big)} 种)后 —— 剩 {t2} 条'长尾'告警:")
print(f"    真复用率={100*reuse2/(t2 or 1):.1f}%   升级深度LLM={100*deep2/(t2 or 1):.1f}%")

print()
print("诚实结论:降噪覆盖率(path=S)被头部重复任务撑高;多样/长尾告警的真复用率才反映'越用越省'能力。")
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: reuse-breakdown" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB"
