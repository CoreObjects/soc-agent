#!/usr/bin/env bash
# server2 重启后恢复服务:探依赖(Neo4j / openGauss / LLM)→ 全通就后台续跑 poller(幂等,接着写没写完的台账)
# → ferry 进度快照。★poller 以 CONCLUDED 作水位:重启后自动从"还没研判完的"续,不重判、不双写、无半截台账。
# 用法: cd ~/soc-agent && git fetch origin && git reset --hard origin/main && bash scripts/resume.sh
# 若提示 openGauss 不通(重启后 podman 容器常没起):sudo podman start opengauss  (或 restart),再重跑本脚本。
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "!! 缺 .env"; exit 1; }
PY=".venv312/bin/python"; [ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || { echo "!! 缺 venv —— 先 bash scripts/cascade-gate.sh"; exit 1; }

mkdir -p feedback logs
FB="feedback/resume.out"
{
  echo "=== resume 探依赖  $(date -u '+%F %H:%MZ' 2>/dev/null || true) ==="
  PYTHONUTF8=1 "$PY" - <<'PYEOF'
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
cfg = Config.from_env(dotenv_path=".env")
ok = True

# 1) Neo4j(台账主库,在靶场那台;server2 重启一般不影响它)
try:
    from soc_agent.graph.client import Neo4jGraph
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    bl = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                      "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n")[0]["n"]
    print(f"  [OK] Neo4j 连通;待研判积压 = {bl}")
    g.close()
except Exception as e:
    ok = False
    print(f"  [FAIL] Neo4j 不通:{str(e)[:160]}")

# 2) openGauss(第二类经验库;重启后 podman 容器常没起)
if cfg.og_enabled:
    try:
        from soc_agent.experience.opengauss import open_stores
        open_stores(cfg)
        print("  [OK] openGauss 连通(经验库持久 → 复用/越用越省有效)")
    except Exception as e:
        ok = False
        print(f"  [FAIL] openGauss 不通:{str(e)[:160]}")
        print("        → 多半是重启后 podman 容器没起。跑:sudo podman start opengauss  (或 restart),再重跑本脚本")
else:
    print("  [WARN] OG_HOST 未配 → 经验库降级内存(不持久、复用失效);建议配上再跑")

# 3) LLM 端点(qwen 网关/vLLM;models.list 快速探活,不做慢生成)
try:
    import httpx
    from openai import OpenAI
    c = OpenAI(base_url=cfg.llm_api_base, api_key=cfg.llm_api_key or "EMPTY",
               max_retries=0, http_client=httpx.Client(trust_env=False, timeout=15))
    ids = [m.id for m in c.models.list().data]
    print(f"  [OK] LLM 端点连通({cfg.llm_api_base});模型 {ids[:3]}")
except Exception as e:
    ok = False
    print(f"  [FAIL] LLM 端点不通({cfg.llm_api_base}):{str(e)[:160]}")
    print("        → server2 本地 vLLM 需领导重启模型服务;若走网关,确认网关在跑")

sys.exit(0 if ok else 1)
PYEOF
  PROBE=$?
  echo
  if [ $PROBE -ne 0 ]; then
    echo "!! 依赖未就绪 —— 按上面提示修好再重跑本脚本(未启动 poller)。"
  elif pgrep -f "soc_agent.runtime" >/dev/null 2>&1; then
    echo "ℹ️ poller 已在跑(pgrep -f soc_agent.runtime 命中),不重复启动。"
    echo "   要重启续跑:pkill -f soc_agent.runtime 后再跑本脚本。"
  else
    echo "# 依赖全通 → 后台续跑 poller(幂等,接着写没写完的台账)"
    bash scripts/poller-full.sh || echo "!! poller-full.sh 启动异常,见上"
  fi

  echo
  echo "—— 台账进度快照 ——"
  PYTHONUTF8=1 "$PY" - <<'PYEOF' 2>/dev/null || echo "  (进度查询略过)"
import os, sys
sys.path.insert(0, os.getcwd())
from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph
cfg = Config.from_env(dotenv_path=".env")
g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
tot = g.run_cypher("MATCH (a:Alert)-[:CONCLUDED]->() RETURN count(DISTINCT a) AS n")[0]["n"]
bl = g.run_cypher("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
                  "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n")[0]["n"]
ps = g.run_cypher("MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true RETURN count(a) AS n")[0]["n"]
g.close()
d = tot + bl
print(f"  已研判 {tot} / 积压 {bl} / 毒告警 {ps}  —— 完成 {100 * tot / (d or 1):.1f}%")
PYEOF
  echo "=== done ==="
} 2>&1 | tee "$FB"

# ferry
git config user.email >/dev/null 2>&1 || git config user.email "soc-agent@server2"
git config user.name  >/dev/null 2>&1 || git config user.name  "soc-agent"
git add "$FB" >/dev/null 2>&1 || true
git commit -q -m "feedback: resume $(date -u '+%m-%d %H:%MZ' 2>/dev/null || echo)" 2>&1 | tail -2 || true
git push origin HEAD >/dev/null 2>&1 \
  || { git pull --rebase -q origin main >/dev/null 2>&1 && git push origin HEAD 2>&1 | tail -2; }
echo "✅ 已推 $FB(进度也可随时 bash scripts/ledger-stats.sh)"
