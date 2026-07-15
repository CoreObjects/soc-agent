"""P3' 首刀总验收(server2 真基建):Kerberoast 换实例双跑。

对图里已有的 kerberoast(T1558.003)告警逐条走快慢通道研判:
- 头一条某判别特征 → 慢通道(path B,LLM)→ 生成 active 规则;
- 后续同判别特征 → 快通道(path A,★0 LLM)复用规则;
核对:① 图台账按 pattern_id 收敛(多告警共享一个 Verdict 节点)② openGauss 规则去重(条数 << 告警数)。
真跑会写台账 + 生成规则(这就是系统的正常行为)。
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.cli import build_orchestrator, run_investigation

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
print("og_enabled=%s neo4j=%s" % (cfg.og_enabled, cfg.neo4j_uri))
graph, orch, repo = build_orchestrator(cfg)
try:
    rows = graph.run_cypher(
        "MATCH (a:Alert) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
        "RETURN a.alert_uid AS uid, a.rule_description AS d ORDER BY a.arrival_ms DESC LIMIT 8")
    print("kerberoast 告警取样:", len(rows))
    if not rows:
        print("!! 图里没有 T1558.003 告警,先在靶场跑 kerberoast 良性/攻击产告警"); sys.exit(0)

    fast = slow = 0
    for i, r in enumerate(rows, 1):
        res = run_investigation(graph, orch, r["uid"])
        v = res.verdict
        fast += (res.path == "A"); slow += (res.path == "B")
        print("[%d] path=%s verdict=%s lean=%s pattern=%s uid=%s"
              % (i, res.path, v.verdict, v.lean, (v.pattern or "-")[:12], r["uid"][:14]))

    print("\n=== 汇总 ===")
    print("快通道(0 LLM) %d 条 / 慢通道 %d 条" % (fast, slow))

    conv = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
        "AND v.pattern_id IS NOT NULL RETURN v.pattern_id AS pid, count(DISTINCT a) AS alerts ORDER BY alerts DESC")
    print("图台账收敛(pattern_id → 共享该结论的告警数):", [(c["pid"][:12], c["alerts"]) for c in conv])

    import psycopg2
    c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                         user=cfg.og_user, password=cfg.og_password)
    with c.cursor() as cur:
        cur.execute("SELECT layer, status, count(*) FROM %s.patterns WHERE skill='kerberoast' GROUP BY layer, status" % cfg.og_schema)
        print("openGauss kerberoast 规则(去重后):", cur.fetchall())
    c.close()
    print("\nACCEPTANCE: 换实例双跑完成 —— 快通道>0 且 图收敛(共享节点)且 规则条数<<告警数 = 通过")
finally:
    graph.close()
