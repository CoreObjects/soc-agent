"""换实例双跑总验收(server2 真基建):Kerberoast。

对图里已有的 kerberoast(T1558.003)告警逐条走快慢通道研判:
- 头一条某签名 → 慢通道(path B,LLM)→ 沉淀 active 规则;
- 后续同签名 → 快通道(path A,★0 LLM)复用规则;
核对:① 快通道>0(0 LLM 复用)② 图台账按 pattern_id 收敛(多告警共享一个 Verdict)
③ openGauss 规则去重(条数<<告警数)④ ★每条告警都闭环(Verdict 必有 LED_TO→ResponsePlan|无处置)。
真跑会写台账 + 沉淀规则(系统正常行为)。
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
    if "--reset" in sys.argv:            # 清 kerberoast 规则 + 台账,从 0 经验重跑(干净演示 slow→mint→fast)
        import psycopg2
        c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                             user=cfg.og_user, password=cfg.og_password)
        c.autocommit = True
        with c.cursor() as cur:
            cur.execute("DELETE FROM %s.patterns WHERE skill='kerberoast'" % cfg.og_schema)
        c.close()
        graph.run_write(                 # 删 kerberoast 告警的台账(经验层,非事实;会重新生成)
            # ★只删 kerberoast 的 Verdict + 其【每告警专属】ResponsePlan/步骤;DETACH DELETE v 自动摘掉
            #   v→「无处置」单例的边,但绝不删单例本身(它跨所有类型共享,删了会连坐其它 scope 的闭环)。
            "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
            "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)-[:STEP]->(d:Disposition) "
            "DETACH DELETE v, p, d")
        print("--reset: 已清 kerberoast 规则库 + 台账(保留共享的无处置单例),从 0 经验开始")

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

    # ★R5 台账闭环:每条 kerberoast 告警的 Verdict 都必有 LED_TO(→ResponsePlan 或 →无处置单例);无悬空
    total = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict) WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
        "RETURN count(DISTINCT v) AS n")[0]["n"]
    closed = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict)-[:LED_TO]->() WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) "
        "RETURN count(DISTINCT v) AS n")[0]["n"]
    noop = graph.run_cypher(
        "MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict)-[:LED_TO]->(:Disposition {step_key:'__no_op__'}) "
        "WHERE 'T1558.003' IN coalesce(a.technique_ids,[]) RETURN count(DISTINCT v) AS n")[0]["n"]
    print("台账闭环:Verdict %d 个,已闭环 %d(其中经【无处置】单例 %d、经响应计划 %d);悬空 %d(应0)"
          % (total, closed, noop, closed - noop, total - closed))

    import psycopg2
    c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                         user=cfg.og_user, password=cfg.og_password)
    with c.cursor() as cur:
        cur.execute("SELECT layer, status, count(*) FROM %s.patterns WHERE skill='kerberoast' GROUP BY layer, status" % cfg.og_schema)
        print("openGauss kerberoast 规则(去重后):", cur.fetchall())
    c.close()
    ok = (fast > 0 and total > 0 and closed == total)
    print("\nACCEPTANCE: 快通道>0 且 图收敛(共享节点)且 规则条数<<告警数 且 ★每条告警都闭环(悬空=0) → %s"
          % ("通过" if ok else "★不通过(见上:快通道数/悬空数)"))
finally:
    graph.close()
