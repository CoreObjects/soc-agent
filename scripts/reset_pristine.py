"""全量对称重置 → 最初态(只有事实、零研判)。图台账 与 openGauss 规则【一起清】,保持两边同步。

清:
- 图(Neo4j):所有 :Verdict / :Disposition 节点 + 其边(CONCLUDED/LED_TO/ON)—— 研判/处置台账(经验层)。
  ★事实(Alert/Event/账号/主机… + ingest 的所有边)一律不动。
- openGauss:app.patterns 全清 —— 攻击模式规则(可复用经验,研发阶段可重建)。

用途:研发阶段每次小测收尾、或这台(ephemeral)下线前跑一次;避免"图脏了一堆已研判告警、openGauss 经验却没了"两边对不上。
"""
import os
import sys

_ROOT = os.path.expanduser("~/soc-agent")
sys.path.insert(0, _ROOT)

from soc_agent.config import Config
from soc_agent.graph.client import Neo4jGraph

cfg = Config.from_env(dotenv_path=os.path.join(_ROOT, ".env"))
print("neo4j=%s  og=%s db=%s enabled=%s" % (cfg.neo4j_uri, cfg.og_host, cfg.og_db, cfg.og_enabled))

# ---- 图:清研判台账,保留事实 ----
graph = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
try:
    n_before = graph.run_cypher("MATCH (n) WHERE n:Verdict OR n:Disposition RETURN count(n) AS n")[0]["n"]
    graph.run_write("MATCH (n) WHERE n:Verdict OR n:Disposition DETACH DELETE n")   # DETACH 连带删 CONCLUDED/LED_TO/ON
    n_after = graph.run_cypher("MATCH (n) WHERE n:Verdict OR n:Disposition RETURN count(n) AS n")[0]["n"]
    alerts = graph.run_cypher("MATCH (a:Alert) RETURN count(a) AS n")[0]["n"]
    conc = graph.run_cypher("MATCH ()-[c:CONCLUDED]->() RETURN count(c) AS n")[0]["n"]
    print("图台账:Verdict+Disposition %d → %d;残留 CONCLUDED 边=%d(应0);事实 Alert=%d(保留)"
          % (n_before, n_after, conc, alerts))
finally:
    graph.close()

# ---- openGauss:清规则 ----
if cfg.og_enabled:
    import psycopg2
    c = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_db,
                         user=cfg.og_user, password=cfg.og_password)
    c.autocommit = True
    tbl = "%s.patterns" % cfg.og_schema
    with c.cursor() as cur:
        try:
            cur.execute("SELECT count(*) FROM " + tbl); r0 = cur.fetchone()[0]
            cur.execute("DELETE FROM " + tbl)
            cur.execute("SELECT count(*) FROM " + tbl); r1 = cur.fetchone()[0]
            print("openGauss 规则:%d → %d" % (r0, r1))
        except psycopg2.errors.UndefinedTable:
            print("openGauss:%s 尚不存在 → 本就无规则" % tbl)
    c.close()
else:
    print("openGauss 未启用(内存fake)→ 跳过(重启进程即空)")

print("PRISTINE OK:图台账 + openGauss 规则已双清,恢复'只有事实、零研判'最初态,两边同步")
