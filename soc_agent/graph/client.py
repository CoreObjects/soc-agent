"""Neo4j 图客户端:只读取事实 + seed(骨架保底)+ 写回经验层。

读写分权:
  run_cypher  走 execute_read(READ 事务)→ 即便守卫漏了,写也被库直接拒(第二道保证)。
  write_result 走 execute_write,只写经验层(Verdict/Disposition)。
neo4j 惰性导入(方法内),故 build_write_statements 等纯逻辑本机可测、不需装 neo4j。
"""
__all__ = ["Neo4jGraph", "build_write_statements"]

# 写回语句(纯逻辑,可单测);ON→实体边留到 P5 处置层(需精确目标解析),P1 先把 target 存属性。
_VERDICT_CYPHER = (
    "MATCH (a:Alert {alert_uid:$alert_uid}) "
    "MERGE (a)-[:CONCLUDED]->(v:Verdict {verdict_id:$vid}) "
    "SET v += $props "
    "RETURN v.verdict_id AS id"
)
_DISPOSITION_CYPHER = (
    "MATCH (a:Alert {alert_uid:$alert_uid})-[:CONCLUDED]->(v:Verdict {verdict_id:$vid}) "
    "MERGE (v)-[:LED_TO]->(d:Disposition {disposition_id:$props.disposition_id}) "
    "SET d += $props "
    "RETURN d.disposition_id AS id"
)


def build_write_statements(alert_uid, result):
    """研判结果 → [(cypher, params)]。无 verdict → []。"""
    if result is None or result.verdict is None:
        return []
    stmts = [(_VERDICT_CYPHER, {
        "alert_uid": alert_uid,
        "vid": result.verdict.verdict_id,
        "props": result.verdict.to_props(),
    })]
    for d in result.dispositions or []:
        stmts.append((_DISPOSITION_CYPHER, {
            "alert_uid": alert_uid,
            "vid": result.verdict.verdict_id,
            "props": d.to_props(),
        }))
    return stmts


_SEED_CYPHER = (
    "MATCH (a:Alert {alert_uid:$u})<-[:TRIGGERED]-(e:Event) "
    "OPTIONAL MATCH (e)-[:BY]->(subj) "
    "OPTIONAL MATCH (e)-[r]->(obj) WHERE NOT type(r) IN ['BY', 'TRIGGERED'] "
    "WITH e, subj, collect(DISTINCT {rel: type(r), node: obj{.*, _labels: labels(obj)}}) AS related "
    "RETURN e{.*} AS event, "
    "  (CASE WHEN subj IS NULL THEN null ELSE subj{.*, _labels: labels(subj)} END) AS subject, "
    "  [x IN related WHERE x.node IS NOT NULL] AS related"
)


class Neo4jGraph:
    def __init__(self, uri, user, password, database=None):
        from neo4j import GraphDatabase          # 惰性导入
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._db = database

    def close(self):
        self._driver.close()

    def _session(self):
        return self._driver.session(database=self._db) if self._db else self._driver.session()

    def run_cypher(self, query, **params):
        """只读执行,返回 [dict]。走 READ 事务:写会被库拒(第二道只读保证)。"""
        with self._session() as s:
            return s.execute_read(lambda tx: [r.data() for r in tx.run(query, **params)])

    def get_alert(self, alert_uid):
        rows = self.run_cypher("MATCH (a:Alert {alert_uid:$u}) RETURN a{.*} AS a", u=alert_uid)
        return rows[0]["a"] if rows else None

    def seed(self, alert):
        """骨架保底:反查触发事件 → 主语/宾语/次要实体。返回 {event, subject, related}。"""
        rows = self.run_cypher(_SEED_CYPHER, u=alert.alert_uid)
        return rows[0] if rows else {}

    def write_result(self, alert_uid, result):
        """把研判/处置结论写回经验层(execute_write)。"""
        stmts = build_write_statements(alert_uid, result)
        if not stmts:
            return None
        with self._session() as s:
            def _tx(tx):
                last = None
                for cypher, params in stmts:
                    last = tx.run(cypher, **params).data()
                return last
            return s.execute_write(_tx)
