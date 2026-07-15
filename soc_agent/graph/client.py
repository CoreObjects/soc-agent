"""Neo4j 图客户端:只读取事实 + seed(骨架保底)+ 写回经验层。

读写分权:
  run_cypher  走 execute_read(READ 事务)→ 即便守卫漏了,写也被库直接拒(第二道保证)。
  write_result 走 execute_write,只写经验层(Verdict/Disposition)。
neo4j 惰性导入(方法内),故 build_write_statements 等纯逻辑本机可测、不需装 neo4j。
"""
__all__ = ["Neo4jGraph", "build_write_statements", "build_constraints"]

# 处置目标类型 → (实体 label, 键字段);:ON 绑真实体用。label/键来自固定表,非用户输入 → 安全内插。
_ENTITY_BY_KIND = {
    "ip": ("IPAddress", "ip"),
    "account": ("Account", "sam"),
    "host": ("Host", "hostname"),
    "process": ("Process", "process_guid"),
    "file": ("File", "path"),
}


def build_constraints():
    """图台账收敛的唯一约束(启动时建;并发 MERGE 防重复节点)。Neo4j 5 语法。"""
    return [
        "CREATE CONSTRAINT verdict_pattern_id IF NOT EXISTS FOR (v:Verdict) REQUIRE v.pattern_id IS UNIQUE",
        "CREATE CONSTRAINT verdict_id IF NOT EXISTS FOR (v:Verdict) REQUIRE v.verdict_id IS UNIQUE",
        "CREATE CONSTRAINT disposition_key IF NOT EXISTS FOR (d:Disposition) REQUIRE d.disposition_key IS UNIQUE",
    ]


def build_write_statements(alert_uid, result):
    """研判结果 → [(cypher, params)]。无 verdict → []。

    ★收敛:verdict 带 pattern(pattern_id)→ 共享 Verdict 节点(按 pattern_id),per-alert 数据落 CONCLUDED 边;
    无 pattern(慢通道未命中)→ per-alert fork(按 verdict_id)。图只存台账/历史,规则本体在 openGauss。
    Disposition 按 conv_key(action+目标)收敛,并 :ON 绑到真实体(可解析且单一时;0/多命中不硬造边)。
    """
    if result is None or result.verdict is None:
        return []
    v = result.verdict
    node_props = {"verdict": v.verdict, "lean": v.lean, "pattern": v.pattern, "agent": v.agent}
    edge_props = {"at": v.investigated_at, "path": result.path, "confidence": v.confidence,
                  "summary": v.summary, "rationale": v.rationale,
                  "evidence_refs": list(v.evidence_refs), "missing_evidence": list(v.missing_evidence)}

    stmts = []
    if v.pattern:                       # 共享 Verdict 台账节点(收敛),per-alert 在边
        node_props["pattern_id"] = v.pattern
        stmts.append((
            "MATCH (a:Alert {alert_uid:$alert_uid}) "
            "MERGE (v:Verdict {pattern_id:$vkey}) SET v += $node_props "
            "MERGE (a)-[c:CONCLUDED]->(v) SET c += $edge_props "
            "RETURN v.pattern_id AS id",
            {"alert_uid": alert_uid, "vkey": v.pattern, "node_props": node_props, "edge_props": edge_props}))
        vmatch, vkey = "MATCH (a:Alert {alert_uid:$alert_uid})-[:CONCLUDED]->(v:Verdict {pattern_id:$vkey}) ", v.pattern
    else:                               # 未命中模式:per-alert fork
        node_props["verdict_id"] = v.verdict_id
        stmts.append((
            "MATCH (a:Alert {alert_uid:$alert_uid}) "
            "MERGE (a)-[c:CONCLUDED]->(v:Verdict {verdict_id:$vkey}) SET v += $node_props, c += $edge_props "
            "RETURN v.verdict_id AS id",
            {"alert_uid": alert_uid, "vkey": v.verdict_id, "node_props": node_props, "edge_props": edge_props}))
        vmatch, vkey = "MATCH (a:Alert {alert_uid:$alert_uid})-[:CONCLUDED]->(v:Verdict {verdict_id:$vkey}) ", v.verdict_id

    for d in result.dispositions or []:
        props = d.to_props()
        dkey = props["disposition_key"]
        stmts.append((
            vmatch + "MERGE (v)-[:LED_TO]->(d:Disposition {disposition_key:$dkey}) SET d += $props "
            "RETURN d.disposition_key AS id",
            {"alert_uid": alert_uid, "vkey": vkey, "dkey": dkey, "props": props}))
        ent = _ENTITY_BY_KIND.get(d.target_kind)
        if ent and d.target:            # :ON 绑真实体(单一命中才绑;0/多→无行/不硬造)
            label, keyf = ent
            stmts.append((
                "MATCH (d:Disposition {disposition_key:$dkey}) "
                f"MATCH (e:{label} {{{keyf}:$target}}) WITH d, e LIMIT 1 "
                f"MERGE (d)-[:ON]->(e) RETURN e.{keyf} AS bound",
                {"dkey": dkey, "target": d.target}))
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

    def ensure_constraints(self):
        """建台账收敛唯一约束(启动时;幂等)。"""
        with self._session() as s:
            for c in build_constraints():
                s.execute_write(lambda tx, q=c: tx.run(q).consume())

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
