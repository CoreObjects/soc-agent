"""Neo4j 图客户端:只读取事实 + seed(骨架保底)+ 写回经验层。

读写分权:
  run_cypher  走 execute_read(READ 事务)→ 即便守卫漏了,写也被库直接拒(第二道保证)。
  write_result 走 execute_write,只写经验层(Verdict/Disposition)。
neo4j 惰性导入(方法内),故 build_write_statements 等纯逻辑本机可测、不需装 neo4j。
"""
__all__ = ["Neo4jGraph", "build_write_statements", "build_constraints"]

# 处置目标类型 → (实体 label, 匹配字段);:ON 绑真实体用。label/字段来自固定表,非用户输入 → 安全内插。
# ★匹配字段取"处置目标值就是那个字段"的:sam(账号)/ip/process_guid/sha256(文件的图唯一键)/fqdn(域)。
#   host 只能按 hostname(prop,图唯一键是 asset_id、但处置时只握有主机名)——靠"仅唯一命中才绑"防绑错。
_ENTITY_BY_KIND = {
    "ip": ("IPAddress", "ip"),
    "account": ("Account", "sam"),
    "host": ("Host", "hostname"),
    "process": ("Process", "process_guid"),
    "file": ("File", "sha256"),
    "domain": ("Domain", "fqdn"),
}


def build_constraints():
    """图台账收敛的唯一约束(启动时建;并发 MERGE 防重复节点)。Neo4j 5 语法。

    ★迁移:先 DROP 掉旧的 disposition_key 唯一约束 —— 新响应台账按 step_key 建 per-step 节点,
    disposition_key(conv_key)降级为信息属性、同 action+目标跨告警会重复,旧唯一约束会误拦(P3' 遗留)。
    """
    return [
        "DROP CONSTRAINT disposition_key IF EXISTS",   # 迁移:清旧 conv_key 唯一约束
        "CREATE CONSTRAINT verdict_pattern_id IF NOT EXISTS FOR (v:Verdict) REQUIRE v.pattern_id IS UNIQUE",
        "CREATE CONSTRAINT verdict_id IF NOT EXISTS FOR (v:Verdict) REQUIRE v.verdict_id IS UNIQUE",
        "CREATE CONSTRAINT responseplan_id IF NOT EXISTS FOR (p:ResponsePlan) REQUIRE p.plan_id IS UNIQUE",
        "CREATE CONSTRAINT disposition_step_key IF NOT EXISTS FOR (d:Disposition) REQUIRE d.step_key IS UNIQUE",
    ]


def build_write_statements(alert_uid, result):
    """研判结果 → [(cypher, params)]。无 verdict → []。

    ★收敛:verdict 带 pattern(pattern_id)→ 共享 Verdict 节点(按 pattern_id),per-alert 数据落 CONCLUDED 边;
    无 pattern(慢通道未命中)→ per-alert fork(按 verdict_id)。图只存台账/历史,规则本体在 openGauss。

    ★响应台账(一告警一响应计划,审计流水):(:Verdict)-[:LED_TO]->(:ResponsePlan {plan_id,status})
      -[:STEP {order}]->(:Disposition {step_key, primitive/params/rollback_handle/status})-[:ON]->真实体。
      每步是独立台账条目(带自己的 rollback_handle/execution_id),不按 conv_key 合并 —— 响应审计要全历史。
      :ON 仅"唯一命中"才绑(0/多命中不硬造边,防绑错)。
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

    disps = result.dispositions or []
    if disps:                           # 有处置 → 建响应计划台账(一告警一计划)
        plan_id = alert_uid
        stmts.append((
            vmatch + "MERGE (v)-[:LED_TO]->(p:ResponsePlan {plan_id:$plan_id}) SET p += $plan_props "
            "RETURN p.plan_id AS id",
            {"alert_uid": alert_uid, "vkey": vkey, "plan_id": plan_id,
             "plan_props": {"plan_id": plan_id, "status": "proposed"}}))
        for i, d in enumerate(disps, start=1):
            props = d.to_props()
            step_key = f"{plan_id}#{i}"
            props["step_key"] = step_key
            props["order"] = i
            stmts.append((
                "MATCH (p:ResponsePlan {plan_id:$plan_id}) "
                "MERGE (p)-[:STEP {order:$order}]->(d:Disposition {step_key:$dkey}) SET d += $props "
                "RETURN d.step_key AS id",
                {"plan_id": plan_id, "order": i, "dkey": step_key, "props": props}))
            ent = _ENTITY_BY_KIND.get(d.target_kind)
            if ent and d.target:        # :ON 绑真实体(仅唯一命中才绑;0/多→不硬造边)
                label, keyf = ent
                stmts.append((
                    "MATCH (d:Disposition {step_key:$dkey}) "
                    f"OPTIONAL MATCH (e0:{label} {{{keyf}:$target}}) "
                    "WITH d, collect(e0) AS es WHERE size(es) = 1 "
                    "WITH d, es[0] AS e "
                    f"MERGE (d)-[:ON]->(e) RETURN e.{keyf} AS bound",
                    {"dkey": step_key, "target": d.target}))
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

    def run_write(self, cypher, **params):
        """维护/回写专用写(execute_write);★研判取证一律走 run_cypher(只读)。仅约束/清理/回写用。"""
        with self._session() as s:
            return s.execute_write(lambda tx: [r.data() for r in tx.run(cypher, **params)])

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
