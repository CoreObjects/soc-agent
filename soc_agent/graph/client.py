"""Neo4j 图客户端:只读取事实 + seed(骨架保底)+ 写回经验层。

读写分权:
  run_cypher  走 execute_read(READ 事务)→ 即便守卫漏了,写也被库直接拒(第二道保证)。
  write_result 走 execute_write,只写经验层(Verdict/Disposition)。
neo4j 惰性导入(方法内),故 build_write_statements 等纯逻辑本机可测、不需装 neo4j。
"""
import json

__all__ = ["Neo4jGraph", "build_write_statements", "build_constraints",
           "shape_ledger", "recall_ledger"]

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
        "CREATE CONSTRAINT verdict_id IF NOT EXISTS FOR (v:Verdict) REQUIRE v.verdict_id IS UNIQUE",
        "CREATE CONSTRAINT responseplan_id IF NOT EXISTS FOR (p:ResponsePlan) REQUIRE p.plan_id IS UNIQUE",
        "CREATE CONSTRAINT disposition_step_key IF NOT EXISTS FOR (d:Disposition) REQUIRE d.step_key IS UNIQUE",
        "CREATE CONSTRAINT finding_key IF NOT EXISTS FOR (f:Finding) REQUIRE f.finding_key IS UNIQUE",
    ]


def build_write_statements(alert_uid, result):
    """研判结果 → [(cypher, params)]。无 verdict → []。

    ★第三类经验(历史台账):per-alert `(:Alert)-[:CONCLUDED]->(:Verdict {verdict_id})`。

    ★响应台账(一告警一响应计划,审计流水):(:Verdict)-[:LED_TO]->(:ResponsePlan {plan_id,status})
      -[:STEP {order}]->(:Disposition {step_key, primitive/params/rollback_handle/status})-[:ON]->真实体。
      每步是独立台账条目(带自己的 rollback_handle/execution_id),不按 conv_key 合并 —— 响应审计要全历史。
      :ON 仅"唯一命中"才绑(0/多命中不硬造边,防绑错)。
    """
    if result is None or result.verdict is None:
        return []
    v = result.verdict
    node_props = {"verdict": v.verdict, "lean": v.lean, "agent": v.agent, "verdict_id": v.verdict_id}
    edge_props = {"path": result.path, "confidence": v.confidence,
                  "summary": v.summary, "rationale": v.rationale,
                  "evidence_refs": list(v.evidence_refs), "missing_evidence": list(v.missing_evidence)}

    stmts = []
    stmts.append((                      # per-alert 台账节点(按 verdict_id);c.at=研判时间(server 端 stamp,
        # 幂等 coalesce 保首次)——审计台账的真实时间戳,daemon settle 窗 / 按龄归档 / recall 取原始结论都靠它。
        "MATCH (a:Alert {alert_uid:$alert_uid}) "
        "MERGE (a)-[c:CONCLUDED]->(v:Verdict {verdict_id:$vkey}) "
        "SET v += $node_props, c += $edge_props, c.at = coalesce(c.at, toString(datetime())) "
        "RETURN v.verdict_id AS id",
        {"alert_uid": alert_uid, "vkey": v.verdict_id, "node_props": node_props, "edge_props": edge_props}))
    vmatch, vkey = "MATCH (a:Alert {alert_uid:$alert_uid})-[:CONCLUDED]->(v:Verdict {verdict_id:$vkey}) ", v.verdict_id

    disps = result.dispositions or []
    if disps:                           # 有处置 → 建响应计划台账(一告警一计划)
        plan_id = alert_uid
        stmts.append((
            # ★先按 plan_id 独立 MERGE 计划节点(复用已有,不撞唯一约束),再 MERGE 边——
            #   否则新 Verdict 上 `MERGE (v)-[:LED_TO]->(p:ResponsePlan {plan_id})` 会新建 p → 重投研判时撞约束。
            vmatch + "MERGE (p:ResponsePlan {plan_id:$plan_id}) SET p += $plan_props "
            "MERGE (v)-[:LED_TO]->(p) "
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
    else:                               # ★无处置(FP/benign/suspicious、或无法组计划的 TP)→ 闭环到「无处置」单例
        # 复用 :Disposition label + step_key 唯一约束(单例 step_key='__no_op__',绝不撞真实 step_key `uid#i`)→
        # reset_pristine/double_run 清 :Disposition 即连带清掉、无孤儿。误报经验也照样闭环(CONCLUDED→Verdict→无处置)。
        stmts.append((
            vmatch + "MERGE (n:Disposition {step_key:'__no_op__'}) "
            "ON CREATE SET n.action='none', n.primitive='none', n.status='none' "
            "MERGE (v)-[:LED_TO]->(n) RETURN n.step_key AS id",
            {"alert_uid": alert_uid, "vkey": vkey}))

    # ★取证入图:每条 finding 作 (:Finding) 挂 Alert(分析层,永久;prune 不碰非 :Event/非高基数标签)。
    #   key=alert_uid#finding_id(每告警每类发现唯一→重研判幂等);attrs 存 json 串(Neo4j 属性不能是嵌套 dict)。
    for f in (result.findings or []):
        fkey = f"{alert_uid}#{f.finding_id}"
        stmts.append((
            "MATCH (a:Alert {alert_uid:$alert_uid}) "
            "MERGE (a)-[:HAS_FINDING]->(fn:Finding {finding_key:$fkey}) SET fn += $props "
            "RETURN fn.finding_key AS id",
            {"alert_uid": alert_uid, "fkey": fkey,
             "props": {"finding_key": fkey, "finding_id": f.finding_id,
                       "attrs": json.dumps(f.attrs, ensure_ascii=False),
                       "polarity": f.polarity, "evidence_ref": f.evidence_ref, "skill": result.skill}}))
    return stmts


# 按 alert_uid(命中经验的来源 VID)捞回台账「原始上下文」:原告警字段 + Verdict 结论/理由 + 处置。
# ★台账永久保存(prune 只清 :Event + 高基数对象,不碰 Alert/Verdict/ResponsePlan/Disposition)→ 事后永久可捞。
# ★summary/rationale/confidence 挂在 CONCLUDED 边(取 c. 不是 v.);d=经 ResponsePlan 的真处置,
#   d0=无处置 `Disposition{step_key:'__no_op__'}` 单例(直连 Verdict,无 ResponsePlan)→ shape 里过滤掉。
_LEDGER_CYPHER = (
    "MATCH (a:Alert {alert_uid:$uid})-[c:CONCLUDED]->(v:Verdict) "
    "WITH a, c, v ORDER BY c.at ASC LIMIT 1 "                       # 取最早一次结论=蒸出该经验的那次研判
    # (原始研判有真 rationale,比后续 AUTO 复用的"经验复用"摘要更有信息量);c.at 由写台账时 server 端 stamp。
    "OPTIONAL MATCH (v)-[:LED_TO]->(:ResponsePlan)-[:STEP]->(d:Disposition) "
    "OPTIONAL MATCH (v)-[:LED_TO]->(d0:Disposition) "              # 无处置 __no_op__ 单例
    "RETURN a{.source,.sensor,.rule_id,.rule_description,.severity,.technique_ids} AS alert, "
    "  v.verdict AS verdict, c.summary AS summary, c.rationale AS rationale, c.confidence AS confidence, "
    "  [x IN collect(DISTINCT d)+collect(DISTINCT d0) WHERE x IS NOT NULL | "
    "     x{.action,.target,.target_kind,.status}] AS dispositions"
)

_NOOP_ACTIONS = (None, "", "none")


def shape_ledger(rows):
    """run_cypher 的行 → 干净台账 dict(过滤无处置 __no_op__ 单例)。空 → None。"""
    if not rows:
        return None
    r = rows[0]
    disps = [d for d in (r.get("dispositions") or []) if (d or {}).get("action") not in _NOOP_ACTIONS]
    return {"alert": r.get("alert") or {}, "verdict": r.get("verdict"),
            "summary": r.get("summary"), "rationale": r.get("rationale"),
            "confidence": r.get("confidence"), "dispositions": disps}


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

    def recall_ledger(self, alert_uid):
        """按 alert_uid 捞回该告警的台账原始上下文(供命中经验喂 LLM)。无 → None。"""
        led = shape_ledger(self.run_cypher(_LEDGER_CYPHER, uid=alert_uid))
        if led is not None:
            led["alert_uid"] = alert_uid          # 回填 VID,自描述
        return led

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
