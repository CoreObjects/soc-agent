"""Web 只读查询构建器(纯 Cypher builder,离线单测;风格仿 response/ledger.py)。

每个函数返回 (cypher, params);真执行走 Neo4jGraph.run_cypher。读侧全部在此 —— 路由只拼装、不写内联 Cypher。
"""

__all__ = [
    "q_alerts_page", "q_alerts_count", "q_findings", "q_trace",
    "q_alert_conclusion", "q_reuse_origin",
    "q_get_config", "q_set_config",
    "q_count_concluded", "q_count_backlog", "q_count_poison",
    "q_verdict_path", "q_method_path", "q_dispo_status", "q_plan_status", "q_tp_sample",
]

# 队列筛选:全部 `$x IS NULL OR ...` 短路 —— 未筛(None)则放行,不必拼多套 Cypher。
_ALERT_FILTER = (
    "WHERE ($verdict IS NULL OR v.verdict = $verdict) "
    "AND ($path IS NULL OR coalesce(c.path, v.path) = $path) "
    "AND ($dispo IS NULL OR p.status = $dispo) "
    "AND ($q IS NULL OR toLower(coalesce(a.rule_description,'')) CONTAINS toLower($q)) "
)


def _filter_params(verdict, path, dispo_status, q):
    # 空串等价于不筛(前端传 "" ≈ None)
    return {"verdict": verdict or None, "path": path or None,
            "dispo": dispo_status or None, "q": q or None}


def q_alerts_page(verdict=None, path=None, dispo_status=None, q=None, skip=0, limit=50):
    """研判队列一页(已研判告警,新的在前)。plan_id==alert_uid 关联响应计划取处置状态。"""
    cypher = (
        "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan {plan_id:a.alert_uid}) "
        "WITH a, c, v, p " + _ALERT_FILTER +
        "RETURN a.alert_uid AS alert_uid, a.rule_description AS rule_description, "
        "  a.severity AS severity, a.technique_ids AS technique_ids, a.source AS source, "
        "  a.sensor AS sensor, v.verdict AS verdict, coalesce(c.path, v.path) AS path, "
        "  coalesce(c.method,'llm') AS method, p.status AS plan_status, "
        "  coalesce(a.arrival_ms,0) AS arrival_ms, c.at AS concluded_at "
        "ORDER BY coalesce(a.arrival_ms,0) DESC, a.alert_uid "
        "SKIP $skip LIMIT $limit"
    )
    p = _filter_params(verdict, path, dispo_status, q)
    p.update({"skip": int(skip), "limit": int(limit)})
    return cypher, p


def q_alerts_count(verdict=None, path=None, dispo_status=None, q=None):
    """同筛选下的总数(分页用)。"""
    cypher = (
        "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan {plan_id:a.alert_uid}) "
        "WITH a, c, v, p " + _ALERT_FILTER +
        "RETURN count(DISTINCT a.alert_uid) AS n"
    )
    return cypher, _filter_params(verdict, path, dispo_status, q)


# ---- 溯源零件 ----
def q_findings(uid):
    """一条告警的取证 findings(极性/证据引用/skill;attrs 为 json 串,路由层 loads)。"""
    return (
        "MATCH (a:Alert {alert_uid:$uid})-[:HAS_FINDING]->(f:Finding) "
        "RETURN f.finding_id AS finding_id, f.polarity AS polarity, "
        "  f.evidence_ref AS evidence_ref, f.skill AS skill, f.attrs AS attrs "
        "ORDER BY f.finding_id",
        {"uid": uid})


def q_trace(uid):
    """一条告警的逐步研判留痕(steps 为 json 串;无 :Trace → 空,前端回退重建流程)。"""
    return (
        "MATCH (a:Alert {alert_uid:$uid})-[:HAS_TRACE]->(t:Trace) "
        "RETURN t.steps AS steps LIMIT 1",
        {"uid": uid})


def q_alert_conclusion(uid):
    """一条告警的完整结论(溯源详情)——比 recall_ledger 更全:含 path/method/lean/agent +
    证据/缺失证据 + 处置步骤(含 __no_op__ 单例,路由层按 action='none' 滤掉)。取最早一次 CONCLUDED。"""
    return (
        "MATCH (a:Alert {alert_uid:$uid})-[c:CONCLUDED]->(v:Verdict) "
        "WITH a, c, v ORDER BY c.at ASC LIMIT 1 "
        "OPTIONAL MATCH (v)-[:LED_TO]->(:ResponsePlan)-[:STEP]->(d:Disposition) "
        "OPTIONAL MATCH (v)-[:LED_TO]->(d0:Disposition) "
        "RETURN v.verdict AS verdict, v.lean AS lean, v.agent AS agent, "
        "  c.path AS path, c.method AS method, c.confidence AS confidence, c.at AS concluded_at, "
        "  c.summary AS summary, c.rationale AS rationale, "
        "  c.evidence_refs AS evidence_refs, c.missing_evidence AS missing_evidence, "
        "  [x IN collect(DISTINCT d)+collect(DISTINCT d0) WHERE x IS NOT NULL | "
        "     x{.action,.target,.target_kind,.status,.risk,.params,.step_key}] AS dispositions",
        {"uid": uid})


def q_reuse_origin(uid):
    """复用告警(method=reuse)→ 反查它复用的源判例(那条真 llm 研判的告警),供'复用来源'卡。"""
    return (
        "MATCH (a:Alert {alert_uid:$uid})-[c:CONCLUDED]->(v:Verdict) "
        "WHERE c.method = 'reuse' "
        "OPTIONAL MATCH (origin:Alert)-[oc:CONCLUDED]->(v) WHERE oc.method = 'llm' "
        "RETURN v.verdict_id AS verdict_id, v.verdict AS verdict, origin.alert_uid AS origin_uid "
        "LIMIT 1",
        {"uid": uid})


# ---- :Config 读写(响应模式开关持久化) ----
def q_get_config(key):
    return ("MATCH (c:Config {key:$key}) RETURN c.value AS value LIMIT 1", {"key": key})


def q_set_config(key, value):
    return ("MERGE (c:Config {key:$key}) SET c.value = $value RETURN c.value AS value",
            {"key": key, "value": value})


# ---- 大盘 stats(移植 scripts/ledger-stats.sh 五段 + 收紧1 的 method 拆分) ----
def q_count_concluded():
    return ("MATCH (a:Alert)-[:CONCLUDED]->() RETURN count(DISTINCT a) AS n", {})


def q_count_backlog():
    return ("MATCH (a:Alert) WHERE NOT (a)-[:CONCLUDED]->() "
            "AND coalesce(a.poller_skip,false)=false RETURN count(a) AS n", {})


def q_count_poison():
    return ("MATCH (a:Alert) WHERE coalesce(a.poller_skip,false)=true RETURN count(a) AS n", {})


def q_verdict_path():
    return ("MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
            "RETURN v.verdict AS verdict, coalesce(c.path,v.path) AS path, count(*) AS n "
            "ORDER BY n DESC", {})


def q_method_path():
    """★收紧1:按 (method, path) 分组 —— 复用命中(method=reuse,含签名/深度经验,随经验涨)
    与浅层短路(path=S 且 method=llm,便宜结案、基本恒定)、深度(path=B)必须能分开,
    否则'越用越省'数字虚高且增长信号被摊平。"""
    return ("MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict) "
            "RETURN coalesce(c.method,'llm') AS method, coalesce(c.path,v.path) AS path, count(*) AS n "
            "ORDER BY n DESC", {})


def q_dispo_status():
    return ("MATCH (d:Disposition) WHERE d.step_key <> '__no_op__' "
            "RETURN d.status AS status, count(*) AS n ORDER BY n DESC", {})


def q_plan_status():
    return ("MATCH (p:ResponsePlan) RETURN p.status AS status, count(*) AS n ORDER BY n DESC", {})


def q_tp_sample(limit=5):
    return ("MATCH (a:Alert)-[:CONCLUDED]->(v:Verdict {verdict:'true_positive'}) "
            "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan)-[:STEP]->(d:Disposition) "
            "RETURN a.alert_uid AS uid, p.status AS plan, "
            "  collect({action:d.action, target:d.target, status:d.status}) AS steps "
            "LIMIT $limit", {"limit": int(limit)})
