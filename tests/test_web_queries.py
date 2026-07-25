"""web/queries.py 纯 Cypher builder 单测(离线,3.10 可跑;风格仿 test_response_ledger)。

每个 builder 返回 (cypher, params);断言关键片段 + 参数,不连 neo4j。
"""
from soc_agent.web import queries as q


# ---- 队列分页/计数 ----
def test_alerts_page_shape_and_paging():
    c, p = q.q_alerts_page(skip=20, limit=10)
    assert "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict)" in c
    assert "OPTIONAL MATCH (v)-[:LED_TO]->(p:ResponsePlan {plan_id:a.alert_uid})" in c
    assert "coalesce(a.arrival_ms,0) AS arrival_ms" in c
    assert "coalesce(c.path, v.path) AS path" in c
    assert "coalesce(c.method,'llm') AS method" in c          # 复用/浅层区分靠 method
    assert "p.status AS plan_status" in c
    assert "ORDER BY coalesce(a.arrival_ms,0) DESC" in c       # 新的在前
    assert "SKIP $skip LIMIT $limit" in c
    assert p["skip"] == 20 and p["limit"] == 10
    # 无筛选 → 全部为 None(Cypher 里 `$x IS NULL OR ...` 短路放行)
    assert p["verdict"] is None and p["path"] is None and p["dispo"] is None and p["q"] is None


def test_alerts_page_filters_map_to_params():
    c, p = q.q_alerts_page(verdict="true_positive", path="B", dispo_status="proposed", q="kerberoast")
    assert p["verdict"] == "true_positive" and p["path"] == "B"
    assert p["dispo"] == "proposed" and p["q"] == "kerberoast"
    assert "($verdict IS NULL OR v.verdict = $verdict)" in c
    assert "($path IS NULL OR coalesce(c.path, v.path) = $path)" in c
    assert "($dispo IS NULL OR p.status = $dispo)" in c
    assert "CONTAINS toLower($q)" in c                         # 关键词模糊


def test_alerts_page_blank_filters_become_null():
    # 空串筛选等价于不筛(前端传空)
    _c, p = q.q_alerts_page(verdict="", path="", dispo_status="", q="")
    assert p["verdict"] is None and p["path"] is None and p["dispo"] is None and p["q"] is None


def test_alerts_count_same_filter_returns_n():
    c, p = q.q_alerts_count(verdict="false_positive")
    assert "count(DISTINCT a.alert_uid) AS n" in c
    assert "MATCH (a:Alert)-[c:CONCLUDED]->(v:Verdict)" in c
    assert p["verdict"] == "false_positive"
    assert "skip" not in p and "limit" not in p                # 计数不分页


# ---- 溯源零件 ----
def test_findings_by_alert():
    c, p = q.q_findings("uidX")
    assert "(a:Alert {alert_uid:$uid})-[:HAS_FINDING]->(f:Finding)" in c
    assert "f.polarity AS polarity" in c and "f.attrs AS attrs" in c
    assert p == {"uid": "uidX"}


def test_trace_by_alert():
    c, p = q.q_trace("uidX")
    assert "(a:Alert {alert_uid:$uid})-[:HAS_TRACE]->(t:Trace)" in c
    assert "t.steps AS steps" in c
    assert p == {"uid": "uidX"}


# ---- :Config 读写(模式开关持久化用) ----
def test_config_get_set():
    gc, gp = q.q_get_config("response_mode")
    assert "(c:Config {key:$key})" in gc and "c.value AS value" in gc and gp == {"key": "response_mode"}
    sc, sp = q.q_set_config("response_mode", "auto")
    assert "MERGE (c:Config {key:$key})" in sc and "SET c.value = $value" in sc
    assert sp == {"key": "response_mode", "value": "auto"}


# ---- 大盘 stats ----
def test_progress_counts():
    assert "count(DISTINCT a) AS n" in q.q_count_concluded()[0]
    bc = q.q_count_backlog()[0]
    assert "NOT (a)-[:CONCLUDED]->()" in bc and "coalesce(a.poller_skip,false)=false" in bc
    assert "coalesce(a.poller_skip,false)=true" in q.q_count_poison()[0]


def test_verdict_path_histogram():
    c, _ = q.q_verdict_path()
    assert "v.verdict AS verdict" in c and "coalesce(c.path,v.path) AS path" in c
    assert "count(*) AS n" in c


def test_method_path_histogram_for_reuse_split():
    # ★收紧1:复用命中(method=reuse)与浅层短路(path=S & method=llm)必须能分开
    c, _ = q.q_method_path()
    assert "coalesce(c.method,'llm') AS method" in c
    assert "coalesce(c.path,v.path) AS path" in c
    assert "count(*) AS n" in c


def test_dispo_and_plan_status_histograms():
    dc, _ = q.q_dispo_status()
    assert "d.step_key <> '__no_op__'" in dc and "d.status AS status" in dc
    pc, _ = q.q_plan_status()
    assert "(p:ResponsePlan)" in pc and "p.status AS status" in pc


def test_tp_sample_with_steps():
    c, p = q.q_tp_sample(limit=5)
    assert "Verdict {verdict:'true_positive'}" in c
    assert "collect({action:d.action, target:d.target, status:d.status}) AS steps" in c
    assert p == {"limit": 5}


# ---- 单告警完整结论(溯源详情用) ----
def test_alert_conclusion_full():
    c, p = q.q_alert_conclusion("uidX")
    assert "(a:Alert {alert_uid:$uid})-[c:CONCLUDED]->(v:Verdict)" in c
    assert "ORDER BY c.at ASC LIMIT 1" in c                       # 取最早一次结论(真研判)
    assert "c.evidence_refs AS evidence_refs" in c and "c.missing_evidence AS missing_evidence" in c
    assert "c.path AS path" in c and "c.method AS method" in c
    assert "x{.action,.target,.target_kind,.status" in c          # 处置步骤(含 __no_op__,路由层滤)
    assert p == {"uid": "uidX"}


def test_reuse_origin_lookup():
    c, p = q.q_reuse_origin("uidX")
    assert "c.method = 'reuse'" in c                              # 仅复用才有来源
    assert "oc.method = 'llm'" in c                               # 源判例是真 llm 研判那条
    assert "origin.alert_uid AS origin_uid" in c
    assert p == {"uid": "uidX"}
