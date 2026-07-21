"""经验层写回语句构建(纯逻辑;真执行在 server2)。

第三类经验(历史台账):per-alert `(:Alert)-[:CONCLUDED]->(:Verdict {verdict_id})`;
处置台账 `Verdict-[:LED_TO]->ResponsePlan-[:STEP]->Disposition-[:ON]->实体`;无处置 → LED_TO 无处置单例闭环。
"""
from soc_agent.forensics import Finding
from soc_agent.graph.client import build_constraints, build_write_statements
from soc_agent.models import Disposition, InvestigationResult, Verdict


def _result(dispositions, findings=None):
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="r", agent="qwen32b-ft")
    return InvestigationResult(alert_uid="a1", path="B", verdict=v, dispositions=dispositions,
                               skill="kerberoast", findings=findings or [])


def test_writes_findings_as_nodes_on_alert():
    # 取证入图:每条 finding → (:Alert)-[:HAS_FINDING]->(:Finding);key=alert_uid#finding_id 幂等
    r = _result([], findings=[Finding("kerberoast.rc4_requested", {"enc": "0x17"},
                                      evidence_ref="ev1", polarity="red")])
    finds = [(c, p) for c, p in build_write_statements("a1", r) if "HAS_FINDING" in c]
    assert len(finds) == 1
    c, p = finds[0]
    assert ":Finding" in c and "HAS_FINDING" in c and "Finding {finding_key:$fkey}" in c
    assert p["fkey"] == "a1#kerberoast.rc4_requested"
    assert p["props"]["finding_id"] == "kerberoast.rc4_requested"
    assert p["props"]["polarity"] == "red" and p["props"]["evidence_ref"] == "ev1"
    assert p["props"]["skill"] == "kerberoast"
    assert '"enc": "0x17"' in p["props"]["attrs"]                # attrs 存 json 串(Neo4j 属性不能是嵌套 dict)


def test_no_findings_no_has_finding_stmts():
    assert [c for c, _ in build_write_statements("a1", _result([])) if "HAS_FINDING" in c] == []


def test_finding_constraint_present():
    assert "f.finding_key IS UNIQUE" in " ".join(build_constraints())


def test_forks_by_verdict_id_with_edge_props():
    stmts = build_write_statements("a1", _result([]))
    assert len(stmts) == 2                                                    # verdict + 无处置闭环
    cypher, params = stmts[0]
    assert "CONCLUDED" in cypher and "Verdict {verdict_id:$vkey}" in cypher   # per-alert fork
    assert params["vkey"] == params["node_props"]["verdict_id"]
    assert params["node_props"]["verdict"] == "true_positive"
    assert "pattern" not in params["node_props"] and "sig" not in params["node_props"]   # 第二类属性已摘
    assert params["edge_props"]["path"] == "B" and params["edge_props"]["confidence"] == 0.9


def test_concluded_edge_stamps_server_time():
    # 台账 CONCLUDED 边落真实时间戳(server 端 datetime,幂等 coalesce 保留首次)——
    # investigated_at 从没被赋值(恒 null)不能用;审计/daemon settle 窗/按龄归档都需要它。
    cypher, params = build_write_statements("a1", _result([]))[0]
    assert "c.at = coalesce(c.at, toString(datetime()))" in cypher
    assert "at" not in params["edge_props"]                        # 不再塞恒 null 的 investigated_at


def test_llm_conclusion_marks_method_llm():
    _c, params = build_write_statements("a1", _result([]))[0]
    assert params["edge_props"]["method"] == "llm"


def test_reuse_points_to_existing_verdict_no_new_node_no_downstream():
    # 复用:CONCLUDED 指向旧 Verdict(源判例),method=reuse,不新建 Verdict、不覆盖其属性、下游处置完全复用(不写)
    r = InvestigationResult(alert_uid="a2", path="A", skill="kerberoast",
                            verdict=Verdict("true_positive", confidence=0.9, agent="q"),
                            dispositions=[Disposition(action="disable_account", target="x", risk="high")],
                            findings=[Finding("kerberoast.rc4_requested", {"enc": "0x17"})],
                            reuse_verdict_id="ORIGIN_V")
    stmts = build_write_statements("a2", r)
    concl = [(c, p) for c, p in stmts if "CONCLUDED" in c]
    assert len(concl) == 1
    c, p = concl[0]
    assert p["vkey"] == "ORIGIN_V"                                  # 指向源判例 verdict_id
    assert "MATCH (a:Alert {alert_uid:$alert_uid}), (v:Verdict {verdict_id:$vkey})" in c
    assert "MERGE (a)-[c:CONCLUDED]->(v) " in c                     # MERGE 边到已 MATCH 的 v(不 inline 新建)
    assert "node_props" not in p                                   # 不写/覆盖 Verdict 节点属性
    assert "c.method = coalesce(c.method, 'reuse')" in c           # method 保首次:不把源判例 llm 降级成 reuse
    assert "method" not in p["edge_props"]
    assert not any(("ResponsePlan" in cc or "STEP" in cc or "__no_op__" in cc) for cc, _ in stmts)  # 下游不写
    assert any("HAS_FINDING" in cc for cc, _ in stmts)             # 但复用告警自己的取证要写


def test_response_plan_ledger_with_steps_and_on_entity():
    r = _result([Disposition(action="disable_account", target="jon.snow", risk="high",
                             rollback_handle={"inverse": "enable_account", "params": {"sam": "jon.snow"}})])
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 4                                      # verdict + ResponsePlan + STEP + :ON
    plan_c, plan_p = stmts[1]
    assert "LED_TO" in plan_c and "ResponsePlan {plan_id:$plan_id}" in plan_c
    assert "MERGE (p:ResponsePlan {plan_id:$plan_id})" in plan_c        # 独立 MERGE 计划(可复用、不撞约束)
    assert "MERGE (v)-[:LED_TO]->(p:ResponsePlan" not in plan_c         # ★不在边里 co-create p(重投研判会撞唯一约束)
    assert plan_p["plan_id"] == "a1" and plan_p["plan_props"]["status"] == "proposed"
    step_c, step_p = stmts[2]
    assert "STEP {order:$order}" in step_c and "Disposition {step_key:$dkey}" in step_c
    assert step_p["order"] == 1 and step_p["dkey"] == "a1#1"
    assert step_p["props"]["action"] == "disable_account"
    assert step_p["props"]["rollback_handle"] is not None       # ★回退凭据落台账
    on_c, on_p = stmts[3]
    assert ":ON" in on_c and "Account {sam:$target}" in on_c
    assert "size(es) = 1" in on_c
    assert on_p["target"] == "jon.snow"


def test_multi_step_plan_orders_steps():
    r = _result([Disposition(action="collect_artifact", target="srv02", target_kind="host"),
                 Disposition(action="disable_account", target="hacker2", risk="high")])
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 6                                      # verdict + plan + (step+on)×2
    assert [p["order"] for c, p in stmts if "STEP" in c] == [1, 2]
    assert [p["dkey"] for c, p in stmts if "STEP" in c] == ["a1#1", "a1#2"]


def test_file_binds_by_sha256_and_domain_by_fqdn():
    r = _result([Disposition(action="block_domain", target="evil.com", target_kind="domain")])
    on_c = build_write_statements("a1", r)[3][0]
    assert "Domain {fqdn:$target}" in on_c


def test_disposition_no_on_when_kind_none():
    r = _result([Disposition(action="escalate", target="Security Team", risk="low")])
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 3                                      # verdict + plan + STEP,无 :ON
    assert all(":ON" not in c for c, _ in stmts)


def test_no_verdict_returns_empty():
    assert build_write_statements("a1", InvestigationResult(alert_uid="a1", path="B", verdict=None)) == []


def test_no_op_closure_when_no_dispositions():
    stmts = build_write_statements("a1", _result([]))
    assert len(stmts) == 2 and "ResponsePlan" not in stmts[0][0]
    noop_c, noop_p = stmts[1]
    assert "Disposition {step_key:'__no_op__'}" in noop_c and "LED_TO" in noop_c   # 无处置单例闭环
    assert "action='none'" in noop_c
    assert noop_p["vkey"] == stmts[0][1]["vkey"]                # 从同一 Verdict(按 verdict_id)挂出


def test_fp_closes_loop_to_no_op_singleton():
    # 误报也闭环:FP 无处置 → CONCLUDED→Verdict→LED_TO→无处置单例
    v = Verdict(verdict="false_positive", confidence=0.9, rationale="跨域机器账号引荐票", agent="q")
    r = InvestigationResult(alert_uid="a9", path="A", verdict=v, dispositions=[])
    stmts = build_write_statements("a9", r)
    assert len(stmts) == 2
    assert stmts[0][1]["node_props"]["verdict"] == "false_positive"
    assert "Disposition {step_key:'__no_op__'}" in stmts[1][0]


def test_constraints_cover_ledger_keys():
    cs = " ".join(build_constraints())
    assert "v.verdict_id IS UNIQUE" in cs
    assert "p.plan_id IS UNIQUE" in cs and "d.step_key IS UNIQUE" in cs
    assert "pattern_id" not in cs                               # 第二类收敛约束已删
