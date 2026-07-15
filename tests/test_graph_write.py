"""经验层写回语句构建(纯逻辑;真执行在 server2)。

★台账收敛:带 pattern → 共享 Verdict(按 pattern_id),per-alert 落 CONCLUDED 边;
无 pattern → per-alert fork(按 verdict_id)。Disposition 按 conv_key 收敛 + :ON 绑真实体。
"""
from soc_agent.graph.client import build_write_statements, build_constraints
from soc_agent.models import Disposition, InvestigationResult, Verdict


def _result(dispositions, pattern=None):
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="r", agent="qwen32b-ft", pattern=pattern)
    return InvestigationResult(alert_uid="a1", path="B", verdict=v, dispositions=dispositions)


def test_unpatterned_forks_by_verdict_id_with_edge_props():
    stmts = build_write_statements("a1", _result([]))
    assert len(stmts) == 1
    cypher, params = stmts[0]
    assert "CONCLUDED" in cypher and "Verdict {verdict_id:$vkey}" in cypher   # fork
    assert params["vkey"] == params["node_props"]["verdict_id"]
    assert params["node_props"]["verdict"] == "true_positive"
    assert params["edge_props"]["path"] == "B" and params["edge_props"]["confidence"] == 0.9   # per-alert 在边


def test_patterned_converges_by_pattern_id():
    stmts = build_write_statements("a1", _result([], pattern="PAT123"))
    cypher, params = stmts[0]
    assert "MERGE (v:Verdict {pattern_id:$vkey})" in cypher     # 共享节点收敛
    assert params["vkey"] == "PAT123"
    assert params["node_props"]["pattern_id"] == "PAT123"
    assert "verdict_id" not in params["node_props"]             # 共享节点不带 per-alert verdict_id


def test_response_plan_ledger_with_steps_and_on_entity():
    r = _result([Disposition(action="disable_account", target="jon.snow", risk="high",
                             rollback_handle={"inverse": "enable_account", "params": {"sam": "jon.snow"}})],
                pattern="PAT123")
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 4                                      # verdict + ResponsePlan + STEP + :ON
    plan_c, plan_p = stmts[1]
    assert "LED_TO" in plan_c and "ResponsePlan {plan_id:$plan_id}" in plan_c
    assert plan_p["plan_id"] == "a1" and plan_p["plan_props"]["status"] == "proposed"  # 一告警一计划
    step_c, step_p = stmts[2]
    assert "STEP {order:$order}" in step_c and "Disposition {step_key:$dkey}" in step_c
    assert step_p["order"] == 1 and step_p["dkey"] == "a1#1"
    assert step_p["props"]["action"] == "disable_account"
    assert step_p["props"]["rollback_handle"] is not None       # ★回退凭据落台账(先前漏)
    on_c, on_p = stmts[3]
    assert ":ON" in on_c and "Account {sam:$target}" in on_c    # 绑真 Account 实体
    assert "size(es) = 1" in on_c                               # 仅唯一命中才绑(不 LIMIT 1 乱绑)
    assert on_p["target"] == "jon.snow"


def test_multi_step_plan_orders_steps():
    r = _result([Disposition(action="collect_artifact", target="srv02", target_kind="host"),
                 Disposition(action="disable_account", target="hacker2", risk="high")], pattern="P")
    stmts = build_write_statements("a1", r)
    # verdict + plan + (step+on)×2 = 6
    assert len(stmts) == 6
    orders = [p["order"] for c, p in stmts if "STEP" in c]
    assert orders == [1, 2]
    keys = [p["dkey"] for c, p in stmts if "STEP" in c]
    assert keys == ["a1#1", "a1#2"]                            # 每步独立台账条目(不 conv_key 合并)


def test_file_binds_by_sha256_and_domain_by_fqdn():
    r = _result([Disposition(action="block_domain", target="evil.com", target_kind="domain")], pattern="P")
    on_c = build_write_statements("a1", r)[3][0]
    assert "Domain {fqdn:$target}" in on_c                      # 域按 fqdn


def test_disposition_no_on_when_kind_none():
    # escalate 无实体目标 → 不产 :ON 语句(但仍进响应计划台账)
    r = _result([Disposition(action="escalate", target="Security Team", risk="low")], pattern="P")
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 3                                      # verdict + plan + STEP,无 :ON
    assert all(":ON" not in c for c, _ in stmts)


def test_no_verdict_returns_empty():
    assert build_write_statements("a1", InvestigationResult(alert_uid="a1", path="B", verdict=None)) == []


def test_no_plan_when_no_dispositions():
    # FP/benign 无处置 → 只有 verdict,无 ResponsePlan
    stmts = build_write_statements("a1", _result([], pattern="P"))
    assert len(stmts) == 1 and "ResponsePlan" not in stmts[0][0]


def test_constraints_cover_convergence_keys():
    cs = " ".join(build_constraints())
    assert "v.pattern_id IS UNIQUE" in cs
    assert "p.plan_id IS UNIQUE" in cs and "d.step_key IS UNIQUE" in cs
