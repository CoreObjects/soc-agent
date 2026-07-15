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


def test_disposition_led_to_and_on_entity():
    r = _result([Disposition(action="disable_account", target="jon.snow", risk="high")], pattern="PAT123")
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 3                                      # verdict + LED_TO + :ON
    led = stmts[1][0]
    assert "LED_TO" in led and "Disposition {disposition_key:$dkey}" in led   # 按 conv_key 收敛
    assert stmts[1][1]["props"]["action"] == "disable_account"
    assert stmts[1][1]["props"]["target_kind"] == "account"
    on_c, on_p = stmts[2]
    assert ":ON" in on_c and "Account {sam:$target}" in on_c    # 绑到真 Account 实体
    assert on_p["target"] == "jon.snow"


def test_disposition_no_on_when_kind_none():
    # escalate 无实体目标 → 不产 :ON 语句
    r = _result([Disposition(action="escalate", target="Security Team", risk="low")], pattern="P")
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 2                                      # verdict + LED_TO,无 :ON
    assert all(":ON" not in c for c, _ in stmts)


def test_no_verdict_returns_empty():
    assert build_write_statements("a1", InvestigationResult(alert_uid="a1", path="B", verdict=None)) == []


def test_constraints_cover_convergence_keys():
    cs = " ".join(build_constraints())
    assert "v.pattern_id IS UNIQUE" in cs and "d.disposition_key IS UNIQUE" in cs
