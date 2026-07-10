"""经验层写回语句构建(纯逻辑;真执行在 server2)。

研判结果 → (:Alert)-[:CONCLUDED]->(:Verdict)[-[:LED_TO]->(:Disposition)] 的 Cypher+params。
(ON→实体边留到 P5 处置层做精确目标解析;P1 先把 target 存 Disposition 属性。)
"""
from soc_agent.graph.client import build_write_statements
from soc_agent.models import Disposition, InvestigationResult, Verdict


def _result(dispositions, verdict=True):
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="r", agent="qwen32b-ft") if verdict else None
    return InvestigationResult(alert_uid="a1", path="B", verdict=v, dispositions=dispositions)


def test_write_statements_verdict_only():
    stmts = build_write_statements("a1", _result([]))
    assert len(stmts) == 1
    cypher, params = stmts[0]
    assert "CONCLUDED" in cypher and "Verdict" in cypher
    assert params["alert_uid"] == "a1"
    assert params["props"]["verdict"] == "true_positive"
    assert params["vid"]                        # verdict_id 非空


def test_write_statements_with_dispositions():
    r = _result([Disposition(action="disable_account", target="jon.snow", risk="high")])
    stmts = build_write_statements("a1", r)
    assert len(stmts) == 2
    dc, dp = stmts[1]
    assert "LED_TO" in dc and "Disposition" in dc
    assert dp["props"]["action"] == "disable_account"
    assert dp["props"]["status"] == "proposed"   # propose-only
    assert dp["vid"] == r.verdict.verdict_id      # 挂到本次 Verdict 上


def test_write_statements_no_verdict_returns_empty():
    r = InvestigationResult(alert_uid="a1", path="B", verdict=None, dispositions=[])
    assert build_write_statements("a1", r) == []
