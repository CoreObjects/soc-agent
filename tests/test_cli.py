"""CLI 研判流程:取告警 → seed(骨架保底)→ 研判 → 写回图。

用 fakes 验流程编排(真客户端在 server2)。
"""
import pytest

from soc_agent.cli import (AlertNotFound, choose_investigator, investigate_alert,
                           render_result, render_trace)
from soc_agent.models import Alert, InvestigationResult, Verdict


class _RecInv:
    def __init__(self, ok):
        self._ok = ok

    def has_recipe(self, alert):
        return self._ok


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"]})


def test_choose_investigator_prefers_recipe_when_available():
    agent = object()
    inv, label = choose_investigator(_alert(), "recipe", agent, _RecInv(True))
    assert inv is not agent and "recipe" in label


def test_choose_investigator_auto_mode_uses_agent():
    agent = object()
    inv, label = choose_investigator(_alert(), "auto", agent, _RecInv(True))
    assert inv is agent and label == "auto"


def test_choose_investigator_falls_back_to_agent_without_recipe():
    agent = object()
    inv, label = choose_investigator(_alert(), "recipe", agent, _RecInv(False))
    assert inv is agent


class FakeGraph:
    def __init__(self, node):
        self.node = node
        self.seeded = None
        self.written = None

    def get_alert(self, uid):
        return self.node

    def seed(self, alert):
        self.seeded = alert
        return {"triggering_event": {"x": 1}}

    def write_result(self, uid, result):
        self.written = (uid, result)


class FakeInvestigator:
    def __init__(self, result):
        self.result = result
        self.called = None

    def investigate(self, alert, seed=None):
        self.called = (alert, seed)
        return self.result


def test_investigate_alert_flow():
    g = FakeGraph({"alert_uid": "a1", "technique_ids": ["T1558.003"]})
    res = InvestigationResult(alert_uid="a1", path="B",
                              verdict=Verdict(verdict="true_positive", confidence=0.9))
    inv = FakeInvestigator(res)
    out = investigate_alert(g, inv, "a1")
    assert out is res
    assert isinstance(inv.called[0], Alert) and inv.called[0].alert_uid == "a1"
    assert inv.called[1] == {"triggering_event": {"x": 1}}     # seed 传进研判
    assert g.written == ("a1", res)                            # 结果写回图


def test_investigate_alert_not_found():
    with pytest.raises(AlertNotFound):
        investigate_alert(FakeGraph(None), FakeInvestigator(None), "missing")


def test_render_result_readable():
    res = InvestigationResult(alert_uid="a1", path="B", skill="kerberoast",
                              verdict=Verdict(verdict="true_positive", confidence=0.9,
                                              rationale="RC4 扇出", agent="qwen32b-ft"))
    txt = render_result(res)
    assert "true_positive" in txt and "a1" in txt and "kerberoast" in txt


def test_render_trace_shows_queries_and_row_counts():
    res = InvestigationResult(alert_uid="a1", path="B", verdict=None, trace=[
        {"tool": "run_cypher", "args": {"query": "MATCH (a:Alert) RETURN a"},
         "result": {"rows": [{"x": 1}, {"x": 2}]}},
        {"tool": "run_cypher", "args": {"query": "MATCH (a) SET a.x=1"},
         "result": {"error": "只读守卫拒绝"}},
    ])
    txt = render_trace(res)
    assert "run_cypher" in txt
    assert "2 行" in txt              # 行数,不打行数据(避免刷屏/泄数据)
    assert "只读守卫拒绝" in txt        # 错误可见
