"""cascade 两组件单测:直接调 invoke,验写台账 / 调 run_deep + sink 回填。

需 openjiuwen(Python 3.11+),在 .venv312 里跑。
"""
import asyncio

from soc_agent.cascade.components import (
    DeepInvestigationComponent,
    ShallowTerminalComponent,
    SHALLOW_DECISION,
)


class _FakeGraph:
    def __init__(self):
        self.written = []

    def write_result(self, alert_uid, result):
        self.written.append((alert_uid, result))


def test_shallow_terminal_writes_fp_and_fills_sink():
    g = _FakeGraph()
    sink = {}
    comp = ShallowTerminalComponent(g, sink, agent_name="qwenX")

    out = asyncio.run(comp.invoke(
        {"alert_uid": "a1", "confidence": 0.92, "rationale": "已知内部漏扫器"}, None, None))

    assert len(g.written) == 1                      # 写了台账
    uid, result = g.written[0]
    assert uid == "a1"
    assert result.path == "S"
    assert result.verdict.verdict == "false_positive"
    assert result.verdict.confidence == 0.92
    assert result.verdict.agent == "qwenX"
    assert result.skill is None
    # sink 回填完整结果 + 占位 report/picked(保 run_pipeline 三元形状)
    assert sink["result"] is result
    assert sink["report"].decision == SHALLOW_DECISION
    assert sink["picked"].startswith("浅层直判")
    assert out["path"] == "S"


def test_deep_component_calls_run_deep_and_fills_sink():
    calls = []
    sentinel_result = type("R", (), {"path": "B", "verdict": None})()
    sentinel_report = object()

    def fake_run_deep(alert_uid):
        calls.append(alert_uid)
        return sentinel_result, sentinel_report, "深度研判(recipe)"

    sink = {}
    comp = DeepInvestigationComponent(fake_run_deep, sink)

    out = asyncio.run(comp.invoke({"alert_uid": "a2"}, None, None))

    assert calls == ["a2"]                          # 调到深度 pipeline
    assert sink["result"] is sentinel_result
    assert sink["report"] is sentinel_report
    assert sink["picked"] == "深度研判(recipe)"
    assert out["path"] == "B"
