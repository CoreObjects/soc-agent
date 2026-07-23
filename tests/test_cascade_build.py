"""cascade 图接线/路由单测:用假浅层组件(免真 LLM 端点),验分叉去向 + sink 回填。

需 openjiuwen(Python 3.11+),在 .venv312 里跑。
"""
import asyncio

from openjiuwen.core.runner.runner import Runner
from openjiuwen.core.workflow import WorkflowComponent, create_workflow_session

from soc_agent.cascade.build import build_cascade_agent, build_cascade_workflow


class _FakeGraph:
    def __init__(self):
        self.written = []

    def write_result(self, alert_uid, result):
        self.written.append((alert_uid, result))


class _FakeShallow(WorkflowComponent):
    """假浅层:直接吐结构化结论,免真 LLM。"""

    def __init__(self, needs_deep):
        super().__init__()
        self._nd = needs_deep

    async def invoke(self, inputs, session, context):
        return {"needs_deep": self._nd,
                "verdict": "suspicious" if self._nd else "false_positive",
                "confidence": 0.8, "rationale": "test"}


def _run(needs_deep, force_deep):
    g = _FakeGraph()
    sink = {}
    calls = []

    def run_deep(uid):
        calls.append(uid)
        r = type("R", (), {"path": "B", "verdict": None})()
        return r, object(), "深度研判"

    async def _go():
        # session 必须在运行中的事件循环内创建(openJiuwen 内部用 get_event_loop)
        flow = build_cascade_workflow(g, run_deep, sink, shallow_comp=_FakeShallow(needs_deep))
        await flow.invoke(
            {"alert_view": "{}", "alert_uid": "a1", "force_deep": force_deep},
            create_workflow_session())

    asyncio.run(_go())
    return g, sink, calls


def test_route_terminal_when_benign_and_no_floor():
    g, sink, calls = _run(needs_deep=False, force_deep=False)
    assert calls == []                                 # 深度没跑
    assert sink["result"].path == "S"                  # 终局 FP
    assert sink["result"].verdict.verdict == "false_positive"
    assert len(g.written) == 1


def test_route_deep_when_needs_deep():
    g, sink, calls = _run(needs_deep=True, force_deep=False)
    assert calls == ["a1"]                              # 升级深度
    assert sink["picked"] == "深度研判"
    assert g.written == []                              # 终局没写台账


def test_force_deep_overrides_benign():
    g, sink, calls = _run(needs_deep=False, force_deep=True)
    assert calls == ["a1"]                              # 硬底线强制升级
    assert sink["picked"] == "深度研判"


def test_agent_runner_path_fills_sink():
    """run_cascade 实际走 WorkflowAgent + Runner.run_agent —— 验这条路也能填 sink。"""
    g = _FakeGraph()
    sink = {}
    calls = []

    def run_deep(uid):
        calls.append(uid)
        return type("R", (), {"path": "B", "verdict": None})(), object(), "深度研判"

    async def _go():
        agent = build_cascade_agent(g, run_deep, sink, shallow_comp=_FakeShallow(True))
        await Runner.run_agent(agent, {"alert_view": "{}", "alert_uid": "a1", "force_deep": False})

    asyncio.run(_go())
    assert calls == ["a1"]
    assert sink["picked"] == "深度研判"
