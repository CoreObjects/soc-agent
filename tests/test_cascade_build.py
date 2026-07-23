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

    def __init__(self, needs_deep, verdict=None):
        super().__init__()
        self._nd = needs_deep
        self._v = verdict or ("suspicious" if needs_deep else "false_positive")

    async def invoke(self, inputs, session, context):
        return {"needs_deep": self._nd, "verdict": self._v, "confidence": 0.8, "rationale": "test"}


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


class _FakePL:
    def __init__(self, node):
        self.policy = {"protected_hosts": [], "protected_accounts": []}
        self.llm_base = self.llm_model = self.llm_key = None
        self.llm_timeout = 600

        class _G:
            def get_alert(self, uid):
                return node
        self.graph = _G()


def test_shallow_probe_captures_decision():
    from soc_agent.cascade.build import build_shallow_probe
    sink = {}

    async def _go():
        flow = build_shallow_probe(sink, shallow_comp=_FakeShallow(True))
        await flow.invoke({"alert_view": "{}"}, create_workflow_session())

    asyncio.run(_go())
    assert sink["shallow"]["needs_deep"] is True
    assert sink["shallow"]["verdict"] == "suspicious"


def test_run_shallow_route_terminal_fp():
    import os
    from soc_agent.cascade.run import run_shallow
    pl = _FakePL({"alert_uid": "a1", "technique_ids": ["T1190"]})
    r = run_shallow(pl, "a1", shallow_comp=_FakeShallow(False))
    assert r["route"] == "terminal_fp"
    assert r["shallow"]["needs_deep"] is False
    assert r["force_deep"] is False
    # 抬过了 openJiuwen 工作流超时(默认 60 会掐断慢 qwen)
    assert os.environ.get("WORKFLOW_EXECUTE_TIMEOUT")


def test_run_shallow_route_escalate_on_needs_deep():
    from soc_agent.cascade.run import run_shallow
    pl = _FakePL({"alert_uid": "a1", "technique_ids": ["T1190"]})
    assert run_shallow(pl, "a1", shallow_comp=_FakeShallow(True))["route"] == "escalate"


def test_run_shallow_route_terminal_tp():
    # 放松后:浅层可直接下 TP(不升级)
    from soc_agent.cascade.run import run_shallow
    pl = _FakePL({"alert_uid": "a1", "technique_ids": ["T1190"]})
    r = run_shallow(pl, "a1", shallow_comp=_FakeShallow(False, verdict="true_positive"))
    assert r["route"] == "terminal_tp"


def test_run_shallow_no_floor_override():
    # floor 已退成空:高危技战术不再强制升级,升/不升全看浅层 LLM
    from soc_agent.cascade.run import run_shallow
    pl = _FakePL({"alert_uid": "a1", "technique_ids": ["T1003.006"]})
    r = run_shallow(pl, "a1", shallow_comp=_FakeShallow(False))
    assert r["force_deep"] is False and r["route"] == "terminal_fp"


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
