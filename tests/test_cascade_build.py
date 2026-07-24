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


def _run(needs_deep, force_deep, verdict=None):
    g = _FakeGraph()
    sink = {}
    calls = []

    def run_deep(uid):
        calls.append(uid)
        r = type("R", (), {"path": "B", "verdict": None})()
        return r, object(), "深度研判"

    async def _go():
        # session 必须在运行中的事件循环内创建(openJiuwen 内部用 get_event_loop)
        flow = build_cascade_workflow(g, run_deep, sink, shallow_comp=_FakeShallow(needs_deep, verdict))
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


def test_route_deep_when_shallow_tp():
    # ★决策 A:浅层判 true_positive(needs_deep=False)→ BranchRouter 仍升级深度(不终局)
    g, sink, calls = _run(needs_deep=False, force_deep=False, verdict="true_positive")
    assert calls == ["a1"]                              # TP 升级了
    assert sink["picked"] == "深度研判"
    assert g.written == []                              # TP 没被当终局写台账


def test_route_deep_when_shallow_suspicious():
    # ★决策 A:suspicious 也升级(不终局)
    g, sink, calls = _run(needs_deep=False, force_deep=False, verdict="suspicious")
    assert calls == ["a1"]
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


def test_run_shallow_tp_escalates_decision_a():
    # ★决策 A:浅层判 TP 不再终局,一律升级深度
    from soc_agent.cascade.run import run_shallow
    pl = _FakePL({"alert_uid": "a1", "technique_ids": ["T1190"]})
    r = run_shallow(pl, "a1", shallow_comp=_FakeShallow(False, verdict="true_positive"))
    assert r["route"] == "escalate"


def test_run_shallow_sig_tp_hit_escalates():
    # ★决策 A:命中 TP 签名 → 升级深度(不短路复用),但仍 bump 命中计数
    import json as _json
    from soc_agent.cascade.run import run_shallow
    from soc_agent.experience.store import Experience, InMemoryExperienceStore
    store = InMemoryExperienceStore()
    store.add(Experience(skill="wazuh", kind="payload", verdict="true_positive", fingerprint={},
                         rule={"conditions": [{"path": "data.win.system.eventID", "op": "eq", "value": "4769"}]},
                         origin_verdict_id="v0"))
    raw = _json.dumps({"data": {"win": {"system": {"eventID": "4769"}}}})
    pl = _FakePL({"alert_uid": "a1", "source": "wazuh", "raw": raw, "technique_ids": ["T1558.003"]})
    r = run_shallow(pl, "a1", sig_store=store)
    assert r["route"] == "escalate" and r["reused"] is False
    assert store.get(store.all()[0].exp_id).hit_count == 1


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


def test_run_cascade_sig_reuse_skips_agent():
    """production:签名库命中 → 复用 verdict、写台账、返回,不跑 openJiuwen agent(零 qwen)。"""
    import json as _json
    from soc_agent.cascade.run import run_cascade
    from soc_agent.experience.store import Experience, InMemoryExperienceStore

    store = InMemoryExperienceStore()
    store.add(Experience(skill="wazuh", kind="payload", verdict="false_positive", fingerprint={},
                         rule={"conditions": [{"path": "data.win.eventdata.sourceImage",
                                               "op": "basename_eq", "value": "wazuh-agent.exe"}]},
                         origin_verdict_id="v0"))
    raw = _json.dumps({"data": {"win": {"eventdata": {"sourceImage": "C:/x/wazuh-agent.exe"}}}})
    node = {"alert_uid": "a1", "source": "wazuh", "raw": raw}
    written = []

    class _G:
        def get_alert(self, uid):
            return node

        def write_result(self, uid, result):
            written.append((uid, result))

    pl = type("PL", (), {"exp_store": store, "graph": _G(), "policy": {}, "agent_name": "x",
                         "llm_base": None, "llm_model": None, "llm_key": None, "llm_timeout": 600,
                         "payload_corpus": None})()
    result, report, picked = run_cascade(pl, "a1")
    assert result.verdict.verdict == "false_positive" and result.path == "S"
    assert report.decision == "SIG_REUSE"
    assert len(written) == 1                       # 写了台账
    assert store.get(store.all()[0].exp_id).hit_count == 1   # bump 了命中


def _cascade_pl(node, written):
    class _G:
        def get_alert(self, uid):
            return node

        def write_result(self, uid, result):
            written.append((uid, result))

    return type("PL", (), {"exp_store": None, "graph": _G(), "policy": {}, "agent_name": "x",
                           "llm_base": None, "llm_model": None, "llm_key": None, "llm_timeout": 600,
                           "payload_corpus": None})()


def test_run_cascade_shallow_fp_terminates(monkeypatch):
    """浅层判 FP → 终局写台账(path=S),不升级深度。openJiuwen 浅层被 mock,不打真端点。"""
    from soc_agent.cascade import run as runmod
    written = []
    pl = _cascade_pl({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, written)
    monkeypatch.setattr(runmod, "_shallow_decision",
                        lambda pl, alert: {"needs_deep": False, "verdict": "false_positive",
                                           "confidence": 0.9, "rationale": "benign"})
    result, report, picked = runmod.run_cascade(pl, "a1")
    assert result.path == "S" and result.verdict.verdict == "false_positive"
    assert report.decision == "SHALLOW_TERMINAL" and len(written) == 1


def test_run_cascade_escalates_to_deep(monkeypatch):
    """★决策 A:浅层非 FP(suspicious/TP/needs_deep)→ 直接跑 run_pipeline(不经 openJiuwen 单例)。"""
    from soc_agent.cascade import run as runmod
    import soc_agent.cli as cli
    pl = _cascade_pl({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, [])
    monkeypatch.setattr(runmod, "_shallow_decision",
                        lambda pl, alert: {"needs_deep": True, "verdict": "suspicious"})
    called = []
    monkeypatch.setattr(cli, "run_pipeline",
                        lambda pl, uid, mode="recipe": (called.append(uid), ("R", "REP", "深度研判"))[1])
    result, report, picked = runmod.run_cascade(pl, "a1")
    assert called == ["a1"] and picked == "深度研判"      # 升级走了 run_pipeline
