"""cascade run_cascade / run_shallow / shallow_triage 单测。

浅层已从 openJiuwen 换成 QwenClient(tool-call)→ 全 mock(llm + graph),**无 openjiuwen**,3.10 可跑。
"""
import json as _json

from soc_agent.cascade.run import run_cascade, run_shallow, shallow_triage
from soc_agent.experience.store import Experience, InMemoryExperienceStore


class _TC:
    def __init__(self, name, arguments):
        self.name, self.arguments = name, arguments


class _Resp:
    def __init__(self, tool_calls):
        self.tool_calls, self.content = tool_calls, ""


class _FakeLLM:
    """据构造的 args 返回一个 shallow_triage 工具调用;args=None → 无 tool_calls(逼 shallow_triage 走兜底)。"""
    def __init__(self, args):
        self._args = args
        self.n = 0

    def chat(self, messages, tools=None, tool_choice=None):
        self.n += 1
        return _Resp([] if self._args is None else [_TC("shallow_triage", self._args)])


class _Graph:
    def __init__(self, node, written):
        self._node, self._written = node, written

    def get_alert(self, uid):
        return self._node

    def write_result(self, uid, result):
        self._written.append((uid, result))


def _pl(node, *, llm=None, exp_store=None):
    written = []
    pl = type("PL", (), {"graph": _Graph(node, written), "llm": llm, "exp_store": exp_store,
                         "policy": {}, "agent_name": "x", "payload_corpus": None})()
    return pl, written


class _Alert:
    def __init__(self, **kw):
        for k in ("alert_uid", "rule_description", "source", "sensor", "severity", "technique_ids", "raw"):
            setattr(self, k, kw.get(k))


# ---------- shallow_triage(QwenClient tool-call)----------
def test_shallow_triage_parses_tool_call():
    llm = _FakeLLM({"needs_deep": False, "verdict": "false_positive", "confidence": 0.9, "rationale": "benign"})
    r = shallow_triage(llm, _Alert(alert_uid="a1", raw="{}"))
    assert r == {"needs_deep": False, "verdict": "false_positive", "confidence": 0.9, "rationale": "benign"}


def test_shallow_triage_bad_verdict_defaults_suspicious():
    r = shallow_triage(_FakeLLM({"needs_deep": False, "verdict": "weird"}), _Alert(alert_uid="a1"))
    assert r["verdict"] == "suspicious"


def test_shallow_triage_no_toolcall_escalates():
    r = shallow_triage(_FakeLLM(None), _Alert(alert_uid="a1"))
    assert r["needs_deep"] is True and r["verdict"] == "suspicious"


# ---------- run_cascade ----------
def test_run_cascade_sig_fp_reuse():
    store = InMemoryExperienceStore()
    store.add(Experience(skill="wazuh", kind="payload", verdict="false_positive", fingerprint={},
                         rule={"conditions": [{"path": "data.win.eventdata.sourceImage",
                                               "op": "basename_eq", "value": "wazuh-agent.exe"}]},
                         origin_verdict_id="v0"))
    raw = _json.dumps({"data": {"win": {"eventdata": {"sourceImage": "C:/x/wazuh-agent.exe"}}}})
    pl, written = _pl({"alert_uid": "a1", "source": "wazuh", "raw": raw}, exp_store=store, llm=_FakeLLM(None))
    result, report, picked = run_cascade(pl, "a1")
    assert result.path == "S" and result.verdict.verdict == "false_positive"
    assert report.decision == "SIG_REUSE" and len(written) == 1
    assert store.get(store.all()[0].exp_id).hit_count == 1


def test_run_cascade_shallow_fp_terminates():
    llm = _FakeLLM({"needs_deep": False, "verdict": "false_positive", "confidence": 0.8, "rationale": "b"})
    pl, written = _pl({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, exp_store=None, llm=llm)
    result, report, picked = run_cascade(pl, "a1")
    assert result.path == "S" and result.verdict.verdict == "false_positive"
    assert report.decision == "SHALLOW_TERMINAL" and len(written) == 1


def test_run_cascade_escalates_to_deep(monkeypatch):
    import soc_agent.cli as cli
    llm = _FakeLLM({"needs_deep": True, "verdict": "suspicious"})
    pl, _ = _pl({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, exp_store=None, llm=llm)
    called = []
    monkeypatch.setattr(cli, "run_pipeline",
                        lambda pl, uid, mode="recipe": (called.append(uid), ("R", "REP", "深度研判"))[1])
    result, report, picked = run_cascade(pl, "a1")
    assert called == ["a1"] and picked == "深度研判"      # 决策 A:非 FP → run_pipeline


# ---------- run_shallow(shallow_fn 注入)----------
def _pl_sh(node):
    return type("PL", (), {"graph": _Graph(node, []), "llm": None, "policy": {}, "agent_name": "x"})()


def test_run_shallow_terminal_fp():
    pl = _pl_sh({"alert_uid": "a1", "technique_ids": ["T1190"], "source": "s", "raw": "{}"})
    r = run_shallow(pl, "a1", shallow_fn=lambda p, a: {"needs_deep": False, "verdict": "false_positive"})
    assert r["route"] == "terminal_fp"


def test_run_shallow_escalate_needs_deep():
    pl = _pl_sh({"alert_uid": "a1", "technique_ids": ["T1190"], "source": "s", "raw": "{}"})
    r = run_shallow(pl, "a1", shallow_fn=lambda p, a: {"needs_deep": True, "verdict": "suspicious"})
    assert r["route"] == "escalate"


def test_run_shallow_tp_escalates_decision_a():
    pl = _pl_sh({"alert_uid": "a1", "technique_ids": ["T1190"], "source": "s", "raw": "{}"})
    r = run_shallow(pl, "a1", shallow_fn=lambda p, a: {"needs_deep": False, "verdict": "true_positive"})
    assert r["route"] == "escalate"                       # 决策 A:浅层 TP 不终局


def test_run_shallow_sig_fp_reuse():
    store = InMemoryExperienceStore()
    store.add(Experience(skill="wazuh", kind="payload", verdict="false_positive", fingerprint={},
                         rule={"conditions": [{"path": "data.win.system.eventID", "op": "eq", "value": "1"}]},
                         origin_verdict_id="v0"))
    raw = _json.dumps({"data": {"win": {"system": {"eventID": "1"}}}})
    r = run_shallow(_pl_sh({"alert_uid": "a1", "source": "wazuh", "raw": raw}), "a1", sig_store=store)
    assert r["route"] == "reuse_fp" and r["reused"] is True


def test_run_shallow_sig_tp_escalates():
    store = InMemoryExperienceStore()
    store.add(Experience(skill="wazuh", kind="payload", verdict="true_positive", fingerprint={},
                         rule={"conditions": [{"path": "data.win.system.eventID", "op": "eq", "value": "4769"}]},
                         origin_verdict_id="v0"))
    raw = _json.dumps({"data": {"win": {"system": {"eventID": "4769"}}}})
    r = run_shallow(_pl_sh({"alert_uid": "a1", "source": "wazuh", "raw": raw}), "a1", sig_store=store)
    assert r["route"] == "escalate" and r["reused"] is False
    assert store.get(store.all()[0].exp_id).hit_count == 1
