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


# ---------- 走完整流水线的 pl(重排之后浅层在 run_pipeline 里面跑,光靠桩 graph 不够了)----------
class _DeepGraph(_Graph):
    def seed(self, alert):
        return {"event": {"event_code": "4769"}, "subject": None, "related": []}


class _Inv:
    """深度研判器桩:记调用次数,返回 path=B 的结论。"""
    def __init__(self, verdict="suspicious"):
        self.n = 0
        self._v = verdict

    def investigate(self, alert, seed=None, skill=None, forensics=None, match_report=None):
        from soc_agent.models import InvestigationResult, Verdict
        self.n += 1
        return InvestigationResult(alert_uid=alert.alert_uid, path="B",
                                   verdict=Verdict(verdict=self._v, confidence=0.5, agent="x"),
                                   skill=getattr(skill, "name", None))


_AUTO = object()          # 哨兵:区分"没传"和"显式传 None"


def _pl_deep(node, *, llm=None, shallow_llm=None, exp_store=_AUTO, verdict="suspicious"):
    """能真正跑完 run_pipeline 的 pl:多了 router / seed / 两个研判器。

    `exp_store=None` 表示**没有经验库** —— consult 会照常返回 FALLTHROUGH,
    但浅层终局后的 `_sig_learn` 会被跳过(它需要 sig_store)。想单看"浅层用了哪个 client"
    就传 None,免得签名蒸馏那次 LLM 混进计数里。
    """
    from soc_agent.graph import coverage
    coverage.reset_cache()                       # ★进程内 TTL 缓存会跨用例串味
    written = []
    skill = type("Sk", (), {"name": "kerberoast", "recipe": None, "is_generic": False,
                            "description": "k"})()
    inv = _Inv(verdict)
    router = type("R", (), {"route": staticmethod(lambda alert, seed=None: skill)})()
    pl = type("PL", (), {
        "graph": _DeepGraph(node, written), "router": router, "llm": llm, "shallow_llm": shallow_llm,
        "exp_store": InMemoryExperienceStore() if exp_store is _AUTO else exp_store,
        "case_store": None, "agent_inv": inv, "recipe_inv": inv, "policy": {},
        "agent_name": "x", "payload_corpus": None})()
    return pl, written, inv


def test_run_cascade_shallow_fp_terminates():
    """浅层判 FP → 仍然 path=S 终局、写一次台账、**不上深度**(只是它现在跑在经验比对之后)。"""
    llm = _FakeLLM({"needs_deep": False, "verdict": "false_positive", "confidence": 0.8, "rationale": "b"})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, llm=llm)
    result, report, picked = run_cascade(pl, "a1")
    assert result.path == "S" and result.verdict.verdict == "false_positive"
    assert report.decision == "SHALLOW_TERMINAL" and len(written) == 1
    assert inv.n == 0                                        # 没上深度


def test_run_cascade_escalates_to_deep():
    """浅层判 needs_deep → 必须真的走到深度研判器。

    ★"某类告警重排后再也走不到深度"是本次改动的头号风险,这条就是钉它的。
    """
    llm = _FakeLLM({"needs_deep": True, "verdict": "suspicious"})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, llm=llm)
    result, report, picked = run_cascade(pl, "a1")
    assert inv.n == 1 and result.path == "B"
    assert report.decision == "FALLTHROUGH" and len(written) == 1


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


# ---------- 双模型漏斗:浅层 9b / 深度 27b(shallow_llm 独立客户端)----------
def test_run_cascade_uses_shallow_llm_when_present():
    """pl.shallow_llm 存在 → 浅层分诊用它,pl.llm(深度)一次都不碰。"""
    fp = {"needs_deep": False, "verdict": "false_positive", "confidence": 0.7, "rationale": "b"}
    deep, shallow = _FakeLLM(fp), _FakeLLM(fp)                 # 两个可区分的 client
    pl, written, _inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"},
                                 llm=deep, shallow_llm=shallow, exp_store=None)
    result, report, picked = run_cascade(pl, "a1")
    assert report.decision == "SHALLOW_TERMINAL"
    assert shallow.n == 1 and deep.n == 0                      # 浅层走 shallow_llm、深度那个没被调


def test_run_cascade_falls_back_to_llm_without_shallow():
    """无 shallow_llm → 浅层回退用 pl.llm,行为不变。"""
    fp = {"needs_deep": False, "verdict": "false_positive", "confidence": 0.7, "rationale": "b"}
    deep = _FakeLLM(fp)
    pl, written, _inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"},
                                 llm=deep, shallow_llm=None, exp_store=None)
    result, report, picked = run_cascade(pl, "a1")
    assert report.decision == "SHALLOW_TERMINAL" and deep.n == 1


def test_浅层终局的签名蒸馏用的是深度模型():
    """★现状钉桩(**不是这次重排引入的,原本就这样**):浅层判 FP 终局之后,`_sig_learn`
    蒸 payload 签名走的是 `pl.llm`(27b),而不是浅层那个 9b —— 尽管这是浅层通道自己的收尾。

    `sig_sediment` 里有收敛守卫(同款签名已覆盖就只 bump 不蒸),所以只有**新 payload**
    才真烧;但那部分是实打实的 27b。要不要改用 9b 是单独的取舍(会影响学到的签名质量),另议。
    这条在这里是为了:改动它的时候必须是**有意**的,而不是某天顺手改掉没人发现。
    """
    fp = {"needs_deep": False, "verdict": "false_positive", "confidence": 0.7, "rationale": "b"}
    deep, shallow = _FakeLLM(fp), _FakeLLM(fp)
    pl, written, _inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"},
                                 llm=deep, shallow_llm=shallow)      # 这次**带**经验库
    run_cascade(pl, "a1")
    assert shallow.n == 1                                      # 分诊:9b
    assert deep.n == 1                                         # 签名蒸馏:27b ← 就是这一次


# ---------- ★重排等价性:浅层从"路由之前"挪到"经验比对之后" ----------
def _auto_fp_report():
    from soc_agent.experience.consult import MatchReport
    exp = type("E", (), {"exp_id": "e1" * 8, "skill": "kerberoast", "playbook": [],
                         "origin_verdict_id": "v1", "kind": "benign_fp"})()
    return MatchReport(decision="AUTO_FP", benign_fp_hits=[exp], chosen=exp)


def test_经验命中时浅层一次都不跑(monkeypatch):
    """★这就是重排要拿的全部收益:实测 56.9% 的告警(path=A)原本白烧一次 9b。"""
    import soc_agent.cli as cli
    shallow = _FakeLLM({"needs_deep": False, "verdict": "false_positive"})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"},
                                llm=_FakeLLM(None), shallow_llm=shallow)
    monkeypatch.setattr(cli, "consult", lambda *a, **k: _auto_fp_report())
    result, report, picked = run_cascade(pl, "a1")
    assert result.path == "A" and report.decision == "AUTO_FP"
    assert shallow.n == 0 and inv.n == 0                       # ★零 LLM
    assert len(written) == 1


def test_TP签名命中时不给浅层机会_直上深度():
    """决策 A 的语义:TP 签名 ⇒ 强制深度。重排后必须还是这样(浅层钩子压根不传)。"""
    store = InMemoryExperienceStore()
    store.add(Experience(skill="wazuh", kind="payload", verdict="true_positive", fingerprint={},
                         rule={"conditions": [{"path": "data.win.eventdata.sourceImage",
                                               "op": "basename_eq", "value": "evil.exe"}]},
                         origin_verdict_id="v0"))
    raw = _json.dumps({"data": {"win": {"eventdata": {"sourceImage": "C:/x/evil.exe"}}}})
    shallow = _FakeLLM({"needs_deep": False, "verdict": "false_positive"})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": raw},
                                llm=_FakeLLM(None), shallow_llm=shallow, exp_store=store)
    result, report, picked = run_cascade(pl, "a1")
    assert shallow.n == 0                                      # 浅层没机会把它判成 FP
    assert inv.n == 1 and result.path == "B"


def test_浅层终局不进语料也不沉淀经验(monkeypatch):
    """与重排之前逐字节一致:只写台账。

    ★沉淀会再烧一次 27b 去蒸馏,正好和这次重排要省的东西相反;而浅层终局的 result
      没有 findings,存进语料只是些永远不会点火的空壳。
    """
    import soc_agent.cli as cli
    seen = []
    monkeypatch.setattr(cli, "sediment", lambda *a, **k: seen.append("sediment"))
    monkeypatch.setattr(cli, "snapshot_case", lambda *a, **k: seen.append("case"))
    llm = _FakeLLM({"needs_deep": False, "verdict": "false_positive", "confidence": 0.8})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, llm=llm)
    run_cascade(pl, "a1")
    assert seen == []


def test_升级到深度的仍然照常沉淀(monkeypatch):
    """反面:真走到深度的那批,回流沉淀不能被这次重排顺手关掉。"""
    import soc_agent.cli as cli
    seen = []
    monkeypatch.setattr(cli, "sediment", lambda *a, **k: seen.append("sediment"))
    llm = _FakeLLM({"needs_deep": True, "verdict": "suspicious"})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"}, llm=llm)
    run_cascade(pl, "a1")
    assert seen == ["sediment"] and inv.n == 1


def test_不传_triage_就是重排之前的流水线():
    """回滚位:run_pipeline 不带钩子 = 加钩子之前的行为(浅层根本不参与)。"""
    from soc_agent.cli import run_pipeline
    shallow = _FakeLLM({"needs_deep": False, "verdict": "false_positive"})
    pl, written, inv = _pl_deep({"alert_uid": "a1", "source": "wazuh", "raw": "{}"},
                                llm=_FakeLLM(None), shallow_llm=shallow)
    result, report, picked = run_pipeline(pl, "a1")
    assert shallow.n == 0 and inv.n == 1 and result.path == "B"


def test_config_shallow_llm_model_from_env():
    from soc_agent.config import Config
    c = Config.from_env(env={"SHALLOW_LLM_MODEL": "qwen3.5-9b"})
    assert c.shallow_llm_model == "qwen3.5-9b"


def test_config_shallow_llm_model_defaults_empty():
    from soc_agent.config import Config
    assert Config.from_env(env={}).shallow_llm_model == ""
