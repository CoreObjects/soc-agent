"""payload 签名匹配 `cascade.signature.payload_match` 单测(纯逻辑,不需 openjiuwen)。

match_spec = {"conditions": [{"path","op","value"}...], "verdict"}。所有 condition AND。
path 走 alert.raw(json.loads 后的点路径),外加顶层归一字段(rule_description/source/…)也可作根键。
"""
import json

from soc_agent.cascade.signature import payload_match
from soc_agent.models import Alert


def _alert(raw_obj=None, **top):
    top.setdefault("alert_uid", "a-1")
    if raw_obj is not None:
        top["raw"] = json.dumps(raw_obj)
    return Alert(**top)


_LSASS = {"data": {"win": {"system": {"eventID": "10"},
                           "eventdata": {"sourceImage": "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe",
                                         "ruleName": "LSASS_access"}}}}


def test_basename_eq_matches_process():
    spec = {"conditions": [{"path": "data.win.eventdata.sourceImage",
                            "op": "basename_eq", "value": "wazuh-agent.exe"}],
            "verdict": "false_positive"}
    assert payload_match(spec, _alert(_LSASS)) is True


def test_basename_eq_not_fooled_by_prefix():
    # ★安全:wazuh-agent.exe 不该命中 evil-wazuh-agent.exe
    raw = {"data": {"win": {"eventdata": {"sourceImage": "C:\\tmp\\evil-wazuh-agent.exe"}}}}
    spec = {"conditions": [{"path": "data.win.eventdata.sourceImage",
                            "op": "basename_eq", "value": "wazuh-agent.exe"}], "verdict": "false_positive"}
    assert payload_match(spec, _alert(raw)) is False


def test_basename_eq_case_insensitive():
    raw = {"data": {"win": {"eventdata": {"sourceImage": "C:\\X\\WAZUH-AGENT.EXE"}}}}
    spec = {"conditions": [{"path": "data.win.eventdata.sourceImage",
                            "op": "basename_eq", "value": "wazuh-agent.exe"}], "verdict": "false_positive"}
    assert payload_match(spec, _alert(raw)) is True


def test_contains_matches_filename_pattern():
    raw = {"data": {"win": {"eventdata": {"targetFilename": "C:\\Windows\\Temp\\__PSScriptPolicyTest_abc.ps1"}}}}
    spec = {"conditions": [{"path": "data.win.eventdata.targetFilename",
                            "op": "contains", "value": "__PSScriptPolicyTest"}], "verdict": "false_positive"}
    assert payload_match(spec, _alert(raw)) is True


def test_multiple_conditions_all_must_hold():
    spec = {"conditions": [
        {"path": "data.win.system.eventID", "op": "eq", "value": "10"},
        {"path": "data.win.eventdata.sourceImage", "op": "basename_eq", "value": "wazuh-agent.exe"},
    ], "verdict": "false_positive"}
    assert payload_match(spec, _alert(_LSASS)) is True
    # 换 eventID 就不该命中
    spec2 = {"conditions": [{"path": "data.win.system.eventID", "op": "eq", "value": "4624"},
                            {"path": "data.win.eventdata.sourceImage", "op": "basename_eq",
                             "value": "wazuh-agent.exe"}], "verdict": "false_positive"}
    assert payload_match(spec2, _alert(_LSASS)) is False


def test_top_level_field_as_root_key():
    # rule_description 是顶层归一字段,也能当 path 根键
    a = _alert(_LSASS, rule_description="Credential dumping via LSASS access by wazuh-agent.exe")
    spec = {"conditions": [{"path": "rule_description", "op": "contains", "value": "wazuh-agent.exe"}],
            "verdict": "false_positive"}
    assert payload_match(spec, a) is True


def test_missing_path_is_false():
    spec = {"conditions": [{"path": "data.win.eventdata.nope", "op": "eq", "value": "x"}],
            "verdict": "false_positive"}
    assert payload_match(spec, _alert(_LSASS)) is False


def test_empty_conditions_never_match():
    assert payload_match({"conditions": [], "verdict": "false_positive"}, _alert(_LSASS)) is False


def test_bad_raw_is_false():
    a = Alert(alert_uid="a-1", raw="not-json")
    assert payload_match({"conditions": [{"path": "x", "op": "eq", "value": "y"}]}, a) is False


def test_numeric_op():
    raw = {"data": {"win": {"eventdata": {"count": 42}}}}
    spec = {"conditions": [{"path": "data.win.eventdata.count", "op": "gte", "value": 20}],
            "verdict": "true_positive"}
    assert payload_match(spec, _alert(raw)) is True


# ---- distill_signature + sig_sediment(考试门)----
from dataclasses import dataclass                                             # noqa: E402
from soc_agent.cascade.signature import distill_signature, sig_sediment, PayloadCase  # noqa: E402
from soc_agent.experience.store import InMemoryExperienceStore                # noqa: E402
from soc_agent.models import InvestigationResult, Verdict                     # noqa: E402


class _FakeTC:
    def __init__(self, name, arguments):
        self.name, self.arguments = name, arguments


class _FakeResp:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


class _FakeLLM:
    """canned:返回一个 distill_signature 工具调用。"""
    def __init__(self, conditions, note="test"):
        self._c, self._n = conditions, note

    def chat(self, messages, tools=None, tool_choice=None):
        return _FakeResp([_FakeTC("distill_signature", {"conditions": self._c, "note": self._n})])


def _terminal(alert, verdict="false_positive"):
    v = Verdict(verdict=verdict, confidence=0.95, rationale="test", agent="qwenX")
    return InvestigationResult(alert_uid=alert.alert_uid, path="S", verdict=v, skill=None)


_GOOD_COND = {"path": "data.win.eventdata.sourceImage", "op": "basename_eq", "value": "wazuh-agent.exe"}


def test_distill_drops_overfit_ip_value():
    llm = _FakeLLM([{"path": "data.win.eventdata.sourceIp", "op": "eq", "value": "10.0.0.5"}, _GOOD_COND])
    spec = distill_signature(llm, _alert(_LSASS), "false_positive", "benign agent")
    paths = [c["path"] for c in spec["conditions"]]
    assert "data.win.eventdata.sourceImage" in paths
    assert "data.win.eventdata.sourceIp" not in paths          # IP 值被过拟合过滤
    assert spec["verdict"] == "false_positive"


def test_distill_no_conditions_returns_none():
    assert distill_signature(_FakeLLM([]), _alert(_LSASS), "false_positive", "x") is None


def test_sig_sediment_adds_on_pass():
    store = InMemoryExperienceStore()
    a = _alert(_LSASS, source="wazuh")
    exp, rep = sig_sediment(_FakeLLM([_GOOD_COND]), store, [], a, _terminal(a))
    assert exp is not None and rep["reason"] == "added"
    assert exp.kind == "payload" and exp.skill == "wazuh" and exp.verdict == "false_positive"
    assert len(store.active_for_skill("wazuh")) == 1


def test_sig_sediment_rejects_origin_miss():
    store = InMemoryExperienceStore()
    a = _alert(_LSASS, source="wazuh")
    bad = {"path": "data.win.eventdata.sourceImage", "op": "basename_eq", "value": "other.exe"}
    exp, rep = sig_sediment(_FakeLLM([bad]), store, [], a, _terminal(a))
    assert exp is None and rep["reason"] == "origin_miss"


def test_sig_sediment_rejects_regression_mishit():
    store = InMemoryExperienceStore()
    a = _alert(_LSASS, source="wazuh")                          # FP 规则(basename wazuh-agent.exe)
    # 反例:一条 TP 判例,其 raw 也含 sourceImage=wazuh-agent.exe → FP 规则会误命中它 → 拒
    opp = PayloadCase(alert_uid="tp1", source="wazuh", verdict="true_positive",
                      raw=json.dumps(_LSASS))
    exp, rep = sig_sediment(_FakeLLM([_GOOD_COND]), store, [opp], a, _terminal(a, "false_positive"))
    assert exp is None and rep["reason"] == "regression_mishit"


def test_sig_sediment_converged_bumps_not_adds():
    store = InMemoryExperienceStore()
    a = _alert(_LSASS, source="wazuh")
    sig_sediment(_FakeLLM([_GOOD_COND]), store, [], a, _terminal(a))          # 第一次加
    exp, rep = sig_sediment(_FakeLLM([_GOOD_COND]), store, [], a, _terminal(a))  # 同款再来
    assert exp is None and rep["reason"] == "converged"
    assert len(store.active_for_skill("wazuh")) == 1                          # 没重复插


def test_sig_sediment_skips_suspicious():
    store = InMemoryExperienceStore()
    a = _alert(_LSASS, source="wazuh")
    exp, rep = sig_sediment(_FakeLLM([_GOOD_COND]), store, [], a, _terminal(a, "suspicious"))
    assert exp is None


def test_sig_consult_hits_active_rule():
    from soc_agent.cascade.signature import sig_consult
    store = InMemoryExperienceStore()
    a = _alert(_LSASS, source="wazuh")
    sig_sediment(_FakeLLM([_GOOD_COND]), store, [], a, _terminal(a))     # 先入一条 FP 签名规则
    hit = sig_consult(store, _alert(_LSASS, source="wazuh"))
    assert hit is not None and hit.verdict == "false_positive"


def test_sig_consult_miss_returns_none():
    from soc_agent.cascade.signature import sig_consult
    assert sig_consult(InMemoryExperienceStore(), _alert(_LSASS, source="wazuh")) is None
