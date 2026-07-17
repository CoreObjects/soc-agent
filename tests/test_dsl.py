"""威胁判定规则 DSL 解释器:确定、可解释、畸形规则拒之。"""
import pytest

from soc_agent.experience.dsl import DSLError, evaluate, safe_evaluate
from soc_agent.forensics import Finding


def _kerb_tp():
    return [Finding("kerberoast.rc4_requested", {"enc_type": "0x17"}),
            Finding("kerberoast.spn_fanout", {"distinct_targets": 12, "bucket": "high"}),
            Finding("kerberoast.target_high_value", {"privileged": True})]


# ---- 叶子算子 ----
def test_exists():
    fs = _kerb_tp()
    assert evaluate({"exists": "kerberoast.rc4_requested"}, fs)[0] is True
    assert evaluate({"exists": "kerberoast.requester_is_machine"}, fs)[0] is False


def test_eq_existential():
    fs = _kerb_tp()
    assert evaluate({"eq": ["kerberoast.rc4_requested:enc_type", "0x17"]}, fs)[0] is True
    assert evaluate({"eq": ["kerberoast.rc4_requested:enc_type", "0x12"]}, fs)[0] is False


def test_numeric_compare():
    fs = _kerb_tp()
    assert evaluate({"gte": ["kerberoast.spn_fanout:distinct_targets", 5]}, fs)[0] is True
    assert evaluate({"gt": ["kerberoast.spn_fanout:distinct_targets", 12]}, fs)[0] is False
    assert evaluate({"lt": ["kerberoast.spn_fanout:distinct_targets", 20]}, fs)[0] is True


def test_in_bucket():
    fs = _kerb_tp()
    assert evaluate({"in": ["kerberoast.spn_fanout:bucket", ["high", "massive"]]}, fs)[0] is True
    assert evaluate({"in": ["kerberoast.spn_fanout:bucket", ["single", "low"]]}, fs)[0] is False


def test_same_source():
    fs = [Finding("a.x", {"actor": "hacker2"}), Finding("a.y", {"actor": "hacker2"}),
          Finding("a.z", {"actor": "other"})]
    assert evaluate({"same_source": ["a.x:actor", "a.y:actor"]}, fs)[0] is True
    assert evaluate({"same_source": ["a.x:actor", "a.z:actor"]}, fs)[0] is False


# ---- 布尔组合 ----
def test_and_or_not():
    fs = _kerb_tp()
    rule = {"and": [
        {"exists": "kerberoast.rc4_requested"},
        {"in": ["kerberoast.spn_fanout:bucket", ["high", "massive"]]},
        {"exists": "kerberoast.target_high_value"},
        {"not": {"exists": "kerberoast.requester_is_machine"}},
    ]}
    assert evaluate(rule, fs)[0] is True
    # 加一个机器账号白发现 → NOT 子句翻假 → 整体假
    fs2 = fs + [Finding("kerberoast.requester_is_machine", {"sam": "DC01$"})]
    assert evaluate(rule, fs2)[0] is False
    assert evaluate({"or": [{"exists": "x.none"}, {"exists": "kerberoast.rc4_requested"}]}, fs)[0] is True


def test_accepts_dict_findings_not_only_objects():
    fs = [{"finding_id": "a.b", "attrs": {"n": 7}}]
    assert evaluate({"gte": ["a.b:n", 5]}, fs)[0] is True


def test_trace_is_explainable():
    fs = _kerb_tp()
    hit, trace = evaluate({"and": [{"exists": "kerberoast.rc4_requested"}]}, fs)
    assert hit is True
    assert any(t.get("op") == "exists" and t.get("result") is True for t in trace)
    assert any(t.get("op") == "and" for t in trace)


# ---- 畸形规则 ----
def test_malformed_raises_dslerror():
    fs = _kerb_tp()
    with pytest.raises(DSLError):
        evaluate({"unknown_op": 1}, fs)
    with pytest.raises(DSLError):
        evaluate({"exists": "a", "extra": "b"}, fs)        # 多键
    with pytest.raises(DSLError):
        evaluate({"eq": ["no_colon_ref", 1]}, fs)          # ref 无 :attr
    with pytest.raises(DSLError):
        evaluate({"and": {"exists": "a"}}, fs)             # and 操作数非列表


def test_safe_evaluate_fails_closed():
    hit, trace = safe_evaluate({"unknown_op": 1}, _kerb_tp())
    assert hit is False
    assert any(t.get("op") == "error" for t in trace)
