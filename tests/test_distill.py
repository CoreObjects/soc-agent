"""经验蒸馏(qwen 沉淀第二类经验):选决定性发现子集(指纹)+ 真威胁写 DSL 规则。"""
from soc_agent.experience.distill import DISTILL, distill
from soc_agent.forensics import Finding
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import Verdict


class _Skill:
    name = "kerberoast"
    methodology = "方法论正文:先证伪→看权限→看扇出"


def _findings():
    return [Finding("kerberoast.rc4_requested", {"enc_type": "0x17"}),
            Finding("kerberoast.target_high_value", {"privileged": True}),
            Finding("kerberoast.spn_fanout", {"distinct_targets": 12, "bucket": "high"})]


def _llm(args):
    return FakeLLMClient([LLMResponse(tool_calls=[ToolCall(id="1", name=DISTILL, arguments=args)])])


def test_distill_threat_builds_fingerprint_and_rule():
    rule = {"and": [{"exists": "kerberoast.rc4_requested"},
                    {"in": ["kerberoast.spn_fanout:bucket", ["high", "massive"]]}]}
    llm = _llm({"decisive_finding_ids": ["kerberoast.rc4_requested", "kerberoast.spn_fanout"], "rule": rule})
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="RC4 扇出取票", agent="q")
    exp = distill(llm, _Skill(), _findings(), {"attacker_account": "hacker2"}, v,
                  agent_name="q", origin_case_id="c1")
    assert exp is not None
    assert exp.kind == "threat" and exp.verdict == "true_positive"
    assert set(exp.fingerprint["finding_ids"]) == {"kerberoast.rc4_requested", "kerberoast.spn_fanout"}
    assert exp.rule == rule
    assert exp.origin_case_id == "c1" and exp.created_by == "q" and exp.playbook == []


def test_distill_benign_drops_rule():
    llm = _llm({"decisive_finding_ids": ["kerberoast.requester_is_machine"], "rule": {"exists": "x"}})
    fs = [Finding("kerberoast.requester_is_machine", {"sam": "DC01$"}), Finding("kerberoast.cross_domain", {})]
    v = Verdict(verdict="false_positive", confidence=0.9, rationale="跨域机器账号引荐票", agent="q")
    exp = distill(llm, _Skill(), fs, {}, v)
    assert exp.kind == "benign_fp" and exp.rule is None        # 误报不留规则
    assert exp.fingerprint["finding_ids"] == ["kerberoast.requester_is_machine"]


def test_distill_suspicious_returns_none():
    v = Verdict(verdict="suspicious", lean="unknown", confidence=0.2, rationale="两可", agent="q")
    assert distill(_llm({"decisive_finding_ids": ["x"]}), _Skill(), _findings(), {}, v) is None


def test_distill_filters_invalid_ids_falls_back_to_all():
    llm = _llm({"decisive_finding_ids": ["nonexistent.id"]})   # 全非法 → 回退全部 finding
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="r", agent="q")
    exp = distill(llm, _Skill(), _findings(), {}, v)
    assert set(exp.fingerprint["finding_ids"]) == {f.finding_id for f in _findings()}


def test_distill_no_toolcall_returns_none():
    llm = FakeLLMClient([LLMResponse(content="没调工具")])
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="r", agent="q")
    assert distill(llm, _Skill(), _findings(), {}, v) is None


def test_distill_stores_note():
    # LLM 给的"本质"一句话要存下(供命中时喂 LLM 的上下文更有意义),不能丢
    llm = _llm({"decisive_finding_ids": ["kerberoast.rc4_requested"],
                "rule": {"exists": "kerberoast.rc4_requested"},
                "note": "普通域用户 RC4 取票攻击本质"})
    v = Verdict(verdict="true_positive", confidence=0.9, rationale="r", agent="q")
    exp = distill(llm, _Skill(), _findings(), {}, v)
    assert exp.note == "普通域用户 RC4 取票攻击本质"
    assert exp.to_dict()["note"] == "普通域用户 RC4 取票攻击本质"      # round-trip
