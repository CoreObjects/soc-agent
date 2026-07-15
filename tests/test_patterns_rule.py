"""PatternRule 的可复用经验形态 = verdict 模板 + 有序处置计划(PrimitiveStepTemplate 列表)。

step 的 params 按角色(entity_role)/字面量(literal)绑定,实例无关 —— 换实例填本告警的角色值即得具体处置。
pattern_id = sig_hash。
"""
from soc_agent.patterns.rule import PatternRule, PrimitiveStepTemplate, VerdictTemplate


def test_step_roundtrip_dict():
    s = PrimitiveStepTemplate(
        order=1, primitive="remove_from_group",
        params={"sam": {"source": "entity_role", "role": "requester"},
                "group": {"source": "literal", "value": "Quarantine"}},
        risk="high", on_failure="continue")
    d = s.to_dict()
    assert d == {"order": 1, "primitive": "remove_from_group",
                 "params": {"sam": {"source": "entity_role", "role": "requester"},
                            "group": {"source": "literal", "value": "Quarantine"}},
                 "risk": "high", "on_failure": "continue"}
    assert PrimitiveStepTemplate.from_dict(d) == s


def test_step_defaults():
    s = PrimitiveStepTemplate(order=0, primitive="collect_artifact",
                              params={"hostname": {"source": "entity_role", "role": "host"}})
    assert s.risk == "low"
    assert s.on_failure == "abort"


def test_pattern_rule_holds_ordered_plan_and_pattern_id():
    rule = PatternRule(
        skill="kerberoast", layer="incriminating", sig="s", sig_hash="deadbeef",
        verdict=VerdictTemplate("true_positive", confidence=0.9, canonical_rationale="RC4 扇出"),
        plan=[
            PrimitiveStepTemplate(order=1, primitive="collect_artifact",
                                  params={"hostname": {"source": "entity_role", "role": "req_host"}}),
            PrimitiveStepTemplate(order=2, primitive="disable_account",
                                  params={"sam": {"source": "entity_role", "role": "requester"}}, risk="high"),
        ],
        status="active")
    assert rule.pattern_id == "deadbeef"
    assert [s.primitive for s in rule.plan] == ["collect_artifact", "disable_account"]
    assert rule.plan[1].params["sam"]["role"] == "requester"


def test_pattern_rule_plan_defaults_empty():
    rule = PatternRule(skill="k", layer="incriminating", sig="s", sig_hash="h",
                       verdict=VerdictTemplate("suspicious", lean="malicious", confidence=0.5))
    assert rule.plan == []
