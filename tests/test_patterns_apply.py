"""快通道套模板 + 慢通道生成规则(patterns.apply)。

- result_from_rule:命中规则 → InvestigationResult(path A,0 LLM),处置目标用 bindings 换实例填。
- mint_rule_from_result:慢通道 verdict → 规则(FP 落 exculpatory、TP 落 incriminating;TP/FP 自动 active、可疑 pending;
  处置目标映射回 target_field 成模板)。
"""
from soc_agent.models import Alert, Verdict, Disposition, InvestigationResult
from soc_agent.patterns.apply import result_from_rule, mint_rule_from_result
from soc_agent.patterns.rule import PatternRule, VerdictTemplate, DispositionTemplate


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100801"})


def test_result_from_rule_fills_target_from_bindings():
    rule = PatternRule(skill="kerberoast", layer="incriminating", sig="s", sig_hash="h",
                       verdict=VerdictTemplate("true_positive", confidence=0.9, canonical_rationale="RC4 扇出"),
                       dispositions=[DispositionTemplate("disable_account", "account", "requester", "high")],
                       status="active")
    res = result_from_rule(_alert(), "kerberoast", rule, {"requester": "hacker2", "target_service": "svc"})
    assert res.path == "A"
    assert res.verdict.verdict == "true_positive"
    assert res.verdict.pattern == "h"                        # pattern_id 溯源
    assert res.dispositions[0].action == "disable_account"
    assert res.dispositions[0].target == "hacker2"           # ★换实例填对目标


def test_mint_active_for_tp_and_maps_target_field():
    disc = {"layers": [{"layer": "incriminating",
                        "features": {"req_is_machine": False, "same_domain": True, "enc": "RC4", "spn_fanout": ">=5"}}],
            "bindings": {"requester": "vagrant", "target_service": "sql_svc"}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="true_positive", confidence=0.9, rationale="RC4 扇出"),
                                 dispositions=[Disposition(action="disable_account", target="vagrant", risk="high")])
    rule = mint_rule_from_result("kerberoast", disc, result)
    assert rule.status == "active" and rule.layer == "incriminating"
    assert rule.verdict.verdict == "true_positive"
    assert rule.dispositions[0].target_field == "requester"  # vagrant→requester 反映射
    assert rule.dispositions[0].target_kind == "account"


def test_mint_pending_for_suspicious():
    disc = {"layers": [{"layer": "incriminating", "features": {"x": 1}}], "bindings": {}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="suspicious", lean="malicious", confidence=0.7, rationale="r"),
                                 dispositions=[])
    assert mint_rule_from_result("kerberoast", disc, result).status == "pending"


def test_mint_fp_uses_exculpatory_layer():
    disc = {"layers": [{"layer": "exculpatory", "features": {"req_is_machine": True, "same_domain": False}}],
            "bindings": {}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="false_positive", confidence=0.9, rationale="机器账号引荐"),
                                 dispositions=[])
    assert mint_rule_from_result("kerberoast", disc, result).layer == "exculpatory"


def test_roundtrip_mint_then_reuse():
    # 慢通道 vagrant→生成规则;换实例 hacker2 命中同规则→套模板填 hacker2
    disc1 = {"layers": [{"layer": "incriminating",
                         "features": {"req_is_machine": False, "same_domain": True, "enc": "RC4", "spn_fanout": ">=5"}}],
             "bindings": {"requester": "vagrant", "target_service": "sql_svc"}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="true_positive", confidence=0.9, rationale="RC4 扇出"),
                                 dispositions=[Disposition(action="disable_account", target="vagrant", risk="high")])
    rule = mint_rule_from_result("kerberoast", disc1, result)
    res2 = result_from_rule(_alert(), "kerberoast", rule, {"requester": "hacker2", "target_service": "svc2"})
    assert res2.dispositions[0].target == "hacker2"
