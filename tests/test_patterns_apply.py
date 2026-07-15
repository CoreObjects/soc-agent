"""快通道套模板 + 慢通道生成规则(patterns.apply)。

- result_from_rule:命中规则的有序计划 → InvestigationResult(path A,0 LLM),逐步按角色换实例填目标。
- mint_rule_from_result:慢通道 verdict(+composer plan)→ 规则(FP→exculpatory、TP→incriminating;
  TP/FP 自动 active、可疑 pending);★不再值相等反查,plan 由 composer 直接给角色绑定。
"""
from soc_agent.models import Alert, Disposition, InvestigationResult, Verdict
from soc_agent.patterns.apply import dispositions_from_plan, mint_rule_from_result, result_from_rule
from soc_agent.patterns.rule import PatternRule, PrimitiveStepTemplate, VerdictTemplate


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100801"})


def _step(order, primitive, role_or_params, risk="low"):
    params = role_or_params if isinstance(role_or_params, dict) else \
        {"sam": {"source": "entity_role", "role": role_or_params}}
    return PrimitiveStepTemplate(order=order, primitive=primitive, params=params, risk=risk)


def test_result_from_rule_fills_target_from_bindings():
    rule = PatternRule(skill="kerberoast", layer="incriminating", sig="s", sig_hash="h",
                       verdict=VerdictTemplate("true_positive", confidence=0.9, canonical_rationale="RC4 扇出"),
                       plan=[_step(1, "disable_account", "requester", "high")], status="active")
    res = result_from_rule(_alert(), "kerberoast", rule, {"requester": "hacker2", "target_service": "svc"})
    assert res.path == "A"
    assert res.verdict.verdict == "true_positive"
    assert res.verdict.pattern == "h"                        # pattern_id 溯源
    assert res.dispositions[0].action == "disable_account"
    assert res.dispositions[0].target == "hacker2"           # ★换实例填对目标
    assert res.dispositions[0].target_kind == "account"


def test_result_from_rule_replays_multi_step_plan_in_order():
    rule = PatternRule(skill="kerberoast", layer="incriminating", sig="s", sig_hash="h2",
                       verdict=VerdictTemplate("true_positive", confidence=0.9, canonical_rationale="r"),
                       plan=[
                           _step(1, "collect_artifact", {"hostname": {"source": "entity_role", "role": "req_host"}}),
                           _step(2, "remove_from_group",
                                 {"sam": {"source": "entity_role", "role": "requester"},
                                  "group": {"source": "literal", "value": "Quarantine"}}, "high"),
                           _step(3, "disable_account", "requester", "high"),
                       ], status="active")
    res = result_from_rule(_alert(), "kerberoast", rule,
                           {"requester": "hacker2", "req_host": "srv02"})
    assert [d.action for d in res.dispositions] == ["collect_artifact", "remove_from_group", "disable_account"]
    assert res.dispositions[0].target == "srv02"             # collect on host
    assert res.dispositions[1].target == "hacker2"           # remove_from_group 主目标=账号
    assert res.dispositions[1].params["group"] == "Quarantine"  # 字面量参数带上
    assert res.dispositions[2].target == "hacker2"


def test_mint_active_for_tp_with_composer_plan():
    disc = {"layers": [{"layer": "incriminating",
                        "features": {"req_is_machine": False, "same_domain": True, "enc": "RC4", "spn_fanout": ">=5"}}],
            "bindings": {"requester": "vagrant", "target_service": "sql_svc"}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="true_positive", confidence=0.9, rationale="RC4 扇出"))
    plan = [_step(1, "disable_account", "requester", "high")]
    rule = mint_rule_from_result("kerberoast", disc, result, plan=plan)
    assert rule.status == "active" and rule.layer == "incriminating"
    assert rule.verdict.verdict == "true_positive"
    assert rule.plan[0].primitive == "disable_account"
    assert rule.plan[0].params["sam"]["role"] == "requester"   # ★角色直存,无反查


def test_mint_verdict_only_when_no_plan():
    disc = {"layers": [{"layer": "incriminating", "features": {"x": 1}}], "bindings": {}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="true_positive", confidence=0.9, rationale="r"))
    rule = mint_rule_from_result("kerberoast", disc, result)   # 无 plan
    assert rule.status == "active" and rule.plan == []          # 先只铸 verdict 规则


def test_mint_pending_for_suspicious():
    disc = {"layers": [{"layer": "incriminating", "features": {"x": 1}}], "bindings": {}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="suspicious", lean="malicious", confidence=0.7, rationale="r"))
    assert mint_rule_from_result("kerberoast", disc, result).status == "pending"


def test_mint_fp_uses_exculpatory_layer():
    disc = {"layers": [{"layer": "exculpatory", "features": {"req_is_machine": True, "same_domain": False}}],
            "bindings": {}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="false_positive", confidence=0.9, rationale="机器账号引荐"))
    assert mint_rule_from_result("kerberoast", disc, result).layer == "exculpatory"


def test_dispositions_from_plan_applies_guardrail():
    # composer 出的计划落地为具体处置时,仍过护栏:受保护账号 → 降级 escalate
    plan = [_step(1, "disable_account", "requester", "high")]
    disps = dispositions_from_plan(plan, {"requester": "krbtgt"},
                                   policy={"protected_hosts": [], "protected_accounts": ["krbtgt"]})
    assert disps[0].action == "escalate"           # 护栏在 composer 落地路径上生效


def test_roundtrip_mint_then_reuse():
    # 慢通道 vagrant + composer 计划 → 生成规则;换实例 hacker2 命中同规则 → 套计划填 hacker2
    disc1 = {"layers": [{"layer": "incriminating",
                         "features": {"req_is_machine": False, "same_domain": True, "enc": "RC4", "spn_fanout": ">=5"}}],
             "bindings": {"requester": "vagrant", "target_service": "sql_svc"}}
    result = InvestigationResult(alert_uid="a1", path="B",
                                 verdict=Verdict(verdict="true_positive", confidence=0.9, rationale="RC4 扇出"))
    plan = [_step(1, "disable_account", "requester", "high")]
    rule = mint_rule_from_result("kerberoast", disc1, result, plan=plan)
    res2 = result_from_rule(_alert(), "kerberoast", rule, {"requester": "hacker2", "target_service": "svc2"})
    assert res2.dispositions[0].target == "hacker2"
