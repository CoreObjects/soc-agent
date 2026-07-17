"""处置计划机件(composer/plan.py):PrimitiveStepTemplate + 计划→具体处置(过护栏)。

原在 patterns/(第二类经验)包,随其删除搬来;这里只测【处置侧】:模板序列化 + 角色/字面量绑定填目标 +
账号域注入 + 护栏。与已删的攻击模式规则库/签名无关。
"""
from soc_agent.composer.plan import PrimitiveStepTemplate, dispositions_from_plan


def _step(order, primitive, role_or_params, risk="low"):
    params = role_or_params if isinstance(role_or_params, dict) else \
        {"sam": {"source": "entity_role", "role": role_or_params}}
    return PrimitiveStepTemplate(order=order, primitive=primitive, params=params, risk=risk)


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
    assert s.risk == "low" and s.on_failure == "abort"


def test_dispositions_fill_target_from_bindings():
    disps = dispositions_from_plan([_step(1, "disable_account", "requester", "high")],
                                   {"requester": "hacker2", "target_service": "svc"})
    assert disps[0].action == "disable_account"
    assert disps[0].target == "hacker2"                      # ★换实例填对目标
    assert disps[0].target_kind == "account"


def test_dispositions_multi_step_order_and_literal():
    plan = [_step(1, "collect_artifact", {"hostname": {"source": "entity_role", "role": "req_host"}}),
            _step(2, "remove_from_group",
                  {"sam": {"source": "entity_role", "role": "requester"},
                   "group": {"source": "literal", "value": "Quarantine"}}, "high"),
            _step(3, "disable_account", "requester", "high")]
    disps = dispositions_from_plan(plan, {"requester": "hacker2", "req_host": "srv02"})
    assert [d.action for d in disps] == ["collect_artifact", "remove_from_group", "disable_account"]
    assert disps[0].target == "srv02"                        # collect on host
    assert disps[1].target == "hacker2"                      # remove_from_group 主目标=账号
    assert disps[1].params["group"] == "Quarantine"          # 字面量参数带上
    assert disps[2].target == "hacker2"


def test_dispositions_account_domain_injection():
    # 账号类原语:从 <role>_domain 注入目标账号的域,供 appliance 路由到该域 DC
    disps = dispositions_from_plan([_step(1, "expire_password", "target_service", "high")],
                                   {"target_service": "sql_svc", "target_service_domain": "essos.local"})
    assert disps[0].target == "sql_svc"
    assert disps[0].params["domain"] == "essos.local"


def test_dispositions_apply_guardrail():
    # 落地为具体处置时仍过护栏:受保护账号 → 降级 escalate
    disps = dispositions_from_plan([_step(1, "disable_account", "requester", "high")],
                                   {"requester": "krbtgt"},
                                   policy={"protected_hosts": [], "protected_accounts": ["krbtgt"]})
    assert disps[0].action == "escalate"
