"""独立 composer 环节:拿研判结果 + 接口文档 + 该攻击的 response.md → 组装基础处置原语成有序计划。

产出 = list[PrimitiveStepTemplate](角色绑定、实例无关)。慢通道组一次 → 固化进规则模板 → 快通道 0 LLM 复用。
只认接口菜单里的原语(过滤掉幻觉/纯 inverse);参数按角色/字面量绑定。
"""
from types import SimpleNamespace

from soc_agent.composer import Composer, build_entity_frame
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import InvestigationResult, Verdict
from soc_agent.response.interface import Interface


def _iface():
    return Interface.from_dict({"version": "t", "primitives": [
        {"id": "collect_artifact", "category": "endpoint", "gating": "auto", "risk_default": "low",
         "target": {"kind": "host", "key_field": "hostname"},
         "params": [{"name": "hostname", "required": True, "source": "entity_role"}]},
        {"id": "disable_account", "category": "identity", "gating": "gated", "risk_default": "high",
         "target": {"kind": "account", "key_field": "sam"},
         "params": [{"name": "sam", "required": True, "source": "entity_role"}]},
        {"id": "enable_account", "category": "identity", "gating": "gated", "risk_default": "low",
         "target": {"kind": "account", "key_field": "sam"}, "planned_by_composer": False,
         "params": [{"name": "sam", "required": True, "source": "entity_role"}]},
    ]})


def _result():
    return InvestigationResult(alert_uid="a1", path="B",
                               verdict=Verdict(verdict="true_positive", confidence=0.9, rationale="RC4 扇出"))


def _skill():
    return SimpleNamespace(name="kerberoast")


def _compose(steps):
    return LLMResponse(tool_calls=[ToolCall("c", "compose_response", {"steps": steps})])


def test_build_entity_frame_from_bindings():
    ef = build_entity_frame({"requester": "hacker2", "req_host": "srv02", "empty": None,
                             "requester_domain": "NORTH"})
    assert ef["requester"] == {"value": "hacker2", "kind": "account"}
    assert ef["req_host"] == {"value": "srv02", "kind": "host"}     # _host → host kind
    assert "empty" not in ef                       # 空值角色不进
    assert "requester_domain" not in ef            # 路由用的 <role>_domain 不作可绑角色


def test_compose_drops_step_when_target_kind_mismatch():
    # collect_artifact 需要 host,却被绑到账号角色 requester → kind 不匹配 → 丢弃(防绑错,如真机把 host 绑到 vagrant)
    llm = FakeLLMClient([_compose([
        {"primitive": "collect_artifact", "params": {"hostname": {"role": "requester"}}},
        {"primitive": "disable_account", "params": {"sam": {"role": "requester"}}},
    ])])
    comp = Composer(llm=llm, iface=_iface())
    plan = comp.compose(_result(), {"bindings": {"requester": "hacker2"}}, _skill())
    assert [s.primitive for s in plan] == ["disable_account"]     # 只留 kind 匹配的 frame


def test_compose_returns_role_bound_ordered_plan():
    llm = FakeLLMClient([_compose([
        {"primitive": "collect_artifact", "params": {"hostname": {"role": "req_host"}}},
        {"primitive": "disable_account", "params": {"sam": {"role": "requester"}}, "risk": "high"},
    ])])
    comp = Composer(llm=llm, iface=_iface())
    disc = {"bindings": {"requester": "hacker2", "req_host": "srv02"}}
    plan = comp.compose(_result(), disc, _skill())
    assert [s.primitive for s in plan] == ["collect_artifact", "disable_account"]
    assert [s.order for s in plan] == [1, 2]
    assert plan[1].params == {"sam": {"source": "entity_role", "role": "requester"}}
    assert plan[0].risk == "low"                   # 缺省用接口 risk_default
    assert plan[1].risk == "high"


def test_compose_supports_literal_params():
    llm = FakeLLMClient([_compose([
        {"primitive": "disable_account",
         "params": {"sam": {"role": "requester"}}},
    ])])
    comp = Composer(llm=llm, iface=_iface())
    plan = comp.compose(_result(), {"bindings": {"requester": "u"}}, _skill())
    assert plan[0].params["sam"] == {"source": "entity_role", "role": "requester"}


def test_compose_drops_unknown_and_pure_inverse_primitives():
    llm = FakeLLMClient([_compose([
        {"primitive": "launch_missiles", "params": {}},          # 幻觉原语
        {"primitive": "enable_account", "params": {"sam": {"role": "requester"}}},  # 纯 inverse,composer 不该规划
        {"primitive": "disable_account", "params": {"sam": {"role": "requester"}}},
    ])])
    comp = Composer(llm=llm, iface=_iface())
    plan = comp.compose(_result(), {"bindings": {"requester": "u"}}, _skill())
    assert [s.primitive for s in plan] == ["disable_account"]     # 只留菜单内正向原语


def test_compose_empty_when_no_entities():
    comp = Composer(llm=FakeLLMClient([]), iface=_iface())
    assert comp.compose(_result(), {"bindings": {}}, _skill()) == []   # 无实体 → 空计划,不叫 LLM


def test_compose_with_real_interface_and_kerberoast_response_md():
    # 集成:真 interface.yaml(json 回退)+ 真 skills/identity/kerberoast/response.md
    from pathlib import Path
    from soc_agent.response.interface import default_interface
    root = Path(__file__).resolve().parents[1]
    kerb = SimpleNamespace(name="kerberoast", path=root / "skills" / "identity" / "kerberoast")
    llm = FakeLLMClient([_compose([
        {"primitive": "disable_account", "params": {"sam": {"role": "requester"}}, "risk": "high"},
        {"primitive": "expire_password", "params": {"sam": {"role": "target_service"}}, "risk": "high"},
    ])])
    comp = Composer(llm=llm, iface=default_interface())
    disc = {"bindings": {"requester": "hacker2", "target_service": "sql_svc"}}
    plan = comp.compose(_result(), disc, kerb)
    assert [s.primitive for s in plan] == ["disable_account", "expire_password"]
    # 响应策略(response.md)被注入进 composer 系统提示
    sys_prompt = llm.calls[0]["messages"][0]["content"]
    assert "红线" in sys_prompt and "target_service" in sys_prompt
    # 真接口菜单被用作原语枚举(含 disable_account,不含 break-glass 的 rotate_krbtgt)
    enum = llm.calls[0]["tools"][0]["function"]["parameters"]["properties"]["steps"]["items"]["properties"]["primitive"]["enum"]
    assert "disable_account" in enum and "rotate_krbtgt" not in enum
