"""处置计划的数据形态 + 计划→具体处置(过护栏)。

原属 patterns/(第二类经验:签名→规则)包,但这两样是【处置侧】机件、与"攻击模式规则库"无关:
- PrimitiveStepTemplate:一步处置原语 + 参数按角色/字面量绑定(实例无关);composer 产出、response/ledger 消费。
- dispositions_from_plan:有序计划 + 本告警 bindings → 具体 Disposition(过护栏)。
第二类经验删除后搬来此处,慢研判→处置的驱动器日后重设计时复用。
"""
from dataclasses import dataclass, field

from ..disposition import apply_guardrail
from ..models import Disposition
from ..response import default_interface

__all__ = ["PrimitiveStepTemplate", "dispositions_from_plan"]


@dataclass
class PrimitiveStepTemplate:
    """处置计划里的一步(实例无关):调哪个原语 + 每个参数绑哪个角色/字面量。

    params: {param_name: {"source": "entity_role", "role": <角色名>}
                       |  {"source": "literal", "value": <字面量>}}
    """
    order: int
    primitive: str
    params: dict = field(default_factory=dict)
    risk: str = "low"
    on_failure: str = "abort"       # abort | continue | rollback_all

    def to_dict(self) -> dict:
        return {"order": self.order, "primitive": self.primitive,
                "params": self.params, "risk": self.risk, "on_failure": self.on_failure}

    @classmethod
    def from_dict(cls, d: dict) -> "PrimitiveStepTemplate":
        return cls(order=d["order"], primitive=d["primitive"], params=dict(d.get("params") or {}),
                   risk=d.get("risk", "low"), on_failure=d.get("on_failure", "abort"))


def _resolve_params(params: dict, bindings: dict) -> dict:
    """step 的参数规格(role/literal)→ 具体 {param_name: value}。缺角色 → None(护栏后按类型/缺失处理)。"""
    out = {}
    for pname, spec in (params or {}).items():
        if not isinstance(spec, dict):
            out[pname] = spec                                 # 容错:直接给了值
        elif spec.get("source") == "literal":
            out[pname] = spec.get("value")
        else:
            out[pname] = (bindings or {}).get(spec.get("role"))
    return out


def _disposition_from_step(step, bindings, iface) -> Disposition:
    resolved = _resolve_params(step.params, bindings)
    kf = iface.target_key_field(step.primitive)               # 主目标 = 原语 target.key_field 参数
    target = resolved.get(kf) if kf else None
    # 账号类原语:注入目标账号的域(约定 <role>_domain),供 appliance 路由到该域的 DC
    if iface.kind_of(step.primitive) == "account" and "domain" not in resolved:
        spec = (step.params or {}).get(kf) or {}
        role = spec.get("role") if isinstance(spec, dict) else None
        dom = (bindings or {}).get(role + "_domain") if role else None
        if dom:
            resolved["domain"] = dom
    return Disposition(action=step.primitive, target=target, target_kind=iface.kind_of(step.primitive),
                       params=resolved, risk=step.risk)


def dispositions_from_plan(plan, bindings, policy=None, iface=None):
    """有序计划(模板)+ 本告警 bindings → 具体处置(过护栏)。"""
    iface = iface or default_interface()
    disps = [_disposition_from_step(s, bindings or {}, iface)
             for s in sorted(plan or [], key=lambda s: s.order)]
    disps, _ = apply_guardrail(disps, policy, iface)
    return disps
