"""攻击模式规则 + 模板(图外可复用经验的数据形态)。

规则 = 判别签名 → verdict 模板 + **有序处置计划**(PrimitiveStepTemplate 列表)+ 状态。
计划里每步 = 一个基础处置原语 + 参数按角色(entity_role)/字面量(literal)绑定(实例无关) →
命中时拿本告警的角色值填出具体处置。pattern_id = sig_hash(确定性,图台账按它溯源)。

★step 的 primitive 语义(kind/gating/可逆/期望目标类型)不在这里硬编码 —— 由处置接口文档
(soc_agent/response/interface.py)驱动;这里只装"调哪个原语、参数绑哪个角色"。
"""
from dataclasses import dataclass, field
from typing import List, Optional


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


@dataclass
class VerdictTemplate:
    verdict: str                # true_positive | false_positive | benign | suspicious
    lean: Optional[str] = None
    confidence: float = 0.0
    canonical_rationale: str = ""

    def to_dict(self):
        return {"verdict": self.verdict, "lean": self.lean,
                "confidence": self.confidence, "canonical_rationale": self.canonical_rationale}


@dataclass
class PatternRule:
    skill: str
    layer: str                  # exculpatory | incriminating
    sig: str                    # 规范签名串
    sig_hash: str               # 唯一键;pattern_id 就是它
    verdict: VerdictTemplate
    plan: List[PrimitiveStepTemplate] = field(default_factory=list)   # 有序处置计划(可空:先只有 verdict、处置待 composer 补)
    status: str = "pending"     # pending | active | deprecated
    stats: dict = field(default_factory=lambda: {"hit_count": 0, "last_hit": None,
                                                  "tp_confirmed": 0, "fp_reverted": 0})
    provenance: dict = field(default_factory=dict)   # source_alert_uid/minted_by/at/adopted_by/skill_spec_version/version

    @property
    def pattern_id(self) -> str:
        return self.sig_hash
