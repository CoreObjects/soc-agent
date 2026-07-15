"""攻击模式规则 + 模板(图外可复用经验的数据形态)。

规则 = 判别签名 → verdict 模板 + 处置模板 + 状态。处置模板用 target_kind+target_field(实例无关),
命中时拿本告警的实体填具体目标。pattern_id = sig_hash(确定性,图台账按它溯源)。
"""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DispositionTemplate:
    action: str
    target_kind: str            # account | ip | host | process | file | none
    target_field: str           # 目标来自证据/seed 的哪个字段(如 "requester") —— 实例无关
    risk: str = "low"

    def to_dict(self):
        return {"action": self.action, "target_kind": self.target_kind,
                "target_field": self.target_field, "risk": self.risk}


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
    dispositions: List[DispositionTemplate] = field(default_factory=list)
    status: str = "pending"     # pending | active | deprecated
    stats: dict = field(default_factory=lambda: {"hit_count": 0, "last_hit": None,
                                                  "tp_confirmed": 0, "fp_reverted": 0})
    provenance: dict = field(default_factory=dict)   # source_alert_uid/minted_by/at/adopted_by/skill_spec_version/version

    @property
    def pattern_id(self) -> str:
        return self.sig_hash
