"""核心数据契约。

Alert                取自图 :Alert 节点(研判入口)。
Verdict / Disposition 研判/处置结论;to_props() 直接喂图写回经验层。
InvestigationResult  一次研判的产出汇总(快/慢通道同形状)。
"""
from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import uuid4

VERDICTS = {"true_positive", "false_positive", "benign", "suspicious"}
# suspicious 的倾向(把"存疑"分诊成带方向+优先级,而非一坨"我不知道")
LEANS = {"malicious", "benign", "unknown"}
# 处置动作受控词表(避免 LLM 自由发挥出不可执行的"废话动作");未知动作归一为 escalate
DISPOSITION_ACTIONS = {
    "disable_account", "block_ip", "isolate_host", "kill_process", "reset_password",
    "revoke_sessions", "quarantine_file", "escalate", "monitor", "none",
}
DISPOSITION_STATUS = {"proposed", "executed", "failed", "simulated"}
RISKS = {"low", "high"}
DISPOSITION_BY = {"auto", "analyst"}


def _new_id() -> str:
    return uuid4().hex


@dataclass
class Alert:
    """一条待研判/已研判的告警(:Alert 节点的字段)。"""
    alert_uid: str
    source: Optional[str] = None
    sensor: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    severity: Optional[Any] = None
    technique_ids: list = field(default_factory=list)
    time: Optional[str] = None
    raw_ref: Optional[str] = None

    @classmethod
    def from_node(cls, node: dict) -> "Alert":
        return cls(
            alert_uid=node["alert_uid"],
            source=node.get("source"),
            sensor=node.get("sensor"),
            rule_id=node.get("rule_id"),
            rule_description=node.get("rule_description"),
            severity=node.get("severity"),
            technique_ids=list(node.get("technique_ids") or []),
            time=node.get("time"),
            raw_ref=node.get("raw_ref"),
        )

    @property
    def primary_technique(self) -> Optional[str]:
        return self.technique_ids[0] if self.technique_ids else None


@dataclass
class Verdict:
    """研判结论。写回 (:Alert)-[:CONCLUDED]->(:Verdict)。"""
    verdict: str                       # true_positive | false_positive | benign | suspicious
    lean: Optional[str] = None         # 仅 suspicious 用:malicious|benign|unknown(存疑的倾向/优先级)
    confidence: float = 0.0
    summary: str = ""
    rationale: str = ""
    evidence_refs: list = field(default_factory=list)   # 引用的证据(事件/实体标识)
    missing_evidence: list = field(default_factory=list)  # 取不到的关键证据(诚实报"证据不足")
    pattern: Optional[str] = None      # 识别出的攻击模式名(有则便于情报按模式检索)
    agent: Optional[str] = None        # 研判者(模型/版本标识)
    investigated_at: Optional[str] = None
    verdict_id: str = field(default_factory=_new_id)

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"未知 verdict: {self.verdict!r}(允许 {sorted(VERDICTS)})")
        if self.lean is not None and self.lean not in LEANS:
            raise ValueError(f"未知 lean: {self.lean!r}(允许 {sorted(LEANS)})")

    def to_props(self) -> dict:
        return {
            "verdict_id": self.verdict_id,
            "verdict": self.verdict,
            "lean": self.lean,
            "confidence": self.confidence,
            "summary": self.summary,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
            "missing_evidence": list(self.missing_evidence),
            "pattern": self.pattern,
            "agent": self.agent,
            "investigated_at": self.investigated_at,
        }


@dataclass
class Disposition:
    """处置结论。写回 (:Verdict)-[:LED_TO]->(:Disposition)-[:ON]->实体。

    默认 propose-only(status=proposed, by=auto):第一版一律仅建议,人审后执行。
    """
    action: str                        # block_ip | isolate_host | disable_account | kill_process | none ...
    target: Optional[str] = None
    risk: str = "low"                  # low | high
    status: str = "proposed"           # proposed | executed | failed | simulated
    simulated: bool = False
    by: str = "auto"                   # auto | analyst
    rollback_handle: Optional[dict] = None
    decided_at: Optional[str] = None
    disposition_id: str = field(default_factory=_new_id)

    def __post_init__(self):
        if self.risk not in RISKS:
            raise ValueError(f"未知 risk: {self.risk!r}(允许 {sorted(RISKS)})")
        if self.status not in DISPOSITION_STATUS:
            raise ValueError(f"未知 status: {self.status!r}(允许 {sorted(DISPOSITION_STATUS)})")
        if self.by not in DISPOSITION_BY:
            raise ValueError(f"未知 by: {self.by!r}(允许 {sorted(DISPOSITION_BY)})")

    def to_props(self) -> dict:
        return {
            "disposition_id": self.disposition_id,
            "action": self.action,
            "target": self.target,
            "risk": self.risk,
            "status": self.status,
            "simulated": self.simulated,
            "by": self.by,
            "decided_at": self.decided_at,
        }


@dataclass
class InvestigationResult:
    """一次研判的产出汇总(快/慢通道同形状,便于统一写回/展示)。"""
    alert_uid: str
    path: str                          # "A"(快) | "B"(慢)
    verdict: Optional[Verdict] = None
    dispositions: list = field(default_factory=list)   # list[Disposition]
    techniques: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    latency_ms: Optional[int] = None
    skill: Optional[str] = None        # 用到的 skill
    trace: list = field(default_factory=list)          # 研判留痕(工具调用/推理)
