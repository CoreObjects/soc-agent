"""核心数据契约。

Alert                取自图 :Alert 节点(研判入口)。
Verdict / Disposition 研判/处置结论;to_props() 直接喂图写回经验层。
InvestigationResult  一次研判的产出汇总(快/慢通道同形状)。
"""
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import uuid4

VERDICTS = {"true_positive", "false_positive", "benign", "suspicious"}
# suspicious 的倾向(把"存疑"分诊成带方向+优先级,而非一坨"我不知道")
LEANS = {"malicious", "benign", "unknown"}
# ★处置动作受控词表不再硬编码在此:执行类原语由处置接口文档(soc_agent/response/interface.py)驱动,
#   非执行动作见 response.interface.NON_EXECUTING(escalate/monitor/none)。
DISPOSITION_STATUS = {"proposed", "executed", "failed", "simulated"}
RISKS = {"low", "high"}
DISPOSITION_BY = {"auto", "analyst"}


def _new_id() -> str:
    return uuid4().hex


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
            "agent": self.agent,
            "investigated_at": self.investigated_at,
        }


# 处置动作 → 目标实体类型(供 :ON 边解析到真实体 + 处置收敛键)
_ACTION_KIND = {
    "block_ip": "ip",
    "disable_account": "account", "reset_password": "account", "revoke_sessions": "account",
    "isolate_host": "host", "kill_process": "process", "quarantine_file": "file",
}


@dataclass
class Disposition:
    """处置结论。写回 (:Verdict)-[:LED_TO]->(:Disposition)-[:ON]->实体。

    默认 propose-only(status=proposed, by=auto):第一版一律仅建议,人审后执行。
    收敛键 conv_key = (action + target_kind + target):同动作同目标合一条(封两个不同 IP=两条,是真历史)。
    """
    action: str                        # 基础处置原语 id(=interface 里的 primitive):disable_account | isolate_host | remove_from_group ...
    target: Optional[str] = None       # 主目标值(= 原语 target.key_field 参数解析出的实体值),供 :ON / conv_key
    target_kind: Optional[str] = None  # ip|account|host|process|file|domain|none(缺则按 action 派生;供 :ON 解析)
    params: dict = field(default_factory=dict)   # 全部已绑定的具体参数值(如 {"sam":"hacker2","group":"Domain Admins"})
    risk: str = "low"                  # low | high
    status: str = "proposed"           # proposed | executed | failed | simulated
    simulated: bool = False
    by: str = "auto"                   # auto | analyst
    rollback_handle: Optional[dict] = None       # 处置面回执:{execution_id, inverse, params, prev_state} —— 回退凭据
    decided_at: Optional[str] = None
    disposition_id: str = field(default_factory=_new_id)

    def __post_init__(self):
        if self.risk not in RISKS:
            raise ValueError(f"未知 risk: {self.risk!r}(允许 {sorted(RISKS)})")
        if self.status not in DISPOSITION_STATUS:
            raise ValueError(f"未知 status: {self.status!r}(允许 {sorted(DISPOSITION_STATUS)})")
        if self.by not in DISPOSITION_BY:
            raise ValueError(f"未知 by: {self.by!r}(允许 {sorted(DISPOSITION_BY)})")
        if self.target_kind is None:
            self.target_kind = _ACTION_KIND.get(self.action, "none")

    def conv_key(self) -> str:
        """处置台账收敛键:同 action+目标 → 一个 Disposition 节点(不同目标各一条)。"""
        return _sha("|".join(["disp", self.action, self.target_kind or "", self.target or ""]))

    def to_props(self) -> dict:
        return {
            "disposition_id": self.disposition_id,
            "disposition_key": self.conv_key(),
            "action": self.action,
            "target": self.target,
            "target_kind": self.target_kind,
            # 嵌套 dict 不能直接当 Neo4j 属性 → json 串存;回退 CLI 读回 json.loads
            "params": json.dumps(self.params, ensure_ascii=False),
            "risk": self.risk,
            "status": self.status,
            "simulated": self.simulated,
            "by": self.by,
            "rollback_handle": (json.dumps(self.rollback_handle, ensure_ascii=False)
                                if self.rollback_handle is not None else None),  # 回退凭据必须落台账(先前漏了)
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
    findings: list = field(default_factory=list)       # list[Finding] 取证规范发现(供经验匹配/沉淀/案例快照)
    bindings: dict = field(default_factory=dict)       # 实体角色→值(供指纹占位符抽象 + 处置重绑)
    playbook: list = field(default_factory=list)       # list[PrimitiveStepTemplate.to_dict()] 处置剧本模板(供沉淀)
    reuse_verdict_id: Optional[str] = None             # 复用(AUTO):CONCLUDED 指向的旧 Verdict id;写台账时不新建 Verdict、下游完全复用
