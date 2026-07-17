"""取证结果的结构化契约(第二类经验层的地基)。

recipe.collect(graph, alert, seed) 返回 Forensics:
  findings    规范化"发现"列表(每条 = 语义观察 finding_id + 证据 attrs)—— 供指纹/规则匹配
  bindings    实体角色 → 值(+ ``<role>_domain``),供指纹占位符抽象 + 处置重绑共用
  context     人读证据(旧 prose dict 的家),仍 json.dumps 喂 LLM
  blind_spots 图盲区一句话("看不到什么")

finding_id 按 skill 命名空间(如 ``kerberoast.rc4_requested``)= 方法论(第一类,离线定);
"哪些 finding → 什么结论"的映射才是第二类(qwen 学)。见 [[soc-agent-experience-v2-design]]。

旧 recipe 只吐散装 prose dict → ``Forensics.from_legacy`` 兜住(findings/bindings 空,不做快通道、
永远走 LLM),迁移一个 recipe 就给它铺一层结构化 finding,零 regression。
"""
from dataclasses import dataclass, field
from typing import Optional

_BLIND = "_图盲区"                       # recipe 约定的"图盲区"键名


@dataclass
class Finding:
    """一条规范化发现 = 一个语义观察 + 证据。格式无关、免疫措辞差异。"""

    finding_id: str                                  # 规范发现 ID(skill 命名空间),如 "kerberoast.rc4_requested"
    attrs: dict = field(default_factory=dict)        # 该观察的类型化数据(可含实例值,指纹时按 bindings 抽象为占位符)
    evidence_ref: Optional[str] = None               # 回指 :Event/实体标识(可空)
    polarity: str = "neutral"                        # red|white|neutral —— recipe 作者给的倾向提示(非承重,LLM 自己定)

    def to_dict(self) -> dict:
        return {"finding_id": self.finding_id, "attrs": dict(self.attrs),
                "evidence_ref": self.evidence_ref, "polarity": self.polarity}

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(finding_id=d["finding_id"], attrs=dict(d.get("attrs") or {}),
                   evidence_ref=d.get("evidence_ref"), polarity=d.get("polarity", "neutral"))


@dataclass
class Forensics:
    """一次取证的完整产出。"""

    findings: list = field(default_factory=list)     # list[Finding]
    bindings: dict = field(default_factory=dict)     # role -> value(+ <role>_domain)
    context: dict = field(default_factory=dict)      # 人读证据(喂 LLM)
    blind_spots: str = ""

    def finding_ids(self) -> set:
        return {f.finding_id for f in self.findings}

    def to_dict(self) -> dict:
        return {"findings": [f.to_dict() for f in self.findings], "bindings": dict(self.bindings),
                "context": dict(self.context), "blind_spots": self.blind_spots}

    @classmethod
    def from_legacy(cls, d: dict) -> "Forensics":
        """旧 recipe 的 prose dict → Forensics(findings/bindings 空;prose 进 context;``_图盲区`` 抽进 blind_spots)。"""
        d = dict(d or {})
        blind = d.pop(_BLIND, "") or ""
        return cls(findings=[], bindings={}, context=d, blind_spots=blind)

    @classmethod
    def coerce(cls, raw) -> "Forensics":
        """recipe 返回值归一:Forensics 原样;dict → from_legacy;None → 空;其余 → TypeError。"""
        if isinstance(raw, cls):
            return raw
        if raw is None:
            return cls()
        if isinstance(raw, dict):
            return cls.from_legacy(raw)
        raise TypeError(f"recipe 返回既非 Forensics 也非 dict:{type(raw)!r}")
