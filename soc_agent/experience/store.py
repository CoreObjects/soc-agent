"""第二类经验记录 + 库接口 + 内存实现 + 进程内缓存。

Experience = findings →(verdict + 处置剧本模板)的一条映射,两形态:
- benign_fp:误报业务指纹(fingerprint)→ 判 FP + 复用压/归档剧本。
- threat:威胁指纹(fingerprint)+ 威胁规则(rule, DSL)→ 双门命中判 TP + 复用剧本。

持久化在 openGauss(Phase 6 server2,见 opengauss.py);本模块只依赖标准库,便于离线单测。
未配 openGauss → 用 InMemoryExperienceStore 降级(经验层等于"永远走 LLM",零 regression)。
生命周期:status active|hint_only|archived + hit_count/override_count(生死线见 exam.py,后续 Phase)。
"""
from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

__all__ = ["Experience", "ExperienceStore", "InMemoryExperienceStore", "ExperienceCache",
           "EXP_KINDS", "EXP_STATUSES"]

EXP_KINDS = {"benign_fp", "threat"}
EXP_STATUSES = {"active", "hint_only", "archived"}


@dataclass
class Experience:
    skill: str
    kind: str                                        # benign_fp | threat
    verdict: str                                     # false_positive | true_positive
    fingerprint: dict = field(default_factory=dict)  # build_fingerprint 输出
    rule: Optional[dict] = None                      # DSL 规则(threat 才有)
    playbook: list = field(default_factory=list)     # list[PrimitiveStepTemplate.to_dict()](FP 多为空=no-op)
    status: str = "active"                           # active | hint_only | archived
    hit_count: int = 0
    override_count: int = 0
    origin_case_id: Optional[str] = None             # 来源告警 alert_uid(=VID,凭它从图台账捞原始上下文)
    note: Optional[str] = None                        # qwen 蒸馏给的"本质"一句话(命中时喂 LLM 作参照)
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    exp_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self):
        if self.kind not in EXP_KINDS:
            raise ValueError(f"未知 kind:{self.kind!r}(允许 {sorted(EXP_KINDS)})")
        if self.status not in EXP_STATUSES:
            raise ValueError(f"未知 status:{self.status!r}(允许 {sorted(EXP_STATUSES)})")

    def to_dict(self) -> dict:
        return {"exp_id": self.exp_id, "skill": self.skill, "kind": self.kind, "verdict": self.verdict,
                "fingerprint": self.fingerprint, "rule": self.rule, "playbook": list(self.playbook),
                "status": self.status, "hit_count": self.hit_count, "override_count": self.override_count,
                "origin_case_id": self.origin_case_id, "note": self.note, "created_by": self.created_by,
                "created_at": self.created_at}

    @classmethod
    def from_dict(cls, d: dict) -> "Experience":
        return cls(skill=d["skill"], kind=d["kind"], verdict=d["verdict"],
                   fingerprint=dict(d.get("fingerprint") or {}), rule=d.get("rule"),
                   playbook=list(d.get("playbook") or []), status=d.get("status", "active"),
                   hit_count=int(d.get("hit_count") or 0), override_count=int(d.get("override_count") or 0),
                   origin_case_id=d.get("origin_case_id"), note=d.get("note"), created_by=d.get("created_by"),
                   created_at=d.get("created_at"), exp_id=d.get("exp_id") or uuid4().hex)


class ExperienceStore:
    """经验库接口(openGauss 实现同签名替换)。"""

    def add(self, exp: Experience) -> str:
        raise NotImplementedError

    def get(self, exp_id: str) -> Optional[Experience]:
        raise NotImplementedError

    def all(self) -> list:
        raise NotImplementedError

    def active_for_skill(self, skill: str) -> list:
        raise NotImplementedError

    def by_kind(self, skill: str, kind: str) -> list:
        return [e for e in self.active_for_skill(skill) if e.kind == kind]

    def bump_hit(self, exp_id: str) -> None:
        raise NotImplementedError

    def bump_override(self, exp_id: str) -> None:
        raise NotImplementedError

    def set_status(self, exp_id: str, status: str) -> None:
        raise NotImplementedError


class InMemoryExperienceStore(ExperienceStore):
    """进程内经验库(测试 / 未配 openGauss 时降级)。"""

    def __init__(self):
        self._by_id: dict = {}

    def add(self, exp: Experience) -> str:
        self._by_id[exp.exp_id] = exp
        return exp.exp_id

    def get(self, exp_id: str) -> Optional[Experience]:
        return self._by_id.get(exp_id)

    def all(self) -> list:
        return list(self._by_id.values())

    def active_for_skill(self, skill: str) -> list:
        return [e for e in self._by_id.values() if e.skill == skill and e.status == "active"]

    def bump_hit(self, exp_id: str) -> None:
        e = self._by_id.get(exp_id)
        if e:
            e.hit_count += 1

    def bump_override(self, exp_id: str) -> None:
        e = self._by_id.get(exp_id)
        if e:
            e.override_count += 1

    def set_status(self, exp_id: str, status: str) -> None:
        if status not in EXP_STATUSES:
            raise ValueError(f"未知 status:{status!r}")
        e = self._by_id.get(exp_id)
        if e:
            e.status = status


class ExperienceCache:
    """进程内缓存:按 skill 装载 active 经验(快通道热读),写后失效重载。

    包在任意 ExperienceStore 外(openGauss 用它避免每条告警都打库)。缓存的是"某 skill 的 active 列表"。
    """

    def __init__(self, store: ExperienceStore):
        self.store = store
        self._cache: dict = {}                       # skill -> list[Experience]

    def active_for_skill(self, skill: str) -> list:
        if skill not in self._cache:
            self._cache[skill] = self.store.active_for_skill(skill)
        return self._cache[skill]

    def by_kind(self, skill: str, kind: str) -> list:
        return [e for e in self.active_for_skill(skill) if e.kind == kind]

    def add(self, exp: Experience) -> str:
        r = self.store.add(exp)
        self._cache.pop(exp.skill, None)             # 该 skill 失效
        return r

    def set_status(self, exp_id: str, status: str) -> None:
        self.store.set_status(exp_id, status)
        self._cache.clear()                          # 不知 skill → 全清(状态变化罕见)

    def bump_hit(self, exp_id: str) -> None:
        self.store.bump_hit(exp_id)                  # 计数不影响 active 成员,无需失效

    def bump_override(self, exp_id: str) -> None:
        self.store.bump_override(exp_id)

    def get(self, exp_id: str) -> Optional[Experience]:
        return self.store.get(exp_id)

    def all(self) -> list:
        return self.store.all()
