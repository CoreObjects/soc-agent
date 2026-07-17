"""案例快照 —— 回归考试(生死线)的语料。

图台账只存"结论叙述 + evidence_refs",不存 findings。要做"新经验入库前对历史反类案例回归、
不得误命中",就得给每个研判过的案例另存一份 **findings 快照 + verdict**。

Phase 1:接口 + 内存实现(未配 openGauss 时降级用它);Phase 3 落 openGauss 持久表。
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Case:
    """一个研判过的案例快照:findings + verdict,供回归考试回放。"""

    skill: str
    alert_uid: str
    verdict: str                                     # true_positive|false_positive|benign|suspicious
    findings: list = field(default_factory=list)     # list[Finding]
    created_at: Optional[str] = None

    def finding_ids(self) -> set:
        return {f.finding_id for f in self.findings}


class CaseStore:
    """案例语料库接口(Phase 3 openGauss 实现同签名替换)。"""

    def add(self, case: Case) -> None:
        raise NotImplementedError

    def by_skill(self, skill: str) -> list:
        raise NotImplementedError


class InMemoryCaseStore(CaseStore):
    """进程内案例库(测试 / 未配 openGauss 时的降级实现)。"""

    def __init__(self):
        self._cases: list = []

    def add(self, case: Case) -> None:
        self._cases.append(case)

    def by_skill(self, skill: str) -> list:
        return [c for c in self._cases if c.skill == skill]

    def all(self) -> list:
        return list(self._cases)


def snapshot_case(store: Optional[CaseStore], skill_name: Optional[str], result) -> Optional[Case]:
    """把一次研判存成回归语料(findings 快照 + verdict)。无 store / 无 verdict → 跳过。"""
    if store is None or result is None or result.verdict is None:
        return None
    case = Case(skill=skill_name or (result.skill or "unknown"), alert_uid=result.alert_uid,
                verdict=result.verdict.verdict, findings=list(result.findings or []))
    store.add(case)
    return case
