"""规则库仓储接口 + 内存 fake。

接口给 openGauss(权威)+ Redis(热读)具体适配用;上层(快通道/生成)只依赖接口。
- upsert:按 sig_hash 去重(幂等);已存在→只 bump hit_count(首铸定模板,后续复用不覆盖)。
- find_active:快通道热读,只服务 active。
- set_status:pending→active(采纳)/active→deprecated(误判停用)。
"""
from typing import List, Optional, Protocol, runtime_checkable

from .rule import PatternRule


@runtime_checkable
class PatternRepository(Protocol):
    def upsert(self, rule: PatternRule) -> PatternRule: ...
    def find_active(self, sig_hash: str) -> Optional[PatternRule]: ...
    def get(self, sig_hash: str) -> Optional[PatternRule]: ...
    def set_status(self, sig_hash: str, status: str) -> None: ...
    def list_pending(self) -> List[PatternRule]: ...


class InMemoryPatternRepository:
    """测试/单机用内存实现;语义即 openGauss+Redis 适配要复现的契约。"""

    def __init__(self):
        self._by_hash = {}          # sig_hash -> PatternRule

    def upsert(self, rule: PatternRule) -> PatternRule:
        cur = self._by_hash.get(rule.sig_hash)
        if cur is None:
            rule.stats["hit_count"] = max(rule.stats.get("hit_count", 0), 1)
            self._by_hash[rule.sig_hash] = rule
            return rule
        cur.stats["hit_count"] = cur.stats.get("hit_count", 0) + 1   # 复用已有,只计数,不覆盖模板/状态
        return cur

    def find_active(self, sig_hash: str) -> Optional[PatternRule]:
        r = self._by_hash.get(sig_hash)
        return r if (r is not None and r.status == "active") else None

    def get(self, sig_hash: str) -> Optional[PatternRule]:
        return self._by_hash.get(sig_hash)

    def set_status(self, sig_hash: str, status: str) -> None:
        r = self._by_hash.get(sig_hash)
        if r is not None:
            r.status = status

    def list_pending(self) -> List[PatternRule]:
        return [r for r in self._by_hash.values() if r.status == "pending"]

    def all(self) -> List[PatternRule]:
        return list(self._by_hash.values())
