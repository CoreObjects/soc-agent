"""进程内热读缓存(替代 Redis:soc-agent 单进程 daemon,active 规则缓内存 dict,写穿失效)。

快通道每条告警查一次 find_active,须快 → 缓 active 规则于内存;写(upsert/set_status)穿到 backing 后失效对应键。
多进程/多实例将来再上 Redis;单进程进程内缓存足够且最省。
"""
from typing import List, Optional

from .repository import PatternRepository
from .rule import PatternRule


class CachedPatternRepository:
    """包一层 backing(openGauss)—— find_active 走缓存(miss 回源并缓 active);写操作写穿 + 失效。"""

    def __init__(self, backing: PatternRepository):
        self.backing = backing
        self._active = {}          # sig_hash -> PatternRule(仅 active)
        self._miss = set()         # 已知非 active(避免每次回源;写操作清)

    def find_active(self, sig_hash: str) -> Optional[PatternRule]:
        r = self._active.get(sig_hash)
        if r is not None:
            return r
        if sig_hash in self._miss:
            return None
        r = self.backing.find_active(sig_hash)
        if r is not None:
            self._active[sig_hash] = r
        else:
            self._miss.add(sig_hash)
        return r

    def _invalidate(self, sig_hash: str):
        self._active.pop(sig_hash, None)
        self._miss.discard(sig_hash)

    def upsert(self, rule: PatternRule) -> PatternRule:
        r = self.backing.upsert(rule)
        self._invalidate(rule.sig_hash)      # 状态/命中变了,下次 find_active 回源
        return r

    def set_status(self, sig_hash: str, status: str) -> None:
        self.backing.set_status(sig_hash, status)
        self._invalidate(sig_hash)

    def get(self, sig_hash: str) -> Optional[PatternRule]:
        return self.backing.get(sig_hash)

    def list_pending(self) -> List[PatternRule]:
        return self.backing.list_pending()
