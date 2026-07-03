"""接入层噪声过滤:剔纯噪声、连接性事件全留、丢弃计数不静默(见 plan 决策1)。

- channel_eventid:(channel,event_id) 级纯噪声(登出 4634/特权 4672/crypto 5058-61...),直接丢。
- instance_rules:某类事件里的良性实例(如 EID10 SourceImage=VBoxService.exe 的良性自查)。
- 非 winlog 文档(WAF 等)不在黑名单——它们靠 mapper 处理,不是噪声。
- stats() 汇总丢弃数,供 runner 结束对账("不许静默截断")。
"""
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DROPSET_PATH = Path(__file__).with_name("dropset.json")

_OPS = {
    "endswith": lambda a, b: a.endswith(b),
    "startswith": lambda a, b: a.startswith(b),
    "equals": lambda a, b: a == b,
    "contains": lambda a, b: b in a,
}


@dataclass
class Rule:
    channel: str
    event_id: str
    field: str
    op: str
    value: str
    reason: str


@dataclass
class Dropset:
    channel_eventid: set = field(default_factory=set)
    instance_rules: list = field(default_factory=list)


def load_dropset(path) -> Dropset:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    ce = {(c, str(e)) for c, e in data.get("channel_eventid", [])}
    rules = [Rule(r["channel"], str(r["event_id"]), r["field"], r["op"], r["value"], r["reason"])
             for r in data.get("instance_rules", [])]
    return Dropset(ce, rules)


class NoiseFilter:
    def __init__(self, dropset: Dropset):
        self._ds = dropset
        self._dropped = Counter()

    def should_ingest(self, doc: dict) -> bool:
        """True=保留,False=噪声(已计数)。"""
        wl = doc.get("winlog")
        if not wl:
            return True                                  # 非 winlog(WAF 等)不在黑名单
        ch = wl.get("channel")
        eid = str(wl.get("event_id"))
        if (ch, eid) in self._ds.channel_eventid:
            self._dropped[f"{ch}/{eid}"] += 1
            return False
        ed = wl.get("event_data") or {}
        for r in self._ds.instance_rules:
            if r.channel == ch and r.event_id == eid:
                val = ed.get(r.field)
                if val is not None and _OPS.get(r.op, lambda a, b: False)(str(val), r.value):
                    self._dropped[r.reason] += 1
                    return False
        return True

    def stats(self) -> dict:
        return dict(self._dropped)
