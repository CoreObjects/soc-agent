"""Poller 纯逻辑单测:取批 Cypher / 水位幂等 / 毒告警 retry→skip / 优雅退出。

mock graph,不需 neo4j/openjiuwen/openGauss —— 3.10 可跑(与研判解耦)。
"""
from soc_agent.runtime.poller import Poller, batch_cypher, poison_props


class _FakeGraph:
    def __init__(self, rows=None, node=None):
        self._rows = rows if rows is not None else []
        self._node = node or {}
        self.calls = []          # (cypher, params)
        self.setted = {}         # uid -> props(来自 SET a += $props)

    def run_cypher(self, cypher, **params):
        self.calls.append((cypher, params))
        if "SET a += $props" in cypher:
            self.setted[params["uid"]] = params["props"]
            return []
        if "count(a)" in cypher:
            return [{"n": len(self._rows)}]
        return [dict(r) for r in self._rows]

    def get_alert(self, uid):
        return dict(self._node)


def _pl(graph):
    return type("PL", (), {"graph": graph})()


def test_batch_cypher_excludes_concluded_and_skip_arrival_order():
    c = batch_cypher()
    assert "NOT (a)-[:CONCLUDED]->()" in c        # 未研判水位
    assert "poller_skip" in c                     # 毒告警排除
    assert "arrival_ms" in c and "ASC" in c       # 到达序(先旧后新)
    assert "LIMIT $batch" in c


def test_fetch_batch_returns_uids():
    g = _FakeGraph(rows=[{"uid": "a1"}, {"uid": "a2"}])
    p = Poller(_pl(g), batch=10)
    assert p.fetch_batch() == ["a1", "a2"]
    assert g.calls[0][1] == {"batch": 10}


def test_poison_props_increments_then_skips_at_cap():
    assert poison_props(0, 3) == {"poller_retries": 1}
    assert poison_props(1, 3) == {"poller_retries": 2}
    assert poison_props(2, 3) == {"poller_retries": 3, "poller_skip": True}
    assert poison_props(None, 3) == {"poller_retries": 1}   # 没跑过也从 1 起


def test_process_one_success_no_poison():
    g = _FakeGraph()
    done = []
    p = Poller(_pl(g), process_fn=lambda pl, uid, mode: done.append(uid))
    p.process_one("a1")
    assert done == ["a1"] and p.stats["done"] == 1
    assert g.setted == {}                          # 成功不打毒标记


def test_process_one_error_marks_retry():
    g = _FakeGraph(node={"poller_retries": 0})

    def boom(pl, uid, mode):
        raise RuntimeError("研判炸了")

    p = Poller(_pl(g), process_fn=boom, retry_cap=3)
    p.process_one("a1")
    assert p.stats["failed"] == 1
    assert g.setted["a1"] == {"poller_retries": 1}


def test_process_one_error_skips_after_cap():
    g = _FakeGraph(node={"poller_retries": 2})

    def boom(pl, uid, mode):
        raise RuntimeError()

    p = Poller(_pl(g), process_fn=boom, retry_cap=3)
    p.process_one("a1")
    assert g.setted["a1"] == {"poller_retries": 3, "poller_skip": True}
    assert p.stats["skipped"] == 1


def test_stop_skips_queued_process():
    g = _FakeGraph()
    done = []
    p = Poller(_pl(g), process_fn=lambda pl, uid, mode: done.append(uid))
    p.request_stop()
    p.process_one("a1")
    assert done == []                              # stop 后排队未起的直接跳过


def test_run_processes_batch_then_exits_on_stop():
    g = _FakeGraph(rows=[{"uid": "a1"}])
    done = []

    def proc(pl, uid, mode):
        done.append(uid)
        p.request_stop()                           # 处理完就请求停

    p = Poller(_pl(g), interval=0.01, concurrency=1, process_fn=proc)
    p.run()                                         # 不能挂;处理 a1 后 stop → 退出
    assert done == ["a1"]
