"""daemon(P5' 自动轮询研判):选未研判告警 → 逐条投现有编排 → 回写;单实例、慢通道串行、毒告警死信闭环。

内存 fake(不碰真 Neo4j/qwen)验编排逻辑;Cypher 语义(无 CONCLUDED / settle 窗口)由真机 --once 验。
"""
from types import SimpleNamespace

import pytest

from soc_agent.daemon import Daemon, SingletonError, acquire_singleton


def _cfg(**kw):
    base = dict(daemon_poll_interval_s=10, daemon_batch_size=20, daemon_settle_s=120,
                daemon_techniques=["T1558.003"], daemon_max_attempts=3, daemon_slow_concurrency=1)
    base.update(kw)
    return SimpleNamespace(**base)


class FakeGraph:
    def __init__(self, uids):
        self._uids = list(uids)
        self.cypher_calls = []
        self.writes = []

    def run_cypher(self, q, **p):
        self.cypher_calls.append((q, p))
        return [{"uid": u} for u in self._uids]

    def write_result(self, uid, result):
        self.writes.append((uid, result))


def test_run_once_investigates_each_selected():
    g = FakeGraph(["a1", "a2", "a3"])
    seen = []
    d = Daemon(graph=g, orch=object(), cfg=_cfg(), investigate_fn=lambda gr, o, uid: seen.append(uid))
    counts = d.run_once(now_ms=1_000_000)
    assert seen == ["a1", "a2", "a3"]
    assert counts["concluded"] == 3 and counts["selected"] == 3


def test_selector_passes_settle_cutoff_techs_batch():
    g = FakeGraph([])
    d = Daemon(graph=g, orch=object(), cfg=_cfg(daemon_settle_s=120, daemon_batch_size=20),
               investigate_fn=lambda *a: None)
    d.run_once(now_ms=1_000_000)
    q, p = g.cypher_calls[0]
    assert "NOT (a)-[:CONCLUDED]->()" in q                    # 未研判 = 无 CONCLUDED 出边
    assert p["cutoff_ms"] == 1_000_000 - 120_000             # settle 窗口 now-Δ
    assert p["techs"] == ["T1558.003"] and p["batch"] == 20  # 范围闸 + 批量


def test_poison_alert_dead_lettered_after_max_attempts():
    g = FakeGraph(["bad"])

    def boom(gr, o, uid):
        raise RuntimeError("kaboom")

    d = Daemon(graph=g, orch=object(), cfg=_cfg(daemon_max_attempts=3), investigate_fn=boom)
    assert d.run_once(now_ms=1)["failed"] == 1               # 第1次失败
    assert d.run_once(now_ms=1)["failed"] == 1               # 第2次
    c3 = d.run_once(now_ms=1)
    assert c3["dead_lettered"] == 1                          # 第3次连败 → 死信
    assert g.writes and g.writes[-1][0] == "bad"            # 写了兜底 verdict 闭环
    assert g.writes[-1][1].verdict.verdict == "suspicious"
    assert d.run_once(now_ms=1)["selected"] == 0            # 死信后不再重选(即便图仍返回它)


def test_transient_failure_then_success_resets_attempts():
    g = FakeGraph(["x"])
    calls = {"n": 0}

    def flaky(gr, o, uid):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")

    d = Daemon(graph=g, orch=object(), cfg=_cfg(daemon_max_attempts=3), investigate_fn=flaky)
    d.run_once(now_ms=1)                                     # 失败(attempts=1)
    d.run_once(now_ms=1)                                     # 成功 → 清零
    assert d._attempts.get("x", 0) == 0


def test_serve_stops_gracefully():
    g = FakeGraph(["a1"])
    seen = []
    d = Daemon(graph=g, orch=object(), cfg=_cfg(), investigate_fn=lambda gr, o, uid: seen.append(uid))

    def stop_after(_s):
        d.stop()

    d.serve(sleep_fn=stop_after)                            # 第一轮后 sleep 触发 stop → 退出
    assert seen == ["a1"]                                   # 只跑了一轮


def test_singleton_lock_rejects_second_live_instance(tmp_path):
    pid = tmp_path / "daemon.pid"
    acquire_singleton(pid, alive_fn=lambda p: True)         # 文件不存在 → 拿到
    with pytest.raises(SingletonError):
        acquire_singleton(pid, alive_fn=lambda p: True)     # 已有活进程 → 拒
    acquire_singleton(pid, alive_fn=lambda p: False)        # 陈旧 pid(进程已死)→ 可重拿
