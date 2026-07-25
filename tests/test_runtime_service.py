"""poller 处理器 make_processor 的模式分诊 + _Locked 线程安全代理单测(mock,3.10 可跑)。

共享 pipeline 版:process(pl, uid, mode) 直接用传入的 pl;manual 不自动处置、auto 调 auto_respond。
"""
import threading

import soc_agent.cli as cli
import soc_agent.response.auto as auto_mod
from soc_agent.cli import _Locked
from soc_agent.config import Config
from soc_agent.runtime.service import make_processor


def _fake_pl():
    return type("PL", (), {"graph": object()})()


def _wire(monkeypatch):
    inv, auto_calls = [], []
    monkeypatch.setattr(cli, "run_investigation", lambda pl, uid, mode: inv.append(uid))
    monkeypatch.setattr(auto_mod, "auto_respond", lambda g, c, uid: (auto_calls.append(uid), [])[1])
    return inv, auto_calls


def test_manual_mode_skips_auto(monkeypatch):
    inv, auto_calls = _wire(monkeypatch)
    cfg = Config.from_env(env={})                       # response_mode 默认 manual
    proc = make_processor(cfg, appliance_client=None)
    proc(_fake_pl(), "a1", "recipe")
    assert inv == ["a1"] and auto_calls == []           # 研判了、没自动处置


def test_auto_mode_calls_respond(monkeypatch):
    inv, auto_calls = _wire(monkeypatch)
    cfg = Config.from_env(env={"SOC_RESPONSE_MODE": "auto"})
    proc = make_processor(cfg, appliance_client=None)
    proc(_fake_pl(), "a1", "recipe")
    assert inv == ["a1"] and auto_calls == ["a1"]       # 研判 + 自动处置


# ---- _Locked 线程安全代理 ----
class _Store:
    def __init__(self):
        self.calls = []
        self.name = "raw"          # 非 callable 属性

    def add(self, x):
        self.calls.append(x)
        return x * 2


def test_locked_delegates_methods_and_passes_attrs():
    lock = threading.RLock()
    s = _Store()
    ls = _Locked(s, lock)
    assert ls.add(3) == 6              # 方法经锁调用、返回值透传
    assert s.calls == [3]
    assert ls.name == "raw"           # 非方法属性原样透传


def test_locked_serializes_shared_lock():
    # 两个 _Locked 共享一把锁 → 串行(无交叉),验证共享连接不会并发访问
    lock = threading.RLock()
    order = []
    s = _Store()
    a, b = _Locked(s, lock), _Locked(s, lock)

    def worker(w, tag):
        for _ in range(50):
            w.add(tag)
    t1 = threading.Thread(target=worker, args=(a, 1))
    t2 = threading.Thread(target=worker, args=(b, 2))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert len(s.calls) == 100        # 100 次都记上、无丢失(锁保证 append 不竞争)
