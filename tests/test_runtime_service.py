"""poller 处理器 make_processor 的模式分诊单测(mock build_pipeline/run_investigation/auto_respond)。

manual(默认):只研判、不自动处置;auto:研判后调 auto_respond。3.10 可跑(不真建 pipeline)。
"""
import threading

import soc_agent.cli as cli
import soc_agent.response.auto as auto_mod
from soc_agent.config import Config
from soc_agent.runtime.service import make_processor


def _fake_pl():
    return type("PL", (), {"graph": object(), "close": lambda self: None})()


def _wire(monkeypatch):
    inv, auto_calls = [], []
    monkeypatch.setattr(cli, "build_pipeline", lambda cfg: _fake_pl())
    monkeypatch.setattr(cli, "run_investigation", lambda pl, uid, mode: inv.append(uid))
    monkeypatch.setattr(auto_mod, "auto_respond", lambda g, c, uid: (auto_calls.append(uid), [])[1])
    return inv, auto_calls


def test_manual_mode_skips_auto(monkeypatch):
    inv, auto_calls = _wire(monkeypatch)
    cfg = Config.from_env(env={})                       # response_mode 默认 manual
    proc = make_processor(cfg, appliance_client=None, built_pls=[], lock=threading.Lock())
    proc(None, "a1", "recipe")
    assert inv == ["a1"] and auto_calls == []           # 研判了、没自动处置


def test_auto_mode_calls_respond(monkeypatch):
    inv, auto_calls = _wire(monkeypatch)
    cfg = Config.from_env(env={"SOC_RESPONSE_MODE": "auto"})
    proc = make_processor(cfg, appliance_client=None, built_pls=[], lock=threading.Lock())
    proc(None, "a1", "recipe")
    assert inv == ["a1"] and auto_calls == ["a1"]       # 研判 + 自动处置


def test_worker_builds_pipeline_once(monkeypatch):
    # 同一线程多条告警 → 只建一次 pipeline(thread-local 复用)
    builds = []
    monkeypatch.setattr(cli, "build_pipeline", lambda cfg: (builds.append(1), _fake_pl())[1])
    monkeypatch.setattr(cli, "run_investigation", lambda pl, uid, mode: None)
    cfg = Config.from_env(env={})
    built = []
    proc = make_processor(cfg, appliance_client=None, built_pls=built, lock=threading.Lock())
    proc(None, "a1", "recipe")
    proc(None, "a2", "recipe")
    assert len(builds) == 1 and len(built) == 1
