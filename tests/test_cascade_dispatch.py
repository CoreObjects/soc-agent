"""cascade 分派:cascade_enabled 决定走 run_cascade(浅度)还是 run_pipeline(深度)。

关键:关掉时**不 import openjiuwen**(懒导入)——所以这测试在 3.10 也能跑。
"""
import sys
import types

import soc_agent.cli as cli


def test_dispatch_cascade_off_uses_run_pipeline(monkeypatch):
    monkeypatch.setattr(cli, "run_pipeline", lambda pl, uid, mode: ("deep_result", "rep", "深度"))
    pl = type("PL", (), {"cascade_enabled": False})()
    assert cli.run_investigation(pl, "a1", "recipe") == ("deep_result", "rep", "深度")


def test_dispatch_cascade_on_uses_run_cascade(monkeypatch):
    # 用假模块顶替 soc_agent.cascade.run,避免真 import openjiuwen(3.10 没有)
    fake = types.ModuleType("soc_agent.cascade.run")
    fake.run_cascade = lambda pl, uid, mode: ("shallow_result", "rep", "浅度")
    monkeypatch.setitem(sys.modules, "soc_agent.cascade.run", fake)
    pl = type("PL", (), {"cascade_enabled": True})()
    assert cli.run_investigation(pl, "a1", "recipe") == ("shallow_result", "rep", "浅度")
