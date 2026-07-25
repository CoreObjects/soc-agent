"""响应模式持久化(:Config)+ poller 按批读(收紧2)+ processor 活态 mode_getter。

mock graph,3.10 可跑。核心断言:一批 N 条告警只读 1 次 :Config(按批、非按条)。
"""
import soc_agent.cli as cli
import soc_agent.response.auto as auto_mod
from soc_agent.config import Config
from soc_agent.graph.client import build_constraints
from soc_agent.response.auto import read_response_mode
from soc_agent.runtime.poller import Poller
from soc_agent.runtime.service import make_processor


class ModeGraph:
    def __init__(self, value=None, uids=("a1", "a2", "a3")):
        self.value = value
        self.reads = 0                 # :Config 读次数
        self._uids = list(uids)

    def run_cypher(self, cypher, **p):
        if "Config {key:'response_mode'}" in cypher:
            self.reads += 1
            return [{"value": self.value}] if self.value is not None else []
        if "count(a) AS n" in cypher:
            return [{"n": len(self._uids)}]
        if "ORDER BY coalesce(a.arrival_ms,0) ASC" in cypher:   # 取批:一次给完,之后空(drain)
            r, self._uids = [{"uid": u} for u in self._uids], []
            return r
        return []

    def get_alert(self, uid):
        return {}

    def run_write(self, cypher, **p):
        return []


def _pl(g):
    return type("PL", (), {"graph": g})()


# ---- read_response_mode ----
def test_read_mode_default_when_unset():
    assert read_response_mode(ModeGraph(), "manual") == "manual"


def test_read_mode_auto():
    assert read_response_mode(ModeGraph(value="auto"), "manual") == "auto"


def test_read_mode_manual_value_overrides_default():
    assert read_response_mode(ModeGraph(value="manual"), "auto") == "manual"


def test_read_mode_swallows_graph_error():
    class Boom:
        def run_cypher(self, *a, **k):
            raise RuntimeError("neo4j down")
    assert read_response_mode(Boom(), "manual") == "manual"


# ---- 收紧2:按批读,不按条 ----
def test_before_batch_reads_config_once_per_batch_not_per_alert():
    g = ModeGraph(value="auto", uids=("a1", "a2", "a3"))
    p = Poller(_pl(g), concurrency=1, once=True, batch=50,
               process_fn=lambda pl, uid, mode: None,
               before_batch=lambda: read_response_mode(g, "manual"))
    p.run()
    assert g.reads == 1                # 3 条告警,:Config 只读 1 次(按批)


# ---- processor 用活态 mode_getter(优先于静态 cfg.response_mode) ----
def test_processor_respects_runtime_mode_getter(monkeypatch):
    inv, autos = [], []
    monkeypatch.setattr(cli, "run_investigation", lambda pl, uid, mode: inv.append(uid))
    monkeypatch.setattr(auto_mod, "auto_respond", lambda g, c, uid: (autos.append(uid), [])[1])
    cfg = Config.from_env(env={})                       # cfg.response_mode 默认 manual
    holder = {"mode": "auto"}
    proc = make_processor(cfg, appliance_client=None, mode_getter=lambda: holder["mode"])
    proc(_pl(object()), "a1", "recipe")
    assert inv == ["a1"] and autos == ["a1"]            # 活态 getter=auto → 自动处置(压过静态 manual)


def test_processor_default_getter_is_static_cfg(monkeypatch):
    inv, autos = [], []
    monkeypatch.setattr(cli, "run_investigation", lambda pl, uid, mode: inv.append(uid))
    monkeypatch.setattr(auto_mod, "auto_respond", lambda g, c, uid: (autos.append(uid), [])[1])
    cfg = Config.from_env(env={})                       # manual
    proc = make_processor(cfg, appliance_client=None)   # 无 getter → 回退静态 cfg.response_mode
    proc(_pl(object()), "a1", "recipe")
    assert inv == ["a1"] and autos == []                # manual → 不自动处置


def test_config_constraint_present():
    assert "c.key IS UNIQUE" in " ".join(build_constraints())
