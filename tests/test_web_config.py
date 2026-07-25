"""Web 模式开关路由:GET/PUT /api/config/response-mode(读/写持久 :Config)。"""
from fastapi.testclient import TestClient

from soc_agent.config import Config
from soc_agent.web import deps
from soc_agent.web.app import create_app


class CfgGraph:
    def __init__(self, value=None):
        self.value = value
        self.writes = []

    def run_cypher(self, cypher, **p):
        if "(c:Config {key:$key})" in cypher and "RETURN c.value" in cypher:
            return [{"value": self.value}] if self.value is not None else []
        return []

    def run_write(self, cypher, **p):
        self.writes.append((cypher, p))
        if "MERGE (c:Config {key:$key})" in cypher:
            self.value = p["value"]
        return [{"value": p.get("value")}]


def _client(graph):
    app = create_app()
    app.dependency_overrides[deps.get_graph] = lambda: graph
    app.dependency_overrides[deps.get_config] = lambda: Config.from_env(env={})
    return TestClient(app)


def test_get_mode_defaults_manual_when_unset():
    r = _client(CfgGraph()).get("/api/config/response-mode")
    assert r.status_code == 200 and r.json()["mode"] == "manual"


def test_put_mode_auto_persists_and_reads_back():
    g = CfgGraph()
    c = _client(g)
    r = c.put("/api/config/response-mode", json={"mode": "auto"})
    assert r.status_code == 200 and r.json()["mode"] == "auto"
    assert any("MERGE (c:Config {key:$key})" in cy for cy, _ in g.writes)
    assert c.get("/api/config/response-mode").json()["mode"] == "auto"      # 读回持久值


def test_put_mode_invalid_400():
    r = _client(CfgGraph()).put("/api/config/response-mode", json={"mode": "weird"})
    assert r.status_code == 400
