"""Web 写路由 + 鉴权单测:approve/reject/execute/rollback 薄封 respond_cli;token 401;护栏路由。

★护栏(NEVER-TOUCH:DC/CA)在 appliance 服务端;单测只验 API **不旁路**——execute 必经 run_plan→appliance,
appliance 拒(refused)如实透出、不谎报已处置。真拒绝在 server2 e2e 验。
"""
import json

import pytest
from fastapi.testclient import TestClient

from soc_agent.config import Config
from soc_agent.web import deps
from soc_agent.web.app import create_app


class FakeGraphW:
    """支持 ledger 状态机写(run_write)+ 步骤读(run_cypher)。"""

    def __init__(self, steps=None, claim_ok=True):
        self.steps = steps if steps is not None else [{
            "order": 1, "step_key": "p1#1", "primitive": "disable_account",
            "params": json.dumps({"sam": "vagrant"}), "target": "vagrant", "target_kind": "account",
            "risk": "high", "status": "proposed", "rollback_handle": None}]
        self.claim_ok = claim_ok
        self.writes = []

    def run_write(self, cypher, **p):
        self.writes.append((cypher, p))
        if "p.status IN $from_statuses" in cypher:                 # q_claim
            return [{"claimed": p["plan_id"]}] if self.claim_ok else []
        if "d.execution_id = $execution_id" in cypher:             # q_record_step
            return [{"step_key": "x"}]
        if "p.finished_at = $at" in cypher:                        # q_finish_plan
            return [{"plan_id": p["plan_id"]}]
        if "SET p.status = 'approved'" in cypher:                  # q_approve
            return [{"updated": p["plan_id"]}]
        if "SET p.status = 'rejected'" in cypher:                  # q_reject
            return [{"updated": p["plan_id"]}]
        if "SET p.status = 'rollback_requested'" in cypher:        # q_request_rollback
            return [{"updated": p["plan_id"]}]
        return []

    def run_cypher(self, cypher, **p):
        if "st.order AS order" in cypher:                          # q_plan_steps
            return list(self.steps)
        if "d.status = 'executed'" in cypher:                      # q_rollbackable_steps
            return [s for s in self.steps if s.get("status") == "executed"]
        return []


class FakeAppliance:
    def __init__(self, enabled=True, refuse=()):
        self.enabled = enabled
        self.refuse = set(refuse)
        self.calls = []

    def execute(self, primitive, params):
        self.calls.append((primitive, params))
        if params.get("sam") in self.refuse:                       # 服务端护栏:受保护目标拒
            return {"status": "refused", "error": "NEVER-TOUCH 受保护目标", "output": ""}
        return {"status": "executed", "execution_id": "e1",
                "rollback_handle": {"inverse": "enable_account", "params": params}, "output": "ok"}

    def rollback(self, handle):
        return {"status": "executed"}


def _client(graph, appliance=None, token=""):
    app = create_app()
    app.dependency_overrides[deps.get_graph] = lambda: graph
    app.dependency_overrides[deps.get_appliance] = lambda: appliance or FakeAppliance()
    app.dependency_overrides[deps.get_config] = lambda: Config.from_env(
        env={"SOC_WEB_TOKEN": token} if token else {})
    return TestClient(app)


def test_approve_thin_wraps_ledger():
    g = FakeGraphW()
    r = _client(g).post("/api/plans/p1/approve", json={"by": "alice"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["status_zh"] == "待处置(已批,待执行)"
    assert any("SET p.status = 'approved'" in c for c, _ in g.writes)


def test_approve_empty_body_defaults():
    g = FakeGraphW()
    r = _client(g).post("/api/plans/p1/approve")               # 无 body → by 默认
    assert r.status_code == 200 and r.json()["ok"] is True


def test_reject_thin_wraps_ledger():
    g = FakeGraphW()
    r = _client(g).post("/api/plans/p1/reject", json={"reason": "误报"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert any("SET p.status = 'rejected'" in c for c, _ in g.writes)


def test_execute_routes_through_run_plan_and_appliance():
    g, ap = FakeGraphW(), FakeAppliance()
    r = _client(g, ap).post("/api/plans/p1/execute")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert ap.calls == [("disable_account", {"sam": "vagrant"})]     # 必经 appliance,不旁路
    assert body["steps"][0]["status"] == "executed"
    assert body["steps"][0]["status_zh"] == "已处置"


def test_execute_dc_target_refused_surfaces_not_executed():
    # 护栏:DC 账号 → appliance 拒;API 如实透出 refused,不标已处置
    steps = [{"order": 1, "step_key": "p1#1", "primitive": "disable_account",
              "params": json.dumps({"sam": "dc01$"}), "target": "dc01$", "target_kind": "account",
              "risk": "high", "status": "proposed", "rollback_handle": None}]
    g, ap = FakeGraphW(steps=steps), FakeAppliance(refuse={"dc01$"})
    r = _client(g, ap).post("/api/plans/p1/execute")
    assert r.status_code == 200
    assert ap.calls == [("disable_account", {"sam": "dc01$"})]       # 确实打到 appliance
    assert r.json()["steps"][0]["status"] == "refused"              # 被拒、非 executed


def test_execute_without_appliance_returns_error():
    g = FakeGraphW()
    r = _client(g, FakeAppliance(enabled=False)).post("/api/plans/p1/execute")
    assert r.status_code == 200 and r.json()["ok"] is False and "appliance" in r.json()["error"]


def test_rollback_requests_when_no_appliance():
    g = FakeGraphW()
    r = _client(g, FakeAppliance(enabled=False)).post("/api/plans/p1/rollback")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert any("SET p.status = 'rollback_requested'" in c for c, _ in g.writes)


# ---- 鉴权 ----
def test_write_requires_token_401_without():
    g = FakeGraphW()
    r = _client(g, token="s3cret").post("/api/plans/p1/approve")
    assert r.status_code == 401


def test_write_ok_with_correct_bearer():
    g = FakeGraphW()
    c = _client(g, token="s3cret")
    r = c.post("/api/plans/p1/approve", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and r.json()["ok"] is True


def test_read_also_guarded_when_token_set():
    g = FakeGraphW()
    r = _client(g, token="s3cret").get("/api/alerts")
    assert r.status_code == 401                                    # token 配了,读也要 Bearer
