"""respond CLI 逻辑:人审 gate(approve/reject/request-rollback)+ 列计划。

人审是硬 gate:无 approve 不进 approved(range-runner 只跑 approved)。守卫失败(状态不符/不存在)
→ 返回 False,不谎报成功。
"""
from soc_agent import respond_cli


class FakeGraph:
    def __init__(self, read_rows=None, write_rows=None):
        self._read = read_rows or []
        self._write = write_rows if write_rows is not None else [{"updated": "a1"}]
        self.reads = []
        self.writes = []

    def run_cypher(self, q, **p):
        self.reads.append((q, p))
        return self._read

    def run_write(self, q, **p):
        self.writes.append((q, p))
        return self._write


def test_approve_transitions_and_reports_true():
    g = FakeGraph(write_rows=[{"updated": "a1"}])
    ok = respond_cli.approve(g, "a1", approver="analyst", now="2026-07-15T10:00:00Z")
    assert ok is True
    q, p = g.writes[0]
    assert "'approved'" in q and p["approver"] == "analyst"   # 走 q_approve,记 approver


def test_approve_guard_fail_reports_false():
    g = FakeGraph(write_rows=[])                              # 守卫未命中(非 proposed)→ 无行
    assert respond_cli.approve(g, "a1", approver="x", now="t") is False   # 不谎报成功


def test_reject_and_request_rollback():
    g = FakeGraph(write_rows=[{"updated": "a1"}])
    assert respond_cli.reject(g, "a1", now="t", reason="nope") is True
    assert "'rejected'" in g.writes[0][0]
    g2 = FakeGraph(write_rows=[{"updated": "a1"}])
    assert respond_cli.request_rollback(g2, "a1", now="t") is True
    assert "'rollback_requested'" in g2.writes[0][0]


class FakeClient:
    enabled = True

    def __init__(self):
        self.calls = []

    def execute(self, primitive, params):
        self.calls.append(("execute", primitive, params))
        return {"status": "executed", "execution_id": "ex1",
                "rollback_handle": {"inverse": "enable_account", "params": params}}

    def rollback(self, handle):
        self.calls.append(("rollback", handle))
        return {"status": "executed"}


def test_run_plan_executes_via_client_and_writes_back():
    g = FakeGraph(read_rows=[{"order": 1, "primitive": "disable_account",
                              "params": '{"sam":"hacker2"}', "target": "hacker2"}],
                  write_rows=[{"claimed": "a1"}])
    c = FakeClient()
    r = respond_cli.run_plan(g, c, "a1", now="t", lease_until="t2")
    assert r["ok"] and r["steps"][0]["status"] == "executed"
    assert c.calls[0] == ("execute", "disable_account", {"sam": "hacker2"})   # 参数 json 串解出来传给 appliance
    # claim + record + finish 都写回了(状态转移语句)
    assert any("SET p.status = $to_status" in q for q, _ in g.writes)   # CAS claim
    assert any("d.execution_id = $execution_id" in q for q, _ in g.writes)  # record_step
    assert any("SET p.status = $status" in q for q, _ in g.writes)      # finish


def test_run_plan_claim_fail_returns_error():
    g = FakeGraph(read_rows=[], write_rows=[])          # claim 返回空 → 没领到
    r = respond_cli.run_plan(g, FakeClient(), "a1", now="t", lease_until="t2")
    assert r["ok"] is False and "领取" in r["error"]


def test_rollback_plan_calls_client_and_marks():
    g = FakeGraph(read_rows=[{"order": 2, "rollback_handle": '{"inverse":"enable_account","params":{"sam":"h"}}'}],
                  write_rows=[{"claimed": "a1"}])
    c = FakeClient()
    r = respond_cli.rollback_plan(g, c, "a1", now="t", lease_until="t2")
    assert r["ok"] and c.calls[0][0] == "rollback"
    assert c.calls[0][1] == {"inverse": "enable_account", "params": {"sam": "h"}}   # handle json 解出来


def test_list_pending_joins_steps():
    # 计划列表(读)+ 每个计划的步骤(读)
    g = FakeGraph(read_rows=[{"plan_id": "a1", "status": "proposed", "verdict": "true_positive",
                              "rationale": "RC4 扇出", "alert_uid": "a1", "claimed_by": None}])
    plans = respond_cli.list_plans(g, status="proposed")
    assert plans[0]["plan_id"] == "a1"
    assert "steps" in plans[0]                                # 每个计划带上步骤
    assert any("ResponsePlan {status:$status}" in q for q, _ in g.reads)
    assert any("STEP" in q for q, _ in g.reads)               # 查了步骤
