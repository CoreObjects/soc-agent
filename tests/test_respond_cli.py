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


def test_list_pending_joins_steps():
    # 计划列表(读)+ 每个计划的步骤(读)
    g = FakeGraph(read_rows=[{"plan_id": "a1", "status": "proposed", "verdict": "true_positive",
                              "rationale": "RC4 扇出", "alert_uid": "a1", "claimed_by": None}])
    plans = respond_cli.list_plans(g, status="proposed")
    assert plans[0]["plan_id"] == "a1"
    assert "steps" in plans[0]                                # 每个计划带上步骤
    assert any("ResponsePlan {status:$status}" in q for q, _ in g.reads)
    assert any("STEP" in q for q, _ in g.reads)               # 查了步骤
