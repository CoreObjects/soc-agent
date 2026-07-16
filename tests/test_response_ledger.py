"""响应台账队列/状态机的 Cypher builder(纯逻辑;真执行在 server2 图)。

状态机:proposed →(人审)approved →(runner CAS claim)executing → executed|failed;
       executed →(请求回退)rollback_requested →(claim)rolling_back → rolled_back。
CAS+lease 防两个 runner 双执行;回退按 order 逆序。
"""
from soc_agent.response import ledger


def test_list_plans_filters_by_status():
    c, p = ledger.q_list_plans("proposed")
    assert "ResponsePlan {status:$status}" in c and p["status"] == "proposed"


def test_plan_steps_ordered():
    c, p = ledger.q_plan_steps("a1")
    assert "STEP" in c and "ORDER BY st.order" in c and p["plan_id"] == "a1"
    assert "d.action AS primitive" in c and "d.params AS params" in c   # runner 拿原语+参数执行


def test_approve_is_guarded_proposed_to_approved():
    c, p = ledger.q_approve("a1", approver="analyst", at="2026-07-15T10:00:00Z")
    assert "WHERE p.status = 'proposed'" in c            # 只能从 proposed 批准
    assert "p.status = 'approved'" in c
    assert p["approver"] == "analyst" and p["at"] == "2026-07-15T10:00:00Z"
    assert p["plan_id"] == "a1"


def test_reject_guarded():
    c, p = ledger.q_reject("a1", at="t", reason="不同意")
    assert "WHERE p.status = 'proposed'" in c and "'rejected'" in c
    assert p["reason"] == "不同意"


def test_request_rollback_only_from_executed():
    c, p = ledger.q_request_rollback("a1", at="t")
    assert "WHERE p.status = 'executed'" in c and "'rollback_requested'" in c


def test_claim_is_cas_with_lease_expiry():
    c, p = ledger.q_claim("a1", runner="r1", now="t2", lease_until="t3",
                          from_status="approved", to_status="executing")
    # CAS:仅当仍 approved,或已 executing 但租约过期(可重领)才领
    assert "p.status = $from_status" in c
    assert "p.status = $to_status AND coalesce(p.lease_until, '') < $now" in c
    assert "SET p.status = $to_status" in c and "p.claimed_by = $runner" in c
    assert p["runner"] == "r1" and p["now"] == "t2" and p["lease_until"] == "t3"
    assert p["from_status"] == "approved" and p["to_status"] == "executing"


def test_record_step_writes_result_and_handle():
    c, p = ledger.q_record_step("a1", order=2, status="executed",
                                execution_id="ex1", rollback_handle='{"inverse":"enable_account"}',
                                error=None, at="t")
    assert "STEP {order:$order}" in c and "d.status = $status" in c
    assert "d.execution_id = $execution_id" in c and "d.rollback_handle = $rollback_handle" in c
    assert p["order"] == 2 and p["execution_id"] == "ex1"
    assert p["rollback_handle"] == '{"inverse":"enable_account"}'


def test_finish_plan_sets_terminal_status():
    c, p = ledger.q_finish_plan("a1", status="executed", at="t")
    assert "SET p.status = $status" in c and p["status"] == "executed"


def test_rollbackable_steps_reverse_order_only_executed_with_handle():
    c, p = ledger.q_rollbackable_steps("a1")
    assert "d.status = 'executed'" in c and "d.rollback_handle IS NOT NULL" in c
    assert "ORDER BY st.order DESC" in c                 # ★逆序回退
    assert p["plan_id"] == "a1"
