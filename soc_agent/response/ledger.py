"""响应台账队列 + 状态机(纯 Cypher builder;真执行走 Neo4jGraph.run_write / run_cypher)。

响应台账形态(Phase 0 建):
  (:Verdict)-[:LED_TO]->(:ResponsePlan {plan_id,status})-[:STEP {order}]->(:Disposition {...})-[:ON]->实体

状态机:
  ResponsePlan.status: proposed →(人审 approve)approved →(runner CAS claim)executing → executed | failed
                       executed →(请求回退)rollback_requested →(claim)rolling_back → rolled_back | rollback_failed
                       proposed →(reject)rejected
  Disposition.status : proposed → executed | failed | rolled_back

分工:agent 侧管状态 + 人审(approve/reject/request_rollback);range 侧 runner 轮询 approved/rollback_requested、
CAS+lease 领取(防两个 runner 双执行)、跑 ansible、回写 step 结果 + rollback_handle。回退按 order 逆序。

每个函数返回 (cypher, params),便于离线单测,不依赖 neo4j。
"""

__all__ = [
    "q_list_plans", "q_plan_steps", "q_approve", "q_reject", "q_request_rollback",
    "q_claim", "q_record_step", "q_finish_plan", "q_rollbackable_steps", "q_mark_step_rolled_back",
]


def q_list_plans(status):
    """按状态列响应计划(+ 溯源告警/结论)。供 respond CLI 展示 / runner 轮询。"""
    return (
        "MATCH (p:ResponsePlan {status:$status}) "
        "OPTIONAL MATCH (a:Alert {alert_uid:p.plan_id})-[:CONCLUDED]->(v:Verdict) "
        "RETURN p.plan_id AS plan_id, p.status AS status, p.claimed_by AS claimed_by, "
        "       a.alert_uid AS alert_uid, "
        "       head(collect(DISTINCT v.verdict)) AS verdict, "
        "       head(collect(DISTINCT v.rationale)) AS rationale "
        "ORDER BY p.plan_id",
        {"status": status})


def q_plan_steps(plan_id):
    """列一个计划的有序步骤(原语 + 参数 + 目标),供 runner 执行 / CLI 展示。params 是 json 串。"""
    return (
        "MATCH (p:ResponsePlan {plan_id:$plan_id})-[st:STEP]->(d:Disposition) "
        "RETURN st.order AS order, d.step_key AS step_key, d.action AS primitive, "
        "       d.params AS params, d.target AS target, d.target_kind AS target_kind, "
        "       d.risk AS risk, d.status AS status, d.rollback_handle AS rollback_handle "
        "ORDER BY st.order",
        {"plan_id": plan_id})


def _guarded_transition(plan_id, from_status, to_status, extra_set="", params=None):
    sets = f"SET p.status = '{to_status}'" + (", " + extra_set if extra_set else "")
    cypher = (f"MATCH (p:ResponsePlan {{plan_id:$plan_id}}) WHERE p.status = '{from_status}' "
              f"{sets} RETURN p.plan_id AS updated")
    p = {"plan_id": plan_id}
    p.update(params or {})
    return cypher, p


def q_approve(plan_id, approver, at):
    """人审通过:proposed → approved(记 approver/approved_at)。无审批不触发执行。"""
    return _guarded_transition(
        plan_id, "proposed", "approved",
        "p.approver = $approver, p.approved_at = $at",
        {"approver": approver, "at": at})


def q_reject(plan_id, at, reason=None):
    """人审驳回:proposed → rejected。"""
    return _guarded_transition(
        plan_id, "proposed", "rejected",
        "p.rejected_at = $at, p.reject_reason = $reason",
        {"at": at, "reason": reason})


def q_request_rollback(plan_id, at):
    """请求回退:executed → rollback_requested(runner 随后逆序跑 inverse)。"""
    return _guarded_transition(
        plan_id, "executed", "rollback_requested",
        "p.rollback_requested_at = $at", {"at": at})


def q_claim(plan_id, runner, now, lease_until, from_status="approved", to_status="executing"):
    """★CAS + lease 领取(防两个 runner 双执行):仅当状态在 from_status(可给多个,如回退接受 executed|failed),
    或已 to_status 但租约过期(可重领)。Neo4j 写事务对该节点加锁 → 并发下只有一个领到,另一个 WHERE 重判失败、返回空。"""
    froms = from_status if isinstance(from_status, (list, tuple)) else [from_status]
    return (
        "MATCH (p:ResponsePlan {plan_id:$plan_id}) "
        "WHERE p.status IN $from_statuses "
        "   OR (p.status = $to_status AND coalesce(p.lease_until, '') < $now) "
        "SET p.status = $to_status, p.claimed_by = $runner, p.lease_until = $lease_until, p.claimed_at = $now "
        "RETURN p.plan_id AS claimed",
        {"plan_id": plan_id, "runner": runner, "now": now, "lease_until": lease_until,
         "from_statuses": list(froms), "to_status": to_status})


def q_record_step(plan_id, order, status, execution_id=None, rollback_handle=None, error=None, at=None):
    """回写一步执行结果 + 回退凭据(rollback_handle 为 json 串)。"""
    return (
        "MATCH (p:ResponsePlan {plan_id:$plan_id})-[st:STEP {order:$order}]->(d:Disposition) "
        "SET d.status = $status, d.execution_id = $execution_id, d.rollback_handle = $rollback_handle, "
        "    d.error = $error, d.executed_at = $at "
        "RETURN d.step_key AS step_key",
        {"plan_id": plan_id, "order": order, "status": status, "execution_id": execution_id,
         "rollback_handle": rollback_handle, "error": error, "at": at})


def q_finish_plan(plan_id, status, at):
    """计划落终态:executed | failed | rolled_back | rollback_failed。"""
    return (
        "MATCH (p:ResponsePlan {plan_id:$plan_id}) SET p.status = $status, p.finished_at = $at "
        "RETURN p.plan_id AS plan_id",
        {"plan_id": plan_id, "status": status, "at": at})


def q_rollbackable_steps(plan_id):
    """已执行、有回退凭据的步骤,★按 order 逆序(后做的先撤)。"""
    return (
        "MATCH (p:ResponsePlan {plan_id:$plan_id})-[st:STEP]->(d:Disposition) "
        "WHERE d.status = 'executed' AND d.rollback_handle IS NOT NULL "
        "RETURN st.order AS order, d.step_key AS step_key, d.rollback_handle AS rollback_handle "
        "ORDER BY st.order DESC",
        {"plan_id": plan_id})


def q_mark_step_rolled_back(plan_id, order, at=None):
    """一步回退成功 → step 置 rolled_back。"""
    return (
        "MATCH (p:ResponsePlan {plan_id:$plan_id})-[st:STEP {order:$order}]->(d:Disposition) "
        "SET d.status = 'rolled_back', d.rolled_back_at = $at RETURN d.step_key AS step_key",
        {"plan_id": plan_id, "order": order, "at": at})
