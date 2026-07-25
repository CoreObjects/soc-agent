"""处置计划:读(待处置队列)+ 写(approve/reject/execute/rollback)。

★写全是 respond_cli 的 HTTP 薄封 —— 不自建执行逻辑。护栏(NEVER-TOUCH:DC/CA)在
respond_cli→ApplianceClient→appliance 内层,API 在最外层拦不掉;execute 必经 run_plan→appliance。
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends

from ...response.auto import zh_status
from ..deps import get_appliance, get_graph, require_token
from ..util import loads

router = APIRouter(prefix="/api", tags=["plans"], dependencies=[Depends(require_token)])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lease(seconds=300) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/plans")
def list_plans_route(status: str = "proposed", graph=Depends(get_graph)):
    """按状态列响应计划 + 有序步骤(= respond_cli.list_plans),附中文状态。"""
    from ...respond_cli import list_plans
    plans = list_plans(graph, status)
    for pl in plans:
        pl["status_zh"] = zh_status(pl.get("status"))
        for s in pl.get("steps") or []:
            s["status_zh"] = zh_status(s.get("status"))
            s["params"] = loads(s.get("params"))
    return {"plans": plans}


@router.post("/plans/{plan_id}/approve")
def approve_plan(plan_id: str, payload: dict = Body(default={}), graph=Depends(get_graph)):
    """人审通过:proposed → approved(薄封 respond_cli.approve)。"""
    from ...respond_cli import approve
    by = (payload or {}).get("by") or "analyst"
    ok = approve(graph, plan_id, by, _now())
    return {"ok": ok, "plan_id": plan_id,
            "status": "approved" if ok else None,
            "status_zh": zh_status("approved") if ok else None}


@router.post("/plans/{plan_id}/reject")
def reject_plan(plan_id: str, payload: dict = Body(default={}), graph=Depends(get_graph)):
    """人审驳回:proposed → rejected(薄封 respond_cli.reject)。"""
    from ...respond_cli import reject
    reason = (payload or {}).get("reason")
    ok = reject(graph, plan_id, _now(), reason)
    return {"ok": ok, "plan_id": plan_id,
            "status": "rejected" if ok else None,
            "status_zh": zh_status("rejected") if ok else None}


@router.post("/plans/{plan_id}/execute")
def execute_plan(plan_id: str, graph=Depends(get_graph), appliance=Depends(get_appliance)):
    """执行已批准计划(薄封 respond_cli.run_plan → appliance)。护栏拒的步骤 refused 如实透出。"""
    from ...respond_cli import run_plan
    if not getattr(appliance, "enabled", False):
        return {"ok": False, "plan_id": plan_id,
                "error": "未配 appliance(RESPONSE_URL);计划保持已批待执行,可走靶场 range-runner"}
    res = run_plan(graph, appliance, plan_id, _now(), _lease())
    for s in res.get("steps") or []:
        s["status_zh"] = zh_status(s.get("status"))
    return {"ok": res.get("ok"), "error": res.get("error"),
            "steps": res.get("steps") or [], "plan_id": plan_id}


@router.post("/plans/{plan_id}/rollback")
def rollback_plan_route(plan_id: str, graph=Depends(get_graph), appliance=Depends(get_appliance)):
    """回退:有 appliance 直接逆序回退(rollback_plan);无则记回退意图(request_rollback)。"""
    from ...respond_cli import request_rollback, rollback_plan
    if getattr(appliance, "enabled", False):
        res = rollback_plan(graph, appliance, plan_id, _now(), _lease())
        for s in res.get("steps") or []:
            s["status_zh"] = zh_status(s.get("status"))
        return {"ok": res.get("ok"), "error": res.get("error"),
                "steps": res.get("steps") or [], "plan_id": plan_id}
    ok = request_rollback(graph, plan_id, _now())
    return {"ok": ok, "plan_id": plan_id,
            "status": "rollback_requested" if ok else None,
            "status_zh": zh_status("rollback_requested") if ok else None}
