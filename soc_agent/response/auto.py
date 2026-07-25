"""auto 模式处置编排 + 处置状态中文标识(待处置/已处置)。

- **manual 模式(默认)不调这里**:研判组出的计划留 proposed(=待处置),等 respond_cli 人审。
- **auto 模式**:对某告警新写的 proposed 计划自动 approve;有 appliance 则直接经 HTTP 执行到 executed(=已处置)。
  护栏(NEVER-TOUCH:DC/CA)在 composer 组装侧 + appliance 服务端双重把关 —— auto 执行同样过 appliance,
  受保护目标仍被拒、留待处置,agent 永不自己碰机器。

复用 respond_cli.approve / run_plan(server2 直连 appliance 那套),不另造执行逻辑。
"""
from datetime import datetime, timedelta, timezone

from . import ledger

__all__ = ["auto_respond", "zh_status", "STATUS_ZH", "read_response_mode"]

_MODE_CYPHER = "MATCH (c:Config {key:'response_mode'}) RETURN c.value AS value LIMIT 1"


def read_response_mode(graph, default="manual") -> str:
    """从持久 :Config 读响应模式(manual/auto);缺失/异常 → default(=启动时 cfg.response_mode)。

    ★poller 每批读一次(见 runtime/service),不每条 —— :Config 是毫秒级只读,mode 切换下一批生效即可,
    避免 64 并发下每条一次往返。UI 的 PUT /api/config/response-mode 改这个节点。
    """
    try:
        rows = graph.run_cypher(_MODE_CYPHER)
    except Exception:
        return default
    if not rows or not rows[0].get("value"):
        return default
    return "auto" if str(rows[0]["value"]).strip().lower() == "auto" else "manual"

# 处置状态 → 中文标识(前端/日志用)。用户口径:proposed=待处置、executed=已处置。
STATUS_ZH = {
    "proposed": "待处置",
    "approved": "待处置(已批,待执行)",
    "executing": "处置中",
    "executed": "已处置",
    "failed": "处置失败",
    "rejected": "已驳回",
    "rollback_requested": "待回退",
    "rolling_back": "回退中",
    "rolled_back": "已回退",
    "rollback_failed": "回退失败",
    "none": "无需处置",
}


def zh_status(status) -> str:
    return STATUS_ZH.get(status, status or "未知")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lease(seconds=300) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def auto_respond(graph, client, alert_uid, approver="auto") -> list:
    """auto 模式:该告警新写的 proposed 计划 → 自动 approve;有 appliance 则直接执行到 executed。

    返回每个计划的结果 [{plan_id, approved, executed, steps?}]。无 proposed 计划(如 FP 无处置)→ 空。
    护栏在 composer/appliance 侧,这里不重复判(auto 执行照过 appliance,DC/CA 仍被拒)。
    """
    from ..respond_cli import approve, run_plan          # 惰性:复用人审那套 approve/run_plan
    now = _now()
    c, p = ledger.q_alert_proposed_plans(alert_uid)
    plan_ids = [r["plan_id"] for r in graph.run_cypher(c, **p)]
    out = []
    for pid in plan_ids:
        approve(graph, pid, approver, now)               # proposed → approved(自动批)
        if client is not None and getattr(client, "enabled", False):
            res = run_plan(graph, client, pid, now, _lease())   # approved → executing → executed/failed
            out.append({"plan_id": pid, "approved": True,
                        "executed": bool(res.get("ok")), "steps": res.get("steps")})
        else:
            out.append({"plan_id": pid, "approved": True, "executed": None})  # 无 appliance:approved 挂给 range-runner
    return out
