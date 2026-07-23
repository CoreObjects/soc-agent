"""cascade 入口:load Alert → 算 force_deep → 跑 openJiuwen 图 → 从 sink 取回 (result, report, picked)。

返回三元形状与 `run_pipeline` 一致,`cli.main` 据 `cascade_enabled` 二选一,下游 render 不用改。
"""
import asyncio
import json

from ..models import Alert
from .build import build_cascade_agent
from .floor import force_deep

__all__ = ["run_cascade", "alert_view"]


def alert_view(alert) -> str:
    """喂浅层 LLM 的告警视图(只读字段,含原文 raw)——不 seed、不取证。"""
    return json.dumps({
        "alert_uid": alert.alert_uid,
        "rule_description": alert.rule_description,
        "source": alert.source,
        "sensor": alert.sensor,
        "severity": alert.severity,
        "technique_ids": alert.technique_ids,
        "raw": alert.raw,
    }, ensure_ascii=False, default=str)


def run_cascade(pl, alert_uid, mode="recipe"):
    """浅判→判不动升级深度。返回 (result, report, picked)。"""
    from ..cli import AlertNotFound, run_pipeline        # 懒导入,避 cli<->cascade 循环
    from openjiuwen.core.runner.runner import Runner

    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    fd = force_deep(alert, pl.policy)

    sink = {}
    agent = build_cascade_agent(
        pl.graph, lambda uid: run_pipeline(pl, uid, mode), sink,
        llm_base=pl.llm_base, llm_model=pl.llm_model, llm_key=pl.llm_key,
        agent_name=pl.agent_name)

    asyncio.run(Runner.run_agent(agent, {
        "alert_view": alert_view(alert), "alert_uid": alert_uid, "force_deep": bool(fd)}))
    return sink["result"], sink["report"], sink["picked"]
