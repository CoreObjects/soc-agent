"""cascade 入口:load Alert → 算 force_deep → 跑 openJiuwen 图 → 从 sink 取回 (result, report, picked)。

返回三元形状与 `run_pipeline` 一致,`cli.main` 据 `cascade_enabled` 二选一,下游 render 不用改。
"""
import asyncio
import json
import os

from ..models import Alert
from .build import build_cascade_agent, build_shallow_probe
from .floor import force_deep

__all__ = ["run_cascade", "run_shallow", "alert_view"]


def _ensure_workflow_timeout(seconds):
    """抬 openJiuwen 工作流执行超时:它默认才 60s(session 从 OS env WORKFLOW_EXECUTE_TIMEOUT 读),
    qwen 在昇腾单次调用常 >60s 会被 workflow 层掐断(报 100101)。用户已设 OS env 则尊重其值。"""
    os.environ.setdefault("WORKFLOW_EXECUTE_TIMEOUT", str(int(seconds)))


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

    # 工作流要包住深度研判(可能多轮 LLM,很久)→ 抬得比单次 LLM 超时大得多
    _ensure_workflow_timeout(max(1800, getattr(pl, "llm_timeout", 600) * 3))
    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    fd = force_deep(alert, pl.policy)

    sink = {}
    agent = build_cascade_agent(
        pl.graph, lambda uid: run_pipeline(pl, uid, mode), sink,
        llm_base=pl.llm_base, llm_model=pl.llm_model, llm_key=pl.llm_key,
        llm_timeout=getattr(pl, "llm_timeout", 600), agent_name=pl.agent_name)

    asyncio.run(Runner.run_agent(agent, {
        "alert_view": alert_view(alert), "alert_uid": alert_uid, "force_deep": bool(fd)}))
    return sink["result"], sink["report"], sink["picked"]


def run_shallow(pl, alert_uid, shallow_comp=None):
    """只跑浅层分诊(不升级、不写台账)。返回 {alert_uid, technique, force_deep, shallow, route}。
    route: escalate(needs_deep 或 force_deep)/ terminal_fp(浅层判良性终局)。供 selftest 量 deferral。"""
    from ..cli import AlertNotFound                       # 懒导入,避 cli<->cascade 循环
    from openjiuwen.core.workflow import create_workflow_session

    _ensure_workflow_timeout(getattr(pl, "llm_timeout", 600))    # 单次浅层 qwen 调用,够
    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    fd = force_deep(alert, pl.policy)

    sink = {}

    async def _go():
        flow = build_shallow_probe(sink, llm_base=pl.llm_base, llm_model=pl.llm_model,
                                   llm_key=pl.llm_key, llm_timeout=getattr(pl, "llm_timeout", 600),
                                   shallow_comp=shallow_comp)
        await flow.invoke({"alert_view": alert_view(alert)}, create_workflow_session())

    asyncio.run(_go())
    shallow = sink.get("shallow") or {}
    if bool(shallow.get("needs_deep")) or fd:
        route = "escalate"
    else:
        route = "terminal_tp" if shallow.get("verdict") == "true_positive" else "terminal_fp"
    return {"alert_uid": alert_uid, "technique": alert.primary_technique,
            "force_deep": fd, "shallow": shallow, "route": route}
