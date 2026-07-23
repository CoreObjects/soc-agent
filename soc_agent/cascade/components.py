"""cascade 的两个自定义 openJiuwen 组件(subclass WorkflowComponent,override async invoke)。

分叉后两个出口都把**完整 InvestigationResult** 写进一次调用的 `sink`(闭包传入),
run_cascade 跑完从 sink 取回——比从 End 模板里捞对象稳(深度层的 trace/dispositions 不丢)。

- ShallowTerminalComponent:浅层终局(v1 只 false_positive)。造 Verdict(path="S")+写台账,**不 sediment**。
- DeepInvestigationComponent:升级出口。调注入的 run_deep(alert_uid)=现有深度 pipeline,一行不改;
  同步调用用 asyncio.to_thread 包,不堵事件循环。
"""
import asyncio

from openjiuwen.core.workflow import Input, Output, WorkflowComponent
from openjiuwen.core.context_engine import ModelContext
from openjiuwen.core.workflow.components import Session

from ..experience.consult import MatchReport
from ..models import VERDICTS, InvestigationResult, Verdict

__all__ = ["ShallowTerminalComponent", "DeepInvestigationComponent", "CaptureComponent",
           "shallow_report"]

SHALLOW_DECISION = "SHALLOW_TERMINAL"


def shallow_report() -> MatchReport:
    """浅层终局的返回占位,保持 run_pipeline 的 (result, report, picked) 三元形状。"""
    return MatchReport(decision=SHALLOW_DECISION)


class ShallowTerminalComponent(WorkflowComponent):
    """浅层直判终局(放松后:TP 或 FP,取浅层给的 verdict)。写台账;不 snapshot、不 sediment。"""

    def __init__(self, graph, sink: dict, agent_name=None):
        super().__init__()
        self._graph = graph
        self._sink = sink
        self._agent_name = agent_name

    async def invoke(self, inputs: Input, session: Session, context: ModelContext) -> Output:
        alert_uid = inputs.get("alert_uid")
        verdict = inputs.get("verdict") or "false_positive"
        if verdict not in VERDICTS:                       # suspicious 本该升级不到这;非法值兜底 FP
            verdict = "false_positive"
        v = Verdict(
            verdict=verdict,
            confidence=float(inputs.get("confidence") or 0.0),
            summary=f"浅层直判(未升级,{verdict})",
            rationale=inputs.get("rationale") or "",
            agent=self._agent_name,
        )
        result = InvestigationResult(alert_uid=alert_uid, path="S", verdict=v, skill=None)
        self._graph.write_result(alert_uid, result)
        self._sink["result"] = result
        self._sink["report"] = shallow_report()
        self._sink["picked"] = "浅层直判(未升级)"
        return {"path": "S", "verdict": v.verdict, "alert_uid": alert_uid}


class CaptureComponent(WorkflowComponent):
    """把上游(浅层)输出原样抓进 sink['shallow'],供 run_shallow 取回。★仅测量用,不写台账。"""

    def __init__(self, sink: dict):
        super().__init__()
        self._sink = sink

    async def invoke(self, inputs: Input, session: Session, context: ModelContext) -> Output:
        self._sink["shallow"] = dict(inputs)
        return {"ok": True}


class DeepInvestigationComponent(WorkflowComponent):
    """升级到深度研判:调 run_deep(alert_uid) → (result, report, picked)(=现有 run_pipeline 深度半)。"""

    def __init__(self, run_deep, sink: dict):
        super().__init__()
        self._run_deep = run_deep          # callable(alert_uid) -> (InvestigationResult, report, picked)
        self._sink = sink

    async def invoke(self, inputs: Input, session: Session, context: ModelContext) -> Output:
        alert_uid = inputs.get("alert_uid")
        result, report, picked = await asyncio.to_thread(self._run_deep, alert_uid)
        self._sink["result"] = result
        self._sink["report"] = report
        self._sink["picked"] = picked
        return {"path": getattr(result, "path", None), "alert_uid": alert_uid}
