"""cascade 入口:load Alert → 算 force_deep → 跑 openJiuwen 图 → 从 sink 取回 (result, report, picked)。

返回三元形状与 `run_pipeline` 一致,`cli.main` 据 `cascade_enabled` 二选一,下游 render 不用改。
"""
import asyncio
import json
import os

from ..models import Alert
from .build import build_cascade_agent, build_shallow_probe
from .floor import force_deep
from .signature import payload_case_of, sig_consult, sig_sediment

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
    """签名库前置(命中零 qwen 复用)→ 浅判 → 判不动升级深度 → 浅层终局蒸签名。返回 (result, report, picked)。"""
    from ..cli import AlertNotFound, run_pipeline        # 懒导入,避 cli<->cascade 循环
    from ..experience.consult import MatchReport
    from ..models import InvestigationResult, Verdict
    from openjiuwen.core.runner.runner import Runner

    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)

    # ★签名库前置(决策 A):只对 **false_positive** 直接复用短路(零 qwen);命中 TP 签名 → 不短路、强制升级深度
    sig_store = getattr(pl, "exp_store", None)
    hit = sig_consult(sig_store, alert)
    if hit is not None and hit.verdict == "false_positive":
        sig_store.bump_hit(hit.exp_id)
        v = Verdict(verdict="false_positive", confidence=0.9, summary="签名库复用",
                    rationale=f"签名库复用 payload 规则 {hit.exp_id[:8]}(kind=payload)", agent=pl.agent_name)
        result = InvestigationResult(alert_uid=alert_uid, path="S", verdict=v, skill=None,
                                     reuse_verdict_id=hit.origin_verdict_id)
        pl.graph.write_result(alert_uid, result)
        return result, MatchReport(decision="SIG_REUSE"), "签名库复用(零qwen)"

    tp_sig = hit is not None and hit.verdict == "true_positive"
    if tp_sig:
        sig_store.bump_hit(hit.exp_id)                       # TP 签名命中也记一次(观测),但走深度
    fd = force_deep(alert, pl.policy) or tp_sig              # ★决策 A:TP 签名命中 → 强制升级深度(跳过浅层 LLM)
    # 工作流要包住深度研判(可能多轮 LLM,很久)→ 抬得比单次 LLM 超时大得多
    _ensure_workflow_timeout(max(1800, getattr(pl, "llm_timeout", 600) * 3))
    sink = {}
    agent = build_cascade_agent(
        pl.graph, lambda uid: run_pipeline(pl, uid, mode), sink,
        llm_base=pl.llm_base, llm_model=pl.llm_model, llm_key=pl.llm_key,
        llm_timeout=getattr(pl, "llm_timeout", 600), agent_name=pl.agent_name)

    asyncio.run(Runner.run_agent(agent, {
        "alert_view": alert_view(alert), "alert_uid": alert_uid, "force_deep": bool(fd)}))
    result, report, picked = sink["result"], sink["report"], sink["picked"]

    # ★浅层终局(path="S",没升级深度)→ 从 payload 蒸签名规则入库 + 记语料
    if sig_store is not None and getattr(result, "path", None) == "S":
        _sig_learn(pl, sig_store, getattr(pl, "payload_corpus", None), alert, result)
    return result, report, picked


def run_shallow(pl, alert_uid, shallow_comp=None, sig_store=None, sig_corpus=None):
    """只跑浅层分诊(不升级、不写台账)。返回 {alert_uid, technique, force_deep, shallow, route, reused}。
    route: escalate / terminal_tp / terminal_fp / reuse_tp / reuse_fp(签名库命中,零 qwen)。
    传 sig_store(+sig_corpus 列表)则:先查签名库命中即复用;未命中判完从 payload 蒸规则入库+记语料。"""
    from ..cli import AlertNotFound                       # 懒导入,避 cli<->cascade 循环
    from openjiuwen.core.workflow import create_workflow_session

    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)
    fd = force_deep(alert, pl.policy)

    # ★签名库前置(决策 A):只 FP 直接复用短路;命中 TP 签名 → 升级深度(不短路、不跑浅层 LLM)
    hit = sig_consult(sig_store, alert)
    if hit is not None and hit.verdict == "false_positive":
        sig_store.bump_hit(hit.exp_id)
        return {"alert_uid": alert_uid, "technique": alert.primary_technique, "force_deep": fd, "reused": True,
                "shallow": {"needs_deep": False, "verdict": "false_positive", "confidence": None,
                            "rationale": f"签名库复用 {hit.exp_id[:8]}"}, "route": "reuse_fp"}
    if hit is not None and hit.verdict == "true_positive":
        sig_store.bump_hit(hit.exp_id)
        return {"alert_uid": alert_uid, "technique": alert.primary_technique, "force_deep": fd, "reused": False,
                "shallow": {"needs_deep": True, "verdict": "true_positive", "confidence": None,
                            "rationale": f"TP 签名命中 {hit.exp_id[:8]} → 决策A 升级深度"}, "route": "escalate"}

    _ensure_workflow_timeout(getattr(pl, "llm_timeout", 600))    # 单次浅层 qwen 调用,够
    sink = {}

    async def _go():
        flow = build_shallow_probe(sink, llm_base=pl.llm_base, llm_model=pl.llm_model,
                                   llm_key=pl.llm_key, llm_timeout=getattr(pl, "llm_timeout", 600),
                                   shallow_comp=shallow_comp)
        await flow.invoke({"alert_view": alert_view(alert)}, create_workflow_session())

    asyncio.run(_go())
    shallow = sink.get("shallow") or {}
    # 决策 A:只 false_positive 终局;needs_deep / force_deep / 非 FP(TP/suspicious)一律升级
    if bool(shallow.get("needs_deep")) or fd or shallow.get("verdict") != "false_positive":
        route = "escalate"
    else:
        route = "terminal_fp"

    # ★浅层终局(只 FP)→ 从 payload 蒸签名规则入库 + 记语料(供反例回归)
    if sig_store is not None and route == "terminal_fp":
        from ..models import InvestigationResult, Verdict
        v = Verdict(verdict=shallow.get("verdict"), confidence=float(shallow.get("confidence") or 0.0),
                    rationale=shallow.get("rationale") or "", agent=pl.agent_name)
        _sig_learn(pl, sig_store, sig_corpus, alert,
                   InvestigationResult(alert_uid=alert_uid, path="S", verdict=v, skill=None))

    return {"alert_uid": alert_uid, "technique": alert.primary_technique,
            "force_deep": fd, "shallow": shallow, "route": route, "reused": False}


def _sig_learn(pl, sig_store, sig_corpus, alert, result):
    """浅层终局 → 蒸签名规则(过考试门:回放+反例回归)入库 + 追加浅层语料。"""
    v = getattr(result, "verdict", None)
    if v is None or v.verdict not in ("true_positive", "false_positive"):
        return
    opposite = sig_corpus.for_source(getattr(alert, "source", None)) if sig_corpus is not None else []
    sig_sediment(pl.llm, sig_store, opposite, alert, result, agent_name=pl.agent_name)
    if sig_corpus is not None:
        sig_corpus.add(payload_case_of(alert, v.verdict))
