"""cascade 入口:load Alert → 算 force_deep → 跑 openJiuwen 图 → 从 sink 取回 (result, report, picked)。

返回三元形状与 `run_pipeline` 一致,`cli.main` 据 `cascade_enabled` 二选一,下游 render 不用改。
"""
import asyncio
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from openjiuwen.core.workflow import create_workflow_session

from ..models import Alert
from .build import build_shallow_probe
from .floor import force_deep
from .signature import payload_case_of, sig_consult, sig_sediment

__all__ = ["run_cascade", "run_shallow", "alert_view"]

_loop_tls = threading.local()

# openJiuwen 专用单线程执行器:Runner 是进程级单例、异步态绑定单一 event loop,多 worker 线程并发调用会踩坏它
# (sink 空/挂死)→ 所有浅层 openJiuwen 调用丢到这一个线程/loop 上串行跑。深度是纯 Python,在 worker 线程并行。
_OJW_EXECUTOR = None
_OJW_LOCK = threading.Lock()


def _ensure_thread_loop():
    """给当前线程建并 set 一个持久事件循环(idempotent)。

    ★必须在 openJiuwen 同步构建(build_cascade_agent 等)**之前**调用:poller 的非主 worker 线程若未
    set_event_loop,openJiuwen 内部同步调 get_event_loop 会报 'There is no current event loop in thread'
    (build 发生在 _run_coro 之外,只在 _run_coro 里 set 太晚)。主线程(cli.main)同样适用。"""
    loop = getattr(_loop_tls, "loop", None)
    if loop is not None and not loop.is_closed():
        return loop
    try:                                # 复用线程已 set 的 loop(如 poller worker 初始化时 set 的)
        existing = asyncio.get_event_loop()
        if existing is not None and not existing.is_closed():
            _loop_tls.loop = existing
            return existing
    except RuntimeError:
        pass
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _loop_tls.loop = loop
    return loop


def _run_coro(coro):
    return _ensure_thread_loop().run_until_complete(coro)


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


def _ojw_executor():
    """openJiuwen 专用单线程执行器(lazy 建;进程退出 atexit 自动收)。"""
    global _OJW_EXECUTOR
    if _OJW_EXECUTOR is None:
        with _OJW_LOCK:
            if _OJW_EXECUTOR is None:
                _OJW_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ojw-shallow")
    return _OJW_EXECUTOR


def _shallow_decision(pl, alert) -> dict:
    """在专用单线程/单 loop 上跑浅层 openJiuwen 探针,返回 {needs_deep, verdict, confidence, rationale}。
    ★所有浅层调用都在这一个线程串行 → 规避 openJiuwen(Runner 单例 + loop 绑定)非线程安全。"""
    def _task():
        _ensure_workflow_timeout(getattr(pl, "llm_timeout", 600))

        async def _go():
            sink = {}
            flow = build_shallow_probe(sink, llm_base=pl.llm_base, llm_model=pl.llm_model,
                                       llm_key=pl.llm_key, llm_timeout=getattr(pl, "llm_timeout", 600))
            await flow.invoke({"alert_view": alert_view(alert)}, create_workflow_session())
            return sink.get("shallow") or {}

        return _run_coro(_go())

    return _ojw_executor().submit(_task).result()


def run_cascade(pl, alert_uid, mode="recipe"):
    """签名库前置(FP 零 qwen 复用)→ 浅层分诊(openJiuwen 专用单线程串行)→ 决策A(只 FP 终局,余升级)
    → 升级直接跑深度 run_pipeline(worker 线程并行)。返回 (result, report, picked)。

    ★浅层为何单线程:openJiuwen 的 Runner 是**进程级单例**、异步态绑定单一 event loop —— poller 多 worker
    线程并发调用会踩坏它(sink 空/挂死)。故 openJiuwen 只在 _ojw_executor 那一个线程/loop 上串行;
    深度是纯 Python(图/qwen/OG,per-worker 连接),在 worker 线程**并行**。"""
    from ..cli import AlertNotFound, run_pipeline        # 懒导入,避 cli<->cascade 循环
    from ..experience.consult import MatchReport
    from ..models import InvestigationResult, Verdict

    node = pl.graph.get_alert(alert_uid)
    if node is None:
        raise AlertNotFound(f"图里没有 alert_uid={alert_uid} 的 :Alert")
    alert = Alert.from_node(node)

    # ★签名库前置(决策 A):只对 false_positive 直接复用短路(零 qwen);命中 TP 签名 → 不短路、强制升级深度
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

    # ★浅层分诊(除非签名/floor 已强制升级)——决策 A:只终局 false_positive,其余(TP/suspicious/needs_deep)升级
    if not (tp_sig or force_deep(alert, pl.policy)):
        shallow = _shallow_decision(pl, alert)
        if not shallow.get("needs_deep") and shallow.get("verdict") == "false_positive":
            v = Verdict(verdict="false_positive", confidence=float(shallow.get("confidence") or 0.0),
                        summary="浅层直判(未升级,false_positive)", rationale=shallow.get("rationale") or "",
                        agent=pl.agent_name)
            result = InvestigationResult(alert_uid=alert_uid, path="S", verdict=v, skill=None)
            pl.graph.write_result(alert_uid, result)
            if sig_store is not None:                        # 浅层 FP 终局 → 从 payload 蒸签名入库 + 记语料
                _sig_learn(pl, sig_store, getattr(pl, "payload_corpus", None), alert, result)
            return result, MatchReport(decision="SHALLOW_TERMINAL"), "浅层直判(未升级)"
        # 非 FP → 落到下面升级深度

    # ★升级深度:直接跑现有 run_pipeline(纯 Python,worker 线程并行;不经 openJiuwen)
    return run_pipeline(pl, alert_uid, mode)


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

    _run_coro(_go())
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
