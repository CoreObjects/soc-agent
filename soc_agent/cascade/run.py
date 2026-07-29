"""cascade 入口:签名库前置 → 浅层 LLM 分诊(QwenClient)→ 决策A(只 FP 终局)→ 升级深度 run_pipeline。

★浅层 LLM 用 **QwenClient**(与深度同款,直连昇腾 qwen,默认关思维链、稳)——**不再用 openJiuwen**:
其 LLMComponent 客户端在持续负载下 ~50% 调用失败(101003),同端点 QwenClient 100% 稳。详见
`docs/openjiuwen-踩坑总结.md`。全 Python、无 Runner 单例/事件循环,可多线程并发。
返回三元形状与 `run_pipeline` 一致,`cli.main` 据 `cascade_enabled` 二选一,下游 render 不用改。
"""
import json

from ..models import VERDICTS, Alert
from .floor import force_deep
from .prompt import SHALLOW_PROMPT
from .signature import payload_case_of, sig_consult, sig_sediment

__all__ = ["run_cascade", "run_shallow", "alert_view", "shallow_triage"]

_SHALLOW_TRIAGE = "shallow_triage"


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


def _shallow_tool_spec():
    return [{"type": "function", "function": {
        "name": _SHALLOW_TRIAGE,
        "description": "浅层分诊:据这条告警自身的 payload/签名判 needs_deep + verdict(不取证、不查图)。",
        "parameters": {"type": "object", "properties": {
            "needs_deep": {"type": "boolean",
                           "description": "true=需深度研判(要重建主机行为/进程链/登录序列才能定);false=光凭告警就能终局"},
            "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "suspicious"],
                        "description": "needs_deep=false 时给 true_positive/false_positive;true 时给 suspicious"},
            "confidence": {"type": "number", "description": "0~1"},
            "rationale": {"type": "string", "description": "一句话依据"},
        }, "required": ["needs_deep", "verdict"]}}}]


def shallow_triage(llm, alert) -> dict:
    """浅层分诊:QwenClient 工具调用 → {needs_deep, verdict, confidence, rationale}。
    ★用 QwenClient(直连昇腾 qwen、默认关思维链、稳),替代此前 openJiuwen LLMComponent(持续负载 ~50% 崩)。"""
    resp = llm.chat(
        [{"role": "system", "content": SHALLOW_PROMPT},
         {"role": "user", "content": alert_view(alert)}],
        tools=_shallow_tool_spec(), tool_choice="required")
    for tc in (getattr(resp, "tool_calls", None) or []):
        if getattr(tc, "name", None) == _SHALLOW_TRIAGE:
            a = tc.arguments or {}
            verdict = a.get("verdict") if a.get("verdict") in VERDICTS else "suspicious"
            return {"needs_deep": bool(a.get("needs_deep")), "verdict": verdict,
                    "confidence": a.get("confidence"), "rationale": a.get("rationale")}
    return {"needs_deep": True, "verdict": "suspicious", "confidence": 0.0,
            "rationale": "浅层无有效工具输出 → 保守升级"}


def run_cascade(pl, alert_uid, mode="recipe"):
    """签名库前置(FP 零 qwen 复用)→ 浅层 LLM 分诊 → 决策A(只 FP 终局,余升级)→ 升级跑深度 run_pipeline。
    返回 (result, report, picked)。全 Python,可多线程并发(每 worker 独立 pipeline)。"""
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
        shallow = shallow_triage(getattr(pl, "shallow_llm", None) or pl.llm, alert)
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

    # ★升级深度:直接跑现有 run_pipeline(纯 Python,worker 线程并行)
    return run_pipeline(pl, alert_uid, mode)


def run_shallow(pl, alert_uid, sig_store=None, sig_corpus=None, shallow_fn=None):
    """只跑浅层分诊(不升级、不写台账)。返回 {alert_uid, technique, force_deep, shallow, route, reused}。
    route: escalate / terminal_fp / reuse_fp / reuse_tp。传 sig_store(+sig_corpus)则先查签名库命中即复用、
    未命中判完从 payload 蒸规则入库+记语料。测试可注入 shallow_fn(pl, alert)->dict 免真 LLM。"""
    from ..cli import AlertNotFound                       # 懒导入,避 cli<->cascade 循环

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

    shallow = (shallow_fn(pl, alert) if shallow_fn is not None
               else shallow_triage(getattr(pl, "shallow_llm", None) or pl.llm, alert))
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
