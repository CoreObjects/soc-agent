"""Copilot 台账问答:POST /api/alerts/{uid}/chat。

以该告警的完整台账(原文摘要 + 取证 findings + 结论/证据)为 system 上下文喂 LLM,多轮 messages 透传。
★只读、无 tools/tool_choice、不写台账、不碰机器 —— 纯 Q&A;前端维护多轮历史(与轮询刷新一致)。
"""
from fastapi import APIRouter, Body, Depends, HTTPException

from .. import queries as qb
from ..deps import get_graph, get_llm_safe, require_token
from ..util import loads, run_spec

router = APIRouter(prefix="/api", tags=["chat"], dependencies=[Depends(require_token)])

_SYSTEM = ("你是 SOC 研判助手。下面是某条告警的完整研判台账。请只依据台账内容 + 安全常识回答分析师的追问,"
           "不要编造证据;证据不足就直说'台账中无此证据'。\n\n===== 告警台账 =====\n")


def _ledger_context(graph, uid):
    """拼这条告警的台账上下文串;告警不存在 → None。"""
    node = graph.get_alert(uid)
    if not node:
        return None
    concl_rows = run_spec(graph, qb.q_alert_conclusion(uid))
    concl = concl_rows[0] if concl_rows else {}
    findings = run_spec(graph, qb.q_findings(uid))
    lines = [
        f"告警: {node.get('rule_description')}  (source={node.get('source')}, "
        f"technique={node.get('technique_ids')})",
        f"研判结论: {concl.get('verdict')}  (path={concl.get('path')}, method={concl.get('method')}, "
        f"置信={concl.get('confidence')})",
        f"依据: {concl.get('rationale')}",
        f"证据引用: {concl.get('evidence_refs')}   缺失证据: {concl.get('missing_evidence')}",
        "取证发现:",
    ]
    for f in findings:
        lines.append(f"  - {f.get('finding_id')} [{f.get('polarity')}] {loads(f.get('attrs'))}")
    raw = node.get("raw")
    if raw:
        lines.append(f"原始告警(截断): {str(raw)[:800]}")
    return "\n".join(lines)


@router.post("/alerts/{uid}/chat")
def chat(uid: str, payload: dict = Body(default={}), graph=Depends(get_graph), llm=Depends(get_llm_safe)):
    if llm is None:
        raise HTTPException(status_code=503, detail="LLM 端点不可用(未配或连不上)")
    ctx = _ledger_context(graph, uid)
    if ctx is None:
        raise HTTPException(status_code=404, detail=f"无此告警: {uid}")
    # 只收 user/assistant(客户端不许注入 system)
    history = [{"role": m.get("role"), "content": m.get("content")}
               for m in (payload.get("messages") or [])
               if m.get("role") in ("user", "assistant") and m.get("content")]
    if not history:
        raise HTTPException(status_code=400, detail="messages 为空")
    messages = [{"role": "system", "content": _SYSTEM + ctx}] + history
    resp = llm.chat(messages)                      # 纯 Q&A,不带 tools
    return {"reply": getattr(resp, "content", "") or ""}
