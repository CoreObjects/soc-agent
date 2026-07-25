"""研判队列 + 单告警完整研判流程(溯源)。全读:薄封 queries + graph 现成读法。"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query

from ...models import Alert
from ...response.auto import zh_status
from .. import queries as qb
from ..deps import get_graph, require_token
from ..util import NOOP_ACTIONS, loads, run_spec

router = APIRouter(prefix="/api", tags=["alerts"], dependencies=[Depends(require_token)])

_ALERT_FIELDS = ("source", "sensor", "rule_id", "rule_description", "severity", "technique_ids", "time")


@router.get("/alerts")
def list_alerts(page: int = 1, size: int = 50, verdict: str = "", path: str = "",
                dispo_status: str = "", q: str = Query("", alias="q"),
                graph=Depends(get_graph)):
    """研判队列一页(已研判告警,新的在前;可按 verdict/path/处置状态/关键词筛)。"""
    page = max(1, page)
    size = max(1, min(size, 200))
    skip = (page - 1) * size
    total = run_spec(graph, qb.q_alerts_count(verdict, path, dispo_status, q))[0]["n"]
    rows = run_spec(graph, qb.q_alerts_page(verdict, path, dispo_status, q, skip=skip, limit=size))
    for r in rows:
        r["plan_status_zh"] = zh_status(r["plan_status"]) if r.get("plan_status") else None
    return {"total": total, "page": page, "size": size, "items": rows}


@router.get("/alerts/{uid}")
def alert_detail(uid: str, graph=Depends(get_graph)):
    """完整研判流程:原始告警 raw → seed 图上下文 → 取证 findings → verdict/证据 → 处置步骤 →
    逐步 trace(有则真·逐步,无则前端重建)→ 复用来源(命中经验时)。"""
    node = graph.get_alert(uid)
    if not node:
        raise HTTPException(status_code=404, detail=f"无此告警: {uid}")
    alert = Alert.from_node(node)

    raw = node.get("raw")
    try:
        raw_parsed = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception:
        raw_parsed = {"_unparsed": raw}

    findings = run_spec(graph, qb.q_findings(uid))
    for f in findings:
        f["attrs"] = loads(f.get("attrs"))

    concl_rows = run_spec(graph, qb.q_alert_conclusion(uid))
    concl = concl_rows[0] if concl_rows else {}
    disps = [d for d in (concl.get("dispositions") or []) if (d or {}).get("action") not in NOOP_ACTIONS]
    for d in disps:
        d["status_zh"] = zh_status(d.get("status"))
        d["params"] = loads(d.get("params"))

    trace_rows = run_spec(graph, qb.q_trace(uid))
    trace = loads(trace_rows[0]["steps"]) if trace_rows and trace_rows[0].get("steps") else None

    return {
        "alert_uid": uid,
        "alert": {k: node.get(k) for k in _ALERT_FIELDS},
        "raw": raw_parsed,
        "seed": graph.seed(alert),
        "findings": findings,
        "verdict": concl.get("verdict"), "lean": concl.get("lean"), "agent": concl.get("agent"),
        "path": concl.get("path"), "method": concl.get("method"),
        "confidence": concl.get("confidence"), "concluded_at": concl.get("concluded_at"),
        "summary": concl.get("summary"), "rationale": concl.get("rationale"),
        "evidence_refs": concl.get("evidence_refs") or [],
        "missing_evidence": concl.get("missing_evidence") or [],
        "dispositions": disps,
        "trace": trace,
        "reuse_source": _reuse_source(graph, uid, concl.get("method")),
    }


def _reuse_source(graph, uid, method):
    """method=reuse → 反查复用的源判例告警 + 其结论摘要(供'复用来源'卡)。非复用 → None。"""
    if method != "reuse":
        return None
    rows = run_spec(graph, qb.q_reuse_origin(uid))
    if not rows:
        return None
    origin_uid = rows[0].get("origin_uid")
    summary = None
    if origin_uid:
        try:
            led = graph.recall_ledger(origin_uid)
            summary = (led or {}).get("summary")
        except Exception:
            summary = None
    return {"origin_uid": origin_uid, "verdict": rows[0].get("verdict"), "summary": summary}
