"""价值大盘:进度/积压/毒告警 + verdict×path + 处置/计划状态直方图 + TP 抽样。

★收紧1:复用命中(method=reuse,含签名+深度经验,随经验涨=越用越省)与浅层短路(path=S 且 method=llm,
便宜结案、基本恒定)、深度(path=B)分开统计 —— 不把浅层 LLM 终局混进"复用",否则数字虚高、增长信号被摊平。
"""
from fastapi import APIRouter, Depends

from ...response.auto import zh_status
from .. import queries as qb
from ..deps import get_graph, require_token
from ..util import run_spec

router = APIRouter(prefix="/api", tags=["stats"], dependencies=[Depends(require_token)])


@router.get("/stats")
def stats(graph=Depends(get_graph)):
    concluded = run_spec(graph, qb.q_count_concluded())[0]["n"]
    backlog = run_spec(graph, qb.q_count_backlog())[0]["n"]
    poison = run_spec(graph, qb.q_count_poison())[0]["n"]
    total = concluded + backlog

    verdict_path = run_spec(graph, qb.q_verdict_path())
    method_path = run_spec(graph, qb.q_method_path())
    reuse_hits = sum(r["n"] for r in method_path if r.get("method") == "reuse")
    shallow_short = sum(r["n"] for r in method_path
                        if r.get("method") == "llm" and r.get("path") == "S")
    deep = sum(r["n"] for r in method_path
               if r.get("method") == "llm" and r.get("path") == "B")

    dispo_status = run_spec(graph, qb.q_dispo_status())
    for d in dispo_status:
        d["status_zh"] = zh_status(d.get("status"))
    plan_status = run_spec(graph, qb.q_plan_status())
    for p in plan_status:
        p["status_zh"] = zh_status(p.get("status"))
    tp_sample = run_spec(graph, qb.q_tp_sample(5))

    denom = concluded or 1
    # 自动结案 = 无需人工研判即定案(FP/benign);TP/suspicious 需人看
    auto_closed = sum(r["n"] for r in verdict_path if r.get("verdict") in ("false_positive", "benign"))
    return {
        "progress": {"concluded": concluded, "backlog": backlog, "poison": poison,
                     "total": total, "pct": round(concluded / (total or 1) * 100, 1)},
        "verdict_path": verdict_path,
        "method_path": method_path,
        "reuse": {"reuse_hits": reuse_hits, "shallow_short": shallow_short, "deep": deep,
                  "reuse_rate": reuse_hits / denom, "shallow_rate": shallow_short / denom},
        "auto_close": {"auto_closed": auto_closed, "rate": auto_closed / denom},
        "dispo_status": dispo_status,
        "plan_status": plan_status,
        "tp_sample": tp_sample,
    }
