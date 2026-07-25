"""响应模式开关(manual/auto)持久化:GET/PUT /api/config/response-mode(读写 :Config)。

★UI 改这里 → poller 每批读一次 :Config(见 runtime/service),下一批生效。
"""
from fastapi import APIRouter, Body, Depends, HTTPException

from .. import queries as qb
from ..deps import get_graph, require_token
from ..util import run_spec

router = APIRouter(prefix="/api/config", tags=["config"], dependencies=[Depends(require_token)])


@router.get("/response-mode")
def get_mode(graph=Depends(get_graph)):
    rows = run_spec(graph, qb.q_get_config("response_mode"))
    val = rows[0]["value"] if rows and rows[0].get("value") else None
    return {"mode": "auto" if str(val).strip().lower() == "auto" else "manual"}


@router.put("/response-mode")
def set_mode(payload: dict = Body(default={}), graph=Depends(get_graph)):
    mode = str((payload or {}).get("mode", "")).strip().lower()
    if mode not in ("manual", "auto"):
        raise HTTPException(status_code=400, detail="mode 只能是 manual|auto")
    cypher, params = qb.q_set_config("response_mode", mode)
    graph.run_write(cypher, **params)
    return {"mode": mode}
