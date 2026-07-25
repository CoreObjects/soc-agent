"""经验库:系统学到了什么(签名/指纹/规则 + 命中数 + 来源案子)。读 exp_store.all()。"""
from fastapi import APIRouter, Depends

from ..deps import get_exp_store, require_token

router = APIRouter(prefix="/api", tags=["experience"], dependencies=[Depends(require_token)])


@router.get("/experience")
def list_experience(skill: str = "", kind: str = "", exp=Depends(get_exp_store)):
    """经验列表(可按 skill/kind 筛);每条含 note/hit_count/origin_case_id 供前端链回溯源。"""
    items = [e.to_dict() for e in exp.all()]
    if skill:
        items = [i for i in items if i.get("skill") == skill]
    if kind:
        items = [i for i in items if i.get("kind") == kind]
    return {"items": items}
