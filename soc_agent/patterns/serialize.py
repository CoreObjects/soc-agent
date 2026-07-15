"""PatternRule ↔ DB 行(json/text blob 装模板)。纯逻辑,不依赖驱动 —— openGauss 适配与单测共用。

模板整块 json 存取、不在库里做内部查询 → 任何 openGauss 版本(甚至只有 text 列)都行。
"""
import json

from .rule import DispositionTemplate, PatternRule, VerdictTemplate

_DEFAULT_STATS = {"hit_count": 0, "last_hit": None, "tp_confirmed": 0, "fp_reverted": 0}


def rule_to_row(r: PatternRule) -> dict:
    return {
        "sig_hash": r.sig_hash, "skill": r.skill, "layer": r.layer, "sig": r.sig,
        "verdict_tmpl": json.dumps(r.verdict.to_dict(), ensure_ascii=False),
        "disp_tmpl": json.dumps([d.to_dict() for d in r.dispositions], ensure_ascii=False),
        "status": r.status,
        "stats": json.dumps(r.stats, ensure_ascii=False),
        "provenance": json.dumps(r.provenance, ensure_ascii=False),
    }


def row_to_rule(row: dict) -> PatternRule:
    vt = json.loads(row["verdict_tmpl"])
    dts = json.loads(row["disp_tmpl"]) or []
    return PatternRule(
        skill=row["skill"], layer=row["layer"], sig=row["sig"], sig_hash=row["sig_hash"],
        verdict=VerdictTemplate(**vt),
        dispositions=[DispositionTemplate(**d) for d in dts],
        status=row["status"],
        stats=json.loads(row["stats"]) if row.get("stats") else dict(_DEFAULT_STATS),
        provenance=json.loads(row["provenance"]) if row.get("provenance") else {},
    )
