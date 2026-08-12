"""经验蒸馏(qwen 沉淀第二类经验)。

一次【置信、非 suspicious】的完整研判后:把 findings + verdict + rationale + 方法论喂 qwen,
它选出【决定性发现子集】(=指纹)、真威胁再写一条【DSL 判定规则】。据此 build_fingerprint 成 Experience。
剧本模板(playbook)留空,Phase 5 由 Composer 产物补入(处置那一半)。

★沉淀者是 qwen,不是我离线拟合:没有真实取证结果就无从蒸馏(见 [[soc-agent-experience-v2-design]])。
"""
import json

from .fingerprint import build_fingerprint
from .store import Experience

__all__ = ["distill", "DISTILL"]

DISTILL = "distill_experience"

_DSL_HELP = ("受限 DSL 算子:{\"exists\":\"finding_id\"} / {\"eq|gt|gte|lt|lte\":[\"fid:attr\",值]} / "
             "{\"in\":[\"fid:attr\",[值...]]} / {\"same_source\":[\"fid_a:attr\",\"fid_b:attr\"]} / "
             "{\"and|or|not\":...}。只用下面出现过的 finding_id;抓攻击本质,别过拟合具体账号/IP/主机。")


def _spec(finding_ids):
    return [{"type": "function", "function": {
        "name": DISTILL,
        "description": ("从本次已完成研判里提炼可复用经验:选出定性据以成立的【决定性发现子集】(=指纹),"
                        "别塞无关发现;若结论是真威胁,再用受限 DSL 写一条【威胁判定规则】。"),
        "parameters": {"type": "object", "properties": {
            "decisive_finding_ids": {"type": "array", "items": {"type": "string", "enum": finding_ids},
                                     "description": "定性据以成立的决定性 finding_id 子集(=指纹)"},
            "rule": {"type": "object", "description": "威胁判定规则(DSL 表达式树;仅真威胁给,误报留空)。" + _DSL_HELP},
            "note": {"type": "string", "description": "一句话说明这条经验的本质"},
        }, "required": ["decisive_finding_ids"]}}}]


def _prompt(skill, kind):
    task2 = ("2) 这是【真威胁】:再用受限 DSL 写一条【威胁判定规则】,作用于 findings、能确定性复现本次定性,"
             "抓本质(如'RC4 取票 且 高价值目标 且 非机器账号非跨域')。\n" + _DSL_HELP
             if kind == "threat" else
             "2) 这是【误报】:不写规则,只把导致这次误报的良性/业务发现挑进决定性子集(=误报业务指纹)。")
    body = ("你是 SOC 经验蒸馏器。给你一次【已完成】的研判(规范发现 findings + 结论 + 依据 + 方法论)。\n"
            "1) 选出定性据以成立的【决定性发现子集】(=指纹),只挑真正支撑结论的,别塞无关项。\n" + task2)
    if skill is not None:
        body += f"\n\n## 方法论(skill: {skill.name})\n{skill.methodology}"
    return body


def distill(llm, skill, findings, bindings, verdict, agent_name=None, origin_case_id=None):
    """→ Experience(playbook 空)或 None(suspicious 不沉淀 / 无 finding / 模型没给)。"""
    if verdict is None or verdict.verdict not in ("true_positive", "false_positive", "benign"):
        return None
    kind = "threat" if verdict.verdict == "true_positive" else "benign_fp"
    # ★`_` 前缀 = 元 finding(`_coverage.absent` 这种"我瞎了"的自述),不是证据,一律不进指纹。
    #   否则"缺进程遥测 → 没发现异常 → FP"会被蒸馏成经验,
    #   下次同样瞎的时候直接自动放过 —— 等于把覆盖度缺口学成了免责条款。
    findings = [f for f in (findings or []) if not str(f.finding_id).startswith("_")]
    finding_ids = sorted({f.finding_id for f in findings})
    if not finding_ids:
        return None
    user = "本次研判:\n" + json.dumps({
        "verdict": verdict.verdict, "rationale": verdict.rationale,
        "findings": [f.to_dict() for f in findings],
    }, ensure_ascii=False, indent=2, default=str)
    resp = llm.chat([{"role": "system", "content": _prompt(skill, kind)},
                     {"role": "user", "content": user}],
                    tools=_spec(finding_ids), tool_choice="required")
    args = None
    for tc in (resp.tool_calls or []):
        if tc.name == DISTILL:
            args = tc.arguments or {}
    if not args:
        return None
    subset = [fid for fid in (args.get("decisive_finding_ids") or []) if fid in finding_ids] or finding_ids
    rule = args.get("rule") if kind == "threat" else None
    note = args.get("note") or None
    fp = build_fingerprint(findings, bindings, subset_ids=subset)
    return Experience(skill=(skill.name if skill else "unknown"), kind=kind, verdict=verdict.verdict,
                      fingerprint=fp, rule=rule, playbook=[], created_by=agent_name,
                      origin_case_id=origin_case_id, origin_verdict_id=verdict.verdict_id, note=note)
