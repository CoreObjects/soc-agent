"""快通道套模板 + 慢通道生成规则(连接规则库 ↔ InvestigationResult)。

- result_from_rule:命中规则的**有序计划** → InvestigationResult(path A,0 LLM)。逐步逐参按角色
  (entity_role→bindings 取本实例值)/字面量解析 → 具体处置 → 过护栏。
- mint_rule_from_result:慢通道 verdict(+ composer 出的 plan)→ PatternRule。
  ★不再做"具体目标→字段"的值相等反查(多参/共值即崩)——plan 由 composer 直接吐【角色绑定】的
  PrimitiveStepTemplate,确定性、无歧义。verdict 定层(FP/benign→exculpatory、其余→incriminating);
  TP/FP 自动 active、可疑 pending。
"""
from ..disposition import apply_guardrail
from ..models import Disposition, InvestigationResult, Verdict
from ..response import default_interface
from .match import signature_for_verdict
from .rule import PatternRule, VerdictTemplate

_ACTIVE_VERDICTS = {"true_positive", "false_positive", "benign"}   # 自动 active;suspicious→pending 待采纳


def _resolve_params(params: dict, bindings: dict) -> dict:
    """step 的参数规格(role/literal)→ 具体 {param_name: value}。缺角色 → None(护栏后按类型/缺失处理)。"""
    out = {}
    for pname, spec in (params or {}).items():
        if not isinstance(spec, dict):
            out[pname] = spec                                 # 容错:直接给了值
        elif spec.get("source") == "literal":
            out[pname] = spec.get("value")
        else:
            out[pname] = (bindings or {}).get(spec.get("role"))
    return out


def _disposition_from_step(step, bindings, iface) -> Disposition:
    resolved = _resolve_params(step.params, bindings)
    kf = iface.target_key_field(step.primitive)               # 主目标 = 原语 target.key_field 参数
    target = resolved.get(kf) if kf else None
    return Disposition(action=step.primitive, target=target, target_kind=iface.kind_of(step.primitive),
                       params=resolved, risk=step.risk)


def dispositions_from_plan(plan, bindings, policy=None, iface=None):
    """有序计划(模板)+ 本告警 bindings → 具体处置(过护栏)。慢通道给铸规则的这条告警落台账用。"""
    iface = iface or default_interface()
    disps = [_disposition_from_step(s, bindings or {}, iface)
             for s in sorted(plan or [], key=lambda s: s.order)]
    disps, _ = apply_guardrail(disps, policy, iface)
    return disps


def result_from_rule(alert, skill_name, rule: PatternRule, bindings: dict, policy=None, iface=None) -> InvestigationResult:
    iface = iface or default_interface()
    vt = rule.verdict
    verdict = Verdict(verdict=vt.verdict, lean=vt.lean, confidence=vt.confidence,
                      summary=vt.canonical_rationale, rationale=vt.canonical_rationale,
                      pattern=rule.pattern_id, agent="fast-channel")
    bindings = bindings or {}
    disps = [_disposition_from_step(s, bindings, iface)
             for s in sorted(rule.plan, key=lambda s: s.order)]
    disps, audit = apply_guardrail(disps, policy, iface)
    trace = [{"tool": "fast_channel", "pattern_id": rule.pattern_id, "layer": rule.layer, "sig": rule.sig}]
    for a in audit:
        if a.get("decision") in ("blocked", "retargeted"):
            trace.append({"tool": "guardrail", **a})
    return InvestigationResult(alert_uid=alert.alert_uid, path="A", verdict=verdict,
                               dispositions=disps, skill=skill_name, trace=trace)


def mint_rule_from_result(skill_name, disc, result: InvestigationResult, plan=None):
    """慢通道 result(+ composer 出的有序 plan)→ 规则(可 upsert);无 verdict/无法定层 → None。

    plan = list[PrimitiveStepTemplate](composer 产出;缺则先只铸 verdict 规则,处置待 composer 补)。
    """
    v = result.verdict
    if v is None:
        return None
    sig = signature_for_verdict(skill_name, disc.get("layers") or [], v.verdict)
    if sig is None:
        return None
    status = "active" if v.verdict in _ACTIVE_VERDICTS else "pending"
    return PatternRule(
        skill=skill_name, layer=sig.layer, sig=sig.sig, sig_hash=sig.sig_hash,
        verdict=VerdictTemplate(verdict=v.verdict, lean=v.lean, confidence=v.confidence,
                                canonical_rationale=v.rationale or v.summary or ""),
        plan=list(plan or []), status=status,
        provenance={"source_alert_uid": result.alert_uid, "minted_by": result.path,
                    "skill_spec_version": None})
