"""快通道套模板 + 慢通道生成规则(连接规则库 ↔ InvestigationResult)。

- result_from_rule:命中的规则模板 → InvestigationResult(path A,0 LLM)。处置目标用 bindings 按 target_field 换实例填、过护栏。
- mint_rule_from_result:慢通道 result → PatternRule。verdict 定层(FP/benign→exculpatory、其余→incriminating);
  TP/FP 自动 active、可疑 pending;处置具体目标反映射回 target_field 成实例无关模板。
"""
from ..models import Disposition, InvestigationResult, Verdict
from ..disposition import apply_guardrail
from .match import signature_for_verdict
from .rule import DispositionTemplate, PatternRule, VerdictTemplate

_ACTIVE_VERDICTS = {"true_positive", "false_positive", "benign"}   # 自动 active;suspicious→pending 待采纳

_ACTION_KIND = {
    "block_ip": "ip",
    "disable_account": "account", "reset_password": "account", "revoke_sessions": "account",
    "isolate_host": "host", "kill_process": "process", "quarantine_file": "file",
}


def _kind(action: str) -> str:
    return _ACTION_KIND.get(action, "none")


def result_from_rule(alert, skill_name, rule: PatternRule, bindings: dict, policy=None) -> InvestigationResult:
    vt = rule.verdict
    verdict = Verdict(verdict=vt.verdict, lean=vt.lean, confidence=vt.confidence,
                      summary=vt.canonical_rationale, rationale=vt.canonical_rationale,
                      pattern=rule.pattern_id, agent="fast-channel")
    bindings = bindings or {}
    disps = [Disposition(action=dt.action, target=bindings.get(dt.target_field), risk=dt.risk)
             for dt in rule.dispositions]
    disps, audit = apply_guardrail(disps, policy)
    trace = [{"tool": "fast_channel", "pattern_id": rule.pattern_id, "layer": rule.layer, "sig": rule.sig}]
    for a in audit:
        if a.get("decision") in ("blocked", "retargeted"):
            trace.append({"tool": "guardrail", **a})
    return InvestigationResult(alert_uid=alert.alert_uid, path="A", verdict=verdict,
                               dispositions=disps, skill=skill_name, trace=trace)


def mint_rule_from_result(skill_name, disc, result: InvestigationResult):
    """慢通道 result → 规则(可 upsert);无 verdict/无法定层 → None。"""
    v = result.verdict
    if v is None:
        return None
    sig = signature_for_verdict(skill_name, disc.get("layers") or [], v.verdict)
    if sig is None:
        return None
    bindings = disc.get("bindings") or {}
    rev = {val: field for field, val in bindings.items() if val}   # 具体目标 → 来自哪个字段
    dts = [DispositionTemplate(action=d.action, target_kind=_kind(d.action),
                               target_field=rev.get(d.target, "?"), risk=d.risk)
           for d in (result.dispositions or [])]
    status = "active" if v.verdict in _ACTIVE_VERDICTS else "pending"
    return PatternRule(
        skill=skill_name, layer=sig.layer, sig=sig.sig, sig_hash=sig.sig_hash,
        verdict=VerdictTemplate(verdict=v.verdict, lean=v.lean, confidence=v.confidence,
                                canonical_rationale=v.rationale or v.summary or ""),
        dispositions=dts, status=status,
        provenance={"source_alert_uid": result.alert_uid, "minted_by": result.path,
                    "skill_spec_version": None})
