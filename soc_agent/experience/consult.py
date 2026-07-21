"""经验研判短路决策(流水线'研判'阶段:取证之后、LLM 之前对 findings 匹配)。

D2(用户定稿):
- 威胁指纹 命中 AND 威胁规则 命中(某条 threat 经验点火)→ **AUTO_TP**,复用其剧本。
- 误报指纹 命中 且 无任何威胁信号(无 threat 指纹/规则命中)→ **AUTO_FP**(压/归档)。
  ★安全否决:误报命中但有威胁信号 → 不自动、落 LLM(防"攻击者模仿良性")。
- 其余(只中其一 / 都不中)→ **FALLTHROUGH**,把"命中/未命中了哪些指纹与规则"作为已知信息喂 LLM。

威胁优先于误报(都命中时判 AUTO_TP,安全)。
"""
import json
from dataclasses import dataclass, field
from typing import Optional

from .matching import experience_fires, fingerprint_hit, rule_hit

__all__ = ["MatchReport", "consult"]


def _render_hit(label, e, recalled) -> str:
    """一条命中经验 → 可读行:命中的 finding 类型 + 本质 note + 规则 + 来源告警的图台账原始上下文。"""
    fids = (e.fingerprint or {}).get("finding_ids") or []
    parts = [f"{label}(命中 finding 类型 {fids})"]
    note = getattr(e, "note", None)
    if note:
        parts.append(f"本质「{note}」")
    if e.kind == "threat" and e.rule:
        parts.append(f"规则 {json.dumps(e.rule, ensure_ascii=False)}")
    led = (recalled or {}).get(getattr(e, "origin_case_id", None))
    if led:
        a = led.get("alert") or {}
        seg = f"该经验蒸自告警 {led.get('alert_uid')}"
        if a.get("rule_description"):
            seg += f"(原规则={a['rule_description']})"
        if led.get("verdict"):
            seg += f",当初判 {led['verdict']}"
        if led.get("summary"):
            seg += f",理由:{led['summary']}"
        disps = led.get("dispositions") or []
        if disps:
            seg += ",处置:" + "、".join(f"{d.get('action')}→{d.get('target')}" for d in disps)
        parts.append(seg)
    return ";".join(parts)


@dataclass
class MatchReport:
    decision: str                                    # AUTO_TP | AUTO_FP | FALLTHROUGH
    benign_fp_hits: list = field(default_factory=list)     # 点火的误报指纹经验
    threat_fp_hits: list = field(default_factory=list)     # 威胁指纹命中的经验
    threat_rule_hits: list = field(default_factory=list)   # 威胁规则命中的经验
    threat_fires: list = field(default_factory=list)       # 点火(指纹∧规则)的威胁经验
    chosen: Optional[object] = None                        # AUTO_* 时复用其 verdict/剧本 的经验
    recalled: dict = field(default_factory=dict)           # FALLTHROUGH:命中经验来源告警的图台账 {VID→ledger}

    def as_context(self) -> str:
        """FALLTHROUGH 时喂给 LLM 的"已知经验比对"上下文。

        不只报计数——逐条给出命中的是哪条经验(finding 类型 + 本质 + 规则)+ 它蒸自哪条告警、
        那次判成啥、为什么、怎么处置的(图台账原始上下文,self.recalled)。命中即召回、非定性,
        大模型据此独立研判。
        """
        lines = []
        for e in self.benign_fp_hits:
            lines.append(_render_hit("误报业务指纹", e, self.recalled))
        for e in self.threat_fp_hits:
            lines.append(_render_hit("威胁指纹(但威胁规则未命中)", e, self.recalled))
        for e in self.threat_rule_hits:
            lines.append(_render_hit("威胁规则(但威胁指纹未召回)", e, self.recalled))
        if not lines:
            return "已知经验比对:无历史经验命中,据证据从头研判。"
        return ("已知经验比对(命中经验仅作参照,未达自动处置的双门/无冲突条件,请据证据独立研判):"
                + "".join("\n- " + ln for ln in lines))


def _best(exps):
    """复用哪条:更具体(指纹发现多)优先,再看命中次数。"""
    if not exps:
        return None
    return max(exps, key=lambda e: (len(e.fingerprint.get("finding_ids") or []), e.hit_count))


def consult(skill_name, findings, exp_store):
    """取证之后比对经验,返回 MatchReport(含决策 + 命中明细 + 复用经验)。"""
    active = exp_store.active_for_skill(skill_name) if (exp_store is not None and skill_name) else []
    threats = [e for e in active if e.kind == "threat"]
    benign = [e for e in active if e.kind == "benign_fp"]
    benign_hits = [e for e in benign if fingerprint_hit(e, findings)[0]]
    threat_fp_hits = [e for e in threats if fingerprint_hit(e, findings)[0]]
    threat_rule_hits = [e for e in threats if rule_hit(e, findings)[0]]
    threat_fires = [e for e in threats if experience_fires(e, findings)[0]]

    if threat_fires:                                                     # 威胁双门 → 自动 TP(优先,安全)
        decision, chosen = "AUTO_TP", _best(threat_fires)
    elif benign_hits and not threat_fp_hits and not threat_rule_hits:   # 纯误报、无任何威胁信号 → 自动 FP
        decision, chosen = "AUTO_FP", _best(benign_hits)
    else:                                                                # 只中其一/都不中/被威胁否决 → 落 LLM
        decision, chosen = "FALLTHROUGH", None
    return MatchReport(decision, benign_hits, threat_fp_hits, threat_rule_hits, threat_fires, chosen)
