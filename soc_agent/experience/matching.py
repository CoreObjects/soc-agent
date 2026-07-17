"""经验'点火'判定 —— exam 与 consult 共用的一份判据。

- threat 经验点火 = 威胁指纹命中 AND 威胁规则命中(D2 双门,定性严:指纹召回 + 规则确定性核验)。
- benign_fp 经验点火 = 误报指纹命中(阈值放宽,量大从宽,降噪主力)。
"""
from .dsl import safe_evaluate
from .fingerprint import match as fp_match

__all__ = ["experience_fires", "fingerprint_hit", "rule_hit",
           "BENIGN_THRESHOLD", "THREAT_FP_THRESHOLD"]

BENIGN_THRESHOLD = 0.8       # 误报指纹:模糊召回,放宽
THREAT_FP_THRESHOLD = 1.0    # 威胁指纹:严(且还得过规则)


def fingerprint_hit(exp, findings):
    """(hit, score, matched_ids);威胁阈值严、误报阈值宽。"""
    thr = THREAT_FP_THRESHOLD if exp.kind == "threat" else BENIGN_THRESHOLD
    return fp_match(exp.fingerprint or {}, findings, thr)


def rule_hit(exp, findings):
    """(hit, trace);无规则 → (False, [])。快通道 fail-closed(畸形规则不崩)。"""
    if not exp.rule:
        return False, []
    return safe_evaluate(exp.rule, findings)


def experience_fires(exp, findings):
    """经验是否点火(会短路研判)。返回 (fires: bool, detail: dict)。"""
    fp_ok, score, matched = fingerprint_hit(exp, findings)
    if exp.kind == "benign_fp":
        return fp_ok, {"kind": "benign_fp", "fp_ok": fp_ok, "fp_score": score, "matched": matched}
    r_ok, _ = rule_hit(exp, findings)
    return (fp_ok and r_ok), {"kind": "threat", "fp_ok": fp_ok, "rule_ok": r_ok,
                              "fp_score": score, "matched": matched}
