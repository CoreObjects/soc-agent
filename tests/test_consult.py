"""经验研判短路决策(D2):威胁双门→AUTO_TP;纯误报无威胁→AUTO_FP;余→FALLTHROUGH(带命中报告)。"""
from soc_agent.experience.consult import MatchReport, consult
from soc_agent.experience.fingerprint import build_fingerprint
from soc_agent.experience.store import Experience, InMemoryExperienceStore
from soc_agent.forensics import Finding


def _threat(fids, rule, **kw):
    return Experience(skill="k", kind="threat", verdict="true_positive",
                      fingerprint=build_fingerprint([Finding(f) for f in fids], {}), rule=rule, **kw)


def _benign(fids, **kw):
    return Experience(skill="k", kind="benign_fp", verdict="false_positive",
                      fingerprint=build_fingerprint([Finding(f) for f in fids], {}), **kw)


def _store(*exps):
    s = InMemoryExperienceStore()
    for e in exps:
        s.add(e)
    return s


def test_auto_tp_when_threat_fingerprint_and_rule_both_hit():
    store = _store(_threat(["k.rc4", "k.hv"], {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}]}))
    r = consult("k", [Finding("k.rc4"), Finding("k.hv")], store)
    assert r.decision == "AUTO_TP" and r.chosen is not None


def test_fallthrough_when_only_fingerprint_hits_not_rule():
    store = _store(_threat(["k.rc4", "k.hv"], {"exists": "k.zzz"}))     # 规则要不存在的 finding
    r = consult("k", [Finding("k.rc4"), Finding("k.hv")], store)
    assert r.decision == "FALLTHROUGH"
    assert len(r.threat_fp_hits) == 1 and len(r.threat_rule_hits) == 0   # 命中状态作已知信息


def test_auto_fp_when_benign_hits_and_no_threat_signal():
    store = _store(_benign(["k.machine", "k.cross"]))
    r = consult("k", [Finding("k.machine"), Finding("k.cross")], store)
    assert r.decision == "AUTO_FP" and r.chosen.kind == "benign_fp"


def test_benign_vetoed_when_threat_signal_present():
    # 误报指纹命中,但同时命中威胁指纹 → 不自动压、落 LLM(防"攻击者模仿良性")
    store = _store(_benign(["k.machine"]), _threat(["k.machine"], {"exists": "k.zzz"}))
    r = consult("k", [Finding("k.machine")], store)
    assert r.decision == "FALLTHROUGH"
    assert len(r.benign_fp_hits) == 1 and len(r.threat_fp_hits) == 1


def test_threat_takes_precedence_over_benign():
    store = _store(_benign(["k.rc4"]), _threat(["k.rc4"], {"exists": "k.rc4"}))
    r = consult("k", [Finding("k.rc4")], store)
    assert r.decision == "AUTO_TP"                                       # 威胁优先(安全)


def test_empty_store_fallthrough():
    r = consult("k", [Finding("k.rc4")], InMemoryExperienceStore())
    assert r.decision == "FALLTHROUGH" and r.chosen is None
    assert r.as_context()                                                # 有可读上下文串(即便无命中)


def test_as_context_renders_hit_experience_and_ledger():
    # FALLTHROUGH 喂 LLM 的上下文要含:命中哪条(finding 类型)+ 本质 note + 原始台账(summary/处置/VID),
    # 不再只是"命中 N 条"计数。
    exp = _threat(["k.rc4", "k.hv"], {"exists": "k.rc4"}, origin_case_id="a0")
    exp.note = "RC4 取票+高价值目标"
    rep = MatchReport("FALLTHROUGH", threat_fp_hits=[exp],
                      recalled={"a0": {"alert_uid": "a0", "verdict": "true_positive",
                                       "summary": "jon.snow roast 多个 SPN",
                                       "alert": {"rule_description": "Kerberoasting"},
                                       "dispositions": [{"action": "disable_account", "target": "jon.snow"}]}})
    ctx = rep.as_context()
    assert "k.rc4" in ctx and "k.hv" in ctx                 # 命中的 finding 类型
    assert "RC4 取票+高价值目标" in ctx                       # 本质 note
    assert "jon.snow roast 多个 SPN" in ctx                  # 原始台账 summary
    assert "disable_account" in ctx                          # 原始处置
    assert "a0" in ctx                                       # 来源 VID


def test_as_context_no_hits_still_readable():
    assert MatchReport("FALLTHROUGH").as_context()           # 无命中也有可读串


def test_best_picks_most_specific():
    broad = _threat(["k.rc4"], {"exists": "k.rc4"})
    specific = _threat(["k.rc4", "k.hv", "k.fan"],
                       {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}, {"exists": "k.fan"}]})
    store = _store(broad, specific)
    r = consult("k", [Finding("k.rc4"), Finding("k.hv"), Finding("k.fan")], store)
    assert r.decision == "AUTO_TP" and r.chosen.exp_id == specific.exp_id   # 更具体的优先复用
