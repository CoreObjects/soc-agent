"""经验'点火'判定(exam 与 consult 共用):威胁双门(指纹∧规则)/ 误报指纹(阈值放宽)。"""
from soc_agent.experience.fingerprint import build_fingerprint
from soc_agent.experience.matching import experience_fires, fingerprint_hit, rule_hit
from soc_agent.experience.store import Experience
from soc_agent.forensics import Finding


def _benign(fp):
    return Experience(skill="k", kind="benign_fp", verdict="false_positive", fingerprint=fp)


def _threat(fp, rule):
    return Experience(skill="k", kind="threat", verdict="true_positive", fingerprint=fp, rule=rule)


def test_benign_fires_on_fuzzy_fingerprint_hit():
    fs = [Finding("k.a"), Finding("k.b"), Finding("k.c"), Finding("k.d"), Finding("k.e")]
    exp = _benign(build_fingerprint(fs, {}))                 # 5 个 finding
    assert experience_fires(exp, fs[:4])[0] is True          # 4/5=0.8 ≥ 误报阈值 → 点火(量大从宽)
    assert experience_fires(exp, fs[:3])[0] is False         # 3/5=0.6 < 0.8 → 不点火


def test_threat_needs_both_fingerprint_and_rule():
    fp = build_fingerprint([Finding("k.rc4"), Finding("k.hv")], {})
    rule = {"and": [{"exists": "k.rc4"}, {"exists": "k.hv"}, {"not": {"exists": "k.machine"}}]}
    exp = _threat(fp, rule)
    tp = [Finding("k.rc4"), Finding("k.hv")]
    assert experience_fires(exp, tp)[0] is True              # 指纹∧规则 都命中 → 点火
    d = experience_fires(exp, tp + [Finding("k.machine")])   # 指纹仍全中,但规则被 NOT 否决
    assert d[0] is False and d[1]["fp_ok"] is True and d[1]["rule_ok"] is False
    assert experience_fires(exp, [Finding("k.hv")])[0] is False   # 指纹不全 → 不点火


def test_threat_fp_strict_benign_loose():
    # 4/5 命中:威胁指纹(阈值 1.0)不算命中;误报指纹(阈值 0.8)算命中
    fs = [Finding(f"k.{i}") for i in range(5)]
    fp = build_fingerprint(fs, {})
    assert fingerprint_hit(_threat(fp, {"exists": "k.0"}), fs[:4])[0] is False
    assert fingerprint_hit(_benign(fp), fs[:4])[0] is True


def test_rule_hit_none_rule_is_false():
    exp = _benign(build_fingerprint([Finding("k.a")], {}))
    assert rule_hit(exp, [Finding("k.a")]) == (False, [])


def test_threat_fingerprint_recalls_across_instances():
    # 威胁指纹只召回(finding 类型),不钉死数值:换实例(7 张票→12 张票)仍召回;值判断归规则。
    fp = build_fingerprint([Finding("kerb.rc4_requested", {"enc": "0x17"}),
                            Finding("kerb.spn_fanout", {"distinct_targets": 7})], {})
    exp = _threat(fp, {"exists": "kerb.rc4_requested"})
    other = [Finding("kerb.rc4_requested", {"enc": "0x17"}),
             Finding("kerb.spn_fanout", {"distinct_targets": 12})]     # 换实例:12 张票
    assert fingerprint_hit(exp, other)[0] is True                      # 纯召回:finding 类型齐 → 召回


def test_benign_fingerprint_still_value_gated():
    # 误报半不动:良性指纹的决定性 attr 值仍比对(src_image),换成攻击进程不误命中(守红线)。
    benign = _benign(build_fingerprint([Finding("lsass.lsass_accessed", {"src_image": "wazuh-agent.exe"})],
                                       {"source_process": "wazuh-agent.exe"}))
    evil = [Finding("lsass.lsass_accessed", {"src_image": "mimikatz.exe"})]
    assert fingerprint_hit(benign, evil)[0] is False                   # 良性仍靠值区分,未回归
