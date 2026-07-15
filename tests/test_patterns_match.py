"""快通道匹配 + 分层签名(patterns.match)。

- to_signatures:判别器的分层特征 → 有序 LayerSig(先证伪在前)。
- layer_for_verdict:FP/benign 落 exculpatory 层(粗键)、TP/suspicious 落 incriminating 层(细键)。
- match_active:按层序查 active 规则,★豁免层命中优先于坐实层(先证伪)。
"""
from soc_agent.patterns.match import to_signatures, layer_for_verdict, match_active
from soc_agent.patterns.repository import InMemoryPatternRepository
from soc_agent.patterns.signature import canonicalize
from soc_agent.patterns.rule import PatternRule, VerdictTemplate

LAYERS = [
    {"layer": "exculpatory", "features": {"req_is_machine": True, "same_domain": False}},
    {"layer": "incriminating", "features": {"req_is_machine": True, "same_domain": False, "enc": "RC4", "spn_fanout": ">=5"}},
]


def _rule(sig, verdict):
    return PatternRule(skill="kerberoast", layer=sig.layer, sig=sig.sig, sig_hash=sig.sig_hash,
                       verdict=VerdictTemplate(verdict), status="active")


def test_to_signatures_order_and_hash():
    sigs = to_signatures("kerberoast", LAYERS)
    assert [s.layer for s in sigs] == ["exculpatory", "incriminating"]
    assert sigs[0].sig_hash == canonicalize("kerberoast", "exculpatory",
                                            {"req_is_machine": True, "same_domain": False}).sig_hash


def test_layer_for_verdict():
    assert layer_for_verdict("false_positive") == "exculpatory"
    assert layer_for_verdict("benign") == "exculpatory"
    assert layer_for_verdict("true_positive") == "incriminating"
    assert layer_for_verdict("suspicious") == "incriminating"


def test_match_active_exculpatory_wins():
    repo = InMemoryPatternRepository()
    sigs = to_signatures("kerberoast", LAYERS)
    repo.upsert(_rule(sigs[0], "false_positive"))    # 豁免层 FP
    repo.upsert(_rule(sigs[1], "true_positive"))     # 坐实层 TP
    assert match_active(repo, "kerberoast", LAYERS).verdict.verdict == "false_positive"   # 先证伪压过坐实


def test_match_active_incriminating_when_no_fp():
    repo = InMemoryPatternRepository()
    sigs = to_signatures("kerberoast", LAYERS)
    repo.upsert(_rule(sigs[1], "true_positive"))
    assert match_active(repo, "kerberoast", LAYERS).verdict.verdict == "true_positive"


def test_match_active_miss_none():
    assert match_active(InMemoryPatternRepository(), "kerberoast", LAYERS) is None
