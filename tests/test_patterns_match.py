"""快通道匹配 + 分层签名(patterns.match)。

- to_signatures:签名函数的分层特征 → 有序 LayerSig(先证伪在前)。
- layer_for_verdict:FP/benign 落 exculpatory 层(粗键)、TP/suspicious 落 incriminating 层(细键)。
- match_all:跑全部签名后【全局两趟先证伪】查 active 规则,★豁免层命中优先于坐实层(跨类型也先证伪)。
"""
from soc_agent.patterns.match import to_signatures, layer_for_verdict, match_all
from soc_agent.patterns.repository import InMemoryPatternRepository
from soc_agent.patterns.signature import canonicalize
from soc_agent.patterns.rule import PatternRule, VerdictTemplate

LAYERS = [
    {"layer": "exculpatory", "features": {"req_is_machine": True, "same_domain": False}},
    {"layer": "incriminating", "features": {"req_is_machine": True, "same_domain": False, "enc": "RC4", "spn_fanout": ">=5"}},
]


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


# ---- match_all: 跑全部签名后的全局两趟先证伪 ----

def _entry(skill, layers, bindings=None):
    return {"skill": skill, "layers": layers, "bindings": bindings or {}}


def _rule_for(skill, sig, verdict):
    return PatternRule(skill=skill, layer=sig.layer, sig=sig.sig, sig_hash=sig.sig_hash,
                       verdict=VerdictTemplate(verdict), status="active")


def test_match_all_returns_rule_and_entry():
    repo = InMemoryPatternRepository()
    sigs = to_signatures("kerberoast", LAYERS)
    repo.upsert(_rule_for("kerberoast", sigs[1], "true_positive"))
    entry = _entry("kerberoast", LAYERS, {"requester": "u"})
    rule, hit = match_all(repo, [entry])
    assert rule.verdict.verdict == "true_positive" and hit is entry     # 回带命中的签名(拿 bindings 套模板)


def test_match_all_global_exculpatory_beats_other_types_incriminating():
    # ★跨类型全局先证伪:B 类型的坐实 TP 不能越过 A 类型的证伪 FP
    repo = InMemoryPatternRepository()
    a_layers = [{"layer": "exculpatory", "features": {"x": 1}}]
    b_layers = [{"layer": "incriminating", "features": {"y": 2}}]
    repo.upsert(_rule_for("typeA", canonicalize("typeA", "exculpatory", {"x": 1}), "false_positive"))
    repo.upsert(_rule_for("typeB", canonicalize("typeB", "incriminating", {"y": 2}), "true_positive"))
    # 即便 typeB 的坐实签名排在前面,也要先命中 typeA 的证伪
    rule, hit = match_all(repo, [_entry("typeB", b_layers), _entry("typeA", a_layers)])
    assert rule.verdict.verdict == "false_positive" and hit["skill"] == "typeA"


def test_match_all_miss_none():
    assert match_all(InMemoryPatternRepository(), [_entry("kerberoast", LAYERS)]) is None
    assert match_all(InMemoryPatternRepository(), []) is None
