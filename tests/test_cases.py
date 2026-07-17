"""案例快照(回归考试语料):Case / InMemoryCaseStore / snapshot_case + investigate_alert 接线。"""
from soc_agent.cli import investigate_alert
from soc_agent.experience.cases import Case, InMemoryCaseStore, snapshot_case
from soc_agent.forensics import Finding
from soc_agent.models import InvestigationResult, Verdict


def _result(uid="a1", skill="kerberoast", verdict="true_positive", findings=None):
    return InvestigationResult(
        alert_uid=uid, path="B", skill=skill,
        verdict=Verdict(verdict=verdict, confidence=0.9, rationale="r", agent="q"),
        findings=findings if findings is not None else [Finding("kerberoast.rc4_requested")])


def test_case_finding_ids():
    c = Case("kerberoast", "a1", "true_positive", [Finding("a.b"), Finding("a.c")])
    assert c.finding_ids() == {"a.b", "a.c"}


def test_inmemory_store_add_and_query_by_skill():
    store = InMemoryCaseStore()
    store.add(Case("kerberoast", "a1", "true_positive"))
    store.add(Case("lsass_dump", "a2", "false_positive"))
    store.add(Case("kerberoast", "a3", "false_positive"))
    assert len(store.all()) == 3
    assert {c.alert_uid for c in store.by_skill("kerberoast")} == {"a1", "a3"}
    assert [c.verdict for c in store.by_skill("lsass_dump")] == ["false_positive"]


def test_snapshot_case_stores_findings_and_verdict():
    store = InMemoryCaseStore()
    case = snapshot_case(store, "kerberoast", _result(findings=[Finding("kerberoast.rc4_requested"),
                                                              Finding("kerberoast.spn_fanout")]))
    assert case is not None
    assert store.by_skill("kerberoast")[0].verdict == "true_positive"
    assert case.finding_ids() == {"kerberoast.rc4_requested", "kerberoast.spn_fanout"}


def test_snapshot_case_skips_when_no_store_or_no_verdict():
    assert snapshot_case(None, "kerberoast", _result()) is None
    no_verdict = InvestigationResult(alert_uid="a1", path="B", verdict=None)
    assert snapshot_case(InMemoryCaseStore(), "kerberoast", no_verdict) is None


# ---- investigate_alert 接线:研判后自动存快照 ----
class _Graph:
    def __init__(self, node):
        self.node = node
        self.written = []

    def get_alert(self, uid):
        return self.node

    def seed(self, alert):
        return {}

    def write_result(self, uid, result):
        self.written.append((uid, result))


class _Inv:
    def __init__(self, result):
        self.result = result

    def investigate(self, alert, seed=None, skill=None):
        return self.result


def test_investigate_alert_snapshots_case_when_store_given():
    node = {"alert_uid": "k9", "technique_ids": ["T1558.003"]}
    graph = _Graph(node)
    result = _result(uid="k9", findings=[Finding("kerberoast.rc4_requested")])
    store = InMemoryCaseStore()
    out = investigate_alert(graph, _Inv(result), "k9", skill=None, case_store=store)
    assert out is result
    assert graph.written == [("k9", result)]                 # 台账照写
    cases = store.by_skill("kerberoast")                     # skill=None → 用 result.skill
    assert len(cases) == 1 and cases[0].alert_uid == "k9"
    assert cases[0].finding_ids() == {"kerberoast.rc4_requested"}


def test_investigate_alert_no_snapshot_when_store_none():
    graph = _Graph({"alert_uid": "k1"})
    result = _result(uid="k1")
    out = investigate_alert(graph, _Inv(result), "k1", skill=None)   # 无 case_store → 不快照、不崩
    assert out is result
    assert graph.written == [("k1", result)]
