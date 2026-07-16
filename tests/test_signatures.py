"""攻击模式签名注册表(快通道用)：跑全部签名函数、各自自锚定算签名、过滤伪签名。

每函数 (graph, alert, seed) → {"skill","layers","bindings"} | None。锚不到触发事件/取不到证据 → None(伪签名)。
run_all 遍历注册表收集非 None。判别全确定性、无大模型。
"""
from soc_agent.models import Alert
from soc_agent.patterns.signatures import run_all, sig_kerberoast


class FakeGraph:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def run_cypher(self, q, **p):
        self.queries.append(q)
        return self.rows


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100801"})


def test_kerberoast_signature_user_spray():
    g = FakeGraph([{"req_sam": "vagrant", "req_domain": "NORTH", "tgt_sam": "sql_svc",
                    "tgt_domain": "NORTH", "enc": "0x17", "fanout": 7, "req_host": None}])
    r = sig_kerberoast(g, _alert())
    assert r["skill"] == "kerberoast"
    assert [l["layer"] for l in r["layers"]] == ["exculpatory", "incriminating"]   # 先证伪在前
    assert r["layers"][1]["features"] == {"req_is_machine": False, "same_domain": True,
                                          "enc": "RC4", "spn_fanout": ">=5"}
    assert r["bindings"]["requester"] == "vagrant"
    assert r["bindings"]["target_service"] == "sql_svc"


def test_kerberoast_signature_machine_cross_domain():
    g = FakeGraph([{"req_sam": "WINTERFELL$", "req_domain": "NORTH", "tgt_sam": "svc",
                    "tgt_domain": "SEVENKINGDOMS", "enc": "0x17", "fanout": 9}])
    r = sig_kerberoast(g, _alert())
    assert r["layers"][0]["features"] == {"req_is_machine": True, "same_domain": False}


def test_kerberoast_signature_none_when_no_anchor():
    # 告警不是 4769 触发(锚定查不到) → 伪签名 → None,不参与碰撞/沉淀
    assert sig_kerberoast(FakeGraph([]), _alert()) is None


def test_run_all_collects_nonnull_with_skill():
    g = FakeGraph([{"req_sam": "vagrant", "req_domain": "NORTH", "tgt_sam": "sql_svc",
                    "tgt_domain": "NORTH", "enc": "0x17", "fanout": 7}])
    sigs = run_all(g, _alert())
    assert len(sigs) == 1 and sigs[0]["skill"] == "kerberoast"


def test_run_all_filters_pseudo_signatures():
    # 锚不到 → 该函数返回 None → run_all 过滤掉 → 空 list
    assert run_all(FakeGraph([]), _alert()) == []


def test_run_all_survives_broken_signature_fn(monkeypatch):
    # 某签名函数抛异常 → 隔离、不拖垮 run_all
    import soc_agent.patterns.signatures as S

    def boom(graph, alert, seed=None):
        raise RuntimeError("bad")
    monkeypatch.setattr(S, "_REGISTRY", [boom, sig_kerberoast])
    g = FakeGraph([{"req_sam": "vagrant", "req_domain": "NORTH", "tgt_sam": "s",
                    "tgt_domain": "NORTH", "enc": "0x17", "fanout": 7}])
    sigs = run_all(g, _alert())
    assert [s["skill"] for s in sigs] == ["kerberoast"]
