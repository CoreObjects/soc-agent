"""快通道签名引擎(patterns.signatures)+ co-located 的 kerberoast signature.py。

引擎本身不认识任何攻击类型:遍历注册表所有 skill、跑各自 `Skill.signature`、盖 skill 名收集非 None。
签名函数与 skill co-located(skills/<layer>/<name>/signature.py),锚不到→None(伪签名过滤)。判别全确定性、无大模型。
"""
from pathlib import Path
from types import SimpleNamespace

from soc_agent.models import Alert
from soc_agent.patterns.signatures import run_all
from soc_agent.skills_runtime import SkillRegistry


class FakeGraph:
    def __init__(self, rows):
        self.rows = rows

    def run_cypher(self, q, **p):
        return self.rows


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100801"})


# ---- 引擎:遍历注册表跑各 skill 的签名、注入 skill 名、过滤伪签名、隔离坏函数 ----

def _skill(name, fn):
    return SimpleNamespace(name=name, signature=fn)


def _registry(*skills):
    return SimpleNamespace(all=lambda: list(skills))


def test_engine_collects_nonnull_and_injects_skill_name():
    reg = _registry(
        _skill("kerberoast", lambda g, a, s=None: {
            "layers": [{"layer": "incriminating", "features": {"x": 1}}], "bindings": {"r": "u"}}),
        _skill("adcs", lambda g, a, s=None: None),                     # 伪签名(锚不到)→ 过滤
    )
    sigs = run_all(reg, FakeGraph([]), _alert())
    assert len(sigs) == 1
    assert sigs[0]["skill"] == "kerberoast"                            # ★skill 名由引擎按目录注入
    assert sigs[0]["bindings"] == {"r": "u"}


def test_engine_skips_pseudo_and_skills_without_signature():
    reg = _registry(
        _skill("adcs", lambda g, a, s=None: None),                     # 伪签名
        SimpleNamespace(name="generic_identity", signature=None),      # 无 signature.py → 跳过
    )
    assert run_all(reg, FakeGraph([]), _alert()) == []


def test_engine_survives_broken_signature_fn():
    def boom(g, a, s=None):
        raise RuntimeError("bad")
    reg = _registry(_skill("bad", boom),
                    _skill("kerberoast", lambda g, a, s=None: {"layers": [], "bindings": {}}))
    sigs = run_all(reg, FakeGraph([]), _alert())
    assert [s["skill"] for s in sigs] == ["kerberoast"]                # 坏函数隔离、不拖垮全局


# ---- co-located kerberoast signature.py(真 skill 目录加载,验 ._kerb 相对导入 + 与 recipe 同一份原语)----

def _kerb_signature():
    reg = SkillRegistry(Path(__file__).resolve().parents[1] / "skills")
    return reg.by_name("kerberoast").signature


def test_kerberoast_signature_loaded_from_skill_dir():
    assert _kerb_signature() is not None                              # signature.py 被自动发现


def test_kerberoast_signature_user_spray():
    g = FakeGraph([{"req_sam": "vagrant", "req_domain": "NORTH", "tgt_sam": "sql_svc",
                    "tgt_domain": "NORTH", "enc": "0x17", "fanout": 7}])
    r = _kerb_signature()(g, _alert())
    assert [l["layer"] for l in r["layers"]] == ["exculpatory", "incriminating"]   # 先证伪在前
    assert r["layers"][1]["features"] == {"req_is_machine": False, "same_domain": True,
                                          "enc": "RC4", "spn_fanout": ">=5"}
    assert r["bindings"]["requester"] == "vagrant"
    assert r["bindings"]["target_service"] == "sql_svc"
    assert "skill" not in r                                           # 函数自己不写 skill 名(引擎注入)


def test_kerberoast_signature_netbios_same_domain():
    # ★NetBIOS 归一(共享 ._kerb.same_domain):NORTH 与 north.sevenkingdoms.local 是同一个域
    g = FakeGraph([{"req_sam": "WINTERFELL$", "req_domain": "NORTH",
                    "tgt_sam": "svc", "tgt_domain": "north.sevenkingdoms.local", "enc": "0x17", "fanout": 9}])
    r = _kerb_signature()(g, _alert())
    assert r["layers"][0]["features"] == {"req_is_machine": True, "same_domain": True}


def test_kerberoast_signature_true_cross_domain():
    g = FakeGraph([{"req_sam": "WINTERFELL$", "req_domain": "NORTH",
                    "tgt_sam": "svc", "tgt_domain": "ESSOS", "enc": "0x17", "fanout": 9}])
    r = _kerb_signature()(g, _alert())
    assert r["layers"][0]["features"] == {"req_is_machine": True, "same_domain": False}


def test_kerberoast_signature_none_when_no_anchor():
    # 告警不是 4769 触发(锚定查不到)→ 伪签名 → None,不参与碰撞/沉淀
    assert _kerb_signature()(FakeGraph([]), _alert()) is None
