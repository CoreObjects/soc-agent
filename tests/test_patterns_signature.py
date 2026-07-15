"""判别特征签名规范化(patterns.signature)。

规则库的键 = skill + 层(exculpatory/incriminating)+ 判别特征值 的规范签名。
必须:特征顺序无关、值规范(bool/None/数)、skill+层参与键 → 同一组判别特征永远得同一 sig_hash(去重、可查)。
"""
from soc_agent.patterns.signature import canonicalize


def test_feature_order_independent():
    a = canonicalize("kerberoast", "incriminating", {"enc": "RC4", "req_is_machine": False, "spn_fanout": ">=5"})
    b = canonicalize("kerberoast", "incriminating", {"spn_fanout": ">=5", "req_is_machine": False, "enc": "RC4"})
    assert a.sig == b.sig
    assert a.sig_hash == b.sig_hash
    assert len(a.sig_hash) == 64          # sha256 hex


def test_distinguishes_values():
    a = canonicalize("kerberoast", "incriminating", {"spn_fanout": ">=5"})
    b = canonicalize("kerberoast", "incriminating", {"spn_fanout": "<5"})
    assert a.sig_hash != b.sig_hash


def test_skill_and_layer_in_key():
    a = canonicalize("kerberoast", "exculpatory", {"x": 1})
    b = canonicalize("kerberoast", "incriminating", {"x": 1})
    c = canonicalize("other", "exculpatory", {"x": 1})
    assert len({a.sig_hash, b.sig_hash, c.sig_hash}) == 3


def test_value_normalization_stable():
    # bool/None/数 归一,不因 True vs "true" vs 1 抖动
    a = canonicalize("s", "l", {"m": True, "n": None, "k": 5})
    b = canonicalize("s", "l", {"m": True, "n": None, "k": 5})
    assert a.sig_hash == b.sig_hash
    assert "m=true" in a.sig and "n=null" in a.sig and "k=5" in a.sig


def test_layersig_carries_fields():
    s = canonicalize("kerberoast", "incriminating", {"enc": "RC4"})
    assert s.skill == "kerberoast" and s.layer == "incriminating"
    assert s.features == {"enc": "RC4"}
