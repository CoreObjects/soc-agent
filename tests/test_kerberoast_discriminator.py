"""Kerberoast 判别 spec(图模式判别 → 分层判别特征)。

判别器查图算判别特征(短窗 SPN 扇出分桶 / req_is_machine / same_domain / enc),产【有序分层】:
- exculpatory(先证伪):跨域机器账号引荐票 —— 键于 {req_is_machine, same_domain}(粗,忽略扇出/enc);
- incriminating(坐实):spray —— 键于 {req_is_machine, same_domain, enc, spn_fanout}。
实例值(账号/域名)不进特征,只留着填处置目标。用 fake graph(判别器只读图)。
"""
import importlib.util
import pathlib

from soc_agent.models import Alert

_DISC = pathlib.Path(__file__).resolve().parents[1] / "skills" / "identity" / "kerberoast" / "discriminator.py"


def _discriminate():
    spec = importlib.util.spec_from_file_location("kdisc", _DISC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.discriminate


class FakeGraph:
    def __init__(self, row):
        self.row = row

    def run_cypher(self, q, **p):
        return [self.row] if self.row is not None else []


def _alert():
    return Alert.from_node({"alert_uid": "a1", "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting", "rule_id": "100801"})


def _layer(result, name):
    return next(l for l in result["layers"] if l["layer"] == name)


def test_layers_ordered_exculpatory_first():
    g = FakeGraph({"req_sam": "vagrant", "req_domain": "NORTH", "tgt_domain": "NORTH", "enc": "0x17", "fanout": 7})
    r = _discriminate()(g, _alert())
    assert [l["layer"] for l in r["layers"]] == ["exculpatory", "incriminating"]   # 先证伪在前


def test_user_spray_features():
    g = FakeGraph({"req_sam": "vagrant", "req_domain": "NORTH", "tgt_domain": "NORTH", "enc": "0x17", "fanout": 7})
    r = _discriminate()(g, _alert())
    assert _layer(r, "exculpatory")["features"] == {"req_is_machine": False, "same_domain": True}
    assert _layer(r, "incriminating")["features"] == {
        "req_is_machine": False, "same_domain": True, "enc": "RC4", "spn_fanout": ">=5"}


def test_bindings_carry_instance_values():
    g = FakeGraph({"req_sam": "vagrant", "req_domain": "NORTH", "tgt_sam": "sql_svc", "tgt_domain": "NORTH",
                   "enc": "0x17", "fanout": 7, "req_host": "castelblack"})
    b = _discriminate()(g, _alert())["bindings"]
    # 实例值只在 bindings(含源主机,供 collect_artifact 绑真主机),不进 features
    assert b == {"requester": "vagrant", "target_service": "sql_svc", "req_host": "castelblack"}


def test_bindings_req_host_none_when_absent():
    g = FakeGraph({"req_sam": "vagrant", "req_domain": "NORTH", "tgt_sam": "sql_svc", "tgt_domain": "NORTH",
                   "enc": "0x17", "fanout": 7})
    assert _discriminate()(g, _alert())["bindings"]["req_host"] is None   # 取不到源主机=None(护栏会把该步降级)


def test_machine_cross_domain_referral_features():
    # WINTERFELL$ 请 SEVENKINGDOMS 的票 = 机器账号跨域引荐 → 豁免层键于 {机器账号, 跨域}
    g = FakeGraph({"req_sam": "WINTERFELL$", "req_domain": "NORTH", "tgt_domain": "SEVENKINGDOMS", "enc": "0x17", "fanout": 9})
    exc = _layer(_discriminate()(g, _alert()), "exculpatory")["features"]
    assert exc == {"req_is_machine": True, "same_domain": False}


def test_enc_and_fanout_buckets():
    g = FakeGraph({"req_sam": "u", "req_domain": "A", "tgt_domain": "A", "enc": "0x12", "fanout": 2})
    inc = _layer(_discriminate()(g, _alert()), "incriminating")["features"]
    assert inc["enc"] == "other" and inc["spn_fanout"] == "<5"


def test_netbios_vs_fqdn_same_domain():
    # NetBIOS NORTH 与 FQDN north.sevenkingdoms.local 是同一域,不能当跨域
    g = FakeGraph({"req_sam": "u", "req_domain": "NORTH", "tgt_domain": "north.sevenkingdoms.local", "enc": "0x17", "fanout": 6})
    exc = _layer(_discriminate()(g, _alert()), "exculpatory")["features"]
    assert exc["same_domain"] is True


def test_skills_runtime_loads_discriminate():
    from soc_agent.skills_runtime import load_skill
    skill = load_skill(_DISC.parent)                 # 真 kerberoast 目录
    assert callable(skill.discriminate)


def test_broken_discriminator_isolated(tmp_path):
    from soc_agent.skills_runtime import load_skill
    d = tmp_path / "identity" / "x"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: x\nlayer: identity\n---\nm", encoding="utf-8")
    (d / "discriminator.py").write_text("import nonexistent_module_xyz\n", encoding="utf-8")
    skill = load_skill(d)                            # 坏文件不炸,该能力=None
    assert skill.discriminate is None
