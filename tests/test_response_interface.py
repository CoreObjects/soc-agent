"""处置接口文档(interface)= 原语语义的唯一来源。

core 逻辑 dict 驱动、可离线单测(不依赖 yaml);load_interface 文件包装单独测(缺 yaml 跳过)。
"""
import pytest

from soc_agent.response.interface import Interface, Primitive


def _data():
    return {
        "version": "2026.07",
        "primitives": [
            {
                "id": "disable_account", "category": "identity",
                "summary": "禁用 AD 账号",
                "target": {"kind": "account", "key_field": "sam", "extra_keys": ["domain"]},
                "params": [
                    {"name": "sam", "type": "string", "required": True,
                     "source": "entity_role"},
                    {"name": "domain", "type": "string", "required": False,
                     "source": "entity_role"},
                ],
                "gating": "gated", "blast_radius": "single_target", "risk_default": "high",
                "reversible": {"mode": "full", "inverse": "enable_account",
                               "inverse_param_map": {"sam": "sam", "domain": "domain"}},
            },
            {
                "id": "remove_from_group", "category": "identity",
                "target": {"kind": "account", "key_field": "sam"},
                "params": [
                    {"name": "sam", "type": "string", "required": True, "source": "entity_role"},
                    {"name": "group", "type": "string", "required": True, "source": "entity_role"},
                ],
                "gating": "gated", "blast_radius": "single_target", "risk_default": "high",
                "reversible": {"mode": "full", "inverse": "add_to_group"},
            },
            {
                "id": "collect_artifact", "category": "endpoint",
                "target": {"kind": "host", "key_field": "hostname"},
                "params": [{"name": "hostname", "type": "string", "required": True,
                            "source": "entity_role"}],
                "gating": "auto", "blast_radius": "single_target", "risk_default": "low",
                "reversible": {"mode": "none"},
            },
            {
                "id": "isolate_host", "category": "endpoint",
                "target": {"kind": "host", "key_field": "hostname"},
                "params": [{"name": "hostname", "type": "string", "required": True,
                            "source": "entity_role"}],
                "gating": "gated", "blast_radius": "host", "risk_default": "high",
                "reversible": {"mode": "full", "inverse": "release_host"},
            },
            {   # inverse:不是 composer 规划的正向原语,标 planned_by_composer=False
                "id": "enable_account", "category": "identity",
                "target": {"kind": "account", "key_field": "sam"},
                "params": [{"name": "sam", "type": "string", "required": True,
                            "source": "entity_role"}],
                "gating": "gated", "blast_radius": "single_target", "risk_default": "low",
                "reversible": {"mode": "full", "inverse": "disable_account"},
                "planned_by_composer": False,
            },
        ],
    }


def test_from_dict_indexes_primitives():
    iface = Interface.from_dict(_data())
    assert iface.version == "2026.07"
    assert iface.ids() == {"disable_account", "remove_from_group", "collect_artifact",
                           "isolate_host", "enable_account"}
    assert iface.is_known("disable_account")
    assert not iface.is_known("nope")
    assert isinstance(iface.get("disable_account"), Primitive)
    assert iface.get("nope") is None


def test_kind_and_expected_target():
    iface = Interface.from_dict(_data())
    assert iface.kind_of("disable_account") == "account"
    assert iface.kind_of("isolate_host") == "host"
    assert iface.kind_of("unknown") == "none"          # 未知归一 none(不硬造 :ON)
    assert iface.target_key_field("remove_from_group") == "sam"


def test_gating_and_blast_radius():
    iface = Interface.from_dict(_data())
    assert iface.is_gated("disable_account")           # 变更类 gated
    assert not iface.is_gated("collect_artifact")      # 只读 auto
    assert iface.is_gated("unknown")                   # 未知从严:gated
    assert iface.blast_radius("isolate_host") == "host"
    assert iface.is_domain_scoped("isolate_host") is False


def test_touches_endpoint_from_category():
    iface = Interface.from_dict(_data())
    assert iface.touches_endpoint("isolate_host")      # endpoint 面 → 查传感器 NEVER-TOUCH
    assert iface.touches_endpoint("collect_artifact")
    assert not iface.touches_endpoint("disable_account")


def test_reversible_and_inverse():
    iface = Interface.from_dict(_data())
    assert iface.reversible_mode("disable_account") == "full"
    assert iface.reversible_mode("collect_artifact") == "none"
    assert iface.inverse_of("disable_account") == "enable_account"
    assert iface.inverse_of("collect_artifact") is None


def test_composer_menu_excludes_pure_inverses():
    iface = Interface.from_dict(_data())
    menu = iface.composer_menu_ids()
    assert "disable_account" in menu
    assert "enable_account" not in menu                # 纯 inverse 不进 composer 菜单
    assert "collect_artifact" in menu


def test_param_spec_lookup():
    iface = Interface.from_dict(_data())
    p = iface.get("remove_from_group")
    assert [x["name"] for x in p.params] == ["sam", "group"]
    assert p.required_params() == ["sam", "group"]
    dis = iface.get("disable_account")
    assert dis.required_params() == ["sam"]            # domain required=False


def test_load_interface_reads_yaml_file(tmp_path):
    yaml = pytest.importorskip("yaml")
    from soc_agent.response.interface import load_interface
    p = tmp_path / "iface.yaml"
    p.write_text(yaml.safe_dump(_data(), allow_unicode=True), encoding="utf-8")
    iface = load_interface(str(p))
    assert iface.version == "2026.07"
    assert "disable_account" in iface.ids()


def test_load_interface_reads_json_file(tmp_path):
    import json
    from soc_agent.response.interface import load_interface
    p = tmp_path / "iface.json"
    p.write_text(json.dumps(_data()), encoding="utf-8")
    iface = load_interface(str(p))
    assert iface.version == "2026.07"
    assert iface.kind_of("isolate_host") == "host"


def test_default_interface_loads_committed_doc():
    # venv 无 yaml 也能加载:load_interface 回退到同名 interface.json
    from soc_agent.response.interface import default_interface
    iface = default_interface()
    assert iface.is_known("disable_account")
    assert iface.kind_of("isolate_host") == "host"
    assert not iface.is_gated("collect_artifact")           # 只读 auto
    assert "rotate_krbtgt" not in iface.composer_menu_ids()  # break-glass 不进菜单


def test_committed_yaml_and_json_do_not_drift():
    # interface.yaml 是权威源,interface.json 是机器可加载副本 —— 二者必须一致(防手改漏同步)
    yaml = pytest.importorskip("yaml")
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    y = yaml.safe_load((root / "interface.yaml").read_text(encoding="utf-8"))
    j = json.loads((root / "interface.json").read_text(encoding="utf-8"))
    assert y == j, "interface.json 与 interface.yaml 漂移:重新生成 interface.json"
