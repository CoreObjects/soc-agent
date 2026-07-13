"""skills_runtime:skill = 文件目录(SKILL.md 方法论 + 后续 recipes/ + patterns/)。

选择:按告警 technique 命中具体 skill;未覆盖 → 该层通用兜底(_generic/<layer>)。
"""
import pytest

from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillNotFound, SkillRegistry, load_skill


def _write_skill(base, rel, front, body="方法论正文:先证伪→看基线→看权限→看时序→看落地"):
    p = base / rel
    p.mkdir(parents=True, exist_ok=True)
    (p / "SKILL.md").write_text(f"---\n{front}\n---\n{body}\n", encoding="utf-8")
    return p


def test_load_skill_parses_frontmatter_and_body(tmp_path):
    p = _write_skill(tmp_path, "identity/kerberoast",
                     "name: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]\ndescription: Kerberoast 研判")
    s = load_skill(p)
    assert s.name == "kerberoast"
    assert s.layer == "identity"
    assert s.technique_ids == ["T1558.003"]
    assert s.description == "Kerberoast 研判"
    assert "先证伪" in s.methodology


def test_registry_selects_specific_by_technique(tmp_path):
    _write_skill(tmp_path, "identity/kerberoast", "name: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]")
    _write_skill(tmp_path, "_generic/identity", "name: generic_identity\nlayer: identity\ntechnique_ids: []")
    reg = SkillRegistry(tmp_path)
    a = Alert.from_node({"alert_uid": "1", "technique_ids": ["T1558.003"]})
    assert reg.select(a).name == "kerberoast"


def test_registry_falls_back_to_generic_by_layer(tmp_path):
    _write_skill(tmp_path, "identity/kerberoast", "name: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]")
    _write_skill(tmp_path, "_generic/identity", "name: generic_identity\nlayer: identity\ntechnique_ids: []")
    reg = SkillRegistry(tmp_path)
    a = Alert.from_node({"alert_uid": "2", "technique_ids": ["T9999"]})   # 未覆盖
    assert reg.select(a, layer="identity").name == "generic_identity"


def test_registry_raises_when_nothing_matches(tmp_path):
    reg = SkillRegistry(tmp_path)   # 空
    a = Alert.from_node({"alert_uid": "3", "technique_ids": ["T1"]})
    with pytest.raises(SkillNotFound):
        reg.select(a)


def test_load_skill_loads_recipe_if_present(tmp_path):
    # skill 目录里有 recipe.py → 加载其 collect(确定性取证脚本 sink①)
    p = _write_skill(tmp_path, "identity/kerberoast",
                     "name: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]")
    (p / "recipe.py").write_text("def collect(graph, alert, seed):\n    return {'ok': 1}\n", encoding="utf-8")
    s = load_skill(p)
    assert s.recipe is not None
    assert s.recipe(None, None, None) == {"ok": 1}


def test_skill_recipe_none_when_absent(tmp_path):
    p = _write_skill(tmp_path, "host/lsass_dump", "name: lsass_dump\nlayer: host\ntechnique_ids: [T1003.001]")
    assert load_skill(p).recipe is None


def test_real_skills_dir_all_valid():
    # 守卫:仓库 skills/ 里每个 skill 都能加载(frontmatter 正常、有 description/layer、recipe 可调用)
    from pathlib import Path
    reg = SkillRegistry(Path(__file__).resolve().parents[1] / "skills")
    skills = reg.all()
    assert skills, "skills/ 应有 skill"
    for s in skills:
        assert s.name and s.description, f"{s.path} 缺 name/description"
        assert s.layer, f"{s.name} 缺 layer"
        if (s.path / "recipe.py").exists():
            assert callable(s.recipe), f"{s.name} 的 recipe.py 没有 collect"
    names = {s.name for s in skills}
    assert {"kerberoast", "adcs", "dcsync", "lateral_movement"} <= names           # 身份层四类
    assert {"lsass_dump", "ingress_tool_transfer", "registry_persistence", "suspicious_process"} <= names  # 主机层四类


def test_real_recipes_run_on_empty_graph():
    # 守卫:每个 recipe 空图跑不崩、返回证据 dict(抓 recipe 语法/逻辑错)
    from pathlib import Path

    from soc_agent.models import Alert

    class _G:
        def run_cypher(self, q, **p):
            return []

    reg = SkillRegistry(Path(__file__).resolve().parents[1] / "skills")
    a = Alert.from_node({"alert_uid": "x", "technique_ids": ["T1"]})
    for s in reg.all():
        if s.recipe:
            assert isinstance(s.recipe(_G(), a, {}), dict), f"{s.name} recipe 未返回 dict"


def test_registry_loads_all_skills(tmp_path):
    _write_skill(tmp_path, "identity/kerberoast", "name: kerberoast\nlayer: identity\ntechnique_ids: [T1558.003]")
    _write_skill(tmp_path, "host/lsass_dump", "name: lsass_dump\nlayer: host\ntechnique_ids: [T1003.001]")
    reg = SkillRegistry(tmp_path)
    assert {s.name for s in reg.all()} == {"kerberoast", "lsass_dump"}
