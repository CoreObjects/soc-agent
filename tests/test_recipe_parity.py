"""行集一致闸门自身的测试 —— 闸门不先证明自己会红,就没有资格拦别人。

只测判定逻辑(`diff`),不连图。守两件事:
  · **少了任何东西一律算差异**(白名单只放行"新增",不放行"缺失");
  · **未声明的新增算差异**,声明过的才放行 —— 白名单是拿来声明的,不是拿来兜底的。
"""
import importlib.util
import pathlib

from soc_agent.forensics import Finding, Forensics

_SPEC = importlib.util.spec_from_file_location(
    "recipe_parity", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "recipe_parity.py")
RP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RP)


def _fo(findings=(), bindings=None, context=None, blind=""):
    return Forensics(findings=list(findings), bindings=dict(bindings or {}),
                     context=dict(context or {}), blind_spots=blind)


def test_identical_is_no_diff():
    a = _fo([Finding("k.x", {"n": 1})], {"account": "jon"}, {"证据": [1, 2]}, "看不到签名")
    b = _fo([Finding("k.x", {"n": 1})], {"account": "jon"}, {"证据": [1, 2]}, "看不到签名")
    assert RP.diff(a, b) == []


def test_missing_finding_is_always_a_diff_even_if_whitelisted():
    """★白名单只管"多出来的";**少东西一律算差异** —— 否则改动可以靠加白名单把丢失掩盖掉。"""
    a = _fo([Finding("k.x"), Finding("k.y")])
    b = _fo([Finding("k.x")])
    d = RP.diff(a, b, new_findings=("k.y",))      # 就算把 k.y 写进白名单
    assert any("findings 少了" in x for x in d)


def test_undeclared_addition_is_a_diff_declared_one_is_not():
    a = _fo([Finding("k.x")])
    b = _fo([Finding("k.x"), Finding("_coverage.absent")])
    assert any("多了未声明的" in x for x in RP.diff(a, b))
    assert RP.diff(a, b, new_findings=("_coverage.absent",)) == []


def test_changed_finding_content_is_a_diff():
    """finding_id 一样但 attrs 变了 —— 这是最容易被漏掉的一种:集合比对看不出来。"""
    a = _fo([Finding("k.x", {"bucket": "low"})])
    b = _fo([Finding("k.x", {"bucket": "high"})])
    assert any("内容变了" in x for x in RP.diff(a, b))


def test_binding_and_context_changes_are_diffs():
    assert any("binding" in x for x in
               RP.diff(_fo(bindings={"a": "1"}), _fo(bindings={"a": "2"})))
    assert any("context" in x for x in
               RP.diff(_fo(context={"k": [1]}), _fo(context={"k": [2]})))
    assert any("blind_spots" in x for x in RP.diff(_fo(blind="x"), _fo(blind="y")))


def test_context_compare_is_order_stable():
    """context 里常是 dict/list;比对必须对 key 顺序不敏感,否则会刷出一堆假差异。"""
    a = _fo(context={"k": {"b": 2, "a": 1}})
    b = _fo(context={"k": {"a": 1, "b": 2}})
    assert RP.diff(a, b) == []


def test_load_old_really_pulls_a_historical_version_from_git():
    """`load_old` 能从 git 取出历史版本并加载 —— **整个闸门的前提就是这一步**。

    (原本在 test_pivot.py 里守着 WP7 的专用闸门;专用闸门退休后搬到这里,
     免得这条前提随着那个文件一起消失。)
    """
    m = RP.load_old("skills/network/c2_beacon/recipe.py", "HEAD")
    assert callable(getattr(m, "collect", None))


def test_changed_recipes_reads_the_diff_not_a_hardcoded_list():
    """待测集合来自 `rev..HEAD` 的真实 diff —— 写死列表就会漏掉刚改的那条。"""
    paths = RP.changed_recipes("HEAD")          # 与自己比 → 必然为空
    assert paths == []


def test_order_only_difference_is_classified_not_failed():
    """★Cypher 的 `collect(DISTINCT …)` 天然无序 —— 换条遍历路径顺序就变。

    真机首跑就撞上:30 条样本每条都报 `endpoints_hit 变了`,细看是**同一批 15 个端点、
    只是顺序不同**。若把它当失败,以后每个 PR 都被这种噪声刷屏,真差异反而被埋掉;
    若悄悄忽略,又会漏掉"顺序确实有意义"的列表(时间线之类)。
    所以分成两类:仅顺序 → 带 [顺序] 前缀报出来、不判失败;内容变 → 照常失败。
    """
    a = _fo(context={"endpoints_hit": ["/a", "/b", "/c"]})
    b = _fo(context={"endpoints_hit": ["/c", "/a", "/b"]})
    d = RP.diff(a, b)
    assert len(d) == 1 and d[0].startswith(RP._ORDER), d
    assert "仅顺序不同" in d[0]


def test_content_change_is_still_a_hard_failure_even_if_lengths_match():
    """同样长度、只换掉一个元素 —— 必须是**硬失败**,不能被顺序豁免蹭过去。"""
    a = _fo(context={"endpoints_hit": ["/a", "/b", "/c"]})
    b = _fo(context={"endpoints_hit": ["/a", "/b", "/X"]})
    d = RP.diff(a, b)
    assert len(d) == 1 and not d[0].startswith(RP._ORDER)
    assert "内容变了" in d[0]


def test_nested_order_difference_is_also_only_order():
    """嵌套结构里的列表顺序同样只算顺序(_unordered 是递归的)。"""
    a = _fo(context={"prof": {"rules": ["1", "2"], "n": 3}})
    b = _fo(context={"prof": {"rules": ["2", "1"], "n": 3}})
    assert RP.diff(a, b)[0].startswith(RP._ORDER)
