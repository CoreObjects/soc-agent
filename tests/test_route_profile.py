"""Phase 0 探针(scripts/route_profile.py)的定性与聚合逻辑。

★这份探针的输出会被拿来决定"要不要上路由记忆层、哪些键要播成负例",
  所以它自己的算术必须有测试 —— 一个算错的探针不会报错,只会给出一个看起来很像样的错结论。
★特别守住一条:探针**必须用生产的 `route_key()`**,不能自己重写一份。
  两份实现一旦漂移,这份报告描述的就是一个不存在的系统。
"""
import importlib.util
import pathlib
from collections import Counter

from soc_agent.experience.route_memo import route_key

_SPEC = importlib.util.spec_from_file_location(
    "route_profile",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "route_profile.py")
RP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RP)


class _Graph:
    def __init__(self, rows):
        self._rows = rows

    def run_cypher(self, q, **kw):
        return self._rows

    def close(self):
        pass


def _row(n=1, skill=None, **kw):
    d = dict(source="wazuh", sensor="wazuh", rule_id=None, technique_ids=[],
             event_code=None, activity=None, skill=skill, n=n)
    d.update(kw)
    return d


# ---------------- 定性 ----------------
def test_样本不足不下结论():
    assert RP.classify(Counter({"a": RP.MIN_SAMPLES - 1})) == "insufficient"


def test_样本够且唯一_eligible():
    assert RP.classify(Counter({"a": RP.MIN_SAMPLES})) == "eligible"


def test_两个_skill_且次数与比例都够_ambiguous():
    assert RP.classify(Counter({"a": 8, "b": 4})) == "ambiguous"      # 4/12 = 33%


def test_少数派只出现一次_记_skewed():
    """单个离群值更可能是 router 的一次抖动,不该在这里就把键判死。"""
    assert RP.classify(Counter({"a": 30, "b": 1})) == "skewed"


def test_大样本下的长尾不算歧义():
    """★只看次数会误判:2511 条里混 6 条别的(0.24%)本质是稳定的,
    判成 ambiguous 等于为了 6 条放弃 2511 条的收益。"""
    c = Counter({"dcsync": 2511, "lateral_movement": 6})
    assert RP.classify(c) == "skewed"
    assert RP.minority_ratio(c) < 0.01


def test_小样本下的高比例仍要够次数():
    """只看比例会误判小样本:4 条里 1 条不同 = 25%,但很可能只是抖了一下。"""
    assert RP.classify(Counter({"a": 3, "b": 1})) == "skewed"


def test_少数派比例_单一_skill_为零():
    assert RP.minority_ratio(Counter({"a": 9})) == 0.0
    assert RP.minority_ratio(Counter()) == 0.0


# ---------------- 聚合 ----------------
def test_按键归并且_r_级优先():
    rows = [_row(n=5, rule_id="100808", technique_ids=["T1505.003"], skill="webshell"),
            _row(n=3, rule_id="100808", technique_ids=["T1505.003"], skill="webshell")]
    per_key, totals = RP.collect(_Graph(rows))
    assert list(per_key) == ["r|wazuh|wazuh|100808"]
    e = per_key["r|wazuh|wazuh|100808"]
    assert (e["alerts"], e["judged"], dict(e["skills"])) == (8, 8, {"webshell": 8})
    assert (totals["keyed"], totals["keyed_r"], totals["keyed_t"]) == (8, 8, 0)


def test_technique_顺序不同在探针里也归并到一个键():
    """Cypher 按原始 list 分组会把 [A,B] 和 [B,A] 分成两行 —— 靠 route_key 归一化才并回来。
    这正是"键必须在 Python 侧算"的理由之一。"""
    rows = [_row(n=2, technique_ids=["T1003.006", "T1021.001"], event_code="4662", skill="dcsync"),
            _row(n=3, technique_ids=["T1021.001", "T1003.006"], event_code="4662", skill="dcsync")]
    per_key, totals = RP.collect(_Graph(rows))
    assert len(per_key) == 1
    assert list(per_key.values())[0]["alerts"] == 5


def test_无键的告警计入兜底不建键():
    rows = [_row(n=7)]                                   # 无 rule_id 也无 technique
    per_key, totals = RP.collect(_Graph(rows))
    assert per_key == {}
    assert (totals["no_key"], totals["keyed"], totals["alerts"]) == (7, 0, 7)


def test_未研判告警计入覆盖但不计入定性样本():
    """path=S 的告警没走过路由、没有 findings ⇒ skill 为空 ⇒ 本来就不该进定性样本。"""
    rows = [_row(n=10, rule_id="1", skill=None), _row(n=4, rule_id="1", skill="webshell")]
    per_key, totals = RP.collect(_Graph(rows))
    e = per_key["r|wazuh|wazuh|1"]
    assert (e["alerts"], e["judged"]) == (14, 4)
    assert totals["judged"] == 4


def test_rule_id_缺失与唯一值统计():
    rows = [_row(n=5, rule_id=None, technique_ids=["T1105"], event_code="11"),
            _row(n=2, rule_id="  ", technique_ids=["T1105"], event_code="11"),
            _row(n=3, rule_id="900"), _row(n=1, rule_id="901")]
    _, totals = RP.collect(_Graph(rows))
    assert totals["no_rule_id"] == 7                     # None 与全空白都算"没有"
    assert totals["rule_ids"] == {"900", "901"}


def test_探针用的就是生产那个_route_key():
    """★别在探针里另写一份键 —— 这条钉死它们是同一个函数。"""
    assert RP.route_key is route_key
