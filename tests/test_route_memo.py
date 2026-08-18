"""路由记忆层:键的阶梯与归一 + candidate/ambiguous/archived/unstable 状态机 + 只播负例的播种。

全部纯逻辑,不连 openGauss、不调 LLM。router 的接线在 test_route_memo_router.py。
"""
import pytest

from soc_agent.experience.route_memo import (
    DISAGREE_CAP,
    OVERRIDE_CAP,
    RELEARN_CAP,
    VERIFY_AT,
    InMemoryRouteMemoStore,
    RouteMemo,
    advance,
    route_key,
    seed_ambiguous,
    should_verify,
)
from soc_agent.models import Alert


def _alert(**kw):
    d = dict(alert_uid="A1", source="wazuh", sensor="wazuh", rule_id=None,
             rule_description="x", severity=7, technique_ids=[])
    d.update(kw)
    return Alert(**d)


def _seed(event_code=None, activity=None):
    ev = {}
    if event_code is not None:
        ev["event_code"] = event_code
    if activity is not None:
        ev["activity"] = activity
    return {"event": ev, "subject": None, "related": []}


# ---------------- 键:阶梯 ----------------
def test_rule_id_优先于_technique():
    """★宁细勿粗:rule_id 比 technique 细,有它就不该退到粗键上去。"""
    a = _alert(rule_id="100808", technique_ids=["T1505.003"])
    assert route_key(a, _seed("11")) == "r|wazuh|wazuh|100808"


def test_无_rule_id_退到_technique_加_event_code():
    a = _alert(rule_id=None, technique_ids=["T1021.001"])
    assert route_key(a, _seed("4624")) == "t|wazuh|wazuh|t1021.001|4624"


def test_两级键全落空_返回_None_不建记忆():
    assert route_key(_alert(rule_id=None, technique_ids=[]), _seed("4624")) is None


def test_空白_rule_id_视为没有_退到下一级():
    a = _alert(rule_id="   ", technique_ids=["T1105"])
    assert route_key(a, _seed("11")) == "t|wazuh|wazuh|t1105|11"


# ---------------- 键:归一 ----------------
def test_大小写与空白归一():
    a1 = _alert(rule_id=" 100808 ", source="Wazuh", sensor="WAZUH")
    a2 = _alert(rule_id="100808", source="wazuh", sensor="wazuh")
    assert route_key(a1, _seed("11")) == route_key(a2, _seed("11"))


def test_technique_顺序不同必须是同一个键():
    """★不排序的话,同一组技战术会因顺序不同裂成多条记忆、各自单独学一遍。"""
    k1 = route_key(_alert(technique_ids=["T1003.006", "T1021.001"]), _seed("4662"))
    k2 = route_key(_alert(technique_ids=["T1021.001", "T1003.006"]), _seed("4662"))
    assert k1 == k2


def test_technique_去重():
    k1 = route_key(_alert(technique_ids=["T1105", "T1105"]), _seed("11"))
    k2 = route_key(_alert(technique_ids=["T1105"]), _seed("11"))
    assert k1 == k2


def test_event_code_缺失时退_activity_再退占位():
    a = _alert(technique_ids=["T1105"])
    assert route_key(a, _seed(activity="file.write")) == "t|wazuh|wazuh|t1105|file.write"
    assert route_key(a, _seed()) == "t|wazuh|wazuh|t1105|-"
    assert route_key(a, None) == "t|wazuh|wazuh|t1105|-"


def test_空_source_sensor_占位不串位():
    """段数必须恒定,否则缺字段时键会串位、把两类告警撞成一个键。"""
    k = route_key(_alert(source=None, sensor=None, rule_id="9"), _seed("1"))
    assert k == "r|-|-|9"
    assert k.count("|") == route_key(_alert(rule_id="9"), _seed("1")).count("|")


# ---------------- 状态机:出生与确认 ----------------
def test_第一次只建_candidate_且不可复用():
    """★第一次 LLM 的答案不许直接被复用 —— 这是整个 candidate 门的存在理由。"""
    m, act = advance(None, "k", "kerberoast", "A1")
    assert (act, m.status, m.skill) == ("created", "candidate", "kerberoast")
    assert m.reusable is False


def test_同一条告警再来一次不算确认():
    """poller 有 retry、DLQ 有 replay、Kafka 有重复消费 —— 同一条告警跑两遍是常态。
    不判这一下,"两次一致"可能只是同一个样本被观察了两遍。"""
    m, _ = advance(None, "k", "kerberoast", "A1")
    m, act = advance(m, "k", "kerberoast", "A1")
    assert act == "same_alert_ignored"
    assert m.status == "candidate" and m.confirm_count == 1
    assert m.reusable is False


def test_不同告警二次一致才转正():
    m, _ = advance(None, "k", "kerberoast", "A1")
    m, act = advance(m, "k", "kerberoast", "A2")
    assert (act, m.status) == ("activated", "active")
    assert m.reusable is True


# ---------------- 状态机:分歧与认输 ----------------
def test_二次不一致_改押新答案且分歧计数():
    m, _ = advance(None, "k", "skill_a", "A1")
    m, act = advance(m, "k", "skill_b", "A2")
    assert act == "disagree"
    assert m.skill == "skill_b" and m.confirm_count == 1 and m.disagree_count == 1
    assert m.status == "candidate" and m.reusable is False


def test_AB交替到上限判_ambiguous():
    """★没有这条,真·歧义键会无限翻烙饼:每条告警照烧一次 LLM,既不变好也不报警。"""
    m, _ = advance(None, "k", "skill_a", "A1")
    acts = []
    for i, s in enumerate(["skill_b", "skill_a", "skill_b"], start=2):
        m, act = advance(m, "k", s, f"A{i}")
        acts.append(act)
    assert m.disagree_count == DISAGREE_CAP
    assert m.status == "ambiguous"
    assert acts[-1] == "ambiguous"


def test_ambiguous_是终态_再观察也不动():
    m = RouteMemo(route_key="k", skill="a", status="ambiguous")
    before = m.to_dict()
    m2, act = advance(m, "k", "b", "A9")
    assert act == "terminal"
    assert {k: v for k, v in m2.to_dict().items() if k != "updated_at"} == \
           {k: v for k, v in before.items() if k != "updated_at"}


# ---------------- 状态机:复核、归档、重学 ----------------
def test_稀疏复核点():
    assert [h for h in (1, 2, 10, 100, 999, 1000, 10000) if should_verify(h)] == [100, 1000, 10000]
    assert set(VERIFY_AT) == {100, 1000, 10000}


def test_复核一致只记次数():
    m = RouteMemo(route_key="k", skill="a", status="active")
    m, act = advance(m, "k", "a", "A5")
    assert (act, m.status, m.verify_count, m.override_count) == ("verified", "active", 1, 0)


def test_复核不一致累计到上限才归档():
    m = RouteMemo(route_key="k", skill="a", status="active")
    m, act = advance(m, "k", "b", "A5")
    assert (act, m.status, m.override_count) == ("override", "active", 1)
    m, act = advance(m, "k", "b", "A6")
    assert (act, m.status) == ("archived", "archived")
    assert m.override_count == OVERRIDE_CAP


def test_归档后可以重学():
    """模型升级/registry 变更/recipe 改写都会让一个键从"不可缓存"变回"可缓存",
    永久判死刑等于永远多花钱。"""
    m = RouteMemo(route_key="k", skill="a", status="archived", override_count=2)
    m, act = advance(m, "k", "b", "A7")
    assert (act, m.status, m.skill) == ("relearn", "candidate", "b")
    assert m.relearn_count == 1 and m.confirm_count == 1
    assert m.override_count == 0                      # 重学要从干净的计数开始
    m, act = advance(m, "k", "b", "A8")
    assert (act, m.status) == ("activated", "active")


def test_重学到上限判_unstable():
    """反复 archive→重学→再 archive 的震荡,本身是在说"这个键少了一个区分字段"。"""
    m = RouteMemo(route_key="k", skill="a", status="archived", relearn_count=RELEARN_CAP)
    m, act = advance(m, "k", "b", "A9")
    assert (act, m.status) == ("unstable", "unstable")


def test_unstable_也是终态():
    m = RouteMemo(route_key="k", skill="a", status="unstable")
    m, act = advance(m, "k", "b", "A9")
    assert act == "terminal" and m.status == "unstable"


def test_未知状态直接拒绝():
    with pytest.raises(ValueError):
        RouteMemo(route_key="k", status="whatever")


# ---------------- 播种:只播负例 ----------------
def test_播种只写_ambiguous():
    st = InMemoryRouteMemoStore()
    assert seed_ambiguous(st, ["k1", "k2"]) == 2
    assert {m.status for m in st.all()} == {"ambiguous"}
    assert all(m.skill is None for m in st.all())


def test_播种可以收紧已有的_active():
    """播种只能收紧、不能放宽 —— 收紧是允许的。"""
    st = InMemoryRouteMemoStore()
    st.upsert(RouteMemo(route_key="k", skill="a", status="active"))
    assert seed_ambiguous(st, ["k"]) == 1
    assert st.lookup("k").status == "ambiguous"


def test_播种不动已有终态():
    st = InMemoryRouteMemoStore()
    st.upsert(RouteMemo(route_key="k", skill="a", status="unstable"))
    assert seed_ambiguous(st, ["k"]) == 0
    assert st.lookup("k").status == "unstable"


def test_播种跳过空键():
    st = InMemoryRouteMemoStore()
    assert seed_ambiguous(st, [None, "", "k"]) == 1


# ---------------- 库 ----------------
def test_内存库_bump_hit_返回自增后的值():
    st = InMemoryRouteMemoStore()
    st.upsert(RouteMemo(route_key="k", skill="a", status="active"))
    assert [st.bump_hit("k") for _ in range(3)] == [1, 2, 3]


def test_内存库_bump_不存在的键不炸():
    assert InMemoryRouteMemoStore().bump_hit("nope") == 0


def test_upsert_不覆盖已有的_hit_count():
    """★两个实现在这点上必须一致:openGauss 的 UPDATE 不写 hit_count(命中只由 bump_hit 自增)。
    内存实现若照写回去,单测量到的行为就和线上不是同一个 —— 而这种差异不会报错。"""
    st = InMemoryRouteMemoStore()
    st.upsert(RouteMemo(route_key="k", skill="a", status="active"))
    st.bump_hit("k")
    st.bump_hit("k")
    stale = RouteMemo(route_key="k", skill="b", status="active", hit_count=0)   # 旧对象
    st.upsert(stale)
    assert st.lookup("k").hit_count == 2
    assert st.lookup("k").skill == "b"          # 其余字段照常更新


def test_记录可往返序列化():
    m = RouteMemo(route_key="k", skill="a", status="active", hit_count=7, relearn_count=2)
    assert RouteMemo.from_dict(m.to_dict()).to_dict() == m.to_dict()
