"""SkillRouter 接上路由记忆之后的行为:什么时候零 LLM、什么时候还得问、出事怎么降级。

路由是全流水线里最贵的单项(实测占 27b 调用的 77%),但**路由错了不会报错** ——
recipe 错 ⇒ findings 错 ⇒ 指纹键在错的 findings 上 ⇒ 整条链一起烂而各道闸门全绿。
所以这里逐条钉死:第一次的答案**不许**被复用、终态键**不许**再写表、
记忆库挂了**不许**把研判也拖停。
"""
from soc_agent.experience.route_memo import (InMemoryRouteMemoStore, RouteMemo,
                                             advance, route_key)
from soc_agent.llm import LLMResponse, ToolCall
from soc_agent.models import Alert
from soc_agent.orchestrator import SkillRouter


class _Skill:
    def __init__(self, name, generic=False):
        self.name = name
        self.description = f"{name} 研判"
        self.is_generic = generic


class _Reg:
    def __init__(self, names=("kerberoast", "dcsync"), generic="generic_identity"):
        self._s = [_Skill(n) for n in names] + ([_Skill(generic, True)] if generic else [])

    def all(self):
        return list(self._s)

    def by_name(self, n):
        return next((s for s in self._s if s.name == n), None)


class _LLM:
    """按脚本回答;答案用完就一直用最后一个。记调用次数 —— 这些测试量的就是它。"""

    def __init__(self, *answers):
        self.answers = list(answers) or ["kerberoast"]
        self.calls = 0

    def chat(self, messages, tools=None, tool_choice=None):
        name = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return LLMResponse(tool_calls=[ToolCall("c1", "select_skill", {"name": name})])


class _Boom:
    """一碰就炸的记忆库 —— 模拟 openGauss 抖动/表没建。"""

    def lookup(self, k):
        raise RuntimeError("connection reset")

    def upsert(self, m):
        raise RuntimeError("connection reset")

    def bump_hit(self, k):
        raise RuntimeError("connection reset")


def _alert(uid="A1", rule_id="100002"):
    return Alert.from_node({"alert_uid": uid, "rule_id": rule_id,
                            "source": "wazuh", "sensor": "wazuh",
                            "technique_ids": ["T1558.003"],
                            "rule_description": "Kerberoasting"})


_SEED = {"event": {"event_code": "4769"}}


def _router(llm, store=None):
    return SkillRouter(llm=llm, registry=_Reg(), agent_name="qwen", memo_store=store)


# ---------------- 回滚位:不传记忆库 = 今天的行为 ----------------
def test_不传记忆库时每条都问_LLM():
    """★这是回滚位,也是 batch_investigate / verify_all 这类脚本走的路。"""
    llm = _LLM("kerberoast")
    r = _router(llm)
    for i in range(3):
        assert r.route(_alert(f"A{i}"), _SEED).name == "kerberoast"
    assert llm.calls == 3


# ---------------- 出生:第一次不许被复用 ----------------
def test_首次未命中_只建_candidate_且第二条仍要问_LLM():
    st, llm = InMemoryRouteMemoStore(), _LLM("kerberoast")
    r = _router(llm, st)
    r.route(_alert("A1"), _SEED)
    key = route_key(_alert("A1"), _SEED)
    assert st.lookup(key).status == "candidate"
    assert llm.calls == 1
    r.route(_alert("A2"), _SEED)                    # 第二条:确认,仍要问
    assert llm.calls == 2
    assert st.lookup(key).status == "active"


def test_转正之后零_LLM():
    st, llm = InMemoryRouteMemoStore(), _LLM("kerberoast")
    r = _router(llm, st)
    r.route(_alert("A1"), _SEED)
    r.route(_alert("A2"), _SEED)
    before = llm.calls
    for i in range(3, 8):
        assert r.route(_alert(f"A{i}"), _SEED).name == "kerberoast"
    assert llm.calls == before                       # ← 一次都没再问
    assert st.lookup(route_key(_alert(), _SEED)).hit_count == 5


def test_同一条告警重复研判不会把_candidate_确认掉():
    """poller retry / DLQ replay / Kafka 重复消费下,同一条告警会跑不止一遍。"""
    st, llm = InMemoryRouteMemoStore(), _LLM("kerberoast")
    r = _router(llm, st)
    r.route(_alert("A1"), _SEED)
    r.route(_alert("A1"), _SEED)
    assert st.lookup(route_key(_alert(), _SEED)).status == "candidate"


def test_答案不稳时不转正():
    st, llm = InMemoryRouteMemoStore(), _LLM("kerberoast", "dcsync")
    r = _router(llm, st)
    r.route(_alert("A1"), _SEED)
    r.route(_alert("A2"), _SEED)
    m = st.lookup(route_key(_alert(), _SEED))
    assert (m.status, m.skill, m.disagree_count) == ("candidate", "dcsync", 1)


# ---------------- 稀疏复核 ----------------
def _activated(llm, skill="kerberoast", hit=99):
    st = InMemoryRouteMemoStore()
    st.upsert(RouteMemo(route_key=route_key(_alert(), _SEED), skill=skill,
                        status="active", confirm_count=2, hit_count=hit,
                        origin_alert_uid="A0"))
    return st, _router(llm, st)


def test_到复核点会顺带问一次_LLM_一致则照用记忆():
    llm = _LLM("kerberoast")
    st, r = _activated(llm)
    assert r.route(_alert("A9"), _SEED).name == "kerberoast"
    assert llm.calls == 1                            # 第 100 次命中 → 复核
    m = st.lookup(route_key(_alert(), _SEED))
    assert (m.status, m.verify_count, m.override_count) == ("active", 1, 0)


def test_复核不一致_这一条用_LLM_的新答案():
    llm = _LLM("dcsync")
    st, r = _activated(llm)
    assert r.route(_alert("A9"), _SEED).name == "dcsync"      # ★不是记忆里的 kerberoast
    assert st.lookup(route_key(_alert(), _SEED)).override_count == 1


def test_复核不一致两次就归档():
    llm = _LLM("dcsync")
    st, r = _activated(llm, hit=99)
    r.route(_alert("A9"), _SEED)
    m = st.lookup(route_key(_alert(), _SEED))
    m.hit_count = 999                                 # 推到下一个复核点
    st.upsert(m)
    r.route(_alert("A10"), _SEED)
    assert st.lookup(route_key(_alert(), _SEED)).status == "archived"


def test_没到复核点就不问():
    llm = _LLM("kerberoast")
    st, r = _activated(llm, hit=5)
    r.route(_alert("A9"), _SEED)
    assert llm.calls == 0


# ---------------- 终态 ----------------
def test_ambiguous_键恒走_LLM_且不再写表():
    llm = _LLM("kerberoast")
    st = InMemoryRouteMemoStore()
    key = route_key(_alert(), _SEED)
    st.upsert(RouteMemo(route_key=key, skill=None, status="ambiguous"))
    r = _router(llm, st)
    for i in range(3):
        assert r.route(_alert(f"A{i}"), _SEED).name == "kerberoast"
    assert llm.calls == 3
    m = st.lookup(key)
    assert (m.status, m.skill, m.confirm_count) == ("ambiguous", None, 1)   # 一动没动


# ---------------- 算不出键 / 库挂了 ----------------
def test_算不出键就不建记忆_每条都问():
    st, llm = InMemoryRouteMemoStore(), _LLM("kerberoast")
    r = _router(llm, st)
    a = Alert.from_node({"alert_uid": "A1", "source": "x", "sensor": "y"})   # 无 rule_id 无 technique
    r.route(a, _SEED)
    r.route(a, _SEED)
    assert llm.calls == 2 and st.all() == []


def test_记忆库炸了也要能研判():
    """★记忆层是优化不是依赖 —— 它挂了必须降级成"每条都问 LLM",不能把研判拖停。"""
    llm = _LLM("kerberoast")
    r = _router(llm, _Boom())
    assert r.route(_alert("A1"), _SEED).name == "kerberoast"
    assert r.route(_alert("A2"), _SEED).name == "kerberoast"
    assert llm.calls == 2


def test_记住的_skill_已从_registry_消失时回退_LLM():
    """skill 改名/删掉是"registry 变更"漂移的一种,记忆不能指着一个不存在的名字返回 None。"""
    llm = _LLM("kerberoast")
    st = InMemoryRouteMemoStore()
    key = route_key(_alert(), _SEED)
    st.upsert(RouteMemo(route_key=key, skill="没了的skill", status="active",
                        confirm_count=2, origin_alert_uid="A0"))
    r = _router(llm, st)
    assert r.route(_alert("A9"), _SEED).name == "kerberoast"
    assert llm.calls == 1


# ---------------- 记的是"路由的结果" ----------------
def test_LLM_答_none_时记住的是兜底_generic():
    """route() 对 none/未知名一律落 generic 兜底 —— memo 记的是**这个函数的返回**,
    不是模型说的那个词,否则复用出来的东西和当初实际用的不是一回事。"""
    st, llm = InMemoryRouteMemoStore(), _LLM("none")
    r = _router(llm, st)
    assert r.route(_alert("A1"), _SEED).name == "generic_identity"
    assert st.lookup(route_key(_alert(), _SEED)).skill == "generic_identity"


def test_advance_与_router_用的是同一套状态机():
    """★别在 router 里另写一份状态推进 —— 这条钉死它调的就是 route_memo.advance。"""
    m, act = advance(None, "k", "s", "A1")
    assert (m.status, act) == ("candidate", "created")
