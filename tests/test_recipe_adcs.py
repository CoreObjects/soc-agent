"""adcs 迁移:结构化 Forensics/Finding 抽取(第二类经验层地基)。

finding_id 按 skill 命名空间 = 方法论(第一类,离线定);"哪些 finding→什么结论"的映射才是第二类(qwen 学)。
★ADCS 核心信号 = subject_dn 与请求者比对三态:True 自签(白)/ False 冒充(红)/ None(4886 缺 subject_dn)两不发。
"""
from pathlib import Path

from soc_agent.forensics import Forensics
from soc_agent.models import Alert
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    """按 Cypher 子串返回预置行,解耦调用顺序(子串须在各查询里唯一)。"""

    def __init__(self, table):
        self.table = table                       # list[(substr, rows)]

    def run_cypher(self, query, **params):
        for substr, rows in self.table:
            if substr in query:
                return rows
        return []


def _adcs():
    return SkillRegistry(_SKILLS).by_name("adcs").recipe


# ---------- ① 冒充态:subject≠requester → subject_mismatch(红),subject_self_enroll 不触发 ----------
def test_adcs_impersonation_emits_mismatch_red_and_binds():
    graph = FakeGraph([
        ("req.sam AS req_sam", [{
            "event_code": "4887", "attributes": "cdc:hacker-pc rmd:north.local", "request_id": "42",
            "subject_dn": "CN=administrator,CN=Users,DC=north,DC=sevenkingdoms,DC=local",
            "req_sam": "hacker2", "req_domain": "NORTH", "req_upn": "hacker2@north.local",
            "req_privileged": False, "ca": "north-CA", "ca_kind": "certificate_authority",
            "ca_host": "winterfell"}]),
        ("collect(DISTINCT g.name) AS groups", [{"privileged": False, "groups": []}]),
    ])
    a = Alert.from_node({"alert_uid": "adcs1", "technique_ids": ["T1649"]})
    fo = _adcs()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "adcs.cert_request" in ids                       # 触发本身(4887 签发)
    assert "adcs.subject_mismatch" in ids                   # 主体≠请求者 = 冒充(红)
    assert "adcs.subject_self_enroll" not in ids            # 非自签
    assert "adcs.requester_privileged" not in ids           # 请求者低权
    # cert_request 的决定性标量 event_code 进 attrs
    cr = next(f for f in fo.findings if f.finding_id == "adcs.cert_request")
    assert cr.attrs["event_code"] == "4887"
    # subject_mismatch presence-only:红、attrs 为空(subject_cn 走 bindings 不进 attrs)
    mm = next(f for f in fo.findings if f.finding_id == "adcs.subject_mismatch")
    assert mm.polarity == "red" and mm.attrs == {}
    # bindings:身份角色抽象登记 + CA 原值 + 主体
    assert fo.bindings["account"] == "hacker2"
    assert fo.bindings["account_domain"] == "NORTH"
    assert fo.bindings["ca"] == "north-CA"
    assert fo.bindings["subject_user"] == "administrator"
    # prose 仍在(喂 LLM)
    assert fo.context.get("请求者与CA")
    assert fo.context["主体与请求者比对"]["subject_matches_requester"] is False


# ---------- ② 自签态:subject==requester → subject_self_enroll(白),subject_mismatch 不触发 ----------
def test_adcs_self_enroll_emits_white_and_no_mismatch():
    graph = FakeGraph([
        ("req.sam AS req_sam", [{
            "event_code": "4887", "attributes": "cdc:robb-pc", "request_id": "7",
            "subject_dn": "CN=robb.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local",
            "req_sam": "robb.stark", "req_domain": "NORTH", "req_upn": "robb.stark@north.local",
            "req_privileged": False, "ca": "north-CA", "ca_kind": "certificate_authority",
            "ca_host": "winterfell"}]),
        ("collect(DISTINCT g.name) AS groups", [{"privileged": False, "groups": []}]),
    ])
    a = Alert.from_node({"alert_uid": "adcs2", "technique_ids": ["T1649"]})
    fo = _adcs()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "adcs.cert_request" in ids
    assert "adcs.subject_self_enroll" in ids                # 主体==请求者 = 自签(白)
    assert "adcs.subject_mismatch" not in ids               # 无冒充
    se = next(f for f in fo.findings if f.finding_id == "adcs.subject_self_enroll")
    assert se.polarity == "white" and se.attrs == {}
    assert fo.bindings["account"] == "robb.stark"
    assert fo.bindings["subject_user"] == "robb.stark"
    assert fo.context["主体与请求者比对"]["subject_matches_requester"] is True


# ---------- ③ 请求阶段(4886,subject_dn 缺失):三态 None → 两个 subject finding 都不发;特权请求者 ----------
def test_adcs_request_stage_missing_subject_is_neither_and_privileged():
    graph = FakeGraph([
        ("req.sam AS req_sam", [{
            "event_code": "4886", "attributes": "cdc:dc01 rmd:north.local", "request_id": "99",
            "subject_dn": None,
            "req_sam": "administrator", "req_domain": "NORTH", "req_upn": "administrator@north.local",
            "req_privileged": True, "ca": "north-CA", "ca_kind": "certificate_authority",
            "ca_host": "winterfell"}]),
        ("collect(DISTINCT g.name) AS groups", [{"privileged": True, "groups": ["Domain Admins"]}]),
    ])
    a = Alert.from_node({"alert_uid": "adcs3", "technique_ids": ["T1649"]})
    fo = _adcs()(graph, a, {})
    ids = fo.finding_ids()
    assert "adcs.cert_request" in ids                       # 4886 请求
    assert "adcs.subject_mismatch" not in ids               # subject_dn 缺 → 三态 None
    assert "adcs.subject_self_enroll" not in ids            # 两个都不发
    assert "adcs.requester_privileged" in ids               # 特权请求者(上下文,neutral)
    rp = next(f for f in fo.findings if f.finding_id == "adcs.requester_privileged")
    assert rp.polarity == "neutral"
    cr = next(f for f in fo.findings if f.finding_id == "adcs.cert_request")
    assert cr.attrs["event_code"] == "4886"
    assert "subject_user" not in fo.bindings                # subject_dn 缺 → 无主体绑定
    assert fo.context["主体与请求者比对"]["subject_matches_requester"] is None


# ---------- 空图:不崩、可归一为 Forensics、无 finding ----------
def test_adcs_empty_graph_is_safe():
    class _G:
        def run_cypher(self, q, **p):
            return []

    a = Alert.from_node({"alert_uid": "adcs0", "technique_ids": ["T1649"]})
    fo = _adcs()(_G(), a, {})
    assert isinstance(fo, Forensics)
    assert fo.finding_ids() == set()
    assert fo.bindings == {}
