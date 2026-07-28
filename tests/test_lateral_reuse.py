"""闭环验证:lateral_movement 迁移后,良性登录判 FP → 蒸出 benign 指纹 →
第二条同型(不同账号/主机)告警被指纹命中 → consult 出 AUTO_FP(零 LLM 复用)。

这是"迁移让经验复用真正生效"的直接证据(迁移前 findings=[],这一切都做不了)。
"""
from pathlib import Path

from soc_agent.experience.consult import consult
from soc_agent.experience.distill import DISTILL, distill
from soc_agent.experience.matching import fingerprint_hit
from soc_agent.experience.store import InMemoryExperienceStore
from soc_agent.llm import FakeLLMClient, LLMResponse, ToolCall
from soc_agent.models import Alert, Verdict
from soc_agent.skills_runtime import SkillRegistry

_SKILLS = Path(__file__).resolve().parents[1] / "skills"


class FakeGraph:
    def __init__(self, table):
        self.table = table

    def run_cypher(self, query, **p):
        for sub, rows in self.table:
            if sub in query:
                return rows
        return []


class _Skill:
    name = "lateral_movement"
    methodology = "先看账号↔主机基线→权限→扇出→目标价值"


def _recipe():
    return SkillRegistry(_SKILLS).by_name("lateral_movement").recipe


def _benign_logon_graph(account, host, count):
    # 普通账号 type3 网络登录成员机、有基线、低扇出 —— 良性型
    return FakeGraph([
        ("AS target_host", [{"event_code": "4624", "logon_type": 3, "result": "success",
                             "acc_sam": account, "acc_domain": "NORTH", "acc_privileged": False,
                             "target_host": host, "target_role": "member_server",
                             "target_criticality": "medium", "src_ip": "192.168.56.20"}]),
        ("r.count AS count", [{"count": count, "first_seen": "2026-06-01", "last_seen": "2026-07-20"}]),
        ("distinct_hosts", [{"distinct_hosts": 3}]),
    ])


def _distill_llm(ids):
    return FakeLLMClient([LLMResponse(tool_calls=[ToolCall(
        id="1", name=DISTILL,
        arguments={"decisive_finding_ids": ids, "note": "普通账号对成员机的常态网络登录(有基线)"})])])


def test_lateral_benign_sediments_then_second_reuses_auto_fp():
    recipe = _recipe()

    # 第 1 条 robb.stark→castelblack:LLM 判 FP → 蒸出 benign 指纹
    a1 = Alert.from_node({"alert_uid": "lm-a", "technique_ids": ["T1021.001"]})
    fo1 = recipe(_benign_logon_graph("robb.stark", "castelblack", 42), a1, {})
    assert "lateral.network_logon" in fo1.finding_ids()          # 迁移后确实产 findings(迁移前为 [])
    v = Verdict(verdict="false_positive", confidence=0.9, rationale="普通账号常态登录", agent="q")
    exp = distill(_distill_llm(["lateral.network_logon", "lateral.host_baseline_present"]),
                  _Skill(), fo1.findings, fo1.bindings, v, agent_name="q", origin_case_id="lm-a")
    assert exp is not None and exp.kind == "benign_fp" and exp.skill == "lateral_movement"

    store = InMemoryExperienceStore()
    store.add(exp)

    # 第 2 条 jon.snow→riverrun(不同账号/主机、不同基线次数,但同型):指纹命中 → AUTO_FP
    a2 = Alert.from_node({"alert_uid": "lm-b", "technique_ids": ["T1021.001"]})
    fo2 = recipe(_benign_logon_graph("jon.snow", "riverrun", 10), a2, {})
    hit, score, matched = fingerprint_hit(exp, fo2.findings)
    assert hit, f"benign 指纹应命中同型第二条(score={score}, matched={matched})"

    report = consult("lateral_movement", fo2.findings, store)
    assert report.decision == "AUTO_FP"        # ★复用:第二条零 LLM 直接判 FP(path=A)
    assert report.chosen is exp


def test_lateral_attack_does_not_reuse_benign_fingerprint():
    """负向:攻击型(首见+特权+登DC)不该命中良性指纹 → 仍 FALLTHROUGH(交 LLM),不误复用成 FP。"""
    recipe = _recipe()
    a1 = Alert.from_node({"alert_uid": "lm-a", "technique_ids": ["T1021.001"]})
    fo1 = recipe(_benign_logon_graph("robb.stark", "castelblack", 42), a1, {})
    v = Verdict(verdict="false_positive", confidence=0.9, rationale="常态", agent="q")
    exp = distill(_distill_llm(["lateral.network_logon", "lateral.host_baseline_present"]),
                  _Skill(), fo1.findings, fo1.bindings, v)
    store = InMemoryExperienceStore()
    store.add(exp)

    # 攻击型:administrator 首见登域控 winterfell,扇出 12
    attack_graph = FakeGraph([
        ("AS target_host", [{"event_code": "4624", "logon_type": 3, "result": "success",
                             "acc_sam": "administrator", "acc_domain": "NORTH", "acc_privileged": True,
                             "target_host": "winterfell", "target_role": "domain_controller",
                             "target_criticality": "critical", "src_ip": "10.0.0.9"}]),
        ("distinct_hosts", [{"distinct_hosts": 12}]),
    ])
    a2 = Alert.from_node({"alert_uid": "lm-c", "technique_ids": ["T1021.001"]})
    fo2 = recipe(attack_graph, a2, {})
    report = consult("lateral_movement", fo2.findings, store)
    assert report.decision == "FALLTHROUGH"    # 攻击型不被良性指纹误吞,老老实实交 LLM
