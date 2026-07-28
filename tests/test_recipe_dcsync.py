"""DCSync recipe 迁移(旧散装 dict → 结构化 Forensics)的 finding 抽取单测。

finding_id = 方法论(第一类,离线定);"哪些 finding→什么结论"的映射才是第二类(qwen 学)。
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


def _dcsync():
    return SkillRegistry(_SKILLS).by_name("dcsync").recipe


def test_dcsync_non_dc_user_get_changes_all_emits_red_findings_and_bindings():
    # 攻击态:普通用户账号 hacker(非机器、非DC)持复制权、properties 含 Get-Changes-All(1131f6ad)
    graph = FakeGraph([
        ("actor.sam AS actor_sam", [{"actor_sam": "hacker", "actor_domain": "NORTH", "actor_upn": "hacker@north",
                                     "actor_privileged": False,
                                     "properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                                     "access_mask": "0x100", "obj_guid": "obj-1",
                                     "event_host": "WINTERFELL", "event_host_is_dc": True}]),
        ("collect(DISTINCT g.name) AS groups", [{"privileged": False, "groups": []}]),
        ("d.dc AS dc_host", [{"domain_fqdn": "north.sevenkingdoms.local", "dc_host": "WINTERFELL"}]),
    ])
    a = Alert.from_node({"alert_uid": "d1", "technique_ids": ["T1003.006"]})
    fo = _dcsync()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "dcsync.replication_request" in ids             # 触发本身
    assert "dcsync.get_changes_all" in ids                 # properties 含 1131f6ad = 拉全量哈希
    assert "dcsync.actor_non_dc_user" in ids               # 非机器非DC账号 = 攻击强信号
    assert "dcsync.actor_is_dc" not in ids                 # hacker 短名 != WINTERFELL
    assert "dcsync.actor_is_machine" not in ids            # 非机器账号
    rr = next(f for f in fo.findings if f.finding_id == "dcsync.replication_request")
    assert rr.polarity == "neutral"
    assert rr.attrs["props_bucket"] == "get_changes_all"   # 决定性标量进 attrs
    nd = next(f for f in fo.findings if f.finding_id == "dcsync.actor_non_dc_user")
    assert nd.polarity == "red" and nd.attrs == {"actor_privileged": False}
    assert fo.bindings["account"] == "hacker"
    assert fo.bindings["account_domain"] == "NORTH"
    assert fo.bindings["domain"] == "north.sevenkingdoms.local"
    assert fo.bindings["host"] == "WINTERFELL"
    assert fo.context.get("发起者与对象")                   # prose 仍在(喂 LLM)


def test_dcsync_dc_machine_replication_is_benign_white():
    # 良性态:本域 DC 机器账号 DC02$ 常规复制(即便含 Get-Changes-All 也是 DC-to-DC 正常复制)
    graph = FakeGraph([
        ("actor.sam AS actor_sam", [{"actor_sam": "DC02$", "actor_domain": "NORTH", "actor_upn": None,
                                     "actor_privileged": True,
                                     "properties": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
                                     "access_mask": "0x100", "obj_guid": "obj-9",
                                     "event_host": "DC01", "event_host_is_dc": True}]),
        ("collect(DISTINCT g.name) AS groups", [{"privileged": True, "groups": ["Enterprise Domain Controllers"]}]),
        ("d.dc AS dc_host", [{"domain_fqdn": "north.sevenkingdoms.local", "dc_host": ["WINTERFELL", "DC02"]}]),
    ])
    a = Alert.from_node({"alert_uid": "d2", "technique_ids": ["T1003.006"]})
    fo = _dcsync()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "dcsync.actor_is_dc" in ids                     # DC02$ 短名命中本域 DC 列表 → DC-to-DC 正常复制
    assert "dcsync.actor_is_machine" in ids                # DC02$ = 机器账号
    assert "dcsync.actor_non_dc_user" not in ids           # 是 DC/机器,不触发攻击信号
    assert "dcsync.replication_request" in ids             # 触发仍在
    dc = next(f for f in fo.findings if f.finding_id == "dcsync.actor_is_dc")
    assert dc.polarity == "white" and dc.attrs == {}       # presence-only 让良性指纹泛化
    im = next(f for f in fo.findings if f.finding_id == "dcsync.actor_is_machine")
    assert im.polarity == "white" and im.attrs == {}
    assert fo.bindings["account"] == "DC02$"
    assert fo.bindings["account_domain"] == "NORTH"
    assert fo.bindings["host"] == "DC01"
    assert fo.context.get("域DC")                           # prose 仍在(喂 LLM)
