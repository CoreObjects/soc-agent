"""取证结构化契约(Finding/Forensics)+ 两个先行 recipe 的 finding 抽取(第二类经验层地基)。

finding_id 按 skill 命名空间 = 方法论(第一类,离线定);"哪些 finding→什么结论"的映射才是第二类(qwen 学)。
"""
from pathlib import Path

import pytest

from soc_agent.forensics import Finding, Forensics
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


# ---------- 模型 ----------
def test_finding_roundtrip():
    f = Finding("kerberoast.rc4_requested", {"enc_type": "0x17"}, evidence_ref="e1", polarity="red")
    assert Finding.from_dict(f.to_dict()) == f


def test_forensics_from_legacy_wraps_prose_and_extracts_blind_spots():
    d = {"步骤A": [{"x": 1}], "步骤B": "文本", "_图盲区": "看不到签名"}
    fo = Forensics.from_legacy(d)
    assert fo.findings == [] and fo.bindings == {}
    assert fo.context == {"步骤A": [{"x": 1}], "步骤B": "文本"}     # _图盲区 抽出 context
    assert fo.blind_spots == "看不到签名"


def test_forensics_coerce():
    fo = Forensics(findings=[Finding("x.y")])
    assert Forensics.coerce(fo) is fo                              # Forensics 原样
    assert Forensics.coerce(None).findings == []                  # None → 空
    assert Forensics.coerce({"a": 1}).context == {"a": 1}         # dict → legacy
    with pytest.raises(TypeError):
        Forensics.coerce(123)


def test_forensics_finding_ids_dedup():
    fo = Forensics(findings=[Finding("a.b"), Finding("a.c"), Finding("a.b")])
    assert fo.finding_ids() == {"a.b", "a.c"}


# ---------- kerberoast 迁移:finding 抽取 ----------
def _kerberoast():
    return SkillRegistry(_SKILLS).by_name("kerberoast").recipe


def test_kerberoast_user_roast_emits_red_findings_and_bindings():
    graph = FakeGraph([
        ("req.sam AS req_sam", [{"req_sam": "hacker2", "req_domain": "NORTH", "req_type": "user",
                                 "req_privileged": False, "tgt_sam": "sql_svc", "tgt_domain": "NORTH",
                                 "enc_type": "0x17", "ticket_options": "0x40810000"}]),
        ("collect(DISTINCT g.name) AS groups", [{"privileged": True, "spn": "MSSQL/db", "groups": ["Domain Admins"]}]),
        ("ORDER BY n DESC", [{"enc": "0x17", "n": 30}]),
        ("[:TRUSTS]", [{"req_domain_fqdn": "north.sevenkingdoms.local", "trusts": ["sevenkingdoms.local"]}]),
        ("distinct_targets", [{"distinct_targets": 12, "total_4769": 40}]),
    ])
    a = Alert.from_node({"alert_uid": "k1", "technique_ids": ["T1558.003"]})
    fo = _kerberoast()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "kerberoast.rc4_requested" in ids               # 0x17 = RC4
    assert "kerberoast.target_high_value" in ids           # privileged 目标
    assert "kerberoast.spn_fanout" in ids                  # 12 个目标
    assert "kerberoast.requester_is_machine" not in ids    # 普通用户
    assert "kerberoast.cross_domain" not in ids            # 同域
    assert fo.bindings["attacker_account"] == "hacker2"
    assert fo.bindings["attacker_account_domain"] == "NORTH"
    assert fo.bindings["target_account"] == "sql_svc"
    assert fo.context.get("请求与目标")                     # prose 仍在(喂 LLM)


def test_kerberoast_machine_cross_domain_emits_white_findings():
    graph = FakeGraph([
        ("req.sam AS req_sam", [{"req_sam": "DC01$", "req_domain": "NORTH", "req_type": "machine",
                                 "req_privileged": True, "tgt_sam": "svc", "tgt_domain": "ESSOS",
                                 "enc_type": "0x17", "ticket_options": "0x40810000"}]),
        ("[:TRUSTS]", [{"req_domain_fqdn": "north.x.local", "trusts": ["essos.x.local"]}]),
        ("distinct_targets", [{"distinct_targets": 1, "total_4769": 1}]),
    ])
    a = Alert.from_node({"alert_uid": "k2", "technique_ids": ["T1558.003"]})
    fo = _kerberoast()(graph, a, {})
    ids = fo.finding_ids()
    assert "kerberoast.requester_is_machine" in ids        # DC01$ 机器账号
    assert "kerberoast.cross_domain" in ids                # NORTH != ESSOS
    assert fo.bindings["attacker_account"] == "DC01$"


# ---------- lsass 迁移:finding 抽取 ----------
def _lsass():
    return SkillRegistry(_SKILLS).by_name("lsass_dump").recipe


def test_lsass_security_agent_emits_white_finding_with_raw_image():
    graph = FakeGraph([
        ("src.image AS src_image", [{"src_guid": "g1", "src_image": r"C:\Program Files\Wazuh\wazuh-agent.exe",
                                     "src_cmdline": "-x", "target_image": "lsass.exe", "granted_access": "0x1410",
                                     "call_trace": "ntdll.dll|wazuh.dll", "host": "SRV02",
                                     "host_role": None, "host_criticality": None}]),
        ("acc.sam AS sam", [{"sam": "SYSTEM", "domain": "NORTH", "privileged": True}]),
        ("AS out_ips", [{"out_ips": [], "spawned": [], "wrote_files": []}]),
        ("gp.image AS grandparent", [{"grandparent": "services.exe", "parent": "wazuh-agent.exe", "parent_cmdline": "-x"}]),
    ])
    a = Alert.from_node({"alert_uid": "l1", "technique_ids": ["T1003.001"]})
    fo = _lsass()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "lsass.lsass_accessed" in ids
    assert "lsass.source_is_security_agent" in ids
    assert "lsass.dump_lib_loaded" not in ids              # 无转储库
    assert fo.bindings["victim_host"] == "SRV02"
    sa = next(f for f in fo.findings if f.finding_id == "lsass.source_is_security_agent")
    assert "wazuh-agent.exe" in (sa.attrs.get("src_image") or "")   # 原始进程名进 attrs(可移植指纹 key)


def test_lsass_dump_tool_emits_red_findings():
    graph = FakeGraph([
        ("src.image AS src_image", [{"src_guid": "g2", "src_image": r"C:\Temp\mimikatz.exe",
                                     "src_cmdline": "sekurlsa", "target_image": "lsass.exe", "granted_access": "0x1410",
                                     "call_trace": "ntdll.dll|dbghelp.dll", "host": "WIN10",
                                     "host_role": None, "host_criticality": None}]),
        ("acc.sam AS sam", [{"sam": "admin", "domain": "NORTH", "privileged": True}]),
        ("AS out_ips", [{"out_ips": ["8.8.8.8"], "spawned": [], "wrote_files": [r"C:\Temp\dump.bin"]}]),
        ("gp.image AS grandparent", [{"grandparent": "explorer.exe", "parent": "cmd.exe", "parent_cmdline": "x"}]),
    ])
    a = Alert.from_node({"alert_uid": "l2", "technique_ids": ["T1003.001"]})
    fo = _lsass()(graph, a, {})
    ids = fo.finding_ids()
    assert "lsass.dump_lib_loaded" in ids                  # dbghelp
    assert "lsass.post_read_exfil" in ids                  # 外连 + 落盘
    assert "lsass.source_is_security_agent" not in ids


# ---------- lateral_movement 迁移:finding 抽取 ----------
def _lateral():
    return SkillRegistry(_SKILLS).by_name("lateral_movement").recipe


def test_lateral_benign_repeat_logon_emits_white_and_binds():
    # robb.stark 型良性:type3 网络登录、普通账号、成员机、有基线、低扇出
    graph = FakeGraph([
        ("AS target_host", [{"event_code": "4624", "logon_type": 3, "result": "success",
                             "acc_sam": "robb.stark", "acc_domain": "NORTH", "acc_privileged": False,
                             "target_host": "castelblack", "target_role": "member_server",
                             "target_criticality": "medium", "src_ip": "192.168.56.20"}]),
        # 基线存在性=AUTHENTICATED_TO 边存在(有 first_seen);次数从 4624 事件读(不读恒 null 的 r.count)
        ("r.first_seen AS first_seen", [{"first_seen": "2026-06-01", "last_seen": "2026-07-20"}]),
        ("AS logins", [{"logins": 42}]),
        ("distinct_hosts", [{"distinct_hosts": 2}]),
    ])
    a = Alert.from_node({"alert_uid": "lm1", "technique_ids": ["T1021.001"]})
    fo = _lateral()(graph, a, {})
    assert isinstance(fo, Forensics)
    ids = fo.finding_ids()
    assert "lateral.network_logon" in ids                  # 触发本身
    assert "lateral.host_baseline_present" in ids          # 有基线 = 良性信号(white)
    assert "lateral.no_host_baseline" not in ids
    assert "lateral.privileged_account" not in ids         # 普通账号
    assert "lateral.high_value_target" not in ids          # 成员机、非关键
    fan = next(f for f in fo.findings if f.finding_id == "lateral.fanout")
    assert fan.polarity == "neutral" and fan.attrs["distinct_hosts"] == 2   # 扇出 2 = 不 red
    assert fo.bindings["account"] == "robb.stark"
    assert fo.bindings["account_domain"] == "NORTH"
    assert fo.bindings["target_host"] == "castelblack"
    assert fo.bindings["src_ip"] == "192.168.56.20"
    assert fo.context.get("登录事件")                       # prose 仍在(喂 LLM)


def test_lateral_attack_first_seen_privileged_fanout_dc():
    # 攻击型:首见(无基线)+ 特权账号 + 扇出 12 + 登域控
    graph = FakeGraph([
        ("AS target_host", [{"event_code": "4624", "logon_type": 3, "result": "success",
                             "acc_sam": "administrator", "acc_domain": "NORTH", "acc_privileged": True,
                             "target_host": "winterfell", "target_role": "domain_controller",
                             "target_criticality": "critical", "src_ip": "10.0.0.9"}]),
        # 无 "r.count AS count" 行 → 基线查询返回 [] → 首见
        ("distinct_hosts", [{"distinct_hosts": 12}]),
    ])
    a = Alert.from_node({"alert_uid": "lm2", "technique_ids": ["T1021.001"]})
    fo = _lateral()(graph, a, {})
    ids = fo.finding_ids()
    assert "lateral.network_logon" in ids
    assert "lateral.no_host_baseline" in ids               # 无基线 = 首见(red)
    assert "lateral.host_baseline_present" not in ids
    assert "lateral.privileged_account" in ids             # 特权账号
    assert "lateral.high_value_target" in ids              # 登域控
    fan = next(f for f in fo.findings if f.finding_id == "lateral.fanout")
    assert fan.polarity == "red" and fan.attrs["distinct_hosts"] == 12    # 12 台 = red
    assert fo.bindings["account"] == "administrator"
    assert fo.bindings["target_host"] == "winterfell"
