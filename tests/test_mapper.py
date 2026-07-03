"""接入层映射器 TDD。夹具取自 44-es-survey / 41-kerberoast 真实事件样本。"""
import pytest

from ingest.mapper import event_uid, map_event


def _edges(m, t):
    return [e for e in m.edges if e.type == t]


# ============ event_uid：优先 record_id;缺则兜底 event_time+raw_hash ============

def test_event_uid_primary_deterministic_and_ignores_event_time():
    a = event_uid(source="winlogbeat", sensor="Security", record_id="12345",
                  event_time="2026-07-02T08:00:00Z")
    b = event_uid(source="winlogbeat", sensor="Security", record_id="12345",
                  event_time="1999-01-01T00:00:00Z")
    assert a == b, "record_id 在场时 event_time 不得影响 uid"
    c = event_uid(source="winlogbeat", sensor="Security", record_id="99999")
    assert a != c, "record_id 变了 uid 必须变"


def test_event_uid_fallback_uses_event_time_and_raw_when_no_record_id():
    a = event_uid(source="filebeat", sensor="ModSecurity", event_time="T1", raw="body1")
    b = event_uid(source="filebeat", sensor="ModSecurity", event_time="T1", raw="body2")
    c = event_uid(source="filebeat", sensor="ModSecurity", event_time="T2", raw="body1")
    assert a != b, "raw 变 → uid 变"
    assert a != c, "event_time 变 → uid 变(仅兜底分支)"


def test_event_uid_requires_record_id_or_raw():
    with pytest.raises(ValueError):
        event_uid(source="x", sensor="y")


def test_event_uid_includes_host_so_same_record_id_on_different_hosts_differ():
    # winlog.record_id 是"每主机每通道"计数器,跨主机会撞。同 record_id 不同观测主机
    # = 不同事件,uid 必须不同(否则 Neo4j MERGE by event_uid 会把三台 DC 的同号事件塌成一个)。
    a = event_uid(source="winlogbeat", sensor="Security", record_id="700001", host="dc01")
    b = event_uid(source="winlogbeat", sensor="Security", record_id="700001", host="dc02")
    assert a != b, "同 record_id 不同主机必须产不同 uid"
    # 同主机同 record_id 仍确定性一致
    assert a == event_uid(source="winlogbeat", sensor="Security", record_id="700001", host="dc01")


# ============ 4769 Kerberoast → authentication·service_ticket ============

DOC_4769_ROAST = {
    "@timestamp": "2026-07-02T07:28:00.000Z",
    "winlog": {
        "channel": "Security",
        "event_id": "4769",
        "record_id": "700001",
        "computer_name": "winterfell.north.sevenkingdoms.local",
        "event_data": {
            "TargetUserName": "vagrant@NORTH.SEVENKINGDOMS.LOCAL",
            "ServiceName": "sql_svc",
            "ServiceSid": "S-1-5-21-1229275207-304159137-1120826147-1121",
            "TicketEncryptionType": "0x17",
            "TicketOptions": "0x40810000",
            "IpAddress": "::1",
            "Status": "0x0",
            "LogonGuid": "{bbf6e39c-93db-cc9b-b27b-981608c531f5}",
            "TargetDomainName": "NORTH.SEVENKINGDOMS.LOCAL",
        },
    },
}


def test_map_4769_event_envelope():
    m = map_event(DOC_4769_ROAST)
    assert m.event.labels == ("Event", "Authentication")
    p = m.event.props
    assert p["category"] == "authentication"
    assert p["action"] == "service_ticket"
    assert p["outcome"] == "success"          # Status 0x0
    assert p["event_code"] == "4769"
    assert p["source"] == "winlogbeat"
    assert p["enc_type"] == "0x17"            # RC4 = roast 信号
    assert p["ticket_options"] == "0x40810000"
    assert p["weak_link"] is False
    assert m.event.key["event_uid"] == event_uid(
        source="winlogbeat", sensor="Security", record_id="700001",
        host="winterfell.north.sevenkingdoms.local")


def test_map_4769_roles():
    m = map_event(DOC_4769_ROAST)
    # 所有角色边都从 Event 出(Event→Object)
    for e in m.edges:
        assert e.src is m.event
    # ACTOR → 请求者(UPN 形)
    actor = _edges(m, "ACTOR")
    assert len(actor) == 1
    assert actor[0].dst.key.get("upn") == "vagrant@NORTH.SEVENKINGDOMS.LOCAL"
    # TARGET → 被 roast 的服务账号(SID 键 + SAM)
    target = _edges(m, "TARGET")
    assert len(target) == 1
    assert target[0].dst.key.get("sid") == "S-1-5-21-1229275207-304159137-1120826147-1121"
    assert target[0].dst.props.get("sam") == "sql_svc"
    # FROM → 来源 IP
    frm = _edges(m, "FROM")
    assert len(frm) == 1 and frm[0].dst.key.get("ip") == "::1"
    # ON_HOST → 观测主机(≠攻击目标)
    onhost = _edges(m, "ON_HOST")
    assert len(onhost) == 1
    assert onhost[0].dst.key.get("hostname") == "winterfell.north.sevenkingdoms.local"


# ============ Sysmon EID1 进程创建 → process·create + 对象结构边 ============

DOC_EID1 = {
    "@timestamp": "2026-07-02T08:30:49.450Z",
    "winlog": {
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "1",
        "record_id": "800001",
        "computer_name": "winterfell.north.sevenkingdoms.local",
        "event_data": {
            "User": "NORTH\\robb.stark",
            "ProcessGuid": "{0d573dc4-21b9-6a46-2b73-000000000e00}",
            "ProcessId": "3140",
            "Image": "C:\\Windows\\System32\\mstsc.exe",
            "CommandLine": "C:\\Windows\\system32\\mstsc.exe /v:castelblack",
            "IntegrityLevel": "High",
            "Hashes": "MD5=FECC,SHA256=D7A69C4398AC1BE41F44477F58C9619D43A1C363D4833C32610AC848B269EDF0",
            "ParentProcessGuid": "{0d573dc4-21b8-6a46-2873-000000000e00}",
            "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentCommandLine": "powershell  c:\\setup\\bot_rdp.ps1",
            "LogonGuid": "{0d573dc4-21b8-6a46-6c3c-2e0400000000}",
        },
    },
}


def test_map_eid1_event():
    m = map_event(DOC_EID1)
    assert m.event.labels == ("Event", "Process")
    assert m.event.props["category"] == "process"
    assert m.event.props["action"] == "create"
    assert m.event.props["command_line"].endswith("/v:castelblack")


def test_map_eid1_produces_child_process():
    m = map_event(DOC_EID1)
    prod = _edges(m, "PRODUCES")
    assert len(prod) == 1
    child = prod[0].dst
    assert child.labels == ("Process",)
    assert child.key["process_guid"] == "{0d573dc4-21b9-6a46-2b73-000000000e00}"
    assert child.props.get("image", "").endswith("mstsc.exe")


def test_map_eid1_structural_edges():
    m = map_event(DOC_EID1)
    child = _edges(m, "PRODUCES")[0].dst
    # PARENT_OF: 父 → 子(对象结构边)
    parent_of = _edges(m, "PARENT_OF")
    assert len(parent_of) == 1
    assert parent_of[0].dst is child
    assert parent_of[0].src.key["process_guid"] == "{0d573dc4-21b8-6a46-2873-000000000e00}"
    # RAN_AS: 子 → Account(User，域\\用户 拆键)
    ran_as = _edges(m, "RAN_AS")
    assert len(ran_as) == 1 and ran_as[0].src is child
    assert ran_as[0].dst.key.get("sam") == "robb.stark"
    assert ran_as[0].dst.props.get("domain") == "NORTH"
    # 子进程 ON_HOST → Host(结构边,src 是子进程而非 Event)
    child_onhost = [e for e in m.edges if e.type == "ON_HOST" and e.src is child]
    assert len(child_onhost) == 1
    assert child_onhost[0].dst.key["hostname"] == "winterfell.north.sevenkingdoms.local"


def test_map_eid1_actor():
    m = map_event(DOC_EID1)
    actor = _edges(m, "ACTOR")
    assert len(actor) == 1 and actor[0].src is m.event
    assert actor[0].dst.key.get("sam") == "robb.stark"


# ---- raw_ref 线程化:Event 带"回 ES 取全文"的指针(index:_id) ----

def test_map_event_threads_raw_ref_onto_event():
    m = map_event(DOC_4769_ROAST, raw_ref="winlogbeat-7.17.22-2026.07.02:AbC123")
    assert m.event.props["raw_ref"] == "winlogbeat-7.17.22-2026.07.02:AbC123"


def test_map_event_without_raw_ref_absent():
    m = map_event(DOC_4769_ROAST)
    assert m.event.props.get("raw_ref") is None
