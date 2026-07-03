"""cypher 渲染器 TDD:Mapping → 幂等 MERGE 语句(纯渲染,无 Neo4j 依赖)。"""
import pytest

from ingest.mapper import map_event
from ingest.models import Node, Edge, Mapping
from ingest.cypher import render_mapping


DOC_4769 = {
    "@timestamp": "2026-07-02T07:28:00.000Z",
    "winlog": {
        "channel": "Security", "event_id": "4769", "record_id": "700001",
        "computer_name": "winterfell.north.sevenkingdoms.local",
        "event_data": {
            "TargetUserName": "vagrant@NORTH.SEVENKINGDOMS.LOCAL",
            "ServiceName": "sql_svc",
            "ServiceSid": "S-1-5-21-1229275207-304159137-1120826147-1121",
            "TicketEncryptionType": "0x17", "TicketOptions": "0x40810000",
            "IpAddress": "::1", "Status": "0x0",
        },
    },
}


def _find(stmts, needle):
    return [s for s in stmts if needle in s.cypher]


def test_render_event_merges_by_uid_with_category_label():
    r = render_mapping(map_event(DOC_4769))
    ev = _find(r.statements, "MERGE (e:Event {event_uid:$uid})")
    assert len(ev) == 1
    s = ev[0]
    assert "SET e:Authentication" in s.cypher          # category 作第二 label,插值
    assert "e += $props" in s.cypher
    assert "coalesce(e.ingest_time, timestamp())" in s.cypher
    assert s.params["props"]["enc_type"] == "0x17"
    assert "event_uid" not in s.params["props"]        # 键不进 SET props


def test_render_object_has_first_and_last_seen():
    r = render_mapping(map_event(DOC_4769))
    acct = _find(r.statements, "MERGE (n:Account")
    assert acct, "应有 Account 的 MERGE"
    s = acct[0]
    assert "ON CREATE SET n += $props, n.first_seen = $et, n.last_seen = $et" in s.cypher
    assert "ON MATCH SET n += $props, n.last_seen = CASE WHEN $et > n.last_seen" in s.cypher


def test_render_edge_matches_both_ends_then_merges_rel():
    r = render_mapping(map_event(DOC_4769))
    actor = _find(r.statements, "[r:ACTOR]")
    assert len(actor) == 1
    s = actor[0]
    assert "MATCH (a:Event {event_uid:$s_event_uid})" in s.cypher
    assert "MATCH (b:Account" in s.cypher
    assert "MERGE (a)-[r:ACTOR]->(b)" in s.cypher


def test_null_key_node_and_its_edges_skipped():
    # sid=None 的 Account 不能落图(否则所有 null 账号塌一起),指向它的边也要跳
    ev = Node(("Event", "Authentication"), key={"event_uid": "u1"},
              props={"event_uid": "u1", "event_time": "T", "category": "authentication"})
    bad = Node(("Account",), key={"sid": None})
    m = Mapping(event=ev, nodes=[bad], edges=[Edge("ACTOR", ev, bad)])
    r = render_mapping(m)
    assert not _find(r.statements, "MERGE (n:Account")   # 空键节点没渲染
    assert not _find(r.statements, "[r:ACTOR]")          # 悬挂边也没渲染
    assert any("null_key" in x for x in r.skipped)


def test_invalid_object_label_raises():
    ev = Node(("Event", "Authentication"), key={"event_uid": "u1"}, props={"event_uid": "u1"})
    bogus = Node(("Bogus",), key={"x": "1"})
    with pytest.raises(ValueError):
        render_mapping(Mapping(event=ev, nodes=[bogus], edges=[]))


def test_invalid_edge_type_raises():
    ev = Node(("Event", "Authentication"), key={"event_uid": "u1"}, props={"event_uid": "u1"})
    h = Node(("Host",), key={"hostname": "x"})
    with pytest.raises(ValueError):
        render_mapping(Mapping(event=ev, nodes=[h], edges=[Edge("BOGUS_EDGE", ev, h)]))
