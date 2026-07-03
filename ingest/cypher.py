"""Mapping → 幂等 MERGE Cypher 语句(纯渲染,无 Neo4j 驱动依赖,离线可测)。

规则(见 plan / graph_model v1.1):
- Event:MERGE by event_uid,category 作第二 label(插值),SET += 信封+叶子+raw_ref,ingest_time coalesce。
- 对象:MERGE by 强键,first_seen/last_seen 走 ON CREATE/ON MATCH(last_seen 只增)。
- 边:MATCH 两端(按各自主 label + 键)后 MERGE 关系;RELATED_TO 才带属性。
- 二级 label / 关系类型不能参数化 → 插值前用白名单校验(防注入 + 防漂移)。
- null 键守卫:任一键值为 None → 跳过该节点及关联边,记 skipped。
"""
from dataclasses import dataclass

from .models import Mapping, Node

# 白名单(与 graph_model.json 保持一致;改模型记得同步)
OBJECT_LABELS = frozenset({
    "Host", "Account", "Process", "File", "RegistryKey", "Ticket", "LogonSession",
    "IPAddress", "Domain", "Uri", "Service", "Application", "DirectoryObject",
})
CATEGORY_LABELS = frozenset({
    "Authentication", "Directory", "Certificate", "Process", "File", "Registry",
    "Network", "Dns", "Web", "Script", "LogManagement",
})
ROLE_EDGES = frozenset({"ON_HOST", "ACTOR", "TARGET", "PRODUCES", "FROM", "TO", "USES", "RELATED_TO"})
STRUCT_EDGES = frozenset({"PARENT_OF", "RAN_AS", "HAS_IP", "BELONGS_TO",
                          "FOR_SERVICE", "AUTHENTICATED_AS", "RESOLVES_TO"})
EDGE_TYPES = ROLE_EDGES | STRUCT_EDGES


@dataclass
class Statement:
    cypher: str
    params: dict


@dataclass
class RenderResult:
    statements: list
    skipped: list          # 原因串,如 "null_key:Account" / "edge_dangling:ACTOR"


def _validate(label: str, allowed: frozenset, kind: str):
    if label not in allowed:
        raise ValueError(f"未知 {kind}: {label!r}(不在白名单,防注入/防拼写漂移)")


def _has_null_key(n: Node) -> bool:
    return (not n.key) or any(v is None for v in n.key.values())


def _key_clause(key: dict, prefix: str):
    """{field:$prefixfield, ...} + 参数字典(字段排序保证确定性)。"""
    parts, params = [], {}
    for field, val in sorted(key.items()):
        p = prefix + field
        parts.append(f"{field}:${p}")
        params[p] = val
    return "{" + ", ".join(parts) + "}", params


def _render_event(ev: Node) -> Statement:
    set_label = ""
    if len(ev.labels) > 1:
        _validate(ev.labels[1], CATEGORY_LABELS, "category label")
        set_label = f"e:{ev.labels[1]}, "
    props = {k: v for k, v in ev.props.items() if k != "event_uid"}
    cypher = (
        "MERGE (e:Event {event_uid:$uid}) "
        f"SET {set_label}e += $props, "
        "e.ingest_time = coalesce(e.ingest_time, timestamp())"
    )
    return Statement(cypher, {"uid": ev.key["event_uid"], "props": props})


def _render_object(n: Node, et) -> Statement:
    label = n.labels[0]
    _validate(label, OBJECT_LABELS, "object label")
    clause, keyparams = _key_clause(n.key, "k_")
    props = {k: v for k, v in n.props.items() if k not in n.key}
    cypher = (
        f"MERGE (n:{label} {clause}) "
        "ON CREATE SET n += $props, n.first_seen = $et, n.last_seen = $et "
        "ON MATCH SET n += $props, n.last_seen = CASE WHEN $et > n.last_seen THEN $et ELSE n.last_seen END"
    )
    return Statement(cypher, {**keyparams, "props": props, "et": et})


def _render_edge(e) -> Statement:
    sclause, sparams = _key_clause(e.src.key, "s_")
    dclause, dparams = _key_clause(e.dst.key, "d_")
    cypher = (
        f"MATCH (a:{e.src.labels[0]} {sclause}) "
        f"MATCH (b:{e.dst.labels[0]} {dclause}) "
        f"MERGE (a)-[r:{e.type}]->(b)"
    )
    params = {**sparams, **dparams}
    if e.props:
        cypher += " ON CREATE SET r += $eprops ON MATCH SET r += $eprops"
        params["eprops"] = e.props
    return Statement(cypher, params)


def render_mapping(m: Mapping) -> RenderResult:
    """一个 Mapping → 一批 (cypher, params) 语句(同事务顺序执行:Event→对象→边)。"""
    stmts, skipped = [], []
    et = m.event.props.get("event_time")

    stmts.append(_render_event(m.event))
    valid = {id(m.event)}

    for n in m.nodes:
        if _has_null_key(n):
            skipped.append(f"null_key:{n.labels[0]}")
            continue
        stmts.append(_render_object(n, et))
        valid.add(id(n))

    for e in m.edges:
        if e.type not in EDGE_TYPES:
            raise ValueError(f"未知 edge type: {e.type!r}(不在角色边/结构边白名单)")
        if id(e.src) not in valid or id(e.dst) not in valid:
            skipped.append(f"edge_dangling:{e.type}")   # 端点被 null 键跳过 → 悬挂边也跳
            continue
        stmts.append(_render_edge(e))

    return RenderResult(stmts, skipped)
