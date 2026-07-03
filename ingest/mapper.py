"""事件 → 图元素 映射器（graph_model v1.1）。

落地规范见 docs/data-ingestion/ingest-mapping-spec.md。纯逻辑,不依赖 ES/Neo4j。
所有观测事件 → 单一 :Event 超类 + category 第二 label + 8 条通用角色边(Event→Object)。
"""
import hashlib
from dataclasses import dataclass

from .models import Node, Edge, Mapping


# ---------------------------------------------------------------- event_uid

def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_uid(*, source: str, sensor: str, record_id=None, host=None,
              event_time=None, raw=None) -> str:
    """事件唯一标识(强键)。

    优先: hash(source + host + sensor + native_record_id)
        —— Windows: host=winlog.computer_name, native=winlog.record_id
           (record_id 是"每主机每通道"计数器,不含 host 会跨主机撞→MERGE 塌图)
        —— WAF: native=transaction.unique_id(本就全局唯一,host 可空)
    兜底: hash(source + host + sensor + event_time + raw_hash) —— 无原生记录号时;不强依赖 event_time
    """
    if record_id is not None:
        return _sha("|".join([source, host or "", sensor, str(record_id)]))
    if raw is not None:
        return _sha("|".join([source, host or "", sensor, str(event_time or ""), _sha(str(raw))]))
    raise ValueError("event_uid 需要 record_id(优先)或 raw(兜底)")


# ---------------------------------------------------------------- 辅助

def _label(category: str) -> str:
    """category → 第二 label(如 log_management → LogManagement)。"""
    return "".join(p.capitalize() for p in category.split("_"))


def _win_outcome(ed: dict):
    st = ed.get("Status")
    if st is None:
        return None
    return "success" if st == "0x0" else "fail"


def _account_from_name(name):
    """账号名 → Account 节点(UPN / SID / 域\\用户 / SAM 择键)。"""
    if not name or name == "-":
        return None
    if "@" in name:
        return Node(("Account",), key={"upn": name})
    if name.startswith("S-1-"):
        return Node(("Account",), key={"sid": name})
    if "\\" in name:
        dom, sam = name.split("\\", 1)
        return Node(("Account",), key={"sam": sam}, props={"domain": dom})
    return Node(("Account",), key={"sam": name})


def _host_of(nodes):
    """取 _base_event 已建的 Host 节点(复用,勿重建)。"""
    for n in nodes:
        if n.labels == ("Host",):
            return n
    return None


@dataclass
class _Ctx:
    source: str
    sensor: str
    code: str
    ed: dict
    computer: str
    record_id: object = None
    event_time: object = None
    raw: object = None


def _base_event(ctx: _Ctx, category: str, action: str,
                outcome=None, weak_link=False, leaf=None):
    """建 :Event 节点 + ON_HOST 边(所有事件共有)。返回 (event, nodes, edges)。"""
    uid = event_uid(source=ctx.source, sensor=ctx.sensor, record_id=ctx.record_id,
                    host=ctx.computer, event_time=ctx.event_time, raw=ctx.raw)
    props = {
        "event_uid": uid, "event_time": ctx.event_time, "source": ctx.source,
        "sensor": ctx.sensor, "event_code": ctx.code, "category": category,
        "action": action, "weak_link": weak_link,
    }
    if outcome is not None:
        props["outcome"] = outcome
    if leaf:
        props.update({k: v for k, v in leaf.items() if v is not None})
    event = Node(labels=("Event", _label(category)), key={"event_uid": uid}, props=props)
    nodes, edges = [], []
    if ctx.computer:
        host = Node(("Host",), key={"hostname": ctx.computer})
        nodes.append(host)
        edges.append(Edge("ON_HOST", event, host))   # 观测主机,≠攻击目标
    return event, nodes, edges


def _ip_node(ip):
    return None if (not ip or ip == "-") else Node(("IPAddress",), key={"ip": ip})


# ---------------------------------------------------------------- 逐事件映射

def _map_4769(ctx: _Ctx):
    """4769 TGS-REQ → authentication·service_ticket(Kerberoast 主场)。"""
    ed = ctx.ed
    leaf = {"enc_type": ed.get("TicketEncryptionType"),
            "ticket_options": ed.get("TicketOptions")}
    event, nodes, edges = _base_event(ctx, "authentication", "service_ticket",
                                      outcome=_win_outcome(ed), leaf=leaf)
    # ACTOR = 请求者
    actor = _account_from_name(ed.get("TargetUserName"))
    if actor:
        nodes.append(actor)
        edges.append(Edge("ACTOR", event, actor))
    # TARGET = 被请求服务账号(ServiceName=SAM, ServiceSid=SID)
    svc = Node(("Account",), key={"sid": ed.get("ServiceSid")},
               props={"sam": ed.get("ServiceName")})
    nodes.append(svc)
    edges.append(Edge("TARGET", event, svc))
    # FROM = 来源 IP
    ip = _ip_node(ed.get("IpAddress"))
    if ip:
        nodes.append(ip)
        edges.append(Edge("FROM", event, ip))
    return Mapping(event=event, nodes=nodes, edges=edges)


def _map_1(ctx: _Ctx):
    """Sysmon EID1 → process·create;显式建进程对象图(PRODUCES + PARENT_OF/RAN_AS/ON_HOST)。"""
    ed = ctx.ed
    leaf = {"command_line": ed.get("CommandLine"),
            "integrity_level": ed.get("IntegrityLevel"),
            "hashes": ed.get("Hashes")}
    event, nodes, edges = _base_event(ctx, "process", "create", leaf=leaf)
    # 子进程对象(PRODUCES)
    child = Node(("Process",), key={"process_guid": ed.get("ProcessGuid")},
                 props={"pid": ed.get("ProcessId"), "image": ed.get("Image"),
                        "command_line": ed.get("CommandLine")})
    nodes.append(child)
    edges.append(Edge("PRODUCES", event, child))
    # 父进程 + PARENT_OF(对象结构边:父→子)
    ppg = ed.get("ParentProcessGuid")
    if ppg:
        parent = Node(("Process",), key={"process_guid": ppg},
                      props={"image": ed.get("ParentImage"),
                             "command_line": ed.get("ParentCommandLine")})
        nodes.append(parent)
        edges.append(Edge("PARENT_OF", parent, child))
    # 运行账号:RAN_AS(结构,子→账号) + ACTOR(角色,事件→账号)
    acct = _account_from_name(ed.get("User"))
    if acct:
        nodes.append(acct)
        edges.append(Edge("RAN_AS", child, acct))
        edges.append(Edge("ACTOR", event, acct))
    # 子进程 ON_HOST(对象结构边,复用 _base_event 建的 Host)
    host = _host_of(nodes)
    if host:
        edges.append(Edge("ON_HOST", child, host))
    return Mapping(event=event, nodes=nodes, edges=edges)


_WINLOG = {
    "4769": _map_4769,
    "1": _map_1,
}


# ---------------------------------------------------------------- 入口

def map_event(doc: dict) -> Mapping:
    """一条 ES 文档 → Mapping(:Event + 对象 + 角色边)。"""
    if "winlog" in doc:
        wl = doc["winlog"]
        code = str(wl.get("event_id"))
        ctx = _Ctx(
            source="winlogbeat",
            sensor=wl.get("channel"),
            code=code,
            ed=wl.get("event_data", {}) or {},
            computer=wl.get("computer_name"),
            record_id=wl.get("record_id"),
            event_time=doc.get("@timestamp"),
        )
        handler = _WINLOG.get(code)
        if handler is None:
            raise NotImplementedError(f"暂无映射: winlog event {code}")
        return handler(ctx)
    raise NotImplementedError("暂只支持 winlogbeat 文档")
