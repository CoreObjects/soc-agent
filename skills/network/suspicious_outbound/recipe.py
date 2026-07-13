"""可疑外连 / 罕见进程 C2 通道(T1571/T1090)确定性取证。

从触发事件取发起进程 + 外连目标(IP/端口/type)+ 父链/账号 + 外连聚合(反复性)+ 目标信誉。
代理后落点、协议真伪需探针,是图盲区。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
        "OPTIONAL MATCH (p)-[:RAN_AS]->(acc:Account) "
        "RETURN p.process_guid AS proc_guid, p.image AS image, p.command_line AS command_line, "
        "parent.image AS parent, acc.sam AS account, "
        "ip.ip AS dst_ip, ip.type AS dst_type, ip.asn AS dst_asn, ip.geo AS dst_geo, "
        "ip.reputation AS dst_reputation, e.dest_port AS dest_port, h.hostname AS host",
        aid=aid)
    ev["进程与目标+父链"] = base[0] if base else {}
    b = ev["进程与目标+父链"]
    pg, dst_ip = b.get("proc_guid"), b.get("dst_ip")

    if pg and dst_ip:
        ev["外连聚合(反复性)"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g})-[c:CONNECTED_TO]->(ip:IPAddress {ip:$ip}) "
            "RETURN c.count AS count, c.first_seen AS first_seen, c.last_seen AS last_seen", g=pg, ip=dst_ip)
    if dst_ip:
        ev["目标域/信誉"] = graph.run_cypher(
            "OPTIONAL MATCH (d:Domain)-[:RESOLVES_TO]->(ip:IPAddress {ip:$ip}) "
            "RETURN collect(DISTINCT {fqdn: d.fqdn, reputation: d.reputation, first_seen: d.first_seen}) AS domains",
            ip=dst_ip)

    ev["_图盲区"] = ("代理之后的真实外部目标(T1090)、协议 vs 端口错配(无 DPI)、字节量/时长、"
                    "reputation 是否有真情报值 —— 需探针")
    return ev
