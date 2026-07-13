"""C2 信标 / DNS beacon(T1071/T1568)确定性取证。

从触发事件取发起进程 + 目标(IP/域);再取聚合边 count/first/last(周期性粗信号)+ 目标信誉
+ 发起进程父链/账号。精确节律/jitter、DNS 深度特征需探针,是图盲区。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress) "
        "OPTIONAL MATCH (e)-[:QUERIED]->(d:Domain) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN p.process_guid AS proc_guid, p.image AS image, p.command_line AS command_line, "
        "e.dest_port AS dest_port, ip.ip AS dst_ip, d.fqdn AS dst_domain, h.hostname AS host",
        aid=aid)
    ev["进程与目标"] = base[0] if base else {}
    b = ev["进程与目标"]
    pg, dst_ip, dst_domain = b.get("proc_guid"), b.get("dst_ip"), b.get("dst_domain")

    if pg and dst_ip:                     # HTTP beacon 维度:聚合边粗信号(周期性)
        ev["外连聚合(周期性)"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g})-[c:CONNECTED_TO]->(ip:IPAddress {ip:$ip}) "
            "RETURN c.count AS count, c.first_seen AS first_seen, c.last_seen AS last_seen", g=pg, ip=dst_ip)
    if pg and dst_domain:                 # DNS beacon 维度
        ev["DNS查询聚合(周期性)"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g})-[q:QUERIED]->(d:Domain {fqdn:$f}) "
            "RETURN q.count AS count, q.first_seen AS first_seen, q.last_seen AS last_seen", g=pg, f=dst_domain)

    if dst_ip or dst_domain:              # 目标信誉/新鲜度/解析扇出
        ev["目标信誉"] = graph.run_cypher(
            "OPTIONAL MATCH (ip:IPAddress {ip:$ip}) "
            "OPTIONAL MATCH (d:Domain {fqdn:$f}) OPTIONAL MATCH (d)-[:RESOLVES_TO]->(rip:IPAddress) "
            "RETURN ip.reputation AS ip_reputation, ip.asn AS ip_asn, "
            "d.reputation AS domain_reputation, d.first_seen AS domain_first_seen, "
            "count(DISTINCT rip) AS resolve_fanout", ip=dst_ip, f=dst_domain)

    if pg:                                # 发起进程正常吗
        ev["发起进程"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
            "OPTIONAL MATCH (p)-[:RAN_AS]->(acc:Account) "
            "RETURN parent.image AS parent, acc.sam AS account", g=pg)

    ev["_图盲区"] = ("精确信标周期/jitter 显著性、字节量/时长、DNS 深度特征(记录类型/子域熵/NXDOMAIN)、"
                    "TLS/JA3、reputation 是否有真情报值 —— host-only 天花板,需 NDR/Zeek 探针")
    return ev
