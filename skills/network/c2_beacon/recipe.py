"""C2 信标 / DNS beacon(T1071/T1568)确定性取证。

从触发事件取发起进程 + 目标(IP/域);解码发起命令(EncodedCommand)+ 良性供给证伪;
外连/DNS 反复性数事件(周期性粗信号);目标域新鲜度;发起进程父链/账号。
精确节律/jitter、DNS 深度特征、reputation/解析扇出需探针,是图盲区。
"""

from soc_agent.recipe_lib import decode_chain, provisioning_noise


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:CONNECTED_TO]->(ip:IPAddress) "
        "OPTIONAL MATCH (e)-[:QUERIED]->(d:Domain) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN p.process_guid AS proc_guid, p.image AS image, p.command_line AS command_line, "
        "e.dst_port AS dst_port, ip.ip AS dst_ip, d.fqdn AS dst_domain, h.hostname AS host",
        aid=aid)
    ev["进程与目标"] = base[0] if base else {}
    b = ev["进程与目标"]
    pg, dst_ip, dst_domain = b.get("proc_guid"), b.get("dst_ip"), b.get("dst_domain")

    # ★解码发起命令行 + 良性供给/自检证伪 —— 编码信标的真身摊开
    layers = decode_chain(b.get("command_line") or "")
    if layers:
        ev["发起命令解码(逐层)"] = layers
    ev["供给/自检噪声"] = provisioning_noise(
        "\n".join([b.get("command_line") or ""] + layers)) or "未识别到已知良性噪声"

    if pg and dst_ip:                     # HTTP beacon:数连接事件(聚合边不存 count,现算)
        ev["外连聚合(周期性)"] = graph.run_cypher(
            "MATCH (e:Event)-[:BY]->(:Process {process_guid:$g}) "
            "MATCH (e)-[:CONNECTED_TO]->(:IPAddress {ip:$ip}) "
            "RETURN count(e) AS count, min(e.event_time) AS first_seen, max(e.event_time) AS last_seen",
            g=pg, ip=dst_ip)
    if pg and dst_domain:                 # DNS beacon:数查询事件
        ev["DNS查询聚合(周期性)"] = graph.run_cypher(
            "MATCH (e:Event)-[:BY]->(:Process {process_guid:$g}) "
            "MATCH (e)-[:QUERIED]->(:Domain {fqdn:$f}) "
            "RETURN count(e) AS count, min(e.event_time) AS first_seen, max(e.event_time) AS last_seen",
            g=pg, f=dst_domain)

    if dst_domain:                        # 目标域新鲜度(reputation/解析扇出未建模=盲区)
        ev["目标域新鲜度"] = graph.run_cypher(
            "MATCH (d:Domain {fqdn:$f}) RETURN d.first_seen AS domain_first_seen", f=dst_domain)

    if pg:                                # 发起进程正常吗
        ev["发起进程"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
            "OPTIONAL MATCH (p)-[:RAN_AS]->(acc:Account) "
            "RETURN parent.image AS parent, acc.sam AS account", g=pg)

    ev["_图盲区"] = ("精确信标周期/jitter 显著性、字节量/时长、DNS 深度特征(记录类型/子域熵/NXDOMAIN)、"
                    "TLS/JA3、目标 reputation/解析扇出(RESOLVES_TO 未建模,需 DNS 应答映射)—— "
                    "host-only 天花板,需 NDR/Zeek 探针")
    return ev
