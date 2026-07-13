"""Ingress Tool Transfer(T1105)确定性取证。

从触发事件取下载进程 + 父链 + 外连目标(IP/域/信誉)+ 落地文件 + 是否随即执行。
重点给 LLM 降噪判据(白名单下载器 vs LOLBin、目的信誉、落地即执行)。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
        "RETURN p.process_guid AS proc_guid, p.image AS image, p.command_line AS command_line, "
        "parent.image AS parent, h.hostname AS host",
        aid=aid)
    ev["下载进程与父链"] = base[0] if base else {}
    pg = ev["下载进程与父链"].get("proc_guid")

    if pg:
        ev["外连目标"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) "
            "OPTIONAL MATCH (p)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (p)-[:QUERIED]->(d:Domain) "
            "RETURN collect(DISTINCT {ip: ip.ip, reputation: ip.reputation, asn: ip.asn}) AS ips, "
            "collect(DISTINCT {fqdn: d.fqdn, reputation: d.reputation, first_seen: d.first_seen}) AS domains",
            g=pg)
        ev["落地与执行"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) "
            "OPTIONAL MATCH (p)-[:WROTE]->(f:File) "
            "OPTIONAL MATCH (p)-[:SPAWNED]->(c:Process) "
            "RETURN collect(DISTINCT {path: f.path, sha256: f.sha256}) AS wrote_files, "
            "collect(DISTINCT c.image) AS spawned",
            g=pg)

    ev["_图盲区"] = ("完整下载 URL/文件名、落地文件哈希/信誉(FileCreate 常无哈希)、下载进程签名、"
                    "IP/域信誉是否实时且覆盖大厂 CDN —— 未建模/可能为空")
    return ev
