"""Ingress Tool Transfer(T1105)确定性取证 —— 从 seed 起,适配事件类型 + 解码 + 认噪声。

要点(与 suspicious_process 同源):此类告警极吵、绝大多数是正常下载/系统自检。触发常是
EID11(掉文件),决定性证据是"谁写的、写了啥、命令行(解码后)是不是良性运维/策略探针"。
不查图里没有的字段(ip.reputation / asn / file.sha256,全空 → 图盲区)。
"""
from soc_agent.recipe_lib import decode_chain, provisioning_noise


def collect(graph, alert, seed=None):
    seed = seed or {}
    event = seed.get("event") or {}
    subject = seed.get("subject") or {}
    related = seed.get("related") or []
    ev = {}

    # 1. 触发/下载进程 + 命令行 + 事件类型
    ev["事件类型"] = event.get("event_code")
    ev["触发进程"] = {k: subject.get(k) for k in ("image", "command_line", "pid", "process_guid")
                    if subject.get(k) is not None}

    # 2. 落地文件 / 主机(来自 seed)
    files = sorted({r["node"].get("path") for r in related
                    if r.get("rel") == "WROTE" and r.get("node") and r["node"].get("path")})
    host = next((r["node"].get("hostname") for r in related
                 if r.get("rel") == "ON_HOST" and r.get("node")), None)
    ev["落地文件"] = files
    ev["主机"] = host

    # 3. ★解码命令行 + 认良性噪声(把"掉可执行文件"其实是策略探针/Ansible 的 FP 认出来)
    layers = decode_chain(subject.get("command_line"))
    if layers:
        ev["解码后命令(逐层)"] = layers
    blob = "\n".join(filter(None, [subject.get("command_line")] + layers + files))
    ev["供给/自检噪声"] = provisioning_noise(blob) or "未识别到已知良性噪声"

    # 4. 下载语义:父进程 + 外连目的 + 落地即执行(有进程 GUID 才查;reputation/asn 图无 → 不查)
    pg = subject.get("process_guid")
    if pg:
        rows = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS parent_image", g=pg)
        ev["父进程"] = rows[0].get("parent_image") if rows else None
        ev["外连目的(仅存在性,信誉是盲区)"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) "
            "OPTIONAL MATCH (p)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (p)-[:QUERIED]->(d:Domain) "
            "RETURN collect(DISTINCT ip.ip)[0..20] AS ips, "
            "collect(DISTINCT d.fqdn)[0..20] AS domains", g=pg)
        ev["落地即执行(SPAWNED 子进程)"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g}) OPTIONAL MATCH (p)-[:SPAWNED]->(c:Process) "
            "RETURN collect(DISTINCT c.image)[0..10] AS spawned", g=pg)

    ev["_图盲区"] = ("完整下载 URL/文件名、落地文件哈希、IP/域信誉(reputation/asn 未建模、全空)、"
                    "下载进程签名 —— 未建模;编码命令已解码见上,据此与噪声标签判良性/恶意")
    return ev
