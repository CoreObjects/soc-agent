"""LSASS 凭据转储(T1003.001)确定性取证。

从触发事件(EID10 访问 lsass)取源进程/掩码/call_trace;再沿 SPAWNED 回溯父链、RAN_AS 取身份、
看读后行为(外连/派生/落地)。进程签名/哈希是图盲区(Process 无 signed/sha256)。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(src:Process) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(tgt:Process) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN src.process_guid AS src_guid, src.image AS src_image, src.command_line AS src_cmdline, "
        "tgt.image AS target_image, e.granted_access AS granted_access, e.call_trace AS call_trace, "
        "h.hostname AS host, h.criticality AS host_criticality",
        aid=aid)
    ev["源进程与访问掩码"] = base[0] if base else {}
    src_guid = ev["源进程与访问掩码"].get("src_guid")

    if src_guid:
        ev["父进程链"] = graph.run_cypher(
            "MATCH (p:Process)-[:SPAWNED]->(src:Process {process_guid:$g}) "
            "OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(p) "
            "RETURN gp.image AS grandparent, p.image AS parent, p.command_line AS parent_cmdline",
            g=src_guid)
        ev["运行账号"] = graph.run_cypher(
            "MATCH (src:Process {process_guid:$g})-[:RAN_AS]->(acc:Account) "
            "RETURN acc.sam AS sam, acc.domain AS domain, coalesce(acc.privileged,false) AS privileged",
            g=src_guid)
        ev["读后行为"] = graph.run_cypher(
            "MATCH (src:Process {process_guid:$g}) "
            "OPTIONAL MATCH (src)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (src)-[:SPAWNED]->(c:Process) "
            "OPTIONAL MATCH (src)-[:WROTE]->(f:File) "
            "RETURN collect(DISTINCT ip.ip) AS out_ips, collect(DISTINCT c.image) AS spawned, "
            "collect(DISTINCT f.path) AS wrote_files",
            g=src_guid)

    ev["_图盲区"] = ("源进程 EXE 签名/发布者/哈希(白名单只能按 image 路径)、"
                    "call_trace 是否已语义化(dbghelp/UNKNOWN)、dump 文件哈希 —— 未建模")
    return ev
