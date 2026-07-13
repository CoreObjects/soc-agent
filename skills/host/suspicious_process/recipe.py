"""可疑进程/LOLBin/恶意子进程(T1059/T1055/T1218)确定性取证。

从触发事件(EID1 SPAWNED)取父/子进程 + 子命令行;取子进程账号(webshell 判定);
沿子进程看后续行为(派生/外连/读 LSASS/写注册表)拉全攻击链。进程签名/解码命令是图盲区。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(parent:Process) "
        "OPTIONAL MATCH (e)-[:SPAWNED]->(child:Process) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "OPTIONAL MATCH (gp:Process)-[:SPAWNED]->(parent) "
        "RETURN gp.image AS grandparent, parent.image AS parent_image, "
        "child.process_guid AS child_guid, child.image AS child_image, child.command_line AS child_cmdline, "
        "h.hostname AS host, h.criticality AS host_criticality",
        aid=aid)
    ev["父子进程"] = base[0] if base else {}
    cg = ev["父子进程"].get("child_guid")

    if cg:
        ev["子进程账号"] = graph.run_cypher(
            "MATCH (child:Process {process_guid:$g})-[:RAN_AS]->(acc:Account) "
            "RETURN acc.sam AS sam, acc.domain AS domain, coalesce(acc.privileged,false) AS privileged",
            g=cg)
        ev["后续行为"] = graph.run_cypher(
            "MATCH (child:Process {process_guid:$g}) "
            "OPTIONAL MATCH (child)-[:SPAWNED]->(d:Process) "
            "OPTIONAL MATCH (child)-[:CONNECTED_TO]->(ip:IPAddress) "
            "OPTIONAL MATCH (child)-[:ACCESSED]->(l:Process) "
            "OPTIONAL MATCH (child)-[:SET]->(rv:RegistryValue) "
            "RETURN collect(DISTINCT d.image) AS descendants, "
            "collect(DISTINCT {ip: ip.ip, reputation: ip.reputation}) AS out_ips, "
            "collect(DISTINCT l.image) AS accessed_procs, collect(DISTINCT rv.key_path) AS reg_keys",
            g=cg)

    ev["_图盲区"] = ("进程 EXE 签名/是否 LOLBin 原版、完整性级别/Token 提权、-EncodedCommand 解码内容"
                    " —— 未建模")
    return ev
