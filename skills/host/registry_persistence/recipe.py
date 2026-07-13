"""注册表自启持久化(T1547.001)确定性取证。

从触发事件(EID13 SET)取被写的键/值名/value_data(启动命令)+ 写入进程/父链/账号。
被持久化文件的哈希/写入进程签名是图盲区。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(p:Process) "
        "OPTIONAL MATCH (e)-[:SET]->(rv:RegistryValue) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "OPTIONAL MATCH (parent:Process)-[:SPAWNED]->(p) "
        "RETURN rv.hive AS hive, rv.key_path AS key_path, rv.value_name AS value_name, "
        "e.value_data AS value_data, p.process_guid AS proc_guid, p.image AS writer_image, "
        "p.command_line AS writer_cmdline, parent.image AS parent, "
        "h.hostname AS host",
        aid=aid)
    ev["键与写入值+写入进程"] = base[0] if base else {}
    pg = ev["键与写入值+写入进程"].get("proc_guid")

    if pg:
        ev["写入账号"] = graph.run_cypher(
            "MATCH (p:Process {process_guid:$g})-[:RAN_AS]->(acc:Account) "
            "RETURN acc.sam AS sam, acc.domain AS domain, coalesce(acc.privileged,false) AS privileged",
            g=pg)

    ev["_图盲区"] = ("被持久化文件的哈希/签名、写入进程 EXE 签名、注册表前值/是否覆盖(篡改 vs 新建)"
                    " —— 未建模")
    return ev
