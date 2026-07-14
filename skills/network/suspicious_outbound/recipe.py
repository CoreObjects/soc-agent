"""可疑外连 / 罕见进程 C2 通道(T1571/T1090)确定性取证。

从触发事件取发起进程 + 外连目标(IP/端口/proto)+ 父链/账号;解码发起命令(LOLBin 常
-EncodedCommand,不解码=判不透意图)+ 已知良性供给证伪;外连反复性数连接事件(周期性粗信号)。
代理后落点、协议真伪、IP/域 reputation 需探针,是图盲区。
"""

from soc_agent.recipe_lib import decode_chain, provisioning_noise


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
        "ip.ip AS dst_ip, e.dst_port AS dst_port, e.proto AS proto, h.hostname AS host",
        aid=aid)
    ev["进程与目标+父链"] = base[0] if base else {}
    b = ev["进程与目标+父链"]
    pg, dst_ip = b.get("proc_guid"), b.get("dst_ip")

    # ★解码发起命令行(EncodedCommand 连锁解开)+ 已知良性供给/自检证伪 —— 把编码外连的真身摊开
    layers = decode_chain(b.get("command_line") or "")
    if layers:
        ev["发起命令解码(逐层)"] = layers
    ev["供给/自检噪声"] = provisioning_noise(
        "\n".join([b.get("command_line") or ""] + layers)) or "未识别到已知良性噪声"

    if pg and dst_ip:                     # 外连反复性:数连接事件(聚合边不存 count,现算)
        ev["外连聚合(反复性)"] = graph.run_cypher(
            "MATCH (e:Event)-[:BY]->(:Process {process_guid:$g}) "
            "MATCH (e)-[:CONNECTED_TO]->(:IPAddress {ip:$ip}) "
            "RETURN count(e) AS count, min(e.event_time) AS first_seen, max(e.event_time) AS last_seen",
            g=pg, ip=dst_ip)

    ev["_图盲区"] = ("目标 IP/域 reputation(无情报源)、代理之后的真实外部目标(T1090)、"
                    "协议 vs 端口错配(无 DPI)、字节量/时长 —— 需 NDR/情报探针")
    return ev
