"""横向移动/PtH/PtT(T1550/T1021)确定性取证。

图内数据较好:登录事件(logon_type/结果/账号/目标主机/源IP)、账号权限、账号↔主机基线
(AUTHENTICATED_TO 聚合边 count/first_seen)、账号扇出。认证包/票据生命周期是图盲区。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(acc:Account) "
        "OPTIONAL MATCH (e)-[:AUTHENTICATED_TO]->(h:Host) "
        "OPTIONAL MATCH (e)-[:FROM]->(ip:IPAddress) "
        "RETURN e.event_code AS event_code, e.logon_type AS logon_type, e.result AS result, "
        "acc.sam AS acc_sam, acc.domain AS acc_domain, coalesce(acc.privileged,false) AS acc_privileged, "
        "h.hostname AS target_host, "
        "ip.ip AS src_ip",
        aid=aid)
    ev["登录事件"] = base[0] if base else {}
    b = ev["登录事件"]
    acc_sam, target = b.get("acc_sam"), b.get("target_host")

    if acc_sam and target:
        rows = graph.run_cypher(
            "MATCH (acc:Account {sam:$s})-[r:AUTHENTICATED_TO]->(h:Host {hostname:$h}) "
            "RETURN r.count AS count, r.first_seen AS first_seen, r.last_seen AS last_seen",
            s=acc_sam, h=target)
        ev["该账号↔该主机基线"] = rows[0] if rows else {"note": "无历史,疑似首次登该主机"}

    if acc_sam:
        rows = graph.run_cypher(
            "MATCH (acc:Account {sam:$s})-[:AUTHENTICATED_TO]->(h:Host) "
            "RETURN count(DISTINCT h) AS distinct_hosts", s=acc_sam)
        ev["账号扇出(共登过几台主机)"] = rows[0] if rows else {}

    ev["_图盲区"] = ("认证包(NTLM/Kerberos)+KeyLength+冒充级别(PtH 首要签名)、票据生命周期(金票)、"
                    "成员机票据↔DC 硬关联(银票) —— 未建模")
    return ev
