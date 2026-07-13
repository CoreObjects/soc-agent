"""DCSync(T1003.006)确定性取证。

核心判据 = 发起者是不是本域 DC 机器账号(是→DC 正常复制 benign;否→成立)。
图内可取:发起者账号/类型/privileged、被访问对象、properties(复制 GUID)、本域 DC 主机名(Domain.dc)。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4662'})-[:BY]->(actor:Account) "
        "OPTIONAL MATCH (e)-[:ACCESSED]->(obj) "
        "RETURN actor.sam AS actor_sam, actor.domain AS actor_domain, actor.type AS actor_type, "
        "coalesce(actor.privileged,false) AS actor_privileged, "
        "e.properties AS properties, obj.dn AS obj_dn, obj.object_class AS obj_class",
        aid=aid)
    ev["发起者与对象"] = base[0] if base else {}
    b = ev["发起者与对象"]
    actor_sam, actor_domain = b.get("actor_sam"), b.get("actor_domain")

    if actor_sam:
        rows = graph.run_cypher(
            "MATCH (actor:Account {sam:$s}) OPTIONAL MATCH (actor)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(actor.privileged,false) AS privileged, collect(DISTINCT g.name) AS groups",
            s=actor_sam)
        ev["发起者估值"] = rows[0] if rows else {}

    if actor_domain:                                  # 本域 DC 主机名(判"发起者是不是 DC")
        rows = graph.run_cypher(
            "MATCH (d:Domain {netbios:$nb}) RETURN d.fqdn AS domain_fqdn, d.dc AS dc_host", nb=actor_domain)
        ev["域DC"] = rows[0] if rows else {}

    ev["_图盲区"] = ("复制范围(是否含 krbtgt/全域)、授予复制权的前置 ACL 修改(5136)、"
                    "DC/同步账号权威标记 —— 未建模;actor 是否 DC 机器账号需拿 actor_sam 与 dc_host 比对判断")
    return ev
