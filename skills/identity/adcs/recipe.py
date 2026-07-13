"""ADCS 证书滥用(T1649)确定性取证。

只取图里真有的字段:4886 携 attributes(含请求机器 cdc/rmd)+ request_id + 请求者;CA 为 Service
(service_id/kind)。★模板名/EKU/SAN 是图盲区(4886 不携带)—— recipe 显式标出,让 LLM 把无法
判定的落到 suspicious + missing_evidence(别硬判),不再空查 template/request_type 死字段。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(req:Account) "
        "OPTIONAL MATCH (e)-[:REQUESTED]->(ca:Service) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN e.event_code AS event_code, e.attributes AS attributes, e.request_id AS request_id, "
        "req.sam AS req_sam, req.domain AS req_domain, req.upn AS req_upn, "
        "coalesce(req.privileged,false) AS req_privileged, "
        "ca.service_id AS ca, ca.kind AS ca_kind, h.hostname AS ca_host",
        aid=aid)
    ev["请求者与CA"] = base[0] if base else {}
    req_sam = ev["请求者与CA"].get("req_sam")

    if req_sam:
        rows = graph.run_cypher(
            "MATCH (req:Account {sam:$s}) OPTIONAL MATCH (req)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(req.privileged,false) AS privileged, collect(DISTINCT g.name) AS groups",
            s=req_sam)
        ev["请求者估值"] = rows[0] if rows else {}

    ev["_图盲区"] = ("模板名/EKU/ENROLLEE_SUPPLIES_SUBJECT、证书 SAN 与请求者是否 mismatch"
                    "(ESC1/ESC6 头号判据)、ESC8 中继链 —— 4886 不携带、均未建模,无法从图判定。"
                    "attributes 里的请求机器(cdc/rmd)可旁证请求来源是否异常主机")
    return ev
