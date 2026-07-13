"""ADCS 证书滥用(T1649)确定性取证。

图内 4886/4887 能取到请求者/CA/模板名/请求者估值;SAN 与模板 EKU 是图盲区,recipe 显式标出,
让 LLM 据此把无法判定的落到 suspicious + missing_evidence(别硬判)。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(req:Account) "
        "OPTIONAL MATCH (e)-[:REQUESTED]->(svc) "
        "RETURN e.event_code AS event_code, req.sam AS req_sam, req.domain AS req_domain, "
        "coalesce(req.privileged,false) AS req_privileged, "
        "e.template AS template, e.request_type AS request_type, svc.name AS ca",
        aid=aid)
    ev["请求者与CA/模板"] = base[0] if base else {}
    req_sam = ev["请求者与CA/模板"].get("req_sam")

    if req_sam:
        rows = graph.run_cypher(
            "MATCH (req:Account {sam:$s}) OPTIONAL MATCH (req)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(req.privileged,false) AS privileged, collect(DISTINCT g.name) AS groups",
            s=req_sam)
        ev["请求者估值"] = rows[0] if rows else {}

    ev["_图盲区"] = ("证书 SAN 与请求者是否 mismatch(ESC1/ESC6 头号判据)、模板 EKU/"
                    "ENROLLEE_SUPPLIES_SUBJECT/是否需审批、ESC8 中继链 —— 均未建模,无法从图判定")
    return ev
