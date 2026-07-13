"""通用兜底取证(未覆盖告警类型):确定性收齐触发事件 + 主语/主机 + 宾语/次要参与者。
让 LLM 在有基础证据下按通用五步判序定性,而非从零规划查询。各层 _generic 共用同一份。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}
    rows = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event) "
        "OPTIONAL MATCH (e)-[:BY]->(subj) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN e{.*} AS event, "
        "head(collect(DISTINCT {labels: labels(subj), props: properties(subj)})) AS subject, "
        "h.hostname AS host, h.criticality AS host_criticality",
        aid=aid)
    ev["触发事件与主语/主机"] = rows[0] if rows else {}
    ev["宾语与次要参与者"] = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[r]->(obj) "
        "WHERE NOT type(r) IN ['BY', 'TRIGGERED', 'ON_HOST'] "
        "RETURN collect(DISTINCT {rel: type(r), labels: labels(obj), props: properties(obj)}) AS related",
        aid=aid)
    return ev
