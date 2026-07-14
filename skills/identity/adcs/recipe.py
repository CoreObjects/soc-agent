"""ADCS 证书滥用(T1649)确定性取证。

取图里真有的字段:4886 携 attributes(含请求机器 cdc/rmd)+ request_id + 请求者;4887(签发)
携 subject_dn(证书签给谁)。CA 为 Service(service_id/kind)。★模板名/EKU/SAN 仍是图盲区。
★subject_dn 与请求者比对是 ESC1 核心信号:subject≠请求者 = 冒充(倾向恶意);subject==请求者
= 正常自签(倾向良性);subject_dn 缺失(4886 阶段)= 仍盲区。
"""
import re


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(req:Account) "
        "OPTIONAL MATCH (e)-[:REQUESTED]->(ca:Service) "
        "OPTIONAL MATCH (e)-[:ON_HOST]->(h:Host) "
        "RETURN e.event_code AS event_code, e.attributes AS attributes, e.request_id AS request_id, "
        "e.subject_dn AS subject_dn, "
        "req.sam AS req_sam, req.domain AS req_domain, req.upn AS req_upn, "
        "coalesce(req.privileged,false) AS req_privileged, "
        "ca.service_id AS ca, ca.kind AS ca_kind, h.hostname AS ca_host",
        aid=aid)
    b = base[0] if base else {}
    ev["请求者与CA"] = b
    req_sam = b.get("req_sam")

    if req_sam:
        rows = graph.run_cypher(
            "MATCH (req:Account {sam:$s}) OPTIONAL MATCH (req)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(req.privileged,false) AS privileged, collect(DISTINCT g.name) AS groups",
            s=req_sam)
        ev["请求者估值"] = rows[0] if rows else {}

    # ★主体(证书签给谁)与请求者比对 —— ESC1 核心:subject/SAN ≠ 请求者 = 冒充
    subject_dn = b.get("subject_dn")
    m = re.search(r"CN=([^,]+)", subject_dn or "", re.I)
    subject_cn = m.group(1).strip() if m else None
    matches = None
    if subject_cn and req_sam:
        matches = (subject_cn.strip().lower() == req_sam.strip().lower())
    ev["主体与请求者比对"] = {
        "subject_dn": subject_dn, "subject_cn": subject_cn, "req_sam": req_sam,
        "subject_matches_requester": matches,
        "_note": ("subject==请求者 → 无冒充,大概率正常自签(suspicious/lean_benign;SAN 仍是盲区);"
                  "subject≠请求者 → 疑似 ESC1 冒充(lean_malicious,甚至 TP);"
                  "subject_dn 缺失(多为 4886 请求阶段)→ 仍盲区,suspicious/lean_unknown。"),
    }

    ev["_图盲区"] = ("模板名/EKU/ENROLLEE_SUPPLIES_SUBJECT、证书 SAN(subjectAltName,ESC1 真正的冒充载体,"
                    "与 subject_dn 不同)、ESC8 中继链 —— 未建模。subject_dn 已取(见上),SAN 仍盲。"
                    "attributes 里请求机器(cdc/rmd)可旁证来源主机是否异常")
    return ev
