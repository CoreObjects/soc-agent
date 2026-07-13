"""Kerberoast 确定性取证脚本(sink①)。

orchestrator 跑它把关键证据一次性收齐(含★跨域信任),再交 LLM 定性。
不依赖模型自己规划该查什么 —— 模型只负责"看着证据下判断"。
graph.run_cypher(query, **params) 只读;多步依赖(后步用前步取出的账号/域)。
"""


def collect(graph, alert, seed=None):
    aid = alert.alert_uid
    ev = {}

    # 1. 请求者 + 目标 + 加密/票据选项
    base = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "OPTIONAL MATCH (e)-[:REQUESTED]->(tgt) "
        "RETURN req.sam AS req_sam, req.domain AS req_domain, req.type AS req_type, "
        "coalesce(req.privileged,false) AS req_privileged, "
        "tgt.sam AS tgt_sam, tgt.domain AS tgt_domain, "
        "e.enc_type AS enc_type, e.ticket_options AS ticket_options",
        aid=aid)
    b = base[0] if base else {}
    ev["请求与目标"] = b
    req_sam, tgt_sam, req_domain = b.get("req_sam"), b.get("tgt_sam"), b.get("req_domain")

    # 2. 目标估值:是否特权 / SPN / 属组(判 high-value)
    if tgt_sam:
        rows = graph.run_cypher(
            "MATCH (tgt:Account {sam:$s}) OPTIONAL MATCH (tgt)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(tgt.privileged,false) AS privileged, tgt.spn AS spn, "
            "collect(DISTINCT g.name) AS groups", s=tgt_sam)
        ev["目标估值"] = rows[0] if rows else {}

    # 3. 请求者 enc 基线(RC4 是常态还是突增)
    if req_sam:
        ev["请求者enc基线"] = graph.run_cypher(
            "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event {event_code:'4769'}) "
            "RETURN e.enc_type AS enc, count(*) AS n ORDER BY n DESC", s=req_sam)

    # 4. ★跨域信任(多域林头号 FP 判据):请求者域信任了哪些域
    if req_domain:
        rows = graph.run_cypher(
            "MATCH (dreq:Domain {netbios:$nb}) OPTIONAL MATCH (dreq)-[:TRUSTS]-(dt:Domain) "
            "RETURN dreq.fqdn AS req_domain_fqdn, collect(DISTINCT dt.fqdn) AS trusts", nb=req_domain)
        ev["跨域信任"] = rows[0] if rows else {"req_domain_fqdn": None, "trusts": []}

    # 5. SPN 扇出(短时去重目标数;扫描式取票信号)
    if req_sam:
        rows = graph.run_cypher(
            "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event {event_code:'4769'})-[:REQUESTED]->(t) "
            "RETURN count(DISTINCT t) AS distinct_targets, count(*) AS total_4769", s=req_sam)
        ev["SPN扇出"] = rows[0] if rows else {}

    return ev
