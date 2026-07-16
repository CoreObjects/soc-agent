"""Kerberoast 判别 spec —— 图模式为主(结构判别特征从图算),产分层判别特征。

层(先证伪在前):
- exculpatory:跨域机器账号引荐票(正常跨域信任 RC4)—— 键于 {req_is_machine, same_domain},
  忽略扇出/enc(机器账号引荐票无论扇出多少都豁免);
- incriminating:spray —— 键于 {req_is_machine, same_domain, enc, spn_fanout(短窗分桶)}。
实例值(账号/域/具体 SPN)不进特征,只留着填处置目标。graph.run_cypher 只读。
kerberoast 无需代码钩子(判别全是结构/计数);需钩子的 skill(如 webshell 解码)在各自 discriminator 里调 recipe_lib。
"""

_FANOUT_WINDOW = "PT10M"     # 短窗:近 10 分钟内该请求者去重目标数(扫描式取票信号)


def _netbios(domain):
    """域归一到 NetBIOS 首段大写:NORTH / north.sevenkingdoms.local → NORTH。"""
    if not domain or domain == "-":
        return None
    return domain.split(".")[0].strip().upper() or None


def discriminate(graph, alert, seed=None):
    """→ {"layers": [有序分层判别特征], "bindings": {处置目标字段→本告警实体值}}。
    bindings 供快通道填处置目标(免跑 recipe);实例值只在此出现,不进 layers 特征。"""
    aid = alert.alert_uid
    rows = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(trig:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "OPTIONAL MATCH (trig)-[:REQUESTED]->(tgt) "
        "WITH req, trig, tgt.sam AS tgt_sam, tgt.domain AS tgt_domain, trig.event_time AS t0, trig.enc_type AS enc "
        "OPTIONAL MATCH (req)<-[:BY]-(e:Event {event_code:'4769'})-[:REQUESTED]->(t) "
        "  WHERE e.event_time >= toString(datetime(t0) - duration('" + _FANOUT_WINDOW + "')) AND e.event_time <= t0 "
        "RETURN req.sam AS req_sam, req.domain AS req_domain, tgt_sam, tgt_domain, enc, "
        "count(DISTINCT t) AS fanout",
        aid=aid)
    b = rows[0] if rows else {}
    # 源主机(req_host)本可供 collect_artifact 绑真主机,但图里 Host↔IP 的 HAS_IP 边未被 ingest 填充 →
    # 暂无法从源 IP 反查主机;留 None(composer 若组 collect_artifact,护栏按"目标未解析"降级 escalate)。
    # 待 ingest 补 HAS_IP 后再恢复源主机反查。

    req_sam = b.get("req_sam") or ""
    req_is_machine = req_sam.strip().endswith("$")
    same_domain = bool(_netbios(b.get("req_domain")) and _netbios(b.get("tgt_domain"))
                       and _netbios(b.get("req_domain")) == _netbios(b.get("tgt_domain")))
    enc_raw = str(b.get("enc") or "").strip().lower()
    enc = "RC4" if enc_raw in ("0x17", "23", "rc4", "rc4-hmac") else "other"
    fanout = b.get("fanout") or 0
    spn_fanout = ">=5" if fanout >= 5 else "<5"

    return {
        "layers": [
            {"layer": "exculpatory",
             "features": {"req_is_machine": req_is_machine, "same_domain": same_domain}},
            {"layer": "incriminating",
             "features": {"req_is_machine": req_is_machine, "same_domain": same_domain,
                          "enc": enc, "spn_fanout": spn_fanout}},
        ],
        "bindings": {"requester": req_sam or None, "target_service": b.get("tgt_sam"),
                     "req_host": b.get("req_host")},   # 源主机(供 collect_artifact 等绑真主机;取不到=None)
    }
