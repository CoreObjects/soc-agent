"""Kerberoast(T1558.003)快通道签名 —— 与 skill co-located,被中央 signatures 引擎自动发现。

`signature(graph, alert, seed) → {"layers", "bindings"} | None`(skill 名由引擎按目录注入,这里不写)。
- **自锚定** 4769 请求票事件;★锚不到 4769 请求者 → 返回 None(伪签名,不参与碰撞/沉淀)。
- exculpatory(先证伪):跨域机器账号引荐票 → 键于 {req_is_machine, same_domain}(机器引荐票无论扇出多少都豁免);
- incriminating(坐实):普通用户 spray → 键于 {req_is_machine, same_domain, enc, spn_fanout 短窗分桶}。
- 实例值(账号/域)只进 bindings,不进特征。低层判定(enc/域/机器账号/短窗)走 `._kerb`,和 recipe 共享不漂。
"""
from ._kerb import FANOUT_WINDOW, is_machine, netbios, norm_enc, same_domain


def signature(graph, alert, seed=None):
    rows = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(trig:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "OPTIONAL MATCH (trig)-[:REQUESTED]->(tgt) "
        "WITH req, trig, tgt.sam AS tgt_sam, tgt.domain AS tgt_domain, trig.event_time AS t0, trig.enc_type AS enc "
        "OPTIONAL MATCH (req)<-[:BY]-(e:Event {event_code:'4769'})-[:REQUESTED]->(t) "
        "  WHERE e.event_time >= toString(datetime(t0) - duration('" + FANOUT_WINDOW + "')) AND e.event_time <= t0 "
        "RETURN req.sam AS req_sam, req.domain AS req_domain, tgt_sam, tgt_domain, enc, "
        "count(DISTINCT t) AS fanout",
        aid=alert.alert_uid)
    b = rows[0] if rows else None
    if not b or not (b.get("req_sam") or "").strip():
        return None                                  # 锚不到 4769 请求者 → 伪签名,不出签名

    req_sam = (b.get("req_sam") or "").strip()
    req_is_machine = is_machine(req_sam)
    sd = same_domain(b.get("req_domain"), b.get("tgt_domain"))
    enc = norm_enc(b.get("enc"))
    spn_fanout = ">=5" if (b.get("fanout") or 0) >= 5 else "<5"

    return {
        "layers": [
            {"layer": "exculpatory",
             "features": {"req_is_machine": req_is_machine, "same_domain": sd}},
            {"layer": "incriminating",
             "features": {"req_is_machine": req_is_machine, "same_domain": sd,
                          "enc": enc, "spn_fanout": spn_fanout}},
        ],
        "bindings": {"requester": req_sam or None, "target_service": b.get("tgt_sam"),
                     "requester_domain": b.get("req_domain"), "target_service_domain": b.get("tgt_domain"),
                     "req_host": b.get("req_host")},
    }
