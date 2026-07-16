"""攻击模式签名注册表 —— 快通道用。

每个攻击类型一个签名函数：`(graph, alert, seed) → {"skill", "layers", "bindings"} | None`。
- **自锚定**告警的触发事件、自己查图取证、算特征签名；★**锚不到触发事件/取不到证据 → 返回 None（伪签名，
  不参与碰撞/沉淀）**。例：应用层告警套主机层签名，溯源入口(进程)找不到 → None。
- `layers` 分层（exculpatory 先证伪在前 / incriminating 坐实）；`bindings` 携本告警实例值（供快通道换实例填处置目标）。
- `run_all` 遍历注册表、收集非 None（每文件 try 隔离，坏函数不拖垮）。判别全是确定性代码，**不用大模型**。

离线由 Claude 写、每攻击类型一份（有限、可数）；攻击实例（签名→结论+处置）运行态沉淀在 openGauss。
新增攻击类型 = 往注册表加一个签名函数。
"""

_FANOUT_WINDOW = "PT10M"     # kerberoast 短窗:近 10 分钟该请求者去重目标数(扫描式取票信号)


def _netbios(domain):
    """域归一到 NetBIOS 首段大写:NORTH / north.sevenkingdoms.local → NORTH。"""
    if not domain or domain == "-":
        return None
    return domain.split(".")[0].strip().upper() or None


def sig_kerberoast(graph, alert, seed=None):
    """Kerberoast(T1558.003)签名：锚定 4769 请求票事件；锚不到 → None(伪签名)。
    exculpatory(先证伪)：跨域机器账号引荐票 → 键于 {req_is_machine, same_domain}；
    incriminating(坐实)：普通用户 spray → 键于 {req_is_machine, same_domain, enc, spn_fanout 短窗分桶}。
    实例值(账号/域)只进 bindings,不进特征。"""
    rows = graph.run_cypher(
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(trig:Event {event_code:'4769'})-[:BY]->(req:Account) "
        "OPTIONAL MATCH (trig)-[:REQUESTED]->(tgt) "
        "WITH req, trig, tgt.sam AS tgt_sam, tgt.domain AS tgt_domain, trig.event_time AS t0, trig.enc_type AS enc "
        "OPTIONAL MATCH (req)<-[:BY]-(e:Event {event_code:'4769'})-[:REQUESTED]->(t) "
        "  WHERE e.event_time >= toString(datetime(t0) - duration('" + _FANOUT_WINDOW + "')) AND e.event_time <= t0 "
        "RETURN req.sam AS req_sam, req.domain AS req_domain, tgt_sam, tgt_domain, enc, "
        "count(DISTINCT t) AS fanout",
        aid=alert.alert_uid)
    b = rows[0] if rows else None
    if not b or not (b.get("req_sam") or "").strip():
        return None                                  # 锚不到 4769 请求者 → 伪签名,不出签名

    req_sam = (b.get("req_sam") or "").strip()
    req_is_machine = req_sam.endswith("$")
    same_domain = bool(_netbios(b.get("req_domain")) and _netbios(b.get("tgt_domain"))
                       and _netbios(b.get("req_domain")) == _netbios(b.get("tgt_domain")))
    enc_raw = str(b.get("enc") or "").strip().lower()
    enc = "RC4" if enc_raw in ("0x17", "23", "rc4", "rc4-hmac") else "other"
    spn_fanout = ">=5" if (b.get("fanout") or 0) >= 5 else "<5"

    return {
        "skill": "kerberoast",
        "layers": [
            {"layer": "exculpatory",
             "features": {"req_is_machine": req_is_machine, "same_domain": same_domain}},
            {"layer": "incriminating",
             "features": {"req_is_machine": req_is_machine, "same_domain": same_domain,
                          "enc": enc, "spn_fanout": spn_fanout}},
        ],
        "bindings": {"requester": req_sam or None, "target_service": b.get("tgt_sam"),
                     "requester_domain": b.get("req_domain"), "target_service_domain": b.get("tgt_domain"),
                     "req_host": b.get("req_host")},
    }


# 攻击类型签名函数注册表(离线扩：加一个函数即铺开一类攻击)。
_REGISTRY = [sig_kerberoast]


def run_all(graph, alert, seed=None):
    """跑注册表里所有签名函数 → 收集非 None（过滤伪签名）。每函数 try 隔离,坏的不拖垮。
    返回 [{"skill","layers","bindings"}, ...]（可空：全是伪签名/无对口类型）。"""
    out = []
    for fn in _REGISTRY:
        try:
            r = fn(graph, alert, seed)
        except Exception:
            r = None
        if r:
            out.append(r)
    return out
