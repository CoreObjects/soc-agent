"""Kerberoast 确定性取证脚本(sink①)。

orchestrator 跑它把关键证据一次性收齐(含★跨域信任),抽出规范化 findings + 实体 bindings,
再交 LLM 定性 / 第二类经验匹配。不依赖模型自己规划该查什么。
graph.run_cypher(query, **params) 只读;多步依赖(后步用前步取出的账号/域)。
★同域按 NetBIOS 归一(NORTH 与 north.sevenkingdoms.local 是同一个域)。

finding 词典(方法论):rc4_requested / requester_is_machine / target_high_value / cross_domain /
domain_trust_present / spn_fanout。红=攻击迹象,白=良性豁免;"哪些组合→什么结论"交第二类(qwen 学)。
"""
from soc_agent.forensics import Finding, Forensics

_RC4 = {"0x17", "0x18", "23", "24", "rc4", "rc4-hmac", "rc4_hmac"}


def _netbios(domain):
    if not domain or domain == "-":
        return None
    return domain.split(".")[0].strip().upper() or None


def is_machine(sam) -> bool:
    return bool(sam and str(sam).strip().endswith("$"))


def _same_domain(req_domain, tgt_domain) -> bool:
    a, b = _netbios(req_domain), _netbios(tgt_domain)
    return bool(a and b and a == b)


def _is_rc4(enc) -> bool:
    return str(enc or "").strip().lower() in _RC4


def _bucket(n) -> str:
    n = n or 0
    if n <= 1:
        return "single"
    if n <= 4:
        return "low"
    if n <= 19:
        return "high"
    return "massive"


def collect(graph, alert, seed=None) -> Forensics:
    aid = alert.alert_uid
    ctx, findings, bindings = {}, [], {}

    # 1. 请求者 + 目标 + 加密/票据选项
    base = graph.run_cypher(
        # ★WP10 放宽:`4769` 是 Windows 专有码,换个 Kerberos 源(Samba AD / 第三方采集器)
        #   就再也命不中 —— 数据入了图,这里却查出零行、不报错。
        #   ★但**不能**简单 `OR e.activity='auth.ticket_request'`:那个活动类把
        #     4768(取 TGT)与 4769(取服务票)**合并了**,粒度不够。kerberoast 判的是
        #     「服务票被大量索取」,一刀切会把取 TGT 也算进来 —— 真机 PROFILE 实测
        #     total 24.5万→46万、distinct_targets 2→6。
        #     计划里那句「6 条统一放宽成 event_code IN […] OR activity=$act」对本 recipe 是错的;
        #     而且只查性能不查结果的话,这个语义 bug 会带着绿灯合进去。
        #   所以配一个**中立判别位** `ticket_kind`(入图侧 WP10 新增,tgt/service):
        #   第三方源同样填得出,而 4768/4769 这种码它们没有。
        #   **只加不改**:存量事件没有 ticket_kind,靠 OR 前半段照常命中,行集不变。
        "MATCH (a:Alert {alert_uid:$aid})<-[:TRIGGERED]-(e:Event)-[:BY]->(req:Account) "
        "WHERE e.event_code='4769' OR (e.activity='auth.ticket_request' AND e.ticket_kind='service') "
        "OPTIONAL MATCH (e)-[:REQUESTED]->(tgt) "
        "RETURN req.sam AS req_sam, req.domain AS req_domain, req.type AS req_type, "
        "coalesce(req.privileged,false) AS req_privileged, "
        "tgt.sam AS tgt_sam, tgt.domain AS tgt_domain, "
        "e.enc_type AS enc_type, e.ticket_options AS ticket_options",
        aid=aid)
    b = base[0] if base else {}
    ctx["请求与目标"] = b
    req_sam, tgt_sam = b.get("req_sam"), b.get("tgt_sam")
    req_domain, tgt_domain, enc_type = b.get("req_domain"), b.get("tgt_domain"), b.get("enc_type")

    if req_sam:
        bindings["attacker_account"] = req_sam
        if req_domain:
            bindings["attacker_account_domain"] = req_domain
    if tgt_sam:
        bindings["target_account"] = tgt_sam
        if tgt_domain:
            bindings["target_account_domain"] = tgt_domain

    if _is_rc4(enc_type):
        findings.append(Finding("kerberoast.rc4_requested", {"enc_type": enc_type}, evidence_ref=aid, polarity="red"))

    req_is_machine = is_machine(req_sam)
    if req_is_machine:
        findings.append(Finding("kerberoast.requester_is_machine", {"sam": req_sam}, polarity="white"))

    # 2. 目标估值:是否特权 / SPN / 属组(判 high-value)
    if tgt_sam:
        rows = graph.run_cypher(
            "MATCH (tgt:Account {sam:$s}) OPTIONAL MATCH (tgt)-[:MEMBER_OF]->(g:Group) "
            "RETURN coalesce(tgt.privileged,false) AS privileged, tgt.spn AS spn, "
            "collect(DISTINCT g.name) AS groups", s=tgt_sam)
        tv = rows[0] if rows else {}
        ctx["目标估值"] = tv
        if tv.get("privileged"):
            findings.append(Finding("kerberoast.target_high_value",
                                    {"privileged": True, "spn": tv.get("spn"), "groups": tv.get("groups") or []},
                                    polarity="red"))

    # 3. 请求者 enc 基线(RC4 是常态还是突增)—— context,供 LLM 看
    if req_sam:
        ctx["请求者enc基线"] = graph.run_cypher(
            # ★放宽同上(见 §1 的说明):必须带 ticket_kind='service',
            #   否则 4768 的取 TGT 会混进这条 enc 基线,把 RC4 占比冲淡。
            "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event) "
            "WHERE e.event_code='4769' OR (e.activity='auth.ticket_request' AND e.ticket_kind='service') "
            "RETURN e.enc_type AS enc, sum(coalesce(e.count,1)) AS n ORDER BY n DESC", s=req_sam)

    # 4. ★"跨域信任 FP"豁免判定(别把真 roast 当跨域正常票)
    same_domain = _same_domain(req_domain, tgt_domain)
    fp = {"req_is_machine": req_is_machine, "same_domain": same_domain,
          "req_domain": req_domain, "tgt_domain": tgt_domain,
          "_note": "NetBIOS 名(如 NORTH)与 FQDN(如 north.sevenkingdoms.local)是同一个域,勿当两个域。"
                   "跨域信任 FP 豁免机器账号引荐票;不豁免普通用户对服务账号的扇出取票。"}
    if req_domain and tgt_domain and not same_domain:
        findings.append(Finding("kerberoast.cross_domain",
                                {"req_domain": req_domain, "tgt_domain": tgt_domain}, polarity="white"))
    if req_domain:
        rows = graph.run_cypher(
            "MATCH (dreq:Domain {netbios:$nb}) OPTIONAL MATCH (dreq)-[:TRUSTS]-(dt:Domain) "
            "RETURN dreq.fqdn AS req_domain_fqdn, collect(DISTINCT dt.fqdn) AS trusts", nb=req_domain)
        r = rows[0] if rows else {}
        fp["req_domain_fqdn"] = r.get("req_domain_fqdn")
        trusts = r.get("trusts") or []
        fp["req_domain_trusts"] = trusts
        if trusts:
            findings.append(Finding("kerberoast.domain_trust_present", {"trusts": trusts}, polarity="white"))
    ctx["跨域信任FP豁免判定"] = fp

    # 5. SPN 扇出(短时去重目标数;扫描式取票信号)
    if req_sam:
        rows = graph.run_cypher(
            # ★放宽同上(见 §1)。**这条就是 PROFILE 逮住语义 bug 的那一条**:
            #   不带 ticket_kind 时 distinct_targets 2→6、total 24.5万→46万 —— 扇出直接被吹大,
            #   而扇出正是"扫描式取票"的判据,吹大它等于凭空造出攻击信号。
            "MATCH (req:Account {sam:$s})<-[:BY]-(e:Event)-[:REQUESTED]->(t) "
            "WHERE e.event_code='4769' OR (e.activity='auth.ticket_request' AND e.ticket_kind='service') "
            "RETURN count(DISTINCT t) AS distinct_targets, sum(coalesce(e.count,1)) AS total_4769", s=req_sam)
        sf = rows[0] if rows else {}
        ctx["SPN扇出"] = sf
        dt = sf.get("distinct_targets")
        if dt is not None:
            findings.append(Finding("kerberoast.spn_fanout",
                                    {"distinct_targets": dt, "total_4769": sf.get("total_4769"), "bucket": _bucket(dt)},
                                    polarity="red" if (dt or 0) >= 5 else "neutral"))

    return Forensics(findings=findings, bindings=bindings, context=ctx,
                     blind_spots="进程签名/发布者、票据实际用途、SPN 是否真服务账号 —— 图未建模")
